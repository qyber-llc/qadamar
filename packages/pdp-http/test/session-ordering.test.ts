import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { createServer } from '../src/server.ts';
import { decisionSessions } from '../src/pdp.ts';
import { Sessions, scopeSession } from '../src/sessions.ts';
import { fixture } from './helpers.ts';

const PEP = 'pep-1';
const point = (resource: string, action: string, sessionId?: string): Record<string, unknown> => ({
  subject: { type: 'user', id: 'carol' }, action: { name: action }, resource: { type: 'case', id: resource },
  context: { network: 'trusted', ...(action === 'read' ? {} : { sessionLevel: 1 }), ...(sessionId === undefined ? {} : { sessionId }) },
});

test('only mark-relevant decisions select a session queue', (t) => {
  const f = fixture(t);
  f.rt.sessions = new Sessions(false);
  const session = scopeSession(PEP, 's1');
  assert.deepEqual(decisionSessions(f.rt, '/access/v1/evaluation', point('CASE-14', 'read', 's1'), PEP), [session]);
  assert.deepEqual(decisionSessions(f.rt, '/access/v1/evaluation', point('CASE-14', 'update', 's1'), PEP), [session]);
  assert.deepEqual(decisionSessions(f.rt, '/access/v1/evaluation', point('CASE-18', 'read', 's1'), PEP), [], 'an L0 read pays nothing');
  assert.deepEqual(decisionSessions(f.rt, '/access/v1/evaluation', point('CASE-14', 'read'), PEP), [], 'no session pays nothing');
  assert.deepEqual(decisionSessions(f.rt, '/access/v1/search/action', point('CASE-18', 'read', 's1'), PEP), [session], 'action search also decides writes');
  const { subject: _subject, ...search } = point('CASE-18', 'read', 's1');
  assert.deepEqual(decisionSessions(f.rt, '/access/v1/search/subject', { ...search, subject: { type: 'user' } }, PEP), [session], 'subject search names no subject id, yet loads the session');
  assert.deepEqual(decisionSessions(f.rt, '/access/v1/search/subject', { ...point('CASE-18', 'read'), subject: { type: 'user' } }, PEP), [], 'no session pays nothing');
  const entries = [point('CASE-14', 'read'), point('CASE-11', 'update')].map(({ context: _context, ...entry }) => entry);
  const batch = { evaluations: entries, context: { network: 'trusted', sessionId: 's1' } };
  assert.deepEqual(decisionSessions(f.rt, '/access/v1/evaluations', batch, PEP), [session], 'batch entries inherit the common session');
});

test('one node orders a write behind a read already decided, without blocking other traffic', { timeout: 30_000 }, async (t) => {
  const dir = mkdtempSync('/tmp/pdp-session-order-');
  let hold = true;
  let entered!: () => void;
  let release!: () => void;
  const reading = new Promise<void>((resolve) => { entered = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const server = createServer({ port: 0, dataDir: dir, decisionHooks: { afterDecision: async () => {
    if (hold) { hold = false; entered(); await gate; }
  } } });
  await server.listen();
  t.after(async () => { release(); await server.close(); rmSync(dir, { recursive: true, force: true }); });
  const { pepApiKey } = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string };
  const ask = async (body: Record<string, unknown>): Promise<{ decision: boolean; context: { rules: string[] } }> => {
    const response = await fetch(`${server.url}/access/v1/evaluation`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${pepApiKey}` }, body: JSON.stringify(body) });
    assert.equal(response.status, 200);
    return await response.json() as { decision: boolean; context: { rules: string[] } };
  };
  const read = ask(point('CASE-14', 'read', 's1'));
  await reading;
  let writeSettled = false;
  const write = ask(point('CASE-11', 'update', 's1')).then((answer) => { writeSettled = true; return answer; });

  const started = performance.now();
  const independent = await Promise.all(Array.from({ length: 16 }, (_, i) => ask(point('CASE-14', 'read', `other-${i}`))));
  const independentMs = performance.now() - started;
  assert.ok(independent.every((answer) => answer.decision));
  const noSessionStarted = performance.now();
  assert.equal((await ask(point('CASE-11', 'update'))).decision, true, 'no-session traffic does not join the held queue');
  const noSessionMs = performance.now() - noSessionStarted;
  assert.equal((await ask(point('CASE-18', 'read', 's1'))).decision, true, 'even an L0 read in the held session bypasses its queue');
  assert.equal(writeSettled, false, 'the write cannot decide while the earlier read is uncommitted');

  release();
  assert.equal((await read).decision, true);
  assert.deepEqual((await write).context.rules, ['BLP.HIGH_WATER']);
  t.diagnostic(`16 independent session decisions completed in ${independentMs.toFixed(1)} ms while s1 was held; no-session decision ${noSessionMs.toFixed(1)} ms`);
});

test('different local session queues sustain concurrent decisions; non-session tasks have no queue cost', async (t) => {
  const sessions = new Sessions(false);
  const count = 5000;
  const task = async (): Promise<boolean> => { await Promise.resolve(); return true; };
  const directStarted = performance.now();
  const direct = await Promise.all(Array.from({ length: count }, () => task()));
  const directMs = performance.now() - directStarted;
  const queuedStarted = performance.now();
  const queued = await Promise.all(Array.from({ length: count }, (_, i) => sessions.serial([`s${i}`], task)));
  const queuedMs = performance.now() - queuedStarted;
  assert.ok(direct.every(Boolean));
  assert.ok(queued.every(Boolean));
  t.diagnostic(`${count} concurrent decisions: no queue ${(count / directMs * 1000).toFixed(0)}/s; independent queues ${(count / queuedMs * 1000).toFixed(0)}/s (${(queuedMs / count * 1000).toFixed(2)} us each)`);
});
