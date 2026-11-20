import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { createServer } from '../../pdp-http/src/server.ts';
import { evaluation, fixture, required } from '../../pdp-http/test/helpers.ts';
import { AccessDeniedError, MASKED_TEXT, PepClient } from '../src/index.ts';
import type { TestContext } from 'node:test';
import type { PdpServer } from '../../pdp-http/src/server.ts';

async function liveClient(t: TestContext): Promise<PepClient | undefined> {
  const dir = mkdtempSync('/tmp/pdp-sdk-live-');
  const server: PdpServer = createServer({
    port: 0, dataDir: dir, worldDir: resolve('examples/toy-domain'), clock: 'fixed:2026-11-08T10:00:00Z', sodHistory: 'caller',
  });
  t.after(() => server.close()); t.after(() => rmSync(dir, { recursive: true, force: true }));
  try { await server.listen(); }
  catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'EPERM') {
      t.skip('Sandbox forbids listening on localhost (EPERM)');
      return undefined;
    }
    throw error;
  }
  const credentials = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string };
  return new PepClient({ baseUrl: server.url, apiKey: credentials.pepApiKey });
}

test('real-server reference PEP: bob/CASE-14 redacts informant_name and masks finance.amount', async (t) => {
  const client = await liveClient(t);
  if (!client) return;
  const request = evaluation('bob', 'CASE-14', 'read', 'trusted') as unknown as Parameters<PepClient['evaluate']>[0];
  const decision = await client.evaluate(request);
  assert.equal(decision.decision, true);
  assert.deepEqual(decision.context.obligations.redact, ['informant_name']);
  assert.deepEqual(decision.context.obligations.maskClasses, ['finance.amount']);
  assert.match(decision.context.policy_version, /^pv\./);

  const original = {
    id: 'CASE-14', title: 'Procurement irregularities', informant_name: 'Confidential Informant',
    content: [
      { class: 'public.summary', text: 'Procurement summary remains readable' },
      { class: 'finance.amount', text: 'AED 900,000' },
    ],
  };
  const released = await client.enforce(request, original);
  assert.equal(released.informant_name, null);
  assert.equal(released.content[1]?.text, MASKED_TEXT);
  assert.equal(released.content[0]?.text, 'Procurement summary remains readable');
  assert.equal(original.informant_name, 'Confidential Informant');
  assert.equal(original.content[1]?.text, 'AED 900,000');

  await assert.rejects(client.enforce(evaluation('bob', 'CASE-7') as unknown as Parameters<PepClient['evaluate']>[0], original), AccessDeniedError);
  assert.equal(original.informant_name, 'Confidential Informant');
});

test('real-server client covers batch, all searches, SQL filter, and single-use decision tokens', async (t) => {
  const client = await liveClient(t);
  if (!client) return;
  const bob = evaluation('bob', 'CASE-14', 'read', 'trusted') as unknown as Parameters<PepClient['evaluate']>[0];
  const batch = await client.evaluateBatch({
    ...bob, evaluations: [{}, { resource: { type: 'case', id: 'CASE-7' } }, {}],
    options: { evaluations_semantic: 'deny_on_first_deny' },
  });
  assert.deepEqual(batch.evaluations.map((item) => item.decision), [true, false]);

  const resources = await client.searchResources({ ...bob, resource: { type: 'case' }, page: { limit: 1 } });
  assert.equal(resources.results.length, 1);
  assert.ok(resources.page.next_token);
  const next = await client.searchResources({
    ...bob, resource: { type: 'case' }, page: { limit: 1, token: resources.page.next_token },
  });
  assert.notDeepEqual(resources.results, next.results);
  const subjects = await client.searchSubjects({ ...bob, subject: { type: 'user' } });
  assert.ok(subjects.results.some((subject) => subject.id === 'bob'));
  assert.ok(!subjects.results.some((subject) => subject.id === 'frank'));
  const actions = await client.searchActions(bob);
  assert.ok(actions.results.some((action) => action.name === 'read'));
  assert.ok(!actions.results.some((action) => action.name === 'delete'));

  const compiled = await client.filter({
    ...bob, resource: { type: 'case' }, dialect: 'postgres',
    columns: {
      'resource.level': { column: 'level', type: 'number' },
      'resource.compartments': { column: 'compartments', kind: 'text[]' }, 'resource.id': 'id',
    },
  });
  assert.equal(typeof compiled.sql.text, 'string');
  assert.ok(compiled.sql.params.length > 0);
  assert.ok(Object.hasOwn(compiled.residual, 'op'));

  const certified = await client.evaluate({
    subject: { type: 'user', id: 'henry' }, action: { name: 'approve' },
    resource: { type: 'payment', id: 'PAY-3' }, context: { network: 'trusted', makerId: 'grace' },
  });
  assert.equal(certified.decision, true);
  const token = required(certified.context.decision_token);
  const consume = { token, action: 'approve', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 } as const;
  const consumed = await client.consumeToken(consume);
  const reservation = required(consumed.reservation);
  await assert.rejects(client.consumeToken(consume), (error: unknown) => {
    return error instanceof Error && 'status' in error && error.status === 409 && 'code' in error && error.code === 'conflict';
  });
  // the PEP ran the command: it reports so, once; a contrary report is refused
  assert.deepEqual(await client.reportOutcome({ reservation, outcome: 'completed' }), { ok: true, reservation, outcome: 'completed' });
  assert.deepEqual(await client.reportOutcome({ reservation, outcome: 'completed' }), { ok: true, reservation, outcome: 'completed' });
  await assert.rejects(client.reportOutcome({ reservation, outcome: 'failed' }), (error: unknown) => error instanceof Error && 'status' in error && error.status === 409);
});

test('real-server openSession and closeSession carry a mark that another token cannot reset', async (t) => {
  const client = await liveClient(t);
  if (!client) return;
  const first = await client.openSession({ type: 'user', id: 'carol' });
  const point = (resource: string, action: string, token: string) => ({
    subject: { type: 'user', id: 'carol' }, action: { name: action }, resource: { type: 'case', id: resource },
    context: { network: 'trusted' as const, sessionToken: token, ...(action === 'read' ? {} : { sessionLevel: 1 as const }) },
  });
  assert.equal((await client.evaluate(point('CASE-14', 'read', first.token))).decision, true);
  const second = await client.openSession({ type: 'user', id: 'carol' });
  const denied = await client.evaluate(point('CASE-11', 'update', second.token));
  assert.deepEqual([denied.decision, denied.context.rules], [false, ['BLP.HIGH_WATER']]);
  assert.deepEqual(await client.closeSession(first.token), { ok: true });
  await assert.rejects(client.evaluate(point('CASE-14', 'read', first.token)), (error: unknown) =>
    error instanceof Error && 'status' in error && error.status === 403 && 'code' in error && error.code === 'invalid_session_token');
  await client.closeSession(second.token);
});

test('real-server registration: a type-bound credential registers, syncs, lists and retires records the PDP then decides on', async (t) => {
  const f = fixture(t);
  const server: PdpServer = createServer({ port: 0, dataDir: resolve(f.dir, 'live'), worldDir: resolve('examples/toy-domain'), clock: 'fixed:2026-11-08T10:00:00Z' });
  t.after(() => server.close());
  try { await server.listen(); } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'EPERM') { t.skip('Sandbox forbids listening on localhost (EPERM)'); return; }
    throw error;
  }
  const credentials = JSON.parse(readFileSync(resolve(f.dir, 'live/INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string; passwords: Record<string, string> };
  const signIn = await fetch(`${server.url}/admin/v1/session`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'lina', password: credentials.passwords.lina }) });
  const session = { cookie: String(signIn.headers.get('set-cookie')).split(';')[0]!, 'x-csrf-token': String(((await signIn.json()) as { csrfToken: string }).csrfToken) };
  const issued = await fetch(`${server.url}/admin/v1/pep-credentials`, { method: 'POST', headers: { 'content-type': 'application/json', ...session }, body: JSON.stringify({ name: 'case-app', resourceTypes: ['case', 'folder'] }) });
  assert.equal(issued.status, 201);
  const app = new PepClient({ baseUrl: server.url, apiKey: ((await issued.json()) as { secret: string }).secret });
  const pep = new PepClient({ baseUrl: server.url, apiKey: credentials.pepApiKey });
  const record = { type: 'case', id: 'CASE-100', level: 1, compartments: [], integrity: 'system', contentClasses: [], owner: 'carol', parent: { type: 'folder', id: 'FOLDER-A' } } as const;
  const bobReads = async (): Promise<boolean> => (await pep.evaluate(evaluation('bob', 'CASE-100') as unknown as Parameters<PepClient['evaluate']>[0])).decision;

  assert.equal(await bobReads(), false);
  assert.deepEqual((await app.registerResource(record)).items, [{ type: 'case', id: 'CASE-100', status: 'created', version: 1 }]);
  assert.equal(await bobReads(), true);
  const lowered = await app.syncResources({ resources: [{ ...record, level: 2 }, { ...record, id: 'CASE-101' }] });
  assert.deepEqual(lowered.counts, { created: 1, updated: 1, unchanged: 0, retired: 0, proposed: 0 });
  const proposed = await app.registerResource({ ...record, level: 1 });
  assert.equal(proposed.items[0]?.status, 'proposed');
  assert.ok(proposed.items[0]?.changeId);
  assert.deepEqual((await app.listResources({ type: 'case', limit: 1000 })).resources.filter((r) => r.id.startsWith('CASE-10')), [
    { type: 'case', id: 'CASE-100', version: 2 }, { type: 'case', id: 'CASE-101', version: 1 }]);
  await assert.rejects(pep.registerResource(record), (e: unknown) => e instanceof Error && 'status' in e && e.status === 403, 'the bootstrap credential writes no resources');
  assert.equal((await app.retireResource({ type: 'case', id: 'CASE-100' })).counts.retired, 1);
  assert.equal(await bobReads(), false);
});
