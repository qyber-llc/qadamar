// BLP session high-water mark (src/sessions.ts): reads raise it, writes cannot go below it, it expires with the session.
import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { evalExpr, type Expr } from '../../core/src/index.ts';
import { pdp } from '../src/pdp.ts';
import { xacml, ATTRIBUTE } from '../src/xacml.ts';
import { HttpError } from '../src/http.ts';
import { fileBacking } from '../src/store.ts';
import { MARK_TOUCH_MS, MAX_SESSIONS, SAVE_DELAY_MS, SESSION_ABSOLUTE_MS, SESSION_IDLE_MS, SESSION_TOMBSTONE_MS, Sessions, scopeSession, sessionsIn, sessionsPerPepFromEnv, type MarkFile, type MarkTable, type StoredMark } from '../src/sessions.ts';
import { fixture, required, type Fixture } from './helpers.ts';

interface Answer { decision: boolean; context: { rules: string[]; decision_token?: string } }
const PEP = 'pep-1';
function setup(t: Parameters<typeof fixture>[0], required = false, table?: MarkTable): Fixture & { clock: { ms: number } } {
  const f = fixture(t);
  const clock = { ms: Date.parse('2026-11-08T10:00:00Z') };
  f.rt.sessions = new Sessions(required, () => clock.ms, undefined, table);
  return { ...f, clock };
}
const body = (subject: string, resource: string, action: string, context: Record<string, unknown> = {}): Record<string, unknown> => ({
  subject: { type: 'user', id: subject }, action: { name: action }, resource: { type: resource.startsWith('PAY') ? 'payment' : 'case', id: resource },
  context: { network: 'trusted', ...context } });
const ask = (f: Fixture, b: Record<string, unknown>, pep = PEP): Answer => pdp(f.rt, '/access/v1/evaluation', b, [], true, pep) as Answer;
// carol (clearance 3) reads CASE-14 (L2), then works at L1 and writes CASE-11 (L1)
const read14 = (f: Fixture, session = 's1', pep = PEP): Answer => ask(f, body('carol', 'CASE-14', 'read', { sessionId: session }), pep);
const write11 = (f: Fixture, context: Record<string, unknown> = { sessionId: 's1' }, pep = PEP): Answer =>
  ask(f, body('carol', 'CASE-11', 'update', { sessionLevel: 1, ...context }), pep);

test('a read raises the session mark; a later write below it is denied, whatever level the caller asks for', (t) => {
  const f = setup(t);
  assert.equal(write11(f).decision, true, 'nothing read yet');
  assert.equal(read14(f).decision, true);
  assert.deepEqual(write11(f).context.rules, ['BLP.HIGH_WATER']);
  assert.deepEqual(write11(f, { sessionId: 's1', sessionLevel: 0 }).context.rules, ['BLP.HIGH_WATER'], 'a lower session level does not lower the floor');
  assert.equal(ask(f, body('carol', 'CASE-14', 'update', { sessionId: 's1', sessionLevel: 1 })).decision, true, 'writing at the mark');
  // the mark never decreases: a lower read leaves it at L2
  assert.equal(ask(f, body('carol', 'CASE-11', 'read', { sessionId: 's1' })).decision, true);
  assert.deepEqual(write11(f).context.rules, ['BLP.HIGH_WATER']);
  // scoped: another session, another PEP credential or no session at all (opt-in) starts clean
  assert.equal(write11(f, { sessionId: 's2' }).decision, true);
  assert.equal(write11(f, { sessionId: 's1' }, 'pep-2').decision, true);
  assert.equal(write11(f, {}).decision, true);
  assert.equal(f.rt.audit.records().at(-1)?.rules?.includes('BLP.HIGH_WATER'), false);
});

test('only permitted point reads raise the mark: not a denied read, a search, a filter, an explanation or a list assertion', (t) => {
  const f = setup(t);
  const s = { sessionId: 's1' };
  assert.equal(ask(f, body('bob', 'CASE-7', 'read', s)).decision, false);
  assert.equal(f.rt.sessions!.size, 0, 'a denied read records nothing');
  pdp(f.rt, '/access/v1/search/resource', { ...body('carol', 'CASE-14', 'read', s), resource: { type: 'case' } }, [], true, PEP);
  const columns = { 'resource.level': { column: 'level', type: 'number' }, 'resource.compartments': { column: 'compartments', kind: 'text[]' }, 'resource.id': 'id' };
  pdp(f.rt, '/x/v1/filter', { ...body('carol', 'CASE-14', 'read', s), resource: { type: 'case' }, columns }, [], true, PEP);
  pdp(f.rt, '/x/v1/explain', body('carol', 'CASE-14', 'read', s), [], true, PEP);
  assert.equal(f.rt.sessions!.size, 0);
  assert.equal(write11(f).decision, true);
});

test('searches and filters for a write apply the mark: what lies below it is not offered', (t) => {
  const f = setup(t);
  read14(f);
  const s = { sessionId: 's1', sessionLevel: 1 };
  const found = pdp(f.rt, '/access/v1/search/resource', { ...body('carol', 'CASE-11', 'update', s), resource: { type: 'case' } }, [], true, PEP) as { results: { id: string }[] };
  assert.ok(found.results.some((r) => r.id === 'CASE-14'));
  assert.ok(!found.results.some((r) => r.id === 'CASE-11'));
  const columns = { 'resource.level': { column: 'level', type: 'number' }, 'resource.compartments': { column: 'compartments', kind: 'text[]' }, 'resource.id': 'id',
    'resource.attrs.status': 'status', 'resource.owner': 'owner', 'resource.integrity': 'integrity' };
  const filtered = pdp(f.rt, '/x/v1/filter', { ...body('carol', 'CASE-11', 'update', s), resource: { type: 'case' }, columns }, [], true, PEP) as { residual: Expr };
  const resource = (id: string) => required(f.rt.store.state.resources.find((r) => r.id === id));
  const kept = (id: string): unknown => evalExpr(filtered.residual, { subject: undefined, resource: resource(id), action: { name: 'update' }, context: { network: 'trusted', now: f.rt.now() } });
  assert.equal(kept('CASE-11'), false);
});

test('a batch decides in order: a read earlier in the batch raises the mark for a write after it', (t) => {
  const f = setup(t);
  const batch = pdp(f.rt, '/access/v1/evaluations', { evaluations: [body('carol', 'CASE-14', 'read', { sessionId: 's1' }),
    body('carol', 'CASE-11', 'update', { sessionId: 's1', sessionLevel: 1 })] }, [], true, PEP) as { evaluations: Answer[] };
  assert.deepEqual(batch.evaluations.map((e) => e.decision), [true, false]);
  assert.deepEqual(batch.evaluations[1]!.context.rules, ['BLP.HIGH_WATER']);
});

test('XACML carries the session in an environment attribute', (t) => {
  const f = setup(t);
  const req = (resource: string, action: string, env: Array<Record<string, unknown>>): Record<string, unknown> => ({ Request: {
    AccessSubject: { Attribute: [{ AttributeId: ATTRIBUTE.subjectId, Value: 'carol' }] },
    Resource: { Attribute: [{ AttributeId: ATTRIBUTE.resourceId, Value: resource }, { AttributeId: ATTRIBUTE.resourceType, Value: 'case' }] },
    Action: { Attribute: { AttributeId: ATTRIBUTE.actionId, Value: action } },
    Environment: { Attribute: [{ AttributeId: ATTRIBUTE.network, Value: 'trusted' }, { AttributeId: ATTRIBUTE.sessionId, Value: 's1' }, ...env] } } });
  assert.equal(xacml(f.rt, req('CASE-14', 'read', []), [], PEP).Response[0]!.Decision, 'Permit');
  assert.equal(xacml(f.rt, req('CASE-11', 'update', [{ AttributeId: ATTRIBUTE.sessionLevel, Value: 1, DataType: 'http://www.w3.org/2001/XMLSchema#integer' }]), [], PEP).Response[0]!.Decision, 'Deny');
  assert.deepEqual(sessionsIn(req('CASE-14', 'read', []), PEP), [scopeSession(PEP, 's1')]);
});

test('a decision token is consumed against the mark of the session that asked for it', (t) => {
  const f = setup(t);
  f.rt.sodHistory = 'caller';
  const approve = ask(f, { ...body('henry', 'PAY-3', 'approve', { sessionId: 's1', makerId: 'grace' }) });
  const token = required(approve.context.decision_token);
  const sid = JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString()).sid as string;
  assert.equal(sid, scopeSession(PEP, 's1'));
  assert.deepEqual(sessionsIn({ token }, 'any'), [sid], 'the token names its session for loading');
  // the session then reads above the payment (as another node would record it)
  assert.equal(f.rt.sessions!.raise(sid, { type: 'user', id: 'henry' }, 2), true);
  assert.throws(() => pdp(f.rt, '/x/v1/tokens/consume', { token, action: 'approve', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 }, [], true, PEP),
    (e: unknown) => e instanceof HttpError && e.status === 409);
});

test('BLP_SESSION_REQUIRED: a cleared subject\'s writes and reads above L0 need a session id', (t) => {
  const f = setup(t, true);
  assert.deepEqual(write11(f, {}).context.rules, ['BLP.SESSION_REQUIRED']);
  assert.deepEqual(ask(f, body('carol', 'CASE-14', 'read')).context.rules, ['BLP.SESSION_REQUIRED']);
  assert.equal(ask(f, body('carol', 'CASE-18', 'read')).decision, true, 'L0 reads need none');
  assert.equal(write11(f).decision, true);
  // the session id is validated at the boundary: printable ASCII, 1..128 characters
  assert.throws(() => ask(f, body('carol', 'CASE-11', 'update', { sessionId: 'has space' })), (e: unknown) => e instanceof HttpError && e.status === 400);
  assert.throws(() => ask(f, body('carol', 'CASE-11', 'update', { sessionId: 'x'.repeat(129) })), (e: unknown) => e instanceof HttpError && e.status === 400);
});

test('a mark ends after 15 minutes idle or 8 hours in all, on the real clock; any use keeps it open', (t) => {
  const f = setup(t);
  read14(f);
  f.clock.ms += SESSION_IDLE_MS - 1;
  assert.deepEqual(write11(f).context.rules, ['BLP.HIGH_WATER'], 'still open, and touched by this decision');
  f.clock.ms += SESSION_IDLE_MS - 1;
  assert.deepEqual(write11(f).context.rules, ['BLP.HIGH_WATER']);
  f.clock.ms += SESSION_IDLE_MS;
  // the session is known expired (CBAC), and stays so: the mark is not revived; a new session starts clean
  assert.deepEqual(write11(f).context.rules, ['CBAC.SESSION_EXPIRED'], 'idle expiry');
  assert.deepEqual(write11(f).context.rules, ['CBAC.SESSION_EXPIRED'], 'still known expired');
  assert.equal(write11(f, { sessionId: 's2' }).decision, true, 'a new session');
  read14(f, 's3');
  const end = f.clock.ms + SESSION_ABSOLUTE_MS;
  while (f.clock.ms + 10 * 60_000 < end) { f.clock.ms += 10 * 60_000; assert.equal(write11(f, { sessionId: 's3' }).decision, false); }
  f.clock.ms = end - 1;
  assert.deepEqual(write11(f, { sessionId: 's3' }).context.rules, ['BLP.HIGH_WATER'], '1 ms before the absolute expiry');
  f.clock.ms = end;
  assert.deepEqual(write11(f, { sessionId: 's3' }).context.rules, ['CBAC.SESSION_EXPIRED'], 'absolute expiry');
});

test('a PEP may assert that its session expired; false changes nothing and a non-boolean is refused', (t) => {
  const f = setup(t);
  assert.deepEqual(write11(f, { sessionId: 's9', sessionExpired: true }).context.rules, ['CBAC.SESSION_EXPIRED']);
  assert.equal(write11(f, { sessionId: 's9', sessionExpired: false }).decision, true);
  read14(f, 's9');
  f.clock.ms += SESSION_IDLE_MS;
  assert.deepEqual(write11(f, { sessionId: 's9', sessionExpired: false }).context.rules, ['CBAC.SESSION_EXPIRED'], 'the caller cannot clear what the PDP knows');
  assert.throws(() => write11(f, { sessionId: 's9', sessionExpired: 'no' }), (e: unknown) => e instanceof HttpError && e.status === 400);
});

test('marks survive a restart without a database, and memory stays bounded', (t) => {
  const f = setup(t);
  const file = resolve(f.dir, 'sessions.json');
  const now = (): number => Date.parse('2026-11-08T10:00:00Z');
  const first = new Sessions(false, now, fileBacking(file));
  assert.equal(first.raise('s', { type: 'user', id: 'carol' }, 2), true);
  first.flush(); // what server.close does; otherwise within SAVE_DELAY_MS
  assert.equal(new Sessions(false, now, fileBacking(file)).level('s', { type: 'user', id: 'carol' }), 2);
  // without a database a full table refuses a new mark (the read is denied); with one, memory is a cache
  const full = new Sessions(false, now, undefined, undefined, MAX_SESSIONS);
  for (let i = 0; i < MAX_SESSIONS; i++) full.raise(`s${i}`, { type: 'user', id: 'carol' }, 1);
  assert.equal(full.raise('one-more', { type: 'user', id: 'carol' }, 1), false);
  f.rt.sessions = full;
  assert.deepEqual(read14(f, 'one-more').context.rules, ['BLP.SESSION_LIMIT']);
  const staged: StoredMark[] = [];
  const cached = new Sessions(false, now, undefined, { stage: (row) => staged.push(row), load: async () => [] }, MAX_SESSIONS);
  for (let i = 0; i <= MAX_SESSIONS; i++) cached.raise(`s${i}`, { type: 'user', id: 'carol' }, 1);
  assert.equal(cached.size, MAX_SESSIONS);
  assert.equal(staged.length, MAX_SESSIONS + 1);
});

test('a PEP credential at its share of marks is refused alone: other credentials keep recording theirs', (t) => {
  const f = setup(t);
  f.rt.sessions = new Sessions(false, () => f.clock.ms, undefined, undefined, 2);
  assert.equal(read14(f, 'a1', 'pep-A').decision, true);
  assert.equal(read14(f, 'a2', 'pep-A').decision, true);
  assert.deepEqual(read14(f, 'a3', 'pep-A').context.rules, ['BLP.SESSION_LIMIT'], 'A is at its share');
  assert.equal(read14(f, 'a1', 'pep-A').decision, true, 'an open session of A still reads');
  assert.equal(read14(f, 'b1', 'pep-B').decision, true, 'B is not affected by A');
  assert.equal(read14(f, 'b2', 'pep-B').decision, true);
  assert.deepEqual(write11(f, { sessionId: 'b1' }, 'pep-B').context.rules, ['BLP.HIGH_WATER'], 'and B\'s marks apply');
  // once A's marks expire, its share frees up
  f.clock.ms += SESSION_IDLE_MS;
  assert.equal(read14(f, 'a3', 'pep-A').decision, true);
  // with a database memory is a cache: A at its share drops its own oldest mark, never B's
  const cached = new Sessions(false, () => f.clock.ms, undefined, { stage: () => undefined, load: async () => [] }, 2);
  for (const id of ['a1', 'a2', 'a3', 'a4']) assert.equal(cached.raise(id, { type: 'user', id: 'carol' }, 1, 'pep-A'), true);
  assert.equal(cached.raise('b1', { type: 'user', id: 'carol' }, 1, 'pep-B'), true);
  assert.deepEqual([cached.held('pep-A'), cached.held('pep-B')], [2, 1]);
  assert.equal(cached.level('a1', { type: 'user', id: 'carol' }), undefined, 'A\'s oldest made room');
  assert.equal(cached.level('b1', { type: 'user', id: 'carol' }), 1);
  assert.equal(sessionsPerPepFromEnv(undefined), undefined);
  assert.equal(sessionsPerPepFromEnv('500'), 500);
  for (const bad of ['0', '1.5', 'x', String(MAX_SESSIONS + 1)]) assert.throws(() => sessionsPerPepFromEnv(bad), /BLP_SESSIONS_PER_PEP must be an integer/);
});

test('without a database raises are written in one batch within SAVE_DELAY_MS, not once per raise', async () => {
  let saved: MarkFile | undefined; let saves = 0;
  const sessions = new Sessions(false, Date.now, { load: () => undefined, save: (v) => { saves++; saved = v; } });
  for (let i = 0; i < 50; i++) sessions.raise(`s${i}`, { type: 'user', id: 'carol' }, 2, 'pep-A');
  assert.equal(saves, 0, 'nothing written per raise');
  await new Promise((r) => setTimeout(r, SAVE_DELAY_MS + 200));
  assert.equal(saves, 1, 'one write for the batch');
  assert.equal(saved?.length, 50);
  assert.equal(saved?.[0]?.[2], 'pep-A', 'the file keeps each mark\'s credential, so the share survives a restart');
  assert.equal(new Sessions(false, Date.now, { load: () => saved, save: () => undefined }).held('pep-A'), 50);
  sessions.flush();
  assert.equal(saves, 1, 'flush writes only what is pending');
});

test('with a database only a rise is written, and a use at most once every MARK_TOUCH_MS', (t) => {
  const staged: StoredMark[] = [];
  const f = setup(t, false, { stage: (row) => staged.push(row), load: async () => [] });
  assert.equal(read14(f).decision, true);
  assert.equal(staged.length, 1, 'the rise');
  for (let i = 0; i < 5; i++) { f.clock.ms += 5_000; write11(f); read14(f); }
  assert.equal(staged.length, 1, 'decisions within a minute write nothing');
  f.clock.ms += MARK_TOUCH_MS;
  assert.deepEqual(write11(f).context.rules, ['BLP.HIGH_WATER']);
  assert.equal(staged.length, 2, 'one touch a minute');
  assert.equal(staged[1]!.mark.seen, f.clock.ms);
});

test('with a shared table, marks other nodes recorded are loaded before deciding, merged upwards, expired ones kept as tombstones', async (t) => {
  const rows: StoredMark[] = [];
  const f = setup(t, false, { stage: () => undefined, load: async (sessions) => rows.filter((r) => sessions.includes(r.session)) });
  const session = scopeSession(PEP, 's1');
  const subject = JSON.stringify(['user', 'carol']);
  rows.push({ session, subject, mark: { level: 2, started: f.clock.ms, seen: f.clock.ms } });
  rows.push({ session: scopeSession(PEP, 'old'), subject, mark: { level: 3, started: f.clock.ms - SESSION_ABSOLUTE_MS, seen: f.clock.ms } });
  assert.equal(write11(f).decision, true, 'not loaded yet');
  await f.rt.sessions!.refresh(sessionsIn(body('carol', 'CASE-11', 'update', { sessionId: 's1' }), PEP));
  await f.rt.sessions!.refresh([scopeSession(PEP, 'old')]);
  assert.deepEqual(write11(f).context.rules, ['BLP.HIGH_WATER']);
  assert.deepEqual(write11(f, { sessionId: 'old' }).context.rules, ['CBAC.SESSION_EXPIRED'], 'another node\'s expired mark is a tombstone here too');
  assert.equal(f.rt.sessions!.raise(scopeSession(PEP, 'old'), { type: 'user', id: 'carol' }, 1, PEP), false, 'no fresh mark over a tombstone');
  rows.push({ session: scopeSession(PEP, 'older'), subject, mark: { level: 3, started: f.clock.ms - SESSION_TOMBSTONE_MS, seen: f.clock.ms } });
  await f.rt.sessions!.refresh([scopeSession(PEP, 'older')]);
  assert.equal(write11(f, { sessionId: 'older' }).decision, true, 'past the tombstone horizon the row is ignored');
  rows[0] = { session, subject, mark: { level: 1, started: f.clock.ms, seen: f.clock.ms } };
  await f.rt.sessions!.refresh([session]);
  assert.deepEqual(write11(f).context.rules, ['BLP.HIGH_WATER'], 'a lower copy never lowers the mark');
});
