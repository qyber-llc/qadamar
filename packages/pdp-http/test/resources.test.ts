// Resource registration (docs/API.md §2.2): a PEP credential bound to resource types registers, updates and retires the
// records its application owns. Narrowing or new records apply at once; declassification and other widening changes
// to a known record wait for a second person (two-person workflow); decisions follow the registry at once.
import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { pdp } from '../src/pdp.ts';
import { validateBundle, indexTuples, levelInheritanceErrors, type Resource } from '../../core/src/index.ts';
import { registrationCost, resources } from '../src/resources.ts';
import { applyResources, applyResourcesInPlace, checkResourceChanges } from '../src/resource-registry.ts';
import { findRef, graphOf } from '../src/decision-index.ts';
import { decideChange, propose } from '../src/admin/changes.ts';
import { admin } from '../src/admin/index.ts';
import { createHandler } from '../src/router.ts';
import { metrics } from '../src/metrics.ts';
import { HttpError } from '../src/http.ts';
import { Store, type Backing, type Disk, type State } from '../src/store.ts';
import type { RecordDelta } from '../src/record-deltas.ts';
import { mkdtempSync } from 'node:fs';
import type { PepCaller } from '../src/auth.ts';
import type { NodeRole } from '../src/runtime.ts';
import { evaluation, FIXED, fixture, required, user, WHY, type Fixture } from './helpers.ts';

interface Item { type: string; id: string; status: string; version?: number; changeId?: string }
interface Answer { items: Item[]; counts: Record<string, number> }
interface Evaluation { decision: boolean; context: { rules: string[] } }

const bearer = (secret: string) => ({ authorization: `Bearer ${secret}` }) as Record<string, string>;
/** A credential bound to `types`, issued by `issuer` (a console user id), as the PEP presents it. */
function registrar(f: Fixture, types: string[] | undefined, issuer = 'amira'): { caller: PepCaller; secret: string } {
  const { secret } = f.auth.createPepCredential(`app-${randomBytes(4).toString('hex')}`, issuer, undefined, undefined, types);
  return { caller: f.auth.pepCaller({ headers: bearer(secret) } as never), secret };
}
const record = (id: string, extra: Record<string, unknown> = {}): Record<string, unknown> =>
  ({ type: 'case', id, level: 1, compartments: [], integrity: 'system', owner: 'carol', contentClasses: [], parent: { type: 'folder', id: 'FOLDER-A' }, attrs: { status: 'open' }, ...extra });
function world(t: TestContext) {
  const f = fixture(t);
  const { caller } = registrar(f, ['case', 'payment', 'folder']);
  const call = (path: string, b: Record<string, unknown>, who = caller): { value: Answer; status: number } =>
    resources(f.rt, `/x/v1/resources${path}`, b, who) as { value: Answer; status: number };
  const register = (r: Record<string, unknown>) => call('', { resource: r });
  const decide = (id: string, resource: string, action = 'read'): Evaluation => pdp(f.rt, '/access/v1/evaluation', evaluation(id, resource, action)) as Evaluation;
  return { ...f, caller, call, register, decide };
}
const refused = (fn: () => unknown, status: number, message?: RegExp): void =>
  assert.throws(fn, (e: unknown) => e instanceof HttpError && e.status === status && (!message || message.test(e.message)));

test('a record registered at run time is decided at once: allowed through its parent, denied without, unknown before', (t) => {
  const { register, decide, rt } = world(t);
  assert.deepEqual(decide('bob', 'CASE-100').context.rules, ['CORE.UNKNOWN_ID'], 'not registered yet: fail closed');
  const created = register(record('CASE-100'));
  assert.equal(created.status, 201);
  assert.deepEqual(created.value.items, [{ type: 'case', id: 'CASE-100', status: 'created', version: 1 }]);
  assert.equal(decide('bob', 'CASE-100').decision, true, 'bob is a member of FOLDER-A: need-to-know through the parent relation');
  assert.ok(rt.store.state.tuples.some((x) => x.object.id === 'CASE-100' && x.relation === 'parent' && x.subject.id === 'FOLDER-A'), 'the parent tuple follows resource.parent');
  register(record('CASE-101', { parent: undefined }));
  const denied = decide('bob', 'CASE-101');
  assert.equal(denied.decision, false);
  assert.ok(denied.context.rules.some((r) => r.startsWith('NTK.')), denied.context.rules.join());
  // the SQL filter path sees the registered child like a seeded one (need-to-know ids from the same tuples)
  const filtered = pdp(rt, '/x/v1/filter', { subject: { type: 'user', id: 'bob' }, resource: { type: 'case' }, action: { name: 'read' },
    columns: { 'resource.id': 'id', 'resource.level': { column: 'level', type: 'number' }, 'resource.compartments': { column: 'compartments', kind: 'text[]' } } }) as { sql: { params: unknown[] } };
  const params = JSON.stringify(filtered.sql.params);
  assert.ok(params.includes('CASE-100') && !params.includes('CASE-101'), params);
  const row = required(rt.audit.records().filter((r) => r.action === 'resource_register').at(-1));
  assert.equal(row.type, 'change');
  assert.deepEqual(row.details?.resources, ['case:CASE-101']);
});

test('upserts are idempotent and versioned; raising a level is direct, lowering it waits for a second person', (t) => {
  const { register, decide, rt } = world(t);
  register(record('CASE-100'));
  const again = register(record('CASE-100'));
  assert.equal(again.status, 200);
  assert.equal(again.value.items[0]?.status, 'unchanged');
  refused(() => register(record('CASE-100', { version: 1, attrs: { status: 'closed' } })), 409, /above the stored version 1/);
  assert.equal(register(record('CASE-100', { level: 3 })).value.items[0]?.status, 'updated');
  assert.ok(decide('bob', 'CASE-100').context.rules.includes('BLP.NO_READ_UP'), 'raised above bob: denied at once');
  const lowered = register(record('CASE-100', { level: 1 }));
  assert.equal(lowered.status, 202);
  const item = required(lowered.value.items[0]);
  assert.equal(item.status, 'proposed');
  assert.equal(decide('bob', 'CASE-100').decision, false, 'nothing declassified before approval');
  assert.equal(register(record('CASE-100', { level: 1 })).value.items[0]?.changeId, item.changeId, 'the same proposal again: no second change');
  const change = required(rt.store.changes.find((c) => c.id === item.changeId));
  assert.equal(change.kind, 'register_resources');
  assert.equal(change.broadens, true);
  assert.ok(change.impact.gained.some((g) => g.subject === 'bob' && g.resource === 'CASE-100' && g.action === 'read'), 'impact preview names who gains');
  // another record registered meanwhile does not make the proposal stale
  register(record('CASE-102'));
  refused(() => decideChange(rt, user('ruth'), change.id, true, { reason: WHY }), 403);
  decideChange(rt, user('omar'), change.id, true, { reason: WHY });
  assert.equal(decide('bob', 'CASE-100').decision, true, 'declassified once a second person approved');
  assert.equal(required(rt.store.state.resources.find((r) => r.id === 'CASE-100')).version, 3);
});

test('a proposal goes stale when its resource changes; the issuer of the credential cannot approve its proposals', (t) => {
  const f = world(t);
  const own = registrar(f, ['case', 'folder'], 'lina');
  f.register(record('CASE-100', { level: 2, compartments: ['FALCON'] }));
  const removed = f.call('', { resource: record('CASE-100', { level: 2 }) }, own.caller).value.items[0]!;
  assert.equal(removed.status, 'proposed', 'removing a compartment is a declassification');
  assert.throws(() => decideChange(f.rt, user('lina'), removed.changeId!, true, { reason: WHY }), (e: unknown) => e instanceof HttpError && e.code === 'self_approval');
  f.register(record('CASE-100', { level: 3, compartments: ['FALCON'] }));
  assert.throws(() => decideChange(f.rt, { id: 'kim', name: 'kim', roles: ['security_officer'] }, removed.changeId!, true, { reason: WHY }),
    (e: unknown) => e instanceof HttpError && e.status === 409 && e.code === 'stale');
  // retired since it was proposed: approving must not bring the record back
  f.register(record('CASE-400', { level: 2 }));
  const lowered = f.register(record('CASE-400')).value.items[0]!;
  f.call('/retire', { resource: { type: 'case', id: 'CASE-400' } });
  assert.throws(() => decideChange(f.rt, user('omar'), lowered.changeId!, true, { reason: WHY }), (e: unknown) => e instanceof HttpError && e.code === 'stale');
  assert.equal(f.rt.store.state.resources.some((r) => r.id === 'CASE-400'), false);
  // rotated by lina: a proposal made with amira's old secret during the grace period is still amira's
  const before = registrar(f, ['case']);
  const rotated = f.auth.rotatePepCredential(before.caller.credential, 'lina');
  assert.equal(f.auth.pepCaller({ headers: bearer(rotated.secret) } as never).issuedBy, 'lina');
  assert.equal(f.auth.pepCaller({ headers: bearer(before.secret) } as never).issuedBy, 'amira');
  // only a registration credential proposes registrations
  assert.throws(() => propose(f.rt, user('amira'), { kind: 'register_resources', payload: { resources: [record('CASE-401', { version: 1 })], basis: ['new'] }, reason: WHY }),
    (e: unknown) => e instanceof HttpError && e.status === 403);
  for (const [change, why] of [[{ integrity: 'verified' }, 'integrity'], [{ owner: 'dan' }, 'owner'], [{ parent: undefined }, 'parent'], [{ contentClasses: [] }, 'content class']] as const) {
    f.register(record('CASE-200', { contentClasses: ['pii.iban'] }));
    const item = f.register(record('CASE-200', { contentClasses: ['pii.iban'], ...change })).value.items[0]!;
    assert.equal(item.status, 'proposed', why);
    assert.match(required(f.rt.store.changes.find((c) => c.id === item.changeId)).reason, new RegExp(why));
  }
});

test('the credential binding: only bound types, never an unbound credential; the schema is enforced, fail closed', (t) => {
  const f = world(t);
  const cases = registrar(f, ['case']).caller;
  refused(() => f.call('', { resource: { ...record('PAY-9'), type: 'payment', parent: undefined } }, cases), 403, /not bound to resource type payment/);
  refused(() => f.call('', { resource: record('CASE-300') }, f.auth.pepCaller({ headers: bearer(f.pepApiKey) } as never)), 403);
  for (const [bad, why] of [
    [{ level: 4 }, /level/], [{ level: '1' }, /level/], [{ compartments: ['NOPE'] }, /compartments/], [{ compartments: ['FALCON', 'FALCON'] }, /twice/],
    [{ integrity: 'Verified' }, /integrity/], [{ contentClasses: undefined }, /contentClasses/], [{ type: 'constructor' }, /resource type/],
    [{ id: '' }, /id/], [{ id: 'x\u0000' }, /id/], [{ colour: 'red' }, /colour/], [{ version: -1 }, /version/], [{ attrs: [] }, /attrs/],
    [{ attrs: { blob: 'x'.repeat(9000) } }, /attrs/], [{ parent: { type: 'folder' } }, /parent/], [{ parent: { type: 'case', id: 'CASE-300' } }, /itself/],
  ] as const) refused(() => f.register(record('CASE-300', bad)), 400, why);
  refused(() => f.call('', { resource: record('CASE-300'), extra: 1 }), 400);
  refused(() => f.register(record('CASE-300', { parent: { type: 'folder', id: 'FOLDER-NONE' } })), 422, /unknown parent/);
  refused(() => f.register(record('CASE-300', { level: 0 })), 422, /below its parent/);
  assert.equal(f.rt.store.state.resources.some((r) => r.id === 'CASE-300'), false);
});

test('retirement fails decisions closed, keeps parents consistent, and a retired id comes back judged against what it was', (t) => {
  const w = world(t);
  const { register, call, decide } = w;
  register(record('CASE-100', { level: 2 }));
  assert.equal(decide('bob', 'CASE-100').decision, true);
  const retired = call('/retire', { resource: { type: 'case', id: 'CASE-100' } });
  assert.equal(retired.value.counts.retired, 1);
  assert.deepEqual(decide('bob', 'CASE-100').context.rules, ['CORE.UNKNOWN_ID']);
  assert.equal(call('/retire', { resource: { type: 'case', id: 'CASE-100' } }).value.items[0]?.status, 'unchanged', 'retiring twice is idempotent');
  refused(() => call('/retire', { resource: { type: 'case', id: 'CASE-404' } }), 404);
  refused(() => call('/retire', { resource: { type: 'folder', id: 'FOLDER-A' } }, registrar(w, ['case']).caller), 403);
  refused(() => call('', { resource: record('CASE-150') }, registrar(w, ['case']).caller), 403, /parent: this PEP credential is not bound to resource type folder/);
  const back = register(record('CASE-100', { level: 2 })).value.items[0]!;
  assert.deepEqual([back.status, back.version], ['proposed', 2], 'a retired id comes back only through review, even unchanged, versioned after it');
  assert.match(required(w.rt.store.changes.find((c) => c.id === back.changeId)).reason, /retired id registered again/);
  assert.equal(register(record('CASE-100', { level: 3 })).value.items[0]?.status, 'proposed', 'whatever its labels');
  decideChange(w.rt, user('omar'), back.changeId!, true, { reason: WHY });
  assert.equal(decide('bob', 'CASE-100').decision, true, 'back once a second person approved');
  // a parent with a live child cannot go: the child would have an unknown parent, which a start refuses
  call('/sync', { resources: [record('CASE-P', { parent: undefined }), record('CASE-C', { parent: { type: 'case', id: 'CASE-P' } })] });
  refused(() => call('/retire', { resource: { type: 'case', id: 'CASE-P' } }), 422, /unknown parent/);
  assert.equal(call('/sync', { retire: [{ type: 'case', id: 'CASE-C' }, { type: 'case', id: 'CASE-P' }] }).value.counts.retired, 2);
});

test('console inventory: one type a page at a time with labels, retired ids for all but owners, owner scope, validated queries', (t) => {
  const w = world(t);
  w.register(record('CASE-100', { level: 2 }));
  w.register(record('CASE-101'));
  w.register(record('CASE-102', { owner: 'dave' }));
  w.call('/retire', { resource: { type: 'case', id: 'CASE-101' } });
  interface Page { type: string; total: number; next: string | null; items: Array<Record<string, unknown> & { id: string }> }
  const get = (who: string, query: string): Page => admin(w.rt, user(who), 'GET', new URL(`http://pdp/admin/v1/resources/${query}`), {}).value as Page;
  const live = w.rt.store.state.resources.filter((r) => r.type === 'case').map((r) => r.id).sort();
  const seen: string[] = [];
  for (let cursor = '', pages = 0; ; pages++) {
    const page = get('sam', `inventory?type=case&limit=2&cursor=${encodeURIComponent(cursor)}`);
    assert.ok(page.items.length <= 2 && pages < 50);
    assert.equal(page.total, live.length);
    seen.push(...page.items.map((r) => r.id));
    if (page.next === null) break;
    cursor = page.next;
  }
  assert.deepEqual(seen, live, 'every live resource once, in id order; the auditor reads it like the other model reads');
  assert.ok(!seen.includes('CASE-101'));
  const labelled = required(get('amira', 'inventory?type=case&limit=500').items.find((r) => r.id === 'CASE-100'));
  assert.deepEqual([labelled.level, labelled.version, labelled.owner, labelled.parent], [2, 1, 'carol', { type: 'folder', id: 'FOLDER-A' }]);
  const retired = get('amira', 'retired?type=case');
  assert.deepEqual(retired.items.map((r) => [r.id, r.version, r.registeredAgain]), [['CASE-101', 1, false]]);
  assert.equal(get('amira', 'retired?type=folder').total, 0);
  const owned = get('ruth', 'inventory?type=case&limit=500').items;
  assert.ok(owned.length > 0 && owned.every((r) => r.owner === 'carol'), 'ruth answers for carol only');
  assert.ok(!owned.some((r) => r.id === 'CASE-102'));
  refused(() => get('ruth', 'retired?type=case'), 403);
  for (const query of ['inventory', 'inventory?type=nope', 'inventory?type=case&limit=0', 'inventory?type=case&limit=501', 'retired?type=case&limit=x', `inventory?type=case&cursor=${'x'.repeat(257)}`]) {
    refused(() => get('amira', query), 400);
  }
});

test('sync: bounded, atomic, idempotent and persistent; list pages the registered ids; one audit row per call; metrics count it', (t) => {
  const w = world(t);
  const { call, register, rt, dir } = w;
  const registry = metrics(rt);
  register(record('CASE-100'));
  const payment = { type: 'payment', id: 'PAY-9', level: 1, compartments: [], integrity: 'verified', contentClasses: [], attrs: { amount: 5 } };
  const batch = { resources: [record('CASE-100', { level: 2 }), record('CASE-101'), payment], retire: [{ type: 'case', id: 'CASE-14' }] };
  const first = call('/sync', batch);
  assert.equal(first.status, 200);
  assert.deepEqual(first.value.counts, { created: 2, updated: 1, unchanged: 0, retired: 1, proposed: 0 });
  assert.deepEqual(call('/sync', batch).value.counts, { created: 0, updated: 0, unchanged: 4, retired: 0, proposed: 0 }, 'the same sync again changes nothing');
  refused(() => call('/sync', { resources: [record('CASE-500'), record('CASE-501', { level: 9 })] }), 400, /resources\[1\]\.level/);
  assert.equal(rt.store.state.resources.some((r) => r.id === 'CASE-500'), false, 'a refused batch keeps nothing');
  refused(() => call('/sync', { resources: [record('CASE-500'), record('CASE-500')] }), 400, /already in this request/);
  refused(() => call('/sync', {}), 400);
  refused(() => call('/sync', { resources: Array.from({ length: 1001 }, (_, i) => record(`C-${i}`)) }), 400, /1\.\.1000/);
  // Clark-Wilson C1: an item of a constrained type is registered only in a state its IVPs accept
  const s = rt.store.state;
  rt.store.state = { ...s, bundle: { ...s.bundle, clarkWilson: { ...s.bundle.clarkWilson, ivps: [{ id: 'amount-positive', description: 'A payment has a positive amount',
    resourceTypes: ['payment'], check: { op: 'gt', left: { path: 'resource.attrs.amount' }, right: { value: 0 } } }] } } };
  refused(() => register({ ...payment, id: 'PAY-10', attrs: {} }), 422, /integrity verification/);
  assert.equal(register({ ...payment, id: 'PAY-10' }).status, 201);
  // the registered ids of one bound type, a page at a time
  const pages: string[][] = []; let cursor = '';
  do {
    const page = call('/list', { type: 'case', limit: 3, ...(cursor ? { cursor } : {}) }).value as unknown as { resources: Array<{ id: string }>; next_cursor: string };
    pages.push(page.resources.map((r) => r.id)); cursor = page.next_cursor;
  } while (cursor);
  const ids = rt.store.state.resources.filter((r) => r.type === 'case').map((r) => r.id).sort();
  assert.deepEqual(pages.flat(), ids);
  assert.ok(pages.every((p) => p.length <= 3) && pages.length > 1);
  refused(() => call('/list', { type: 'folder' }, registrar(w, ['case']).caller), 403);
  refused(() => call('/list', { type: 'case', cursor: 'nope' }), 400);
  const rows = rt.audit.records().filter((r) => r.action === 'resource_sync');
  assert.equal(rows.length, 2, 'one row per successful call');
  assert.deepEqual(rows[0]?.details?.resources, ['case:CASE-100', 'case:CASE-101', 'payment:PAY-9', 'case:CASE-14']);
  const text = registry.render(rt);
  assert.match(text, /gate_resource_registrations_total\{operation="sync"\} 2/);
  assert.match(text, /gate_registered_resources_total\{outcome="unchanged"\} 4/);
  // what was registered and retired is in the state document: a restart decides on it
  const restarted = new Store(dir, resolve('examples/toy-domain'), FIXED);
  assert.ok(restarted.state.resources.some((r) => r.id === 'PAY-9') && !restarted.state.resources.some((r) => r.id === 'CASE-14'));
  assert.deepEqual(restarted.retired.get('case', 'CASE-14'), { type: 'case', id: 'CASE-14', version: 8, at: FIXED }, 'retired ids are in their own append-only log');
  assert.equal(Object.hasOwn(restarted.state, 'retiredResources'), false, 'and not in the state document');
});

// --- over HTTP, and through a cluster follower --------------------------------------------------------------------
interface Reply { status: number; data: Record<string, unknown> }
function send(url: string, path: string, method = 'POST', data?: unknown, headers: Record<string, string> = {}): Promise<Reply> {
  return new Promise((done, fail) => {
    const body = data === undefined ? undefined : JSON.stringify(data);
    const r = request(`${url}${path}`, { method, headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...headers } }, (res) => {
      let text = '';
      res.on('data', (c: Buffer) => { text += c.toString(); });
      res.on('end', () => { let parsed = {}; try { parsed = JSON.parse(text); } catch { /* empty */ } done({ status: res.statusCode ?? 0, data: parsed }); });
    });
    r.on('error', fail);
    r.end(body);
  });
}
async function listen(t: TestContext, handler: ReturnType<typeof createHandler>): Promise<string> {
  const server: Server = createServer((req, res) => void handler(req, res));
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  t.after(() => { server.close(); server.closeAllConnections(); });
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

test('over HTTP: authenticated, POST only, refusals audited; a follower forwards registrations to the leader', async (t) => {
  const f = fixture(t);
  const { secret } = registrar(f, ['case', 'folder']);
  const key = randomBytes(32);
  const role = (leader: boolean, url: () => string | null, id: string): NodeRole => ({ id, leader: () => leader, fresh: () => true, leaderUrl: url });
  const staticDir = resolve(f.dir, 'static');
  const leader = await listen(t, createHandler({ ...f.rt, node: role(true, () => null, 'gate-0') }, f.auth, { staticDir, hopKey: key }, () => 'http://x'));
  const follower = await listen(t, createHandler({ ...f.rt, node: role(false, () => leader, 'gate-1') }, f.auth, { staticDir, hopKey: key }, () => 'http://x'));
  const orphan = await listen(t, createHandler({ ...f.rt, node: role(false, () => null, 'gate-2') }, f.auth, { staticDir, hopKey: key }, () => 'http://x'));

  assert.equal((await send(leader, '/x/v1/resources', 'POST', { resource: record('CASE-100') })).status, 401);
  assert.equal((await send(leader, '/x/v1/resources', 'GET', undefined, bearer(secret))).status, 404);
  const created = await send(follower, '/x/v1/resources', 'POST', { resource: record('CASE-100') }, bearer(secret));
  assert.equal(created.status, 201, JSON.stringify(created.data));
  assert.ok(f.rt.store.state.resources.some((r) => r.id === 'CASE-100'), 'written by the leader');
  assert.equal((await send(follower, '/access/v1/evaluation', 'POST', evaluation('bob', 'CASE-100'), bearer(f.pepApiKey))).data.decision, true);
  const lost = await send(orphan, '/x/v1/resources', 'POST', { resource: record('CASE-101') }, bearer(secret));
  assert.deepEqual([lost.status, lost.data.error], [409, 'not_leader'], 'a follower that knows no leader never writes');

  const denied = await send(leader, '/x/v1/resources', 'POST', { resource: { ...record('PAY-9'), type: 'payment', parent: undefined } }, bearer(secret));
  assert.equal(denied.status, 403);
  const row = required(f.rt.audit.records().at(-1));
  assert.deepEqual([row.type, row.action, row.effect, row.details?.route, row.details?.error], ['change', 'refused', 'deny', '/x/v1/resources', 'forbidden']);
});

test('Clark-Wilson: an existing constrained item is never changed by registration; creating holds its IVPs, retiring waits for a second person', (t) => {
  const { call, register, decide, rt } = world(t);
  const payment = { type: 'payment', id: 'PAY-20', level: 1, compartments: [], integrity: 'verified', contentClasses: [], owner: 'grace', attrs: { amount: 5, status: 'pending' } };
  assert.equal(register(payment).status, 201);
  assert.equal(register(payment).value.items[0]?.status, 'unchanged', 'the same state again is not a change');
  for (const change of [{ attrs: { amount: 9, status: 'pending' } }, { level: 2 }, { version: 7 }]) {
    assert.throws(() => register({ ...payment, ...change }), (e: unknown) => e instanceof HttpError && e.status === 409 && e.code === 'certified_command_required' && /certified command/.test(e.message));
  }
  assert.throws(() => call('/sync', { resources: [record('CASE-900'), { ...payment, attrs: { amount: 1 } }] }), (e: unknown) => e instanceof HttpError && e.code === 'certified_command_required');
  assert.equal(rt.store.state.resources.some((r) => r.id === 'CASE-900'), false, 'the whole batch is refused');
  const retire = call('/retire', { resource: { type: 'payment', id: 'PAY-20' } });
  assert.equal(retire.status, 202);
  const item = required(retire.value.items[0]);
  assert.equal(item.status, 'proposed');
  assert.ok(rt.store.state.resources.some((r) => r.id === 'PAY-20'), 'still there until approved');
  assert.equal(call('/retire', { resource: { type: 'payment', id: 'PAY-20' } }).value.items[0]?.changeId, item.changeId, 'not queued twice');
  decideChange(rt, user('omar'), item.changeId!, true, { reason: WHY });
  assert.deepEqual(decide('grace', 'PAY-20').context.rules, ['CORE.UNKNOWN_ID']);
  assert.equal(rt.store.retired.get('payment', 'PAY-20')?.version, 1, 'its retired id recorded at approval');
});

test('attributes the policy reads change only with a second person; other attributes stay direct; a bundle can govern more', (t) => {
  const { register, rt } = world(t);
  register(record('CASE-100', { attrs: { status: 'open', title: 'Harbour' } }));
  // closed-is-read-only reads resource.attrs.status: any change of it, either way, is proposed
  for (const status of ['closed', 'archived']) {
    const item = required(register(record('CASE-100', { attrs: { status, title: 'Harbour' } })).value.items[0]);
    assert.equal(item.status, 'proposed', status);
    assert.match(required(rt.store.changes.find((c) => c.id === item.changeId)).reason, /policy attribute changed/);
  }
  assert.equal(register(record('CASE-100', { attrs: { title: 'Harbour' } })).value.items[0]?.status, 'proposed', 'removing a read attribute too');
  assert.equal(register(record('CASE-100', { attrs: { status: 'open', title: 'Harbour 2' } })).value.items[0]?.status, 'updated', 'an attribute no rule reads is direct');
  const s = rt.store.state;
  rt.store.state = { ...s, bundle: { ...s.bundle, schema: { ...s.bundle.schema, resourceTypes: { ...s.bundle.schema.resourceTypes,
    case: { ...s.bundle.schema.resourceTypes.case!, governedAttributes: ['title'] } } } } };
  assert.equal(register(record('CASE-100', { attrs: { status: 'open', title: 'Harbour 3' } })).value.items[0]?.status, 'proposed', 'governedAttributes adds to the rules');
  assert.equal(validateBundle({ ...s.bundle, schema: { ...s.bundle.schema, resourceTypes: { ...s.bundle.schema.resourceTypes, case: { ...s.bundle.schema.resourceTypes.case!, governedAttributes: ['a.b'] } } } }).ok, false);
});

test('bounded: a write costs more than a decision, retired ids are kept outside the state with no cap, pending proposals capped per credential', (t) => {
  const w = world(t);
  const { register, call, rt } = w;
  assert.deepEqual([registrationCost('/x/v1/resources/list', {}), registrationCost('/x/v1/resources', {}), registrationCost('/x/v1/resources/retire', {}),
    registrationCost('/x/v1/resources/sync', { resources: [1, 2], retire: [3] }), registrationCost('/x/v1/resources/sync', { resources: Array(1000).fill(0) })], [1, 11, 11, 13, 1000]);
  // no cap on retirements: many create/retire cycles leave the state document as it was, and every id stays known
  const size = JSON.stringify(rt.store.state).length;
  for (let round = 0; round < 3; round++) {
    const ids = Array.from({ length: 1000 }, (_, i) => `R${round}-${i}`);
    call('/sync', { resources: ids.map((id) => record(id, { parent: undefined })) });
    assert.equal(call('/sync', { retire: ids.map((id) => ({ type: 'case', id })) }).value.counts.retired, 1000);
  }
  assert.ok(JSON.stringify(rt.store.state).length <= size, 'nothing retired stays in the state document');
  assert.ok(rt.store.retired.get('case', 'R0-0') && rt.store.retired.get('case', 'R2-999'));
  assert.equal(register(record('R1-500', { parent: undefined })).value.items[0]?.status, 'proposed');
  const env = (name: string, value: string): void => { const old = process.env[name]; process.env[name] = value; t.after(() => { if (old === undefined) delete process.env[name]; else process.env[name] = old; }); };
  env('RESOURCE_PENDING_PROPOSALS_PER_PEP', '2');
  register(record('CASE-102', { level: 2 }));
  const first = register(record('CASE-102', { level: 1 })).value.items[0]!;
  assert.equal(register(record('CASE-102', { level: 1 })).value.items[0]?.changeId, first.changeId, 'the same proposal again is not a new one');
  register(record('CASE-103', { level: 2 }));
  assert.throws(() => register(record('CASE-103', { level: 1 })), (e: unknown) => e instanceof HttpError && e.status === 409 && e.code === 'proposal_limit');
  assert.equal(required(rt.store.state.resources.find((r) => r.id === 'CASE-103')).level, 2);
  const other = registrar(w, ['case', 'folder']).caller;
  assert.equal(call('', { resource: record('CASE-103', { level: 1 }) }, other).value.items[0]?.status, 'proposed', 'the cap is per credential');
});

test('incremental level validation matches full validation on random worlds and changes, with fresh-equivalent indexes', (t) => {
  const f = world(t);
  let seed = 0x51a7;
  const random = (max: number): number => { seed = (Math.imul(seed, 1_664_525) + 1_013_904_223) >>> 0; return seed % max; };
  const make = (id: string, level: number, parent?: { type: string; id: string }): Resource => ({ type: 'case', id, level: level as Resource['level'], compartments: [], integrity: 'system', owner: 'carol', contentClasses: [], version: 1, ...(parent ? { parent } : {}) });
  for (let run = 0; run < 40; run++) {
    const initial: Resource[] = [];
    for (let i = 0; i < 40; i++) {
      const parent = i > 0 && random(4) === 0 ? { type: 'case', id: `R${random(i)}` } : undefined;
      const level = parent ? initial.find((r) => r.id === parent.id)!.level : random(4);
      initial.push(make(`R${i}`, Math.max(level, random(4)), parent));
    }
    let state: State = { ...f.rt.store.state, resources: initial, tuples: [] };
    for (let step = 0; step < 12; step++) {
      const action = random(4);
      const upserts: Resource[] = [];
      const retired: Array<{ type: string; id: string }> = [];
      if (action === 0) {
        const parent = state.resources.length && random(3) > 0 ? state.resources[random(state.resources.length)]! : undefined;
        upserts.push(make(`N${run}-${step}`, parent ? Math.max(parent.level, random(4)) : random(4), parent && { type: parent.type, id: parent.id }));
      } else if (action === 1) {
        const old = state.resources[random(state.resources.length)]!;
        upserts.push({ ...old, level: random(4) as Resource['level'], version: (old.version ?? 0) + 1 });
      } else if (action === 2) {
        const old = state.resources[random(state.resources.length)]!;
        const parent = random(4) === 0 ? { type: 'case', id: 'MISSING' } : state.resources[random(state.resources.length)]!;
        upserts.push({ ...old, parent: { type: parent.type, id: parent.id }, version: (old.version ?? 0) + 1 });
      } else {
        const old = state.resources[random(state.resources.length)]!;
        retired.push({ type: old.type, id: old.id });
      }
      const preview = applyResources(state, upserts, retired);
      const expected = levelInheritanceErrors(preview.resources).sort();
      let actual: string[] = [];
      try { checkResourceChanges(state, upserts, retired); } catch (err) {
        assert.ok(err instanceof HttpError && err.code === 'unprocessable');
        actual = (err.details ?? []).map(String).sort();
      }
      assert.deepEqual(actual, expected, `run=${run} step=${step}`);
      if (expected.length) continue;
      state = applyResourcesInPlace(state, upserts, retired);
      assert.deepEqual(state.resources, preview.resources, 'in-place mutation preserves exact legacy array order');
      assert.deepEqual(graphOf(state.tuples), indexTuples(state.tuples), 'patched tuple graph equals a fresh index');
    }
  }
});

test('versioned proposal digests preserve legacy approval and reject later state changes; file revisions survive restart', (t) => {
  const w = world(t);
  assert.match(w.rt.store.digest(), /^v2\./);
  const legacy = propose(w.rt, user('amira'), { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY });
  legacy.stateDigest = w.rt.store.legacyDigest();
  decideChange(w.rt, user('omar'), legacy.id, true, { reason: WHY });
  const pending = propose(w.rt, user('amira'), { kind: 'update_subject', payload: { id: 'bob', set: { active: true } }, reason: WHY });
  w.register(record('CASE-V2'));
  assert.throws(() => decideChange(w.rt, user('omar'), pending.id, true, { reason: WHY }), (e: unknown) => e instanceof HttpError && e.code === 'stale');
  const current = w.rt.store.digest();
  const restarted = new Store(w.dir, resolve('examples/toy-domain'), FIXED);
  assert.equal(restarted.digest(), current);
});

test('file retired log: a torn last line (crash mid-append) is ignored, a bad line elsewhere stops the start', async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { fileRetiredLog } = await import('../src/store.ts');
  const dir = mkdtempSync(join(tmpdir(), 'retired-'));
  try {
    const row = JSON.stringify({ type: 'case', id: 'CASE-1', version: 2, at: '2026-11-10T00:00:00Z' });
    writeFileSync(join(dir, 'torn.jsonl'), `${row}\n{"type":"case","id":"CA`);
    assert.equal(fileRetiredLog(join(dir, 'torn.jsonl')).get('case', 'CASE-1')?.version, 2);
    writeFileSync(join(dir, 'bad.jsonl'), `{"type":\n${row}\n`);
    assert.throws(() => fileRetiredLog(join(dir, 'bad.jsonl')), SyntaxError);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

for (const mode of ['file', 'per-record'] as const) {
  test(`a refused write rolls back completely (${mode} store): nothing applied, nothing staged, a retirement cannot skip the retired log`, (t) => {
    const w = world(t);
    const { register, call, rt } = w;
    if (mode === 'per-record') {
      // the PostgreSQL backing's shape: committed states patch the live arrays in place and stage per-record deltas
      let disk: Disk | undefined; const committed: RecordDelta[][] = [];
      const backing: Backing<Disk> = { records: true, load: () => disk && structuredClone(disk), save: (value, records = []) => { disk = structuredClone(value); committed.push([...records]); } };
      rt.store = new Store(mkdtempSync('/tmp/pdp-test-rollback-'), resolve('examples/toy-domain'), rt.now(), backing);
      t.after(() => { assert.ok(!committed.flat().some((d) => d.id === 'CASE-200' && d.op === 'delete'), 'the refused retirement never reached the database'); });
    }
    // the store-level contract: assigning a saved state back undoes what the arrays were patched with since
    const saved = rt.store.state; const count = saved.resources.length;
    rt.store.state = applyResources(saved, [record('ZZ-1') as unknown as Resource]);
    rt.store.state = saved;
    assert.equal(rt.store.state.resources.length, count);
    assert.equal(rt.store.state.resources.some((r) => r.id === 'ZZ-1'), false);

    const old = process.env.RESOURCE_PENDING_PROPOSALS_PER_PEP; process.env.RESOURCE_PENDING_PROPOSALS_PER_PEP = '1';
    t.after(() => { if (old === undefined) delete process.env.RESOURCE_PENDING_PROPOSALS_PER_PEP; else process.env.RESOURCE_PENDING_PROPOSALS_PER_PEP = old; });
    assert.equal(register(record('CASE-200')).status, 201);
    register(record('CASE-300', { level: 2 })); register(record('CASE-301', { level: 2 }));
    assert.equal(register(record('CASE-301', { level: 1 })).value.items[0]?.status, 'proposed', 'the one allowed proposal is pending');
    const before = rt.store.state.resources.length;
    // a direct retirement and a change needing review, refused as a whole: "nothing was kept"
    assert.throws(() => call('/sync', { resources: [record('CASE-300', { level: 1 })], retire: [{ type: 'case', id: 'CASE-200' }] }),
      (e: unknown) => e instanceof HttpError && e.code === 'proposal_limit');
    assert.equal(rt.store.state.resources.length, before);
    assert.ok(findRef(rt.store.state.resources, 'CASE-200', 'case'), 'still registered, and found through the index');
    assert.equal(rt.store.retired.get('case', 'CASE-200'), undefined);
    rt.store.save(); // the next commit carries nothing of the refused request
    assert.ok(rt.store.state.resources.some((r) => r.id === 'CASE-200'));
    // re-registering it is an ordinary update of a live record, never a fresh creation that skips review
    const again = register(record('CASE-200')).value.items[0]?.status;
    assert.ok(again !== 'created' && again !== 'proposed', `re-registered as ${again}`);
  });
}
