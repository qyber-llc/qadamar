// The PDP's copy of a constrained item follows its certified commands: the post-state a token consumption carried is
// applied when the PEP reports the command completed (never when it failed or is still pending), only while the item
// is still at the version the token was bound to; otherwise it is kept for reconciliation.
import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { pdp } from '../src/pdp.ts';
import { checkPostState } from '../src/resource-registry.ts';
import { admin } from '../src/admin/index.ts';
import { HttpError } from '../src/http.ts';
import type { Resource } from '../../core/src/index.ts';
import { evaluation, fixture, required, user } from './helpers.ts';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { createHandler } from '../src/router.ts';
import type { NodeRole } from '../src/runtime.ts';

interface Evaluation { decision: boolean; context: { rules: string[]; decision_token?: string } }
const ivp = (min: number) => ({ id: 'amount-floor', description: 'A payment amount is at least the floor', resourceTypes: ['payment'],
  check: { op: 'ge' as const, left: { path: 'resource.attrs.amount' }, right: { value: min } } });

function world(t: TestContext) {
  const f = fixture(t);
  const { rt } = f;
  const payment = required(rt.store.state.resources.find((r) => r.id === 'PAY-3'));
  const setIvp = (min: number): void => { const s = rt.store.state; rt.store.state = { ...s, bundle: { ...s.bundle, clarkWilson: { ...s.bundle.clarkWilson, ivps: [ivp(min)] } } }; };
  rt.store.state = { ...rt.store.state,
    subjects: rt.store.state.subjects.map((s) => s.id === 'alice' ? { ...s, clearance: 1 as const, roles: ['finance_clerk'] } : s),
    resources: [...rt.store.state.resources, { ...payment, id: 'PAY-NEW', owner: 'alice', version: 1, attrs: { ...payment.attrs, amount: 5 } }] };
  setIvp(1);
  const item = (): Resource => required(rt.store.state.resources.find((r) => r.id === 'PAY-NEW'));
  const decide = (): Evaluation => pdp(rt, '/access/v1/evaluation', { ...evaluation('alice', 'PAY-NEW', 'create'), context: { network: 'trusted' } }) as Evaluation;
  const reserve = (attrs: Record<string, unknown>, pep = 'pep-1'): string => {
    const token = required(decide().context.decision_token);
    return (pdp(rt, '/x/v1/tokens/consume', { token, action: 'create', resource: { type: 'payment', id: 'PAY-NEW' }, resourceVersion: item().version, attrs }, [], true, pep) as { reservation: string }).reservation;
  };
  const report = (reservation: string, outcome: string): unknown => pdp(rt, '/x/v1/tokens/outcome', { reservation, outcome }, [], true, 'pep-1');
  return { ...f, item, decide, reserve, report, setIvp };
}

test('a completed command applies its post-state: attrs merged, version bound + 1, audited; the next IVP check sees it', (t) => {
  const { rt, item, decide, reserve, report, setIvp } = world(t);
  const reservation = reserve({ amount: 9 });
  assert.equal(item().attrs?.amount, 5, 'pending: nothing applied');
  report(reservation, 'completed');
  assert.deepEqual([item().attrs?.amount, item().attrs?.status, item().version], [9, 'pending', 2]);
  assert.deepEqual(required(rt.audit.records().at(-1)).details?.postState, { applied: true, version: 2 });
  setIvp(9);
  assert.equal(decide().context.rules.some((r) => r.startsWith('CW.IVP')), false, 'the IVP runs on the state the command committed');
  setIvp(10);
  assert.ok(decide().context.rules.includes('CW.IVP.amount-floor'));
});

test('a failed command applies nothing', (t) => {
  const { item, reserve, report } = world(t);
  report(reserve({ amount: 9 }), 'failed');
  assert.deepEqual([item().attrs?.amount, item().version], [5, 1]);
});

test('an item changed since the token was consumed is not overwritten: the post-state waits for reconciliation', async (t) => {
  const { rt, item, reserve, report } = world(t);
  const reservation = reserve({ amount: 9 });
  rt.store.state = { ...rt.store.state, resources: rt.store.state.resources.map((r) => r.id === 'PAY-NEW' ? { ...r, version: 2, attrs: { ...r.attrs, amount: 7 } } : r) };
  report(reservation, 'completed');
  assert.deepEqual([item().attrs?.amount, item().version], [7, 2], 'left as it is');
  assert.deepEqual(required(rt.audit.records().at(-1)).details?.postState, { applied: false, reason: 'the item is at version 2, the command was decided at version 1' });
  const listed = await admin(rt, user('lina'), 'GET', new URL('http://x/admin/v1/integrity/reservations'), {}).value as { unappliedPostStates: Array<{ reservation: string; storedVersion: number; boundVersion: number }> };
  assert.deepEqual(listed.unappliedPostStates.map((u) => [u.reservation, u.boundVersion, u.storedVersion]), [[reservation, 1, 2]]);
  // a later command applied to the item settles the earlier unapplied one
  report(reserve({ amount: 11 }), 'completed');
  assert.deepEqual([item().attrs?.amount, item().version], [11, 3]);
  assert.deepEqual(rt.store.state.unappliedPostStates, []);
});

test('on a cluster follower a completion carrying a post-state is refused for the leader; a failure is settled there', (t) => {
  const { rt, item, reserve, report } = world(t);
  const first = reserve({ amount: 9 }); const second = reserve({ amount: 8 });
  rt.node = { id: 'b', leader: () => false, fresh: () => true, leaderUrl: () => null };
  assert.throws(() => report(first, 'completed'), (e: unknown) => e instanceof HttpError && e.status === 409 && e.code === 'not_leader');
  assert.equal(rt.store.pendingReservations().some((p) => p.id === first), true, 'still pending');
  report(second, 'failed');
  rt.node = undefined;
  report(first, 'completed');
  assert.equal(item().attrs?.amount, 9);
});

test('over HTTP a follower passes a completion with a post-state to the leader, which applies it', async (t) => {
  const f = world(t);
  const key = randomBytes(32);
  const listen = async (node: NodeRole): Promise<string> => {
    const handler = createHandler({ ...f.rt, node }, f.auth, { staticDir: resolve(f.dir, 'static'), hopKey: key }, () => 'http://x');
    const server: Server = createServer((req, res) => void handler(req, res));
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
    t.after(() => { server.close(); server.closeAllConnections(); });
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  };
  const leader = await listen({ id: 'a', leader: () => true, fresh: () => true, leaderUrl: () => null });
  const follower = await listen({ id: 'b', leader: () => false, fresh: () => true, leaderUrl: () => leader });
  const reservation = f.reserve({ amount: 9 }, 'bootstrap');
  const answer = await fetch(`${follower}/x/v1/tokens/outcome`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${f.pepApiKey}` },
    body: JSON.stringify({ reservation, outcome: 'completed' }) });
  assert.equal(answer.status, 200, await answer.clone().text());
  assert.deepEqual([f.item().attrs?.amount, f.item().version], [9, 2]);
});

test('a post-state is accepted only for a constrained type, bounded, with declared keys; a policy-read attribute only as declared input', (t) => {
  const { rt, item, reserve } = world(t);
  const consume = (type: string, id: string, action: string, attrs: Record<string, unknown>): unknown =>
    pdp(rt, '/x/v1/tokens/consume', { token: 'not-even-read', action, resource: { type, id }, resourceVersion: 1, attrs }, [], true, 'pep-1');
  const status = (fn: () => unknown, code: number, message: RegExp): void =>
    assert.throws(fn, (e: unknown) => e instanceof HttpError && e.status === code && message.test(e.message));
  status(() => consume('case', 'CASE-14', 'close', { status: 'closed' }), 400, /only for a constrained type/);
  status(() => consume('payment', 'PAY-NEW', 'create', { amount: 9, colour: 'red' }), 400, /attrs\.colour is neither an input/);
  status(() => consume('payment', 'PAY-NEW', 'create', Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`a${i}`, i]))), 400, /at most 64/);
  status(() => consume('payment', 'PAY-NEW', 'create', { amount: 'x'.repeat(9000) }), 400, /bytes/);
  // amount becomes policy-read (governedAttributes): an IVP reading it does not let the command set it
  const s = rt.store.state;
  const governed = { ...s.bundle, schema: { ...s.bundle.schema, resourceTypes: { ...s.bundle.schema.resourceTypes, payment: { ...s.bundle.schema.resourceTypes.payment!, governedAttributes: ['amount'] } } } };
  rt.store.state = { ...s, bundle: governed };
  status(() => consume('payment', 'PAY-NEW', 'create', { amount: 9 }), 403, /read by the policy/);
  assert.equal(rt.store.performed.length, 0, 'nothing reserved');
  // declared as the certified procedure's input, it may be set (validated field by field by C5)
  const declared = { ...governed, clarkWilson: { ...governed.clarkWilson, inputValidators: [{ id: 'create-amount', description: 'A created payment has an amount',
    resourceTypes: ['payment'], actions: ['create'], fields: { amount: { type: 'integer' as const, min: 1 } } }] } };
  assert.doesNotThrow(() => checkPostState(declared, 'payment', 'create', { amount: 9 }));
  assert.throws(() => checkPostState(declared, 'payment', 'release', { amount: 9 }), (e: unknown) => e instanceof HttpError && e.status === 403, 'another procedure does not declare it');
  rt.store.state = s;
  assert.ok(reserve({ amount: 9 }), 'restored: the same post-state is accepted again');
  assert.equal(item().attrs?.amount, 5, 'and applied only once completed');
});
