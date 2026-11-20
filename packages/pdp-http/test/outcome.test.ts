// A consumed decision token reserves the certified action; the PEP reports whether it ran. Separation of duty counts a
// reservation while pending and once completed, never once failed; the report is once per reservation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pdp } from '../src/pdp.ts';
import { admin } from '../src/admin/index.ts';
import { HttpError } from '../src/http.ts';
import { Store } from '../src/store.ts';
import { evaluation, FIXED, fixture, required, user } from './helpers.ts';

interface Evaluation { decision: boolean; context: { rules: string[]; decision_token?: string } }
interface Consumed { ok: true; reservation: string }

function world(t: Parameters<typeof fixture>[0], sodHistory?: 'server') {
  const f = fixture(t);
  const { rt } = f;
  if (sodHistory) rt.sodHistory = sodHistory;
  const payment = required(rt.store.state.resources.find((r) => r.id === 'PAY-3'));
  rt.store.state = {
    ...rt.store.state,
    subjects: rt.store.state.subjects.map((s) => s.id === 'alice' || s.id === 'bob' ? { ...s, clearance: 1 as const, roles: ['finance_clerk', 'finance_approver'] } : s),
    resources: [...rt.store.state.resources, { ...payment, id: 'PAY-NEW', owner: 'alice' }],
  };
  const decide = (id: string, action: string, context?: Record<string, unknown>): Evaluation =>
    pdp(rt, '/access/v1/evaluation', { ...evaluation(id, 'PAY-NEW', action), ...(context ? { context } : {}) }) as Evaluation;
  const reserve = (id: string, action: string, pep?: string): Consumed => {
    const token = required(decide(id, action).context.decision_token);
    return pdp(rt, '/x/v1/tokens/consume', { token, action, resource: { type: 'payment', id: 'PAY-NEW' }, resourceVersion: payment.version }, [], true, pep) as Consumed;
  };
  const report = (reservation: string, outcome: string, pep?: string): unknown => pdp(rt, '/x/v1/tokens/outcome', { reservation, outcome }, [], true, pep);
  return { ...f, decide, reserve, report };
}
const status = (fn: () => unknown, code: number): void => assert.throws(fn, (e: unknown) => e instanceof HttpError && e.status === code);

test('a failed action stops counting for separation of duty once its failure is reported', (t) => {
  const { rt, decide, reserve, report } = world(t);
  const { reservation } = reserve('alice', 'create');
  assert.equal(decide('alice', 'release').decision, false, 'pending: the reservation counts');
  assert.deepEqual(report(reservation, 'failed'), { ok: true, reservation, outcome: 'failed' });
  const row = required(rt.audit.records().at(-1));
  assert.deepEqual(row.rules, ['GATE.ACTION_FAILED']);
  assert.deepEqual(row.details, { phase: 'outcome', reservation, outcome: 'failed', reservedAt: FIXED });
  assert.equal(row.subject, 'alice'); assert.equal(row.action, 'create');
  assert.equal(decide('alice', 'release').decision, true, 'the create never happened: alice may release');
});

test('a completed action keeps counting, survives a restart, and its report is idempotent; another outcome is refused', (t) => {
  const { rt, dir, decide, reserve, report } = world(t);
  const { reservation } = reserve('alice', 'create');
  assert.deepEqual(report(reservation, 'completed'), { ok: true, reservation, outcome: 'completed' });
  assert.deepEqual(rt.audit.records().at(-1)?.rules, ['GATE.ACTION_COMPLETED']);
  const audited = rt.audit.records().length;
  assert.deepEqual(report(reservation, 'completed'), { ok: true, reservation, outcome: 'completed' }, 'the same report again: same answer');
  assert.equal(rt.audit.records().length, audited, 'and nothing recorded twice');
  status(() => report(reservation, 'failed'), 409);
  assert.deepEqual(rt.audit.records().at(-1)?.rules, ['GATE.OUTCOME_CONFLICT']);
  assert.equal(decide('alice', 'release').decision, false, 'a completed create still forbids alice to release');
  const state = rt.store.state;
  rt.store = new Store(dir, resolve('examples/toy-domain'), FIXED);
  rt.store.state = state;
  assert.equal(rt.store.performed[0]?.outcome, 'completed');
  status(() => report(reservation, 'failed'), 409);
  assert.equal(decide('alice', 'release').decision, false);
});

test('reports are bound to the consuming credential and to a known reservation, with a valid outcome', (t) => {
  const { reserve, report } = world(t);
  const { reservation } = reserve('alice', 'create', 'cred-a');
  status(() => report(reservation, 'failed', 'cred-b'), 404);
  status(() => report(reservation, 'failed'), 404);
  status(() => report('no-such-reservation', 'failed', 'cred-a'), 404);
  status(() => report(reservation, 'done', 'cred-a'), 400);
  status(() => report('x'.repeat(65), 'failed', 'cred-a'), 400);
  assert.deepEqual(report(reservation, 'failed', 'cred-a'), { ok: true, reservation, outcome: 'failed' });
});

test('SOD_HISTORY=server: a pending reservation makes its maker known, so a second maker cannot race past the two-person rule', (t) => {
  const { decide, reserve, report } = world(t, 'server');
  const { reservation } = reserve('alice', 'create');
  const self = decide('alice', 'approve');
  assert.equal(self.decision, false);
  assert.ok(self.context.rules.includes('SOD.SELF_APPROVAL'), self.context.rules.join());
  assert.equal(decide('bob', 'approve').decision, true, 'the checker is someone else');
  report(reservation, 'failed');
  assert.deepEqual(decide('bob', 'approve').context.rules, ['SOD.MAKER_UNKNOWN'], 'nothing was created: no maker to approve for');
});

test('reservations without an outcome are listed for reconciliation until reported', (t) => {
  const { rt, reserve, report } = world(t);
  const first = reserve('alice', 'create', 'cred-a');
  const list = () => (admin(rt, user('sam'), 'GET', new URL('http://x/admin/v1/integrity/reservations'), {}).value as { items: Array<Record<string, unknown>> }).items;
  assert.deepEqual(list(), [{ reservation: first.reservation, subject: { type: 'user', id: 'alice' }, resource: { type: 'payment', id: 'PAY-NEW' },
    action: 'create', reservedAt: FIXED, pep: 'cred-a' }]);
  assert.throws(() => admin(rt, user('ruth'), 'GET', new URL('http://x/admin/v1/integrity/reservations'), {}), (e: unknown) => e instanceof HttpError && e.status === 403);
  report(first.reservation, 'completed', 'cred-a');
  assert.deepEqual(list(), []);
});

test('an outcome that arrives before its reservation (another node consumed it) is applied when the reservation does', (t) => {
  const { rt } = world(t);
  const reservation = { id: 'r-1', subject: { type: 'user', id: 'alice' }, resource: { type: 'payment', id: 'PAY-NEW' }, action: 'create', at: FIXED };
  rt.store.addPerformed([{ ref: 'r-1', outcome: 'failed', at: FIXED }]);
  assert.equal(rt.store.performed.length, 0);
  rt.store.addPerformed([reservation]);
  assert.deepEqual(rt.store.performed, [{ ...reservation, outcome: 'failed', outcomeAt: FIXED }]);
  rt.store.addPerformed([{ ...reservation, id: 'r-2' }, { ref: 'r-2', outcome: 'completed', at: FIXED }]);
  assert.equal(rt.store.performed[1]?.outcome, 'completed', 'both in one batch');
});
