import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pdp } from '../src/pdp.ts';
import { parseSodHistory, sodInput } from '../src/runtime.ts';
import { atomic, Store } from '../src/store.ts';
import type { Subject } from '../../core/src/index.ts';
import { evaluation, FIXED, fixture, required } from './helpers.ts';

interface Evaluation { decision: boolean; context: { rules: string[]; decision_token?: string } }

test('consumed certified actions drive SoD for makers, delegates and restarts', (t) => {
  const { rt, dir } = fixture(t);
  rt.sodHistory = 'caller';
  const payment = required(rt.store.state.resources.find((r) => r.id === 'PAY-3'));
  const alice = required(rt.store.state.subjects.find((s) => s.id === 'alice'));
  const delegate: Subject = { ...alice, type: 'agent', id: 'alice-delegate', clearance: 1, roles: ['finance_approver'], attrs: { delegatedBy: 'alice' } };
  rt.store.state = {
    ...rt.store.state,
    subjects: [
      ...rt.store.state.subjects.map((s) => s.id === 'alice' || s.id === 'bob'
        ? { ...s, clearance: 1 as const, roles: ['finance_clerk', 'finance_approver'] } : s),
      delegate,
    ],
    resources: [...rt.store.state.resources, { ...payment, id: 'PAY-SOD', owner: 'alice' }],
  };
  const decide = (id: string, action: string, type = 'user', context?: Record<string, unknown>): Evaluation =>
    pdp(rt, '/access/v1/evaluation', {
      ...evaluation(id, 'PAY-SOD', action), subject: { type, id }, ...(context ? { context } : {}),
    }) as Evaluation;

  const created = decide('alice', 'create');
  assert.equal(created.decision, true);
  const token = required(created.context.decision_token);
  const consumed = pdp(rt, '/x/v1/tokens/consume', {
    token, action: 'create', resource: { type: 'payment', id: 'PAY-SOD' }, resourceVersion: payment.version,
  }) as { ok: boolean; reservation: string };
  assert.equal(consumed.ok, true);
  assert.deepEqual(rt.store.performed, [{
    id: consumed.reservation, subject: { type: 'user', id: 'alice' }, resource: { type: 'payment', id: 'PAY-SOD' }, action: 'create', at: FIXED,
  }]);

  const approvedByAlice = decide('alice', 'approve', 'user', { priorActions: [] });
  assert.equal(approvedByAlice.decision, false);
  assert.ok(approvedByAlice.context.rules.includes('SOD.SELF_APPROVAL'));
  assert.ok(approvedByAlice.context.rules.includes('SOD.create-vs-approve'));
  const releasedByAlice = decide('alice', 'release');
  assert.equal(releasedByAlice.decision, false);
  assert.ok(releasedByAlice.context.rules.includes('SOD.create-vs-release'));

  const approvedByDelegate = decide('alice-delegate', 'approve', 'agent');
  assert.equal(approvedByDelegate.decision, false);
  assert.ok(approvedByDelegate.context.rules.includes('SOD.SELF_APPROVAL'));
  assert.ok(approvedByDelegate.context.rules.includes('SOD.create-vs-approve'));

  for (const action of ['approve', 'release']) {
    const allowed = decide('bob', action);
    assert.equal(allowed.decision, true, `bob can ${action} without supplying a maker or history`);
    assert.ok(allowed.context.decision_token);
  }
  const mismatch = decide('bob', 'approve', 'user', { makerId: 'grace' });
  assert.equal(mismatch.decision, false);
  assert.deepEqual(mismatch.context.rules, ['SOD.MAKER_MISMATCH']);

  rt.store = new Store(dir, resolve('examples/toy-domain'), FIXED);
  assert.equal(rt.store.performed.length, 1);
  assert.equal(decide('alice', 'release').decision, false);
  assert.equal(decide('bob', 'approve').decision, true);
});

test('state files without performed-action history still load', (t) => {
  const { dir } = fixture(t);
  const file = resolve(dir, 'state.json');
  const disk = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  delete disk.performed;
  atomic(file, disk);
  const loaded = new Store(dir, resolve('examples/toy-domain'), FIXED);
  assert.deepEqual(loaded.performed, []);
  loaded.save();
  assert.deepEqual((JSON.parse(readFileSync(file, 'utf8')) as { performed: unknown[] }).performed, []);
});

test('an action done by a delegate counts for the person it acted for', (t) => {
  const { rt } = fixture(t);
  const payment = required(rt.store.state.resources.find((r) => r.id === 'PAY-3'));
  const alice = required(rt.store.state.subjects.find((s) => s.id === 'alice'));
  const roles = ['finance_clerk', 'finance_approver'];
  const delegate: Subject = { ...alice, type: 'agent', id: 'alice-delegate', clearance: 1, roles, attrs: { delegatedBy: 'alice' } };
  rt.store.state = {
    ...rt.store.state,
    subjects: [...rt.store.state.subjects.map((s) => s.id === 'alice' || s.id === 'bob' ? { ...s, clearance: 1 as const, roles } : s), delegate],
    resources: [...rt.store.state.resources, { ...payment, id: 'PAY-DLG', owner: 'alice' }],
  };
  const decide = (id: string, action: string, type = 'user', context?: Record<string, unknown>): Evaluation =>
    pdp(rt, '/access/v1/evaluation', { ...evaluation(id, 'PAY-DLG', action), subject: { type, id }, ...(context ? { context } : {}) }) as Evaluation;
  const created = decide('alice-delegate', 'create', 'agent');
  assert.equal(created.decision, true);
  pdp(rt, '/x/v1/tokens/consume', { token: required(created.context.decision_token), action: 'create', resource: { type: 'payment', id: 'PAY-DLG' }, resourceVersion: payment.version });
  assert.deepEqual(rt.store.performed[0]?.onBehalfOf, [{ type: 'user', id: 'alice' }]);
  const byAlice = decide('alice', 'approve');
  assert.equal(byAlice.decision, false, 'alice cannot approve what her delegate created for her');
  assert.ok(byAlice.context.rules.includes('SOD.SELF_APPROVAL'));
  assert.ok(byAlice.context.rules.includes('SOD.create-vs-approve'));
  assert.equal(decide('alice', 'release').decision, false);
  assert.equal(decide('bob', 'approve').decision, true);
  assert.equal(decide('bob', 'approve', 'user', { makerId: 'alice' }).decision, true, 'naming the principal as maker is not a mismatch');
  assert.equal(decide('bob', 'approve', 'user', { makerId: 'grace' }).decision, true, 'server history ignores the contradictory caller claim');
});

function payments(t: Parameters<typeof fixture>[0]) {
  const f = fixture(t);
  const { rt } = f;
  const payment = required(rt.store.state.resources.find((r) => r.id === 'PAY-3'));
  rt.store.state = {
    ...rt.store.state,
    subjects: rt.store.state.subjects.map((s) => s.id === 'alice' || s.id === 'bob' ? { ...s, clearance: 1 as const, roles: ['finance_clerk', 'finance_approver'] } : s),
    resources: [...rt.store.state.resources, { ...payment, id: 'PAY-NEW', owner: 'alice' }, { ...payment, id: 'PAY-DONE', owner: 'alice' }],
  };
  const decide = (id: string, resource: string, action: string, context?: Record<string, unknown>): Evaluation =>
    pdp(rt, '/access/v1/evaluation', { ...evaluation(id, resource, action), ...(context ? { context } : {}) }) as Evaluation;
  const perform = (id: string, resource: string, action: string): void => {
    const token = required(decide(id, resource, action).context.decision_token);
    pdp(rt, '/x/v1/tokens/consume', { token, action, resource: { type: 'payment', id: resource }, resourceVersion: payment.version });
  };
  return { rt, decide, perform };
}
const denies = (e: Evaluation, rule: string): void => { assert.equal(e.decision, false); assert.ok(e.context.rules.includes(rule), `${rule} in ${e.context.rules.join(', ')}`); };

test('SOD_HISTORY=caller (explicit compatibility opt-in): without server history, caller-supplied maker and prior actions are taken as given', (t) => {
  const { rt, decide } = payments(t);
  rt.sodHistory = 'caller';
  assert.equal(decide('bob', 'PAY-NEW', 'approve', { makerId: 'alice' }).decision, true);
  denies(decide('bob', 'PAY-NEW', 'approve'), 'SOD.MAKER_UNKNOWN');
  denies(decide('alice', 'PAY-NEW', 'approve', { makerId: 'alice' }), 'SOD.SELF_APPROVAL');
  denies(decide('alice', 'PAY-NEW', 'release', { priorActions: ['create'] }), 'SOD.create-vs-release');
  // the permissive side: a caller that lies about the maker is believed
  assert.equal(decide('alice', 'PAY-NEW', 'approve', { makerId: 'bob' }).decision, true);
});

test('SOD_HISTORY defaults to server: constrained actions ignore caller makerId and priorActions; no history means maker unknown', (t) => {
  const { rt, decide, perform } = payments(t);
  assert.equal(rt.sodHistory, undefined, 'the runtime default applies even without an explicit option');
  // no recorded history on PAY-NEW: the claimed maker is ignored, so the two-person rule fails closed
  denies(decide('bob', 'PAY-NEW', 'approve', { makerId: 'alice' }), 'SOD.MAKER_UNKNOWN');
  denies(decide('alice', 'PAY-NEW', 'approve', { makerId: 'bob' }), 'SOD.MAKER_UNKNOWN');
  // ...and the conflict sets see an empty history whatever the caller asserts
  assert.equal(decide('alice', 'PAY-NEW', 'release', { priorActions: ['create'] }).decision, true);
  // with recorded history, only the server's maker and actions count
  perform('alice', 'PAY-DONE', 'create');
  const bob = decide('bob', 'PAY-DONE', 'approve', { makerId: 'grace' });
  assert.equal(bob.decision, true, 'a contradictory caller maker is ignored, not a mismatch');
  assert.ok(!bob.context.rules.includes('SOD.MAKER_MISMATCH'));
  for (const context of [undefined, { makerId: 'bob', priorActions: [] }]) {
    const alice = decide('alice', 'PAY-DONE', 'approve', context);
    denies(alice, 'SOD.SELF_APPROVAL'); denies(alice, 'SOD.create-vs-approve');
    denies(decide('alice', 'PAY-DONE', 'release', context), 'SOD.create-vs-release');
  }
  assert.equal(decide('bob', 'PAY-DONE', 'release', { priorActions: ['create'] }).decision, true, 'a false self-incrimination is ignored too');
});

test('SOD_HISTORY=server leaves unconstrained actions and their context untouched', (t) => {
  const { rt } = payments(t);
  rt.sodHistory = 'server';
  const bundle = rt.store.state.bundle;
  const ctx = { now: FIXED, network: 'trusted' as const, makerId: 'alice', priorActions: ['create'] };
  assert.deepEqual(sodInput(rt, bundle, 'case', 'read', ctx), ctx);
  assert.deepEqual(sodInput(rt, bundle, 'payment', 'approve', ctx), { now: FIXED, network: 'trusted' });
  assert.deepEqual(sodInput(rt, bundle, 'payment', 'create', ctx), { now: FIXED, network: 'trusted' });
  assert.deepEqual(sodInput(rt, bundle, 'payment', 'constructor', ctx), ctx);
  rt.sodHistory = 'caller';
  assert.deepEqual(sodInput(rt, bundle, 'payment', 'approve', ctx), ctx);
  assert.equal(parseSodHistory(undefined), undefined);
  assert.equal(parseSodHistory('server'), 'server');
  assert.throws(() => parseSodHistory('strict'), /SOD_HISTORY/);
});
