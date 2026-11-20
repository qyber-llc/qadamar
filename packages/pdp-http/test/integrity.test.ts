// Clark-Wilson completion on the server: IVPs at decision and token consumption (refused and audited), the admin
// IVP run, and two-person certification records of transformation procedures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { pdp } from '../src/pdp.ts';
import { admin } from '../src/admin/index.ts';
import { policyVersion } from '../../core/src/index.ts';
import type { IvpDef, Resource, Subject } from '../../core/src/index.ts';
import { FIXED as FIXED_AT, fixture, required, user, WHY } from './helpers.ts';
import type { Fixture } from './helpers.ts';
import type { Change, Certification } from '../src/store.ts';

const IVP: IvpDef = {
  id: 'payment-consistent', description: 'A payment has a positive amount and a known status', resourceTypes: ['payment'],
  check: { op: 'and', args: [
    { op: 'gt', left: { path: 'resource.attrs.amount' }, right: { value: 0 } },
    { op: 'in', left: { path: 'resource.attrs.status' }, right: { value: ['pending', 'approved', 'released'] } },
  ] },
};
interface Evaluation { decision: boolean; context: { rules: string[]; decision_token?: string } }
const call = (f: Fixture, id: string, method: string, path: string, b: Record<string, unknown> = {}) =>
  admin(f.rt, user(id), method, new URL(`http://x/admin/v1${path}`), b).value;

function withIvp(f: Fixture, amount: number): void {
  const s = f.rt.store.state;
  f.rt.store.state = { ...s, bundle: { ...s.bundle, clarkWilson: { ...s.bundle.clarkWilson, ivps: [IVP] } },
    resources: s.resources.map((r): Resource => r.id === 'PAY-3' ? { ...r, attrs: { ...r.attrs, amount } } : r) };
}
const approve = (f: Fixture): Evaluation => {
  f.rt.sodHistory = 'caller';
  return pdp(f.rt, '/access/v1/evaluation', {
    subject: { type: 'user', id: 'henry' }, action: { name: 'approve' }, resource: { type: 'payment', id: 'PAY-3' },
    context: { network: 'trusted', makerId: 'grace' } }) as Evaluation;
};
/** Console users are PDP subjects with the same id: E4 checks them there. The demo world has lina and omar (no role). */
function certifiers(f: Fixture, ...extra: Subject[]): void {
  const s = f.rt.store.state;
  for (const id of ['lina', 'omar']) required(s.subjects.find((x) => x.id === id));
  f.rt.store.state = { ...s, subjects: [...s.subjects, ...extra] };
}
const consume = (f: Fixture, token: string, attrs?: Record<string, unknown>) => pdp(f.rt, '/x/v1/tokens/consume',
  { token, action: 'approve', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4, ...(attrs ? { attrs } : {}) });

test('an item in an invalid state gets no decision token for a certified command', (t) => {
  const f = fixture(t);
  withIvp(f, -5);
  const d = approve(f);
  assert.equal(d.decision, false);
  assert.deepEqual(d.context.rules, ['CW.IVP.payment-consistent']);
  assert.equal(d.context.decision_token, undefined);
});

test('consumption refuses a proposed state that fails an IVP, audits it, and keeps the token for a valid retry', (t) => {
  const f = fixture(t);
  withIvp(f, 1200);
  const token = required(approve(f).context.decision_token);
  assert.throws(() => consume(f, token, { amount: -5 }), (e: unknown) => e instanceof Error && 'status' in e && e.status === 409);
  const refused = f.rt.audit.records().at(-1);
  assert.equal(refused?.effect, 'deny');
  assert.deepEqual(refused?.rules, ['CW.IVP.payment-consistent']);
  assert.deepEqual(refused?.details, { phase: 'token_consume', state: 'proposed' });
  assert.equal(f.rt.store.performed.length, 0, 'a refused consumption records no performed action');
  assert.throws(() => consume(f, token, { status: 'lost' }), (e: unknown) => e instanceof Error && 'status' in e && e.status === 409);
  assert.throws(() => consume(f, token, [] as unknown as Record<string, unknown>), (e: unknown) => e instanceof Error && 'status' in e && e.status === 400);
  assert.equal((consume(f, token, { amount: 1200, status: 'approved' }) as { ok: boolean }).ok, true);
  assert.equal(f.rt.store.performed.length, 1);
  assert.throws(() => consume(f, token), (e: unknown) => e instanceof Error && 'status' in e && e.status === 409);
});

test('the stored state is re-verified at consumption: a change after issuance refuses the command', (t) => {
  const f = fixture(t);
  withIvp(f, 1200);
  const token = required(approve(f).context.decision_token);
  withIvp(f, 0);
  assert.throws(() => consume(f, token), (e: unknown) => e instanceof Error && 'status' in e && e.status === 409);
  const row = f.rt.audit.records().at(-1);
  assert.equal(row?.effect, 'deny');
  assert.ok(row?.rules?.includes('CW.IVP.payment-consistent'));
});

test('the admin IVP run checks every constrained item, is audited with ids only, and is limited to security roles', (t) => {
  const f = fixture(t);
  assert.deepEqual(call(f, 'lina', 'POST', '/integrity/verify'), { verified: true, checked: 0, policyVersion: (call(f, 'sam', 'GET', '/policy') as { current: { version: string } }).current.version, items: [] });
  withIvp(f, -1);
  const run = call(f, 'sam', 'POST', '/integrity/verify') as { verified: boolean; checked: number; items: unknown[] };
  assert.equal(run.verified, false);
  assert.deepEqual(run.items, [{ ivp: 'payment-consistent', resourceType: 'payment', resource: 'PAY-3', ok: false }]);
  const row = required(f.rt.audit.records().at(-1));
  assert.equal(row.action, 'ivp_run');
  assert.deepEqual(row.rules, ['CW.IVP.payment-consistent']);
  assert.deepEqual(row.details, { checked: 1, failed: [{ ivp: 'payment-consistent', resourceType: 'payment', resource: 'PAY-3' }] });
  assert.throws(() => call(f, 'amira', 'POST', '/integrity/verify'), (e: unknown) => e instanceof Error && 'status' in e && e.status === 403);
});

test('certifying a procedure is a two-person change by a security officer who cannot execute it', (t) => {
  const f = fixture(t);
  certifiers(f);
  const before = call(f, 'omar', 'GET', '/integrity/certifications') as { items: Certification[]; missing: unknown[] };
  assert.deepEqual(before.items, []);
  assert.deepEqual(before.missing, [{ resourceType: 'payment', action: 'create' }, { resourceType: 'payment', action: 'approve' }, { resourceType: 'payment', action: 'release' }]);
  const forbidden = (fn: () => unknown, status = 403): void => assert.throws(fn, (e: unknown) => e instanceof Error && 'status' in e && e.status === status);
  forbidden(() => call(f, 'amira', 'POST', '/changes', { kind: 'certify_tp', payload: { resourceType: 'payment', action: 'approve' }, reason: WHY }));
  forbidden(() => call(f, 'lina', 'POST', '/changes', { kind: 'certify_tp', payload: { resourceType: 'case', action: 'close' }, reason: WHY }), 422);
  forbidden(() => call(f, 'lina', 'POST', '/changes', { kind: 'certify_tp', payload: { resourceType: 'payment', action: 'edit' }, reason: WHY }), 422);
  forbidden(() => call(f, 'lina', 'POST', '/changes', { kind: 'certify_tp', payload: { resourceType: 'payment', action: 'approve', extra: 1 }, reason: WHY }), 422);
  // E4: a security officer who is also the PDP subject holding finance_approver may not certify approve
  forbidden(() => admin(f.rt, { id: 'henry', name: 'henry', roles: ['security_officer'] }, 'POST', new URL('http://x/admin/v1/changes'),
    { kind: 'certify_tp', payload: { resourceType: 'payment', action: 'approve' }, reason: WHY }).value);
  const change = call(f, 'lina', 'POST', '/changes', { kind: 'certify_tp', payload: { resourceType: 'payment', action: 'approve' }, reason: WHY }) as Change;
  assert.equal(change.status, 'pending');
  assert.equal(change.broadens, false);
  forbidden(() => call(f, 'lina', 'POST', `/changes/${change.id}/approve`, { reason: WHY }));
  forbidden(() => admin(f.rt, { id: 'henry', name: 'henry', roles: ['approver'] }, 'POST', new URL(`http://x/admin/v1/changes/${change.id}/approve`), { reason: WHY }).value);
  const applied = call(f, 'omar', 'POST', `/changes/${change.id}/approve`, { reason: WHY }) as Change;
  assert.equal(applied.status, 'applied');
  const after = call(f, 'sam', 'GET', '/integrity/certifications') as { items: Certification[]; missing: unknown[] };
  assert.equal(after.items.length, 1);
  const record = required(after.items[0]);
  assert.match(String(record.fingerprint), /^cw1\.[0-9a-f]{64}$/);
  assert.deepEqual({ ...record, policyVersion: '', fingerprint: '' }, { resourceType: 'payment', action: 'approve', certifiedBy: 'lina', approvedBy: 'omar',
    certifiedAt: f.rt.now(), policyVersion: '', changeId: change.id, reason: WHY, fingerprint: '', current: true });
  assert.deepEqual(after.missing, [{ resourceType: 'payment', action: 'create' }, { resourceType: 'payment', action: 'release' }]);
  forbidden(() => call(f, 'ruth', 'GET', '/integrity/certifications'));
  // decisions are unchanged by a certification record
  assert.equal(approve(f).decision, true);
});

test('consumption without the post-state is refused and audited when the type has IVPs', (t) => {
  const f = fixture(t);
  withIvp(f, 1200);
  const token = required(approve(f).context.decision_token);
  assert.throws(() => consume(f, token), (e: unknown) => e instanceof Error && 'status' in e && e.status === 409);
  const row = required(f.rt.audit.records().at(-1));
  assert.equal(row.effect, 'deny');
  assert.deepEqual(row.rules, ['CW.POST_STATE_REQUIRED']);
  assert.deepEqual(row.details, { phase: 'token_consume', state: 'missing' });
  assert.equal(f.rt.store.performed.length, 0);
  assert.equal((consume(f, token, { status: 'approved' }) as { ok: boolean }).ok, true, 'the token stays usable with a post-state');
});

test('E4 fails closed without a PDP subject, and the engine decides whether the certifier could execute', (t) => {
  const f = fixture(t);
  const propose = (id: string) => () => admin(f.rt, { id, name: id, roles: ['security_officer'] }, 'POST', new URL('http://x/admin/v1/changes'),
    { kind: 'certify_tp', payload: { resourceType: 'payment', action: 'approve' }, reason: WHY }).value;
  const forbidden = (fn: () => unknown): void => assert.throws(fn, (e: unknown) => e instanceof Error && 'status' in e && e.status === 403);
  forbidden(propose('nadia')); // no subject named nadia: refused rather than assumed harmless
  const s = f.rt.store.state;
  const henry = required(s.subjects.find((x) => x.id === 'henry'));
  // no role grants approve, but an ABAC permit on the subject's unit does: rbacGrant alone missed it
  f.rt.store.state = { ...s, bundle: { ...s.bundle, abac: [...s.bundle.abac, { id: 'finance-unit-approves', description: 'Finance staff approve payments',
    effect: 'permit', resourceTypes: ['payment'], actions: ['approve'], when: { op: 'eq', left: { path: 'subject.attrs.unit' }, right: { value: 'Finance' } } }] } };
  certifiers(f, { ...henry, id: 'quinn', roles: [] });
  forbidden(propose('quinn'));
  assert.equal((propose('lina')() as Change).status, 'pending', 'a subject that cannot execute may certify');
});

test('requireCertification: a certified action runs only once its procedure has an approved certification record', (t) => {
  const f = fixture(t);
  certifiers(f);
  const s = f.rt.store.state;
  f.rt.store.state = { ...s, bundle: { ...s.bundle, clarkWilson: { ...s.bundle.clarkWilson, requireCertification: ['payment'] } } };
  const before = approve(f);
  assert.equal(before.decision, false);
  assert.deepEqual(before.context.rules, ['CW.NOT_CERTIFIED']);
  assert.equal(before.context.decision_token, undefined);
  const change = call(f, 'lina', 'POST', '/changes', { kind: 'certify_tp', payload: { resourceType: 'payment', action: 'approve' }, reason: WHY }) as Change;
  call(f, 'omar', 'POST', `/changes/${change.id}/approve`, { reason: WHY });
  const after = approve(f);
  assert.equal(after.decision, true);
  assert.ok(after.context.decision_token);
  // a caller cannot claim a certification: the context field is server-derived
  const s2 = f.rt.store.state;
  f.rt.store.state = { ...s2, certifications: [] };
  const claimed = pdp(f.rt, '/access/v1/evaluation', { subject: { type: 'user', id: 'henry' }, action: { name: 'approve' }, resource: { type: 'payment', id: 'PAY-3' },
    context: { network: 'trusted', makerId: 'grace', certified: [{ resourceType: 'payment', action: 'approve' }] } }) as Evaluation;
  assert.deepEqual(claimed.context.rules, ['CW.NOT_CERTIFIED']);
});

test('the shipped demo world lets the console accounts lina and omar certify every procedure', (t) => {
  const f = fixture(t); // examples/toy-domain as shipped, no added subject
  for (const action of ['create', 'approve', 'release']) {
    const change = call(f, 'lina', 'POST', '/changes', { kind: 'certify_tp', payload: { resourceType: 'payment', action }, reason: WHY }) as Change;
    assert.equal((call(f, 'omar', 'POST', `/changes/${change.id}/approve`, { reason: WHY }) as Change).status, 'applied');
  }
  assert.deepEqual((call(f, 'sam', 'GET', '/integrity/certifications') as { missing: unknown[] }).missing, []);
  assert.equal(approve(f).decision, true, 'the certifiers add no decision of their own');
});

test('a certification binds the procedure it certified: a change to that procedure needs recertifying, another change does not', (t) => {
  const f = fixture(t);
  certifiers(f);
  const s = f.rt.store.state;
  f.rt.store.state = { ...s, bundle: { ...s.bundle, clarkWilson: { ...s.bundle.clarkWilson, requireCertification: ['payment'] } } };
  const certify = (): void => {
    const change = call(f, 'lina', 'POST', '/changes', { kind: 'certify_tp', payload: { resourceType: 'payment', action: 'approve' }, reason: WHY }) as Change;
    assert.equal((call(f, 'omar', 'POST', `/changes/${change.id}/approve`, { reason: WHY }) as Change).status, 'applied');
  };
  const publish = (forbid: { type: string; action: string }): Change => {
    const bundle = f.rt.store.state.bundle;
    const rule = { id: `never-${forbid.type}-${forbid.action}`, description: 'Nobody', effect: 'forbid', resourceTypes: [forbid.type], actions: [forbid.action],
      when: { op: 'eq', left: { path: 'subject.id' }, right: { value: 'nobody' } } };
    const change = call(f, 'amira', 'POST', '/changes', { kind: 'publish_policy', payload: { bundle: { ...bundle, abac: [...bundle.abac, rule] } }, reason: WHY }) as Change;
    assert.equal((call(f, 'omar', 'POST', `/changes/${change.id}/approve`, { reason: WHY }) as Change).status, 'applied');
    return change;
  };
  certify();
  const first = required((f.rt.store.state.certifications ?? [])[0]);
  assert.equal(approve(f).decision, true);
  // a change to another procedure leaves the record in force
  assert.deepEqual(publish({ type: 'case', action: 'read' }).invalidatesCertifications, []);
  assert.equal(approve(f).decision, true, 'an unrelated change does not invalidate the certification');
  // a change to the certified procedure's authorization rules: the preview names the record, the procedure is refused
  const touching = publish({ type: 'payment', action: 'approve' });
  assert.deepEqual(touching.invalidatesCertifications, [{ resourceType: 'payment', action: 'approve', changeId: first.changeId }]);
  const stale = approve(f);
  assert.equal(stale.decision, false);
  assert.deepEqual(stale.context.rules, ['CW.CERTIFICATION_STALE']);
  assert.equal(stale.context.decision_token, undefined);
  const listed = call(f, 'sam', 'GET', '/integrity/certifications') as { items: Array<{ current: boolean }>; missing: unknown[]; stale: unknown[] };
  assert.deepEqual(listed.items.map((c) => c.current), [false]);
  assert.deepEqual(listed.stale, [{ resourceType: 'payment', action: 'approve' }]);
  assert.ok(listed.missing.some((p) => JSON.stringify(p) === JSON.stringify({ resourceType: 'payment', action: 'approve' })));
  certify();
  assert.equal(approve(f).decision, true, 'recertified for the new definition');
  assert.deepEqual((call(f, 'sam', 'GET', '/integrity/certifications') as { stale: unknown[] }).stale, []);
});

test('a certification record of 0.4.0 (no fingerprint) holds only under the policy version it was made for', (t) => {
  const f = fixture(t);
  const s = f.rt.store.state;
  const bundle = { ...s.bundle, clarkWilson: { ...s.bundle.clarkWilson, requireCertification: ['payment'] } };
  const legacy = (policyVersion: string): Certification => ({ resourceType: 'payment', action: 'approve', certifiedBy: 'lina', approvedBy: 'omar',
    certifiedAt: FIXED_AT, policyVersion, changeId: 'c-legacy', reason: WHY });
  f.rt.store.state = { ...s, bundle, certifications: [legacy(policyVersion(bundle))] };
  assert.equal(approve(f).decision, true);
  f.rt.store.state = { ...f.rt.store.state, certifications: [legacy('pv.unrelated')] };
  assert.deepEqual(approve(f).context.rules, ['CW.CERTIFICATION_STALE'], 'an unrelated policy version certifies nothing');
});
