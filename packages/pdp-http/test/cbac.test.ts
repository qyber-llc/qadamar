// CBAC through the PDP's admin plane: the legacy content field (cbac) read as abacContent with a deprecation warning in
// the change, its audit rows and the stored bundle; time-bounded role assignments and tuple windows (notBefore/notAfter)
// through the admin API, with their edges; E4 counting a role assignment that starts later.
import test from 'node:test';
import assert from 'node:assert/strict';
import { DEPRECATED_CONTENT_FIELD, policyVersion, type PolicyBundle, type Subject } from '../../core/src/index.ts';
import { admin } from '../src/admin/index.ts';
import { dueGrants } from '../src/admin/reviews.ts';
import { decideChange, propose } from '../src/admin/changes.ts';
import { HttpError } from '../src/http.ts';
import { pdp } from '../src/pdp.ts';
import { Store } from '../src/store.ts';
import { evaluation, FIXED, fixture, required, user, users, WHY } from './helpers.ts';
import type { Fixture } from './helpers.ts';

const call = (f: Fixture, id: string, method: string, path: string, b: Record<string, unknown> = {}) => admin(f.rt, user(id), method, new URL(`http://x/admin/v1${path}`), b).value;
const status = (code: number) => (e: unknown): boolean => e instanceof HttpError && e.status === code;
const legacyOf = (bundle: PolicyBundle): PolicyBundle => {
  const { abacContent, ...rest } = bundle;
  return { ...rest, cbac: abacContent } as PolicyBundle;
};
interface Answer { decision: boolean; context: { rules: string[] } }
const ask = (f: Fixture, subject: string, resource: string, action = 'read'): Answer => pdp(f.rt, '/access/v1/evaluation', evaluation(subject, resource, action, 'trusted')) as Answer;

test('a legacy bundle is published as abacContent; the change and both audit rows carry the deprecation; both fields are refused', (t) => {
  const f = fixture(t);
  const legacy = legacyOf(f.rt.store.state.bundle);
  const change = propose(f.rt, users.amira, { kind: 'publish_policy', payload: { bundle: legacy }, reason: WHY });
  assert.deepEqual(change.warnings, [DEPRECATED_CONTENT_FIELD]);
  const published = change.payload.bundle as PolicyBundle;
  assert.ok(!Object.hasOwn(published, 'cbac'));
  assert.deepEqual(published.abacContent, f.rt.store.state.bundle.abacContent);
  assert.deepEqual(change.weakensMandatory, []);
  assert.deepEqual(f.rt.audit.records().find((r) => r.action === 'propose')?.details?.warnings, [DEPRECATED_CONTENT_FIELD]);
  decideChange(f.rt, users.omar, change.id, true, { reason: WHY });
  assert.deepEqual(f.rt.audit.records().find((r) => r.action === 'approve')?.details?.warnings, [DEPRECATED_CONTENT_FIELD]);
  assert.ok(!Object.hasOwn(f.rt.store.state.bundle, 'cbac'));
  assert.throws(() => propose(f.rt, users.amira, { kind: 'publish_policy', payload: { bundle: { ...legacy, abacContent: [] } }, reason: WHY }), status(422));
  const modern = propose(f.rt, users.amira, { kind: 'publish_policy', payload: { bundle: { ...f.rt.store.state.bundle, name: 'renamed' } }, reason: WHY });
  assert.equal(modern.warnings, undefined);
});

test('a stored bundle with the legacy field keeps loading, keeps its policy version and still masks content', (t) => {
  const f = fixture(t);
  const legacy = legacyOf(f.rt.store.state.bundle);
  f.rt.store.state = { ...f.rt.store.state, bundle: legacy };
  f.rt.store.save();
  const loaded = new Store(f.dir, 'examples/toy-domain', FIXED);
  assert.ok(Object.hasOwn(loaded.state.bundle, 'cbac'), 'stored as it was');
  assert.equal(policyVersion(loaded.state.bundle), policyVersion(legacy));
  f.rt.store = loaded;
  const read = pdp(f.rt, '/access/v1/evaluation', evaluation('bob', 'CASE-14', 'read', 'trusted')) as { decision: boolean; context: { obligations: { maskClasses: string[] } } };
  assert.equal(read.decision, true);
  assert.deepEqual(read.context.obligations.maskClasses, ['finance.amount']);
});

test('add_tuple takes notBefore/notAfter (legacy validFrom/validTo still accepted) and stores the new names', (t) => {
  const f = fixture(t);
  const base = { object: { type: 'case', id: 'CASE-15' }, relation: 'allocated', subject: { type: 'user', id: 'bob' } };
  const proposeGrant = (window: Record<string, unknown>) => propose(f.rt, users.amira, { kind: 'add_tuple', payload: { ...base, ...window }, reason: WHY });
  for (const bad of [{ notAfter: '2026-12-01T00:00:00Z', validTo: '2026-12-01T00:00:00Z' }, { notBefore: FIXED, validFrom: FIXED, notAfter: '2026-12-01T00:00:00Z' },
    { notBefore: '2026-11-08T10:00:01Z', notAfter: '2026-12-01T00:00:00Z' }, { notAfter: FIXED }, { notAfter: 'soon' }]) {
    assert.throws(() => proposeGrant(bad), status(422), JSON.stringify(bad));
  }
  const legacy = proposeGrant({ validTo: '2026-12-01T00:00:00Z' });
  assert.deepEqual([legacy.payload.notBefore, legacy.payload.notAfter, legacy.payload.validTo], [FIXED, '2026-12-01T00:00:00.000Z', undefined]);
  const change = proposeGrant({ notAfter: '2026-11-20T00:00:00Z' });
  // approval after the end of the window is stale: the grant would never exist
  f.setClock('2026-11-20T00:00:00Z');
  assert.throws(() => decideChange(f.rt, users.omar, change.id, true, { reason: WHY }), status(409));
  f.setClock(FIXED);
  decideChange(f.rt, users.omar, change.id, true, { reason: WHY });
  const tuple = required(f.rt.store.state.tuples.find((x) => x.grantedBy === 'amira'));
  assert.deepEqual([tuple.notBefore, tuple.notAfter, tuple.validFrom, tuple.validTo], [FIXED, '2026-11-20T00:00:00.000Z', undefined, undefined]);
  assert.ok(dueGrants(f.rt).some((g) => g.tupleId === tuple.id && g.validTo === '2026-11-20T00:00:00.000Z'), 'due for review: it ends within 30 days');
  assert.equal(ask(f, 'bob', 'CASE-15').decision, true);
  f.setClock('2026-11-20T00:00:00.000Z');
  assert.equal(ask(f, 'bob', 'CASE-15').decision, true, 'live at exactly notAfter');
  f.setClock('2026-11-20T00:00:00.001Z');
  assert.deepEqual(ask(f, 'bob', 'CASE-15').context.rules, ['NTK.NO_REASON']);
});

test('update_subject sets time-bounded role assignments; the grant ends with its window', (t) => {
  const f = fixture(t);
  const set = (roleAssignments: unknown) => propose(f.rt, users.amira, { kind: 'update_subject', payload: { id: 'lina', set: { roleAssignments } }, reason: WHY });
  for (const bad of [[{ role: 'nobody' }], [{ role: 'viewer', notBefore: '2026-11-09T00:00:00Z' }], [{ role: 'viewer', notAfter: FIXED }],
    [{ role: 'viewer', notAfter: '2026-12-01' }], [{ role: 'viewer', extra: true }], 'viewer', Array.from({ length: 257 }, () => ({ role: 'viewer' }))]) {
    assert.throws(() => set(bad), status(422), JSON.stringify(bad).slice(0, 80));
  }
  assert.equal(ask(f, 'lina', 'CASE-18').decision, false);
  const change = set([{ role: 'viewer', notBefore: '2026-11-01T00:00:00Z', notAfter: '2026-11-09T00:00:00Z' }]);
  assert.equal(change.broadens, true);
  decideChange(f.rt, users.omar, change.id, true, { reason: WHY });
  assert.equal(ask(f, 'lina', 'CASE-18').decision, true);
  f.setClock('2026-11-09T00:00:00.001Z');
  assert.deepEqual(ask(f, 'lina', 'CASE-18').context.rules, ['RBAC.NOT_ELIGIBLE'], '1 ms after notAfter');
  // a policy that drops a role still assigned for a time is refused like one that drops a held role
  const bundle = f.rt.store.state.bundle;
  const { viewer: dropped, ...roles } = bundle.rbac.roles;
  assert.ok(dropped);
  const without = { ...bundle, rbac: { ...bundle.rbac, roles: Object.fromEntries(Object.entries(roles).map(([k, v]) => [k, { ...v, inherits: (v.inherits ?? []).filter((r) => r !== 'viewer') }])) } };
  assert.throws(() => propose(f.rt, users.amira, { kind: 'publish_policy', payload: { bundle: without }, reason: WHY }), (e: unknown) => e instanceof HttpError && /Role is still in use/.test(e.message));
});

test('E4: a role assignment that starts later counts against the certifier; one that already ended does not', (t) => {
  const f = fixture(t);
  const assign = (window: Record<string, string>) => {
    const s = f.rt.store.state;
    f.rt.store.state = { ...s, subjects: s.subjects.map((x): Subject => x.id === 'lina' ? { ...x, roleAssignments: [{ role: 'finance_approver', ...window }] } : x) };
  };
  const certify = () => call(f, 'lina', 'POST', '/changes', { kind: 'certify_tp', payload: { resourceType: 'payment', action: 'approve' }, reason: WHY });
  assign({ notBefore: '2026-12-01T00:00:00Z' });
  assert.throws(certify, status(403));
  assign({ notAfter: '2026-11-01T00:00:00Z' });
  assert.equal((certify() as { status: string }).status, 'pending');
});

test('SCIM updates keep the time-bounded role assignments an administrator set', (t) => {
  const f = fixture(t);
  const s = f.rt.store.state;
  f.rt.store.state = { ...s, subjects: s.subjects.map((x): Subject => x.id === 'alice' ? { ...x, roleAssignments: [{ role: 'viewer', notAfter: '2026-12-01T00:00:00Z' }] } : x) };
  const alice = required(f.rt.store.state.subjects.find((x) => x.id === 'alice'));
  const { roleAssignments: ignored, ...scimView } = alice;
  const change = propose(f.rt, { id: 'scim', name: 'scim', roles: ['scim_provisioner'] }, { kind: 'scim_subjects', payload: { subjects: [{ ...scimView, active: false }] }, reason: WHY });
  assert.deepEqual((change.payload.subjects as Subject[])[0]?.roleAssignments, [{ role: 'viewer', notAfter: '2026-12-01T00:00:00Z' }]);
});
