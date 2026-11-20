import test from 'node:test';
import assert from 'node:assert/strict';
import { admin } from '../src/admin/index.ts';
import { HttpError } from '../src/http.ts';
import { propose, decideChange, scopedImpact, impact } from '../src/admin/changes.ts';
import { Store } from '../src/store.ts';
import { fixture, users, user as userById, required, WHY, FIXED, evaluation, digestMutations } from './helpers.ts';
import { pdp } from '../src/pdp.ts';
import type { Change } from '../src/store.ts';
import type { Runtime } from '../src/runtime.ts';

const call = (rt: Runtime, user: string, path: string, method = 'GET', b: Record<string, unknown> = {}): unknown =>
  admin(rt, userById(user), method, new URL(`http://localhost/admin/v1${path}`), b).value;
const forbidden = (e: unknown): boolean => e instanceof HttpError && e.status === 403;
const unprocessable = (e: unknown): boolean => e instanceof HttpError && e.status === 422;
const grant = (): Record<string, unknown> => ({ kind: 'add_tuple', reason: WHY, payload: {
  object: { type: 'case', id: 'CASE-15' }, relation: 'allocated', subject: { type: 'user', id: 'bob' }, validTo: '2026-12-08T10:00:00Z',
} });

test('two-person flow evaluates the affected cells, applies and persists with maker/checker audit', (t) => {
  const { rt, dir } = fixture(t);
  const before = pdp(rt, '/access/v1/evaluation', evaluation('bob', 'CASE-15')) as { decision: boolean };
  assert.equal(before.decision, false);
  const c = call(rt, 'amira', '/changes', 'POST', grant()) as Change;
  assert.equal(c.status, 'pending'); assert.equal(c.broadens, true); assert.equal(c.impact.evaluated, 30);
  assert.ok(c.impact.gained.some((x) => x.subjectType === 'user' && x.subject === 'bob' && x.resourceType === 'case' && x.resource === 'CASE-15' && x.action === 'read'));
  assert.equal(c.stateDigest, rt.store.digest());
  const approved = call(rt, 'omar', `/changes/${c.id}/approve`, 'POST', { reason: WHY }) as Change;
  assert.equal(approved.status, 'applied'); assert.equal(approved.checkerId, 'omar');
  assert.equal((pdp(rt, '/access/v1/evaluation', evaluation('bob', 'CASE-15')) as { decision: boolean }).decision, true);
  assert.equal(rt.audit.verify().verified, true);
  const row = rt.audit.records().find((r) => r.action === 'approve');
  assert.deepEqual(row?.details, { changeId: c.id, makerId: 'amira', checkerId: 'omar', kind: 'add_tuple' });
  const loaded = new Store(dir, 'examples/toy-domain', FIXED);
  assert.equal(required(loaded.changes[0]).status, 'applied');
  assert.ok(loaded.state.tuples.some((x) => x.grantedBy === 'amira'));
});
test('queued proposals remain valid through other proposals; applied state yields stale 409', (t) => {
  const { rt } = fixture(t);
  const a = propose(rt, users.amira, grant());
  const b = propose(rt, users.amira, { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY });
  assert.equal(a.stateDigest, b.stateDigest);
  decideChange(rt, users.omar, b.id, true, { reason: WHY });
  assert.throws(() => decideChange(rt, users.omar, a.id, true, { reason: WHY }), (e) => e instanceof HttpError && e.status === 409 && e.code === 'stale');
  const rejected = decideChange(rt, users.omar, a.id, false, { reason: WHY });
  assert.equal(rejected.status, 'rejected');
});
test('every change including pure narrowing waits for independent approval', (t) => {
  const { rt } = fixture(t);
  const c = propose(rt, users.lina, { kind: 'remove_tuple', payload: { tupleId: 'seed-4' }, reason: WHY });
  assert.equal(c.broadens, false); assert.equal(c.status, 'pending');
  assert.ok(rt.store.state.tuples.some((x) => x.id === 'seed-4'));
  assert.throws(() => decideChange(rt, users.lina, c.id, true, { reason: WHY }), (e) => e instanceof HttpError && e.code === 'self_approval');
  // Even a principal holding both capabilities can never approve their own proposal.
  const both = { ...users.omar, roles: ['approver', 'access_admin'] };
  const own = propose(rt, both, grant());
  assert.throws(() => decideChange(rt, users.omar, own.id, true, { reason: WHY }), forbidden);
});
test('role matrix: read access, simulator, proposals, approvals, audit and reviews', (t) => {
  const { rt } = fixture(t);
  for (const user of Object.keys(users)) for (const path of ['/overview', '/schema', '/policy', '/subjects', '/resources', '/tuples']) assert.ok(call(rt, user, path));
  for (const user of ['sam', 'omar']) assert.throws(() => call(rt, user, '/changes', 'POST', grant()), forbidden);
  assert.throws(() => call(rt, 'sam', '/simulate/what-can', 'POST', { subjectId: 'bob', action: 'read', network: 'trusted' }), forbidden);
  assert.throws(() => call(rt, 'amira', '/audit'), forbidden);
  assert.throws(() => call(rt, 'omar', '/reviews'), forbidden);
  assert.ok(call(rt, 'sam', '/audit/verify'));
  const policyOnly = { id: 'writer', name: 'writer', roles: ['policy_author'] };
  assert.throws(() => propose(rt, policyOnly, grant()), forbidden);
  assert.equal(propose(rt, policyOnly, { kind: 'publish_policy', payload: { bundle: rt.store.state.bundle }, reason: WHY }).status, 'pending');
});
test('resource owner mapped to carol (RESOURCE_OWNERS) sees only her scope, cannot target other resources, and has scoped counts', (t) => {
  const { rt } = fixture(t);
  const resources = call(rt, 'ruth', '/resources') as { items: { id: string; owner: string }[] };
  assert.equal(resources.items.length, 5); assert.ok(resources.items.every((r) => r.owner === 'carol'));
  const tuples = call(rt, 'ruth', '/tuples') as { items: { object: { id: string } }[] };
  assert.ok(tuples.items.every((x) => resources.items.some((r) => r.id === x.object.id)));
  assert.throws(() => call(rt, 'ruth', '/explain', 'POST', { subjectId: 'bob', resourceId: 'CASE-7', action: 'read' }), (e) => e instanceof HttpError && e.status === 404);
  assert.throws(() => call(rt, 'ruth', '/changes', 'POST', grant()), forbidden);
  assert.throws(() => call(rt, 'ruth', '/changes', 'POST', { kind: 'remove_tuple', payload: { tupleId: 'seed-10' }, reason: WHY }), (e) => e instanceof HttpError && e.status === 404);
  const own = call(rt, 'ruth', '/changes', 'POST', { kind: 'remove_tuple', payload: { tupleId: 'seed-4' }, reason: WHY }) as Change;
  assert.ok(own.impact.lost.every((x) => resources.items.some((r) => r.id === x.resource)));
  const overview = call(rt, 'ruth', '/overview') as { counts: { activeBreakGlass: number } };
  assert.equal(overview.counts.activeBreakGlass, 0);
});
test('change validation: reasons, 90-day grants, strict patch fields and bundle details', (t) => {
  const { rt } = fixture(t);
  assert.throws(() => propose(rt, users.amira, { ...grant(), reason: 'short' }), unprocessable);
  const original = grant().payload as Record<string, unknown>;
  for (const validTo of [undefined, '2027-12-31', 'garbage', '2026-11-01']) assert.throws(() => propose(rt, users.amira, { ...grant(), payload: { ...original, validTo } }), unprocessable);
  assert.throws(() => propose(rt, users.amira, { kind: 'update_subject', payload: { id: 'bob', set: { clearance: 99 } }, reason: WHY }), unprocessable);
  assert.throws(() => propose(rt, users.amira, { kind: 'update_subject', payload: { id: 'bob', set: { attrs: { delegatedBy: 'alice' } } }, reason: WHY }), unprocessable);
  assert.throws(() => propose(rt, users.amira, { kind: 'publish_policy', payload: { bundle: {} }, reason: WHY }), (e) => e instanceof HttpError && e.status === 422 && !!e.details?.length);
  const published = propose(rt, users.amira, { kind: 'publish_policy', payload: { bundle: { ...rt.store.state.bundle, name: 'reviewed-policy' } }, reason: WHY });
  decideChange(rt, users.omar, published.id, true, { reason: WHY });
  assert.equal(rt.store.history.at(-1)?.publishedBy, 'amira'); assert.equal(rt.store.history.at(-1)?.approvedBy, 'omar');
});
test('simulator routes return metadata, relation paths and impact without storing a change', (t) => {
  const { rt } = fixture(t);
  const what = call(rt, 'amira', '/simulate/what-can', 'POST', { subjectId: 'bob', action: 'read', network: 'trusted' }) as { items: unknown[] };
  assert.equal(what.items.length, 8);
  const who = call(rt, 'omar', '/simulate/who-can', 'POST', { resourceId: 'CASE-14', action: 'read', network: 'trusted' }) as { items: unknown[] };
  assert.equal(who.items.length, 12);
  const explain = call(rt, 'amira', '/explain', 'POST', { subjectId: 'bob', resourceId: 'CASE-7', action: 'read', network: 'trusted' }) as { decision: boolean; rules: string[] };
  assert.equal(explain.decision, false); assert.ok(explain.rules.includes('BLP.NO_READ_UP'));
  const count = rt.store.changes.length;
  const delta = call(rt, 'omar', '/simulate/impact', 'POST', grant()) as { evaluated: number };
  assert.equal(delta.evaluated, 30); assert.equal(rt.store.changes.length, count);
});
test('access matrix evaluates every subject and resource layer by layer', (t) => {
  const { rt } = fixture(t);
  type Cell = { subject: string; resource: string; applicable: boolean; decision?: boolean; layers?: Record<string, { o: string; rules: string[] }> };
  const m = call(rt, 'amira', '/simulate/matrix', 'POST', { action: 'read', network: 'trusted' }) as { subjects: unknown[]; resources: unknown[]; cells: Cell[]; layers: string[] };
  assert.deepEqual(m.layers, ['rights', 'clearance', 'needToKnow', 'conditions', 'content', 'context', 'controls']);
  assert.equal(m.cells.length, m.subjects.length * m.resources.length);
  const at = (s: string, r: string): Cell => required(m.cells.find((c) => c.subject === s && c.resource === r));
  const bob7 = at('bob', 'CASE-7');
  assert.equal(bob7.layers?.context?.o, 'none');
  assert.equal(bob7.decision, false); assert.equal(bob7.layers?.rights?.o, 'pass');
  assert.equal(bob7.layers?.clearance?.o, 'deny'); assert.equal(bob7.layers?.needToKnow?.o, 'deny');
  assert.equal(at('bob', 'CASE-14').layers?.content?.o, 'obligation'); // finance amounts masked
  assert.equal(at('grace', 'CASE-11').layers?.rights?.o, 'deny');
  assert.equal(at('dan', 'CASE-12').layers?.needToKnow?.o, 'obligation'); // break-glass: notify and review
  assert.equal(at('assistant-1', 'CASE-7').layers?.controls?.o, 'none'); // the delegator's clearance is clearance, not a control
  const ex = call(rt, 'amira', '/simulate/matrix', 'POST', { action: 'export', network: 'trusted' }) as { cells: Cell[] };
  assert.equal(required(ex.cells.find((c) => c.subject === 'bob' && c.resource === 'CASE-15')).layers?.content?.o, 'deny'); // IBAN never exported
  assert.equal(required(ex.cells.find((c) => c.resource === 'FOLDER-A')).applicable, false);
  assert.throws(() => call(rt, 'sam', '/simulate/matrix', 'POST', { action: 'read' }), forbidden);
});
test('access review certification and revocation create pending changes', (t) => {
  const { rt } = fixture(t);
  rt.store.state = { ...rt.store.state, tuples: rt.store.state.tuples.map((t) => t.id === 'seed-4' ? { ...t, validTo: '2026-12-01T10:00:00Z' } : t) };
  assert.ok((call(rt, 'lina', '/reviews') as { items: unknown[] }).items.length);
  const c = call(rt, 'ruth', '/reviews/seed-4', 'POST', { decision: 'certify', newValidTo: '2027-01-15T10:00:00Z', reason: WHY }) as Change;
  assert.equal(c.status, 'pending'); assert.equal(c.kind, 'add_tuple');
  const revoked = call(rt, 'ruth', '/reviews/seed-4', 'POST', { decision: 'revoke', reason: WHY }) as Change;
  assert.equal(revoked.status, 'pending'); assert.equal(revoked.kind, 'remove_tuple');
});


test('access reviews and the matrix show time-bound role assignments with their windows', (t) => {
  const { rt } = fixture(t);
  const soon = { role: 'viewer', notBefore: '2026-11-01T00:00:00Z', notAfter: '2026-11-20T00:00:00Z' };
  rt.store.state = { ...rt.store.state, subjects: rt.store.state.subjects.map((s) => s.id === 'frank'
    ? { ...s, roleAssignments: [soon, { role: 'investigator', notAfter: '2027-06-01T00:00:00Z' }, { role: 'viewer', notAfter: '2026-11-01T00:00:00Z' }] } : s) };
  const listed = call(rt, 'lina', '/reviews') as { roleAssignments?: unknown[] };
  assert.deepEqual(listed.roleAssignments, [{ subject: { type: 'user', id: 'frank' }, ...soon, daysLeft: 12 }], 'ending within 30 days, not expired');
  assert.equal((call(rt, 'ruth', '/reviews') as { roleAssignments?: unknown[] }).roleAssignments, undefined, 'subjects are not resource-owner scoped');
  const m = call(rt, 'lina', '/simulate/matrix', 'POST', { action: 'read', network: 'trusted' }) as { subjects: Array<{ id: string; roleAssignments?: unknown[] }> };
  assert.deepEqual(m.subjects.find((s) => s.id === 'frank')?.roleAssignments?.[0], soon);
});

test('owner impact scopes by resource type and id while preserving subject type labels', (t) => {
  const { rt } = fixture(t);
  const owned = required(rt.store.state.resources.find((r) => r.owner === 'carol'));
  const baseline = impact(rt, rt.store.state);
  rt.store.state = { ...rt.store.state, resources: [...rt.store.state.resources, { ...owned, type: 'payment', owner: 'alice' }] };
  const row = { subjectType: 'user', subject: 'bob', resourceType: owned.type, resource: owned.id, action: 'read', rules: [] };
  const rows = [row, { ...row, subjectType: 'agent' }, { ...row, resourceType: 'payment' }, { ...row, resource: 'missing' }];
  const delta = { ...baseline, gained: rows, lost: rows };
  const scoped = scopedImpact(rt, users.ruth, delta);
  assert.deepEqual(scoped.gained, rows.slice(0, 1));
  assert.deepEqual(scoped.lost, rows.slice(0, 1));
  assert.ok(scoped.evaluated > 0 && scoped.evaluated <= 210);
  assert.equal(scopedImpact(rt, users.amira, delta), delta);
});

test('a v2 digest refuses approval after any change to tuples, subjects, resources, retirements, policy or certifications', (t) => {
  const { rt, dir } = fixture(t);
  for (const [name, mutate] of digestMutations) {
    const pending = propose(rt, users.amira, grant());
    mutate(rt); rt.store.save();
    assert.throws(() => decideChange(rt, users.omar, pending.id, true, { reason: WHY }),
      (e) => e instanceof HttpError && e.code === 'stale' && e.message === 'State changed; submit a new proposal', name);
    decideChange(rt, users.omar, pending.id, false, { reason: WHY });
  }
  // the file revision is saved with the state: after a restart an untouched proposal still approves
  const last = propose(rt, users.amira, grant());
  const restarted = { ...rt, store: new Store(dir, 'examples/toy-domain', FIXED) };
  assert.equal(restarted.store.digest(), last.stateDigest);
  assert.equal(decideChange(restarted, users.omar, last.id, true, { reason: WHY }).status, 'applied');
});
