// Resource-owner isolation comes from the authenticated principal (and RESOURCE_OWNERS), never from a fixed demo owner.
import test from 'node:test';
import assert from 'node:assert/strict';
import { admin } from '../src/admin/index.ts';
import { HttpError } from '../src/http.ts';
import { decide, parseResourceOwners } from '../src/runtime.ts';
import type { Runtime } from '../src/runtime.ts';
import type { User } from '../src/auth.ts';
import type { Change } from '../src/store.ts';
import { fixture, user as fixtureUser, WHY } from './helpers.ts';

const ownerA: User = { id: 'carol', name: 'carol', roles: ['resource_owner'] }; // owns CASE-11/14/18, FOLDER-A
const ownerB: User = { id: 'dan', name: 'dan', roles: ['resource_owner'] }; // owns CASE-12 and, here, CASE-15
const stranger: User = { id: 'zed', name: 'zed', roles: ['resource_owner'] }; // owns nothing, mapped to nothing
const A_OWNS = ['CASE-11', 'CASE-14', 'CASE-18', 'FOLDER-A'];
const B_OWNS = ['CASE-12', 'CASE-15'];
const notFound = (e: unknown): boolean => e instanceof HttpError && e.status === 404;
const call = (rt: Runtime, user: User, path: string, method = 'GET', b: Record<string, unknown> = {}): unknown => {
  const value = admin(rt, user, method, new URL(`http://localhost/admin/v1${path}`), b).value;
  assert.ok(!(value instanceof Promise), 'file-mode admin routes answer synchronously');
  return value;
};
const ids = (items: Array<{ id: string }>): string[] => items.map((x) => x.id).sort();

function world(t: Parameters<typeof fixture>[0]): Runtime {
  const { rt } = fixture(t);
  const s = rt.store.state;
  // a second owner with a reviewable grant of its own, next to carol's
  rt.store.state = { ...s, resources: s.resources.map((r) => r.id === 'CASE-15' ? { ...r, owner: 'dan' } : r),
    tuples: [...s.tuples, { id: 'b-grant', object: { type: 'case', id: 'CASE-15' }, relation: 'allocated', subject: { type: 'user', id: 'bob' },
      validFrom: '2026-11-01T00:00:00Z', validTo: '2026-11-20T00:00:00Z', grantedBy: 'amira' }] };
  return rt;
}

test('owner A and owner B never see each other\'s resources, tuples or subjects', (t) => {
  const rt = world(t);
  const res = (u: User) => (call(rt, u, '/resources') as { items: Array<{ id: string; owner: string }> }).items;
  assert.deepEqual(ids(res(ownerA)), [...A_OWNS].sort());
  assert.deepEqual(ids(res(ownerB)), [...B_OWNS].sort());
  assert.deepEqual(res(stranger), [], 'an owner id that owns nothing sees nothing');
  assert.deepEqual(ids(res(fixtureUser('ruth'))), [...A_OWNS].sort(), 'RESOURCE_OWNERS maps ruth to carol');
  assert.ok(res(ownerB).every((r) => r.owner === 'dan') && res(ownerA).every((r) => r.owner === 'carol'));
  for (const [u, theirs] of [[ownerA, B_OWNS], [ownerB, A_OWNS]] as const) {
    const tuples = (call(rt, u, '/tuples') as { items: Array<{ object: { id: string } }> }).items;
    assert.ok(tuples.length > 0 && tuples.every((x) => !theirs.includes(x.object.id)));
  }
  const subjects = (u: User) => ids((call(rt, u, '/subjects') as { items: Array<{ id: string }> }).items);
  assert.ok(subjects(ownerA).includes('assistant-1') && !subjects(ownerA).includes('eve') && !subjects(ownerA).includes('dan'));
  assert.ok(subjects(ownerB).includes('eve') && subjects(ownerB).includes('dan') && !subjects(ownerB).includes('assistant-1'));
  assert.deepEqual(subjects(stranger), []);
});

test('owner B cannot explain, simulate or matrix owner A\'s resources or subjects, and vice versa', (t) => {
  const rt = world(t);
  const post = (u: User, path: string, b: Record<string, unknown>) => call(rt, u, path, 'POST', { action: 'read', network: 'trusted', ...b });
  assert.throws(() => post(ownerB, '/explain', { subjectId: 'bob', resourceId: 'CASE-14' }), notFound);
  assert.throws(() => post(ownerB, '/explain', { subjectId: 'assistant-1', resourceId: 'CASE-15' }), notFound);
  assert.throws(() => post(ownerA, '/explain', { subjectId: 'bob', resourceId: 'CASE-15' }), notFound);
  assert.throws(() => post(ownerA, '/explain', { subjectId: 'eve', resourceId: 'CASE-14' }), notFound);
  assert.throws(() => post(ownerB, '/simulate/who-can', { resourceId: 'CASE-14' }), notFound);
  assert.throws(() => post(ownerA, '/simulate/who-can', { resourceId: 'CASE-12' }), notFound);
  assert.throws(() => post(ownerB, '/simulate/what-can', { subjectId: 'assistant-1' }), notFound);
  assert.throws(() => post(ownerA, '/simulate/what-can', { subjectId: 'eve' }), notFound);
  const whatCan = post(ownerB, '/simulate/what-can', { subjectId: 'bob' }) as { items: Array<{ resource: { id: string } }> };
  assert.deepEqual(whatCan.items.map((x) => x.resource.id).sort(), [...B_OWNS].sort());
  const whoCan = post(ownerB, '/simulate/who-can', { resourceId: 'CASE-15' }) as { items: Array<{ subject: { id: string } }> };
  assert.ok(whoCan.items.some((x) => x.subject.id === 'bob') && whoCan.items.every((x) => x.subject.id !== 'assistant-1'));
  for (const [u, mine] of [[ownerA, A_OWNS], [ownerB, B_OWNS]] as const) {
    const m = post(u, '/simulate/matrix', {}) as { resources: Array<{ id: string }>; cells: Array<{ resource: string }> };
    assert.deepEqual(ids(m.resources), [...mine].sort());
    assert.ok(m.cells.every((c) => mine.includes(c.resource)));
  }
  const empty = post(stranger, '/simulate/matrix', {}) as { resources: unknown[]; cells: unknown[] };
  assert.deepEqual([empty.resources, empty.cells], [[], []]);
  assert.throws(() => post(stranger, '/explain', { subjectId: 'bob', resourceId: 'CASE-14' }), notFound);
});

test('impact, proposals, change lists and reviews stay inside each owner\'s scope', (t) => {
  const rt = world(t);
  const removal = (tupleId: string) => ({ kind: 'remove_tuple', payload: { tupleId }, reason: WHY });
  // simulate and propose: the other owner's tuple does not exist for you
  assert.throws(() => call(rt, ownerB, '/simulate/impact', 'POST', removal('seed-4')), notFound);
  assert.throws(() => call(rt, ownerA, '/simulate/impact', 'POST', removal('b-grant')), notFound);
  assert.throws(() => call(rt, ownerB, '/changes', 'POST', removal('seed-4')), notFound);
  assert.throws(() => call(rt, ownerA, '/changes', 'POST', removal('b-grant')), notFound);
  assert.throws(() => call(rt, stranger, '/changes', 'POST', removal('seed-4')), notFound);
  const simulated = call(rt, ownerB, '/simulate/impact', 'POST', removal('b-grant')) as Change['impact'];
  assert.ok(simulated.lost.length > 0 && simulated.lost.every((x) => B_OWNS.includes(x.resource)));
  const a = call(rt, ownerA, '/changes', 'POST', removal('seed-4')) as Change;
  const b = call(rt, ownerB, '/changes', 'POST', removal('b-grant')) as Change;
  assert.ok(a.impact.lost.every((x) => A_OWNS.includes(x.resource)) && b.impact.lost.every((x) => B_OWNS.includes(x.resource)));
  // a change touching both owners' resources (an administrator's) shows each owner only its own rows
  const admin = call(rt, fixtureUser('amira'), '/changes', 'POST', { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY }) as Change;
  assert.ok(admin.impact.lost.some((x) => A_OWNS.includes(x.resource)) && admin.impact.lost.some((x) => B_OWNS.includes(x.resource)));
  const listed = (u: User) => (call(rt, u, '/changes') as { items: Change[] }).items;
  assert.deepEqual(listed(ownerA).map((c) => c.id), [a.id]);
  assert.deepEqual(listed(ownerB).map((c) => c.id), [b.id]);
  assert.ok(!listed(ownerA).some((c) => c.id === admin.id), 'an update_subject change is not an owner\'s to see');
  assert.deepEqual(listed(stranger), []);
  for (const [u, mine] of [[ownerA, A_OWNS], [ownerB, B_OWNS]] as const) {
    const evaluated = (call(rt, u, '/changes') as { items: Change[] }).items;
    assert.ok(evaluated.every((c) => [...c.impact.gained, ...c.impact.lost].every((x) => mine.includes(x.resource))));
  }
  // reviews
  const reviewIds = (u: User) => (call(rt, u, '/reviews') as { items: Array<{ tupleId: string }> }).items.map((x) => x.tupleId);
  assert.ok(!reviewIds(ownerA).includes('b-grant'));
  assert.ok(reviewIds(ownerB).includes('b-grant') && reviewIds(ownerB).every((id) => rt.store.state.tuples.some((x) => x.id === id && B_OWNS.includes(x.object.id))));
  assert.deepEqual(reviewIds(stranger), []);
  assert.throws(() => call(rt, ownerB, '/reviews/seed-4', 'POST', { decision: 'revoke', reason: WHY }), notFound);
  assert.throws(() => call(rt, ownerA, '/reviews/b-grant', 'POST', { decision: 'certify', newValidTo: '2026-12-31T00:00:00Z', reason: WHY }), notFound);
  const certified = call(rt, ownerB, '/reviews/b-grant', 'POST', { decision: 'certify', newValidTo: '2026-12-31T00:00:00Z', reason: WHY }) as Change;
  assert.equal(certified.kind, 'add_tuple');
  assert.ok(!listed(ownerA).some((c) => c.id === certified.id) && listed(ownerB).some((c) => c.id === certified.id));
});

test('overview counts (audit length, decisions, break-glass, expiring grants) are per owner', (t) => {
  const rt = world(t);
  for (const [s, r, type] of [['bob', 'CASE-14', 'case'], ['bob', 'CASE-18', 'case'], ['bob', 'CASE-15', 'case'], ['dan', 'CASE-12', 'case'], ['alice', 'CASE-7', 'case']] as const) {
    decide(rt, { type: 'user', id: s }, { type, id: r }, 'read', { now: rt.now(), network: 'trusted' });
  }
  type Overview = { counts: { activeBreakGlass: number; expiringGrants30d: number; pendingChanges: number }; audit: { length: number }; pdp: { decisions: number } };
  const view = (u: User) => call(rt, u, '/overview') as Overview;
  const records = rt.audit.records();
  const on = (owned: readonly string[]) => records.filter((x) => x.resource && owned.includes(x.resource));
  const a = view(ownerA); const b = view(ownerB); const z = view(stranger);
  assert.equal(a.pdp.decisions, 2); assert.equal(b.pdp.decisions, 2); assert.equal(z.pdp.decisions, 0);
  assert.equal(a.audit.length, on(A_OWNS).length); assert.equal(b.audit.length, on(B_OWNS).length); assert.equal(z.audit.length, 0);
  assert.equal(a.counts.activeBreakGlass, 0); assert.equal(b.counts.activeBreakGlass, 1, 'the break-glass grant on CASE-12 is dan\'s');
  assert.equal(b.counts.expiringGrants30d, 2, 'b-grant and the break-glass grant'); assert.equal(a.counts.expiringGrants30d, 0);
  assert.equal(z.counts.expiringGrants30d, 0);
  // the unscoped lists stay closed to owners: only the scoped counts above reach them
  const forbidden = (e: unknown): boolean => e instanceof HttpError && e.status === 403;
  for (const path of ['/audit', '/break-glass', '/compliance']) assert.throws(() => call(rt, ownerB, path), forbidden);
});

test('RESOURCE_OWNERS parses a strict JSON map and refuses anything else', () => {
  assert.equal(parseResourceOwners(undefined), undefined);
  assert.deepEqual(parseResourceOwners('{"ruth":["carol","carol"],"constructor":["x"]}'), new Map([['ruth', ['carol']], ['constructor', ['x']]]));
  for (const bad of ['[]', 'null', '"carol"', '{"ruth":"carol"}', '{"ruth":[1]}', '{"ruth":[""]}', '{bad']) assert.throws(() => parseResourceOwners(bad), /RESOURCE_OWNERS/);
});

test('a console user whose id is an inherited property name gets no extra owners', (t) => {
  const rt = world(t);
  const proto: User = { id: 'constructor', name: 'x', roles: ['resource_owner'] };
  assert.deepEqual((call(rt, proto, '/resources') as { items: unknown[] }).items, []);
});
