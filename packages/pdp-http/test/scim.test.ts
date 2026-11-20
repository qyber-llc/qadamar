import test from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage, ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import type { TestContext } from 'node:test';
import { createHandler } from '../src/router.ts';
import { Scim, SCIM_SERVICE, type ScimOptions } from '../src/scim.ts';
import { fileBacking } from '../src/store.ts';
import { propose, decideChange } from '../src/admin/changes.ts';
import { HttpError } from '../src/http.ts';
import { fixture, users, WHY, type Fixture } from './helpers.ts';

const TOKEN = 'scim-test-token-0123456789abcdefghijklmnop';
const USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
const GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const MAPPING = { 'Case investigators': 'investigator', 'grp-viewers': 'viewer' };
type Handler = ReturnType<typeof createHandler>;
interface Reply { status: number; headers: Record<string, unknown>; text: string; data: Record<string, unknown> }

async function send(route: Handler, path: string, method = 'GET', data?: unknown, headers: Record<string, string> = {}): Promise<Reply> {
  const socket = { remoteAddress: '127.0.0.1', readable: false } as ConstructorParameters<typeof IncomingMessage>[0];
  const req = new IncomingMessage(socket); req.url = path; req.method = method;
  req.headers = { ...(data === undefined ? {} : { 'content-type': 'application/scim+json' }), ...headers };
  let text = '';
  const res = new ServerResponse(req);
  res.end = ((chunk?: unknown): ServerResponse => { text = chunk === undefined ? '' : String(chunk); return res; }) as typeof res.end;
  const pending = route(req, res);
  req.push(data === undefined ? '' : JSON.stringify(data)); req.push(null);
  await pending;
  let parsed: Record<string, unknown> = {};
  try { parsed = JSON.parse(text) as Record<string, unknown>; } catch { /* NDJSON and empty bodies */ }
  return { status: res.statusCode, headers: res.getHeaders(), text, data: parsed };
}
function setup(t: TestContext, options: ScimOptions = { bearerToken: TOKEN, groupRoles: MAPPING }): { f: Fixture; scim: Scim; route: Handler } {
  const f = fixture(t);
  const scim = new Scim(f.rt, fileBacking(resolve(f.dir, 'scim-credential.json')), options);
  return { f, scim, route: createHandler(f.rt, f.auth, { scim }, () => 'http://localhost:8787') };
}
const bearer = { authorization: `Bearer ${TOKEN}` };
const approve = (f: Fixture, id: string): void => { decideChange(f.rt, users.omar, id, true, { reason: WHY }); };
const subject = (f: Fixture, id: string) => f.rt.store.state.subjects.find((s) => s.id === id);

test('SCIM needs its own bearer credential and answers errors in the SCIM error schema', async (t) => {
  const { f, route } = setup(t);
  for (const headers of [{} as Record<string, string>, { authorization: 'Bearer wrong' }, { authorization: `Bearer ${f.pepApiKey}` }]) {
    const refused = await send(route, '/scim/v2/Users', 'GET', undefined, headers);
    assert.equal(refused.status, 401);
    assert.match(String(refused.headers['content-type']), /application\/scim\+json/);
    assert.deepEqual(refused.data.schemas, ['urn:ietf:params:scim:api:messages:2.0:Error']);
  }
  const listed = await send(route, '/scim/v2/Users', 'GET', undefined, bearer);
  assert.equal(listed.status, 200);
  assert.equal(listed.data.totalResults, 11, 'every user subject is listed, agents are not');
  const created = await send(route, '/scim/v2/Users', 'POST', { schemas: [USER], userName: 'x' }, { authorization: 'Bearer wrong' });
  assert.equal(created.status, 401);
  assert.equal(f.rt.audit.records().at(-1)?.action, 'refused', 'refused SCIM mutations are audited');
});

test('refused admin and SCIM writes leave one audit row per source, route family and error', async (t) => {
  const { f, route } = setup(t);
  for (const path of ['/scim/v2/Users', '/admin/v1/changes']) {
    for (let i = 0; i < 5; i++) assert.equal((await send(route, path, 'POST', { schemas: [USER], userName: 'x' }, { authorization: 'Bearer wrong' })).status, 401);
    const rows = f.rt.audit.records().filter((row) => row.action === 'refused' && row.details?.route === path);
    assert.equal(rows.length, 1, path);
  }
});

test('admin-minted credential is hashed at rest, shown once, audited, and refused while an env token is set', async (t) => {
  const { f, scim } = setup(t, { groupRoles: MAPPING });
  assert.throws(() => scim.rotateCredential(users.omar), (e: unknown) => e instanceof HttpError && e.status === 403);
  assert.throws(() => scim.rotateCredential(users.lina), (e: unknown) => e instanceof HttpError && e.status === 403, 'a security officer can approve, so cannot mint');
  const minted = scim.rotateCredential(users.amira);
  const credential = (minted.body as { credential: string }).credential;
  assert.equal(minted.status, 201);
  const stored = JSON.stringify(fileBacking(resolve(f.dir, 'scim-credential.json')).load());
  assert.ok(!stored.includes(credential));
  assert.equal(f.rt.audit.records().at(-1)?.action, 'scim_credential_rotate');
  assert.ok(!JSON.stringify(f.rt.audit.records()).includes(credential));
  const req = (token: string) => ({ headers: { authorization: `Bearer ${token}` } }) as unknown as IncomingMessage;
  assert.match(scim.authenticate(req(credential)), /^scim:/);
  assert.match(scim.authenticate(req(credential)), /^scim:/, 'the cached digest still matches');
  scim.rotateCredential({ ...users.amira, id: 'amira-2' });
  assert.throws(() => scim.authenticate(req(credential)), (e: unknown) => e instanceof HttpError && e.status === 401, 'rotation revokes the old credential');
  // cluster: another node shares the stored credential and caches its digest; a rotation committed elsewhere must revoke it there too
  const second = (scim.rotateCredential(users.amira).body as { credential: string }).credential;
  const peer = new Scim(f.rt, fileBacking(resolve(f.dir, 'scim-credential.json')), { groupRoles: MAPPING });
  assert.match(peer.authenticate(req(second)), /^scim:/);
  scim.rotateCredential({ ...users.amira, id: 'amira-2' });
  assert.throws(() => peer.authenticate(req(second)), (e: unknown) => e instanceof HttpError && e.status === 401, 'a rotation on another node revokes the cached credential');
  const fromEnv = setup(t).scim;
  assert.throws(() => fromEnv.rotateCredential(users.amira), (e: unknown) => e instanceof HttpError && e.status === 409);
  assert.throws(() => new Scim(f.rt, fileBacking(resolve(f.dir, 'x.json')), { bearerToken: 'short' }), /32/);
  assert.throws(() => new Scim(f.rt, fileBacking(resolve(f.dir, 'x.json')), { groupRoles: { a: 'viewer', b: 'viewer' } }), /one group/);
});

test('by default every SCIM change is a pending two-person proposal; approval applies it', async (t) => {
  const { f, route } = setup(t);
  const before = f.rt.store.state;
  const group = await send(route, '/scim/v2/Groups', 'POST', { schemas: [GROUP], displayName: 'Case investigators', externalId: 'g-1' }, bearer);
  assert.equal(group.status, 202);
  assert.equal(group.data.status, 'pending');
  assert.equal(f.rt.store.state, before, 'nothing changes before review');
  const change = f.rt.store.changes.find((c) => c.id === group.data.changeId);
  assert.equal(change?.kind, 'scim_subjects'); assert.equal(change?.makerId, 'scim');
  assert.equal(f.rt.audit.records().at(-1)?.action, 'propose');
  approve(f, String(group.data.changeId));
  const groupId = String(group.data.id);
  assert.equal(subject(f, groupId)?.type, 'group');

  const user = await send(route, '/scim/v2/Users', 'POST', { schemas: [USER], userName: 'Nadia@example.org', externalId: 'u-1', displayName: 'Nadia', groups: [{ value: groupId }] }, bearer);
  assert.equal(user.status, 202);
  assert.deepEqual(user.data.groups, [{ value: groupId, display: 'Case investigators' }], 'the response shows the proposed state');
  assert.throws(() => decideChange(f.rt, users.amira, String(user.data.changeId), true, { reason: WHY }), (e: unknown) => e instanceof HttpError && e.status === 403);
  approve(f, String(user.data.changeId));
  const nadia = subject(f, String(user.data.id));
  assert.deepEqual(nadia?.roles, ['investigator']);
  assert.equal(nadia?.clearance, 0); assert.deepEqual(nadia?.compartments, []);

  const found = await send(route, `/scim/v2/Users?filter=${encodeURIComponent('userName eq "nadia@EXAMPLE.org"')}`, 'GET', undefined, bearer);
  assert.equal(found.data.totalResults, 1);
  const byExternal = await send(route, `/scim/v2/Groups?filter=${encodeURIComponent('externalId eq "g-1"')}`, 'GET', undefined, bearer);
  assert.deepEqual((byExternal.data.Resources as Array<{ members: unknown }>)[0]?.members, [{ value: nadia?.id, display: 'Nadia@example.org' }]);
  assert.equal((await send(route, `/scim/v2/Users?filter=${encodeURIComponent('emails co "x"')}`, 'GET', undefined, bearer)).status, 400);
  assert.equal((await send(route, '/scim/v2/Users', 'POST', { schemas: [USER], userName: 'nadia@example.org' }, bearer)).status, 409);
});

test('attributes the PDP does not model are rejected, never stored', async (t) => {
  const { f, route } = setup(t);
  const count = f.rt.store.changes.length;
  for (const body of [
    { schemas: [USER], userName: 'a', emails: [{ value: 'a@example.org' }] },
    { schemas: [USER], userName: 'a', name: { givenName: 'A' } },
    { schemas: [USER, 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'], userName: 'a' },
    { schemas: [USER], userName: 'a', active: 'yes' },
    { schemas: [USER], userName: '' },
  ]) assert.equal((await send(route, '/scim/v2/Users', 'POST', body, bearer)).status, 400, JSON.stringify(body));
  const patch = { schemas: [PATCH], Operations: [{ op: 'replace', path: 'title', value: 'x' }] };
  assert.equal((await send(route, '/scim/v2/Users/bob', 'PATCH', patch, bearer)).status, 400);
  assert.equal((await send(route, '/scim/v2/Groups', 'POST', { schemas: [GROUP], displayName: 'Unmapped' }, bearer)).status, 422, 'groups need an explicit role mapping');
  assert.equal(f.rt.store.changes.length, count);
});

test('direct mode applies at once and audits each change; PATCH and DELETE deactivate', async (t) => {
  const { f, route } = setup(t, { bearerToken: TOKEN, groupRoles: MAPPING, direct: true });
  const group = await send(route, '/scim/v2/Groups', 'POST', { schemas: [GROUP], displayName: 'grp-viewers', members: [{ value: 'bob' }] }, bearer);
  assert.equal(group.status, 201);
  assert.ok(subject(f, 'bob')?.roles.includes('viewer'));
  const audited = f.rt.audit.records().at(-1);
  assert.equal(audited?.action, 'scim.group.create'); assert.equal(audited?.actor, 'scim');
  assert.deepEqual(audited?.details?.direct, true);
  assert.match(String(audited?.details?.credential), /^[0-9a-f]{16}$/, 'direct writes name the credential by fingerprint');
  assert.ok(!JSON.stringify(f.rt.audit.records()).includes(TOKEN), 'never by its secret');

  const off = await send(route, '/scim/v2/Users/bob', 'PATCH', { schemas: [PATCH], Operations: [{ op: 'Replace', value: { active: 'False' } }] }, bearer);
  assert.equal(off.status, 200); assert.equal(subject(f, 'bob')?.active, false);
  assert.equal(subject(f, 'bob')?.clearance, 2, 'clearance, compartments and other attributes are kept');
  assert.equal(subject(f, 'bob')?.attrs?.unit, 'Investigations');
  const removed = await send(route, `/scim/v2/Groups/${group.data.id}`, 'PATCH', { schemas: [PATCH], Operations: [{ op: 'remove', path: 'members[value eq "bob"]' }] }, bearer);
  assert.equal(removed.status, 200);
  assert.deepEqual(subject(f, 'bob')?.roles, ['investigator']);
  assert.equal((await send(route, '/scim/v2/Users/frank', 'DELETE', undefined, bearer)).status, 204);
  assert.equal(subject(f, 'frank')?.active, false);
  assert.ok(subject(f, 'frank'), 'delete deactivates, it never removes the subject');
  assert.equal((await send(route, '/scim/v2/Users/assistant-1', 'GET', undefined, bearer)).status, 404, 'agents are not SCIM users');
});

test('the SCIM change kind is reserved to the service and its beneficiary cannot approve it', (t) => {
  const f = fixture(t);
  const alice = f.rt.store.state.subjects.find((s) => s.id === 'alice')!;
  const payload = { subjects: [{ ...alice, active: false }] };
  assert.throws(() => propose(f.rt, users.amira, { kind: 'scim_subjects', payload, reason: WHY }), (e: unknown) => e instanceof HttpError && e.status === 403);
  assert.throws(() => propose(f.rt, SCIM_SERVICE, { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY }), (e: unknown) => e instanceof HttpError && e.status === 403);
  assert.throws(() => propose(f.rt, SCIM_SERVICE, { kind: 'scim_subjects', payload: { subjects: [{ ...alice, clearance: 0 }] }, reason: WHY }), /clearance/);
  assert.throws(() => propose(f.rt, SCIM_SERVICE, { kind: 'scim_subjects', payload: { subjects: [{ ...alice, attrs: { ...alice.attrs, unit: 'Elsewhere' } }] }, reason: WHY }), /unmodelled/);
  const change = propose(f.rt, SCIM_SERVICE, { kind: 'scim_subjects', payload, reason: WHY });
  assert.throws(() => decideChange(f.rt, { id: 'alice', name: 'alice', roles: ['approver'] }, change.id, true, { reason: WHY }), (e: unknown) => e instanceof HttpError && e.status === 403);
});

test('POST /admin/v1/scim/credential needs a session, CSRF and an admin role; the minted credential then works', async (t) => {
  const { f, route } = setup(t, { groupRoles: MAPPING });
  const login = async (id: string): Promise<Record<string, string>> => {
    const response = await send(route, '/admin/v1/session', 'POST', { username: id, password: f.passwords[id] }, { 'content-type': 'application/json' });
    return { cookie: String(response.headers['set-cookie']).split(';')[0]!, 'x-csrf-token': String(response.data.csrfToken) };
  };
  const admin = await login('amira'); const auditor = await login('sam');
  assert.equal((await send(route, '/scim/v2/Users', 'GET', undefined, { authorization: 'Bearer anything-at-all' })).status, 401, 'no credential yet: closed');
  assert.equal((await send(route, '/admin/v1/scim/credential', 'POST', {}, { cookie: admin.cookie! })).status, 403, 'CSRF token required');
  assert.equal((await send(route, '/admin/v1/scim/credential', 'POST', {}, auditor)).status, 403);
  const minted = await send(route, '/admin/v1/scim/credential', 'POST', {}, admin);
  assert.equal(minted.status, 201);
  assert.equal(minted.headers['cache-control'], 'no-store');
  assert.equal((await send(route, '/scim/v2/Groups', 'GET', undefined, { authorization: `Bearer ${String(minted.data.credential)}` })).status, 200);
  const info = await send(route, '/admin/v1/scim/credential', 'GET', undefined, admin);
  assert.equal(info.status, 200);
  assert.equal(info.data.source, 'console');
  assert.equal(info.data.rotatedBy, 'amira');
  assert.equal(typeof info.data.rotated, 'string');
  assert.ok(!JSON.stringify(info.data).includes(String(minted.data.credential)) && !('hash' in info.data), 'holder and time only');
  assert.equal((await send(route, '/admin/v1/scim/credential', 'GET', undefined, auditor)).status, 403);
});

test('whoever minted the SCIM credential cannot approve what it proposes; env-token proposals are marked env', async (t) => {
  const { f, scim, route } = setup(t, { groupRoles: MAPPING });
  const minter = { id: 'nour', name: 'nour', roles: ['access_admin', 'approver'] };
  const credential = String((scim.rotateCredential(minter).body as { credential: string }).credential);
  assert.equal((fileBacking(resolve(f.dir, 'scim-credential.json')).load() as { rotatedBy?: string }).rotatedBy, 'nour');
  const proposed = await send(route, '/scim/v2/Users/bob', 'PATCH', { schemas: [PATCH], Operations: [{ op: 'replace', value: { active: false } }] }, { authorization: `Bearer ${credential}` });
  assert.equal(proposed.status, 202);
  const change = f.rt.store.changes.find((c) => c.id === proposed.data.changeId)!;
  assert.equal(change.scimCredential?.rotatedBy, 'nour');
  assert.match(change.scimCredential?.fingerprint ?? '', /^[0-9a-f]{16}$/);
  const audited = f.rt.audit.records().at(-1);
  assert.equal(audited?.action, 'propose'); assert.equal(audited?.details?.credential, change.scimCredential?.fingerprint);
  assert.ok(!JSON.stringify(f.rt.audit.records()).includes(credential));
  assert.throws(() => decideChange(f.rt, minter, change.id, true, { reason: WHY }), (e: unknown) => e instanceof HttpError && e.code === 'self_approval');
  approve(f, change.id);
  assert.equal(subject(f, 'bob')?.active, false, 'another approver can');

  const env = setup(t);
  const fromEnv = await send(env.route, '/scim/v2/Users/bob', 'DELETE', undefined, bearer);
  assert.equal(env.f.rt.store.changes.find((c) => c.id === fromEnv.data.changeId)?.scimCredential?.rotatedBy, 'env');
  const unattributed = propose(env.f.rt, SCIM_SERVICE, { kind: 'scim_subjects', payload: { subjects: [{ ...subject(env.f, 'bob')!, active: false }] }, reason: WHY });
  assert.throws(() => decideChange(env.f.rt, users.omar, unattributed.id, true, { reason: WHY }), (e: unknown) => e instanceof HttpError && e.code === 'self_approval', 'a SCIM proposal of unknown origin is never approvable');
});

test('SCIM_DIRECT is refused at startup without SCIM_BEARER_TOKEN', (t) => {
  const f = fixture(t);
  assert.throws(() => new Scim(f.rt, fileBacking(resolve(f.dir, 'x.json')), { groupRoles: MAPPING, direct: true }), /SCIM_DIRECT requires SCIM_BEARER_TOKEN/);
  assert.ok(new Scim(f.rt, fileBacking(resolve(f.dir, 'x.json')), { bearerToken: TOKEN, groupRoles: MAPPING, direct: true }));
});
