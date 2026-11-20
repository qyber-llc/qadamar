// Cluster mode: a follower behind a plain Service forwards admin and SCIM requests to the leader (forward.ts), streamed,
// with cookies and CSRF kept, authenticated by a signed single-use hop header; 409 not_leader stays the fallback.
import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request, type Server } from 'node:http';
import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { resolve } from 'node:path';
import { createHandler } from '../src/router.ts';
import { HOP_HEADER, HOP_WINDOW_MS, HopVerifier, leaderOrigin, signHop } from '../src/forward.ts';
import { trustedProxies } from '../src/proxy.ts';
import type { NodeRole } from '../src/runtime.ts';
import { fixture, WHY, type Fixture } from './helpers.ts';

interface Answer { status: number; headers: Record<string, string | string[] | undefined>; data: Record<string, unknown> }
function call(url: string, path: string, method = 'GET', data?: unknown, headers: Record<string, string> = {}): Promise<Answer> {
  return new Promise((done, fail) => {
    const body = data === undefined ? undefined : JSON.stringify(data);
    const r = request(`${url}${path}`, { method, headers: { ...(body ? { 'content-type': 'application/json' } : {}), ...headers } }, (res) => {
      let text = '';
      res.on('data', (c: Buffer) => { text += c.toString(); });
      res.on('end', () => { let parsed = {}; try { parsed = JSON.parse(text); } catch { /* empty */ } done({ status: res.statusCode ?? 0, headers: res.headers, data: parsed }); });
    });
    r.on('error', fail);
    r.end(body);
  });
}
async function listen(handler: ReturnType<typeof createHandler>): Promise<{ url: string; server: Server }> {
  const server = createServer((req, res) => void handler(req, res));
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server };
}

/** One state, two roles: a leader and a follower that knows the leader's URL (as gate_sync tells it). */
async function cluster(t: TestContext, f: Fixture, opts: { key?: Buffer; leaderUrl?: string } = {}) {
  const key = opts.key ?? randomBytes(32);
  const role = (leader: boolean, url: () => string | null, id: string): NodeRole => ({ id, leader: () => leader, fresh: () => true, leaderUrl: url });
  const static_ = resolve(f.dir, 'static');
  const leader = await listen(createHandler({ ...f.rt, node: role(true, () => null, 'gate-0') }, f.auth, { staticDir: static_, hopKey: key }, () => 'http://x'));
  const follower = await listen(createHandler({ ...f.rt, node: role(false, () => opts.leaderUrl ?? leader.url, 'gate-1') }, f.auth,
    { staticDir: static_, hopKey: key, proxies: trustedProxies('127.0.0.1') }, () => 'http://x'));
  t.after(() => { leader.server.close(); follower.server.close(); leader.server.closeAllConnections(); follower.server.closeAllConnections(); });
  return { leader: leader.url, follower: follower.url, key };
}

test('a follower forwards console requests to the leader: sign-in, cookies, CSRF, body and the client address', async (t) => {
  const f = fixture(t);
  const { follower } = await cluster(t, f);
  const signIn = await call(follower, '/admin/v1/session', 'POST', { username: 'amira', password: f.passwords.amira });
  assert.equal(signIn.status, 200);
  const cookie = String(signIn.headers['set-cookie']).split(';')[0]!;
  const me = { cookie, 'x-csrf-token': String(signIn.data.csrfToken) };
  assert.equal((await call(follower, '/admin/v1/session', 'GET', undefined, me)).status, 200);
  assert.equal((await call(follower, '/admin/v1/changes', 'POST', { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY }, { cookie })).status, 403, 'CSRF still enforced by the leader');
  const proposed = await call(follower, '/admin/v1/changes', 'POST', { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY }, me);
  assert.equal(proposed.status, 201);
  assert.ok(f.rt.store.changes.some((c) => c.id === proposed.data.id), 'written by the leader into the shared state');
  assert.equal((await call(follower, '/admin/v1/changes?status=pending', 'GET', undefined, me)).status, 200, 'query kept');
  // the client address the follower saw (here behind a trusted proxy) reaches the leader's audit through the signed hop
  await call(follower, '/admin/v1/session', 'POST', { username: 'amira', password: 'wrong' }, { 'x-forwarded-for': '203.0.113.9' });
  assert.ok(f.rt.audit.records().some((r) => r.action === 'login' && r.effect === 'deny' && JSON.stringify(r.details).includes('203.0.113.9')));
  // decisions are answered by the follower itself, never forwarded
  assert.equal((await call(follower, '/leaderz')).status, 503);
});

test('the leader accepts only a valid, fresh, single-use hop; a follower never forwards a hopped request', async (t) => {
  const f = fixture(t);
  const { leader, follower, key } = await cluster(t, f);
  const path = '/admin/v1/auth-methods';
  const none = Buffer.alloc(0);
  const hop = signHop(key, 'GET', path, none, '198.51.100.7', 'gate-1');
  assert.equal((await call(leader, path, 'GET', undefined, { [HOP_HEADER]: hop })).status, 200);
  assert.equal((await call(leader, path, 'GET', undefined, { [HOP_HEADER]: hop })).status, 401, 'replayed');
  assert.equal((await call(leader, path, 'GET', undefined, { [HOP_HEADER]: signHop(randomBytes(32), 'GET', path, none, 'x', 'gate-1') })).status, 401, 'wrong key');
  assert.equal((await call(leader, path, 'GET', undefined, { [HOP_HEADER]: signHop(key, 'POST', path, none, 'x', 'gate-1') })).status, 401, 'other method');
  assert.equal((await call(leader, path, 'GET', undefined, { [HOP_HEADER]: signHop(key, 'GET', '/admin/v1/session', none, 'x', 'gate-1') })).status, 401, 'other path');
  assert.equal((await call(leader, path, 'GET', undefined, { [HOP_HEADER]: signHop(key, 'GET', `${path}?x=1`, none, 'x', 'gate-1') })).status, 401, 'other query');
  assert.equal((await call(leader, path, 'GET', undefined, { [HOP_HEADER]: signHop(key, 'GET', path, none, 'x', 'gate-1', Date.now() - HOP_WINDOW_MS - 1000) })).status, 401, 'stale');
  assert.equal((await call(leader, path, 'GET', undefined, { [HOP_HEADER]: 'v1.garbage' })).status, 401);
  // the body digest is signed: a captured hop cannot carry another body (here: another proposal)
  const proposal = { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY };
  const signedFor = signHop(key, 'POST', '/admin/v1/changes', Buffer.from(JSON.stringify(proposal)), '198.51.100.7', 'gate-1');
  const swapped = await call(leader, '/admin/v1/changes', 'POST', { ...proposal, payload: { id: 'bob', set: { active: true } } }, { [HOP_HEADER]: signedFor });
  assert.equal(swapped.status, 401, 'other body');
  const looped = await call(follower, path, 'GET', undefined, { [HOP_HEADER]: signHop(key, 'GET', path, none, 'x', 'gate-0') });
  assert.equal(looped.status, 409); assert.equal(looped.data.error, 'not_leader');
  const verifier = new HopVerifier(key);
  const body = Buffer.from('{"a":1}');
  assert.deepEqual(verifier.verify(signHop(key, 'GET', '/x?y=1', body, '2001:db8::1', 'gate-1'), 'GET', '/x?y=1', body), { client: '2001:db8::1', node: 'gate-1' });
  assert.equal(verifier.verify(signHop(key, 'POST', '/x', body, 'c', 'gate-1'), 'POST', '/x', Buffer.from('{"a":2}')), null, 'tampered body');
  assert.equal(verifier.verify(signHop(key, 'POST', '/x', body, 'c', 'gate-1'), 'POST.', '/x', body), null, 'fields cannot shift');
});

test('only an http(s) origin is a leader address; a malformed published one is never contacted', async (t) => {
  assert.equal(leaderOrigin('http://gate-0.gate-nodes.tenant.svc:8787').host, 'gate-0.gate-nodes.tenant.svc:8787');
  for (const bad of ['ftp://x', 'http://u:p@x', 'http://x/path', 'http://x?q=1', 'http://x#f', 'gopher://x', 'not a url', 'file:///etc/passwd']) {
    assert.throws(() => leaderOrigin(bad), /GATE_ADVERTISE_URL/, bad);
  }
  const f = fixture(t);
  const { follower } = await cluster(t, f, { leaderUrl: 'http://127.0.0.1:9/elsewhere?x=1' });
  const r = await call(follower, '/admin/v1/session');
  assert.equal(r.status, 409); assert.equal(r.data.error, 'not_leader');
});

test('a follower bounds the forwarded body (1 MB) and answers the refusal itself, without an audit row', async (t) => {
  const f = fixture(t);
  const { follower } = await cluster(t, f);
  const rows = f.rt.audit.records().length;
  // as on any node, the oversized upload is drained and refused with 413; it is never sent on to the leader
  const outcome = await call(follower, '/admin/v1/changes', 'POST', { pad: 'x'.repeat(1_100_000) }).then((r) => r.status, () => 'reset');
  assert.equal(outcome, 413);
  assert.equal(f.rt.audit.records().length, rows);
});

test('fallbacks: 409 not_leader when the leader is unknown or no hop key exists, 503 when it cannot be reached', async (t) => {
  const f = fixture(t);
  const unknown = await listen(createHandler({ ...f.rt, node: { id: 'gate-1', leader: () => false, fresh: () => true, leaderUrl: () => null } }, f.auth,
    { staticDir: resolve(f.dir, 'static'), hopKey: randomBytes(32) }, () => 'http://x'));
  const keyless = await listen(createHandler({ ...f.rt, node: { id: 'gate-1', leader: () => false, fresh: () => true, leaderUrl: () => 'http://127.0.0.1:9' } }, f.auth,
    { staticDir: resolve(f.dir, 'static') }, () => 'http://x'));
  t.after(() => { unknown.server.close(); keyless.server.close(); });
  for (const url of [unknown.url, keyless.url]) {
    const r = await call(url, '/admin/v1/session');
    assert.equal(r.status, 409); assert.equal(r.data.error, 'not_leader');
  }
  // a port nothing listens on: the leader is gone
  const closed = createServer(); await new Promise<void>((done) => closed.listen(0, '127.0.0.1', done));
  const gone = `http://127.0.0.1:${(closed.address() as AddressInfo).port}`;
  closed.close();
  const { follower } = await cluster(t, f, { leaderUrl: gone });
  const r = await call(follower, '/admin/v1/session');
  assert.equal(r.status, 503); assert.equal(r.headers['retry-after'], '1');
});
