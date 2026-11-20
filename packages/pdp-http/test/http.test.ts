import test from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage, ServerResponse } from 'node:http';
import { mkdirSync, writeFileSync, readFileSync, symlinkSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHandler, refusalLimiter } from '../src/router.ts';
import { rateLimitsFromEnv } from '../src/ratelimit.ts';
import { createServer } from '../src/server.ts';
import { Auth, dummyPasswordHash, verifySecretAsync } from '../src/auth.ts';
import { AUDIT_MAX_ROW } from '../src/audit.ts';
import { createHash } from 'node:crypto';
import { fixture, evaluation, mockScrypt, required, WHY } from './helpers.ts';
import type { Fixture } from './helpers.ts';

type Handler = ReturnType<typeof createHandler>;
interface Response { status: number; headers: Record<string, unknown>; text: string; data: Record<string, unknown> }
async function send(handler: Handler, path: string, method = 'GET', data?: unknown, headers: Record<string, string> = {}, raw?: string): Promise<Response> {
  const socket = { remoteAddress: '127.0.0.1', readable: false } as ConstructorParameters<typeof IncomingMessage>[0];
  const req = new IncomingMessage(socket); req.url = path; req.method = method; req.headers = { ...(method === 'POST' ? { 'content-type': 'application/json' } : {}), ...headers };
  let text = '';
  const res = new ServerResponse(req);
  res.end = ((chunk?: unknown): ServerResponse => { text = chunk === undefined ? '' : String(chunk); return res; }) as typeof res.end;
  const pending = handler(req, res);
  req.push(raw ?? (data === undefined ? '' : JSON.stringify(data))); req.push(null);
  await pending;
  let parsed: Record<string, unknown> = {};
  try { parsed = JSON.parse(text) as Record<string, unknown>; } catch { /* Static responses need not be JSON. */ }
  return { status: res.statusCode, headers: res.getHeaders(), text, data: parsed };
}
function handler(f: Fixture, rateLimit = 120, pepRateLimit = rateLimit): Handler { return createHandler(f.rt, f.auth, { rateLimit, pepRateLimit, staticDir: resolve(f.dir, 'static') }, () => 'http://localhost:8787'); }

test('HTTP discovery and PEP authentication with security headers and error envelopes', async (t) => {
  const f = fixture(t); const route = handler(f);
  const discovery = await send(route, '/.well-known/authzen-configuration');
  assert.equal(discovery.status, 200); assert.equal(discovery.data.access_evaluation_endpoint, 'http://localhost:8787/access/v1/evaluation');
  for (const [key, value] of Object.entries({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'", 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'cache-control': 'no-store' })) assert.equal(discovery.headers[key], value);
  assert.equal((await send(route, '/access/v1/evaluation', 'POST', evaluation())).status, 401);
  assert.equal((await send(route, '/access/v1/evaluation', 'POST', evaluation(), { authorization: 'Bearer invalid' })).status, 401);
  const allowed = await send(route, '/access/v1/evaluation', 'POST', evaluation(), { authorization: `Bearer ${f.pepApiKey}` });
  assert.equal(allowed.status, 200); assert.equal(allowed.data.decision, true);
});
test('HTTP admin cookies, CSRF, role enforcement, two-person approval and stale conflict', async (t) => {
  const f = fixture(t); const route = handler(f);
  const login = async (id: string): Promise<Record<string, string>> => {
    const response = await send(route, '/admin/v1/session', 'POST', { username: id, password: f.passwords[id] });
    assert.equal(response.status, 200);
    const cookie = String(response.headers['set-cookie']);
    assert.match(cookie, /HttpOnly; SameSite=Strict/);
    return { cookie: required(cookie.split(';')[0]), 'x-csrf-token': String(response.data.csrfToken) };
  };
  const maker = await login('amira'); const checker = await login('omar'); const auditor = await login('sam');
  assert.equal((await send(route, '/admin/v1/session', 'GET', undefined, maker)).status, 200);
  const proposal = { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY };
  assert.equal((await send(route, '/admin/v1/changes', 'POST', proposal, { cookie: required(maker.cookie) })).status, 403);
  assert.equal((await send(route, '/admin/v1/changes', 'POST', proposal, auditor)).status, 403);
  const a = await send(route, '/admin/v1/changes', 'POST', proposal, maker);
  const b = await send(route, '/admin/v1/changes', 'POST', proposal, maker);
  assert.equal(a.status, 201); assert.ok(a.data.impact);
  assert.equal((await send(route, `/admin/v1/changes/${a.data.id}/approve`, 'POST', { reason: WHY }, maker)).data.error, 'self_approval');
  assert.equal((await send(route, `/admin/v1/changes/${a.data.id}/approve`, 'POST', { reason: WHY }, checker)).status, 200);
  const stale = await send(route, `/admin/v1/changes/${b.data.id}/approve`, 'POST', { reason: WHY }, checker);
  assert.equal(stale.status, 409); assert.equal(stale.data.error, 'stale');
  assert.equal((await send(route, '/admin/v1/session', 'DELETE', undefined, maker)).status, 204);
  assert.equal((await send(route, '/admin/v1/session', 'GET', undefined, maker)).status, 401);
});
test('HTTP malformed/oversize JSON and hidden-means-absent errors', async (t) => {
  const f = fixture(t); const route = handler(f); const headers = { authorization: `Bearer ${f.pepApiKey}` };
  assert.equal((await send(route, '/access/v1/evaluation', 'POST', undefined, headers, '{')).status, 400);
  const oversized = await send(route, '/access/v1/evaluation', 'POST', undefined, headers, 'x'.repeat(1_048_577));
  assert.equal(oversized.status, 413);
  assert.deepEqual(oversized.data, { error: 'payload_too_large', message: 'Body exceeds 1 MB' });
  assert.equal(oversized.headers.connection, 'close');
  const refusal = f.rt.audit.records().at(-1)!;
  assert.equal(refusal.type, 'security'); assert.equal(refusal.action, 'refused');
  assert.equal(refusal.details?.error, 'payload_too_large');
  const hidden = await send(route, '/x/v1/explain', 'POST', evaluation('bob', 'CASE-7'), headers);
  const missing = await send(route, '/x/v1/explain', 'POST', evaluation('bob', 'missing'), headers);
  assert.equal(hidden.status, 404); assert.equal(hidden.text, missing.text);
});
test('a full sign-in queue answers 503 with Retry-After at once and audits it, instead of an endless backlog', async (t) => {
  const f = fixture(t); const route = handler(f);
  let release = (): void => undefined;
  const calls = mockScrypt(t, new Promise((resolve) => { release = resolve; }));
  t.after(() => release());
  const hash = dummyPasswordHash();
  // 2 running, 32 waiting: a spray of unknown names fills the queue
  const queued = Array.from({ length: 34 }, () => verifySecretAsync('guess', hash));
  const extra = verifySecretAsync('guess', hash).then(() => 'queued', (e: unknown) => e);
  const outcome = await Promise.race([extra, new Promise((resolve) => setImmediate(() => resolve('queued')))]);
  assert.ok(outcome instanceof Error && /Too many sign-ins/.test(outcome.message), 'refused at once, not queued');
  const busy = await send(route, '/admin/v1/session', 'POST', { username: 'amira', password: f.passwords.amira });
  assert.equal(busy.status, 503); assert.equal(busy.headers['retry-after'], '3');
  const row = f.rt.audit.records().filter((r) => r.type === 'session').at(-1);
  assert.deepEqual([row?.action, row?.effect, (row?.details as { reason?: string } | undefined)?.reason], ['login', 'deny', 'busy']);
  release();
  assert.deepEqual(await Promise.all(queued), Array(34).fill(false), 'the queued checks still complete');
  assert.equal(calls.length, 2 * 34);
  assert.equal(await verifySecretAsync('guess', hash), false, 'the queue is open again once drained');
});
test('HTTP 429 includes Retry-After for both request and login limits', async (t) => {
  const f = fixture(t); const route = handler(f, 1);
  assert.equal((await send(route, '/.well-known/authzen-configuration')).status, 200);
  const limited = await send(route, '/.well-known/authzen-configuration');
  assert.equal(limited.status, 429); assert.ok(Number(limited.headers['retry-after']) > 0);
  const loginRoute = handler(f);
  for (let i = 0; i < 5; i++) assert.equal((await send(loginRoute, '/admin/v1/session', 'POST', { username: 'sam', password: 'wrong' })).status, 401);
  const lock = await send(loginRoute, '/admin/v1/session', 'POST', { username: 'sam', password: f.passwords.sam });
  assert.equal(lock.status, 429); assert.ok(lock.headers['retry-after']);
});
test('static serving has SPA fallback and rejects traversal and escaping symlinks', async (t) => {
  const f = fixture(t); const route = handler(f); const dir = resolve(f.dir, 'static');
  mkdirSync(dir); writeFileSync(resolve(dir, 'index.html'), '<h1>Admin</h1>'); writeFileSync(resolve(dir, 'app.js'), 'export {};');
  symlinkSync(resolve(f.dir, 'INITIAL-CREDENTIALS.txt'), resolve(dir, 'leak.txt'));
  assert.equal((await send(route, '/')).text, '<h1>Admin</h1>');
  assert.equal((await send(route, '/changes/some-id')).text, '<h1>Admin</h1>');
  assert.match(String((await send(route, '/app.js')).headers['content-type']), /javascript/);
  for (const path of ['/../INITIAL-CREDENTIALS.txt', '/%2e%2e/INITIAL-CREDENTIALS.txt', '/%2e%2e%2fINITIAL-CREDENTIALS.txt', '/%5c..%5csecret', '/leak.txt', '/%00']) {
    assert.equal((await send(route, path)).status, 400, path);
  }
  assert.equal((await send(route, '/admin/v1/unknown')).status, 401);
});
test('real server binds port 0 and answers discovery and evaluation', async (t) => {
  const f = fixture(t);
  const server = createServer({ port: 0, dataDir: resolve(f.dir, 'live'), clock: 'fixed:2026-11-08T10:00:00Z' });
  t.after(() => server.close());
  try { await server.listen(); }
  catch (e) {
    if (e && typeof e === 'object' && 'code' in e && e.code === 'EPERM') { t.skip('Sandbox forbids listening on localhost (EPERM)'); return; }
    throw e;
  }
  const discovery = await fetch(server.url + '/.well-known/authzen-configuration'); assert.equal(discovery.status, 200);
  const credentials = JSON.parse(readFileSync(resolve(f.dir, 'live/INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string };
  const response = await fetch(server.url + '/access/v1/evaluation', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${credentials.pepApiKey}` }, body: JSON.stringify(evaluation()) });
  assert.equal(response.status, 200); assert.equal((await response.json()).decision, true);
  const oversized = await fetch(server.url + '/access/v1/evaluation', {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${credentials.pepApiKey}` }, body: 'x'.repeat(3 * 1_048_576),
  });
  assert.equal(oversized.status, 413);
  assert.equal(oversized.headers.get('connection'), 'close');
  assert.deepEqual(await oversized.json(), { error: 'payload_too_large', message: 'Body exceeds 1 MB' });
});

test('M4: refused CSRF/session and simulator requests have the correct actor and audit classification', async (t) => {
  const f = fixture(t); const route = handler(f);
  const login = await f.auth.login('amira', f.passwords.amira, 'ip');
  const proposal = { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY };
  assert.equal((await send(route, '/admin/v1/changes', 'POST', proposal, { cookie: `sid=${login.sid}` })).status, 403);
  const refusal = f.rt.audit.records().at(-1)!;
  assert.equal(refusal.actor, 'amira'); assert.equal(refusal.type, 'change'); assert.equal(refusal.effect, 'deny');
  assert.equal((await send(route, '/admin/v1/session', 'DELETE', undefined, { cookie: `sid=${login.sid}` })).status, 403);
  assert.equal(f.rt.audit.records().at(-1)?.type, 'session');
  assert.equal(f.rt.audit.records().at(-1)?.actor, 'amira');
  assert.equal((await send(route, '/admin/v1/changes', 'POST', proposal)).status, 401);
  assert.equal(f.rt.audit.records().at(-1)?.actor, 'unknown');
  const auditor = await f.auth.login('sam', f.passwords.sam, 'ip');
  assert.equal((await send(route, '/admin/v1/simulate/who-can', 'POST', { resourceId: 'CASE-14', action: 'read' }, { cookie: `sid=${auditor.sid}`, 'x-csrf-token': auditor.csrfToken })).status, 403);
  assert.equal(f.rt.audit.records().at(-1)?.type, 'simulation');
  assert.equal(f.rt.audit.records().at(-1)?.actor, 'sam');
});

test('decision-plane refusals are audited: failed PEP credentials and refused consumptions, one row a minute per source', async (t) => {
  const f = fixture(t); const route = handler(f);
  const refused = () => f.rt.audit.records().filter((r) => r.type === 'security' && r.action === 'refused');
  for (let i = 0; i < 5; i++) assert.equal((await send(route, '/access/v1/evaluation', 'POST', evaluation(), { authorization: 'Bearer guess' })).status, 401);
  assert.equal(refused().length, 1, 'a guessing run leaves one row, not five');
  assert.deepEqual({ ...refused()[0]!.details }, { route: '/access/v1/evaluation', error: 'unauthenticated', source: '127.0.0.1' });
  const consume = await send(route, '/x/v1/tokens/consume', 'POST', { token: 'forged', action: 'approve', resource: { type: 'payment', id: 'PAY-3' } }, { authorization: `Bearer ${f.pepApiKey}` });
  assert.ok(consume.status >= 400);
  assert.equal(refused().at(-1)?.details?.route, '/x/v1/tokens/consume');
});

test('rate limits: the decision plane has its own budget, both are configurable and validated', async (t) => {
  const f = fixture(t); const route = createHandler(f.rt, f.auth, { rateLimit: 2, staticDir: resolve(f.dir, 'static') }, () => 'http://localhost:8787');
  const pep = { authorization: `Bearer ${f.pepApiKey}` };
  // console budget of 2 a minute; the default decision-plane budget serves far more than the old 120 a minute
  for (let i = 0; i < 150; i++) assert.equal((await send(route, '/access/v1/evaluation', 'POST', evaluation(), pep)).status, 200, `evaluation ${i}`);
  const batch = await send(route, '/access/v1/evaluations', 'POST', { evaluations: Array.from({ length: 1000 }, () => evaluation()) }, pep);
  assert.equal(batch.status, 200, 'the largest batch fits the default budget');
  assert.deepEqual(rateLimitsFromEnv({}), {});
  assert.deepEqual(rateLimitsFromEnv({ RATE_LIMIT_PER_MINUTE: '600', PEP_RATE_LIMIT_PER_MINUTE: '120000' }), { rateLimit: 600, pepRateLimit: 120000 });
  assert.throws(() => rateLimitsFromEnv({ PEP_RATE_LIMIT_PER_MINUTE: '999' }), /at least 1000/);
  assert.throws(() => rateLimitsFromEnv({ RATE_LIMIT_PER_MINUTE: '0' }), /at least 1/);
  assert.throws(() => rateLimitsFromEnv({ RATE_LIMIT_PER_MINUTE: '1.5' }), /integer/);
});

test('refusalLimiter admits one key a window and reports what it left out', () => {
  let now = 0; const cap = refusalLimiter(1000, 2, () => now);
  assert.equal(cap.admit('a'), 0); assert.equal(cap.admit('a'), undefined); assert.equal(cap.admit('a'), undefined);
  now = 1000; assert.equal(cap.admit('a'), 2);
  cap.admit('b'); cap.admit('c'); // 'a' is forgotten past two keys
  assert.equal(cap.admit('a'), 0);
});

test('M1: HTTP batch evaluations are charged before any decision executes', async (t) => {
  const f = fixture(t); const route = handler(f, 2);
  const response = await send(route, '/access/v1/evaluations', 'POST', { evaluations: [evaluation(), evaluation(), evaluation()] }, { authorization: `Bearer ${f.pepApiKey}` });
  assert.equal(response.status, 429);
  assert.equal(f.rt.decisions, 0);
});

test('M3/M5: HTTP rejects non-JSON logins and API SPA fallbacks; static directories never get read as files', async (t) => {
  const f = fixture(t); const route = handler(f); const dir = resolve(f.dir, 'static');
  mkdirSync(dir); mkdirSync(resolve(dir, 'nested')); mkdirSync(resolve(dir, 'nested/index.html'));
  writeFileSync(resolve(dir, 'index.html'), '<h1>Admin</h1>');
  const denied = await send(route, '/admin/v1/session', 'POST', { username: 'amira', password: f.passwords.amira }, { 'content-type': 'text/plain' });
  assert.equal(denied.status, 415);
  assert.equal((await send(route, '/admin/v1')).status, 404);
  assert.equal((await send(route, '/admin/v2/foo')).status, 404);
  assert.equal((await send(route, '/nested')).status, 404);
  const staticPage = await send(route, '/');
  assert.equal(staticPage.status, 200); assert.equal(staticPage.headers['cache-control'], undefined);
});

test('L1: session endpoints resolve the session once and TLS sets a Secure cookie', async (t) => {
  const f = fixture(t); const route = handler(f);
  const logged = await f.auth.login('amira', f.passwords.amira, 'ip');
  const original = f.auth.session.bind(f.auth);
  let calls = 0;
  f.auth.session = (...args) => { calls++; return original(...args); };
  const headers = { cookie: `sid=${logged.sid}`, 'x-csrf-token': logged.csrfToken };
  assert.equal((await send(route, '/admin/v1/session', 'GET', undefined, headers)).status, 200);
  assert.equal(calls, 1);
  assert.equal((await send(route, '/admin/v1/session', 'DELETE', undefined, headers)).status, 204);
  assert.equal(calls, 2);
  const socket = { remoteAddress: 'ip', readable: false, encrypted: true } as unknown as ConstructorParameters<typeof IncomingMessage>[0];
  const request = new IncomingMessage(socket);
  request.url = '/admin/v1/session'; request.method = 'POST'; request.headers = { 'content-type': 'application/json' };
  const response = new ServerResponse(request); response.end = (() => response) as typeof response.end;
  const pending = route(request, response);
  request.push(JSON.stringify({ username: 'amira', password: f.passwords.amira })); request.push(null);
  await pending;
  assert.equal(response.statusCode, 200);
  assert.match(String(response.getHeader('Set-Cookie')), /; Secure$/);
});

test('rate limits refill on elapsed time, not on the pinned business clock (CLOCK=fixed demo)', async (t) => {
  const f = fixture(t); let ms = 0;
  const route = createHandler(f.rt, f.auth, { rateLimit: 1, staticDir: resolve(f.dir, 'static'), elapsed: () => ms }, () => 'http://localhost:8787');
  assert.equal((await send(route, '/.well-known/authzen-configuration')).status, 200);
  assert.equal((await send(route, '/.well-known/authzen-configuration')).status, 429);
  ms += 60_000;
  assert.equal((await send(route, '/.well-known/authzen-configuration')).status, 200);
  const auth = new Auth(f.dir, f.rt.audit, f.rt.now, () => ms);
  for (let i = 0; i < 5; i++) await auth.login('sam', f.passwords.sam, 'ip');
  await assert.rejects(async () => auth.login('sam', f.passwords.sam, 'ip'), (e: { status?: number }) => e.status === 429);
  ms += 60_000;
  assert.ok((await auth.login('sam', f.passwords.sam, 'ip')).sid);
});

test('audit rows are bounded: an attacker-sized route or name is cut with a marker and its SHA-256, a row is capped', async (t) => {
  const f = fixture(t); const route = handler(f);
  const long = `/admin/v1/${'a'.repeat(6000)}`;
  assert.equal((await send(route, long, 'POST', {})).status, 401);
  const refused = f.rt.audit.records().at(-1)!;
  assert.equal(refused.action, 'refused');
  const kept = String(refused.details?.route);
  assert.ok(kept.length < 400, `${kept.length} characters`);
  assert.ok(kept.startsWith('/admin/v1/aaaa') && kept.includes('[truncated 6010 chars, sha256:'), kept);
  assert.ok(kept.includes(createHash('sha256').update(long).digest('hex')), 'the hash of the full value');
  f.rt.audit.append({ type: 'security', actor: 'x'.repeat(10_000), action: 'test', details: { many: Array.from({ length: 200 }, (_, i) => `${i}`.padEnd(400, 'y')) } });
  const capped = f.rt.audit.records().at(-1)!;
  assert.ok(JSON.stringify(capped).length < AUDIT_MAX_ROW + 1024);
  assert.equal(capped.details?.truncated, true); assert.match(String(capped.details?.sha256), /^[0-9a-f]{64}$/);
  assert.ok(capped.actor.length < 400);
  assert.equal(f.rt.audit.verify().verified, true, 'the chain covers the bounded rows');
});
