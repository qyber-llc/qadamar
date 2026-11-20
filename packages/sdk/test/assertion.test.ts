// The backend side of decision assertions: the example node:http backend behind withGateAssertion refuses unsigned,
// expired, replayed, re-targeted and wrong-key requests, and follows the PDP's key rotation through its JWKS.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { request, type Server } from 'node:http';
import { AssertionVerifier, bodySha256, MemoryReplayStore, type AssertionVerifierOptions, type ReplayStore } from '../src/index.ts';
import { exampleBackend } from '../src/example-backend.ts';

const T0 = Date.parse('2026-11-08T10:00:00Z');
let nowMs = T0;
const pair = (): { publicKey: KeyObject; privateKey: KeyObject } => generateKeyPairSync('ed25519');
const k1 = pair(); const k2 = pair(); const attacker = pair();
const jwk = (key: KeyObject, kid: string, extra: Record<string, unknown> = {}) => ({ ...key.export({ format: 'jwk' }), kid, use: 'sig', alg: 'EdDSA', ...extra });
let published: unknown[] = [jwk(k1.publicKey, 'k1')];
let jwksUp = true;
let fetches = 0;
let lastInit: RequestInit | undefined;
const fakeFetch = (async (_url: unknown, init?: RequestInit) => {
  fetches++; lastInit = init;
  return jwksUp ? new Response(JSON.stringify({ keys: published }), { status: 200 }) : new Response('down', { status: 503 });
}) as unknown as typeof fetch;

let server: Server; let audience = '';
before(async () => {
  // audience is the backend's own origin; known once it listens, so the verifier reads it lazily
  let verifier: AssertionVerifier | undefined;
  const proxy = { verify: (r: Parameters<AssertionVerifier['verify']>[0]) => required(verifier).verify(r) } as unknown as AssertionVerifier;
  server = exampleBackend(proxy);
  await new Promise<void>((accept) => server.listen(0, '127.0.0.1', accept));
  const address = server.address();
  audience = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
  verifier = new AssertionVerifier({ jwksUrl: 'https://pdp.test/.well-known/jwks.json', audience, fetch: fakeFetch, now: () => nowMs });
});
after(() => new Promise<void>((accept) => { server.closeAllConnections(); server.close(() => accept()); }));
function required<T>(v: T | undefined): T { assert.ok(v !== undefined); return v; }

const b64 = (v: unknown): string => Buffer.from(JSON.stringify(v)).toString('base64url');
let counter = 0;
function assertion(over: Record<string, unknown> = {}, opts: { key?: KeyObject; header?: Record<string, unknown> } = {}): string {
  const iat = Math.floor(nowMs / 1000);
  const claims = { sub: { type: 'user', id: 'bob' }, act: 'read', res: { type: 'case', id: 'CASE-14' }, did: `d-${++counter}`, pv: 'pv1',
    aud: audience, htm: 'GET', htp: '/cases/CASE-14', bsh: bodySha256(Buffer.alloc(0)), iat, exp: iat + 30, nonce: `n-${counter}`, ...over };
  const content = `${b64({ alg: 'EdDSA', typ: 'gate-assertion+jwt', kid: 'k1', ...opts.header })}.${b64(claims)}`;
  return `${content}.${sign(null, Buffer.from(content), opts.key ?? k1.privateKey).toString('base64url')}`;
}
interface Reply { status: number; json: Record<string, unknown> }
function call(path: string, header?: string, method = 'GET', body = ''): Promise<Reply> {
  return new Promise((accept, reject) => {
    const req = request(`${audience}${path}`, { method, agent: false, headers: header === undefined ? {} : { 'gate-assertion': header } }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => accept({ status: res.statusCode ?? 0, json: JSON.parse(Buffer.concat(chunks).toString() || '{}') as Record<string, unknown> }));
    });
    req.on('error', reject);
    req.end(body);
  });
}
const refused = async (reply: Promise<Reply>, error: string, status = 401): Promise<void> => {
  const r = await reply;
  assert.deepEqual([r.status, r.json.error], [status, error]);
};

test('a valid assertion is accepted once, and the handler reads who and what from the claims', async () => {
  const token = assertion();
  const ok = await call('/cases/CASE-14', token);
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.json.subject, { type: 'user', id: 'bob' });
  assert.deepEqual(ok.json.resource, { type: 'case', id: 'CASE-14' });
  assert.equal(lastInit?.redirect, 'error', 'the JWKS fetch must not follow a redirect');
  await refused(call('/cases/CASE-14', token), 'assertion_replayed');
  const posted = '{"status":"approved"}';
  const post = assertion({ htm: 'POST', htp: '/payments/PAY-3/approve', bsh: bodySha256(Buffer.from(posted)), act: 'approve', res: { type: 'payment', id: 'PAY-3' } });
  assert.equal((await call('/payments/PAY-3/approve', post, 'POST', posted)).status, 200);
});

test('unsigned, malformed and confused tokens are refused', async () => {
  await refused(call('/cases/CASE-14'), 'assertion_missing');
  await refused(call('/cases/CASE-14', 'not-a-jws'), 'assertion_invalid');
  const [h, p, s] = assertion().split('.');
  await refused(call('/cases/CASE-14', `${h}.${p}.`), 'assertion_invalid');
  await refused(call('/cases/CASE-14', `${h}.${p}`), 'assertion_invalid');
  await refused(call('/cases/CASE-14', `${h}.${p}.${s}.x`), 'assertion_invalid');
  await refused(call('/cases/CASE-14', `${h}=.${p}.${s}`), 'assertion_invalid');
  await refused(call('/cases/CASE-14', assertion({}, { header: { typ: 'JWT' } })), 'assertion_invalid', 401);
  await refused(call('/cases/CASE-14', assertion({}, { header: { alg: 'none' } })), 'assertion_invalid');
  await refused(call('/cases/CASE-14', assertion({}, { header: { jku: 'https://evil.test' } })), 'assertion_invalid');
  await refused(call('/cases/CASE-14', assertion({ extra: 1 })), 'assertion_invalid');
  await refused(call('/cases/CASE-14', assertion({ sub: { type: 'user' } })), 'assertion_invalid');
  await refused(call('/cases/CASE-14', assertion({ exp: Math.floor(nowMs / 1000) + 300 })), 'assertion_invalid', 401);
  // an unsigned payload swapped under a valid signature
  const other = assertion({ sub: { type: 'user', id: 'admin' } }).split('.')[1];
  await refused(call('/cases/CASE-14', `${h}.${other}.${s}`), 'assertion_invalid');
});

test('expired and future assertions are refused, within the clock skew they pass', async () => {
  const now = Math.floor(nowMs / 1000);
  await refused(call('/cases/CASE-14', assertion({ iat: now - 40, exp: now - 10 })), 'assertion_expired');
  assert.equal((await call('/cases/CASE-14', assertion({ iat: now - 33, exp: now - 3 }))).status, 200, 'skew 5 s');
  await refused(call('/cases/CASE-14', assertion({ iat: now + 10, exp: now + 40 })), 'assertion_invalid');
  assert.equal((await call('/cases/CASE-14', assertion({ iat: now + 4, exp: now + 34 }))).status, 200);
});

test('a request re-targeted to another path, method, body or backend is refused', async () => {
  await refused(call('/cases/CASE-7', assertion()), 'assertion_mismatch');
  await refused(call('/cases/CASE-14?all=1', assertion()), 'assertion_mismatch');
  await refused(call('/cases/CASE-14', assertion(), 'DELETE'), 'assertion_mismatch');
  await refused(call('/cases/CASE-14', assertion({ htm: 'POST' }), 'POST', 'smuggled'), 'assertion_mismatch');
  await refused(call('/cases/CASE-14', assertion({ aud: 'http://other-backend:8080' })), 'assertion_mismatch');
  // a refused request does not spend the nonce: the genuine one still passes
  const token = assertion();
  await refused(call('/cases/CASE-7', token), 'assertion_mismatch');
  assert.equal((await call('/cases/CASE-14', token)).status, 200);
});

test('wrong keys are refused, rotation is followed through the JWKS, and an unreachable JWKS fails closed', async () => {
  await refused(call('/cases/CASE-14', assertion({}, { key: attacker.privateKey })), 'assertion_invalid', 401);
  await refused(call('/cases/CASE-14', assertion({}, { key: attacker.privateKey, header: { kid: 'evil' } })), 'assertion_key_unknown');
  // the PDP rotates: k2 signs, k1 stays published for its grace period
  published = [jwk(k1.publicKey, 'k1'), jwk(k2.publicKey, 'k2')];
  const signedByK2 = (): string => assertion({}, { key: k2.privateKey, header: { kid: 'k2' } });
  nowMs += 11_000;
  const before = fetches;
  assert.equal((await call('/cases/CASE-14', signedByK2())).status, 200, 'an unknown kid refetches the JWKS');
  assert.equal(fetches, before + 1);
  await refused(call('/cases/CASE-14', assertion({}, { key: attacker.privateKey, header: { kid: 'k3' } })), 'assertion_key_unknown');
  assert.equal(fetches, before + 1, 'unknown kids refetch at most every 10 s');
  // k1 retired: dropped from the JWKS, it stops verifying at the next refresh
  published = [jwk(k2.publicKey, 'k2'), jwk(attacker.publicKey, 'k1', { kty: 'RSA' }), { ...jwk(attacker.publicKey, 'kp'), d: 'private' }];
  nowMs += 301_000;
  await refused(call('/cases/CASE-14', assertion()), 'assertion_key_unknown');
  await refused(call('/cases/CASE-14', assertion({}, { key: attacker.privateKey, header: { kid: 'kp' } })), 'assertion_key_unknown', 401);
  assert.equal((await call('/cases/CASE-14', signedByK2())).status, 200);
  jwksUp = false;
  nowMs += 301_000;
  await refused(call('/cases/CASE-14', signedByK2()), 'jwks_unavailable', 503);
  jwksUp = true;
});

test('a shared replay store refuses on every replica an assertion another replica accepted; a failing store fails closed', async () => {
  // stand-in for Redis SET NX PX or a PostgreSQL unique insert: one atomic check-and-set shared by every replica
  published = [jwk(k1.publicKey, 'k1')]; // fresh verifiers below fetch the JWKS on first use
  const shared = new Map<string, number>();
  const calls: Array<[string, number]> = [];
  const store: ReplayStore = { spend: async (nonce, expiresAt) => {
    calls.push([nonce, expiresAt]);
    if (shared.has(nonce)) return false;
    shared.set(nonce, expiresAt); return true;
  } };
  const options = { jwksUrl: 'https://pdp.test/.well-known/jwks.json', audience, fetch: fakeFetch, now: () => nowMs, replayStore: store };
  const [replicaA, replicaB] = [new AssertionVerifier(options), new AssertionVerifier(options)];
  const token = assertion();
  const forwarded = { method: 'GET', path: '/cases/CASE-14', body: Buffer.alloc(0), header: token };
  assert.equal((await replicaA.verify(forwarded)).sub.id, 'bob');
  await assert.rejects(replicaB.verify(forwarded), (e: Error & { code?: string }) => e.code === 'assertion_replayed');
  const exp = JSON.parse(Buffer.from(required(token.split('.')[1]), 'base64url').toString()).exp as number;
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0], [calls[0]![0], exp + 5], 'expiry plus clock skew');
  // without the shared store each replica has its own memory: the documented per-process default
  const [alone1, alone2] = [new AssertionVerifier({ ...options, replayStore: undefined }), new AssertionVerifier({ ...options, replayStore: new MemoryReplayStore(() => nowMs) })];
  const other = { ...forwarded, header: assertion() };
  await alone1.verify(other); await alone2.verify(other);
  await assert.rejects(alone2.verify(other), (e: Error & { code?: string }) => e.code === 'assertion_replayed');
  const broken = new AssertionVerifier({ ...options, replayStore: { spend: () => { throw new Error('redis down'); } } });
  await assert.rejects(broken.verify({ ...forwarded, header: assertion() }), (e: Error & { code?: string }) => e.code === 'replay_store_unavailable');
});

test('verifier options are checked and oversized bodies are refused before verification', async () => {
  const base: AssertionVerifierOptions = { jwksUrl: 'https://pdp.test/jwks', audience: 'http://backend:8080' };
  for (const bad of [{ jwksUrl: 'ftp://pdp.test/jwks' }, { jwksUrl: 'https://u:p@pdp.test/jwks' }, { audience: 'http://backend:8080/path' },
    { clockSkewSeconds: 61 }, { clockSkewSeconds: 1.5 }, { jwksCacheSeconds: 5 }, { timeoutMs: 0 }]) {
    assert.throws(() => new AssertionVerifier({ ...base, ...bad }), TypeError, JSON.stringify(bad));
  }
  const small = exampleBackend(new AssertionVerifier({ ...base, fetch: fakeFetch }));
  await new Promise<void>((accept) => small.listen(0, '127.0.0.1', accept));
  const address = small.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  const status = await new Promise<number>((accept, reject) => {
    const req = request(`http://127.0.0.1:${port}/x`, { method: 'POST', agent: false }, (res) => { res.resume(); accept(res.statusCode ?? 0); });
    req.on('error', () => accept(413));
    req.end(Buffer.alloc(2_000_000));
    void reject;
  });
  assert.equal(status, 413);
  await new Promise<void>((accept) => { small.closeAllConnections(); small.close(() => accept()); });
});
