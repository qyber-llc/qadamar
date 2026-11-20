import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { constants, generateKeyPairSync, sign } from 'node:crypto';
import { Oidc } from '../src/oidc.ts';

const EVENT = 'http://schemas.openid.net/event/backchannel-logout';
const NOW = Date.parse('2026-11-10T10:00:00Z');
const NOW_S = NOW / 1000;
const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');

async function setup(t: { after: (fn: () => unknown) => void }) {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const server: Server = createServer((req, res) => {
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const send = (value: unknown): void => {
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(value));
    };
    if (req.url === '/.well-known/openid-configuration') return send({
      issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, jwks_uri: `${base}/jwks`,
    });
    if (req.url === '/jwks') return send({ keys: [
      { ...rsa.publicKey.export({ format: 'jwk' }), kid: 'rsa', use: 'sig' },
      { ...ec.publicKey.export({ format: 'jwk' }), kid: 'ec', use: 'sig' },
    ] });
    res.statusCode = 404;
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const issuer = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  let now = NOW, sequence = 0;
  const oidc = new Oidc({ issuer, clientId: 'gate-console', idClaim: 'sub' }, 'https://gate.example', () => now);
  const signParts = (head: string, body: string, alg: string): string => {
    const data = Buffer.from(`${head}.${body}`);
    const signature = alg === 'ES256'
      ? sign('sha256', data, { key: ec.privateKey, dsaEncoding: 'ieee-p1363' })
      : alg === 'PS256'
        ? sign('sha256', data, { key: rsa.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 })
        : sign('sha256', data, rsa.privateKey);
    return `${head}.${body}.${signature.toString('base64url')}`;
  };
  const makeToken = (claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}): string => {
    const jose = { alg: 'RS256', kid: 'rsa', typ: 'logout+jwt', ...header };
    const payload = {
      iss: issuer, aud: 'gate-console', iat: NOW_S, jti: `jti-${++sequence}`, events: { [EVENT]: {} }, ...claims,
    };
    return signParts(encode(jose), encode(payload), String(jose.alg));
  };
  return { oidc, makeToken, signParts, advance: (ms: number) => { now += ms; } };
}

const withoutSignature = (token: string): string => `${token.split('.').slice(0, 2).join('.')}.`;
const tamperSignature = (token: string): string => {
  const parts = token.split('.');
  const signature = parts[2]!;
  parts[2] = `${signature[0] === 'A' ? 'B' : 'A'}${signature.slice(1)}`;
  return parts.join('.');
};

test('logout tokens accept sid or sub, audience arrays, and all permitted algorithms', async (t) => {
  const { oidc, makeToken } = await setup(t);
  assert.deepEqual(await oidc.verifyLogoutToken(makeToken({ sid: 'session-1', jti: 'sid-only' })), { sid: 'session-1', jti: 'sid-only' });
  assert.deepEqual(await oidc.verifyLogoutToken(makeToken({ sub: 'user-1', jti: 'sub-only' })), { sub: 'user-1', jti: 'sub-only' });
  assert.deepEqual(await oidc.verifyLogoutToken(makeToken({ sub: 'user-2', sid: 'session-2', jti: 'both', aud: ['other', 'gate-console'] })), {
    sub: 'user-2', sid: 'session-2', jti: 'both',
  });
  assert.deepEqual(await oidc.verifyLogoutToken(makeToken({ sid: 'ps', jti: 'ps' }, { alg: 'PS256' })), { sid: 'ps', jti: 'ps' });
  assert.deepEqual(await oidc.verifyLogoutToken(makeToken({ sid: 'es', jti: 'es' }, { alg: 'ES256', kid: 'ec' })), { sid: 'es', jti: 'es' });
});

test('logout tokens reject bad signatures, issuer, audience, and algorithm or key mismatches', async (t) => {
  const { oidc, makeToken } = await setup(t);
  assert.equal(await oidc.verifyLogoutToken(tamperSignature(makeToken({ sid: 's' }))), null);
  assert.equal(await oidc.verifyLogoutToken(withoutSignature(makeToken({ sid: 's' }))), null);
  for (const claims of [
    { iss: 'https://attacker.example' },
    { aud: 'someone-else' },
    { aud: ['someone-else'] },
    { aud: undefined },
    { aud: ['gate-console', 42] },
  ]) assert.equal(await oidc.verifyLogoutToken(makeToken({ sid: 's', ...claims })), null);
  assert.equal(await oidc.verifyLogoutToken(makeToken({ sid: 's' }, { alg: 'none' })), null);
  assert.equal(await oidc.verifyLogoutToken(makeToken({ sid: 's' }, { alg: 'HS256' })), null);
  assert.equal(await oidc.verifyLogoutToken(makeToken({ sid: 's' }, { alg: ['RS256'] })), null);
  assert.equal(await oidc.verifyLogoutToken(makeToken({ sid: 's' }, { alg: 'ES256', kid: 'rsa' })), null);
});

test('logout tokens require finite iat within clock skew and validate optional exp and nbf', async (t) => {
  const { oidc, makeToken } = await setup(t);
  for (const iat of [undefined, 'now', null, Number.NaN, Number.POSITIVE_INFINITY, NOW_S + 61]) {
    assert.equal(await oidc.verifyLogoutToken(makeToken({ sid: 's', iat })), null);
  }
  assert.ok(await oidc.verifyLogoutToken(makeToken({ sid: 's', iat: NOW_S + 60 })));
  for (const claims of [
    { exp: NOW_S - 61 }, { exp: null }, { exp: Number.POSITIVE_INFINITY },
    { nbf: NOW_S + 61 }, { nbf: null }, { nbf: Number.NaN },
  ]) assert.equal(await oidc.verifyLogoutToken(makeToken({ sid: 's', ...claims })), null);
  assert.ok(await oidc.verifyLogoutToken(makeToken({ sid: 's', exp: NOW_S - 60 })));
  assert.ok(await oidc.verifyLogoutToken(makeToken({ sid: 's', nbf: NOW_S + 60 })));
});

test('logout tokens require the back-channel logout event and sid or sub, and prohibit nonce', async (t) => {
  const { oidc, makeToken } = await setup(t);
  for (const events of [
    undefined, null, [], {}, { 'wrong:event': {} }, { [EVENT]: null }, { [EVENT]: [] }, { [EVENT]: 'logout' },
  ]) assert.equal(await oidc.verifyLogoutToken(makeToken({ sid: 's', events })), null);
  // the spec requires the member to be an object and only RECOMMENDS it empty; other events may sit beside it
  assert.ok(await oidc.verifyLogoutToken(makeToken({ sid: 's', events: { [EVENT]: { reason: 'x' }, extra: {} } })));
  for (const claims of [
    {}, { sub: '' }, { sid: '' }, { sub: '', sid: '' }, { sub: 42 }, { sid: 42 },
    { sub: 'user', sid: '' }, { sub: '', sid: 'session' }, { sid: 's', nonce: null }, { sub: 'u', nonce: 'n' },
    { sid: 's', jti: undefined }, { sid: 's', jti: '' }, { sid: 's', jti: 42 },
  ]) assert.equal(await oidc.verifyLogoutToken(makeToken(claims)), null);
});

test('logout token jtis are single use and are claimed only after complete validation', async (t) => {
  const { oidc, makeToken } = await setup(t);
  const token = makeToken({ sub: 'user', jti: 'once' });
  assert.deepEqual(await oidc.verifyLogoutToken(token), { sub: 'user', jti: 'once' });
  assert.equal(await oidc.verifyLogoutToken(token), null);
  assert.equal(await oidc.verifyLogoutToken(makeToken({ sub: 'other', jti: 'once' })), null);

  const forged = makeToken({ sid: 's', jti: 'after-bad-signature' });
  assert.equal(await oidc.verifyLogoutToken(tamperSignature(forged)), null);
  assert.ok(await oidc.verifyLogoutToken(forged));
  assert.equal(await oidc.verifyLogoutToken(makeToken({ sid: 's', jti: 'after-bad-claims', events: {} })), null);
  assert.ok(await oidc.verifyLogoutToken(makeToken({ sid: 's', jti: 'after-bad-claims' })));
});

test('logout replay entries expire and a full cache fails closed', async (t) => {
  const { oidc, makeToken, advance } = await setup(t);
  const token = makeToken({ sid: 's', jti: 'bounded' });
  assert.ok(await oidc.verifyLogoutToken(token));
  advance(24 * 60 * 60_000 + 1);
  assert.ok(await oidc.verifyLogoutToken(token));

  const cache = (oidc as unknown as { logoutJtis: Map<string, number> }).logoutJtis;
  for (let i = 0; i < 10_000; i++) cache.set(`full-${i}`, NOW + 48 * 60 * 60_000);
  assert.equal(await oidc.verifyLogoutToken(makeToken({ sid: 's', jti: 'over-limit' })), null);
  for (const [jti] of cache) cache.set(jti, NOW - 1);
  assert.ok(await oidc.verifyLogoutToken(makeToken({ sid: 's', jti: 'after-prune' })));
});

test('malformed compact JWS and unsupported headers return null without throwing', async (t) => {
  const { oidc, makeToken, signParts } = await setup(t);
  const valid = makeToken({ sid: 's' });
  for (const token of [
    '', 'a.b', 'a.b.c.d', `${valid}=`, tamperSignature(valid).replace(/.$/, '='),
    `${encode(null)}.${encode({})}.AA`, `${encode([])}.${encode({})}.AA`,
    `${encode({ alg: 'RS256' })}.${encode(null)}.AA`, `${encode({ alg: 'RS256' })}.${encode([])}.AA`,
    'AB.AB.AA', '!.AA.AA', `${valid.split('.')[0]}.${valid.split('.')[1]}.!`,
  ]) assert.equal(await oidc.verifyLogoutToken(token), null);
  for (const header of [{ typ: undefined }, { typ: 'JWT' }]) assert.ok(await oidc.verifyLogoutToken(makeToken({ sid: 's' }, header)));
  for (const header of [
    { typ: 'at+jwt' }, { typ: 42 }, { typ: 'logout+jwt', crit: ['b64'], b64: false },
    { typ: 'logout+jwt', b64: true }, { typ: 'logout+jwt', kid: 42 },
  ]) assert.equal(await oidc.verifyLogoutToken(makeToken({ sid: 's' }, header)), null);
  const invalidUtf8 = Buffer.from([0xc3, 0x28]).toString('base64url');
  assert.equal(await oidc.verifyLogoutToken(signParts(encode({ alg: 'RS256', kid: 'rsa', typ: 'logout+jwt' }), invalidUtf8, 'RS256')), null);
});
