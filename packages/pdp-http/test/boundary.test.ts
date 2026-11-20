import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, utimesSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createCipheriv, createPublicKey, randomBytes, verify } from 'node:crypto';
import { Auth } from '../src/auth.ts';
import { Tokens, MAX_DECISION_TOKEN_TTL_SECONDS, SESSION_TOKEN_TTL_SECONDS } from '../src/tokens.ts';
import { admin } from '../src/admin/index.ts';
import { HttpError } from '../src/http.ts';
import { fixture, req, users, FIXED } from './helpers.ts';

const status = (code: number) => (error: unknown): boolean => error instanceof HttpError && error.status === code;
const bearer = (secret: string) => req({ authorization: `Bearer ${secret}` });
const call = (f: ReturnType<typeof fixture>, user: keyof typeof users, path: string, method = 'GET', body: Record<string, unknown> = {}): unknown =>
  admin(f.rt, users[user], method, new URL(`http://localhost/admin/v1${path}`), body, f.auth).value;

test('legacy shared PEP hash migrates to the bootstrap named credential without changing its secret', (t) => {
  const f = fixture(t);
  const file = resolve(f.dir, 'credentials.json');
  const current = JSON.parse(readFileSync(file, 'utf8')) as { users: unknown[]; pepCredentials: Array<{ hash: string }> };
  writeFileSync(file, JSON.stringify({ users: current.users, pepHash: current.pepCredentials[0]!.hash }), { mode: 0o600 });
  const restarted = new Auth(f.dir, f.rt.audit, f.rt.now);
  assert.match(restarted.pep(bearer(f.pepApiKey)), /^pep:[a-f0-9]{64}$/);
  assert.deepEqual(restarted.pepCredentials().map((credential) => ({ id: credential.id, name: credential.name })), [{ id: 'bootstrap', name: 'bootstrap' }]);
  const disk = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  assert.equal(disk.pepHash, undefined);
  assert.ok(!readFileSync(file, 'utf8').includes(f.pepApiKey));
});

test('PEP credentials show secrets once, overlap rotation, expire old secrets, revoke and audit every change', (t) => {
  const f = fixture(t);
  let ms = Date.parse(FIXED);
  const secured = new Auth(f.dir, f.rt.audit, f.rt.now, () => ms, { pepRotationGraceSeconds: 60 });
  const created = secured.createPepCredential('gateway production', 'lina');
  assert.ok(created.secret.startsWith(`pep.${created.credential.id}.`));
  assert.equal(created.credential.lastUsed, undefined);
  assert.match(secured.pep(bearer(created.secret)), /^pep:/);
  assert.ok(secured.pepCredentials().find((credential) => credential.id === created.credential.id)?.lastUsed);
  assert.ok(!readFileSync(resolve(f.dir, 'credentials.json'), 'utf8').includes(created.secret));
  assert.equal(JSON.stringify(secured.pepCredentials()).includes(created.secret), false);

  const rotated = secured.rotatePepCredential(created.credential.id, 'lina');
  assert.notEqual(rotated.secret, created.secret);
  assert.match(secured.pep(bearer(created.secret)), /^pep:/);
  assert.match(secured.pep(bearer(rotated.secret)), /^pep:/);
  const second = secured.rotatePepCredential(created.credential.id, 'lina');
  assert.match(secured.pep(bearer(rotated.secret)), /^pep:/, 'an earlier rotation remains valid for its own grace period');
  f.setClock('2026-11-08T10:01:01Z'); ms += 61_000;
  assert.throws(() => secured.pep(bearer(created.secret)), status(401));
  assert.throws(() => secured.pep(bearer(rotated.secret)), status(401));
  assert.match(secured.pep(bearer(second.secret)), /^pep:/);

  const revoked = secured.revokePepCredential(created.credential.id, 'lina');
  assert.equal(revoked.revoked, '2026-11-08T10:01:01Z');
  assert.throws(() => secured.pep(bearer(second.secret)), status(401));
  assert.throws(() => secured.rotatePepCredential(created.credential.id, 'lina'), status(409));
  const actions = f.rt.audit.records().filter((row) => row.type === 'security').map((row) => row.action);
  assert.deepEqual(actions, ['pep_credential_create', 'pep_credential_rotate', 'pep_credential_rotate', 'pep_credential_revoke']);
  const audit = JSON.stringify(f.rt.audit.records());
  for (const secret of [created.secret, rotated.secret, second.secret]) assert.ok(!audit.includes(secret));
});

test('PEP and signing-key admin routes enforce security officer writes and access admin reads', (t) => {
  const f = fixture(t);
  assert.ok((call(f, 'amira', '/pep-credentials') as { items: unknown[] }).items.length);
  assert.ok((call(f, 'lina', '/signing-keys') as { items: unknown[] }).items.length);
  assert.throws(() => call(f, 'sam', '/pep-credentials'), status(403));
  assert.throws(() => call(f, 'amira', '/pep-credentials', 'POST', { name: 'gateway' }), status(403));
  const created = call(f, 'lina', '/pep-credentials', 'POST', { name: 'gateway' }) as { credential: { id: string }; secret: string };
  assert.ok(created.secret);
  assert.throws(() => call(f, 'omar', `/pep-credentials/${created.credential.id}/revoke`, 'POST'), status(403));
  assert.ok(call(f, 'lina', `/pep-credentials/${created.credential.id}/revoke`, 'POST'));
  assert.throws(() => call(f, 'amira', '/signing-keys/rotate', 'POST'), status(403));
  const rotated = call(f, 'lina', '/signing-keys/rotate', 'POST') as { current: { kid: string } };
  assert.ok(rotated.current.kid);
  assert.equal(f.rt.audit.records().at(-1)?.action, 'signing_key_rotate');
  assert.equal(f.rt.audit.records().at(-1)?.details?.kid, rotated.current.kid, 'the audit row names the new key');
  const keys = JSON.stringify(f.rt.tokens.signingKeys());
  f.rt.audit.append = () => { throw new Error('Audit integrity failure'); };
  assert.throws(() => call(f, 'lina', '/signing-keys/rotate', 'POST'), /Audit integrity failure/);
  assert.equal(JSON.stringify(f.rt.tokens.signingKeys()), keys, 'a refused audit append leaves the keyring unchanged');
});

test('bootstrap plaintext survives failed sign-in but is removed on first success and by its timer', async (t) => {
  const f = fixture(t);
  const file = resolve(f.dir, 'INITIAL-CREDENTIALS.txt');
  const messages: string[] = [];
  const secured = new Auth(f.dir, f.rt.audit, f.rt.now, undefined, { initialCredentialsTtlSeconds: 1, onBootstrapStatus: (message) => messages.push(message) });
  await assert.rejects(async () => secured.login('amira', 'wrong-password', 'ip'), status(401));
  assert.equal(existsSync(file), true);
  assert.equal((await secured.login('amira', f.passwords.amira, 'ip')).user.id, 'amira');
  assert.equal(existsSync(file), false);
  assert.ok(messages[0]?.includes('first successful sign-in'));
  assert.ok(messages.every((message) => !message.includes(f.passwords.amira!) && !message.includes(f.pepApiKey)));

  const second = fixture(t);
  const timed = new Auth(second.dir, second.rt.audit, second.rt.now, undefined, { initialCredentialsTtlSeconds: 1 });
  assert.ok(timed);
  await new Promise((resolveWait) => setTimeout(resolveWait, 1100));
  assert.equal(existsSync(resolve(second.dir, 'INITIAL-CREDENTIALS.txt')), false);
});

test('decision tokens carry kid, JWKS verifies offline, and rotation retains old public keys for the maximum TTL', (t) => {
  const f = fixture(t);
  const context = { now: FIXED, network: 'trusted' as const };
  const oldToken = f.rt.tokens.issue({ sub: 'user:bob', act: 'write', res: 'case:CASE-14', ver: 1, pv: 'pv.test' }, 300, context);
  const expiringToken = f.rt.tokens.issue({ sub: 'user:bob', act: 'write', res: 'case:CASE-14', ver: 1, pv: 'pv.test' }, 300, context);
  const [header, payload, signature] = oldToken.split('.');
  const parsed = JSON.parse(Buffer.from(header!, 'base64url').toString()) as { alg: string; kid: string };
  assert.equal(parsed.alg, 'EdDSA'); assert.ok(parsed.kid);
  const jwk = f.rt.tokens.jwks().keys.find((key) => key.kid === parsed.kid)!;
  assert.equal(jwk.kty, 'OKP'); assert.equal(jwk.crv, 'Ed25519'); assert.equal(jwk.d, undefined);
  const publicKey = createPublicKey({ key: jwk as never, format: 'jwk' });
  assert.equal(verify(null, Buffer.from(`${header}.${payload}`), publicKey, Buffer.from(signature!, 'base64url')), true);

  const session = f.rt.tokens.issueSession({ sid: '11111111-1111-4111-8111-111111111111', sub: JSON.stringify(['user', 'carol']), pep: 'bootstrap', idle: 900 });
  const policy = { name: 'policy-before-rotation' };
  const policySignature = f.rt.tokens.detached(policy);
  const manifest = { format: 'gate-evidence-manifest/1', generatedAt: FIXED, packSha256: 'abc', sections: {} };
  const manifestSignature = f.rt.tokens.detached(manifest);
  const rotated = f.rt.tokens.rotate();
  assert.equal(rotated.previous.kid, parsed.kid);
  assert.equal(f.rt.tokens.jwks().keys.length, 2);
  const newToken = f.rt.tokens.issue({ sub: 'user:bob', act: 'write', res: 'case:CASE-14', ver: 1, pv: 'pv.test' }, 15, context);
  assert.notEqual(JSON.parse(Buffer.from(newToken.split('.')[0]!, 'base64url').toString()).kid, parsed.kid);
  f.setClock('2026-11-08T10:04:59Z');
  f.rt.tokens.consume(oldToken, () => true);
  f.setClock('2026-11-08T10:05:00Z');
  assert.equal(Date.parse(rotated.previous.verifyUntil!) - Date.parse(FIXED), MAX_DECISION_TOKEN_TTL_SECONDS * 1000);
  assert.equal(Date.parse((rotated.previous as typeof rotated.previous & { sessionVerifyUntil?: string }).sessionVerifyUntil!) - Date.parse(FIXED), SESSION_TOKEN_TTL_SECONDS * 1000);
  assert.throws(() => f.rt.tokens.consume(expiringToken, () => true), status(409), 'decision tokens keep the 300 s grace');
  assert.equal(f.rt.tokens.verifySession(session).sid, JSON.parse(Buffer.from(session.split('.')[1]!, 'base64url').toString()).sid, 'only BLP sessions keep their longer grace');
  assert.equal(f.rt.tokens.verifyDetached(policy, policySignature), false, 'policy signatures keep the 300 s grace');
  assert.equal(f.rt.tokens.verifyManifest(manifest, manifestSignature), true, 'evidence stays verifiable offline');
  assert.equal(f.rt.tokens.jwks().keys.length, 2, 'session tokens signed by the old key still verify');
  f.setClock('2026-11-08T11:00:00Z');
  assert.throws(() => f.rt.tokens.verifySession(session), status(403));
  assert.equal(f.rt.tokens.verifyManifest(manifest, manifestSignature), true);
  assert.equal(f.rt.tokens.jwks().keys.length, 1);
  f.setClock('2026-11-09T10:00:00Z');
  assert.equal(f.rt.tokens.verifyManifest(manifest, manifestSignature), true, 'retired public keys remain offline evidence history');
});

test('SIGNING_KEY_SEAL encrypts private keys at rest, migrates plaintext PEM and survives restart', (t) => {
  const f = fixture(t);
  const seal = randomBytes(32).toString('base64url');
  const sealed = new Tokens(f.dir, f.rt.now, undefined, { signingKeySeal: seal });
  assert.equal(existsSync(resolve(f.dir, 'signing-private.pem')), false);
  const disk = readFileSync(resolve(f.dir, 'signing-keys.json'), 'utf8');
  assert.ok(!disk.includes('PRIVATE KEY'));
  assert.ok(disk.includes('v2.'));
  const token = sealed.issue({ sub: 'user:bob', act: 'write', res: 'case:CASE-14', ver: 1, pv: 'pv.test' }, 15, { now: FIXED, network: 'trusted' });
  const restarted = new Tokens(f.dir, f.rt.now, undefined, { signingKeySeal: seal });
  restarted.consume(token, () => true);
  assert.throws(() => new Tokens(f.dir, f.rt.now, undefined, { signingKeySeal: randomBytes(32).toString('base64url') }));
  assert.throws(() => new Tokens(f.dir, f.rt.now));
  assert.throws(() => new Tokens(f.dir, f.rt.now, undefined, { signingKeySeal: 'short' }), /SIGNING_KEY_SEAL/);
});

test('the bootstrap lifetime counts from the file creation, so a restart does not extend it', async (t) => {
  const f = fixture(t);
  const file = resolve(f.dir, 'INITIAL-CREDENTIALS.txt');
  const old = new Date(Date.now() - 2 * 3_600_000);
  utimesSync(file, old, old);
  const messages: string[] = [];
  assert.ok(new Auth(f.dir, f.rt.audit, f.rt.now, undefined, { initialCredentialsTtlSeconds: 3600, onBootstrapStatus: (message) => messages.push(message) }));
  await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  assert.equal(existsSync(file), false);
  assert.ok(messages.some((message) => message.includes('configured expiry')));
});

test('back-channel logout ends sessions by sid, or by sub when the session has no IdP sid, and nothing else', (t) => {
  const f = fixture(t);
  const user = users.omar;
  const a1 = f.auth.issue(user, 'oidc', { sub: 'a', sid: '1' });
  const a2 = f.auth.issue(user, 'oidc', { sub: 'a', sid: '9' });
  const bare = f.auth.issue(user, 'oidc', { sub: 'a' });
  const b = f.auth.issue(user, 'oidc', { sub: 'b', sid: '2' });
  const local = f.auth.issue(user, 'password');
  const alive = (sid: string): boolean => { try { f.auth.session(req({ cookie: `sid=${sid}` }), false); return true; } catch { return false; } };
  assert.equal(f.auth.endOidcSessions({ sub: 'a', sid: '1' }), 2);
  assert.deepEqual([a1, a2, bare, b, local].map((s) => alive(s.sid)), [false, true, false, true, true]);
  assert.equal(f.auth.endOidcSessions({ sid: '2' }), 1);
  assert.equal(f.auth.endOidcSessions({ sub: 'a' }), 1);
  assert.deepEqual([a2, b, local].map((s) => alive(s.sid)), [false, false, true]);
});

test('the PEP rotation grace runs on real time, so a pinned business clock cannot keep an old secret alive', (t) => {
  const f = fixture(t); let ms = 0;
  const auth = new Auth(f.dir, f.rt.audit, f.rt.now, () => ms, { pepRotationGraceSeconds: 60 });
  const created = auth.createPepCredential('gateway', 'lina');
  const rotated = auth.rotatePepCredential(created.credential.id, 'lina');
  assert.match(auth.pep(bearer(created.secret)), /^pep:/);
  const cache = (auth as unknown as { verified: Map<string, Buffer> }).verified;
  const cached = cache.size;
  ms += 60_000; // CLOCK=fixed: the business clock has not moved at all
  assert.throws(() => auth.pep(bearer(created.secret)), status(401));
  assert.match(auth.pep(bearer(rotated.secret)), /^pep:/);
  assert.equal(cache.size, cached, 'the expired secret left the verified-digest cache, the new one joined it');
  auth.rotatePepCredential(created.credential.id, 'lina');
  auth.revokePepCredential(created.credential.id, 'lina');
  assert.equal(cache.size, 0, 'revocation drops every digest of the credential');
});

test('sealed signing keys bind their kid; v1 keys (no additional data) still load and are re-sealed as v2', (t) => {
  const f = fixture(t);
  const seal = randomBytes(32);
  const file = resolve(f.dir, 'signing-keys.json');
  const plain = JSON.parse(readFileSync(file, 'utf8')) as { keys: Array<{ kid: string; privateKey: string }> };
  const v1 = (text: string): string => {
    const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', seal, iv);
    const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    return `v1.${iv.toString('base64url')}.${cipher.getAuthTag().toString('base64url')}.${data.toString('base64url')}`;
  };
  writeFileSync(file, JSON.stringify({ keys: plain.keys.map((key) => ({ ...key, privateKey: v1(key.privateKey) })) }));
  const migrated = new Tokens(f.dir, f.rt.now, undefined, { signingKeySeal: seal.toString('hex') });
  const disk = JSON.parse(readFileSync(file, 'utf8')) as { keys: Array<{ kid: string; privateKey: string }> };
  assert.ok(disk.keys.every((key) => key.privateKey.startsWith('v2.')));
  const token = migrated.issue({ sub: 'user:bob', act: 'write', res: 'case:CASE-14', ver: 1, pv: 'pv.test' }, 15, { now: FIXED, network: 'trusted' });
  new Tokens(f.dir, f.rt.now, undefined, { signingKeySeal: seal.toString('hex') }).consume(token, () => true);
  writeFileSync(file, JSON.stringify({ keys: disk.keys.map((key) => ({ ...key, kid: `${key.kid}-moved` })) }));
  assert.throws(() => new Tokens(f.dir, f.rt.now, undefined, { signingKeySeal: seal.toString('hex') }), 'a sealed key moved to another kid does not open');
});

test('console sessions expire on real time even when the business clock is pinned (CLOCK=fixed)', async (t) => {
  const f = fixture(t); let ms = 1_000_000;
  const auth = new Auth(f.dir, f.rt.audit, f.rt.now, () => ms);
  const { sid } = await auth.login('amira', f.passwords.amira, 'ip');
  const asks = () => auth.session(req({ cookie: `sid=${sid}` }), false).user.id;
  assert.equal(asks(), 'amira');
  ms += 14 * 60_000; assert.equal(asks(), 'amira', 'touched within 15 minutes');
  ms += 16 * 60_000; assert.throws(asks, /unauthenticated|Unauthenticated|401/i, 'idle past 15 minutes while the business clock stood still');
});


test('a sealed value whose GCM tag was truncated is refused (the tag length is fixed at 16 bytes)', async () => {
  const { seal, unseal } = await import('../src/tokens.ts');
  const { randomBytes: rnd } = await import('node:crypto');
  const key = rnd(32);
  const sealed = seal('secret material', key, 'k1');
  assert.equal(unseal(sealed, key, 'k1'), 'secret material');
  const [v, iv, tag, data] = sealed.split('.');
  const short = [v, iv, Buffer.from(tag!, 'base64url').subarray(0, 4).toString('base64url'), data].join('.');
  assert.throws(() => unseal(short, key, 'k1'));
});
