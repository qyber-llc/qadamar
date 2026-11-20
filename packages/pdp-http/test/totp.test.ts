import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import type { TestContext } from 'node:test';
import { Audit } from '../src/audit.ts';
import { Auth } from '../src/auth.ts';
import { HttpError } from '../src/http.ts';
import { createServer } from '../src/server.ts';
import { base32, fromBase32, hotp, totpStep } from '../src/totp.ts';
import { FIXED, req } from './helpers.ts';

const SEAL = 'a'.repeat(64);
const status = (code: number) => (e: unknown): boolean => e instanceof HttpError && e.status === code;

test('RFC 6238 SHA-1 vectors (6-digit truncation), ±1 step, base32 round trip', async () => {
  const key = Buffer.from('12345678901234567890');
  for (const [seconds, code] of [[59, '287082'], [1111111109, '081804'], [1234567890, '005924'], [2000000000, '279037']] as const) {
    assert.equal(hotp(key, Math.floor(seconds / 30)), code);
    assert.equal(totpStep(key, code, seconds * 1000), Math.floor(seconds / 30));
  }
  const at = 1234567890 * 1000, step = Math.floor(at / 30_000);
  assert.equal(totpStep(key, hotp(key, step - 1), at), step - 1);
  assert.equal(totpStep(key, hotp(key, step + 1), at), step + 1);
  assert.equal(totpStep(key, hotp(key, step + 2), at), undefined);
  assert.equal(totpStep(key, '12345', at), undefined);
  assert.equal(totpStep(key, 123456, at), undefined);
  assert.equal(base32(Buffer.from('foobar')), 'MZXW6YTBOI');
  assert.deepEqual(fromBase32(base32(key)), key);
  assert.throws(() => fromBase32('abc'), /Invalid base32/);
});

function setup(t: TestContext, seal: string | null = SEAL) {
  const dir = mkdtempSync('/tmp/pdp-totp-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let wall = Date.parse(FIXED);
  const audit = new Audit(resolve(dir, 'audit.jsonl'), () => FIXED);
  const auth = new Auth(dir, audit, () => FIXED, () => wall, { signingKeySeal: seal ?? undefined });
  let n = 0;
  const ip = (): string => `ip-${n++}`; // the per-IP login throttle is not under test here
  const { passwords } = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<string, string> };
  const cookie = (sid: string) => req({ cookie: `sid=${sid}` });
  const secretOf = (uri: string): Buffer => fromBase32(new URL(uri).searchParams.get('secret')!);
  const code = (key: Buffer, offsetSteps = 0): string => hotp(key, Math.floor(wall / 30_000) + offsetSteps);
  return { dir, audit, auth, passwords, cookie, secretOf, code, ip, tick: (ms: number) => { wall += ms; } };
}

test('enrolment: local password session only, sealed secret, first valid code activates, recovery codes once', async (t) => {
  const s = setup(t);
  assert.deepEqual(Auth.accountsWithoutTotp(s.dir).sort(), ['amira', 'lina', 'omar', 'ruth', 'sam']);
  const sso = s.auth.issue({ id: 'amira', name: 'amira', roles: ['access_admin'] }, 'oidc', { sub: 'x' });
  await assert.rejects(async () => s.auth.enrolTotp(s.cookie(sso.sid), s.passwords.amira), status(403)); // an IdP user named like a local account
  await assert.rejects(async () => s.auth.enrolTotp(req(), s.passwords.amira), status(403));
  const amira = s.cookie((await s.auth.login('amira', s.passwords.amira, 'ip')).sid);
  assert.throws(() => s.auth.activateTotp(amira, '000000'), status(409));
  // re-authentication: a session alone cannot bind a second factor
  await assert.rejects(async () => s.auth.enrolTotp(amira, undefined), status(403));
  await assert.rejects(async () => s.auth.enrolTotp(amira, 'not-the-password'), status(403));
  const first = (await s.auth.enrolTotp(amira, s.passwords.amira)).otpauthUri;
  const { otpauthUri } = await s.auth.enrolTotp(amira, s.passwords.amira); // restarting replaces the pending secret
  assert.notEqual(first, otpauthUri);
  assert.match(otpauthUri, /^otpauth:\/\/totp\/Qadamar%3Aamira\?secret=[A-Z2-7]{32}&issuer=Qadamar&algorithm=SHA1&digits=6&period=30$/);
  const key = s.secretOf(otpauthUri);
  const disk = readFileSync(resolve(s.dir, 'credentials.json'), 'utf8');
  assert.ok(!disk.includes(base32(key)), 'the TOTP secret is never stored in clear');
  assert.match(disk, /"secret": "v2\./);
  assert.throws(() => s.auth.activateTotp(amira, s.code(s.secretOf(first))), status(422)); // the replaced secret
  assert.throws(() => s.auth.activateTotp(amira, 'nope'), status(422));
  const { recoveryCodes } = s.auth.activateTotp(amira, s.code(key));
  assert.equal(recoveryCodes.length, 10);
  assert.equal(new Set(recoveryCodes).size, 10);
  for (const c of recoveryCodes) assert.match(c, /^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$/);
  const stored = readFileSync(resolve(s.dir, 'credentials.json'), 'utf8');
  assert.ok(recoveryCodes.every((c) => !stored.includes(c) && !stored.includes(c.replaceAll('-', '').toUpperCase())));
  await assert.rejects(async () => s.auth.enrolTotp(amira, s.passwords.amira), status(409));
  assert.throws(() => s.auth.activateTotp(amira, s.code(key)), status(409));
  assert.ok(!Auth.accountsWithoutTotp(s.dir).includes('amira'));
  const actions = s.audit.records().filter((r) => r.type === 'security').map((r) => [r.action, r.effect ?? 'allow']);
  assert.deepEqual(actions, [['totp_enrol', 'deny'], ['totp_enrol', 'deny'], ['totp_enrol', 'allow'], ['totp_enrol', 'allow'], ['totp_activate', 'allow']]);
  const log = readFileSync(resolve(s.dir, 'audit.jsonl'), 'utf8');
  assert.ok(!log.includes(base32(key)) && recoveryCodes.every((c) => !log.includes(c)), 'no secret or code in the audit');
});

test('enrolment re-authenticates off the event loop (scrypt on the thread pool, as sign-in)', async (t) => {
  const s = setup(t);
  const amira = s.cookie((await s.auth.login('amira', s.passwords.amira, s.ip())).sid);
  let ticked = false;
  setImmediate(() => { ticked = true; });
  await s.auth.enrolTotp(amira, s.passwords.amira);
  assert.ok(ticked, 'the event loop ran while the password was being checked');
});

test('enrolment needs SIGNING_KEY_SEAL; an enrolled account fails closed when the seal key is gone', async (t) => {
  const bare = setup(t, null);
  const amira = bare.cookie((await bare.auth.login('amira', bare.passwords.amira, 'ip')).sid);
  await assert.rejects(async () => bare.auth.enrolTotp(amira, bare.passwords.amira), (e) => status(409)(e) && /SIGNING_KEY_SEAL/.test((e as Error).message));
  const s = setup(t);
  const session = s.cookie((await s.auth.login('omar', s.passwords.omar, 'ip')).sid);
  const key = s.secretOf((await s.auth.enrolTotp(session, s.passwords.omar)).otpauthUri);
  s.auth.activateTotp(session, s.code(key));
  const unsealed = new Auth(s.dir, s.audit, () => FIXED, () => Date.parse(FIXED) + 60_000);
  // the generic 401, as for a wrong password: a 503 here would confirm the password to whoever guessed it
  await assert.rejects(async () => unsealed.login('omar', s.passwords.omar, 'ip', s.code(key, 2)), status(401));
  await assert.rejects(async () => unsealed.login('omar', 'wrong-password', 'ip-2', s.code(key, 2)), status(401));
});

test('sign-in requires the code once enrolled; replays, wrong and used codes are refused and count towards lockout', async (t) => {
  const s = setup(t);
  const session = s.cookie((await s.auth.login('lina', s.passwords.lina, s.ip())).sid);
  const key = s.secretOf((await s.auth.enrolTotp(session, s.passwords.lina)).otpauthUri);
  const { recoveryCodes } = s.auth.activateTotp(session, s.code(key));
  const unauthenticated = status(401);
  await assert.rejects(async () => s.auth.login('lina', s.passwords.lina, s.ip()), unauthenticated);
  // the activation code's step is spent: the same code is a replay
  await assert.rejects(async () => s.auth.login('lina', s.passwords.lina, s.ip(), s.code(key)), unauthenticated);
  s.tick(30_000);
  const good = s.code(key);
  await assert.rejects(async () => s.auth.login('lina', 'wrong-password', s.ip(), good), unauthenticated); // a code never rescues a bad password
  const signed = await s.auth.login('lina', s.passwords.lina, 'ip-signed', good);
  assert.equal(signed.user.id, 'lina');
  assert.deepEqual(s.audit.records().at(-1)?.details, { method: 'password', mfa: 'totp', client: 'ip-signed' });
  await assert.rejects(async () => s.auth.login('lina', s.passwords.lina, s.ip(), good), unauthenticated); // replay within its window
  await assert.rejects(async () => s.auth.login('lina', s.passwords.lina, s.ip(), s.code(key, -1)), unauthenticated); // an older step
  const deny = s.audit.records().at(-1)!;
  assert.equal(deny.effect, 'deny'); assert.equal(deny.details?.reason, 'second_factor'); assert.match(String(deny.details?.client), /^ip-\d+$/);
  // recovery code: any case and spacing, single use
  const recovery = recoveryCodes[0]!;
  assert.equal((await s.auth.login('lina', s.passwords.lina, s.ip(), ` ${recovery.toUpperCase()} `)).user.id, 'lina');
  assert.deepEqual(s.audit.records().at(-2)?.details, { remaining: 9 });
  assert.equal(s.audit.records().at(-1)?.details?.mfa, 'recovery');
  await assert.rejects(async () => s.auth.login('lina', s.passwords.lina, s.ip(), recovery), unauthenticated);
  await assert.rejects(async () => s.auth.login('lina', s.passwords.lina, s.ip(), 'x'.repeat(65)), unauthenticated);
  // second-factor failures count like password failures: past five on the account, a client that failed waits, the
  // right code included (a client that never failed is not locked out by the others, CWE-307)
  s.tick(30_000);
  await assert.rejects(async () => s.auth.login('lina', s.passwords.lina, 'ip-failing', '000000'), unauthenticated);
  await assert.rejects(async () => s.auth.login('lina', s.passwords.lina, 'ip-failing', s.code(key)), status(429));
  const log = readFileSync(resolve(s.dir, 'audit.jsonl'), 'utf8');
  assert.ok(!log.includes(good) && !log.includes(recovery), 'codes never reach the audit');
});

test('second-factor failures lock the account for every client; password failures from strangers do not', async (t) => {
  const s = setup(t);
  const session = s.cookie((await s.auth.login('lina', s.passwords.lina, s.ip())).sid);
  const key = s.secretOf((await s.auth.enrolTotp(session, s.passwords.lina)).otpauthUri);
  s.auth.activateTotp(session, s.code(key));
  s.tick(30_000);
  // a stranger guessing passwords from other addresses does not lock the owner's address
  for (let i = 0; i < 6; i++) await assert.rejects(async () => s.auth.login('lina', 'wrong-password', s.ip()), status(401));
  // the password is known, the code is not: rotating addresses must not buy fresh tries
  for (let i = 0; i < 5; i++) await assert.rejects(async () => s.auth.login('lina', s.passwords.lina, s.ip(), '000000'), status(401));
  assert.equal(s.audit.records().at(-1)?.details?.reason, 'second_factor');
  await assert.rejects(async () => s.auth.login('lina', s.passwords.lina, s.ip(), s.code(key)), status(429));
  // the lock runs on real elapsed time and is progressive, then lifts
  const store = JSON.parse(readFileSync(resolve(s.dir, 'lockouts.json'), 'utf8')) as Array<[string, unknown]>;
  assert.ok(store.some(([k]) => k === 'account-mfa:lina'), 'persisted through the lock store');
});

test('HTTP: enrol and activate through the session routes, then sign in with a recovery code', async (t) => {
  const s = setup(t);
  const dataDir = resolve(s.dir, 'live');
  const server = createServer({ port: 0, dataDir, signingKeySeal: SEAL });
  t.after(() => server.close());
  await server.listen();
  const { passwords } = JSON.parse(readFileSync(resolve(dataDir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<string, string> };
  const call = async (path: string, body: unknown, headers: Record<string, string> = {}) => {
    const res = await fetch(server.url + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
    return { status: res.status, cookie: res.headers.get('set-cookie')?.split(';')[0] ?? '', data: await res.json() as Record<string, unknown> };
  };
  const login = await call('/admin/v1/session', { username: 'sam', password: passwords.sam });
  assert.equal(login.status, 200);
  const headers = { cookie: login.cookie, 'x-csrf-token': String(login.data.csrfToken) };
  const status = async () => (await fetch(server.url + '/admin/v1/session/totp', { headers: { cookie: login.cookie } })).json();
  assert.deepEqual(await status(), { active: false, pending: false, available: true });
  assert.equal((await fetch(server.url + '/admin/v1/session/totp')).status, 401);
  assert.equal((await call('/admin/v1/session/totp/enrol', {}, { cookie: login.cookie })).status, 403); // CSRF token required
  assert.equal((await call('/admin/v1/session/totp/enrol', {}, headers)).status, 403, 'the current password is required');
  const enrol = await call('/admin/v1/session/totp/enrol', { password: passwords.sam }, headers);
  assert.equal(enrol.status, 200);
  assert.deepEqual(await status(), { active: false, pending: true, available: true });
  const key = fromBase32(new URL(String(enrol.data.otpauthUri)).searchParams.get('secret')!);
  assert.equal((await call('/admin/v1/session/totp/activate', { code: '000000' === hotp(key, Math.floor(Date.now() / 30_000)) ? '111111' : '000000' }, headers)).status, 422);
  const activated = await call('/admin/v1/session/totp/activate', { code: hotp(key, Math.floor(Date.now() / 30_000)) }, headers);
  assert.equal(activated.status, 200);
  const codes = activated.data.recoveryCodes as string[];
  assert.deepEqual(await status(), { active: true, pending: false, available: true });
  assert.equal((await call('/admin/v1/session', { username: 'sam', password: passwords.sam })).status, 401);
  assert.equal((await call('/admin/v1/session', { username: 'sam', password: passwords.sam, code: codes[1] })).status, 200);
});
