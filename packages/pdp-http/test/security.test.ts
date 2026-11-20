import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { createPublicKey, scryptSync, verify } from 'node:crypto';
import { canonical } from '../../core/src/index.ts';
import { pdp } from '../src/pdp.ts';
import { Auth, dummyPasswordHash, hashMachineSecret, hashSecret, needsRehash, verifySecret, verifySecretAsync } from '../src/auth.ts';
import { Scim } from '../src/scim.ts';
import { fileBacking } from '../src/store.ts';
import { Tokens } from '../src/tokens.ts';
import { open, reviewEmergency, emergencies } from '../src/admin/break-glass.ts';
import { compliance } from '../src/admin/compliance.ts';
import { audit } from '../src/admin/audit.ts';
import { HttpError } from '../src/http.ts';
import { LeasedRateLimiter, RateLimiter } from '../src/ratelimit.ts';
import { fixture, mockScrypt, required, req, users, WHY, FIXED } from './helpers.ts';

const status = (code: number) => (e: unknown): boolean => e instanceof HttpError && e.status === code;
test('generated credentials are long, private, hashed and never regenerated', async (t) => {
  const { auth, rt, dir, passwords, pepApiKey } = fixture(t);
  for (const pass of Object.values(passwords)) assert.ok(pass.length >= 16);
  for (const file of ['INITIAL-CREDENTIALS.txt', 'credentials.json', 'signing-keys.json', 'signing-public.pem']) assert.equal(statSync(resolve(dir, file)).mode & 0o777, 0o600);
  const disk = readFileSync(resolve(dir, 'credentials.json'), 'utf8');
  for (const secret of [...Object.values(passwords), pepApiKey]) assert.ok(!disk.includes(secret));
  assert.throws(() => auth.pep(req()), status(401));
  assert.throws(() => auth.pep(req({ authorization: 'Bearer bad' })), status(401));
  assert.match(auth.pep(req({ authorization: `Bearer ${pepApiKey}` })), /^pep:[a-f0-9]{64}$/);
  const before = readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8');
  new Auth(dir, rt.audit, rt.now);
  assert.equal(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8'), before);
});
test('sign-in hashes off the event loop: same hash format, unknown users still pay the dummy hash', async (t) => {
  const hash = hashSecret('correct horse');
  assert.equal(await verifySecretAsync('correct horse', hash), true);
  assert.equal(await verifySecretAsync('wrong horse', hash), false);
  assert.equal(await verifySecretAsync('x'.repeat(257), hash), false);
  assert.equal(await verifySecretAsync('correct horse', 'malformed'), false);
  assert.equal(verifySecret('correct horse', hash), true, 'hashes stay interchangeable with the synchronous check');
  const { auth, passwords } = fixture(t);
  for (const [user, password] of [['amira', passwords.amira], ['nobody', 'guess']] as const) {
    let ticked = false;
    setImmediate(() => { ticked = true; });
    await auth.login(user, password, `ip-${user}`).catch((e: unknown) => assert.ok(status(401)(e)));
    assert.ok(ticked, `the event loop ran while ${user} was being checked`);
  }
});
/** The 0.8.3 form: `<salt>:<key>`, scrypt at the Node defaults (N=2^14, r=8, p=1). */
const legacyHash = (secret: string, salt = 'ab'.repeat(16)): string => `${salt}:${scryptSync(secret, salt, 32).toString('hex')}`;
interface StoredCredentials { users: Array<{ id: string; hash: string }>; pepCredentials: Array<{ id: string; hash: string }> }
test('password hashes carry their scrypt cost; a 0.8.3 hash still verifies and is rehashed at the next sign-in', async (t) => {
  const current = hashSecret('correct horse');
  assert.match(current, /^scrypt-wrap\$16\$8\$2\$[0-9a-f]{32}\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
  assert.equal(needsRehash(current), false);
  assert.equal(needsRehash(legacyHash('correct horse')), true);
  assert.equal(await verifySecretAsync('correct horse', legacyHash('correct horse')), true);
  assert.equal(verifySecret('wrong horse', legacyHash('correct horse')), false);
  for (const cost of ['$30$8$2$', '$18$16$2$', '$16$8$9$']) {
    assert.equal(verifySecret('correct horse', current.replace('$16$8$2$', cost)), false, `a cost out of bounds is refused, never computed: ${cost}`);
  }
  assert.match(dummyPasswordHash(), /^scrypt-wrap\$16\$8\$2\$/, 'unknown accounts pay the current cost');
  // more sign-ins than scrypt slots: the waiting ones get their slot in turn, each with its own answer
  const answers = await Promise.all(['correct horse', 'wrong', 'correct horse', 'wrong', 'correct horse'].map((p) => verifySecretAsync(p, current)));
  assert.deepEqual(answers, [true, false, true, false, true]);
  const { auth, dir, passwords } = fixture(t);
  const file = resolve(dir, 'credentials.json');
  const omar = (): string => required((JSON.parse(readFileSync(file, 'utf8')) as StoredCredentials).users.find((u) => u.id === 'omar')).hash;
  assert.equal(needsRehash(omar()), false, 'seeded accounts are hashed at the current cost');
  const stored = JSON.parse(readFileSync(file, 'utf8')) as StoredCredentials;
  const password = required(passwords.omar);
  required(stored.users.find((u) => u.id === 'omar')).hash = legacyHash(password);
  writeFileSync(file, JSON.stringify(stored));
  auth.reload();
  await assert.rejects(auth.login('omar', 'not-the-password', 'ip-1'), status(401));
  assert.equal(needsRehash(omar()), true, 'a failed sign-in changes nothing');
  await auth.login('omar', password, 'ip-1');
  assert.equal(needsRehash(omar()), false);
  assert.equal(await verifySecretAsync(password, omar()), true);
  await auth.login('omar', password, 'ip-2');
});
test('unknown, dormant 0.8.3 and current accounts run the same scrypt calls: legacy hashes are wrapped at start', async (t) => {
  const { dir, rt, passwords } = fixture(t);
  const file = resolve(dir, 'credentials.json');
  const omar = (): string => required((JSON.parse(readFileSync(file, 'utf8')) as StoredCredentials).users.find((u) => u.id === 'omar')).hash;
  const stored = JSON.parse(readFileSync(file, 'utf8')) as StoredCredentials;
  required(stored.users.find((u) => u.id === 'omar')).hash = legacyHash(required(passwords.omar));
  writeFileSync(file, JSON.stringify(stored));
  const auth = new Auth(dir, rt.audit, rt.now);
  // no password was needed: the 0.8.3 key, under its own salt, is the input of the current layer
  const [form, ln, r, p, inner, salt, key] = omar().split('$');
  assert.deepEqual([form, ln, r, p, inner, salt?.length, key?.length], ['scrypt-wrap', '16', '8', '2', 'ab'.repeat(16), 32, 64]);
  assert.equal(needsRehash(omar()), false);
  assert.equal(await verifySecretAsync(required(passwords.omar), omar()), true);
  assert.equal(await verifySecretAsync('wrong horse', omar()), false);
  const calls = mockScrypt(t);
  const work = async (user: string): Promise<string[]> => {
    calls.length = 0;
    await assert.rejects(auth.login(user, 'wrong horse', `ip-${user}`), status(401));
    return [...calls];
  };
  const unknown = await work('nobody');
  assert.deepEqual(unknown, ['N=16384 r=8 p=1', 'N=65536 r=8 p=2']);
  assert.deepEqual(await work('omar'), unknown, 'a dormant 0.8.3 account');
  assert.deepEqual(await work('amira'), unknown, 'a current account');
});
test('PEP and SCIM secrets are HMAC-hashed (random 192-bit secrets need no stretching); 0.8.3 scrypt hashes upgrade on first use', (t) => {
  const { auth, rt, dir, pepApiKey } = fixture(t);
  const file = resolve(dir, 'credentials.json');
  const bootstrap = (): string => required((JSON.parse(readFileSync(file, 'utf8')) as StoredCredentials).pepCredentials[0]).hash;
  assert.match(bootstrap(), /^hmac-sha256\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
  const stored = JSON.parse(readFileSync(file, 'utf8')) as StoredCredentials;
  required(stored.pepCredentials[0]).hash = legacyHash(pepApiKey);
  writeFileSync(file, JSON.stringify(stored));
  auth.reload();
  assert.throws(() => auth.pep(req({ authorization: `Bearer ${pepApiKey}x` })), status(401));
  assert.equal(needsRehash(bootstrap(), true), true);
  const actor = auth.pep(req({ authorization: `Bearer ${pepApiKey}` }));
  assert.equal(needsRehash(bootstrap(), true), false);
  assert.equal(verifySecret(pepApiKey, bootstrap()), true);
  auth.reload();
  assert.equal(auth.pep(req({ authorization: `Bearer ${pepApiKey}` })), actor, 'the upgraded hash authenticates the same key');
  const token = 's'.repeat(48);
  const scimFile = resolve(dir, 'scim-credential.json');
  writeFileSync(scimFile, JSON.stringify({ hash: legacyHash(token), rotatedBy: 'amira' }));
  new Scim(rt, fileBacking(scimFile)).authenticate(req({ authorization: `Bearer ${token}` }));
  const upgraded = (JSON.parse(readFileSync(scimFile, 'utf8')) as { hash: string; rotatedBy: string });
  assert.equal(upgraded.rotatedBy, 'amira');
  assert.equal(verifySecret(token, upgraded.hash) && !needsRehash(upgraded.hash, true), true);
  assert.equal(needsRehash(hashMachineSecret(token), true), false);
  assert.throws(() => new Scim(rt, fileBacking(scimFile)).authenticate(req({ authorization: `Bearer ${token}x` })), status(401));
});
test('login, session, CSRF, idle expiry and logout', async (t) => {
  const { auth, passwords, rt, setClock } = fixture(t);
  const login = await auth.login('amira', passwords.amira, '127.0.0.1');
  const headers = { cookie: `sid=${login.sid}`, 'x-csrf-token': login.csrfToken };
  assert.equal(auth.session(req(headers), false).user.id, 'amira');
  assert.throws(() => auth.session(req({ cookie: headers.cookie }), true), status(403));
  auth.session(req(headers), true);
  setClock('2026-11-08T10:15:00Z'); assert.throws(() => auth.session(req(headers), false), status(401));
  setClock(FIXED);
  const second = await auth.login('amira', passwords.amira, 'other-ip');
  auth.logout(req({ cookie: `sid=${second.sid}` }), 'amira');
  assert.throws(() => auth.session(req({ cookie: `sid=${second.sid}` }), false), status(401));
  const log = JSON.stringify(rt.audit.records());
  assert.ok(!log.includes(required(passwords.amira))); assert.ok(!log.includes(login.sid)); assert.ok(!log.includes(login.csrfToken));
});
test('absolute session lifetime remains eight hours despite activity', async (t) => {
  const { auth, passwords, setClock } = fixture(t);
  const login = await auth.login('omar', passwords.omar, 'ip');
  const request = req({ cookie: `sid=${login.sid}` });
  for (let minute = 10; minute < 480; minute += 10) {
    setClock(new Date(Date.parse(FIXED) + minute * 60_000).toISOString()); auth.session(request, false);
  }
  setClock('2026-11-08T18:00:00Z'); assert.throws(() => auth.session(request, false), status(401));
});
test('five failed logins lock the username/IP progressively; failures are audited and persisted', async (t) => {
  const { auth, passwords, rt, setClock, dir } = fixture(t);
  for (let i = 0; i < 5; i++) await assert.rejects(async () => auth.login('amira', 'wrong-password', 'ip'), status(401));
  await assert.rejects(async () => auth.login('amira', passwords.amira, 'ip'), status(429));
  setClock('2026-11-08T10:01:01Z');
  await assert.rejects(async () => auth.login('amira', 'wrong-password', 'ip'), status(401));
  setClock('2026-11-08T10:02:02Z');
  const restarted = new Auth(dir, rt.audit, rt.now, () => Date.parse(rt.now()));
  await assert.rejects(async () => restarted.login('amira', passwords.amira, 'ip'), status(429));
  setClock('2026-11-08T10:03:02Z');
  assert.equal((await restarted.login('amira', passwords.amira, 'ip')).user.id, 'amira');
  const denies = rt.audit.records().filter((r) => r.action === 'login' && r.effect === 'deny');
  assert.equal(denies.length, 6);
  assert.deepEqual(denies.map((r) => r.details?.lockedSeconds ?? 0), [0, 0, 0, 0, 60, 120], 'the failure that locks says for how long');
});
test('break-glass respects four hours, mandatory refusal, review separation, expiry and revocation', (t) => {
  const { rt, setClock } = fixture(t);
  const b = { subjectId: 'bob', resourceId: 'CASE-15', reason: WHY, hours: 4 };
  for (const hours of [0, -1, 4.01, '4', Infinity]) assert.throws(() => open(rt, users.amira, { ...b, hours }), status(422));
  assert.throws(() => open(rt, users.amira, { ...b, resourceId: 'CASE-7' }), (e) => e instanceof HttpError && e.status === 422 && !!e.details?.includes('BLP.NO_READ_UP'));
  const emergency = open(rt, users.amira, b);
  assert.equal(Date.parse(emergency.expiresAt) - Date.parse(emergency.openedAt), 4 * 3_600_000);
  assert.ok(rt.store.state.tuples.some((t) => t.id === emergency.tupleId && t.breakGlass));
  assert.ok(emergencies(rt).toReview.some((x) => x.id === emergency.id));
  assert.throws(() => reviewEmergency(rt, { ...users.amira, roles: ['security_officer'] }, emergency.id, 'review', { outcome: 'justified', note: WHY }), status(403));
  reviewEmergency(rt, users.lina, emergency.id, 'review', { outcome: 'justified', note: WHY });
  assert.ok(emergencies(rt).reviewed.some((e) => e.id === emergency.id));
  assert.ok(emergencies(rt).active.some((e) => e.id === emergency.id));
  reviewEmergency(rt, users.lina, emergency.id, 'revoke', { reason: WHY });
  assert.ok(!rt.store.state.tuples.some((t) => t.id === emergency.tupleId));
  const expires = open(rt, users.amira, b);
  setClock('2026-11-08T14:00:01Z');
  assert.ok(!emergencies(rt).active.some((e) => e.id === expires.id));
});
test('break-glass refuses an ambiguous subject or resource id', (t) => {
  const { rt } = fixture(t);
  const original = rt.store.state;
  const count = rt.store.emergencies.length;
  const body = { subjectId: 'bob', resourceId: 'CASE-15', reason: WHY, hours: 1 };
  const subject = required(original.subjects.find((item) => item.id === body.subjectId));
  rt.store.state = { ...original, subjects: [...original.subjects, { ...subject, type: 'duplicate-user' }] };
  assert.throws(() => open(rt, users.amira, body), status(422));
  const resource = required(original.resources.find((item) => item.id === body.resourceId));
  rt.store.state = { ...original, resources: [...original.resources, { ...resource, type: 'payment' }] };
  assert.throws(() => open(rt, users.amira, body), status(422));
  assert.equal(rt.store.emergencies.length, count);
});

test('break-glass hour refusal states the bundle cap', (t) => {
  const { rt } = fixture(t);
  const bundle = rt.store.state.bundle;
  rt.store.state = { ...rt.store.state, bundle: { ...bundle, needToKnow: { ...bundle.needToKnow, breakGlassMaxHours: 2 } } };
  assert.throws(() => open(rt, users.amira, { subjectId: 'bob', resourceId: 'CASE-15', reason: WHY, hours: 3 }),
    (error: unknown) => error instanceof HttpError && error.status === 422 && error.message === 'hours must be in (0, 2]');
});

test('audit hash formula, verifier, filters, pagination and on-disk tamper detection', (t) => {
  const { rt } = fixture(t);
  rt.audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'bob', resource: 'CASE-14', effect: 'deny', rules: ['NTK.NO_REASON'] });
  rt.audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'alice', effect: 'allow' });
  assert.deepEqual(rt.audit.verify(), { verified: true, length: 2 });
  const rows = rt.audit.records(); assert.equal(required(rows[0]).prevHash, '0'.repeat(64)); assert.equal(required(rows[1]).prevHash, required(rows[0]).hash);
  const first = audit(rt, users.sam, new URL('http://local/admin/v1/audit?limit=1')) as { items: unknown[]; next: string };
  assert.equal(first.items.length, 1); assert.equal(first.next, '1');
  const filtered = audit(rt, users.sam, new URL('http://local/admin/v1/audit?effect=deny&subject=bob&rule=NTK.NO_REASON&type=decision&resource=CASE-14')) as { items: unknown[] };
  assert.equal(filtered.items.length, 1);
  required(rows[0]).actor = 'tampered'; writeFileSync(rt.audit.file, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
  assert.deepEqual(rt.audit.verify(), { verified: false, length: 2, brokenAt: 1 });
  assert.throws(() => rt.audit.append({ type: 'session', actor: 'x', action: 'login' }));
});
test('compliance has required control mappings, actual audit counts and valid detached signature', (t) => {
  const { rt, dir } = fixture(t);
  rt.audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'deny', rules: ['NTK.NO_REASON'] });
  const result = compliance(rt, users.sam, true) as { pack: { frameworks: { controls: { id: string; evidence: { decisions: number; denies: number } }[] }[] }; signature: string };
  assert.equal(required(result.pack.frameworks[0]).controls.length, 9);
  assert.equal(required(result.pack.frameworks[1]).controls.length, 4);
  assert.equal(required(result.pack.frameworks[2]).controls.length, 0);
  assert.deepEqual(required(required(result.pack.frameworks[0]).controls[0]).evidence, { decisions: 1, denies: 1, lastSeen: FIXED });
  const [header, empty, signature] = result.signature.split('.'); assert.equal(empty, ''); assert.ok(header); assert.ok(signature);
  const publicKey = createPublicKey(readFileSync(resolve(dir, 'signing-public.pem')));
  assert.equal(verify(null, Buffer.from(`${header}.${Buffer.from(canonical(result.pack)).toString('base64url')}`), publicKey, Buffer.from(signature, 'base64url')), true);
});
test('single-use jti is persisted across token service restarts', async (t) => {
  const { rt, dir } = fixture(t);
  const token = rt.tokens.issue({ sub: 'user:bob', act: 'read', res: 'case:CASE-14', ver: 8, pv: 'pv.test' }, 15, { now: FIXED, network: 'trusted' });
  const restarted = new Tokens(dir, rt.now);
  restarted.consume(token, () => true);
  const again = new Tokens(dir, rt.now);
  assert.throws(() => again.consume(token, () => true), status(409));
});
test('token buckets independently limit keys and refill over time', async () => {
  const limit = new RateLimiter(); limit.take('a', 0, 1); limit.take('b', 0, 1);
  assert.throws(() => limit.take('a', 0, 1), status(429));
  limit.take('a', 60_000, 1);
});

test('cluster buckets lease in batches, serialize one key and never overspend the shared tokens', async () => {
  let shared = 100, calls = 0; const keys: string[] = [];
  const limit = new LeasedRateLimiter(async (key, _capacity, _perMinute, amount) => {
    calls++; keys.push(key);
    const granted = Math.min(shared, amount); shared -= granted;
    return { granted, available: shared };
  });
  await Promise.all(Array.from({ length: 25 }, () => limit.take('a-client', 0, 100)));
  assert.equal(calls, 3, '25 concurrent requests needed three leases, not 25 database calls');
  for (let i = 0; i < 75; i++) await limit.take('a-client', 0, 100);
  assert.equal(shared, 0); assert.equal(calls, 10);
  await assert.rejects(limit.take('a-client', 0, 100), status(429));
  const afterRefusal = calls;
  await assert.rejects(limit.take('a-client', 0, 100), status(429));
  assert.equal(calls, afterRefusal, 'Retry-After suppresses a database call per refused request');
  assert.ok(keys.every((key) => /^[0-9a-f]{64}$/.test(key) && key !== 'a-client'), 'only the key hash reaches PostgreSQL');
});

test('every concurrent request waiting on a failed lease fails closed with the same sanitized 503', async () => {
  const limit = new LeasedRateLimiter(async () => { throw new Error('database detail'); });
  const settled = await Promise.allSettled([limit.take('a-client', 0, 100), limit.take('a-client', 0, 100)]);
  for (const result of settled) {
    assert.equal(result.status, 'rejected');
    assert.ok(result.reason instanceof HttpError && result.reason.status === 503 && result.reason.message === 'Rate limit store unavailable');
  }
});

test('audit verifier reports malformed JSON, non-record data and partial trailing writes', async (t) => {
  const { rt } = fixture(t);
  for (const text of ['{broken}\n', 'null\n', '[]\n', '{}\n']) {
    writeFileSync(rt.audit.file, text);
    assert.deepEqual(rt.audit.verify(), { verified: false, length: 1, brokenAt: 1 });
  }
});


test('break-glass admission uses the requested network and access requests still enforce it', async (t) => {
  const { rt } = fixture(t);
  // alice/CASE-7 is compartmented (trusted network only); the seed already holds an emergency on dan/CASE-12
  const body = { subjectId: 'alice', resourceId: 'CASE-7', reason: WHY, hours: 1, network: 'trusted' };
  const admitted = open(rt, users.amira, body);
  assert.equal(admitted.status, 'active');
  const request = { subject: { type: 'user', id: 'alice' }, resource: { type: 'case', id: 'CASE-7' }, action: { name: 'read' } };
  const trusted = pdp(rt, '/access/v1/evaluation', { ...request, context: { network: 'trusted' } }) as { decision: boolean };
  assert.equal(trusted.decision, true);
  const untrusted = pdp(rt, '/access/v1/evaluation', { ...request, context: { network: 'untrusted' } }) as { decision: boolean; context: { rules: string[] } };
  assert.equal(untrusted.decision, false);
  assert.ok(untrusted.context.rules.some((rule) => rule.startsWith('NET.')));
  const count = rt.store.emergencies.length;
  assert.throws(() => open(rt, users.amira, { ...body, subjectId: 'bob', resourceId: 'CASE-7' }), (e) => {
    assert.ok(e instanceof HttpError);
    assert.equal(e.status, 422);
    const rules = required(e.details);
    assert.ok(rules.includes('BLP.NO_READ_UP'));
    assert.ok(rules.includes('MAC.COMPARTMENT'));
    assert.ok(rules.every((rule) => typeof rule === 'string' && !rule.startsWith('NET.')));
    return true;
  });
  assert.equal(rt.store.emergencies.length, count);
});

test('break-glass still refuses inactive and ineligible subjects', async (t) => {
  const { rt } = fixture(t);
  const original = rt.store.state;
  const count = rt.store.emergencies.length;
  for (const patch of [{ active: false }, { roles: [] }]) {
    rt.store.state = { ...original, bundle: { ...original.bundle, abac: original.bundle.abac.filter((rule) => rule.effect !== 'permit') },
      subjects: original.subjects.map((s) => s.id === 'dan' ? { ...s, ...patch } : s) };
    assert.throws(() => open(rt, users.amira, { subjectId: 'dan', resourceId: 'CASE-12', reason: WHY, hours: 1, network: 'trusted' }), status(422));
    assert.equal(rt.store.emergencies.length, count);
  }
});


test('break-glass admission refuses other policy denials', async (t) => {
  const { rt } = fixture(t);
  const bundle = rt.store.state.bundle;
  rt.store.state = { ...rt.store.state, bundle: { ...bundle, abac: [...bundle.abac, {
    id: 'test-deny-read', description: 'Read access remains subject to ABAC', effect: 'forbid', actions: ['read'], when: { op: 'true' },
  }] } };
  assert.throws(() => open(rt, users.amira, { subjectId: 'dan', resourceId: 'CASE-12', reason: WHY, hours: 1, network: 'trusted' }), status(422));
  const result = pdp(rt, '/access/v1/evaluation', {
    subject: { type: 'user', id: 'dan' }, resource: { type: 'case', id: 'CASE-12' }, action: { name: 'read' }, context: { network: 'trusted' },
  }) as { decision: boolean; context: { rules: string[] } };
  assert.equal(result.decision, false);
  assert.ok(result.context.rules.includes('ABAC.test-deny-read'));
});

test('CWE-307: failures sprayed from other addresses never lock the owner out; the failing clients are held back', async (t) => {
  const { auth, passwords, rt } = fixture(t);
  for (let i = 0; i < 12; i++) await assert.rejects(async () => auth.login('amira', 'wrong', `198.51.100.${i}`), status(401));
  await assert.rejects(async () => auth.login('amira', passwords.amira, '198.51.100.3'), status(429), 'a client that failed waits for the account delay');
  assert.equal((await auth.login('amira', passwords.amira, '203.0.113.5')).user.id, 'amira', 'a client that has not failed signs in');
  await assert.rejects(async () => auth.login('amira', passwords.amira, '198.51.100.3'), status(429), 'a success elsewhere does not reopen the account to failing clients');
  // one address hammering one account still locks that pair, whatever the account counter says
  for (let i = 0; i < 5; i++) await assert.rejects(async () => auth.login('omar', 'wrong', 'ip-pair'), status(401));
  await assert.rejects(async () => auth.login('omar', passwords.omar, 'ip-pair'), status(429));
  assert.ok(rt.audit.records().some((r) => r.action === 'login' && r.effect === 'deny' && Number(r.details?.lockedSeconds) > 0), 'the lockout is audited');
});

test('CWE-1284: a lock ends on real elapsed time even with a pinned business clock (CLOCK=fixed)', async (t) => {
  const { passwords, rt, dir } = fixture(t);
  let ms = 0;
  const auth = new Auth(dir, rt.audit, rt.now, () => ms); // rt.now never moves
  for (let i = 0; i < 5; i++) await assert.rejects(async () => auth.login('sam', 'wrong', 'ip'), status(401));
  await assert.rejects(async () => auth.login('sam', passwords.sam, 'ip'), (e) => status(429)(e) && (e as HttpError).details?.[0] === 60);
  ms += 61_000;
  assert.equal((await auth.login('sam', passwords.sam, 'ip')).user.id, 'sam');
});
