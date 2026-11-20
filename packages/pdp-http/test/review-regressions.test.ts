import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync, appendFileSync, unlinkSync, rmSync } from 'node:fs';
import { generateKeyPairSync, createPublicKey } from 'node:crypto';
import { resolve } from 'node:path';
import { PassThrough } from 'node:stream';
import type { IncomingMessage } from 'node:http';
import { fixture, users, WHY, evaluation, req, required } from './helpers.ts';
import { HttpError, body } from '../src/http.ts';
import { candidate, propose, decideChange, impact } from '../src/admin/changes.ts';
import { model } from '../src/admin/model.ts';
import { simulator } from '../src/admin/simulator.ts';
import { open, reviewEmergency, expireEmergencies } from '../src/admin/break-glass.ts';
import { reviews, review } from '../src/admin/reviews.ts';
import { pdp } from '../src/pdp.ts';
import { Tokens } from '../src/tokens.ts';
import { RateLimiter } from '../src/ratelimit.ts';
import { audit } from '../src/admin/audit.ts';
import { contentRules, mandatoryWeakenings } from '../../core/src/index.ts';
import type { PolicyBundle } from '../../core/src/index.ts';

const status = (n: number) => (e: unknown) => e instanceof HttpError && e.status === n;
const grant = (id = 'bob') => ({ kind: 'add_tuple', reason: WHY, payload: {
  object: { type: 'case', id: 'CASE-15' }, relation: 'allocated', subject: { type: 'user', id }, validTo: '2026-12-08T10:00:00Z',
} });

test('C1: mandatory weakenings are stored and require an independent security officer', (t) => {
  const { rt } = fixture(t);
  const before = rt.store.state.bundle;
  const bundle = { ...before, needToKnow: { ...before.needToKnow, mode: 'off' as const } };
  const c = propose(rt, users.amira, { kind: 'publish_policy', payload: { bundle }, reason: WHY });
  assert.deepEqual(c.weakensMandatory, mandatoryWeakenings(before, bundle));
  assert.ok(c.weakensMandatory!.length);
  assert.throws(() => decideChange(rt, users.omar, c.id, true, { reason: WHY }), status(403));
  assert.throws(() => decideChange(rt, { ...users.amira, roles: ['security_officer'] }, c.id, true, { reason: WHY }), status(403));
  assert.equal(decideChange(rt, users.lina, c.id, true, { reason: WHY }).status, 'applied');
});

test('C1: publishing cannot orphan compartments, roles, resource types or tuple relations', (t) => {
  const { rt } = fixture(t);
  const original = rt.store.state.bundle;
  const variants: PolicyBundle[] = [];
  const compartments = structuredClone(original); Object.assign(compartments.schema, { compartments: [] });
  variants.push(compartments);
  const roles = structuredClone(original); delete (roles.rbac.roles as Record<string, unknown>).investigator;
  variants.push(roles);
  const types = structuredClone(original); delete (types.schema.resourceTypes as Record<string, unknown>).payment;
  variants.push(types);
  const relations = structuredClone(original); delete (relations.schema.resourceTypes.case!.relations as Record<string, unknown>).allocated;
  variants.push(relations);
  for (const bundle of variants) assert.throws(() => candidate(rt, users.amira, 'publish_policy', { bundle }), status(422));
});

test('C2: explain hides unreadable resources for every requested action and subject eligibility', (t) => {
  const { rt } = fixture(t);
  for (const id of ['bob', 'frank', 'grace']) for (const action of ['read', 'export', 'update', 'delete', 'unknown']) {
    const resource = id === 'grace' ? 'CASE-18' : 'CASE-7';
    assert.throws(() => pdp(rt, '/x/v1/explain', evaluation(id, resource, action, 'trusted')), status(404));
    assert.throws(() => pdp(rt, '/x/v1/explain', evaluation(id, 'missing', action, 'trusted')), status(404));
  }
});

test('H1: previews refuse future grants, include untrusted and second-person gains, and match resource versions', (t) => {
  const { rt } = fixture(t);
  rt.sodHistory = 'caller';
  const g = grant();
  assert.throws(() => candidate(rt, users.amira, g.kind, { ...g.payload, validFrom: '2026-11-08T10:00:01Z' }), status(422));
  const before = rt.store.state;
  const after = { ...before, bundle: { ...before.bundle, abac: before.bundle.abac.filter((r) => r.id !== 'no-export-untrusted') } };
  assert.ok(impact(rt, after).gained.some((r) => r.action === 'export'));
  rt.store.state = { ...before, subjects: before.subjects.map((s) => s.id === 'bob' ? { ...s, clearance: 1 } : s) };
  const role = candidate(rt, users.amira, 'update_subject', { id: 'bob', set: { roles: ['finance_approver'] } });
  assert.ok(impact(rt, role.state).gained.some((r) => r.subject === 'bob' && r.resource === 'PAY-3' && r.action === 'approve'));
  const old = required(before.resources.find((r) => r.id === 'CASE-14'));
  const c = candidate(rt, users.amira, 'update_resource', { id: old.id, set: { level: 1 } });
  assert.equal(c.state.resources.find((r) => r.id === old.id)?.version, (old.version ?? 0) + 1);
});

test('H1: approval rechecks temporal impact even when the state digest is unchanged', (t) => {
  const { rt, setClock } = fixture(t);
  const c = propose(rt, users.amira, grant());
  setClock('2026-12-09T10:00:00Z');
  assert.throws(() => decideChange(rt, users.omar, c.id, true, { reason: WHY }), (e) => e instanceof HttpError && e.status === 409 && e.code === 'stale');
});

test('H2: own changes, beneficiary approvals and all alternate break-glass tuple paths are refused', (t) => {
  const { rt } = fixture(t);
  const bob = { id: 'bob', name: 'Bob', roles: ['access_admin', 'approver', 'security_officer'] };
  assert.throws(() => open(rt, bob, { subjectId: 'bob', resourceId: 'CASE-15', hours: 1, reason: WHY }), status(403));
  assert.throws(() => candidate(rt, bob, 'update_subject', { id: 'bob', set: { clearance: 3 } }), status(403));
  for (const c of [propose(rt, users.amira, grant()), propose(rt, users.amira, { kind: 'update_subject', payload: { id: 'bob', set: { clearance: 3 } }, reason: WHY })]) {
    assert.throws(() => decideChange(rt, bob, c.id, true, { reason: WHY }), status(403));
    for (const approve of [true, false]) assert.throws(() => decideChange(rt, { ...users.amira, roles: ['approver'] }, c.id, approve, { reason: WHY }), status(403));
  }
  assert.throws(() => candidate(rt, users.amira, 'add_tuple', { ...grant().payload, breakGlass: true }), status(403));
  const e = open(rt, users.amira, { subjectId: 'bob', resourceId: 'CASE-15', hours: 1, reason: WHY });
  assert.throws(() => candidate(rt, users.amira, 'remove_tuple', { tupleId: e.tupleId }), status(403));
  for (const action of ['review', 'revoke']) {
    assert.throws(() => reviewEmergency(rt, { ...users.amira, roles: ['security_officer'] }, e.id, action, { reason: WHY, note: WHY, outcome: 'justified' }), status(403));
    assert.throws(() => reviewEmergency(rt, bob, e.id, action, { reason: WHY, note: WHY, outcome: 'justified' }), status(403));
  }
});

test('H2: reviews exclude expired and emergency grants, forbid self-certification and replace renewals', (t) => {
  const { rt } = fixture(t);
  const original = rt.store.state.tuples;
  const old = required(original.find((x) => x.id === 'seed-4'));
  rt.store.state = { ...rt.store.state, tuples: [
    { ...old, id: 'expired', validTo: '2026-01-01T00:00:00Z' },
    { ...old, id: 'emergency', breakGlass: true, validTo: '2026-11-09T00:00:00Z' },
    { ...old, id: 'long-allocation', relation: 'allocated', validFrom: '2026-01-01T00:00:00Z', validTo: '2027-01-01T00:00:00Z' },
    { ...old, validTo: '2026-12-01T00:00:00Z' },
  ] };
  const rows = reviews(rt, users.lina).items as { tupleId: string }[];
  assert.deepEqual(rows.map((r) => r.tupleId), ['seed-4']);
  for (const id of ['expired', 'emergency']) assert.throws(() => review(rt, users.lina, id, { decision: 'certify', newValidTo: '2027-01-01', reason: WHY }), status(404));
  for (const id of [old.subject.id, old.grantedBy!]) assert.throws(() => review(rt, { id, name: id, roles: ['security_officer'] }, old.id, { decision: 'certify', newValidTo: '2027-01-01', reason: WHY }), status(403));
  const c = review(rt, users.lina, old.id, { decision: 'certify', newValidTo: '2027-01-01', reason: WHY });
  decideChange(rt, users.omar, c.id, true, { reason: WHY });
  assert.equal(rt.store.state.tuples.length, 4);
  assert.ok(!rt.store.state.tuples.some((x) => x.id === old.id));
});

test('H3: resource-owner simulators share subject scope and use resource type as well as id', (t) => {
  const { rt } = fixture(t);
  const resources = model(rt, users.ruth, '/resources') as { items: { id: string; type: string }[] };
  const subjects = model(rt, users.ruth, '/subjects') as { items: { id: string; type: string }[] };
  const who = simulator(rt, users.ruth, '/simulate/who-can', { resourceId: 'CASE-14', action: 'read' }) as { items: { subject: { id: string } }[] };
  assert.deepEqual(who.items.map((s) => s.subject.id), subjects.items.map((s) => s.id));
  const outside = required(rt.store.state.subjects.find((s) => !subjects.items.some((x) => x.id === s.id && x.type === s.type)));
  for (const path of ['/explain', '/simulate/what-can']) assert.throws(() => simulator(rt, users.ruth, path, { subjectId: outside.id, resourceId: 'CASE-14', action: 'read' }), status(404));
  assert.throws(() => simulator(rt, users.ruth, '/simulate/impact', grant()), status(403));
  const owned = required(rt.store.state.resources.find((r) => resources.items.some((x) => x.id === r.id)));
  rt.store.state = { ...rt.store.state, resources: [...rt.store.state.resources, { ...owned, type: 'payment', owner: 'alice' }], tuples: [...rt.store.state.tuples, { id: 'collision', object: { type: 'payment', id: owned.id }, relation: 'granted', subject: { type: 'user', id: 'alice' } }] };
  assert.ok(!(model(rt, users.ruth, '/resources') as typeof resources).items.some((r) => r.id === owned.id && r.type === 'payment'));
  assert.throws(() => candidate(rt, users.ruth, 'remove_tuple', { tupleId: 'collision' }), status(404));
});

test('H4: simulations, impact previews and emergency admission never create decisions', async (t) => {
  const { rt } = fixture(t);
  simulator(rt, users.amira, '/simulate/what-can', { subjectId: 'bob', action: 'read' });
  simulator(rt, users.amira, '/simulate/who-can', { resourceId: 'CASE-14', action: 'read' });
  simulator(rt, users.amira, '/explain', { subjectId: 'bob', resourceId: 'CASE-14', action: 'read' });
  simulator(rt, users.amira, '/simulate/impact', grant());
  assert.throws(() => open(rt, users.amira, { subjectId: 'bob', resourceId: 'CASE-7', hours: 1, reason: WHY }), status(422));
  open(rt, users.amira, { subjectId: 'bob', resourceId: 'CASE-15', hours: 1, reason: WHY });
  assert.equal(rt.decisions, 0);
  assert.equal(rt.audit.records().filter((r) => r.type === 'decision').length, 0);
});

test('H4: unknown login inputs never enter audit or lockout storage and rate limits do not append', async (t) => {
  const { auth, rt, dir } = fixture(t);
  const secret = 'mistyped-secret-'.repeat(70000);
  for (let i = 0; i < 5; i++) await assert.rejects(async () => auth.login(secret, 'x', 'ip'), status(401));
  const count = rt.audit.records().length;
  await assert.rejects(async () => auth.login(secret, 'x', 'ip'), status(429));
  assert.equal(rt.audit.records().length, count);
  for (const file of ['audit.jsonl', 'lockouts.json']) {
    const text = readFileSync(resolve(dir, file), 'utf8');
    assert.ok(text.length < 10000); assert.ok(!text.includes('mistyped-secret'));
  }
});

test('H4: undefined audit fields remain verifiable; blanks, truncation and deletion fail verification', (t) => {
  const { rt } = fixture(t);
  rt.audit.append({ type: 'session', actor: 'x', action: 'test', resource: undefined, details: { value: undefined } });
  assert.equal(rt.audit.verify().verified, true);
  const one = readFileSync(rt.audit.file, 'utf8');
  rt.audit.append({ type: 'session', actor: 'x', action: 'second' });
  const two = readFileSync(rt.audit.file, 'utf8');
  appendFileSync(rt.audit.file, '\n'); assert.equal(rt.audit.verify().verified, false);
  writeFileSync(rt.audit.file, one); assert.equal(rt.audit.verify().verified, false);
  writeFileSync(rt.audit.file, two); assert.equal(rt.audit.verify().verified, true);
  unlinkSync(rt.audit.file); assert.equal(rt.audit.verify().verified, false);
  assert.throws(() => rt.audit.append({ type: 'session', actor: 'x', action: 'test' }));
});

test('H5: unversioned decision tokens consume; mismatched claims never record decisions; refs are collision-free', (t) => {
  const { rt } = fixture(t);
  rt.store.state = { ...rt.store.state, resources: rt.store.state.resources.map((r) => r.id === 'PAY-3' ? { ...r, version: undefined } : r) };
  const result = pdp(rt, '/access/v1/evaluation', evaluation('henry', 'PAY-3', 'release', 'trusted')) as { context: { decision_token: string } };
  const claims = JSON.parse(Buffer.from(result.context.decision_token.split('.')[1]!, 'base64url').toString());
  assert.deepEqual(JSON.parse(claims.sub), ['user', 'henry']);
  assert.deepEqual(JSON.parse(claims.res), ['payment', 'PAY-3']);
  const count = rt.decisions;
  const consume = { token: result.context.decision_token, resource: { type: 'payment', id: 'PAY-3' }, action: 'release' };
  for (const bad of [{ action: 'approve' }, { resourceVersion: 1 }, { resource: { type: 'payment:PAY-3', id: '' } }]) {
    assert.throws(() => pdp(rt, '/x/v1/tokens/consume', { ...consume, ...bad }));
    assert.equal(rt.decisions, count);
  }
  assert.equal((pdp(rt, '/x/v1/tokens/consume', consume) as { ok: boolean }).ok, true);
  assert.notEqual(JSON.stringify(['a:b', 'c']), JSON.stringify(['a', 'b:c']));
});

test('H6: emergency admission enforces network, policy cap and all denies; review and revoke persist correct states', async (t) => {
  const { rt } = fixture(t);
  const b = { subjectId: 'alice', resourceId: 'CASE-7', hours: 1, reason: WHY };
  assert.throws(() => open(rt, users.amira, { ...b, network: 'untrusted' }), (e) => status(422)(e) && (e as HttpError).details!.some((x) => String(x).startsWith('NET.')));
  const bundle = rt.store.state.bundle;
  rt.store.state = { ...rt.store.state, bundle: { ...bundle, needToKnow: { ...bundle.needToKnow, breakGlassMaxHours: 0.5 } } };
  assert.throws(() => open(rt, users.amira, { ...b, network: 'trusted' }), status(422));
  rt.store.state = { ...rt.store.state, bundle };
  const e = open(rt, users.amira, { ...b, network: 'trusted' });
  assert.equal(reviewEmergency(rt, users.lina, e.id, 'review', { outcome: 'justified', note: WHY }).status, 'reviewed');
  assert.throws(() => reviewEmergency(rt, users.lina, e.id, 'revoke', { reason: 'short' }), status(422));
  assert.equal(reviewEmergency(rt, users.lina, e.id, 'revoke', { reason: WHY }).status, 'revoked');
  assert.throws(() => reviewEmergency(rt, users.lina, e.id, 'revoke', { reason: WHY }), status(409));
});

test('M1: verified PEP digests are cached, invalid and oversized keys fail closed; buckets charge batch costs', async (t) => {
  const { auth, pepApiKey } = fixture(t);
  const first = auth.pep(req({ authorization: `Bearer ${pepApiKey}` }));
  assert.equal(auth.pep(req({ authorization: `Bearer ${pepApiKey}` })), first);
  assert.throws(() => auth.pep(req({ authorization: 'Bearer wrong' })), status(401));
  assert.throws(() => auth.pep(req({ authorization: `Bearer ${'x'.repeat(257)}` })), status(401));
  const limiter = new RateLimiter();
  limiter.take('pep:a', 0, 120, 120, 119);
  assert.throws(() => limiter.take('pep:a', 0, 120, 120, 2), status(429));
  limiter.take('pep:b', 0, 120, 120, 120);
});

test('M2: normalized accounts count failures across IPs, hold back the failing clients with the remaining time, and maps are bounded', async (t) => {
  const { auth, passwords, setClock } = fixture(t);
  for (let i = 0; i < 5; i++) await assert.rejects(async () => auth.login(' AmIrA ', 'wrong', `ip-${i}`), status(401));
  setClock('2026-11-08T10:00:10Z');
  await assert.rejects(async () => auth.login('amira', passwords.amira, 'ip-2'), (e) => status(429)(e) && (e as HttpError).details?.[0] === 50);
  assert.equal((await auth.login('amira', passwords.amira, 'new-ip')).user.id, 'amira', 'CWE-307: an address that never failed is not locked out');
  const limiter = new RateLimiter();
  for (let i = 0; i < 10000; i++) limiter.take(`key-${i}`, 0, 1);
  const buckets = (limiter as unknown as { buckets: Map<string, unknown> }).buckets;
  assert.equal(buckets.size, 10000);
  // every bucket is drained: none may be dropped, or its sender would get a full one back
  // capacity 1 per minute: the first bucket is full again at 60 s, which the refusal reports without rescanning
  assert.throws(() => limiter.take('key-new', 0, 1), (e) => status(429)(e) && (e as HttpError).details?.[0] === 60);
  assert.throws(() => limiter.take('key-new2', 30_000, 1), (e) => status(429)(e) && (e as HttpError).details?.[0] === 30);
  assert.throws(() => limiter.take('key-0', 0, 1), status(429), 'a drained bucket is still there and still drained');
  // one minute later the buckets have refilled: the least recently used one makes room
  limiter.take('key-new', 60_000, 1);
  assert.equal(buckets.size, 10000);
  assert.ok(!buckets.has('key-0') && buckets.has('key-1') && buckets.has('key-new'));
});

test('M3: CSRF handles same-length wrong values and JSON-only bodies drain oversized streams before refusing', async (t) => {
  const { auth, passwords } = fixture(t);
  const login = await auth.login('amira', passwords.amira, 'ip');
  assert.throws(() => auth.session(req({ cookie: `sid=${login.sid}`, 'x-csrf-token': 'x'.repeat(login.csrfToken.length) }), true), status(403));
  assert.throws(() => auth.session(req({ cookie: `sid=${login.sid}`, 'x-csrf-token': 'é'.repeat(login.csrfToken.length) }), true), status(403));
  await assert.rejects(body(req({ 'content-type': 'text/plain' })), status(415));
  const stream = new PassThrough();
  Object.assign(stream, { headers: { 'content-type': 'application/json' } });
  const pending = body(stream as unknown as IncomingMessage);
  stream.write(Buffer.alloc(1048577));
  stream.end();
  await assert.rejects(pending, status(413));
});

test('M5: malformed page tokens and inherited resource type names fail closed', (t) => {
  const { rt } = fixture(t);
  for (const token of ['!!!', 'IA', 'MA=', 'LTE', 'MS4w']) assert.throws(() => pdp(rt, '/access/v1/search/resource', { ...evaluation(), resource: { type: 'case' }, page: { token } }), status(400));
  assert.deepEqual(pdp(rt, '/access/v1/search/action', { ...evaluation(), resource: { type: '__proto__', id: 'x' } }), { results: [] });
  assert.throws(() => candidate(rt, users.amira, 'add_tuple', { ...grant().payload, object: { type: '__proto__', id: 'x' }, relation: 'toString' }), status(422));
});

// Part 1 changed this: the keyring (signing-keys.json) is authoritative, a legacy PEM is imported only when it is absent,
// and rotation goes through Tokens.rotate (admin route) instead of replacing the PEM file.
test('L1: later valid sid cookies work; imported and rotated keys refresh the PEM; audit filters are validated', async (t) => {
  const { auth, passwords, rt, dir } = fixture(t);
  const login = await auth.login('amira', passwords.amira, 'ip');
  assert.equal(auth.session(req({ cookie: `sid=stale; sid=${login.sid}` }), false).user.id, 'amira');
  const pair = generateKeyPairSync('ed25519');
  writeFileSync(resolve(dir, 'signing-private.pem'), pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  rmSync(resolve(dir, 'signing-keys.json'));
  const imported = new Tokens(dir, rt.now);
  assert.equal(readFileSync(resolve(dir, 'signing-public.pem'), 'utf8'), createPublicKey(pair.privateKey).export({ type: 'spki', format: 'pem' }));
  const rotated = imported.rotate().current.kid;
  const jwk = required(imported.jwks().keys.find((key) => key.kid === rotated));
  assert.equal(readFileSync(resolve(dir, 'signing-public.pem'), 'utf8'), createPublicKey({ key: jwk as never, format: 'jwk' }).export({ type: 'spki', format: 'pem' }));
  for (const query of ['effect=anything', 'type=anything', 'effect=', 'type=']) assert.throws(() => audit(rt, users.sam, new URL(`http://local/admin/v1/audit?${query}`)), status(400));
});

test('H1: unchanged persisted state becomes stale when an existing grant expires and its removal impact changes', (t) => {
  const { rt, setClock } = fixture(t);
  rt.store.state = { ...rt.store.state, tuples: [...rt.store.state.tuples, {
    id: 'temporary-access', object: { type: 'case', id: 'CASE-15' }, relation: 'allocated', subject: { type: 'user', id: 'bob' },
    validFrom: rt.now(), validTo: '2026-11-08T11:00:00Z', grantedBy: 'amira',
  }] };
  const c = propose(rt, users.amira, { kind: 'remove_tuple', payload: { tupleId: 'temporary-access' }, reason: WHY });
  assert.ok(c.impact.lost.some((r) => r.subject === 'bob' && r.resource === 'CASE-15'));
  setClock('2026-11-08T11:00:01Z');
  assert.equal(rt.store.digest(), c.stateDigest);
  assert.throws(() => decideChange(rt, users.omar, c.id, true, { reason: WHY }), (e) => status(409)(e) && (e as HttpError).code === 'stale');
});

test('M2: expired lock entries are pruned and lock storage is capped', async (t) => {
  const { auth, rt } = fixture(t);
  const locks = (auth as unknown as { locks: Map<string, { failures: number; until: number; touched: number }> }).locks;
  const at = Date.parse(rt.now());
  locks.set('account:amira', { failures: 5, until: at + 60000, touched: at });
  locks.set('expired', { failures: 1, until: 0, touched: at - 3600001 });
  for (let i = 0; i < 10001; i++) locks.set(`unknown:ip-${i}`, { failures: 1, until: 0, touched: at });
  await assert.rejects(async () => auth.login('unknown', 'wrong', 'new-ip'), status(401));
  assert.equal(locks.size, 10000);
  assert.ok(!locks.has('expired'));
  assert.ok(locks.has('account:amira'));
});

test('C1: state references are checked even when the candidate bundle itself is valid', (t) => {
  const { rt } = fixture(t);
  const original = rt.store.state;
  const subject = required(original.subjects.find((s) => s.id === 'bob'));
  const bundle = { ...original.bundle, schema: { ...original.bundle.schema, compartments: [...original.bundle.schema.compartments, 'TEMP'] } };
  rt.store.state = { ...original, bundle, subjects: original.subjects.map((s) => s.id === subject.id ? { ...s, compartments: ['TEMP'] } : s) };
  assert.throws(() => candidate(rt, users.amira, 'publish_policy', { bundle: original.bundle }), (e) => status(422)(e) && (e as HttpError).message === 'Compartment is still in use');
  const role = original.bundle.rbac.roles.viewer!;
  rt.store.state = { ...original, bundle: { ...original.bundle, rbac: { ...original.bundle.rbac, roles: { ...original.bundle.rbac.roles, temp: role } } }, subjects: original.subjects.map((s) => s.id === subject.id ? { ...s, roles: ['temp'] } : s) };
  assert.throws(() => candidate(rt, users.amira, 'publish_policy', { bundle: original.bundle }), (e) => status(422)(e) && (e as HttpError).message === 'Role is still in use');
});

// ---------- Kimi review, 2026-11-09 ----------

test('K1: update_resource cannot leave a child below its parent level', (t) => {
  const { rt } = fixture(t);
  assert.throws(() => candidate(rt, users.amira, 'update_resource', { id: 'CASE-11', set: { level: 0 } }), status(422));
  assert.throws(() => candidate(rt, users.amira, 'update_resource', { id: 'FOLDER-A', set: { level: 3 } }), status(422));
  assert.doesNotThrow(() => candidate(rt, users.amira, 'update_resource', { id: 'CASE-11', set: { level: 2 } }));
});

test('K2: built-in resource fields must be mapped with their real SQL type', async (t) => {
  const { rt } = fixture(t);
  const good = { 'resource.level': { column: 'level', type: 'number' }, 'resource.compartments': { column: 'compartments', kind: 'text[]' }, 'resource.id': 'id' };
  const body = (columns: Record<string, unknown>) => ({ ...evaluation(), resource: { type: 'case' }, columns });
  assert.doesNotThrow(() => pdp(rt, '/x/v1/filter', body(good)));
  assert.throws(() => pdp(rt, '/x/v1/filter', body({ ...good, 'resource.level': 'level' })), status(400));
  assert.throws(() => pdp(rt, '/x/v1/filter', body({ ...good, 'resource.compartments': 'compartments' })), status(400));
});

test('K4: expired sessions are evicted on the next login', async (t) => {
  const { auth, passwords, setClock } = fixture(t);
  const sessions = (auth as unknown as { sessions: Map<string, unknown> }).sessions;
  await auth.login('amira', passwords.amira, 'ip-1');
  setClock('2026-11-08T18:00:01Z');
  await auth.login('omar', passwords.omar, 'ip-2');
  assert.equal(sessions.size, 1);
});

test('Demo data: no seeded break-glass is opened by its own beneficiary', (t) => {
  const { rt } = fixture(t);
  assert.ok(rt.store.emergencies.length > 0);
  for (const e of rt.store.emergencies) assert.notEqual(e.openedBy, e.subjectId);
});

// ---------- Kimi pentest, 2026-11-10 (docs/security/PENTEST-2026-11-10-kimi.md) ----------

test('KIMI-01: disabling the untrusted-export deny or the finance mask needs the security officer, not an ordinary approver', (t) => {
  const { rt } = fixture(t);
  const before = rt.store.state.bundle;
  const exportOpen = { ...before, abac: before.abac.map((r) => r.id === 'no-export-untrusted'
    ? { ...r, when: { op: 'eq' as const, left: { path: 'context.network' }, right: { value: 'never' } } } : r) };
  const maskOff = { ...before, abacContent: contentRules(before).map((r) => r.id === 'finance-mask' ? { ...r, unless: { op: 'true' as const } } : r) };
  for (const [bundle, flag] of [[exportOpen, 'ABAC rule no-export-untrusted removed or weakened'], [maskOff, 'ABAC content rule finance-mask removed or weakened']] as const) {
    const c = propose(rt, users.amira, { kind: 'publish_policy', payload: { bundle }, reason: WHY });
    assert.deepEqual(c.weakensMandatory, [flag]);
    assert.equal(c.broadens, true);
    assert.throws(() => decideChange(rt, users.omar, c.id, true, { reason: WHY }), status(403));
    assert.equal(rt.store.state.bundle, before, 'nothing published by the ordinary approver');
    decideChange(rt, users.omar, c.id, false, { reason: WHY });
  }
  const denied = pdp(rt, '/access/v1/evaluation', evaluation('bob', 'CASE-14', 'export', 'untrusted')) as { decision: boolean };
  assert.equal(denied.decision, false);
  const c = propose(rt, users.amira, { kind: 'publish_policy', payload: { bundle: exportOpen }, reason: WHY });
  assert.equal(decideChange(rt, users.lina, c.id, true, { reason: WHY }).status, 'applied');
  assert.equal((pdp(rt, '/access/v1/evaluation', evaluation('bob', 'CASE-14', 'export', 'untrusted')) as { decision: boolean }).decision, true,
    'the security officer may still approve it, knowingly');
});

// an audit append that fails (integrity failure, disk error) must refuse the privileged action and leave state unchanged
const failAudit = (rt: { audit: { append: (e: never) => void } }): void => { rt.audit.append = () => { throw new Error('Audit integrity failure'); }; };

test('audit-first: break-glass open and review/revoke are refused, state unchanged, when the audit append fails', (t) => {
  const { rt } = fixture(t);
  const b = { subjectId: 'dan', resourceId: 'CASE-14', hours: 1, reason: WHY, network: 'trusted' };
  const state = rt.store.state; const emergencies = rt.store.emergencies;
  const real = rt.audit.append.bind(rt.audit);
  failAudit(rt);
  assert.throws(() => open(rt, users.amira, b), /Audit integrity failure/);
  assert.equal(rt.store.state, state); assert.equal(rt.store.emergencies, emergencies);
  rt.audit.append = real;
  const e = open(rt, users.amira, b);
  const opened = { state: rt.store.state, emergencies: rt.store.emergencies };
  failAudit(rt);
  for (const [action, extra] of [['review', { outcome: 'justified', note: WHY }], ['revoke', { reason: WHY }]] as const) {
    assert.throws(() => reviewEmergency(rt, users.lina, e.id, action, extra), /Audit integrity failure/);
    assert.equal(rt.store.state, opened.state); assert.equal(rt.store.emergencies, opened.emergencies);
  }
});

test('audit-first: an approved change is not applied when the audit append fails', (t) => {
  const { rt } = fixture(t);
  const c = propose(rt, users.amira, grant());
  const { state, changes, history } = { state: rt.store.state, changes: rt.store.changes, history: rt.store.history };
  failAudit(rt);
  assert.throws(() => decideChange(rt, users.omar, c.id, true, { reason: WHY }), /Audit integrity failure/);
  assert.equal(rt.store.state, state); assert.equal(rt.store.changes, changes); assert.equal(rt.store.history, history);
  assert.equal(rt.store.changes.find((x) => x.id === c.id)!.status, 'pending');
});

test('audit-first: an expired emergency stays un-notified when the audit append fails', (t) => {
  const { rt } = fixture(t);
  const e = open(rt, users.amira, { subjectId: 'dan', resourceId: 'CASE-14', hours: 1, reason: WHY, network: 'trusted' });
  rt.now = () => new Date(Date.parse(e.expiresAt) + 1000).toISOString();
  failAudit(rt);
  assert.throws(() => expireEmergencies(rt), /Audit integrity failure/);
  assert.equal(rt.store.emergencies.find((x) => x.id === e.id)!.expiryNotified, undefined);
});

test('a tuple reference written as a string is refused with a message naming the field', (t) => {
  const { rt } = fixture(t);
  const refused = (field: string, payload: Record<string, unknown>): void => {
    assert.throws(() => propose(rt, users.amira, { kind: 'add_tuple', reason: WHY, payload }),
      (e: unknown) => e instanceof HttpError && e.status === 400 && e.message === `${field} must be an object {"type", "id"}`, field);
  };
  refused('object', { object: 'case:CASE-14', relation: 'allocated', subject: { type: 'user', id: 'dan' } });
  refused('subject', { object: { type: 'case', id: 'CASE-14' }, relation: 'allocated', subject: 'user:dan' });
});
