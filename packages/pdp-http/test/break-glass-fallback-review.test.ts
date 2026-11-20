// Owner decision "Revue par un 2e role": when no security officer other than the opener and the beneficiary exists, an
// access_admin who is neither may review or revoke the emergency, so the pair is never locked forever. Always two
// distinct people; the audit row records the reviewer's role and the fallback. Refused while another officer exists.
import test from 'node:test';
import assert from 'node:assert/strict';
import { open, reviewEmergency } from '../src/admin/break-glass.ts';
import { admin } from '../src/admin/index.ts';
import { HttpError } from '../src/http.ts';
import type { User } from '../src/auth.ts';
import { fixture, users, WHY } from './helpers.ts';

const status = (code: number) => (e: unknown): boolean => e instanceof HttpError && e.status === code;
const b = { subjectId: 'bob', resourceId: 'CASE-15', reason: WHY, hours: 1 };
const review = { outcome: 'justified', note: WHY };
const lastDetails = (f: ReturnType<typeof fixture>): Record<string, unknown> => (f.rt.audit.records().at(-1)?.details ?? {}) as Record<string, unknown>;

test('an access_admin reviews when the opener is the only security officer, and the audit says so', (t) => {
  const f = fixture(t);
  const e = open(f.rt, users.lina, b);
  assert.equal(reviewEmergency(f.rt, users.amira, e.id, 'review', review, ['lina']).reviewedBy, 'amira');
  assert.deepEqual([lastDetails(f).reviewerRole, lastDetails(f).fallback], ['access_admin', true]);
});

test('the fallback is refused while another eligible security officer exists, or when none can be counted', (t) => {
  const { rt } = fixture(t);
  const e = open(rt, users.lina, b);
  assert.throws(() => reviewEmergency(rt, users.amira, e.id, 'review', review, ['lina', 'nadia']), status(403));
  assert.throws(() => reviewEmergency(rt, users.amira, e.id, 'revoke', { reason: WHY }, ['lina', 'nadia']), status(403));
  assert.throws(() => reviewEmergency(rt, users.amira, e.id, 'review', review), status(403), 'officers unknown: refused');
  assert.throws(() => reviewEmergency(rt, users.omar, e.id, 'review', review, ['lina']), status(403), 'an approver is no access_admin');
});

test('the beneficiary officer does not count, and the fallback also revokes', (t) => {
  const { rt } = fixture(t);
  const e = open(rt, users.amira, { ...b, subjectId: 'dan' }); // dan, the beneficiary, is the only officer listed
  const zoe: User = { id: 'zoe', name: 'zoe', roles: ['access_admin'] };
  assert.equal(reviewEmergency(rt, zoe, e.id, 'revoke', { reason: WHY }, ['dan']).status, 'revoked');
});

test('the opener and the beneficiary never review, on either path', (t) => {
  const { rt } = fixture(t);
  const e = open(rt, users.lina, b);
  const bobAdmin: User = { id: 'bob', name: 'bob', roles: ['access_admin'] };
  assert.throws(() => reviewEmergency(rt, bobAdmin, e.id, 'review', review, ['lina']), status(403), 'beneficiary');
  const mine = open(rt, users.amira, { ...b, resourceId: 'CASE-14' });
  assert.throws(() => reviewEmergency(rt, users.amira, mine.id, 'review', review, []), status(403), 'opener');
  assert.throws(() => reviewEmergency(rt, users.amira, mine.id, 'revoke', { reason: WHY }, []), status(403), 'opener');
});

test('a security officer reviews as before, never through the fallback, even when also access_admin', (t) => {
  const f = fixture(t);
  const e = open(f.rt, users.amira, b);
  const nadia: User = { id: 'nadia', name: 'nadia', roles: ['security_officer', 'access_admin'] };
  reviewEmergency(f.rt, nadia, e.id, 'review', review, ['nadia', 'lina']);
  assert.deepEqual([lastDetails(f).reviewerRole, lastDetails(f).fallback], ['security_officer', false]);
});

test('console: the officers are the local accounts, and the list says which emergencies the caller may review', (t) => {
  const { rt, auth } = fixture(t);
  const e = open(rt, users.lina, b); // lina is the only seeded security officer
  const url = (p: string): URL => new URL(`http://x/admin/v1${p}`);
  const list = (u: User): unknown => (admin(rt, u, 'GET', url('/break-glass'), {}, auth).value as { fallbackReview: unknown }).fallbackReview;
  assert.deepEqual(list(users.amira), ['seed-10', e.id]); // the demo's seeded emergency was opened by lina too
  assert.deepEqual(list(users.lina), []);
  assert.equal((admin(rt, users.amira, 'POST', url(`/break-glass/${e.id}/review`), review, auth).value as { reviewedBy: string }).reviewedBy, 'amira');
});

test('with SSO sign-in configured, officers may exist only at the identity provider: no fallback', (t) => {
  const { rt, auth } = fixture(t);
  const e = open(rt, users.lina, b);
  const url = (p: string): URL => new URL(`http://x/admin/v1${p}`);
  const sso = { officersKnown: false };
  assert.deepEqual((admin(rt, users.amira, 'GET', url('/break-glass'), {}, auth, sso).value as { fallbackReview: unknown }).fallbackReview, []);
  assert.throws(() => admin(rt, users.amira, 'POST', url(`/break-glass/${e.id}/review`), review, auth, sso), status(403));
});
