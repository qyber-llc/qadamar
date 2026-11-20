// Break-glass cannot be re-opened for the same subject and resource while one is active or unreviewed, so the
// time box is a bound and a revoke sticks until a security officer has reviewed it (admin-plane review finding 2).
import test from 'node:test';
import assert from 'node:assert/strict';
import { open, reviewEmergency } from '../src/admin/break-glass.ts';
import { HttpError } from '../src/http.ts';
import { fixture, users, WHY } from './helpers.ts';

const pending = (e: unknown): boolean => e instanceof HttpError && e.status === 409 && e.code === 'break_glass_pending';

test('a second emergency on the same pair is refused while the first is active, unreviewed, or revoked without review', (t) => {
  const { rt, setClock } = fixture(t);
  const b = { subjectId: 'bob', resourceId: 'CASE-15', reason: WHY, hours: 1 };
  const first = open(rt, users.amira, b);
  assert.throws(() => open(rt, users.amira, b), pending, 'active and unreviewed');
  assert.throws(() => open(rt, users.lina, b), pending, 'whoever asks');
  open(rt, users.amira, { ...b, resourceId: 'CASE-14' }); // another resource is another emergency
  reviewEmergency(rt, users.lina, first.id, 'review', { outcome: 'justified', note: WHY });
  assert.throws(() => open(rt, users.amira, b), pending, 'reviewed but still active');
  setClock('2026-11-08T11:00:01Z');
  open(rt, users.amira, b); // the reviewed one expired: a new emergency may start

  const second = open(rt, users.amira, { ...b, subjectId: 'dan', resourceId: 'CASE-11' });
  reviewEmergency(rt, users.lina, second.id, 'revoke', { reason: WHY });
  assert.throws(() => open(rt, users.amira, { ...b, subjectId: 'dan', resourceId: 'CASE-11' }), pending, 'revoked, not yet reviewed');
  reviewEmergency(rt, users.lina, second.id, 'review', { outcome: 'escalated', note: WHY });
  open(rt, users.amira, { ...b, subjectId: 'dan', resourceId: 'CASE-11' });

  const third = open(rt, users.amira, { ...b, subjectId: 'iris', resourceId: 'CASE-18' });
  setClock('2026-11-08T12:00:02Z');
  assert.throws(() => open(rt, users.amira, { ...b, subjectId: 'iris', resourceId: 'CASE-18' }), pending, 'expired, never reviewed');
  reviewEmergency(rt, users.lina, third.id, 'review', { outcome: 'justified', note: WHY });
  assert.equal(open(rt, users.amira, { ...b, subjectId: 'iris', resourceId: 'CASE-18' }).resourceType, 'case');
});
