// The certify_tp impact preview shows the access the certification record would open (admin-plane review finding 6).
import test from 'node:test';
import assert from 'node:assert/strict';
import { admin } from '../src/admin/index.ts';
import { fixture, user, WHY } from './helpers.ts';
import type { Change } from '../src/store.ts';

test('a certify_tp proposal previews the cells the record opens, and approval writes one real record', (t) => {
  const f = fixture(t);
  const s = f.rt.store.state;
  f.rt.store.state = { ...s, bundle: { ...s.bundle, clarkWilson: { ...s.bundle.clarkWilson, requireCertification: ['payment'] } } };
  f.rt.sodHistory = 'caller'; // henry approves a payment grace created (integrity.test.ts)
  const call = (id: string, path: string, b: Record<string, unknown>) => admin(f.rt, user(id), 'POST', new URL(`http://x/admin/v1${path}`), b).value;
  const change = call('lina', '/changes', { kind: 'certify_tp', payload: { resourceType: 'payment', action: 'approve' }, reason: WHY }) as Change;
  assert.ok(change.impact.gained.some((g) => g.resourceType === 'payment' && g.action === 'approve'), 'the preview lists the payment:approve cells the record permits');
  assert.equal(change.broadens, true);
  assert.deepEqual(f.rt.store.state.certifications ?? [], [], 'the proposal writes no record');
  const applied = call('omar', `/changes/${change.id}/approve`, { reason: WHY }) as Change;
  assert.equal(applied.status, 'applied', 'the approval-time impact matches the preview');
  const records = f.rt.store.state.certifications ?? [];
  assert.equal(records.length, 1);
  assert.equal(records[0]!.certifiedBy, 'lina'); assert.equal(records[0]!.approvedBy, 'omar');
});
