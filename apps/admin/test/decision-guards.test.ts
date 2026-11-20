// Console decision buttons mirror the server's refusals (console review finding 8).
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'vite';

const vite = await createServer({ server: { middlewareMode: true, watch: null, ws: false }, logLevel: 'silent' });
after(() => vite.close());
const { decisionBlocks } = await vite.ssrLoadModule('/src/screens/ApprovalsScreen.tsx');
const { breakGlassManageBlocked } = await vite.ssrLoadModule('/src/screens/BreakGlassScreen.tsx');

const impact = { evaluated: 1, gained: [], lost: [], obligationsLost: [], obligationsGained: [], policyVersionBefore: 'a', policyVersionAfter: 'a' };
const change = (extra: Record<string, unknown>) => ({ id: 'c', kind: 'add_tuple', status: 'pending', makerId: 'amira', reason: 'r', createdAt: '', broadens: false,
  stateDigest: 'd', impact, payload: { object: { type: 'case', id: 'CASE-1' }, relation: 'granted', subject: { type: 'user', id: 'bob' } }, ...extra });
const approver = { id: 'omar', name: 'omar', roles: ['approver'] };
const officer = { id: 'lina', name: 'lina', roles: ['security_officer'] };

test('the maker and a credential holder can neither approve nor reject', () => {
  assert.deepEqual(decisionBlocks(change({}), { ...approver, id: 'amira' }), { both: 'selfMaker' });
  assert.deepEqual(decisionBlocks(change({ kind: 'scim_subjects', payload: { subjects: [] }, scimCredential: { rotatedBy: 'omar', fingerprint: 'f' } }), approver), { both: 'credentialHolder' });
  assert.deepEqual(decisionBlocks(change({ kind: 'scim_subjects', payload: { subjects: [] } }), approver), { both: 'credentialHolder' });
  assert.deepEqual(decisionBlocks(change({ kind: 'register_resources', payload: { resources: [] }, pepCredential: { id: 'p', issuedBy: 'omar' } }), approver), { both: 'credentialHolder' });
  assert.deepEqual(decisionBlocks(change({ kind: 'register_resources', payload: { resources: [] }, pepCredential: { id: 'p', issuedBy: 'amira' } }), approver), {});
});

test('approve only: the beneficiary, break-glass tuples, and officer-only changes for an approver', () => {
  assert.deepEqual(decisionBlocks(change({}), { ...approver, id: 'bob' }), { approve: 'beneficiary' });
  assert.deepEqual(decisionBlocks(change({ kind: 'update_subject', payload: { id: 'omar', set: {} } }), approver), { approve: 'beneficiary' });
  assert.deepEqual(decisionBlocks(change({ kind: 'scim_subjects', payload: { subjects: [{ id: 'omar' }] }, scimCredential: { rotatedBy: 'x', fingerprint: 'f' } }), approver), { approve: 'beneficiary' });
  assert.deepEqual(decisionBlocks(change({ payload: { object: { type: 'case', id: 'C' }, relation: 'granted', subject: { type: 'user', id: 'bob' }, breakGlass: true } }), approver), { approve: 'breakGlass' });
  const weakening = change({ kind: 'publish_policy', payload: { bundle: {} }, weakensMandatory: ['BLP no longer applies'] });
  assert.deepEqual(decisionBlocks(weakening, approver), { approve: 'officerOnly' });
  assert.deepEqual(decisionBlocks(weakening, officer), {});
  const incomplete = change({ impact: { ...impact, contextAnalysis: { cap: 1, evaluatedClasses: 1, truncated: false, incomplete: true, unsupported: [], classes: [] } } });
  assert.deepEqual(decisionBlocks(incomplete, approver), { approve: 'officerOnly' });
  assert.deepEqual(decisionBlocks(incomplete, officer), {});
  assert.deepEqual(decisionBlocks(change({}), approver), {});
});

test('break-glass review and revoke are closed to the opener and to the subject', () => {
  const grant = { id: 'e', subjectId: 'bob', resourceId: 'CASE-15', openedBy: 'amira' };
  assert.equal(breakGlassManageBlocked(grant, 'amira'), true);
  assert.equal(breakGlassManageBlocked(grant, 'bob'), true);
  assert.equal(breakGlassManageBlocked(grant, 'lina'), false);
});
