import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'vite';

const vite = await createServer({ server: { middlewareMode: true, watch: null, ws: false }, logLevel: 'silent' });
after(() => vite.close());
const { validateImpact, validateChangeRecord, validateChangesResponse } = await vite.ssrLoadModule('/src/api/validators.ts');

const entry = { subject: 'user:alice', resource: 'doc:1', action: 'read', rules: ['RBAC.viewer'] };
const delta = { redact: ['ssn'], maskClasses: [], notify: [], fieldAllowlist: { before: ['id'], after: null }, decisionToken: true };
const impact = { evaluated: 4, gained: [entry], lost: [], obligationsLost: [{ ...entry, obligations: delta }], obligationsGained: [],
  policyVersionBefore: 'a', policyVersionAfter: 'b' };
const change = { id: 'chg-1', kind: 'add_tuple', status: 'pending', impact };

test('a well-formed impact and change pass unchanged', () => {
  assert.equal(validateImpact(impact), impact);
  assert.equal(validateChangeRecord(change), change);
  assert.deepEqual(validateChangesResponse({ items: [change] }), { items: [change] });
  assert.equal(validateImpact({ evaluated: 0, gained: [], lost: [] }).evaluated, 0, 'servers before obligation rows still validate');
});

test('rows the impact tables dereference are checked, so a malformed answer is an invalid response, not a render crash', () => {
  for (const bad of [
    { ...impact, gained: [null] },
    { ...impact, gained: [{ ...entry, rules: 'x' }] },
    { ...impact, lost: [{}] },
    { ...impact, obligationsLost: [{ redact: 5 }] },
    { ...impact, obligationsLost: [{ ...entry, obligations: { ...delta, notify: undefined } }] },
    { ...impact, obligationsGained: [{ ...entry, obligations: { ...delta, fieldAllowlist: { before: 1, after: null } } }] },
  ]) {
    assert.throws(() => validateImpact(bad), /Invalid API response for impact/, JSON.stringify(bad));
  }
});

test('a change record, alone or in a list, carries a valid impact', () => {
  assert.throws(() => validateChangeRecord({ ...change, impact: {} }), /Invalid API response for impact/);
  assert.throws(() => validateChangesResponse({ items: [change, { ...change, impact: {} }] }), /Invalid API response for changes\.items/);
});
