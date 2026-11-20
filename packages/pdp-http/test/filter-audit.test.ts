// /x/v1/filter is audited (storage review 4): one decision row per answered filter call, as /x/v1/assertions/list.
import test from 'node:test';
import assert from 'node:assert/strict';
import { policyVersion } from '../../core/src/index.ts';
import { pdp } from '../src/pdp.ts';
import { evaluation, fixture } from './helpers.ts';

const columns = { 'resource.level': { column: 'level', type: 'number' }, 'resource.compartments': { column: 'compartments', kind: 'text[]' }, 'resource.id': 'id' };

test('each filter call writes one decision row naming the subject, action, type, policy version and residual kind', (t) => {
  const { rt } = fixture(t);
  const filter = (id: string, extra: Record<string, unknown> = {}) => {
    const before = rt.audit.records().length;
    pdp(rt, '/x/v1/filter', { ...evaluation(id), resource: { type: 'case' }, columns, ...extra });
    const rows = rt.audit.records().slice(before);
    assert.equal(rows.length, 1);
    return rows[0]!;
  };
  const bob = filter('bob');
  assert.deepEqual({ type: bob.type, actor: bob.actor, action: bob.action, subject: bob.subject, effect: bob.effect, rules: bob.rules, policyVersion: bob.policyVersion, details: bob.details },
    { type: 'decision', actor: 'pep', action: 'read', subject: 'bob', effect: 'allow', rules: ['GATE.FILTER'], policyVersion: policyVersion(rt.store.state.bundle), details: { listOf: 'case', residual: 'conditional' } });
  const ghost = filter('ghost');
  assert.deepEqual([ghost.effect, ghost.rules, ghost.details], ['deny', ['GATE.FILTER_NONE'], { listOf: 'case', residual: 'false' }]);
  // a refused request releases no predicate and writes no row
  const before = rt.audit.records().length;
  assert.throws(() => pdp(rt, '/x/v1/filter', { ...evaluation(), resource: { type: 'case' }, columns: {} }));
  assert.equal(rt.audit.records().length, before);
});
