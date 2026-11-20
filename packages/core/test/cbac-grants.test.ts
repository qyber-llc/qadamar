// CBAC grant duration and session expiry, and the content-rule rename (bundle field abacContent, legacy cbac read for
// one version). Edges are inclusive: a grant is live at exactly notBefore and at exactly notAfter, not 1 ms outside.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  buildFilter, contentRules, DEPRECATED_CONTENT_FIELD, evalExpr, evaluate, indexTuples, liveRoles, mandatoryWeakenings, procedureFingerprint,
  rbacGrant, requestErrors, validateBundle, windowState,
  type Context, type PolicyBundle, type Resource, type Subject, type Tuple,
} from '../src/index.ts';

const load = (f: string) => JSON.parse(readFileSync(new URL(`../../../examples/toy-domain/${f}`, import.meta.url), 'utf8'));
const toy: PolicyBundle = load('bundle.json');
const world: { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] } = load('world.json');
const graph = indexTuples(world.tuples);
const S = (id: string): Subject => world.subjects.find((s) => s.id === id) as Subject;
const R = (id: string): Resource => world.resources.find((r) => r.id === id) as Resource;
const at = (ms: number): string => new Date(Date.parse(world.now) + ms).toISOString();
const ctx: Context = { network: 'trusted', now: world.now };
// lina holds no role: CASE-18 (level 0, outside need-to-know) is readable only through a viewer assignment
const lina = (window: { notBefore?: string; notAfter?: string }): Subject => ({ ...S('lina'), roleAssignments: [{ role: 'viewer', ...window }] });
const read = (subject: Subject, item = R('CASE-18'), context = ctx, g = graph) => evaluate(toy, { subject, action: 'read', resource: item, context }, g);

test('a role assignment is live from notBefore to notAfter inclusive, and does not exist 1 ms outside', () => {
  assert.deepEqual(read(lina({ notBefore: world.now })).rules, ['RBAC.viewer']);
  assert.deepEqual(read(lina({ notAfter: world.now })).rules, ['RBAC.viewer']);
  assert.equal(read(lina({ notBefore: at(-1000), notAfter: at(1000) })).decision, true);
  for (const [window, code] of [[{ notAfter: at(-1) }, 'CBAC.GRANT_EXPIRED'], [{ notBefore: at(1) }, 'CBAC.GRANT_NOT_YET']] as const) {
    const d = read(lina(window));
    assert.deepEqual(d.rules, ['RBAC.NOT_ELIGIBLE'], code);
    const step = d.trace.find((t) => t.stage === 'cbac');
    assert.deepEqual([step?.rule, step?.outcome, step?.policyRule, step?.requirement, step?.observed], [code, 'skip', 'viewer', 'roleAssignment', world.now]);
  }
});

test('an unconditional role still grants, and an assignment outside its window is traced only when nothing else grants', () => {
  const both: Subject = { ...S('lina'), roles: ['viewer'], roleAssignments: [{ role: 'viewer', notAfter: at(-1) }] };
  const d = read(both);
  assert.equal(d.decision, true);
  assert.ok(!d.trace.some((t) => t.stage === 'cbac'));
  // an assignment of a role that grants nothing here is not traced either
  assert.ok(!read({ ...S('lina'), roleAssignments: [{ role: 'finance_clerk', notAfter: at(-1) }] }).trace.some((t) => t.stage === 'cbac'));
});

test('liveRoles and rbacGrant read the window at now; without now every assignment counts', () => {
  const expired = lina({ notAfter: at(-1) });
  assert.deepEqual(liveRoles(expired, world.now), []);
  assert.deepEqual(liveRoles(expired), ['viewer']);
  assert.equal(rbacGrant(toy, expired, 'case', 'read', world.now), null);
  assert.equal(rbacGrant(toy, expired, 'case', 'read'), 'RBAC.viewer');
});

test('the list filter honours role windows exactly as point decisions do', () => {
  for (const window of [{ notBefore: world.now }, { notAfter: world.now }, { notAfter: at(-1) }, { notBefore: at(1) }]) {
    const subject = lina(window);
    const residual = buildFilter(toy, subject, 'case', 'read', ctx, graph);
    for (const item of world.resources.filter((r) => r.type === 'case')) {
      const kept = evalExpr(residual, { subject, resource: item, action: { name: 'read', kind: 'read' }, context: ctx });
      assert.equal(kept, read(subject, item).decision, `${JSON.stringify(window)} ${item.id}`);
    }
  }
});

test('a relation grant outside its window does not exist: inclusive edges, notBefore/notAfter over validFrom/validTo', () => {
  const bob = S('bob');
  const ended = read(bob, R('CASE-15'));
  assert.deepEqual(ended.rules, ['NTK.NO_REASON']);
  const step = ended.trace.find((t) => t.stage === 'cbac');
  assert.deepEqual([step?.rule, step?.policyRule, step?.requirement], ['CBAC.GRANT_EXPIRED', 'NTK.knows', 'relationTuple']);
  const grant = (window: Partial<Tuple>): Tuple => ({ object: { type: 'case', id: 'CASE-15' }, relation: 'granted', subject: { type: 'user', id: 'bob' }, ...window });
  const withGrant = (t: Tuple) => read(bob, R('CASE-15'), ctx, indexTuples([...world.tuples, t]));
  assert.equal(withGrant(grant({ notBefore: world.now })).decision, true);
  assert.equal(withGrant(grant({ notAfter: world.now })).decision, true);
  const early = withGrant(grant({ notBefore: at(1) }));
  assert.equal(early.decision, false);
  assert.ok(early.trace.some((t) => t.rule === 'CBAC.GRANT_NOT_YET'));
  // the new names win over the legacy ones, in both directions
  assert.equal(withGrant(grant({ validTo: at(-1), notAfter: at(1000) })).decision, true);
  assert.equal(withGrant(grant({ validTo: at(1000), notAfter: at(-1) })).decision, false);
  assert.equal(withGrant(grant({ validFrom: at(-1000), notBefore: at(1) })).decision, false);
});

test('an unparseable bound or instant is never live (fail closed)', () => {
  assert.equal(windowState({ notAfter: 'tomorrow' }, Date.parse(world.now)), 'expired');
  assert.equal(windowState({}, Number.NaN), 'expired');
  assert.equal(windowState({}, Date.parse(world.now)), 'live');
});

test('role assignments are validated strictly in requests', () => {
  const bad: unknown[] = [
    'viewer', [{ role: '' }], [{ role: 'viewer', notBefore: 'yesterday' }], [{ role: 'viewer', extra: 1 }],
    [{ role: 'viewer', notBefore: at(1), notAfter: at(0) }], Array.from({ length: 257 }, () => ({ role: 'viewer' })),
  ];
  for (const roleAssignments of bad) {
    const subject = { ...S('lina'), roleAssignments } as unknown as Subject;
    assert.ok(requestErrors({ subject, action: 'read', resource: R('CASE-18'), context: ctx }).length > 0, JSON.stringify(roleAssignments).slice(0, 60));
    assert.equal(read(subject).decision, false);
  }
});

test('a session known to be expired denies with CBAC.SESSION_EXPIRED, and the list filter keeps nothing', () => {
  const expired: Context = { ...ctx, sessionId: 's-1', sessionExpired: true };
  const d = read(S('alice'), R('CASE-18'), expired);
  assert.deepEqual(d.rules, ['CBAC.SESSION_EXPIRED']);
  assert.equal(d.trace.find((t) => t.rule === 'CBAC.SESSION_EXPIRED')?.stage, 'cbac');
  assert.equal(read(S('alice'), R('CASE-18'), { ...ctx, sessionExpired: false }).decision, true);
  assert.deepEqual(buildFilter(toy, S('alice'), 'case', 'read', expired, graph), { op: 'not', arg: { op: 'true' } });
  assert.ok(requestErrors({ subject: S('alice'), action: 'read', resource: R('CASE-18'), context: { ...ctx, sessionExpired: 'yes' as unknown as boolean } }).length > 0);
});

const { abacContent, ...withoutContent } = toy;
const legacy = { ...withoutContent, cbac: abacContent } as unknown as PolicyBundle;

test('a bundle with the legacy cbac field is read as abacContent with a deprecation warning; both fields are refused', () => {
  const result = validateBundle(legacy);
  assert.ok(result.ok);
  assert.deepEqual(result.warnings, [DEPRECATED_CONTENT_FIELD]);
  assert.match(DEPRECATED_CONTENT_FIELD, /^DEPRECATED_CBAC_FIELD/);
  assert.deepEqual(result.bundle.abacContent, abacContent);
  assert.ok(!Object.hasOwn(result.bundle, 'cbac'));
  const modern = validateBundle(toy);
  assert.ok(modern.ok);
  assert.deepEqual(modern.warnings, []);
  assert.equal(modern.bundle, toy, 'a current bundle is returned as given (its policy version does not move)');
  const both = validateBundle({ ...toy, cbac: [] });
  assert.ok(!both.ok);
  assert.ok(both.errors.includes('cbac and abacContent cannot both be present'));
  const named = validateBundle({ ...legacy, cbac: [{ id: 'x', description: 'x', contentClass: 'pii', effect: 'redact' }] });
  assert.ok(!named.ok && named.errors.some((e) => e.startsWith('cbac x:')), 'errors name the field the author wrote');
  assert.ok(!validateBundle({ ...toy, abacContent: {} }).ok);
});

test('a stored legacy bundle decides, filters, fingerprints and compares exactly as its renamed form', () => {
  const extra: Tuple = { object: { type: 'case', id: 'CASE-15' }, relation: 'granted', subject: { type: 'user', id: 'bob' } };
  const g = indexTuples([...world.tuples, extra]);
  for (const [subject, action, item] of [['bob', 'export', 'CASE-15'], ['bob', 'read', 'CASE-14'], ['henry', 'read', 'CASE-14']] as const) {
    const req = { subject: S(subject), action, resource: R(item), context: ctx };
    assert.deepEqual(evaluate(legacy, req, g).trace, evaluate(toy, req, g).trace, `${subject} ${action} ${item}`);
    assert.deepEqual(buildFilter(legacy, S(subject), 'case', action, ctx, g), buildFilter(toy, S(subject), 'case', action, ctx, g));
  }
  assert.deepEqual(contentRules(legacy), contentRules(toy));
  for (const [type, action] of [['case', 'export'], ['payment', 'approve']] as const) assert.equal(procedureFingerprint(legacy, type, action), procedureFingerprint(toy, type, action));
  assert.deepEqual(mandatoryWeakenings(legacy, toy), []);
  assert.equal(mandatoryWeakenings(toy, { ...toy, abacContent: [] }).length, 2);
  // a bundle that skipped validation with both fields loses no rule
  assert.equal(contentRules({ ...toy, cbac: [{ id: 'extra', description: 'x', contentClass: 'pii.iban', effect: 'deny' }] }).length, 3);
});

test('a live role assignment is a role everywhere (ABAC conditions, trusted roles, filters); an expired one counts for nothing', () => {
  // the probe of the review: a forbid written against a role must catch the time-bound grant of that role too
  const forbid: PolicyBundle = { ...toy, abac: [...toy.abac, { id: 'no-viewers', description: 'no viewers', effect: 'forbid', resourceTypes: ['case'], actions: ['read'],
    when: { op: 'contains', left: { path: 'subject.roles' }, right: { value: 'viewer' } } }] };
  const probe = (s: Subject) => evaluate(forbid, { subject: s, action: 'read', resource: R('CASE-18'), context: ctx }, graph);
  assert.deepEqual(probe({ ...S('lina'), roles: ['viewer'] }).rules, ['ABAC.no-viewers']);
  assert.deepEqual(probe(lina({ notAfter: at(1000) })).rules, ['ABAC.no-viewers']);
  const actions = Object.entries(toy.schema.resourceTypes).flatMap(([type, def]) => Object.keys(def.actions).map((action) => [type, action] as const));
  let compared = 0;
  for (const base of world.subjects.filter((s) => !s.delegator)) {
    for (const role of [...Object.keys(toy.rbac.roles), ...toy.mandatory.trustedRoles]) {
      const plain = { ...base, roles: base.roles.filter((r) => r !== role) };
      const held = { ...plain, roles: [...plain.roles, role] };
      const live = { ...plain, roleAssignments: [{ role, notBefore: at(-1000), notAfter: at(1000) }] };
      const expired = { ...plain, roleAssignments: [{ role, notAfter: at(-1) }] };
      for (const [type, action] of actions) {
        for (const context of [ctx, { ...ctx, sessionLevel: 3 as const }, { ...ctx, network: 'untrusted' as const }]) {
          const decide = (s: Subject, b = forbid) => world.resources.filter((r) => r.type === type).map((resource) => {
            const d = evaluate(b, { subject: s, action, resource, context }, graph);
            return [d.decision, d.rules.filter((r) => !r.startsWith('CBAC.GRANT_'))];
          });
          assert.deepEqual(decide(live), decide(held), `${base.id} ${role} live ${type} ${action}`);
          assert.deepEqual(decide(expired), decide(plain), `${base.id} ${role} expired ${type} ${action}`);
          compared++;
          if (toy.schema.resourceTypes[type]!.actions[action]!.requiresSecondPerson) continue; // the maker is a point-only fact
          const residual = buildFilter(forbid, live, type, action, context, graph);
          for (const resource of world.resources.filter((r) => r.type === type)) {
            const kind = toy.schema.resourceTypes[type]!.actions[action]!.kind;
            assert.equal(evalExpr(residual, { subject: live, resource, action: { name: action, kind }, context }),
              evaluate(forbid, { subject: live, action, resource, context }, graph).decision, `filter ${base.id} ${role} ${resource.id} ${action}`);
          }
        }
      }
    }
  }
  assert.ok(compared > 500, `${compared}`);
});
