import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  buildFilter, evalExpr, evaluate, filterDecides, indexTuples, legacyPolicyVersion, policyVersion, simulate, validateBundle,
  type Context, type PolicyBundle, type Resource, type Subject, type Tuple,
} from '../src/index.ts';

const load = (f: string) => JSON.parse(readFileSync(new URL(`../../../examples/toy-domain/${f}`, import.meta.url), 'utf8'));
const bundle: PolicyBundle = load('bundle.json');
const world: { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] } = load('world.json');
const graph = indexTuples(world.tuples);
const S = (id: string): Subject => {
  const s = world.subjects.find((x) => x.id === id);
  if (!s) throw new Error(`no subject ${id}`);
  return s;
};
const R = (id: string): Resource => {
  const r = world.resources.find((x) => x.id === id);
  if (!r) throw new Error(`no resource ${id}`);
  return r;
};
const ctx = (over: Partial<Context> = {}): Context => ({ network: 'trusted', now: world.now, ...over });
const agent = (): Subject => ({ ...S('assistant-1'), delegator: S('bob') });

const decide = (subject: Subject, action: string, resource: Resource, context = ctx(), b = bundle, g = graph) =>
  evaluate(b, { subject, action, resource, context }, g);

test('team membership gives a reason to know, with its path', () => {
  const d = decide(S('alice'), 'read', R('CASE-7'));
  assert.equal(d.decision, true);
  const ntk = d.trace.find((t) => t.stage === 'need_to_know');
  assert.deepEqual(ntk?.path, ['case:CASE-7#member@team:orchid#member', 'team:orchid#member@user:alice']);
});

test('untrusted network caps the level and excludes compartments', () => {
  const d = decide(S('alice'), 'read', R('CASE-7'), ctx({ network: 'untrusted' }));
  assert.equal(d.decision, false);
  assert.deepEqual([...d.rules].sort(), ['NET.UNTRUSTED_COMPARTMENT', 'NET.UNTRUSTED_LEVEL']);
});

test('BLP no read up and compartments deny, whatever the relations', () => {
  const d = decide(S('bob'), 'read', R('CASE-7'));
  assert.equal(d.decision, false);
  for (const r of ['BLP.NO_READ_UP', 'MAC.COMPARTMENT', 'NTK.NO_REASON']) assert.ok(d.rules.includes(r), r);
});

test('a relation never lifts a mandatory control (the product invariant)', () => {
  const extra: Tuple = { object: { type: 'case', id: 'CASE-7' }, relation: 'granted', subject: { type: 'user', id: 'bob' } };
  const d = decide(S('bob'), 'read', R('CASE-7'), ctx(), bundle, indexTuples([...world.tuples, extra]));
  assert.equal(d.decision, false);
  assert.ok(d.rules.includes('BLP.NO_READ_UP') && d.rules.includes('MAC.COMPARTMENT'));
  assert.ok(!d.rules.includes('NTK.NO_REASON'));
});

test('a live allocation allows, with ABAC content masking and ABAC redaction', () => {
  const d = decide(S('bob'), 'read', R('CASE-14'));
  assert.equal(d.decision, true);
  assert.deepEqual(d.obligations.maskClasses, ['finance.amount']);
  assert.deepEqual(d.obligations.redact, ['informant_name']);
  assert.match(d.trace.find((t) => t.stage === 'need_to_know')?.path?.[0] ?? '', /allocated@user:bob until 2026-12-31/);
});

test('the reporting line is transitive: a manager knows what the report knows', () => {
  const d = decide(S('carol'), 'read', R('CASE-14'));
  assert.equal(d.decision, true);
  const path = d.trace.find((t) => t.stage === 'need_to_know')?.path ?? [];
  assert.ok(path.some((p) => p.includes('user:bob#manager@user:carol')));
});

test('a reporting-line cycle is never followed', () => {
  const cycle: Tuple[] = [
    ...world.tuples,
    { object: { type: 'user', id: 'carol' }, relation: 'manager', subject: { type: 'user', id: 'bob' } },
  ];
  const d = decide(S('eve'), 'read', R('CASE-11'), ctx(), bundle, indexTuples(cycle));
  assert.equal(d.decision, false);
});

test('inheritance from a parent folder gives a reason to know', () => {
  assert.equal(decide(S('bob'), 'read', R('CASE-11')).decision, true);
});

test('an ended allocation gives no reason to know', () => {
  const d = decide(S('bob'), 'read', R('CASE-15'));
  assert.deepEqual(d.rules, ['NTK.NO_REASON']);
});

test('an inactive subject is denied first', () => {
  assert.deepEqual(decide(S('frank'), 'read', R('CASE-18')).rules, ['CORE.INACTIVE']);
});

test('an AI agent reads its delegated case but cannot write verified data (Biba)', () => {
  assert.equal(decide(agent(), 'read', R('CASE-14')).decision, true);
  const w = decide(agent(), 'update', R('CASE-14'));
  assert.equal(w.decision, false);
  assert.deepEqual(w.rules, ['BIBA.NO_WRITE_UP']);
});

test('an agent needs its own delegation: the delegator knowing is not enough', () => {
  const d = decide(agent(), 'read', R('CASE-11'));
  assert.equal(d.decision, false);
  assert.ok(d.rules.includes('NTK.NO_REASON'));
});

test('an agent never exceeds its delegator', () => {
  const strong: Subject = { ...S('assistant-1'), clearance: 3, compartments: ['ORCHID'], delegator: S('bob') };
  const extra: Tuple = { object: { type: 'case', id: 'CASE-7' }, relation: 'delegate', subject: { type: 'agent', id: 'assistant-1' } };
  const d = decide(strong, 'read', R('CASE-7'), ctx(), bundle, indexTuples([...world.tuples, extra]));
  assert.equal(d.decision, false);
  assert.ok(d.rules.includes('DELEGATION.BLP.NO_READ_UP') && d.rules.includes('DELEGATION.NTK.NO_REASON'));
});

test('break-glass gives a reason to know for its window only, and notifies', () => {
  const d = decide(S('dan'), 'read', R('CASE-12'));
  assert.equal(d.decision, true);
  assert.deepEqual(d.obligations.notify, ['security-officer']);
  assert.equal(decide(S('dan'), 'read', R('CASE-12'), ctx({ now: '2026-11-08T14:00:00Z' })).decision, false);
});

test('a break-glass grant longer than the cap is ignored', () => {
  const long = world.tuples.map((t) => (t.breakGlass ? { ...t, validTo: '2026-11-08T16:00:00Z' } : t));
  assert.equal(decide(S('dan'), 'read', R('CASE-12'), ctx(), bundle, indexTuples(long)).decision, false);
});

test('BLP no write down, unless the session is lowered', () => {
  const d = decide(S('carol'), 'update', R('CASE-11'));
  assert.deepEqual(d.rules, ['BLP.NO_WRITE_DOWN']);
  assert.equal(decide(S('carol'), 'update', R('CASE-11'), ctx({ sessionLevel: 1 })).decision, true);
});

test('BLP high-water mark: a session that read L2 cannot write below it, whatever level it asks for', () => {
  const marked = ctx({ sessionLevel: 1, sessionId: 's1', highWater: 2 });
  assert.deepEqual(decide(S('carol'), 'update', R('CASE-11'), marked).rules, ['BLP.HIGH_WATER']);
  assert.equal(decide(S('carol'), 'update', R('CASE-14'), marked).decision, true, 'writing at the mark is allowed');
  // the mark raises the working level for reads too (never above the clearance)
  assert.deepEqual(decide(S('carol'), 'read', R('CASE-14'), ctx({ sessionLevel: 1 })).rules, ['BLP.NO_READ_UP']);
  assert.equal(decide(S('carol'), 'read', R('CASE-14'), marked).decision, true);
  // below the requested level stays NO_WRITE_DOWN; a mark above a lowered clearance still holds
  assert.deepEqual(decide(S('carol'), 'update', R('CASE-11'), ctx({ sessionLevel: 2, highWater: 3 })).rules, ['BLP.NO_WRITE_DOWN']);
  assert.deepEqual(decide({ ...S('carol'), clearance: 1 }, 'update', R('CASE-11'), ctx({ highWater: 2 })).rules, ['BLP.HIGH_WATER']);
  const trusted: Tuple = { object: { type: 'case', id: 'CASE-11' }, relation: 'granted', subject: { type: 'user', id: 'iris' } };
  assert.equal(decide(S('iris'), 'update', R('CASE-11'), ctx({ highWater: 3 }), bundle, indexTuples([...world.tuples, trusted])).decision, true, 'trusted roles are exempt');
});

test('BLP_SESSION_REQUIRED: cleared writes and reads above L0 need a session, in the engine and in the filter', () => {
  const required = ctx({ sessionLevel: 1, sessionRequired: true });
  assert.ok(decide(S('carol'), 'update', R('CASE-11'), required).rules.includes('BLP.SESSION_REQUIRED'));
  assert.ok(decide(S('carol'), 'read', R('CASE-14'), required).rules.includes('BLP.SESSION_REQUIRED'));
  assert.equal(decide(S('carol'), 'read', R('CASE-18'), required).decision, true, 'L0 reads need no session');
  assert.equal(decide(S('carol'), 'update', R('CASE-11'), { ...required, sessionId: 's1' }).decision, true);
  for (const [action, kind] of [['read', 'read'], ['update', 'write']] as const) {
    for (const c of [required, ctx({ sessionLevel: 1, sessionId: 's1', highWater: 2 })]) {
      const residual = buildFilter(bundle, S('carol'), 'case', action, c, graph);
      for (const r of world.resources.filter((x) => x.type === 'case')) {
        const kept = evalExpr(residual, { subject: S('carol'), resource: r, action: { name: action, kind }, context: c }) === true;
        assert.equal(kept, decide(S('carol'), action, r, c).decision, `${action} ${r.id}`);
      }
    }
  }
});

test('a trusted subject may write down', () => {
  const extra: Tuple = { object: { type: 'case', id: 'CASE-11' }, relation: 'granted', subject: { type: 'user', id: 'iris' } };
  assert.equal(decide(S('iris'), 'update', R('CASE-11'), ctx(), bundle, indexTuples([...world.tuples, extra])).decision, true);
});

test('ABAC forbid: a closed case is read-only', () => {
  const d = decide(S('carol'), 'update', R('CASE-18'), ctx({ sessionLevel: 0 }));
  assert.deepEqual(d.rules, ['ABAC.closed-is-read-only']);
});

test('ABAC on content attributes, deny: a document with bank account numbers is never exported', () => {
  const extra: Tuple = { object: { type: 'case', id: 'CASE-15' }, relation: 'granted', subject: { type: 'user', id: 'bob' } };
  const d = decide(S('bob'), 'export', R('CASE-15'), ctx(), bundle, indexTuples([...world.tuples, extra]));
  assert.deepEqual(d.rules, ['ABAC.CONTENT_DENY']);
  const step = d.trace.find((t) => t.rule === 'ABAC.CONTENT_DENY');
  assert.deepEqual([step?.stage, step?.kind, step?.policyRule], ['abac', 'content', 'no-iban-export']);
  assert.ok(!d.trace.some((t) => t.stage === 'cbac'), 'content rules are not CBAC');
});

test('Clark-Wilson: a constrained item changes only through a certified command', () => {
  assert.deepEqual(decide(S('grace'), 'edit', R('PAY-3')).rules, ['CW.UNCERTIFIED_TP']);
  const ok = decide(S('henry'), 'approve', R('PAY-3'), ctx({ makerId: 'grace' }));
  assert.equal(ok.decision, true);
  assert.deepEqual(ok.obligations.decisionToken, { ttlSeconds: 15, resourceVersion: 4 });
});

test('two-person rule and separation of duty', () => {
  const both: Subject = { ...S('grace'), id: 'gus', roles: ['finance_clerk', 'finance_approver'] };
  assert.deepEqual(decide(both, 'approve', R('PAY-3'), ctx({ makerId: 'gus' })).rules, ['SOD.SELF_APPROVAL']);
  assert.deepEqual(decide(both, 'approve', R('PAY-3')).rules, ['SOD.MAKER_UNKNOWN']);
  assert.deepEqual(decide(both, 'release', R('PAY-3'), ctx({ priorActions: ['create'] })).rules, ['SOD.create-vs-release']);
});

test('Biba no read down: an approval cannot rely on machine-derived data', () => {
  const derived: Resource = { ...R('PAY-3'), integrity: 'derived' };
  assert.deepEqual(decide(S('henry'), 'approve', derived, ctx({ makerId: 'grace' })).rules, ['BIBA.NO_READ_DOWN']);
});

test('Biba no-read-down scope defaults to the action list and generalizes to reads or every action', () => {
  const derived: Resource = { ...R('CASE-14'), integrity: 'derived' };
  const verified: Resource = { ...derived, integrity: 'verified' };
  const scoped = (scope: 'actions' | 'reads' | 'all'): PolicyBundle => ({ ...bundle, mandatory: { ...bundle.mandatory, bibaNoReadDownScope: scope } });
  assert.equal(decide(S('bob'), 'read', derived).decision, true, 'an old bundle keeps its per-action default');
  assert.equal(decide(S('bob'), 'read', derived, ctx(), scoped('actions')).decision, true);
  for (const scope of ['reads', 'all'] as const) {
    const b = scoped(scope);
    assert.ok(decide(S('bob'), 'read', derived, ctx(), b).rules.includes('BIBA.NO_READ_DOWN'), scope);
    assert.equal(decide(S('bob'), 'read', verified, ctx(), b).decision, true, `${scope}: equal integrity still reads`);
    const residual = buildFilter(b, S('bob'), 'case', 'read', ctx(), graph);
    const env = (resource: Resource) => ({ subject: S('bob'), resource, action: { name: 'read', kind: 'read' }, context: ctx() });
    assert.equal(evalExpr(residual, env(derived)), false, `${scope}: filter refuses lower integrity`);
    assert.equal(evalExpr(residual, env(verified)), true, `${scope}: filter retains equal integrity`);
  }
  assert.ok(!decide(S('bob'), 'update', derived, ctx(), scoped('reads')).rules.includes('BIBA.NO_READ_DOWN'), 'reads does not cover writes');
  assert.ok(decide(S('bob'), 'update', derived, ctx(), scoped('all')).rules.includes('BIBA.NO_READ_DOWN'), 'all covers writes too');
  assert.equal(validateBundle({ ...bundle, mandatory: { ...bundle.mandatory, bibaNoReadDownScope: 'sometimes' } }).ok, false);
});

test('ABAC permit: an owner reads without a reading role, still under the mandatory models', () => {
  const owner: Subject = { ...S('grace'), id: 'carol-alt', roles: [], clearance: 1 };
  const own: Resource = { ...R('CASE-18'), owner: 'carol-alt' };
  const d = decide(owner, 'read', own);
  assert.equal(d.decision, true);
  assert.ok(d.rules.includes('ABAC.owner-read'));
});

test('dry run allows but records who would lose access', () => {
  const dry: PolicyBundle = { ...bundle, needToKnow: { ...bundle.needToKnow, mode: 'dry_run' } };
  const d = decide(S('eve'), 'read', R('CASE-11'), ctx(), dry);
  assert.equal(d.decision, true);
  assert.deepEqual(d.wouldDeny, ['NTK.NO_REASON']);
});

test('a malformed rule denies (fail closed)', () => {
  const broken = { ...bundle, abac: [{ id: 'bad', description: 'x', effect: 'forbid', when: { op: 'eq' } }] } as unknown as PolicyBundle;
  const d = decide(S('bob'), 'read', R('CASE-14'), ctx(), broken);
  assert.equal(d.decision, false);
  assert.ok(d.rules.includes('ENGINE.RULE_ERROR'));
});

test('an undeclared action is denied', () => {
  assert.deepEqual(decide(S('alice'), 'shred', R('CASE-7')).rules, ['SCHEMA.UNKNOWN_ACTION']);
});

test('the list filter never keeps a resource the point decision denies (and keeps every allowed one)', () => {
  const subjects = [...world.subjects, agent()];
  let checked = 0;
  for (const network of ['trusted', 'untrusted'] as const) {
    for (const s of subjects) {
      for (const type of Object.keys(bundle.schema.resourceTypes)) {
        for (const [action, def] of Object.entries(bundle.schema.resourceTypes[type]?.actions ?? {})) {
          const pointOnly = def.requiresSecondPerson === true || bundle.sod.some((rule) => rule.conflicting.includes(action));
          assert.equal(filterDecides(bundle, type, action), !pointOnly);
          if (pointOnly) continue; // per-row history, checked point-wise by the PEP
          const residual = buildFilter(bundle, s, type, action, ctx({ network }), graph);
          for (const r of world.resources.filter((x) => x.type === type)) {
            const context = ctx({ network });
            const point = decide(s, action, r, context).decision;
            const kept = evalExpr(residual, { subject: s, resource: r, action: { name: action, kind: def.kind }, context });
            assert.equal(kept, point, `${s.id} ${action} ${r.id} ${network}`);
            checked++;
          }
        }
      }
    }
  }
  assert.ok(checked > 100);
});

test('simulate: removing an allocation shows the transitive losses', () => {
  const before = { bundle, subjects: [...world.subjects, agent()], resources: world.resources, tuples: world.tuples };
  const after = { ...before, tuples: world.tuples.filter((t) => !(t.relation === 'allocated' && t.object.id === 'CASE-14')) };
  const impact = simulate(before, after, ctx(), ['read']);
  assert.deepEqual(impact.gained, []);
  const lost = impact.lost.map((c) => `${c.subject}:${c.resource}`);
  assert.deepEqual(lost, ['assistant-1:CASE-14', 'bob:CASE-14', 'carol:CASE-14']);
});

test('the toy bundle validates; a broken one lists every error', () => {
  assert.equal(validateBundle(bundle).ok, true);
  const bad = validateBundle({ ...bundle, rbac: { roles: { x: { inherits: ['ghost'], grants: [{ resourceType: 'nope', actions: ['read'] }] } } } });
  assert.equal(bad.ok, false);
  if (!bad.ok) {
    assert.ok(bad.errors.includes('role x inherits unknown role ghost'));
    assert.ok(bad.errors.includes('role x grants on unknown type nope'));
    assert.ok(bad.errors.includes('mandatory.trustedRoles: unknown role declassifier'));
  }
});

test('the policy version is stable and changes with the bundle', () => {
  assert.equal(policyVersion(bundle), policyVersion(JSON.parse(JSON.stringify(bundle))));
  assert.notEqual(policyVersion(bundle), policyVersion({ ...bundle, name: 'other' }));
  assert.match(policyVersion(bundle), /^pv\.[0-9a-f]{64}$/);
  assert.match(legacyPolicyVersion(bundle), /^pv\.[0-9a-f]{16}$/);
});
