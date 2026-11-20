// Regressions for the adversarial review of 2026-11-08: each test is a wrong ALLOW (or a silent widening) found
// against the first version of the engine, and must now deny or be rejected.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  buildFilter, evalExpr, evaluate, indexTuples, validateBundle,
  type Context, type PolicyBundle, type Resource, type Subject, type Tuple,
} from '../src/index.ts';

const load = (f: string) => JSON.parse(readFileSync(new URL(`../../../examples/toy-domain/${f}`, import.meta.url), 'utf8'));
const bundle: PolicyBundle = load('bundle.json');
const world: { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] } = load('world.json');
const graph = indexTuples(world.tuples);
const S = (id: string): Subject => world.subjects.find((x) => x.id === id) as Subject;
const R = (id: string): Resource => world.resources.find((x) => x.id === id) as Resource;
const ctx = (over: Partial<Context> = {}): Context => ({ network: 'trusted', now: world.now, ...over });
const decide = (subject: unknown, action: string, resource: unknown, context: unknown = ctx(), b = bundle, g = graph) =>
  evaluate(b, { subject, action, resource, context } as never, g);
const denied = (d: { decision: boolean }) => assert.equal(d.decision, false);

test('malformed subject or resource fields deny instead of skipping a check', () => {
  const eve = S('eve');
  const extra: Tuple = { object: { type: 'case', id: 'CASE-15' }, relation: 'granted', subject: { type: 'user', id: 'eve' } };
  const g = indexTuples([...world.tuples, extra]);
  denied(decide({ ...eve, clearance: undefined }, 'read', R('CASE-15'), ctx(), bundle, g));
  denied(decide(eve, 'read', { ...R('CASE-15'), level: null }, ctx(), bundle, g));
  denied(decide({ ...S('assistant-1'), integrity: 'Derived', delegator: S('bob') }, 'update', R('CASE-14')));
  denied(decide({ ...S('bob'), active: 'false' }, 'read', R('CASE-14')));
  denied(decide(S('carol'), 'update', R('CASE-11'), ctx({ sessionLevel: Number.NaN as never })));
  denied(decide({ ...S('bob'), compartments: 'ORCHID-X' }, 'read', R('CASE-14')));
  denied(decide(S('bob'), 'read', { ...R('CASE-14'), contentClasses: undefined }));
  assert.deepEqual(decide(S('bob'), 'read', { ...R('CASE-14'), level: null }).rules, ['ENGINE.MALFORMED_REQUEST']);
});

test('validity windows are compared as instants; a bad now or bound is not live', () => {
  const t = (validTo: string): Tuple => ({ object: { type: 'case', id: 'CASE-11' }, relation: 'granted', subject: { type: 'user', id: 'eve' }, validTo });
  denied(decide(S('eve'), 'read', R('CASE-11'), { network: 'trusted' }, bundle, indexTuples([...world.tuples, t('2020-01-01T00:00:00Z')])));
  denied(decide(S('eve'), 'read', R('CASE-11'), ctx({ now: '2026-11-08T00:30:00-05:00' }), bundle, indexTuples([...world.tuples, t('2026-11-08T03:00:00Z')])));
  denied(decide(S('eve'), 'read', R('CASE-11'), ctx(), bundle, indexTuples([...world.tuples, t('expired')])));
});

test('every link of a delegation chain is checked, and an agent needs a delegator', () => {
  const extra: Tuple = { object: { type: 'case', id: 'CASE-14' }, relation: 'delegate', subject: { type: 'agent', id: 'x' } };
  const g = indexTuples([...world.tuples, extra]);
  const chain = { ...S('assistant-1'), id: 'x', delegator: { ...S('carol'), delegator: S('eve') } };
  const d = decide(chain, 'read', R('CASE-14'), ctx(), bundle, g);
  denied(d);
  assert.ok(d.rules.includes('DELEGATION.BLP.NO_READ_UP'));
  denied(decide({ ...S('assistant-1') }, 'read', R('CASE-14')));
});

test('ABAC forbid and CBAC rules run for the delegator too', () => {
  const agent = { ...S('assistant-1'), roles: ['investigator', 'finance_approver'], delegator: S('bob') };
  const d = decide(agent, 'read', R('CASE-14'));
  assert.equal(d.decision, true);
  assert.deepEqual(d.obligations.maskClasses, ['finance.amount']); // bob is not exempt, so the mask stays
});

test('a typo in a bundle is rejected by validation and fails closed in the engine', () => {
  const forbidTypo = { ...bundle, abac: bundle.abac.map((r) => (r.id === 'closed-is-read-only' ? { ...r, effect: 'Forbid' } : r)) } as unknown as PolicyBundle;
  assert.equal(validateBundle(forbidTypo).ok, false);
  denied(decide(S('carol'), 'update', R('CASE-18'), ctx({ sessionLevel: 0 }), forbidTypo));
  const kindTypo = JSON.parse(JSON.stringify(bundle));
  kindTypo.schema.resourceTypes.case.actions.update.kind = 'Write';
  assert.equal(validateBundle(kindTypo).ok, false);
  denied(decide(S('carol'), 'update', R('CASE-11'), ctx(), kindTypo));
  const modeTypo = { ...bundle, needToKnow: { ...bundle.needToKnow, mode: 'Enforce' } } as unknown as PolicyBundle;
  assert.equal(validateBundle(modeTypo).ok, false);
  denied(decide(S('eve'), 'read', R('CASE-11'), ctx(), modeTypo));
  const emptyAnd = { ...bundle, abac: [{ id: 'all', description: 'x', effect: 'permit', when: { op: 'and', args: [] } }] };
  assert.equal(validateBundle(emptyAnd).ok, false);
});

test('SoD and Biba action names must be declared by a resource type', () => {
  const sod = JSON.parse(JSON.stringify(bundle));
  sod.sod[1].conflicting = ['create', 'Release'];
  const sodResult = validateBundle(sod);
  assert.ok(!sodResult.ok && sodResult.errors.includes('sod create-vs-release: conflicting must name declared actions'));

  const biba = JSON.parse(JSON.stringify(bundle));
  biba.mandatory.bibaNoReadDownActions = ['approve', 'Close'];
  const bibaResult = validateBundle(biba);
  assert.ok(!bibaResult.ok && bibaResult.errors.includes('mandatory.bibaNoReadDownActions must list declared actions'));
});

test('validation rejects unknown top-level keys and role-inheritance cycles', () => {
  const extra = validateBundle({ ...bundle, abacRules: [] });
  assert.equal(extra.ok, false);
  assert.ok(!extra.ok && extra.errors.includes('unknown top-level key abacRules'));
  const roles = { ...bundle.rbac.roles, a: { inherits: ['b'], grants: [] }, b: { inherits: ['c'], grants: [] }, c: { inherits: ['a'], grants: [] } };
  const cyclic = validateBundle({ ...bundle, rbac: { roles } });
  assert.equal(cyclic.ok, false);
  assert.ok(!cyclic.ok && cyclic.errors.some((e) => e === 'role inheritance cycle: a -> b -> c -> a'), JSON.stringify(cyclic));
  const self = validateBundle({ ...bundle, rbac: { roles: { ...bundle.rbac.roles, solo: { inherits: ['solo'], grants: [] } } } });
  assert.ok(!self.ok && self.errors.includes('role inheritance cycle: solo -> solo'));
  const badInherits = validateBundle({ ...bundle, rbac: { roles: { ...bundle.rbac.roles, x: { inherits: 'a', grants: [] } } } });
  assert.ok(!badInherits.ok && badInherits.errors.includes('role x: inherits must be a list of roles'));
  assert.equal(validateBundle(bundle).ok, true); // a diamond (shared ancestor) is not a cycle
});

test('validation reports a resource type without actions instead of throwing', () => {
  const malformed = JSON.parse(JSON.stringify(bundle));
  malformed.schema.resourceTypes.case = {};
  const result = validateBundle(malformed);
  assert.ok(!result.ok && result.errors.includes('type case needs actions'));
});

test('two-person rule compares ids as strings', () => {
  const both: Subject = { ...S('grace'), id: '5', roles: ['finance_approver'] };
  denied(decide(both, 'approve', R('PAY-3'), ctx({ makerId: 5 as never })));
});

test('approve and execute are writes: a derived agent cannot approve verified data', () => {
  const agent = { ...S('assistant-1'), roles: ['finance_approver'], clearance: 1, delegator: S('henry') };
  assert.ok(decide(agent, 'approve', R('PAY-3'), ctx({ makerId: 'grace' })).rules.includes('BIBA.NO_WRITE_UP'));
  assert.ok(decide(agent, 'release', R('PAY-3')).rules.includes('BIBA.NO_WRITE_UP'));
});

test('a lowered session level also caps reads', () => {
  assert.ok(decide(S('alice'), 'read', R('CASE-7'), ctx({ sessionLevel: 0 })).rules.includes('BLP.NO_READ_UP'));
});

test('inherited property names are not declared actions', () => {
  const star = { ...bundle, rbac: { roles: { ...bundle.rbac.roles, all: { grants: [{ resourceType: '*', actions: ['*'] }] } } } };
  assert.deepEqual(decide({ ...S('bob'), roles: ['all'] }, 'constructor', R('CASE-14'), ctx(), star).rules, ['SCHEMA.UNKNOWN_ACTION']);
});

test('a break-glass edge anywhere on the path notifies', () => {
  const tuples: Tuple[] = [
    ...world.tuples,
    { object: { type: 'folder', id: 'FOLDER-B' }, relation: 'member', subject: { type: 'user', id: 'eve' } },
    { object: { type: 'case', id: 'CASE-11' }, relation: 'parent', subject: { type: 'folder', id: 'FOLDER-B' }, breakGlass: true, validFrom: '2026-11-08T09:00:00Z', validTo: '2026-11-08T12:00:00Z' },
  ];
  const d = decide(S('eve'), 'read', R('CASE-11'), ctx(), bundle, indexTuples(tuples));
  assert.equal(d.decision, true);
  assert.deepEqual(d.obligations.notify, ['security-officer']);
});

test('a permit cannot be satisfied by a missing attribute (three-valued logic)', () => {
  const b = { ...bundle, abac: [...bundle.abac, {
    id: 'not-suspended', description: 'x', effect: 'permit' as const, resourceTypes: ['case'], actions: ['read'],
    when: { op: 'not' as const, arg: { op: 'eq' as const, left: { path: 'subject.attrs.suspended' }, right: { value: true } } },
  }] };
  denied(decide({ ...S('grace'), roles: [] }, 'read', R('CASE-18'), ctx(), b));
});

test('a forbid over a missing attribute fires (fail closed), in the engine and in the filter', () => {
  const noStatus: Resource = { ...R('CASE-11'), attrs: { title: 'x' } };
  denied(decide(S('carol'), 'update', noStatus, ctx({ sessionLevel: 1 })));
  const residual = buildFilter(bundle, S('carol'), 'case', 'update', ctx({ sessionLevel: 1 }), graph);
  const env = { subject: S('carol'), resource: noStatus, action: { name: 'update', kind: 'write' }, context: ctx({ sessionLevel: 1 }) };
  assert.equal(evalExpr(residual, env), false);
});

test('a diamond-shaped relation graph stays fast', () => {
  const tuples: Tuple[] = [];
  for (let i = 0; i < 30; i++) {
    for (const side of ['a', 'b']) {
      tuples.push({ object: { type: 'team', id: `t${i}` }, relation: 'member', subject: { type: 'team', id: `t${i + 1}${side}` }, subjectRelation: 'member' });
      tuples.push({ object: { type: 'team', id: `t${i + 1}${side}` }, relation: 'member', subject: { type: 'team', id: `t${i + 1}` }, subjectRelation: 'member' });
    }
  }
  tuples.push({ object: { type: 'case', id: 'CASE-11' }, relation: 'member', subject: { type: 'team', id: 't0' }, subjectRelation: 'member' });
  const started = Date.now();
  denied(decide(S('eve'), 'read', R('CASE-11'), ctx(), bundle, indexTuples([...world.tuples, ...tuples])));
  assert.ok(Date.now() - started < 500, 'relation walk must stay linear');
});

test('ids containing separators cannot impersonate another subject', () => {
  const tuples: Tuple[] = [...world.tuples, { object: { type: 'case', id: 'CASE-14' }, relation: 'granted', subject: { type: 'user', id: 'zed:1' } }];
  denied(decide({ ...S('eve'), type: 'user:zed', id: '1', clearance: 3 }, 'read', R('CASE-14'), ctx(), bundle, indexTuples(tuples)));
});

test('simulate keeps subjects and resources of different types apart (found by Codex)', async () => {
  const { simulate } = await import('../src/index.ts');
  const twin: Resource = { ...R('FOLDER-A'), id: 'CASE-14' }; // a folder sharing a case id
  const before = { bundle, subjects: [S('bob')], resources: [R('CASE-14'), twin], tuples: world.tuples };
  const after = { ...before, tuples: world.tuples.filter((t) => !(t.relation === 'allocated' && t.object.id === 'CASE-14')) };
  const impact = simulate(before, after, ctx(), ['read']);
  assert.deepEqual(impact.lost.map((c) => `${c.resourceType}:${c.resource}`), ['case:CASE-14']);
});

test('validation reports a null role instead of throwing (found by Codex)', () => {
  const r = validateBundle({ ...bundle, rbac: { roles: { ...bundle.rbac.roles, ghost: null } } });
  assert.equal(r.ok, false);
});

test('a candidate bundle that loosens the mandatory models is detected (found by Gemini)', async () => {
  const { mandatoryWeakenings } = await import('../src/index.ts');
  assert.deepEqual(mandatoryWeakenings(bundle, bundle), []);
  const loose = JSON.parse(JSON.stringify(bundle));
  loose.needToKnow.mode = 'off';
  loose.mandatory.untrustedNetworkMaxLevel = 3;
  loose.mandatory.trustedRoles.push('viewer');
  loose.schema.resourceTypes.payment.constrained = false;
  loose.schema.resourceTypes.payment.actions.approve.requiresSecondPerson = false;
  loose.sod = [];
  const w = mandatoryWeakenings(bundle, loose);
  for (const s of ['need-to-know mode lowered to off', 'untrusted network max level raised to L3', 'new BLP trusted role viewer',
    'payment is no longer a Clark-Wilson constrained item', 'payment.approve no longer requires a second person',
    'separation-of-duty rule create-vs-approve removed']) assert.ok(w.includes(s), s);
  const tighter = JSON.parse(JSON.stringify(bundle));
  tighter.mandatory.untrustedNetworkMaxLevel = 1;
  assert.deepEqual(mandatoryWeakenings(bundle, tighter), []);
});

// ---------- Kimi review, 2026-11-09 ----------

test('K1: a child below its parent level is rejected, so resource.level is always the effective level', async () => {
  const { levelInheritanceErrors } = await import('../src/index.ts');
  assert.deepEqual(levelInheritanceErrors(world.resources), []);
  const lowered = world.resources.map((r) => r.id === 'CASE-11' ? { ...r, level: 0 as const } : r);
  assert.equal(levelInheritanceErrors(lowered).length, 1);
  const raisedParent = world.resources.map((r) => r.id === 'FOLDER-A' ? { ...r, level: 3 as const } : r);
  assert.equal(levelInheritanceErrors(raisedParent).length, 1);
  const dangling = world.resources.map((r) => r.id === 'FOLDER-A' ? { ...r, id: 'FOLDER-GONE' } : r);
  assert.equal(levelInheritanceErrors(dangling).length, 1);
});

test('K3: changing a relation definition counts as a mandatory weakening', async () => {
  const { mandatoryWeakenings } = await import('../src/index.ts');
  const knows = bundle.schema.resourceTypes.case!.relations!.knows!;
  const withRelations = (rel: typeof knows): PolicyBundle => ({ ...bundle, schema: { ...bundle.schema, resourceTypes: {
    ...bundle.schema.resourceTypes, case: { ...bundle.schema.resourceTypes.case!, relations: { ...bundle.schema.resourceTypes.case!.relations, knows: rel } } } } });
  const deeper = withRelations({ union: knows.union.map((u) => 'viaReports' in u ? { viaReports: { ...u.viaReports, maxDepth: 50 } } : u) });
  assert.ok(mandatoryWeakenings(bundle, deeper).some((w) => w.includes('case.knows')));
  const grantable = withRelations({ union: [...knows.union, { this: true }] });
  assert.ok(mandatoryWeakenings(bundle, grantable).some((w) => w.includes('case.knows')));
  const team = bundle.schema.subjectRelations!.team!;
  const subjectChange: PolicyBundle = { ...bundle, schema: { ...bundle.schema, subjectRelations: { ...bundle.schema.subjectRelations, team: { ...team, member: { union: [{ this: true }, { computed: 'lead' }] } } } } };
  assert.ok(mandatoryWeakenings(bundle, subjectChange).some((w) => w.includes('team.member')));
});
