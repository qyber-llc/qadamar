// Clark-Wilson integrity verification procedures (IVP): validation, engine, filter, weakening, and a differential
// proof that declaring no IVP (empty list), or IVPs every item satisfies, leaves every toy-domain decision unchanged.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  buildFilter, evalExpr, evaluate, indexTuples, mandatoryWeakenings, procedureFingerprint, validateBundle, verifyIntegrity,
  type Context, type IvpDef, type PolicyBundle, type Resource, type Subject, type Tuple,
} from '../src/index.ts';

const load = (f: string) => JSON.parse(readFileSync(new URL(`../../../examples/toy-domain/${f}`, import.meta.url), 'utf8'));
const bundle: PolicyBundle = load('bundle.json');
const world: { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] } = load('world.json');
const graph = indexTuples(world.tuples);
const S = (id: string): Subject => world.subjects.find((x) => x.id === id) as Subject;
const PAY = world.resources.find((x) => x.id === 'PAY-3') as Resource;
const ctx = (over: Partial<Context> = {}): Context => ({ network: 'trusted', now: world.now, ...over });

const AMOUNT: IvpDef = {
  id: 'payment-consistent', description: 'A payment has a positive amount and a known status',
  resourceTypes: ['payment'],
  check: { op: 'and', args: [
    { op: 'gt', left: { path: 'resource.attrs.amount' }, right: { value: 0 } },
    { op: 'in', left: { path: 'resource.attrs.status' }, right: { value: ['pending', 'approved', 'released'] } },
  ] },
};
const withIvps = (ivps: IvpDef[], b = bundle): PolicyBundle => ({ ...b, clarkWilson: { ...b.clarkWilson, ivps } });
const pay = (attrs: Record<string, unknown>): Resource => ({ ...PAY, attrs: { ...PAY.attrs, ...attrs } as Resource['attrs'] });
const approve = (b: PolicyBundle, resource: Resource) =>
  evaluate(b, { subject: S('henry'), action: 'approve', resource, context: ctx({ makerId: 'grace' }) }, graph);

test('validateBundle accepts a resource-only IVP on a constrained type and refuses malformed ones', () => {
  assert.equal(validateBundle(withIvps([AMOUNT])).ok, true);
  const bad = (ivp: unknown): string => {
    const r = validateBundle({ ...bundle, clarkWilson: { ...bundle.clarkWilson, ivps: [ivp] } });
    return r.ok ? '' : r.errors.join('\n');
  };
  assert.match(bad({ ...AMOUNT, resourceTypes: ['case'] }), /constrained types/);
  assert.match(bad({ ...AMOUNT, resourceTypes: [] }), /constrained types/);
  assert.match(bad({ ...AMOUNT, check: { op: 'eq', left: { path: 'subject.id' }, right: { value: 'x' } } }), /resource\.\* paths only/);
  assert.match(bad({ ...AMOUNT, check: { op: 'not', arg: { op: 'has', path: 'context.network' } } }), /resource\.\* paths only/);
  assert.match(bad({ ...AMOUNT, check: { op: 'Eq' } }), /unknown operator/);
  assert.match(bad({ ...AMOUNT, description: '' }), /description/);
  assert.match(bad({ ...AMOUNT, id: 'create-vs-approve' }), /duplicate rule id/);
  assert.match(bad('x'), /must be objects/);
  const notList = validateBundle({ ...bundle, clarkWilson: { ...bundle.clarkWilson, ivps: {} } });
  assert.ok(!notList.ok && notList.errors.some((e) => /must be a list/.test(e)));
});

test('a failing IVP denies the certified command with its rule id; reads and passing IVPs are unaffected', () => {
  const b = withIvps([AMOUNT]);
  assert.equal(approve(b, pay({ amount: 1200 })).decision, true);
  const negative = approve(b, pay({ amount: -5 }));
  assert.equal(negative.decision, false);
  assert.deepEqual(negative.rules, ['CW.IVP.payment-consistent']);
  assert.deepEqual(negative.obligations, { redact: [], maskClasses: [], notify: [] });
  // a missing amount is UNKNOWN, which fails closed
  assert.deepEqual(approve(b, PAY).rules, ['CW.IVP.payment-consistent']);
  const read = evaluate(b, { subject: S('henry'), action: 'read', resource: pay({ amount: -5 }), context: ctx() }, graph);
  assert.equal(read.decision, true);
  assert.deepEqual(verifyIntegrity(b, pay({ amount: -5 })).map((r) => r.ok), [false]);
  assert.deepEqual(verifyIntegrity(b, world.resources.find((r) => r.id === 'CASE-14') as Resource), []);
});

test('the list filter carries the IVP of a certified command, so a kept row is a valid item', () => {
  const b = withIvps([AMOUNT]);
  const residual = buildFilter(b, S('henry'), 'payment', 'approve', ctx({ makerId: 'grace' }), graph);
  const env = (r: Resource) => ({ subject: null, resource: r, action: null, context: null });
  assert.equal(evalExpr(residual, env(pay({ amount: 1200 }))), true);
  assert.equal(evalExpr(residual, env(pay({ amount: -5 }))), false);
  assert.equal(evalExpr(buildFilter(bundle, S('henry'), 'payment', 'approve', ctx(), graph), env(pay({ amount: -5 }))), true);
});

test('removing or editing an IVP is a mandatory weakening; adding one is not', () => {
  const b = withIvps([AMOUNT]);
  assert.deepEqual(mandatoryWeakenings(bundle, b), []);
  assert.deepEqual(mandatoryWeakenings(b, bundle), ['integrity verification payment-consistent removed or changed']);
  assert.deepEqual(mandatoryWeakenings(b, withIvps([{ ...AMOUNT, check: { op: 'true' } }])), ['integrity verification payment-consistent removed or changed']);
});

test('differential: an empty IVP list, and an IVP every item satisfies, give the same decisions as no IVP', () => {
  const holds = withIvps([{ ...AMOUNT, id: 'status-known', check: { op: 'has', path: 'resource.attrs.status' } }]);
  const variants = [withIvps([]), holds];
  const people = [...world.subjects, { ...S('assistant-1'), delegator: S('bob') }];
  const actions = [...new Set(Object.values(bundle.schema.resourceTypes).flatMap((t) => Object.keys(t.actions)))];
  let compared = 0;
  for (const subject of people) for (const resource of world.resources) for (const action of actions) {
    for (const network of ['trusted', 'untrusted'] as const) for (const makerId of [undefined, 'grace', subject.id]) {
      const context = ctx({ network, ...(makerId ? { makerId } : {}), ...(action === 'approve' ? { priorActions: ['create'] } : {}) });
      const base = evaluate(bundle, { subject, action, resource, context }, graph);
      for (const b of variants) {
        const d = evaluate(b, { subject, action, resource, context }, graph);
        // the only difference IVPs make to a permit: its decision token asks the PEP for the post-state
        const { postState, ...token } = d.obligations.decisionToken ?? {};
        assert.equal(postState, b === holds && d.obligations.decisionToken && resource.type === 'payment' ? true : undefined);
        const same = { ...d, obligations: { ...d.obligations, ...(d.obligations.decisionToken ? { decisionToken: token } : {}) }, policyVersion: '' };
        assert.deepEqual(same, { ...base, policyVersion: '' }, `${subject.id} ${action} ${resource.id}`);
        compared++;
      }
    }
  }
  assert.ok(compared > 1000, `${compared} comparisons`);
});

test('requireCertification: a certified action on a listed type needs a certification record (CW.NOT_CERTIFIED)', () => {
  const required: PolicyBundle = { ...bundle, clarkWilson: { ...bundle.clarkWilson, requireCertification: ['payment'] } };
  assert.equal(validateBundle(required).ok, true);
  assert.equal(validateBundle({ ...bundle, clarkWilson: { ...bundle.clarkWilson, requireCertification: ['case'] } }).ok, false, 'only constrained types');
  const run = (b: PolicyBundle, certified?: Context['certified']) =>
    evaluate(b, { subject: S('henry'), action: 'approve', resource: PAY, context: ctx({ makerId: 'grace', ...(certified ? { certified } : {}) }) }, graph);
  assert.equal(run(bundle).decision, true, 'no requirement declared: unchanged');
  const missing = run(required);
  assert.equal(missing.decision, false);
  assert.deepEqual(missing.rules, ['CW.NOT_CERTIFIED']);
  assert.deepEqual(run(required, [{ resourceType: 'payment', action: 'release' }]).rules, ['CW.NOT_CERTIFIED'], 'another procedure\'s record does not count');
  const current = (action: string) => ({ resourceType: 'payment', action, fingerprint: procedureFingerprint(required, 'payment', action) });
  assert.equal(run(required, [current('approve')]).decision, true);
  // a record binds the procedure definition it certified: none, or another one, is stale (recertify)
  assert.deepEqual(run(required, [{ resourceType: 'payment', action: 'approve' }]).rules, ['CW.CERTIFICATION_STALE']);
  assert.deepEqual(run(required, [{ ...current('approve'), fingerprint: 'cw1.other' }]).rules, ['CW.CERTIFICATION_STALE']);
  assert.equal(run(required, [{ ...current('approve'), fingerprint: 'cw1.other' }, current('approve')]).decision, true, 'one current record suffices');
  assert.equal(evaluate(required, { subject: S('henry'), action: 'read', resource: PAY, context: ctx() }, graph).decision, true, 'reads are not procedures');
  const filter = (certified?: Context['certified']) => buildFilter(required, S('henry'), 'payment', 'release', ctx(certified ? { certified } : {}), graph);
  assert.deepEqual(filter(), { op: 'not', arg: { op: 'true' } });
  assert.notDeepEqual(filter([current('release')]), { op: 'not', arg: { op: 'true' } });
  assert.deepEqual(filter([{ resourceType: 'payment', action: 'release' }]), { op: 'not', arg: { op: 'true' } }, 'a stale record opens no list either');
  assert.ok(mandatoryWeakenings(required, bundle).some((w) => /no longer require a certification record/.test(w)));
  const malformed = evaluate(required, { subject: S('henry'), action: 'approve', resource: PAY, context: { ...ctx({ makerId: 'grace' }), certified: 'payment' as never } }, graph);
  assert.deepEqual(malformed.rules, ['ENGINE.MALFORMED_REQUEST']);
});

test('a decision token for a type with IVPs asks the PEP for the post-state', () => {
  assert.equal(approve(bundle, PAY).obligations.decisionToken?.postState, undefined);
  assert.equal(approve(withIvps([AMOUNT]), pay({ amount: 10 })).obligations.decisionToken?.postState, true);
});

test('procedureFingerprint changes with what decides the procedure, and only with that', () => {
  const fp = (b: PolicyBundle, action = 'approve') => procedureFingerprint(b, 'payment', action);
  const base = fp(bundle);
  const cw = bundle.clarkWilson;
  const ivp = { id: 'positive', description: 'positive amount', resourceTypes: ['payment'], check: { op: 'gt' as const, left: { path: 'resource.attrs.amount' }, right: { value: 0 } } };
  const types = bundle.schema.resourceTypes;
  const payment = types.payment!;
  const changed: PolicyBundle[] = [
    { ...bundle, clarkWilson: { ...cw, ivps: [ivp] } },
    { ...bundle, clarkWilson: { ...cw, inputValidators: [{ id: 'v', description: 'v', resourceTypes: ['payment'], actions: ['approve'], fields: {} }] } },
    { ...bundle, clarkWilson: { ...cw, requirePepBinding: ['payment'] } },
    { ...bundle, schema: { ...bundle.schema, resourceTypes: { ...types, payment: { ...payment, actions: { ...payment.actions, approve: { ...payment.actions.approve!, requiresSecondPerson: false } } } } } },
    { ...bundle, rbac: { roles: { ...bundle.rbac.roles, auditor2: { grants: [{ resourceType: 'payment', actions: ['approve'] }] } } } },
    { ...bundle, sod: bundle.sod.filter((r) => !r.conflicting.includes('approve')) },
    { ...bundle, abac: [...bundle.abac, { id: 'f', description: 'f', effect: 'forbid', resourceTypes: ['payment'], actions: ['approve'], when: { op: 'true' } }] },
  ];
  for (const [i, b] of changed.entries()) assert.notEqual(fp(b), base, `change ${i}`);
  const unrelated: PolicyBundle[] = [
    { ...bundle, rbac: { roles: { ...bundle.rbac.roles, reader2: { grants: [{ resourceType: 'case', actions: ['read'] }] } } } },
    { ...bundle, abac: [...bundle.abac, { id: 'g', description: 'g', effect: 'forbid', resourceTypes: ['case'], actions: ['read'], when: { op: 'true' } }] },
    { ...bundle, clarkWilson: { ...cw, tokenTtlSeconds: cw.tokenTtlSeconds + 1 } },
  ];
  for (const [i, b] of unrelated.entries()) assert.equal(fp(b), base, `unrelated ${i}`);
  assert.notEqual(fp(bundle, 'release'), base, 'per procedure');
  // need-to-know on the type: the protecting relation's rewrites (any type) and the break-glass window decide it too
  const protectedB: PolicyBundle = { ...bundle, needToKnow: { ...bundle.needToKnow, protect: { ...bundle.needToKnow.protect, payment: { relation: 'viewer' } } } };
  const nk = fp(protectedB);
  assert.notEqual(nk, base);
  assert.notEqual(fp({ ...protectedB, needToKnow: { ...protectedB.needToKnow, breakGlassMaxHours: protectedB.needToKnow.breakGlassMaxHours + 1 } }), nk, 'break-glass window');
  const other = Object.keys(types).find((t) => t !== 'payment')!;
  assert.notEqual(fp({ ...protectedB, schema: { ...bundle.schema, resourceTypes: { ...types, [other]: { ...types[other]!, relations: { ...types[other]!.relations, extra: { union: [{ this: true }] } } } } } }), nk, 'another type\'s relation');
});
