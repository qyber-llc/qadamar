import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  buildFilter, cidrParts, contextChecks, contextRuleApplies, evalExpr, evaluate, indexTuples, inTimeWindow, ipInRange, rangesOf, requestErrors, validateBundle, validIp,
  type Context, type ContextRule, type PolicyBundle, type Request, type Resource, type Subject, type Tuple,
} from '../src/index.ts';

const load = (f: string) => JSON.parse(readFileSync(new URL(`../../../examples/toy-domain/${f}`, import.meta.url), 'utf8'));
const toy: PolicyBundle = load('bundle.json');
const world: { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] } = load('world.json');
const graph = indexTuples(world.tuples);
const bob = world.subjects.find((s) => s.id === 'bob') as Subject;
const agent = { ...world.subjects.find((s) => s.id === 'assistant-1') as Subject, delegator: bob };
const resource = (id: string): Resource => world.resources.find((r) => r.id === id) as Resource;
const ago = (seconds: number): string => new Date(Date.parse(world.now) - seconds * 1000).toISOString();
const good: Context = {
  network: 'trusted', now: world.now, ip: '10.1.2.3', country: 'AE', device: { managed: true, compliant: true },
  authTime: ago(60), mfaTime: ago(30), authMethods: ['pwd', 'webauthn'], riskScore: 0,
};
const policy = (rule: ContextRule): PolicyBundle => ({ ...toy, context: [rule] });
const decide = (rule: ContextRule, context: Context = good, subject = bob, item = resource('CASE-14')) =>
  evaluate(policy(rule), { subject, action: 'read', resource: item, context }, graph);

test('every CBAC requirement passes only on its asserted value and traces rule, requirement and observation', () => {
  const cases: Array<[ContextRule, Context, string]> = [
    [{ id: 'network', actions: ['read'], network: 'trusted' }, { ...good, network: 'untrusted' }, 'CBAC.NETWORK'],
    [{ id: 'country', actions: ['read'], countries: ['AE', 'US'] }, { ...good, country: 'FR' }, 'CBAC.COUNTRY'],
    [{ id: 'ip', actions: ['read'], ipRanges: ['10.0.0.0/8', '2001:db8::/32'] }, { ...good, ip: '192.0.2.1' }, 'CBAC.IP_RANGE'],
    [{ id: 'time', actions: ['read'], timeWindows: [{ days: [7], from: '09:00', to: '17:00', timeZone: 'Asia/Dubai' }] }, { ...good, now: '2026-11-08T18:00:00Z' }, 'CBAC.TIME_WINDOW'],
    [{ id: 'managed', actions: ['read'], device: { managed: true } }, { ...good, device: { managed: false, compliant: true } }, 'CBAC.DEVICE_UNMANAGED'],
    [{ id: 'compliant', actions: ['read'], device: { compliant: true } }, { ...good, device: { managed: true, compliant: false } }, 'CBAC.DEVICE_NONCOMPLIANT'],
    [{ id: 'mfa', actions: ['read'], mfaMaxAgeSeconds: 60 }, { ...good, mfaTime: ago(61) }, 'CBAC.MFA_STALE'],
    [{ id: 'auth', actions: ['read'], authMaxAgeSeconds: 60 }, { ...good, authTime: ago(61) }, 'CBAC.AUTH_STALE'],
    [{ id: 'method', actions: ['read'], authMethodsAny: ['webauthn', 'otp'] }, { ...good, authMethods: ['pwd'] }, 'CBAC.AUTH_METHOD'],
    [{ id: 'risk', actions: ['read'], maxRiskScore: 50 }, { ...good, riskScore: 51 }, 'CBAC.RISK'],
  ];
  for (const [rule, context, code] of cases) {
    const denied = decide(rule, context);
    assert.equal(denied.decision, false, rule.id);
    assert.ok(denied.rules.includes(code), `${rule.id}: ${denied.rules.join(',')}`);
    const step = denied.trace.find((t) => t.stage === 'cbac' && t.outcome === 'deny');
    assert.equal(step?.policyRule, rule.id);
    assert.ok(step?.requirement);
    assert.ok(Object.hasOwn(step ?? {}, 'observed'));
    assert.equal(decide(rule).decision, true, `${rule.id} accepts its good context`);
  }
});

test('a missing required signal is UNKNOWN and denies, independently for every signal', () => {
  const cases: Array<[ContextRule, keyof Context]> = [
    [{ id: 'country', actions: ['read'], countries: ['AE'] }, 'country'],
    [{ id: 'ip', actions: ['read'], ipRanges: ['10.0.0.0/8'] }, 'ip'],
    [{ id: 'managed', actions: ['read'], device: { managed: true } }, 'device'],
    [{ id: 'compliant', actions: ['read'], device: { compliant: true } }, 'device'],
    [{ id: 'mfa', actions: ['read'], mfaMaxAgeSeconds: 60 }, 'mfaTime'],
    [{ id: 'auth', actions: ['read'], authMaxAgeSeconds: 60 }, 'authTime'],
    [{ id: 'method', actions: ['read'], authMethodsAny: ['pwd'] }, 'authMethods'],
    [{ id: 'risk', actions: ['read'], maxRiskScore: 100 }, 'riskScore'],
  ];
  for (const [rule, field] of cases) {
    const context = { ...good, [field]: undefined };
    const denied = decide(rule, context);
    assert.equal(denied.decision, false, rule.id);
    assert.ok(denied.rules.includes('CBAC.SIGNAL_MISSING'), rule.id);
    const step = denied.trace.find((t) => t.stage === 'cbac' && t.outcome === 'deny');
    assert.equal(step?.observed, null);
  }
});

test('authentication ages include the exact limit, reject the next second and never trust a future timestamp', () => {
  for (const [field, requirement, code] of [['mfaTime', 'mfaMaxAgeSeconds', 'CBAC.MFA_STALE'], ['authTime', 'authMaxAgeSeconds', 'CBAC.AUTH_STALE']] as const) {
    const rule = { id: field, actions: ['read'], [requirement]: 60 } as ContextRule;
    assert.equal(decide(rule, { ...good, [field]: ago(60) }).decision, true);
    assert.ok(decide(rule, { ...good, [field]: ago(61) }).rules.includes(code));
    assert.ok(decide(rule, { ...good, [field]: ago(-1) }).rules.includes(code));
  }
});

test('risk boundaries 0 and 100 are enforced without coercion', () => {
  assert.equal(decide({ id: 'zero', actions: ['read'], maxRiskScore: 0 }, { ...good, riskScore: 0 }).decision, true);
  assert.equal(decide({ id: 'zero', actions: ['read'], maxRiskScore: 0 }, { ...good, riskScore: 1 }).decision, false);
  assert.equal(decide({ id: 'hundred', actions: ['read'], maxRiskScore: 100 }, { ...good, riskScore: 100 }).decision, true);
});

test('CIDR checks include both boundary addresses and support IPv6', () => {
  for (const [ip, range, expected] of [
    ['10.0.0.0', '10.0.0.0/31', true], ['10.0.0.1', '10.0.0.0/31', true], ['10.0.0.2', '10.0.0.0/31', false],
    ['192.0.2.1', '192.0.2.1/32', true], ['192.0.2.2', '192.0.2.1/32', false],
    ['2001:db8::', '2001:db8::/126', true], ['2001:db8::3', '2001:db8::/126', true], ['2001:db8::4', '2001:db8::/126', false],
    ['::1', '::1/128', true], ['::2', '::1/128', false], ['2001:db8::1', '10.0.0.0/8', false],
  ] as const) assert.equal(ipInRange(ip, range), expected, `${ip} in ${range}`);
});

test('local windows have start-inclusive/end-exclusive edges, overnight days, time zones and DST', () => {
  const window = { days: [7], from: '09:00', to: '17:00', timeZone: 'Asia/Dubai' };
  assert.equal(inTimeWindow('2026-11-08T04:59:59Z', window), false);
  assert.equal(inTimeWindow('2026-11-08T05:00:00Z', window), true);
  assert.equal(inTimeWindow('2026-11-08T12:59:59Z', window), true);
  assert.equal(inTimeWindow('2026-11-08T13:00:00Z', window), false);
  const overnight = { days: [1], from: '22:00', to: '02:00', timeZone: 'Asia/Dubai' };
  assert.equal(inTimeWindow('2026-11-09T18:30:00Z', overnight), true, 'Monday 22:30');
  assert.equal(inTimeWindow('2026-11-09T21:30:00Z', overnight), true, 'Tuesday 01:30 Dubai belongs to Monday night');
  assert.equal(inTimeWindow('2026-11-10T01:30:00Z', overnight), false, 'Tuesday night is not selected');
  const dst = { days: [7], from: '01:30', to: '03:30', timeZone: 'America/New_York' };
  assert.equal(inTimeWindow('2026-03-08T06:30:00Z', dst), true, '01:30 EST');
  assert.equal(inTimeWindow('2026-03-08T07:29:59Z', dst), true, '03:29 EDT after the skipped hour');
  assert.equal(inTimeWindow('2026-03-08T07:30:00Z', dst), false, '03:30 EDT');
});

test('selectors cover action kind, resource level and sensitive content classes', () => {
  const req: Request = { subject: bob, action: 'read', resource: resource('CASE-14'), context: good };
  const rule: ContextRule = { id: 'sensitive', actionKinds: ['read'], resourceTypes: ['case'], minResourceLevel: 2, contentClasses: ['finance.amount'], maxRiskScore: 10 };
  assert.equal(contextRuleApplies(rule, req, 'read'), true);
  assert.equal(contextRuleApplies(rule, { ...req, action: 'update' }, 'write'), false);
  assert.equal(contextRuleApplies(rule, { ...req, resource: resource('CASE-11') }, 'read'), false);
  assert.equal(decide(rule, { ...good, riskScore: 11 }).decision, false);
  assert.equal(decide(rule, { ...good, riskScore: 11 }, bob, resource('CASE-11')).decision, true);
});

test('point decisions and list filters agree for changed context, with no decision cache reuse', () => {
  const rule: ContextRule = { id: 'risk', resourceTypes: ['case'], actionKinds: ['read'], minResourceLevel: 1, maxRiskScore: 50 };
  const bundle = policy(rule);
  for (const riskScore of [0, 50, 51, 100]) {
    const context = { ...good, riskScore };
    const residual = buildFilter(bundle, bob, 'case', 'read', context, graph);
    for (const item of world.resources.filter((r) => r.type === 'case')) {
      const point = evaluate(bundle, { subject: bob, action: 'read', resource: item, context }, graph).decision;
      const kept = evalExpr(residual, { subject: bob, resource: item, action: { name: 'read', kind: 'read' }, context });
      assert.equal(kept, point, `${item.id} risk ${riskScore}`);
    }
  }
  assert.equal(decide(rule, { ...good, riskScore: 0 }).decision, true);
  assert.equal(decide(rule, { ...good, riskScore: 100 }).decision, false);
});

test('CBAC is request-wide for an AI agent and every delegation link keeps its existing checks', () => {
  const denied = decide({ id: 'mfa', actions: ['read'], mfaMaxAgeSeconds: 60 }, { ...good, mfaTime: ago(61) }, agent);
  assert.equal(denied.decision, false);
  assert.ok(denied.rules.includes('CBAC.MFA_STALE'));
  assert.equal(denied.trace.filter((step) => step.stage === 'cbac').length, 1);
});

test('strict request validation rejects malformed or oversized context signals', () => {
  const invalid: unknown[] = [
    { ip: '999.1.1.1' }, { ip: '2001:db8::1/128' }, { country: 'ae' }, { country: 'ZZ' },
    { device: { managed: true } }, { device: { managed: true, compliant: true, extra: 1 } },
    { authTime: 'yesterday' }, { authTime: '2026-02-30T10:00:00Z' }, { mfaTime: '2026-11-08 10:00:00Z' },
    { authMethods: Array(17).fill('pwd') }, { authMethods: ['x'.repeat(33)] }, { authMethods: [1] },
    { riskScore: -1 }, { riskScore: 101 }, { riskScore: 1.5 }, { riskScore: '0' },
  ];
  for (const signals of invalid) {
    const req: Request = { subject: bob, action: 'read', resource: resource('CASE-14'), context: { ...good, ...(signals as Partial<Context>) } };
    assert.ok(requestErrors(req).length > 0, JSON.stringify(signals));
    assert.equal(evaluate(toy, req, graph).decision, false);
  }
});

test('bundle validation accepts complete context rules and fails closed on malformed policy', () => {
  const rule: ContextRule = { id: 'all', description: 'all signals', resourceTypes: ['case'], actionKinds: ['read'], minResourceLevel: 2,
    contentClasses: ['finance.amount'], network: 'trusted', countries: ['AE'], ipRanges: ['10.0.0.0/8', '2001:db8::/32'],
    timeWindows: [{ days: [1, 7], from: '22:00', to: '02:00', timeZone: 'Asia/Dubai' }], device: { managed: true, compliant: true },
    mfaMaxAgeSeconds: 300, authMaxAgeSeconds: 3600, authMethodsAny: ['webauthn'], maxRiskScore: 100 };
  assert.equal(validateBundle(policy(rule)).ok, true);
  const bad: unknown[] = [
    { id: 'empty', actions: ['read'] }, { id: 'global', maxRiskScore: 50 },
    { id: 'bad-cidr', actions: ['read'], ipRanges: ['10.0.0.0/33'] },
    { id: 'bad-zone', actions: ['read'], timeWindows: [{ days: [1], from: '09:00', to: '10:00', timeZone: 'Mars/Olympus' }] },
    { id: 'same-time', actions: ['read'], timeWindows: [{ days: [1], from: '09:00', to: '09:00', timeZone: 'Asia/Dubai' }] },
    { id: 'bad-risk', actions: ['read'], maxRiskScore: 101 }, { id: 'bad-key', actions: ['read'], maxRiskScore: 1, unknown: true },
  ];
  for (const value of bad) assert.equal(validateBundle({ ...toy, context: [value] }).ok, false, JSON.stringify(value));
  assert.ok(decide({ id: 'empty', actions: ['read'] }).rules.includes('ENGINE.RULE_ERROR'));
});

test('IPv6 zone ids are refused in signals and ranges', () => {
  assert.equal(validIp('fe80::1%eth0'), false);
  assert.equal(validIp('fe80::1'), true);
  assert.equal(cidrParts('fe80::%1/64'), undefined);
  assert.equal(validateBundle({ ...toy, context: [{ id: 'zone', actions: ['read'], ipRanges: ['fe80::%eth0/64'] }] }).ok, false);
});

test('a decision builds no BlockList or time-zone formatter per rule: both are cached', () => {
  const rule = { id: 'r', actions: ['read'], ipRanges: ['10.0.0.0/8', '2001:db8::/32'], timeWindows: [{ days: [1, 2, 3, 4, 5, 6, 7], from: '00:00', to: '23:59', timeZone: 'Asia/Dubai' }] };
  assert.equal(rangesOf(rule), rangesOf(rule), 'one BlockList per rule');
  const Original = Intl.DateTimeFormat;
  let built = 0;
  Intl.DateTimeFormat = function (...args: ConstructorParameters<typeof Original>) { built++; return new Original(...args); } as unknown as typeof Original;
  try {
    for (let i = 0; i < 20; i++) contextChecks(rule, { network: 'trusted', now: '2026-11-08T10:00:00Z', ip: '10.1.2.3' });
  } finally { Intl.DateTimeFormat = Original; }
  assert.ok(built <= 1, `${built} formatters for 20 decisions`);
});

test('the bundle caps ranges and windows in total (4096 each), not only per rule', () => {
  const ranges = Array.from({ length: 100 }, (_, i) => `10.${i}.0.0/16`);
  const many = (n: number) => Array.from({ length: n }, (_, i) => ({ id: `r${i}`, actions: ['read'], ipRanges: ranges }));
  assert.equal(validateBundle({ ...toy, context: many(40) }).ok, true);
  const refused = validateBundle({ ...toy, context: many(41) });
  assert.ok(!refused.ok && refused.errors.some((e) => /4096/.test(e)));
  const windows = Array.from({ length: 100 }, () => ({ days: [1], from: '09:00', to: '10:00', timeZone: 'Asia/Dubai' }));
  assert.equal(validateBundle({ ...toy, context: Array.from({ length: 41 }, (_, i) => ({ id: `w${i}`, actions: ['read'], timeWindows: windows })) }).ok, false);
});
