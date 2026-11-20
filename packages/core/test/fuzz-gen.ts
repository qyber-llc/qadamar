// Seeded generators of toy-domain requests (valid, odd and malformed), shared by the fuzz and the Lean differential
// tests. Not a test file itself: node --test runs only *.test.ts.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  MAX_DELEGATION_DEPTH, indexTuples,
  type AbacRule, type Context, type ContextRule, type Expr, type Integrity, type Json, type Level, type PolicyBundle, type Request, type Resource, type Subject, type Tuple,
} from '../src/index.ts';

export const load = (f: string) => JSON.parse(readFileSync(new URL(`../../../examples/toy-domain/${f}`, import.meta.url), 'utf8'));
export const toy: PolicyBundle = load('bundle.json');
// Rules over tenant attributes the generator fills with values of every JSON type, so a mistyped operand is exercised
// on each operator family (ordering, contains, subset, in) for permits and forbids alike.
export const attrRule = (id: string, effect: 'permit' | 'forbid', action: string, when: Expr): AbacRule => ({ id, description: id, effect, resourceTypes: ['case'], actions: [action], when });
export const bundle: PolicyBundle = { ...toy, abac: [...toy.abac,
  attrRule('fuzz-big-amount', 'forbid', 'update', { op: 'ge', left: { path: 'resource.attrs.amount' }, right: { value: 10000 } }),
  attrRule('fuzz-low-priority', 'permit', 'read', { op: 'lt', left: { path: 'resource.attrs.priority' }, right: { value: 3 } }),
  attrRule('fuzz-secret-tag', 'forbid', 'export', { op: 'contains', left: { path: 'resource.attrs.tags' }, right: { value: 'secret' } }),
  attrRule('fuzz-known-tags', 'permit', 'update', { op: 'subset', left: { path: 'resource.attrs.tags' }, right: { value: ['a', 'b'] } }),
  attrRule('fuzz-north', 'forbid', 'close', { op: 'in', left: { value: 'north' }, right: { path: 'resource.attrs.regions' } }),
] };
export const MISTYPED: readonly Json[] = [50000, 5, 2, '50000', '5', 'secret', 'north', '', [5], ['secret'], ['a'], ['north'], [], {}, { v: 1 }, true, false, null];
export const world: { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] } = load('world.json');
export const graph = indexTuples(world.tuples);
export const S = (id: string): Subject => world.subjects.find((x) => x.id === id) as Subject;
export const R = (id: string): Resource => world.resources.find((x) => x.id === id) as Resource;
export const ctx = (over: Partial<Context> = {}): Context => ({ network: 'trusted', now: world.now, ...over });

export type Rng = () => number;
export const INTEGRITIES: readonly Integrity[] = ['derived', 'extracted', 'system', 'verified'];
export const ODD_STRINGS = ['\u0000', '\ud800', '\udfff', 'unknown', 'case:odd#id', '__proto__', 'constructor', '  ', '❄️'];
export const ALL_ACTIONS = Object.values(bundle.schema.resourceTypes).flatMap((type) => Object.keys(type.actions));
export const ALL_ROLES = Object.keys(bundle.rbac.roles);
export const UNTRUSTED_ROLES = ALL_ROLES.filter((role) => !bundle.mandatory.trustedRoles.includes(role));
export const MANDATORY_RULES = new Set([
  'BLP.NO_READ_UP', 'MAC.COMPARTMENT', 'NET.UNTRUSTED_LEVEL', 'NET.UNTRUSTED_COMPARTMENT',
  'BLP.NO_WRITE_DOWN', 'BLP.HIGH_WATER', 'BLP.SESSION_REQUIRED', 'BIBA.NO_WRITE_UP', 'BIBA.NO_READ_DOWN',
]);

export function prng(seed: number): Rng {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 0x100000000;
  };
}

export const integer = (rng: Rng, max: number): number => Math.floor(rng() * max);
export const pick = <T>(rng: Rng, values: readonly T[]): T => values[integer(rng, values.length)] as T;
export const chance = (rng: Rng, probability: number): boolean => rng() < probability;
export const odd = (rng: Rng): string => pick(rng, ODD_STRINGS);
export const level = (rng: Rng): Level => integer(rng, 4) as Level;
export const randomBibaNoReadDownScope = (rng: Rng): 'actions' | 'reads' | 'all' => pick(rng, ['actions', 'reads', 'all'] as const);
export const strings = (rng: Rng, values: readonly string[]): string[] =>
  Array.from({ length: integer(rng, 4) }, () => pick(rng, values));

// role-assignment windows around the toy clock (2026-11-08T10:00:00Z) and the other instants randomContext uses
const WINDOWS = [{ notAfter: '2026-11-08T09:00:00Z' }, { notBefore: '2026-11-08T11:00:00Z' }, { notBefore: '2026-11-08T10:00:00Z' },
  { notAfter: '2026-11-08T10:00:00Z' }, { notBefore: '2026-11-01T00:00:00Z', notAfter: '2026-12-01T00:00:00Z' }, {}];

export function randomSubject(rng: Rng, depth = 0): Subject {
  const base = pick(rng, world.subjects);
  let subject: Subject = {
    ...base,
    type: chance(rng, 0.15) ? pick(rng, ['user', 'service', 'external', 'agent', odd(rng)]) : base.type,
    id: chance(rng, 0.3) ? odd(rng) : base.id,
    active: chance(rng, 0.15) ? false : true,
    roles: strings(rng, [...ALL_ROLES, 'unknown-role', odd(rng)]),
    clearance: level(rng),
    compartments: strings(rng, [...bundle.schema.compartments, 'UNKNOWN', odd(rng)]),
    integrity: pick(rng, INTEGRITIES),
    attrs: { ...base.attrs, fuzz: odd(rng) },
    ...(chance(rng, 0.3) ? { roleAssignments: Array.from({ length: 1 + integer(rng, 2) }, () => ({ role: pick(rng, [...ALL_ROLES, 'unknown-role']), ...pick(rng, WINDOWS) })) } : {}),
  };
  if (depth >= 2 && subject.type === 'agent') subject = { ...subject, type: 'user' };
  if (depth < 2 && (subject.type === 'agent' || chance(rng, 0.15))) {
    subject = { ...subject, delegator: randomSubject(rng, depth + 1) };
  }
  return subject;
}

export function randomResource(rng: Rng): Resource {
  const base = pick(rng, world.resources);
  return {
    ...base,
    type: chance(rng, 0.15) ? pick(rng, [...Object.keys(bundle.schema.resourceTypes), odd(rng)]) : base.type,
    id: chance(rng, 0.35) ? odd(rng) : base.id,
    level: level(rng),
    compartments: strings(rng, [...bundle.schema.compartments, 'UNKNOWN', odd(rng)]),
    integrity: pick(rng, INTEGRITIES),
    owner: chance(rng, 0.5) ? odd(rng) : base.owner,
    version: integer(rng, 100),
    contentClasses: strings(rng, ['pii.iban', 'finance.amount', 'unknown.class', odd(rng)]),
    attrs: {
      ...base.attrs,
      status: pick(rng, ['open', 'closed', 'pending', odd(rng), ...MISTYPED]),
      ...Object.fromEntries(['amount', 'priority', 'tags', 'regions'].filter(() => chance(rng, 0.7)).map((k) => [k, pick(rng, MISTYPED)])),
    },
  };
}

export function randomContext(rng: Rng): Context {
  return ctx({
    network: chance(rng, 0.5) ? 'trusted' : 'untrusted',
    now: pick(rng, [world.now, '2026-11-08T00:30:00-05:00', '2027-01-01T00:00:00Z']),
    ...(chance(rng, 0.7) ? { sessionLevel: level(rng) } : {}),
    ...(chance(rng, 0.5) ? { makerId: pick(rng, ['grace', 'henry', odd(rng)]) } : {}),
    ...(chance(rng, 0.6) ? { priorActions: strings(rng, [...ALL_ACTIONS, odd(rng)]) } : {}),
    ...(chance(rng, 0.7) ? { ip: pick(rng, ['10.0.0.1', '192.0.2.1', '2001:db8::1', '::1']) } : {}),
    ...(chance(rng, 0.7) ? { country: pick(rng, ['AE', 'US', 'FR']) } : {}),
    ...(chance(rng, 0.7) ? { device: { managed: chance(rng, 0.5), compliant: chance(rng, 0.5) } } : {}),
    ...(chance(rng, 0.7) ? { authTime: pick(rng, [world.now, '2026-11-08T09:00:00Z', '2026-11-08T05:30:00Z']) } : {}),
    ...(chance(rng, 0.7) ? { mfaTime: pick(rng, [world.now, '2026-11-08T09:00:00Z', '2026-11-08T05:30:00Z']) } : {}),
    ...(chance(rng, 0.7) ? { authMethods: strings(rng, ['pwd', 'otp', 'webauthn']) } : {}),
    ...(chance(rng, 0.7) ? { riskScore: integer(rng, 101) } : {}),
  });
}

export function randomContextRules(rng: Rng): ContextRule[] {
  return Array.from({ length: integer(rng, 4) }, (_, id): ContextRule => {
    const selector = chance(rng, 0.5) ? { actions: [pick(rng, ALL_ACTIONS)] } : { actionKinds: [pick(rng, ['read', 'write', 'delete', 'approve', 'execute'] as const)] } as const;
    const requirements = pick(rng, [
      { network: 'trusted' }, { countries: ['AE', 'US'] }, { ipRanges: ['10.0.0.0/8', '2001:db8::/32'] },
      { device: { managed: true, compliant: true } }, { mfaMaxAgeSeconds: 3600 }, { authMaxAgeSeconds: 7200 },
      { authMethodsAny: ['otp', 'webauthn'] }, { maxRiskScore: 50 },
      { timeWindows: [{ days: [1, 2, 3, 4, 5, 6, 7], from: '00:00', to: '23:59', timeZone: 'Asia/Dubai' }] },
    ] as const);
    return { id: `fuzz-context-${id}`, ...selector, ...requirements };
  });
}

export function randomRequest(rng: Rng): Request {
  const resource = randomResource(rng);
  const declared = Object.keys(bundle.schema.resourceTypes[resource.type]?.actions ?? {});
  const action = declared.length > 0 && chance(rng, 0.8)
    ? pick(rng, declared)
    : pick(rng, [...ALL_ACTIONS, 'shred', odd(rng)]);
  return { subject: randomSubject(rng), action, resource, context: randomContext(rng) };
}


export const validRequest = (): Request => ({ subject: S('bob'), action: 'read', resource: R('CASE-14'), context: ctx() });
export const invalidLevel = (rng: Rng): unknown => pick(rng, [-1, 4, 1.5, Number.NaN, null, undefined, '3']);
export const malformed: readonly ((rng: Rng) => unknown)[] = [
  () => null,
  () => undefined,
  () => 'not an object',
  () => [],
  () => ({}),
  () => ({ ...validRequest(), subject: null }),
  () => ({ ...validRequest(), resource: null }),
  () => ({ ...validRequest(), context: null }),
  (rng) => ({ ...validRequest(), action: pick(rng, ['', 5, null]) }),
  (rng) => ({ ...validRequest(), action: `${odd(rng)}${'x'.repeat(256)}` }),
  (rng) => ({ ...validRequest(), subject: { ...S('bob'), id: pick(rng, ['', 'x'.repeat(257), 5, null]) } }),
  () => ({ ...validRequest(), subject: { ...S('bob'), type: 'x'.repeat(257) } }),
  () => ({ ...validRequest(), subject: { ...S('bob'), active: 'false' } }),
  (rng) => ({ ...validRequest(), subject: { ...S('bob'), roles: pick(rng, ['investigator', [1], null]) } }),
  (rng) => ({ ...validRequest(), subject: { ...S('bob'), clearance: invalidLevel(rng) } }),
  () => ({ ...validRequest(), subject: { ...S('bob'), compartments: 'ORCHID' } }),
  () => ({ ...validRequest(), subject: { ...S('bob'), integrity: 'Verified' } }),
  () => ({ ...validRequest(), subject: { ...S('assistant-1'), delegator: undefined } }),
  () => {
    let subject = S('bob');
    for (let i = 0; i <= MAX_DELEGATION_DEPTH; i++) subject = { ...S('assistant-1'), id: `agent-${i}`, delegator: subject };
    return { ...validRequest(), subject };
  },
  (rng) => ({ ...validRequest(), resource: { ...R('CASE-14'), id: pick(rng, ['', 'x'.repeat(257), null]) } }),
  (rng) => ({ ...validRequest(), resource: { ...R('CASE-14'), level: invalidLevel(rng) } }),
  () => ({ ...validRequest(), resource: { ...R('CASE-14'), compartments: [null] } }),
  () => ({ ...validRequest(), resource: { ...R('CASE-14'), integrity: 'Derived' } }),
  (rng) => ({ ...validRequest(), resource: { ...R('CASE-14'), contentClasses: pick(rng, [undefined, 'pii.iban', [null]]) } }),
  (rng) => ({ ...validRequest(), resource: { ...R('CASE-14'), version: pick(rng, [1.5, Number.NaN, '4']) } }),
  (rng) => ({ ...validRequest(), context: { ...ctx(), network: odd(rng) } }),
  (rng) => ({ ...validRequest(), context: { ...ctx(), now: pick(rng, ['not-a-date', odd(rng), null]) } }),
  (rng) => ({ ...validRequest(), context: { ...ctx(), sessionLevel: pick(rng, [-1, 4, 1.5, Number.NaN, null, '3']) } }),
  (rng) => ({ ...validRequest(), context: { ...ctx(), makerId: pick(rng, ['', 5, null]) } }),
  (rng) => ({ ...validRequest(), context: { ...ctx(), priorActions: pick(rng, ['create', [null], {}]) } }),
  (rng) => ({ ...validRequest(), subject: { ...S('bob'), roleAssignments: pick(rng, [[{ role: 'viewer', notAfter: 'tomorrow' }], 'viewer',
    [{ role: 'viewer', notBefore: '2026-12-01T00:00:00Z', notAfter: '2026-11-01T00:00:00Z' }], [{ role: '', notAfter: '2026-12-01T00:00:00Z' }], [{ role: 'viewer', until: 'x' }]]) } }),
  (rng) => ({ ...validRequest(), context: { ...ctx(), ...pick(rng, [{ ip: 'fe80::1%eth0' }, { country: 'XX' }, { riskScore: 101 }, { device: { managed: true } }, { authMethods: [''] }, { sessionExpired: 1 }]) } }),
];

export const envInteger = (name: string, fallback: number, max: number): number => {
  const value = process.env[name];
  if (value === undefined) return fallback;
  const parsed = Number(value);
  assert.ok(Number.isInteger(parsed) && parsed >= 0 && parsed <= max, `${name} must be an integer 0..${max}`);
  return parsed;
};
