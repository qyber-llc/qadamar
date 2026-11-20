// Differential test of the TypeScript engine against the executable Lean 4 model of formal/ (docs/spec/FORMAL-MODEL.md):
// random bundles and requests from the fuzz generators, each decided by `evaluate` and by `lake exe gate-model`, must
// agree on the decision, the rule ids, the obligations and the dry-run would-denies. What the model abstracts (the ReBAC
// relation check, the certification fingerprint, role-assignment windows, the CIDR / time-window / authentication-age
// requirements of CBAC rules and the grammar of the context signals) is computed here by TypeScript and handed to it.
// Skips when no Lean toolchain is found, unless LEAN_REQUIRED=1 (CI).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomInt } from 'node:crypto';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import {
  certificationGap, check, contextChecks, evaluate, indexTuples, principals, procedureFingerprint, requestErrors, windowState,
  type AbacContentRule, type AbacRule, type ContextRule, type Decision, type Expr, type Json, type Operand, type PolicyBundle, type Request, type Tuple,
} from '../src/index.ts';
import {
  ALL_ACTIONS, MISTYPED, chance, envInteger, graph, integer, level, malformed, odd, pick, prng, randomBibaNoReadDownScope, randomRequest, toy, world, type Rng,
} from './fuzz-gen.ts';

const FORMAL = fileURLToPath(new URL('../../../formal/', import.meta.url));
const REQUIRED = process.env.LEAN_REQUIRED === '1';

function findLake(): string | undefined {
  const dirs = [...(process.env.PATH ?? '').split(delimiter), join(homedir(), '.elan', 'bin')];
  return [process.env.LAKE, ...dirs.map((d) => join(d, 'lake'))].find((p): p is string => p !== undefined && p !== '' && existsSync(p));
}
const lake = findLake();

// ---------- random bundles over the toy schema ----------

const TYPES = Object.keys(toy.schema.resourceTypes);
const ACTIONS = [...new Set([...ALL_ACTIONS, 'shred'])];
const ROLE_NAMES = [...Object.keys(toy.rbac.roles), 'constructor', 'Zed', 'émile', '😀role'];
const CLASSES = ['pii.iban', 'finance.amount', 'unknown.class'];
const PATHS = [
  'subject.id', 'subject.type', 'subject.clearance', 'subject.roles', 'subject.roles.0', 'subject.roles.01', 'subject.roles.length',
  'subject.compartments', 'subject.attrs.fuzz', 'subject.attrs.unit', 'subject.delegator.id', 'subject.id.length',
  'resource.owner', 'resource.level', 'resource.integrity', 'resource.attrs.amount', 'resource.attrs.priority', 'resource.attrs.tags',
  'resource.attrs.regions', 'resource.attrs.status', 'resource.attrs.tags.0', 'resource.version', 'resource.contentClasses',
  'context.network', 'context.sessionLevel', 'context.attrs.x', 'context.input.amount', 'action.name', 'action.kind',
  'nope.x', 'subject', 'resource.attrs', '', 'subject..id', 'context.now',
];
const VALUES: readonly Json[] = [
  ...MISTYPED, 3, 0, 1.5, -2, 0.1, 0.30000000000000004, 10000, 1e21, 2 ** 53 - 1, 2 ** 53, -(2 ** 53), 'a', 'b', 'open', 'closed', 'trusted', 'untrusted',
  'finance_approver', 'investigator', '😀', '', 'ORCHID', 'Z', ['a', 'b'], ['finance_approver'], { v: 1 }, 'bob', 'read',
];

// Strings whose UTF-16 order differs from their code-point order (0.8.2): astral characters against U+E000..U+FFFF.
const ORDER_STRINGS = ['😀', '\ue000', '\uffff', '𝒜b', 'ｚ', 'a😀', 'a\uff5a', ''];

const subset = <T>(rng: Rng, xs: readonly T[], p = 0.3): T[] => xs.filter(() => chance(rng, p));
const maybe = <T>(rng: Rng, p: number, f: () => T): T | undefined => (chance(rng, p) ? f() : undefined);

function randomOperand(rng: Rng): Operand {
  if (chance(rng, 0.3)) return chance(rng, 0.5) ? { path: 'resource.attrs.label' } : { value: pick(rng, ORDER_STRINGS) };
  return chance(rng, 0.6) ? { path: pick(rng, PATHS) } : { value: pick(rng, VALUES) };
}

function randomExpr(rng: Rng, depth = 0): Expr {
  const r = integer(rng, depth >= 2 ? 6 : 10);
  if (r < 4) {
    return { op: pick(rng, ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'in', 'contains', 'subset'] as const), left: randomOperand(rng), right: randomOperand(rng) };
  }
  if (r === 4) return { op: 'has', path: pick(rng, PATHS) };
  if (r === 5) return pick(rng, [{ op: 'true' }, { op: 'unknown' }] as const);
  if (r === 6) return { op: 'not', arg: randomExpr(rng, depth + 1) };
  const args = Array.from({ length: integer(rng, 4) }, () => randomExpr(rng, depth + 1));
  return r < 8 ? { op: 'and', args } : { op: 'or', args };
}

function randomAbac(rng: Rng, i: number): AbacRule {
  const effect = pick(rng, ['permit', 'permit', 'forbid', 'obligation', 'obligation'] as const);
  const obligations = effect === 'obligation' || chance(rng, 0.2) ? {
    ...(chance(rng, 0.3) ? { fieldAllowlist: subset(rng, ['a', 'b', 'c', 'a'], 0.5) } : {}),
    ...(chance(rng, 0.5) ? { redact: subset(rng, ['informant_name', 'iban', 'x', 'x'], 0.5) } : {}),
    ...(chance(rng, 0.3) ? { maskClasses: subset(rng, CLASSES, 0.5) } : {}),
    ...(chance(rng, 0.3) ? { notify: subset(rng, ['security-officer', 'dpo'], 0.5) } : {}),
  } : undefined;
  return {
    id: `r${i}`, description: `rule ${i}`, effect, when: randomExpr(rng),
    ...(chance(rng, 0.5) ? { resourceTypes: subset(rng, [...TYPES, 'ghost'], 0.5) } : {}),
    ...(chance(rng, 0.5) ? { actions: subset(rng, ACTIONS, 0.4) } : {}),
    ...(obligations ? { obligations } : {}),
  };
}

function randomCbac(rng: Rng, i: number): AbacContentRule {
  return {
    id: `c${i}`, description: `content ${i}`, contentClass: pick(rng, CLASSES), effect: pick(rng, ['deny', 'mask', 'redact'] as const),
    ...(chance(rng, 0.5) ? { fields: subset(rng, ['iban', 'amount', 'iban'], 0.5) } : {}),
    ...(chance(rng, 0.5) ? { actions: subset(rng, ACTIONS, 0.4) } : {}),
    ...(chance(rng, 0.5) ? { unless: randomExpr(rng) } : {}),
  };
}

const COUNTRIES = ['AE', 'US', 'FR'];
const ZONES = ['Asia/Dubai', 'UTC', 'America/New_York'];
const REQUIREMENTS: readonly ((rng: Rng) => Partial<ContextRule>)[] = [
  () => ({ network: 'trusted' }),
  (rng) => ({ countries: [pick(rng, COUNTRIES), ...subset(rng, COUNTRIES, 0.3)] }),
  (rng) => ({ ipRanges: [pick(rng, ['10.0.0.0/8', '2001:db8::/32', '192.0.2.0/30']), ...subset(rng, ['10.0.0.0/8', '::1/128'], 0.3)] }),
  (rng) => ({ timeWindows: [{ days: [1 + integer(rng, 7), ...subset(rng, [1, 2, 3, 4, 5, 6, 7], 0.4)], ...pick(rng, [
    { from: '08:00', to: '18:00' }, { from: '22:00', to: '06:00' }, { from: '00:00', to: '23:59' }, { from: '13:30', to: '14:00' }]), timeZone: pick(rng, ZONES) }] }),
  (rng) => ({ device: pick(rng, [{ managed: true }, { compliant: true }, { managed: true, compliant: true }, { managed: false }]) }),
  (rng) => ({ mfaMaxAgeSeconds: pick(rng, [0, 60, 3600, 86400]) }),
  (rng) => ({ authMaxAgeSeconds: pick(rng, [60, 7200, 31536000]) }),
  (rng) => ({ authMethodsAny: [pick(rng, ['otp', 'webauthn', 'pwd']), ...subset(rng, ['otp', 'webauthn'], 0.3)] }),
  (rng) => ({ maxRiskScore: integer(rng, 101) }),
];

/** A CBAC (context) rule: any selector, sometimes narrowed by level or content class, with one to three requirements. */
function randomContextRule(rng: Rng, i: number): ContextRule {
  const requirements = Array.from({ length: 1 + integer(rng, 3) }, () => pick(rng, REQUIREMENTS)(rng));
  return Object.assign({ id: `ctx${i}` },
    chance(rng, 0.4) ? { resourceTypes: [pick(rng, TYPES), ...subset(rng, [...TYPES, 'ghost'], 0.3)] } : {},
    chance(rng, 0.5) ? { actions: [pick(rng, ACTIONS), ...subset(rng, ACTIONS, 0.2)] } : {},
    chance(rng, 0.4) ? { actionKinds: [pick(rng, ['read', 'write', 'delete', 'approve', 'execute'] as const)] } : {},
    chance(rng, 0.2) ? { minResourceLevel: level(rng) } : {},
    chance(rng, 0.2) ? { contentClasses: [pick(rng, CLASSES)] } : {},
    ...requirements) as ContextRule;
}

function randomBundle(rng: Rng): PolicyBundle {
  const resourceTypes = Object.fromEntries(Object.entries(toy.schema.resourceTypes).map(([t, d]) => [t, {
    ...d,
    constrained: chance(rng, 0.3) ? d.constrained !== true : d.constrained === true,
    actions: Object.fromEntries(Object.entries(d.actions).map(([a, def]) => [a, {
      kind: chance(rng, 0.1) ? pick(rng, ['read', 'write', 'delete', 'approve', 'execute'] as const) : def.kind,
      ...((chance(rng, 0.2) ? !def.certified : def.certified) ? { certified: true } : {}),
      ...((chance(rng, 0.2) ? !def.requiresSecondPerson : def.requiresSecondPerson) ? { requiresSecondPerson: true } : {}),
    }])),
  }]));
  const roles = Object.fromEntries(subset(rng, ROLE_NAMES, 0.7).map((name) => [name, {
    ...(chance(rng, 0.5) ? { inherits: subset(rng, [...ROLE_NAMES, 'ghost'], 0.2) } : {}),
    grants: Array.from({ length: integer(rng, 4) }, () => ({ resourceType: pick(rng, [...TYPES, '*', 'ghost']), actions: subset(rng, [...ACTIONS, '*'], 0.4) })),
  }]));
  const knowsCase = { relation: pick(rng, ['knows', 'member', 'granted']), ...(chance(rng, 0.6) ? { minLevel: level(rng) } : {}) };
  return {
    name: 'lean-differential',
    schema: { ...toy.schema, resourceTypes },
    rbac: { roles },
    mandatory: {
      trustedRoles: subset(rng, ROLE_NAMES, 0.2),
      untrustedNetworkMaxLevel: level(rng),
      ...(chance(rng, 0.8) ? { compartmentsRequireTrustedNetwork: chance(rng, 0.5) } : {}),
      bibaNoReadDownActions: subset(rng, ACTIONS, 0.3),
      ...(chance(rng, 0.8) ? { bibaNoReadDownScope: randomBibaNoReadDownScope(rng) } : {}),
    } as PolicyBundle['mandatory'],
    needToKnow: {
      mode: pick(rng, ['off', 'dry_run', 'enforce'] as const),
      protect: { ...(chance(rng, 0.8) ? { case: knowsCase } : {}), ...(chance(rng, 0.3) ? { folder: { relation: 'member' } } : {}) },
      breakGlassMaxHours: 4,
      breakGlassNotify: subset(rng, ['security-officer', 'dpo'], 0.6),
    },
    abac: [...subset(rng, toy.abac, 0.5), ...Array.from({ length: integer(rng, 7) }, (_, i) => randomAbac(rng, i))],
    // content rules under abacContent, or under the legacy field cbac (read as abacContent for one version)
    [chance(rng, 0.2) ? 'cbac' : 'abacContent']: [...subset(rng, toy.abacContent ?? [], 0.5), ...Array.from({ length: integer(rng, 4) }, (_, i) => randomCbac(rng, i))],
    ...(chance(rng, 0.6) ? { context: Array.from({ length: 1 + integer(rng, 4) }, (_, i) => randomContextRule(rng, i)) } : {}),
    sod: [...subset(rng, toy.sod, 0.5), ...Array.from({ length: integer(rng, 3) }, (_, i) => ({ id: `s${i}`, description: `sod ${i}`, conflicting: subset(rng, ACTIONS, 0.4) }))],
    clarkWilson: {
      tokenTtlSeconds: pick(rng, [15, 30, 0.5]),
      ...maybe(rng, 0.3, () => ({ ivps: [{ id: 'ivp1', description: 'ivp', resourceTypes: subset(rng, TYPES, 0.6), check: randomExpr(rng) }] })),
      ...maybe(rng, 0.3, () => ({ requireCertification: subset(rng, TYPES, 0.6) })),
      ...maybe(rng, 0.3, () => ({ inputValidators: [{
        id: 'v1', description: 'input', resourceTypes: subset(rng, TYPES, 0.6), actions: subset(rng, ACTIONS, 0.5),
        fields: {
          amount: { type: 'number' as const, required: chance(rng, 0.5), min: 0, max: 1000 },
          note: { type: 'string' as const, maxLength: 3 },
          flag: { type: 'boolean' as const },
          n: { type: 'integer' as const, enum: [1, 2, 3] },
        },
      }] })),
      ...maybe(rng, 0.3, () => ({ requirePepBinding: subset(rng, TYPES, 0.6) })),
    },
  };
}

// ---------- requests: the fuzz generator, plus the context fields it does not draw ----------

// context.now must pass validInstant: explicit zone, hour 0..23, a real calendar day, 1 to 9 fraction digits, year >= 100
const NOW_EDGES = [
  '2026-11-08', '2026-11-08T10:00', '2026-11-08T10:00:00', '2026-11-08T10:00:00.123+01:00', '+002026-11-08T10:00:00Z',
  '2026-13-08T10:00:00Z', '2026-11-08T10:00:00.Z', '2026', '2026-11', '2026-11-08T24:00:00Z', '2026-02-29T10:00:00Z',
  '2024-02-29T10:00:00Z', '2100-02-29T10:00:00Z', '2000-02-29T10:00:00Z', '2026-04-31T10:00:00Z', '2026-11-08T10:00:00+23:59',
  '2026-11-08T10:00:00+24:00', '2026-11-08T10:00:00-05:60', '0099-11-08T10:00:00Z', '0100-11-08T10:00:00Z',
  '2026-11-08T10:00:00.123456789Z', '2026-11-08T10:00:00.1234567891Z', 'Nov 8, 2026', '2026-11-08T10:00:00z',
];

function randomCase(rng: Rng, bundle: PolicyBundle): unknown {
  if (chance(rng, 0.08)) return pick(rng, malformed)(rng);
  const req = randomRequest(rng);
  const extra: Record<string, unknown> = {
    ...maybe(rng, 0.3, () => ({ highWater: level(rng) })),
    ...maybe(rng, 0.3, () => ({ sessionId: pick(rng, ['s1', odd(rng)]) })),
    ...maybe(rng, 0.3, () => ({ sessionRequired: chance(rng, 0.6) })),
    ...maybe(rng, 0.2, () => ({ serverMakerId: pick(rng, ['grace', 'henry', req.subject.id]) })),
    ...maybe(rng, 0.3, () => ({ certified: Array.from({ length: integer(rng, 3) }, () => {
      const resourceType = pick(rng, [req.resource.type, ...TYPES]);
      const action = pick(rng, [req.action, ...ACTIONS]);
      return { resourceType, action, ...(chance(rng, 0.6) ? { by: subset(rng, ['bob', 'grace', 'henry', req.subject.id], 0.4) } : {}),
        ...(chance(rng, 0.7) ? { fingerprint: chance(rng, 0.6) ? procedureFingerprint(bundle, resourceType, action) : 'cw1.old' } : {}) };
    }) })),
    ...maybe(rng, 0.3, () => ({ pepSubjectTypes: subset(rng, ['user', 'agent', 'service', 'external'], 0.5) })),
    ...maybe(rng, 0.3, () => ({ input: Object.fromEntries(subset(rng, ['amount', 'note', 'flag', 'n', 'extra'], 0.6).map((k) => [k, pick(rng, [...VALUES, 'abc', 'abcd', '😀😀😀', 2])])) })),
    ...maybe(rng, 0.3, () => ({ attrs: { x: pick(rng, VALUES) } })),
    ...maybe(rng, 0.1, () => ({ sessionExpired: chance(rng, 0.5) })),
    ...maybe(rng, 0.1, () => ({ now: pick(rng, NOW_EDGES) })),
    // validation edges: well-formed and ill-formed optional context fields, other instant formats
    ...maybe(rng, 0.05, () => pick(rng, [
      { highWater: 1.5 }, { sessionRequired: 'yes' }, { pepSubjectTypes: 'user' }, { input: [] }, { input: null },
      { certified: [{ resourceType: '' , action: 'read' }] }, { certified: [{ resourceType: 'case', action: 'read', by: 'bob' }] },
      { ip: 'fe80::1%eth0' }, { ip: '10.0.0.256' }, { ip: 5 }, { country: 'XX' }, { country: 'ae' }, { riskScore: 101 }, { riskScore: 1.5 },
      { device: { managed: true } }, { device: { managed: true, compliant: false, extra: 1 } }, { authTime: '2026-11-08' },
      { mfaTime: '2026-02-30T10:00:00Z' }, { authMethods: ['bad method'] }, { authMethods: 'otp' }, { sessionExpired: 'yes' },
    ])),
  };
  const labelled = { ...req.resource, attrs: { ...req.resource.attrs, label: pick(rng, ORDER_STRINGS) } };
  const resource = chance(rng, 0.05) ? { ...labelled, version: pick(rng, [null, 1.5, -3, 7]) as number } : labelled;
  const out = { ...req, resource, context: { ...req.context, ...extra } };
  return chance(rng, 0.5) ? friendly(rng, out, bundle) : out;
}

/** Steers a request towards the allow path (every role, full clearance, trusted network, fewer content classes), so
 *  obligations, the allow basis and the later stages are exercised, not only the first denials. */
function friendly(rng: Rng, req: Request, bundle: PolicyBundle): Request {
  const subject = { ...req.subject, active: true, clearance: 3 as const, roles: Object.keys(bundle.rbac.roles), compartments: [...bundle.schema.compartments], integrity: req.resource.integrity };
  return {
    ...req,
    subject: chance(rng, 0.7) ? (({ delegator: _d, ...s }) => ({ ...s, type: s.type === 'agent' ? 'user' : s.type }))(subject) : subject,
    resource: { ...req.resource, compartments: req.resource.compartments.filter((c) => chance(rng, 0.5) && bundle.schema.compartments.includes(c)), ...(chance(rng, 0.5) ? { contentClasses: [] } : {}) },
    context: (({ highWater: _h, sessionRequired: _r, priorActions: _p, ...c }) => ({ ...c, network: 'trusted' as const, sessionLevel: req.resource.level }))(req.context),
  };
}

// The model's strings are Unicode scalar values: a lone surrogate (which JSON carries as an escape) becomes a distinct
// supplementary private-use character, before either engine sees the request.
const LONE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;
const wellFormed = (value: unknown): unknown => JSON.parse(JSON.stringify(value ?? null, (_k, v: unknown) =>
  (typeof v === 'string' ? v.replace(LONE, (c) => String.fromCodePoint(0xf0000 + c.charCodeAt(0))) : v)));

interface Oracle {
  readonly ntk: ({ ok: boolean; breakGlass: boolean } | null)[];
  readonly fingerprintCurrent: boolean;
  readonly signalsValid: boolean;
  readonly roleLive: Record<string, unknown>[][];
  readonly ctxOk: Record<string, boolean>[];
}

// the request errors whose grammar the model leaves to the oracle (contextSignalErrors, role-assignment windows)
const SIGNAL_ERROR = /^context\.(ip|country|device|authTime|mfaTime|authMethods|riskScore) |\.roleAssignments must be/;
const ABSTRACTED = new Set(['ipRanges', 'timeWindows', 'mfaMaxAgeSeconds', 'authMaxAgeSeconds']);

function oracleFor(bundle: PolicyBundle, req: Request, g: ReturnType<typeof indexTuples>): Oracle {
  const errors = requestErrors(req);
  const signalsValid = !errors.some((e) => SIGNAL_ERROR.test(e));
  if (errors.length > 0) return { ntk: [], fingerprintCurrent: false, signalsValid, roleLive: [], ctxOk: [] };
  const nowMs = Date.parse(req.context.now);
  const nk = bundle.needToKnow;
  const protect = Object.hasOwn(nk.protect, req.resource.type) ? nk.protect[req.resource.type] : undefined;
  return {
    ntk: principals(req.subject).map((p) => {
      if (!protect) return null;
      const r = check(bundle, g, req.resource, protect.relation, p, req.context.now);
      return { ok: r.ok, breakGlass: r.ok && r.breakGlass === true };
    }),
    fingerprintCurrent: certificationGap(bundle, req) !== 'stale',
    signalsValid,
    roleLive: principals(req.subject).map((p) => (p.roleAssignments ?? []).map((a) => ({ ...a, live: windowState(a, nowMs) === 'live' }))),
    ctxOk: (bundle.context ?? []).map((rule) => Object.fromEntries(contextChecks(rule, req.context)
      .filter((c) => ABSTRACTED.has(c.requirement)).map((c) => [c.requirement, c.ok]))),
  };
}

const project = (d: Decision): unknown => JSON.parse(JSON.stringify({ decision: d.decision, rules: d.rules, obligations: d.obligations, wouldDeny: d.wouldDeny }));

function leanBinary(): string {
  const env = { ...process.env, PATH: `${dirname(lake as string)}${delimiter}${process.env.PATH ?? ''}` };
  const built = spawnSync(lake as string, ['build', 'gate-model'], { cwd: FORMAL, env, encoding: 'utf8' });
  assert.equal(built.status, 0, `lake build gate-model failed:\n${built.stdout}\n${built.stderr}`);
  return join(FORMAL, '.lake', 'build', 'bin', process.platform === 'win32' ? 'gate-model.exe' : 'gate-model');
}

const seed = envInteger('LEAN_DIFF_SEED', randomInt(0x100000000), 0xffffffff);
const runs = envInteger('LEAN_DIFF_RUNS', 2000, 1_000_000);
const PER_BUNDLE = 20;

test('the TypeScript engine and the Lean model decide alike', {
  skip: lake === undefined && !REQUIRED ? 'no Lean toolchain (elan): see docs/spec/FORMAL-MODEL.md; LEAN_REQUIRED=1 makes this a failure' : false,
}, (t) => {
  assert.ok(lake !== undefined, 'LEAN_REQUIRED=1 but no lake found on PATH, in ~/.elan/bin or in $LAKE');
  const bin = leanBinary();
  const rng = prng(seed);
  const groups: { bundle: PolicyBundle; cases: { request: unknown; oracle: Oracle; expected: unknown }[] }[] = [];
  const bibaScopes = new Set<string>();
  for (let n = 0; n < runs; n += PER_BUNDLE) {
    const bundle = wellFormed(randomBundle(rng)) as PolicyBundle;
    bibaScopes.add(bundle.mandatory.bibaNoReadDownScope ?? 'actions');
    const cases = Array.from({ length: Math.min(PER_BUNDLE, runs - n) }, () => {
      const request = wellFormed(randomCase(rng, bundle)) as Request;
      const valid = requestErrors(request).length === 0;
      const g = valid && chance(rng, 0.5)
        ? indexTuples([...world.tuples, ...principals(request.subject).map((s): Tuple => ({ object: { type: request.resource.type, id: request.resource.id }, relation: pick(rng, ['granted', 'member']), subject: { type: s.type, id: s.id }, ...(chance(rng, 0.3) ? { breakGlass: true, validTo: '2026-11-08T12:00:00Z' } : {}) }))])
        : graph;
      return { request, oracle: oracleFor(bundle, request, g), expected: project(evaluate(bundle, request, g)) };
    });
    groups.push({ bundle, cases });
  }
  const input = groups.map((g) => JSON.stringify({ bundle: g.bundle, cases: g.cases.map(({ request, oracle }) => ({ request, oracle })) })).join('\n');
  const out = spawnSync(bin, [], { input, encoding: 'utf8', maxBuffer: 1 << 30 });
  assert.equal(out.status, 0, `gate-model failed: ${out.stderr}`);
  const lines = out.stdout.trim().split('\n');
  assert.equal(lines.length, groups.length);
  let compared = 0;
  let allowed = 0;
  const ruleIds = new Set<string>();
  lines.forEach((line, i) => {
    const group = groups[i] as (typeof groups)[number];
    const parsed = JSON.parse(line) as { results?: unknown[]; error?: string };
    assert.ok(parsed.results, `the model rejected bundle ${i} (outside the modelled subset?): ${parsed.error} (LEAN_DIFF_SEED=${seed})`);
    group.cases.forEach((c, j) => {
      const got = (parsed.results as unknown[])[j];
      if (JSON.stringify(got) !== JSON.stringify(c.expected)) {
        try {
          assert.deepEqual(got, c.expected);
        } catch (error) {
          console.error(`Lean/TypeScript disagreement: LEAN_DIFF_SEED=${seed} LEAN_DIFF_RUNS=${runs}, bundle ${i}, case ${j}\n` +
            `bundle=${JSON.stringify(group.bundle)}\nrequest=${JSON.stringify(c.request)}\noracle=${JSON.stringify(c.oracle)}`);
          throw error;
        }
      }
      compared++;
      const d = c.expected as { decision: boolean; rules: string[] };
      if (d.decision) allowed++;
      for (const r of d.rules) ruleIds.add(r.replace(/^DELEGATION\./, '').replace(/^(ABAC|SOD|RBAC|NTK|CW\.INPUT|CW\.IVP)\..*/, '$1.*'));
    });
  });
  assert.equal(compared, runs);
  if (runs >= 1000) assert.deepEqual([...bibaScopes].sort(), ['actions', 'all', 'reads'], 'the differential run covers every Biba scope');
  t.diagnostic(`LEAN_DIFF_SEED=${seed}: ${compared} cases agree (${allowed} allow, ${compared - allowed} deny), Biba scopes: ${[...bibaScopes].sort().join(' ')}, rule families: ${[...ruleIds].sort().join(' ')}`);
});
