// KIMI-01 (pentest 2026-11-10): every change that can remove, narrow or condition away an ABAC forbid/obligation or a
// content-attribute deny/mask/redact (abacContent) is a mandatory weakening. The pentest's two reproductions, then a property over random edits:
// whenever the evaluator shows a lost deny or a lost obligation for some request, the analysis must have flagged it.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  contentRules, evaluate, indexTuples, mandatoryWeakenings,
  type AbacRule, type AbacContentRule, type Context, type Decision, type Expr, type PolicyBundle, type Resource, type Subject, type Tuple,
} from '../src/index.ts';

const load = (f: string) => JSON.parse(readFileSync(new URL(`../../../examples/toy-domain/${f}`, import.meta.url), 'utf8'));
const bundle: PolicyBundle = load('bundle.json');
const world: { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] } = load('world.json');
const graph = indexTuples(world.tuples);
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const S = (id: string): Subject => world.subjects.find((x) => x.id === id) as Subject;
const R = (id: string): Resource => world.resources.find((x) => x.id === id) as Resource;
const ctx = (network: Context['network']): Context => ({ network, now: world.now, makerId: 'independent-maker' });
const decide = (b: PolicyBundle, s: Subject, action: string, r: Resource, network: Context['network'] = 'trusted') =>
  evaluate(b, { subject: s, action, resource: r, context: ctx(network) }, graph);
type Mutable<T> = { -readonly [K in keyof T]: T[K] };

test('KIMI-01 scenario 1: making no-export-untrusted inapplicable is flagged, and it was a lost deny', () => {
  const weak: PolicyBundle = { ...bundle, abac: bundle.abac.map((r) => r.id === 'no-export-untrusted'
    ? { ...r, when: { op: 'eq', left: { path: 'context.network' }, right: { value: 'never' } } } as AbacRule : r) };
  assert.equal(decide(bundle, S('bob'), 'export', R('CASE-14'), 'untrusted').decision, false);
  assert.equal(decide(weak, S('bob'), 'export', R('CASE-14'), 'untrusted').decision, true);
  assert.deepEqual(mandatoryWeakenings(bundle, weak), ['ABAC rule no-export-untrusted removed or weakened']);
});

test('KIMI-01 scenario 2: an always-true finance-mask exemption is flagged, and it was a lost mask', () => {
  const weak: PolicyBundle = { ...bundle, abacContent: contentRules(bundle).map((r) => r.id === 'finance-mask' ? { ...r, unless: { op: 'true' } } as AbacContentRule : r) };
  assert.deepEqual(decide(bundle, S('bob'), 'read', R('CASE-14')).obligations.maskClasses, ['finance.amount']);
  assert.deepEqual(decide(weak, S('bob'), 'read', R('CASE-14')).obligations.maskClasses, []);
  assert.deepEqual(mandatoryWeakenings(bundle, weak), ['ABAC content rule finance-mask removed or weakened']);
});

test('removing a redaction, an obligation or a deny, or narrowing their scope, is flagged', () => {
  const abac = (b: PolicyBundle, id: string) => b.abac.find((r) => r.id === id) as Mutable<AbacRule>;
  const content = (b: PolicyBundle, id: string) => contentRules(b).find((r) => r.id === id) as Mutable<AbacContentRule>;
  const edits: Array<[string, (b: PolicyBundle) => void]> = [
    ['ABAC rule informant-redaction', (b) => { (b.abac as AbacRule[]).splice(b.abac.findIndex((r) => r.id === 'informant-redaction'), 1); }],
    ['ABAC rule informant-redaction', (b) => { abac(b, 'informant-redaction').obligations = { redact: [] }; }],
    ['ABAC rule closed-is-read-only', (b) => { abac(b, 'closed-is-read-only').actions = ['update']; }],
    ['ABAC rule no-export-untrusted', (b) => { abac(b, 'no-export-untrusted').resourceTypes = ['payment']; }],
    ['ABAC rule no-export-untrusted', (b) => { abac(b, 'no-export-untrusted').effect = 'obligation'; }],
    ['ABAC content rule no-iban-export', (b) => { content(b, 'no-iban-export').effect = 'mask'; }],
    ['ABAC content rule no-iban-export', (b) => { content(b, 'no-iban-export').contentClass = 'pii.other'; }],
    ['ABAC content rule no-iban-export', (b) => { content(b, 'no-iban-export').unless = { op: 'eq', left: { path: 'context.network' }, right: { value: 'trusted' } }; }],
  ];
  for (const [want, change] of edits) {
    const b = clone(bundle); change(b);
    assert.ok(mandatoryWeakenings(bundle, b).includes(`${want} removed or weakened`), want);
  }
  const redact = clone(bundle);
  (redact.abacContent as AbacContentRule[]).push({ id: 'iban-redact', description: 'x', contentClass: 'pii.iban', effect: 'redact', fields: ['iban', 'bic'] });
  const fewer = clone(redact);
  content(fewer, 'iban-redact').fields = ['iban'];
  assert.deepEqual(mandatoryWeakenings(redact, fewer), ['ABAC content rule iban-redact removed or weakened']);
  assert.deepEqual(mandatoryWeakenings(bundle, redact), [], 'adding a redaction strengthens');
});

test('provably stronger edits of protective rules are not weakenings', () => {
  const b = clone(bundle);
  const forbid = b.abac.find((r) => r.id === 'no-export-untrusted') as Mutable<AbacRule>;
  forbid.when = { op: 'or', args: [forbid.when, { op: 'eq', left: { path: 'subject.id' }, right: { value: 'bob' } }] };
  delete forbid.actions; // every action
  const mask = contentRules(b).find((r) => r.id === 'finance-mask') as Mutable<AbacContentRule>;
  mask.unless = { op: 'and', args: [mask.unless as Expr, { op: 'eq', left: { path: 'context.network' }, right: { value: 'trusted' } }] };
  const redaction = b.abac.find((r) => r.id === 'informant-redaction') as Mutable<AbacRule>;
  redaction.obligations = { redact: ['informant_name', 'witness_name'] };
  delete redaction.resourceTypes;
  (b.abac as AbacRule[]).push({ id: 'new-forbid', description: 'x', effect: 'forbid', when: { op: 'true' }, actions: ['delete'] });
  assert.deepEqual(mandatoryWeakenings(bundle, b), []);
});

// ---------- property: a lost deny or a lost obligation is always flagged ----------

function prng(seed: number): () => number {
  let s = seed >>> 0;
  return () => { s = (s + 0x6d2b79f5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const ACTIONS = [...new Set(Object.values(bundle.schema.resourceTypes).flatMap((t) => Object.keys(t.actions)))];
const TYPES = Object.keys(bundle.schema.resourceTypes);
const CLASSES = ['finance.amount', 'pii.iban', 'pii.other'];
const ATOMS: Expr[] = [
  { op: 'true' }, { op: 'not', arg: { op: 'true' } },
  { op: 'eq', left: { path: 'context.network' }, right: { value: 'untrusted' } },
  { op: 'eq', left: { path: 'context.network' }, right: { value: 'trusted' } },
  { op: 'lt', left: { path: 'subject.clearance' }, right: { value: 2 } },
  { op: 'contains', left: { path: 'subject.roles' }, right: { value: 'investigator' } },
  { op: 'contains', left: { path: 'subject.roles' }, right: { value: 'finance_approver' } },
  { op: 'eq', left: { path: 'resource.attrs.status' }, right: { value: 'closed' } },
  { op: 'eq', left: { path: 'subject.attrs.missing' }, right: { value: 1 } }, // UNKNOWN
  { op: 'ge', left: { path: 'resource.level' }, right: { value: 2 } },
];

function edit(rng: () => number, b: PolicyBundle): void {
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rng() * xs.length)] as T;
  const sub = <T>(xs: readonly T[]): T[] => xs.filter(() => rng() < 0.5);
  const expr = (depth = 0): Expr => depth < 2 && rng() < 0.4
    ? (rng() < 0.2 ? { op: 'not', arg: expr(depth + 1) } : { op: rng() < 0.5 ? 'and' : 'or', args: [expr(depth + 1), expr(depth + 1)] })
    : pick(ATOMS);
  const reshape = (e: Expr): Expr => pick<() => Expr>([() => expr(), () => ({ op: 'or', args: [e, expr()] }), () => ({ op: 'and', args: [e, expr()] }), () => ({ op: 'not', arg: e })])();
  const list = <T>(cur: readonly T[] | undefined, all: readonly T[]): T[] | undefined => rng() < 0.25 ? undefined : rng() < 0.5 ? sub(all) : [...(cur ?? all), pick(all)];
  const abac = b.abac as AbacRule[]; const content = b.abacContent as AbacContentRule[];
  const protective = abac.map((r, i) => [r, i] as const).filter(([r]) => r.effect !== 'permit');
  if (rng() < 0.55 && protective.length) {
    const [rule, i] = pick(protective);
    const r = clone(rule) as Mutable<AbacRule>;
    switch (Math.floor(rng() * 6)) {
      case 0: abac.splice(i, 1); return;
      case 1: r.effect = pick(['permit', 'forbid', 'obligation'] as const); break;
      case 2: r.when = reshape(r.when); break;
      case 3: r.actions = list(r.actions, ACTIONS); break;
      case 4: r.resourceTypes = list(r.resourceTypes, TYPES); break;
      default: r.obligations = { redact: sub(['informant_name', 'witness_name']), notify: sub(['dpo']), ...(rng() < 0.3 ? { fieldAllowlist: sub(['id', 'title']) } : {}) };
    }
    abac[i] = r;
    return;
  }
  const i = Math.floor(rng() * content.length);
  const r = clone(content[i]) as Mutable<AbacContentRule>;
  switch (Math.floor(rng() * 6)) {
    case 0: content.splice(i, 1); return;
    case 1: r.effect = pick(['deny', 'mask', 'redact'] as const); if (r.effect === 'redact') r.fields = ['iban']; break;
    case 2: r.unless = r.unless ? reshape(r.unless) : expr(); break;
    case 3: r.actions = list(r.actions, ACTIONS); break;
    case 4: r.contentClass = pick(CLASSES); break;
    default: r.fields = sub(['iban', 'amount']); r.effect = 'redact';
  }
  content[i] = r;
}

/** before → after loses protection on this cell: a deny became an allow, or an allow lost an obligation. */
function lost(was: Decision, now: Decision): boolean {
  if (!was.decision) return now.decision;
  if (!now.decision) return false;
  const o = was.obligations; const p = now.obligations;
  const missing = (a: readonly string[], b: readonly string[]) => a.some((x) => !b.includes(x));
  return missing(o.redact, p.redact) || missing(o.maskClasses, p.maskClasses) || missing(o.notify, p.notify) ||
    (o.fieldAllowlist !== undefined && (p.fieldAllowlist === undefined || missing(p.fieldAllowlist, o.fieldAllowlist)));
}

test('property: every random rule edit that loses a deny or an obligation for some request is flagged', () => {
  // more content on the resources, so content rules bite on several cells
  const resources = world.resources.map((r) => r.id === 'CASE-7' ? { ...r, contentClasses: ['finance.amount', 'pii.iban', 'pii.other'] } : r);
  const cells = world.subjects.flatMap((s) => resources.flatMap((r) => Object.keys(bundle.schema.resourceTypes[r.type]?.actions ?? {})
    .flatMap((action) => (['trusted', 'untrusted'] as const).map((network) => ({ subject: s, resource: r, action, context: ctx(network) })))));
  const base = cells.map((req) => evaluate(bundle, req, graph));
  const rng = prng(0x5eed01);
  let losing = 0;
  for (let round = 0; round < 250; round++) {
    const b = clone(bundle);
    for (let n = 1 + Math.floor(rng() * 2); n > 0; n--) edit(rng, b);
    const at = cells.findIndex((req, i) => lost(base[i] as Decision, evaluate(b, req, graph)));
    if (at < 0) continue;
    losing++;
    const c = cells[at]!;
    assert.ok(mandatoryWeakenings(bundle, b).length > 0,
      `round ${round}: ${c.subject.id} ${c.action} ${c.resource.id} ${c.context.network} lost protection, unflagged:\n${JSON.stringify({ abac: b.abac, abacContent: b.abacContent })}`);
  }
  assert.ok(losing >= 50, `the generator must exercise losses (got ${losing})`);
});

test('context rule removal, loosening, narrowing and edits are security-reviewed; addition alone is not a weakening', () => {
  const before: PolicyBundle = { ...bundle, context: [{ id: 'zero-trust', resourceTypes: ['case'], actions: ['read'], countries: ['AE'], maxRiskScore: 50 }] };
  const removed = { ...before, context: [] };
  assert.deepEqual(mandatoryWeakenings(before, removed), ['context rule zero-trust removed or weakened']);
  for (const after of [
    { ...before, context: [{ ...before.context![0]!, maxRiskScore: 60 }] },
    { ...before, context: [{ ...before.context![0]!, countries: ['AE', 'US'] }] },
    { ...before, context: [{ ...before.context![0]!, actions: ['read', 'update'] }] },
    { ...before, context: [{ ...before.context![0]!, maxRiskScore: 40 }] },
  ]) assert.deepEqual(mandatoryWeakenings(before, after), ['context rule zero-trust removed or weakened']);
  const added = { ...before, context: [...before.context!, { id: 'device', actionKinds: ['read' as const], device: { managed: true } }] };
  assert.deepEqual(mandatoryWeakenings(before, added), []);
});


test('Biba no-read-down scope changes are governed by their effective action coverage', () => {
  const scoped = (scope: 'actions' | 'reads' | 'all', actions: readonly string[] = []): PolicyBundle => ({
    ...bundle, mandatory: { ...bundle.mandatory, bibaNoReadDownActions: actions, bibaNoReadDownScope: scope },
  });
  assert.deepEqual(mandatoryWeakenings(scoped('actions'), scoped('reads')), [], 'extending an empty list to reads strengthens');
  assert.deepEqual(mandatoryWeakenings(bundle, scoped('all')), [], 'all retains the listed approvals and adds everything else');
  assert.ok(mandatoryWeakenings(scoped('all'), scoped('reads')).includes('Biba no-read-down removed from update'));
  assert.ok(mandatoryWeakenings(scoped('reads'), scoped('actions')).includes('Biba no-read-down removed from read'));
  assert.ok(mandatoryWeakenings(bundle, scoped('reads')).includes('Biba no-read-down removed from approve'),
    'read coverage does not silently discard the old approval list');
  assert.deepEqual(mandatoryWeakenings(scoped('actions', ['approve']), scoped('actions', ['approve'])), []);
});
