// Product invariant: tenant policy can narrow the mandatory models and never silently disable them
// (docs/ARCHITECTURE.md §1). This lists every way a candidate bundle loosens the published one, so the control plane
// can refuse it or demand a stronger approval. Pure, deterministic, metadata only.
import type { AbacContentRule, AbacRule, Expr, PolicyBundle } from './types.ts';
import { contentRules } from './content.ts';
import { canonical } from './version.ts';
import { bibaNoReadDown } from './mandatory.ts';

const missingFrom = (before: readonly string[], after: readonly string[]): string[] => before.filter((x) => !after.includes(x));
const addedTo = (before: readonly string[], after: readonly string[]): string[] => after.filter((x) => !before.includes(x));
const STRENGTH: Readonly<Record<string, number>> = { off: 0, dry_run: 1, enforce: 2 };

export function mandatoryWeakenings(before: PolicyBundle, after: PolicyBundle): string[] {
  const out: string[] = [];
  const m0 = before.mandatory;
  const m1 = after.mandatory;
  if (m1.untrustedNetworkMaxLevel > m0.untrustedNetworkMaxLevel) out.push(`untrusted network max level raised to L${m1.untrustedNetworkMaxLevel}`);
  if (m0.compartmentsRequireTrustedNetwork && !m1.compartmentsRequireTrustedNetwork) out.push('compartments no longer require a trusted network');
  for (const r of addedTo(m0.trustedRoles, m1.trustedRoles)) out.push(`new BLP trusted role ${r}`);
  const bibaRemoved = new Set<string>();
  for (const [type, definition] of Object.entries(before.schema.resourceTypes)) for (const [action, oldAction] of Object.entries(definition.actions)) {
    const newAction = after.schema.resourceTypes[type]?.actions[action];
    if (newAction && bibaNoReadDown(m0, action, oldAction.kind) && !bibaNoReadDown(m1, action, newAction.kind)) bibaRemoved.add(action);
  }
  for (const action of bibaRemoved) out.push(`Biba no-read-down removed from ${action}`);

  const n0 = before.needToKnow;
  const n1 = after.needToKnow;
  if ((STRENGTH[n1.mode] ?? -1) < (STRENGTH[n0.mode] ?? 2)) out.push(`need-to-know mode lowered to ${n1.mode}`);
  for (const [type, p] of Object.entries(n0.protect)) {
    const q = Object.hasOwn(n1.protect, type) ? n1.protect[type] : undefined;
    if (!q) out.push(`need-to-know no longer protects ${type}`);
    else {
      if ((q.minLevel ?? 0) > (p.minLevel ?? 0)) out.push(`need-to-know on ${type} starts at L${q.minLevel} instead of L${p.minLevel ?? 0}`);
      if (q.relation !== p.relation) out.push(`need-to-know on ${type} uses relation ${q.relation} instead of ${p.relation}`);
    }
  }
  if (n1.breakGlassMaxHours > n0.breakGlassMaxHours) out.push(`break-glass cap raised to ${n1.breakGlassMaxHours} h`);
  for (const who of missingFrom(n0.breakGlassNotify, n1.breakGlassNotify)) out.push(`break-glass no longer notifies ${who}`);

  if (after.clarkWilson.tokenTtlSeconds > before.clarkWilson.tokenTtlSeconds) out.push(`decision token lifetime raised to ${after.clarkWilson.tokenTtlSeconds} s`);
  for (const t of before.clarkWilson.requireCertification ?? []) {
    if (!(after.clarkWilson.requireCertification ?? []).includes(t)) out.push(`${t} procedures no longer require a certification record`);
  }
  for (const t of before.clarkWilson.requirePepBinding ?? []) {
    if (!(after.clarkWilson.requirePepBinding ?? []).includes(t)) out.push(`${t} procedures no longer require a PEP bound to the subject's population`);
  }
  for (const v of before.clarkWilson.inputValidators ?? []) {
    const w = (after.clarkWilson.inputValidators ?? []).find((x) => x.id === v.id);
    if (!w || canonical(w) !== canonical(v)) out.push(`input validation ${v.id} removed or changed`);
  }
  // an edited check cannot be judged stricter generically, so any edit counts, like relations below
  for (const i of before.clarkWilson.ivps ?? []) {
    const j = (after.clarkWilson.ivps ?? []).find((x) => x.id === i.id);
    if (!j || canonical(j.check) !== canonical(i.check) || missingFrom(i.resourceTypes, j.resourceTypes).length > 0) out.push(`integrity verification ${i.id} removed or changed`);
  }
  for (const [type, t0] of Object.entries(before.schema.resourceTypes)) {
    const t1 = Object.hasOwn(after.schema.resourceTypes, type) ? after.schema.resourceTypes[type] : undefined;
    if (!t1) { out.push(`resource type ${type} removed`); continue; }
    if (t0.constrained && !t1.constrained) out.push(`${type} is no longer a Clark-Wilson constrained item`);
    for (const [name, a0] of Object.entries(t0.actions)) {
      const a1 = Object.hasOwn(t1.actions, name) ? t1.actions[name] : undefined;
      if (!a1) continue; // removing an action narrows access
      if (a0.certified && !a1.certified) out.push(`${type}.${name} is no longer a certified command`);
      if (a0.requiresSecondPerson && !a1.requiresSecondPerson) out.push(`${type}.${name} no longer requires a second person`);
      // conditions and the mandatory models read the kind (action.kind, write vs read): any reclassification counts
      if (a0.kind !== a1.kind) out.push(`${type}.${name} reclassified from ${a0.kind} to ${a1.kind}`);
    }
  }
  // Relations define the reasons to know; judging narrowing generically is unsafe, so any edit is flagged.
  type Rels = Readonly<Record<string, unknown>>;
  const relationSets = (b: PolicyBundle): [string, string, Rels][] => [
    ...Object.entries(b.schema.resourceTypes).map(([t, d]): [string, string, Rels] => [`resource:${t}`, t, d.relations ?? {}]),
    ...Object.entries(b.schema.subjectRelations ?? {}).map(([t, d]): [string, string, Rels] => [`subject:${t}`, t, d]),
  ];
  const afterSets = new Map(relationSets(after).map(([key, , rels]) => [key, rels]));
  for (const [key, type, rels0] of relationSets(before)) {
    const rels1 = afterSets.get(key) ?? {};
    for (const [name, def] of Object.entries(rels0)) {
      if (Object.hasOwn(rels1, name) && canonical(rels1[name]) !== canonical(def)) out.push(`relation ${type}.${name} redefined`);
    }
  }
  for (const c of missingFrom(before.schema.compartments, after.schema.compartments)) out.push(`compartment ${c} removed`);
  for (const r of before.sod) {
    const s = after.sod.find((x) => x.id === r.id);
    if (!s) out.push(`separation-of-duty rule ${r.id} removed`);
    else for (const a of missingFrom(r.conflicting, s.conflicting)) out.push(`separation-of-duty rule ${r.id} no longer covers ${a}`);
  }
  // Protective rules (KIMI-01): each one before must still be covered by a rule after that fires in at least every case
  // it fired and imposes at least as much. Coverage is judged syntactically; anything not provably as strong counts.
  for (const r of before.abac.filter((x) => x.effect !== 'permit')) {
    if (!after.abac.some((s) => abacCovers(s, r))) out.push(`ABAC rule ${r.id} removed or weakened`);
  }
  for (const r of contentRules(before)) {
    if (!contentRules(after).some((s) => contentCovers(s, r))) out.push(`ABAC content rule ${r.id} removed or weakened`);
  }
  // Context requirements form a conjunction over open-ended selectors: only an identical rule is provably as strong.
  for (const r of before.context ?? []) {
    if (!(after.context ?? []).some((s) => canonical(s) === canonical(r))) out.push(`context rule ${r.id} removed or weakened`);
  }
  return out;
}

/** a ⇒ b in Kleene logic, for both TRUE (exemption) and TRUE-or-UNKNOWN (forbid): proven only for these shapes. */
function implies(a: Expr, b: Expr): boolean {
  if (b.op === 'true' || canonical(a) === canonical(b)) return true;
  if (b.op === 'or' && b.args.some((x) => implies(a, x))) return true;
  return a.op === 'and' && a.args.some((x) => implies(x, b));
}
const within = (inner: readonly string[] | undefined, outer: readonly string[] | undefined): boolean =>
  outer === undefined || (inner !== undefined && inner.every((x) => outer.includes(x)));
const superset = (big: readonly string[] | undefined, small: readonly string[] | undefined): boolean => (small ?? []).every((x) => (big ?? []).includes(x));

/** s fires wherever r fires (same or wider scope, a condition r's implies) with the same effect and at least r's obligations. */
function abacCovers(s: AbacRule, r: AbacRule): boolean {
  if (canonical(s) === canonical(r)) return true;
  if (s.effect !== r.effect || (r.effect !== 'forbid' && r.effect !== 'obligation')) return false;
  if (!within(r.resourceTypes, s.resourceTypes) || !within(r.actions, s.actions) || !implies(r.when, s.when)) return false;
  if (r.effect === 'forbid') return true;
  const o = s.obligations ?? {}; const p = r.obligations ?? {};
  return superset(o.redact, p.redact) && superset(o.maskClasses, p.maskClasses) && superset(o.notify, p.notify) &&
    (p.fieldAllowlist === undefined || (o.fieldAllowlist !== undefined && o.fieldAllowlist.every((f) => p.fieldAllowlist?.includes(f))));
}

/** s applies wherever r applies (same class, same or more actions, an exemption that implies r's) with as much effect. */
function contentCovers(s: AbacContentRule, r: AbacContentRule): boolean {
  if (canonical(s) === canonical(r)) return true;
  if (s.effect !== r.effect || s.contentClass !== r.contentClass || !within(r.actions, s.actions)) return false;
  if (s.unless !== undefined && (r.unless === undefined || !implies(s.unless, r.unless))) return false;
  return r.effect !== 'redact' || superset(s.fields, r.fields);
}
