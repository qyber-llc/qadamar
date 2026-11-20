// List filtering by partial evaluation: what a subject may do on a resource type, as a residual predicate over
// `resource.*` only, with SQL's three-valued logic (a row is kept only when the predicate is TRUE). The SQL compiler
// (packages/sql) turns the residual into a WHERE clause. The residual mirrors evaluate() principal by principal;
// a property test checks that a kept row is allowed point-wise and an allowed row is kept.
import { and, FALSE, not, or, partial, TRUE, type Env } from './conditions.ts';
import { contentRules } from './content.ts';
import { contextFilter, validInstant } from './context.ts';
import { ivpsFor } from './integrity.ts';
import { procedureFindings } from './procedures.ts';
import { bibaNoReadDown, INTEGRITY_RANK, isWrite, sessionOf, writeFloor } from './mandatory.ts';
import { actionDef, appliesTo, notCertified, rbacGrant, withLiveRoles } from './evaluate.ts';
import { knownObjects, type Graph } from './relations.ts';
import { contextSignalErrors, hasUnsafeNumber, principals, subjectChainErrors } from './request.ts';
import type { ActionKind, Context, Expr, Integrity, PolicyBundle, Subject } from './types.ts';

const integrities = (pred: (rank: number) => boolean): string[] =>
  (Object.keys(INTEGRITY_RANK) as Integrity[]).filter((i) => pred(INTEGRITY_RANK[i]));

function mandatory(bundle: PolicyBundle, s: Subject, action: string, kind: ActionKind, ctx: Context): Expr {
  const m = bundle.mandatory;
  const session = sessionOf(s, ctx);
  const parts: Expr[] = [
    { op: 'le', left: { path: 'resource.level' }, right: { value: session } },
    { op: 'subset', left: { path: 'resource.compartments' }, right: { value: [...s.compartments] } },
  ];
  if (ctx.network !== 'trusted') {
    parts.push({ op: 'le', left: { path: 'resource.level' }, right: { value: m.untrustedNetworkMaxLevel } });
    if (m.compartmentsRequireTrustedNetwork !== false) parts.push({ op: 'subset', left: { path: 'resource.compartments' }, right: { value: [] } });
  }
  const mine = INTEGRITY_RANK[s.integrity];
  // BLP_SESSION_REQUIRED without a session: no write at all for a cleared subject, reads of L0 only (mandatory.ts)
  if (ctx.sessionRequired === true && ctx.sessionId === undefined) {
    if (isWrite(kind) && s.clearance > 0) parts.push(FALSE);
    if (!isWrite(kind)) parts.push({ op: 'le', left: { path: 'resource.level' }, right: { value: 0 } });
  }
  if (isWrite(kind)) {
    if (!s.roles.some((r) => m.trustedRoles.includes(r))) parts.push({ op: 'ge', left: { path: 'resource.level' }, right: { value: writeFloor(s, ctx) } });
    parts.push({ op: 'in', left: { path: 'resource.integrity' }, right: { value: integrities((r) => r <= mine) } });
  }
  if (bibaNoReadDown(m, action, kind)) {
    parts.push({ op: 'in', left: { path: 'resource.integrity' }, right: { value: integrities((r) => r >= mine) } });
  }
  return and(parts);
}

function forPrincipal(bundle: PolicyBundle, s: Subject, type: string, action: string, kind: ActionKind, ctx: Context, graph: Graph): Expr {
  const env: Omit<Env, 'resource'> = { subject: s, action: { name: action, kind }, context: ctx };
  const eligible = rbacGrant(bundle, s, type, action, ctx.now)
    ? TRUE
    : or(bundle.abac.filter((r) => r.effect === 'permit' && appliesTo(r, type, action)).map((r) => partial(r.when, env)));
  const parts: Expr[] = [eligible, mandatory(bundle, s, action, kind, ctx)];
  const nk = bundle.needToKnow;
  const protect = Object.hasOwn(nk.protect, type) ? nk.protect[type] : undefined;
  if (protect && nk.mode !== 'off' && nk.mode !== 'dry_run') {
    const known = knownObjects(bundle, graph, type, protect.relation, s, ctx.now);
    const inKnown: Expr = { op: 'in', left: { path: 'resource.id' }, right: { value: known } };
    parts.push(protect.minLevel ? or([{ op: 'lt', left: { path: 'resource.level' }, right: { value: protect.minLevel } }, inKnown]) : inKnown);
  }
  // forbid fires on TRUE or UNKNOWN: keep the row only when the condition is certainly FALSE
  for (const r of bundle.abac.filter((x) => x.effect === 'forbid' && appliesTo(x, type, action))) parts.push(not(partial(r.when, env)));
  for (const r of contentRules(bundle).filter((x) => x.effect === 'deny' && (!x.actions || x.actions.includes(action)))) {
    const exempt = r.unless ? partial(r.unless, env) : FALSE;
    parts.push(or([exempt, not({ op: 'contains', left: { path: 'resource.contentClasses' }, right: { value: r.contentClass } })]));
  }
  return and(parts);
}

/** Whether the residual decides the action, rather than only its resource-independent stages. */
export function filterDecides(bundle: PolicyBundle, type: string, action: string): boolean {
  const def = actionDef(bundle, type, action);
  return def?.requiresSecondPerson !== true && !bundle.sod.some((rule) => rule.conflicting.includes(action));
}

/**
 * Residual predicate for "resources of `type` the subject may `action`". TRUE = all, FALSE = none.
 * Not covered by the residual (checked point-wise by the PEP on each row it acts on): obligations, the two-person
 * rule and separation of duty, which depend on per-row history rather than on resource columns.
 */
export function buildFilter(bundle: PolicyBundle, subject: Subject, type: string, action: string, ctx: Context, graph: Graph): Expr {
  const def = actionDef(bundle, type, action);
  if (!def || ctx.sessionExpired === true || subjectChainErrors(subject).length > 0) return FALSE;
  if (ctx.network !== 'trusted' && ctx.network !== 'untrusted') return FALSE;
  if (!validInstant(ctx.now) || contextSignalErrors(ctx).length > 0 || hasUnsafeNumber([subject, ctx])) return FALSE;
  const chain = principals(withLiveRoles(subject, ctx.now));
  if (chain.some((p) => !p.active)) return FALSE;
  const constrained = bundle.schema.resourceTypes[type]?.constrained === true;
  if (constrained && isWrite(def.kind) && !def.certified) return FALSE;
  if (constrained && def.certified && notCertified(bundle, { resource: { type }, action, context: ctx })) return FALSE;
  if (def.certified && procedureFindings(bundle, chain, type, action, ctx).length > 0) return FALSE;
  // IVPs read the resource only; anything else resolves to UNKNOWN, as in evaluate()
  const ivps = constrained && def.certified ? ivpsFor(bundle, type).map((i) => partial(i.check, { subject: null, action: null, context: null })) : [];
  return and([...chain.map((p) => forPrincipal(bundle, p, type, action, def.kind, ctx, graph)),
    contextFilter(bundle.context ?? [], type, action, def.kind, ctx), ...ivps]);
}
