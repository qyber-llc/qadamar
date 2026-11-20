// The decision pipeline, in the fixed order of docs/ARCHITECTURE.md §3.2: validation → inactive → eligibility (RBAC,
// ABAC permit) → mandatory (BLP, compartments, network, Biba) → need-to-know (ReBAC) → ABAC (including content attributes)
// → CBAC (context-based, Zero Trust) → Clark-Wilson (certified commands, integrity verification) → separation of duty. An AI agent is checked together with every person in its delegation chain: each principal
// must pass every stage. Any deny wins; a throwing or malformed rule denies; the decision is a pure function.
import { createHash } from 'node:crypto';
import { evalExpr, mayHold, type Env } from './conditions.ts';
import { contentRules } from './content.ts';
import { contextChecks, contextRuleApplies, contextRuleSelected } from './context.ts';
import { ivpsFor, verifyIntegrity } from './integrity.ts';
import { ACTION_KINDS, isWrite, mandatoryFindings, type Finding } from './mandatory.ts';
import { check, keyOf, windowState, type Graph } from './relations.ts';
import { procedureFindings, validatorsFor } from './procedures.ts';
import { principals, requestErrors } from './request.ts';
import type {
  ActionDef, Decision, Obligations, PolicyBundle, Request, StageName, Subject, TraceStep,
} from './types.ts';
import { canonical, policyVersion } from './version.ts';

const EMPTY: Obligations = { redact: [], maskClasses: [], notify: [] };

const union = (a: readonly string[], b: readonly string[] = []): string[] => [...new Set([...a, ...b])];

export function mergeObligations(a: Obligations, b: Partial<Obligations>): Obligations {
  const allow = b.fieldAllowlist === undefined ? a.fieldAllowlist
    : a.fieldAllowlist === undefined ? b.fieldAllowlist : a.fieldAllowlist.filter((f) => b.fieldAllowlist?.includes(f));
  const token = b.decisionToken ?? a.decisionToken;
  return {
    ...(allow === undefined ? {} : { fieldAllowlist: allow }),
    redact: union(a.redact, b.redact),
    maskClasses: union(a.maskClasses, b.maskClasses),
    notify: union(a.notify, b.notify),
    ...(token ? { decisionToken: token } : {}),
  };
}

/** Roles with their inherited roles, cycle-safe. */
export function expandRoles(bundle: PolicyBundle, roles: readonly string[]): string[] {
  const seen = new Set<string>();
  const stack = [...roles];
  while (stack.length > 0) {
    const r = stack.pop() as string;
    if (seen.has(r) || !Object.hasOwn(bundle.rbac.roles, r)) continue;
    seen.add(r);
    stack.push(...(bundle.rbac.roles[r]?.inherits ?? []));
  }
  return [...seen].sort();
}

const roleGrants = (bundle: PolicyBundle, role: string, type: string, action: string): boolean => bundle.rbac.roles[role]?.grants.some((g) =>
  (g.resourceType === type || g.resourceType === '*') && (g.actions.includes(action) || g.actions.includes('*'))) === true;

/** The subject's roles at `now`: its unconditional roles and the role assignments live then (CBAC grant duration).
 *  Without `now`, every assignment counts whatever its window (a caller asking what the subject could hold). */
export function liveRoles(subject: Subject, now?: string): string[] {
  const at = now === undefined ? undefined : Date.parse(now);
  const timed = (subject.roleAssignments ?? []).filter((a) => at === undefined || windowState(a, at) === 'live').map((a) => a.role);
  return [...new Set([...subject.roles, ...timed])];
}

/** The subject (and every delegator) as of `now`: `roles` also holds its live role assignments, so ABAC conditions,
 *  trusted roles and RBAC see one role set. An assignment outside its window counts for nothing. */
export function withLiveRoles(subject: Subject, now: string): Subject {
  return { ...subject, roles: liveRoles(subject, now), ...(subject.delegator ? { delegator: withLiveRoles(subject.delegator, now) } : {}) };
}

export function rbacGrant(bundle: PolicyBundle, subject: Subject, type: string, action: string, now?: string): string | null {
  for (const role of expandRoles(bundle, liveRoles(subject, now))) if (roleGrants(bundle, role, type, action)) return `RBAC.${role}`;
  return null;
}

/** The declared action, own properties only (an action named "constructor" is not declared). */
export function actionDef(bundle: PolicyBundle, type: string, action: string): ActionDef | null {
  const rt = Object.hasOwn(bundle.schema.resourceTypes, type) ? bundle.schema.resourceTypes[type] : undefined;
  const def = rt && Object.hasOwn(rt.actions, action) ? rt.actions[action] : undefined;
  return def && ACTION_KINDS.has(def.kind) ? def : null;
}

export const appliesTo = (rule: { resourceTypes?: readonly string[]; actions?: readonly string[] }, type: string, action: string): boolean =>
  (!rule.resourceTypes || rule.resourceTypes.includes(type)) && (!rule.actions || rule.actions.includes(action));

/** Stage prefix: the subject itself, then each person it acts for. */
const prefixOf = (i: number): string => (i === 0 ? '' : 'DELEGATION.');

class Run {
  readonly trace: TraceStep[] = [];
  readonly denies: Finding[] = [];
  readonly basis: string[] = [];
  readonly wouldDeny: string[] = [];
  obligations: Obligations = EMPTY;

  deny(stage: StageName, f: Finding & Partial<Pick<TraceStep, 'policyRule' | 'requirement' | 'observed' | 'kind'>>): void {
    this.denies.push(f);
    this.trace.push({ stage, rule: f.rule, outcome: 'deny', reason: f.reason,
      ...(f.policyRule ? { policyRule: f.policyRule } : {}), ...(f.requirement ? { requirement: f.requirement } : {}),
      ...(f.observed !== undefined ? { observed: f.observed } : {}), ...(f.kind ? { kind: f.kind } : {}) });
  }

  pass(stage: StageName, rule: string, reason: string, path?: readonly string[]): void {
    this.basis.push(rule);
    this.trace.push({ stage, rule, outcome: 'pass', reason, ...(path ? { path } : {}) });
  }

  oblige(stage: StageName, rule: string, reason: string, o: Partial<Obligations>, details: Pick<TraceStep, 'policyRule' | 'kind'> = {}): void {
    this.obligations = mergeObligations(this.obligations, o);
    this.trace.push({ stage, rule, outcome: 'obligation', reason, ...details });
  }

  /** A rule that throws denies (fail closed). */
  guarded(stage: StageName, rule: string, fn: () => void): void {
    try {
      fn();
    } catch (err: unknown) {
      this.deny(stage, { rule: 'ENGINE.RULE_ERROR', reason: `${rule} failed: ${err instanceof Error ? err.message : 'unknown error'}` });
    }
  }
}

/** The relations of `type` that feed `relation` on the same object through computed rewrites, itself included. */
function feeding(bundle: PolicyBundle, type: string, relation: string): Set<string> {
  const relations = bundle.schema.resourceTypes[type]?.relations ?? {};
  const out = new Set([relation]);
  const stack = [relation];
  while (stack.length > 0) {
    const r = stack.pop() as string;
    for (const w of Object.hasOwn(relations, r) ? relations[r]?.union ?? [] : []) {
      if ('computed' in w && !out.has(w.computed)) { out.add(w.computed); stack.push(w.computed); }
    }
  }
  return out;
}

/** Informational: the decision is whatever the remaining grants give. */
function grantSkipped(run: Run, prefix: string, state: 'expired' | 'not_yet', policyRule: string, requirement: string, now: string, what: string): void {
  const expired = state === 'expired';
  run.trace.push({ stage: 'cbac', rule: `${prefix}CBAC.GRANT_${expired ? 'EXPIRED' : 'NOT_YET'}`, outcome: 'skip', policyRule, requirement, observed: now,
    reason: `${what} is ${expired ? 'expired' : 'not yet active'}: it does not exist for this request` });
}

function eligibility(run: Run, bundle: PolicyBundle, req: Request, env: Env, who: Subject, prefix: string): void {
  const { type } = req.resource;
  const grant = rbacGrant(bundle, who, type, req.action, req.context.now);
  if (grant) return run.pass('rbac', `${prefix}${grant}`, `role grants ${req.action} on ${type}`);
  // CBAC grant duration: a role assignment outside its window does not exist for this request; the trace says which
  const nowMs = Date.parse(req.context.now);
  for (const assignment of who.roleAssignments ?? []) {
    const state = windowState(assignment, nowMs);
    if (state === 'live' || !expandRoles(bundle, [assignment.role]).some((role) => roleGrants(bundle, role, type, req.action))) continue;
    grantSkipped(run, prefix, state, assignment.role, 'roleAssignment', req.context.now, `role assignment ${assignment.role}`);
  }
  for (const rule of bundle.abac.filter((r) => r.effect === 'permit' && appliesTo(r, type, req.action))) {
    let ok = false;
    run.guarded('abac', rule.id, () => { ok = evalExpr(rule.when, { ...env, subject: who }); });
    if (ok) return run.pass('abac', `${prefix}ABAC.${rule.id}`, rule.description);
  }
  run.deny('rbac', { rule: `${prefix}RBAC.NOT_ELIGIBLE`, reason: `no role or permit rule allows ${req.action} on ${type}` });
}

function needToKnow(run: Run, bundle: PolicyBundle, req: Request, graph: Graph, who: Subject, prefix: string): void {
  const nk = bundle.needToKnow;
  const protect = Object.hasOwn(nk.protect, req.resource.type) ? nk.protect[req.resource.type] : undefined;
  if (nk.mode === 'off' || !protect || req.resource.level < (protect.minLevel ?? 0)) return;
  const r = check(bundle, graph, req.resource, protect.relation, who, req.context.now);
  if (r.ok) {
    run.pass('need_to_know', `${prefix}NTK.${protect.relation}`, `reason to know via ${protect.relation}`, r.path);
    if (r.breakGlass) {
      run.oblige('need_to_know', `${prefix}NTK.BREAK_GLASS`, 'break-glass access: notify and review', { notify: nk.breakGlassNotify });
    }
    return;
  }
  // a direct grant outside its window does not exist for this request (CBAC grant duration): the trace says so
  const nowMs = Date.parse(req.context.now);
  const feeds = feeding(bundle, req.resource.type, protect.relation);
  for (const tuple of graph.byObject.get(keyOf(req.resource)) ?? []) {
    if (!feeds.has(tuple.relation) || tuple.subjectRelation || keyOf(tuple.subject) !== keyOf(who)) continue;
    const state = windowState(tuple, nowMs);
    if (state !== 'live') grantSkipped(run, prefix, state, `NTK.${protect.relation}`, 'relationTuple', req.context.now, `relation grant ${tuple.relation}`);
  }
  const f = { rule: `${prefix}NTK.NO_REASON`, reason: `no ${protect.relation} relation to ${req.resource.type}:${req.resource.id}` };
  if (nk.mode === 'dry_run') {
    run.wouldDeny.push(f.rule);
    run.trace.push({ stage: 'need_to_know', rule: f.rule, outcome: 'would_deny', reason: `${f.reason} (dry run)` });
  } else {
    run.deny('need_to_know', f); // enforce, and any unknown mode (fail closed)
  }
}

function abac(run: Run, bundle: PolicyBundle, req: Request, env: Env, prefix: string): void {
  for (const rule of bundle.abac) {
    if (rule.effect === 'permit' || !appliesTo(rule, req.resource.type, req.action)) continue;
    run.guarded('abac', rule.id, () => {
      if (rule.effect !== 'forbid' && rule.effect !== 'obligation') throw new Error(`unknown effect ${String(rule.effect)}`);
      if (!mayHold(rule.when, env)) return; // a forbid that cannot be evaluated fires (fail closed)
      if (rule.effect === 'forbid') run.deny('abac', { rule: `${prefix}ABAC.${rule.id}`, reason: rule.description });
      else run.oblige('abac', `${prefix}ABAC.${rule.id}`, rule.description, rule.obligations ?? {});
    });
  }
}

function content(run: Run, bundle: PolicyBundle, req: Request, env: Env, prefix: string): void {
  const classes = req.resource.contentClasses ?? [];
  for (const rule of contentRules(bundle)) {
    if (!classes.includes(rule.contentClass) || (rule.actions && !rule.actions.includes(req.action))) continue;
    run.guarded('abac', rule.id, () => {
      if (rule.effect !== 'deny' && rule.effect !== 'mask' && rule.effect !== 'redact') throw new Error(`unknown effect ${String(rule.effect)}`);
      if (rule.unless && evalExpr(rule.unless, env)) return; // an exemption must hold for certain
      const id = `${prefix}ABAC.CONTENT_${rule.effect === 'deny' ? 'DENY' : rule.effect === 'mask' ? 'MASK' : 'REDACT'}`;
      const details = { policyRule: rule.id, kind: 'content' as const };
      if (rule.effect === 'deny') run.deny('abac', { rule: id, reason: rule.description, ...details });
      else if (rule.effect === 'mask') run.oblige('abac', id, rule.description, { maskClasses: [rule.contentClass] }, details);
      else run.oblige('abac', id, rule.description, { redact: rule.fields ?? [] }, details);
    });
  }
}

function situational(run: Run, bundle: PolicyBundle, req: Request, kind: Parameters<typeof contextRuleApplies>[2]): void {
  if (req.context.sessionExpired === true) run.deny('cbac', { rule: 'CBAC.SESSION_EXPIRED', reason: 'the request session is known to be expired', observed: req.context.sessionId ?? null });
  for (const rule of bundle.context ?? []) {
    if (!contextRuleApplies(rule, req, kind)) continue;
    run.guarded('cbac', rule.id, () => {
      const checks = contextChecks(rule, req.context);
      if (checks.length === 0) throw new Error(`context rule ${rule.id} has no requirements`);
      for (const item of checks) {
        const step = { policyRule: rule.id, requirement: item.requirement, observed: item.observed };
        const reason = `CBAC rule ${rule.id}: ${item.detail}; observed ${JSON.stringify(item.observed)}`;
        if (item.ok) run.trace.push({ stage: 'cbac', rule: item.code, outcome: 'pass', reason, ...step });
        else run.deny('cbac', { rule: item.code, reason, ...step });
      }
    });
  }
}

/** Consumption must carry the state the command commits: the item's IVPs (C1) or the command's input validators (C5) check it. */
export function postStateRequired(bundle: PolicyBundle, type: string, action: string, constrained: boolean): boolean {
  return (constrained && ivpsFor(bundle, type).length > 0) || validatorsFor(bundle, type, action).length > 0;
}

const fingerprints = new WeakMap<PolicyBundle, Map<string, string>>();
/** What a certification certifies (Clark-Wilson C2/E2): every part of the bundle that decides this one procedure, hashed.
 *  Per procedure rather than the whole policy version, so a change elsewhere does not void every record: the action's
 *  definition and its type's constrained flag, the type's IVPs, the procedure's input validators and PEP binding, the
 *  roles that grant it (after inheritance), ABAC (including content attributes), CBAC and SoD rules that apply to it, need-to-know on its type, and
 *  the mandatory section (global, but it decides every write). Change any of these and the procedure needs recertifying. */
export function procedureFingerprint(bundle: PolicyBundle, type: string, action: string): string {
  let cache = fingerprints.get(bundle);
  if (!cache) { cache = new Map(); fingerprints.set(bundle, cache); }
  const key = JSON.stringify([type, action]);
  const hit = cache.get(key);
  if (hit) return hit;
  const typeDef = Object.hasOwn(bundle.schema.resourceTypes, type) ? bundle.schema.resourceTypes[type] : undefined;
  const cw = bundle.clarkWilson;
  const protect = Object.hasOwn(bundle.needToKnow.protect, type) ? bundle.needToKnow.protect[type] : undefined;
  const kind = typeDef?.actions[action]?.kind;
  const situational = kind ? (bundle.context ?? []).filter((rule) => contextRuleSelected(rule, type, action, kind)) : [];
  const semantics = {
    v: 1, type, action, constrained: typeDef?.constrained === true, def: actionDef(bundle, type, action),
    ivps: ivpsFor(bundle, type), validators: validatorsFor(bundle, type, action), pepBinding: (cw.requirePepBinding ?? []).includes(type),
    roles: Object.keys(bundle.rbac.roles).filter((role) => expandRoles(bundle, [role]).some((r) => roleGrants(bundle, r, type, action))).sort(),
    abac: bundle.abac.filter((r) => appliesTo(r, type, action)),
    // content-attribute rules keep the key `cbac`: renaming it would make every recorded certification stale
    cbac: contentRules(bundle).filter((r) => !r.actions || r.actions.includes(action)),
    ...(situational.length ? { context: situational } : {}),
    sod: bundle.sod.filter((r) => r.conflicting.includes(action)),
    // need-to-know resolves the protecting relation through any type's rewrites (parents, usersets), so all of them count
    needToKnow: protect ? {
      mode: bundle.needToKnow.mode, protect, breakGlassMaxHours: bundle.needToKnow.breakGlassMaxHours,
      relations: Object.fromEntries(Object.entries(bundle.schema.resourceTypes).map(([t, d]) => [t, d.relations ?? null])),
      subjectRelations: bundle.schema.subjectRelations ?? null,
    } : null,
    mandatory: bundle.mandatory,
  };
  const value = `cw1.${createHash('sha256').update(canonical(semantics)).digest('hex')}`;
  cache.set(key, value);
  return value;
}

/** C2 enforced, for a type that requires certification: "missing" without any record of the procedure, "stale" when
 *  its records certified another definition of it (procedureFingerprint), undefined when one is current. */
export function certificationGap(bundle: PolicyBundle, req: Pick<Request, 'action' | 'context'> & { resource: { type: string } }): 'missing' | 'stale' | undefined {
  if (!(bundle.clarkWilson.requireCertification ?? []).includes(req.resource.type)) return undefined;
  const records = (req.context.certified ?? []).filter((c) => c.resourceType === req.resource.type && c.action === req.action);
  if (records.length === 0) return 'missing';
  const current = procedureFingerprint(bundle, req.resource.type, req.action);
  return records.some((c) => c.fingerprint === current) ? undefined : 'stale';
}
export const notCertified = (bundle: PolicyBundle, req: Parameters<typeof certificationGap>[1]): boolean => certificationGap(bundle, req) !== undefined;

function clarkWilsonAndSod(run: Run, bundle: PolicyBundle, req: Request, def: ActionDef, constrained: boolean, chain: readonly Subject[]): void {
  if (constrained && isWrite(def.kind) && !def.certified) {
    run.deny('clark_wilson', { rule: 'CW.UNCERTIFIED_TP', reason: `${req.action} is not a certified command for a constrained ${req.resource.type}` });
  }
  if (def.certified) {
    run.oblige('clark_wilson', 'CW.DECISION_TOKEN', 'certified command: single-use decision token bound to the resource version', {
      decisionToken: { ttlSeconds: bundle.clarkWilson.tokenTtlSeconds, resourceVersion: req.resource.version ?? null,
        ...(postStateRequired(bundle, req.resource.type, req.action, constrained) ? { postState: true as const } : {}) },
    });
    for (const f of procedureFindings(bundle, chain, req.resource.type, req.action, req.context)) run.deny('clark_wilson', f);
  }
  const gap = constrained && def.certified ? certificationGap(bundle, req) : undefined;
  if (gap === 'missing') run.deny('clark_wilson', { rule: 'CW.NOT_CERTIFIED', reason: `${req.action} on ${req.resource.type} has no certification record` });
  if (gap === 'stale') {
    run.deny('clark_wilson', { rule: 'CW.CERTIFICATION_STALE', reason: `${req.action} on ${req.resource.type} changed since it was certified: recertify it` });
  }
  // C1: a certified command runs only on a constrained item in a valid state (no IVP declared: nothing to check)
  if (constrained && def.certified) {
    for (const r of verifyIntegrity(bundle, req.resource)) {
      if (!r.ok) run.deny('clark_wilson', { rule: `CW.IVP.${r.ivp}`, reason: `integrity verification failed: ${r.reason}` });
    }
  }
  const claimedMaker = req.context.makerId;
  const serverMaker = req.context.serverMakerId;
  if (serverMaker !== undefined && claimedMaker !== undefined && String(serverMaker) !== String(claimedMaker)) {
    run.deny('sod', { rule: 'SOD.MAKER_MISMATCH', reason: 'the caller-supplied maker contradicts the performed-action history' });
  }
  if (def.requiresSecondPerson) {
    const maker = serverMaker ?? claimedMaker;
    if (maker === undefined) run.deny('sod', { rule: 'SOD.MAKER_UNKNOWN', reason: 'two-person rule: the maker is not known, so the check fails closed' });
    else if (chain.some((p) => String(p.id) === String(maker))) {
      run.deny('sod', { rule: 'SOD.SELF_APPROVAL', reason: 'two-person rule: the maker cannot perform this action' });
    }
  }
  const prior = req.context.priorActions ?? [];
  for (const rule of bundle.sod) {
    if (!rule.conflicting.includes(req.action)) continue;
    const clash = prior.filter((a) => a !== req.action && rule.conflicting.includes(a));
    if (clash.length > 0) run.deny('sod', { rule: `SOD.${rule.id}`, reason: `${rule.description} (already did ${clash.join(', ')})` });
  }
}

function pipeline(run: Run, bundle: PolicyBundle, req: Request, graph: Graph): void {
  const errors = requestErrors(req);
  if (errors.length > 0) return run.deny('engine', { rule: 'ENGINE.MALFORMED_REQUEST', reason: errors.join('; ') });
  const { resource, action, context } = req;
  const subject = withLiveRoles(req.subject, context.now);
  const def = actionDef(bundle, resource.type, action);
  if (!def) return run.deny('engine', { rule: 'SCHEMA.UNKNOWN_ACTION', reason: `${action} on ${resource.type} is not declared` });
  const chain = principals(subject);
  for (const [i, p] of chain.entries()) {
    if (!p.active) return run.deny(i === 0 ? 'inactive' : 'delegation', { rule: i === 0 ? 'CORE.INACTIVE' : 'DELEGATION.INACTIVE', reason: `${p.id} is inactive` });
  }
  const typeDef = bundle.schema.resourceTypes[resource.type];
  const envOf = (p: Subject): Env => ({ subject: p, resource, action: { name: action, kind: def.kind }, context });
  chain.forEach((p, i) => eligibility(run, bundle, req, envOf(p), p, prefixOf(i)));
  chain.forEach((p, i) => {
    for (const f of mandatoryFindings(bundle, p, resource, action, def.kind, context)) {
      run.deny(i === 0 ? 'mandatory' : 'delegation', { rule: `${prefixOf(i)}${f.rule}`, reason: i === 0 ? f.reason : `${p.id}: ${f.reason}` });
    }
  });
  if (run.denies.length === 0) run.trace.push({ stage: 'mandatory', rule: 'MAC', outcome: 'pass', reason: 'level, compartments, network and integrity satisfied' });
  chain.forEach((p, i) => needToKnow(run, bundle, req, graph, p, prefixOf(i)));
  chain.forEach((p, i) => abac(run, bundle, req, envOf(p), prefixOf(i)));
  chain.forEach((p, i) => content(run, bundle, req, envOf(p), prefixOf(i)));
  situational(run, bundle, req, def.kind);
  clarkWilsonAndSod(run, bundle, req, def, typeDef?.constrained === true, chain);
}

export function evaluate(bundle: PolicyBundle, req: Request, graph: Graph): Decision {
  const run = new Run();
  run.guarded('engine', 'pipeline', () => pipeline(run, bundle, req, graph));
  const allowed = run.denies.length === 0;
  let version = 'pv.invalid';
  try { version = policyVersion(bundle); } catch { /* an unhashable bundle still yields a decision: the deny above */ }
  return {
    decision: allowed,
    rules: allowed ? [...new Set(run.basis)] : [...new Set(run.denies.map((d) => d.rule))],
    reasons: allowed ? [] : run.denies.map((d) => d.reason),
    // a denied request carries no obligations: nothing is released
    obligations: allowed ? run.obligations : EMPTY,
    trace: run.trace,
    wouldDeny: run.wouldDeny,
    policyVersion: version,
  };
}
