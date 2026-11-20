import { randomUUID } from 'node:crypto';
import { actionDef, contentRules, evaluate, indexTuples, validInstant, windowOf, windowState, rbacGrant, simulate, validateBundle, policyVersion, procedureFingerprint, mandatoryWeakenings, canonical, levelInheritanceErrors } from '../../../core/src/index.ts';
import type { Context, Impact, ImpactCell, ImpactContextClass, Subject, Resource, PolicyBundle, Expr } from '../../../core/src/index.ts';
import { impactContexts, IMPACT_CONTEXT_CLASS_LIMIT } from './context-impact.ts';
import type { State, StoredTuple, Change, ScimCredentialOrigin, PepCredentialOrigin, RetiredLog } from '../store.ts';
import type { Runtime } from '../runtime.ts';
import { certificationCurrent, findRef, graphOf, hydrated, inScope, resourceScope, sodInput, subject, subjectInScope, withCertified, withPerformed } from '../runtime.ts';
import { affectedImpact, AffectedSetLimit } from './impact-analysis.ts';
import type { User } from '../auth.ts';
import { allowed, ownerOnly } from '../auth.ts';
import { HttpError, object, string, reason } from '../http.ts';
import { signPolicy } from '../policy-signature.ts';
import { applyResources, checkResources, MAX_BATCH, parseRef, parseResource, resourceKey, retiredId, storedBasis, validBasis } from '../resource-registry.ts';
import { withRecordDeltas, type RecordDelta } from '../record-deltas.ts';

const invalid = (message: string): never => { throw new HttpError(422, 'unprocessable', message); };
function keys(value: Record<string, unknown>, permitted: string[]): void {
  if (Object.keys(value).some((k) => !permitted.includes(k))) invalid('Unknown payload field');
}
function strings(value: unknown): value is string[] { return Array.isArray(value) && value.every((x) => typeof x === 'string'); }
function instant(value: unknown): string {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) return invalid('Invalid timestamp');
  return new Date(value).toISOString();
}
/** CBAC grant duration on roles: bounded, known roles, ISO instants in order. A future start is refused as for tuples:
 *  the impact of a grant is reviewed when it takes effect. */
function roleAssignments(rt: Runtime, value: unknown): void {
  if (!Array.isArray(value) || value.length > 256) invalid('Invalid role assignments');
  const now = Date.parse(rt.now());
  for (const item of value as unknown[]) {
    const a = object(item);
    keys(a, ['role', 'notBefore', 'notAfter']);
    if (!Object.hasOwn(rt.store.state.bundle.rbac.roles, string(a.role))) invalid('Unknown role');
    if ((a.notBefore !== undefined && !validInstant(a.notBefore)) || (a.notAfter !== undefined && !validInstant(a.notAfter))) invalid('Invalid timestamp');
    const from = a.notBefore === undefined ? undefined : Date.parse(a.notBefore as string);
    const to = a.notAfter === undefined ? undefined : Date.parse(a.notAfter as string);
    if (from !== undefined && from > now) invalid('Future grants require a new proposal when effective');
    if (to !== undefined && (to <= now || (from !== undefined && to <= from))) invalid('Invalid validity window');
  }
}
function attributes(rt: Runtime, set: Record<string, unknown>, subject: boolean): void {
  keys(set, subject ? ['clearance', 'compartments', 'roles', 'roleAssignments', 'active'] : ['level', 'compartments', 'integrity']);
  for (const [k, v] of Object.entries(set)) {
    if (['clearance', 'level'].includes(k) && ![0, 1, 2, 3].includes(v as number)) invalid('Level must be 0..3');
    if (k === 'active' && typeof v !== 'boolean') invalid('active must be boolean');
    if (k === 'integrity' && !['derived', 'extracted', 'system', 'verified'].includes(String(v))) invalid('Invalid integrity');
    if (k === 'roleAssignments') roleAssignments(rt, v);
    if (k === 'roles' && (!strings(v) || v.some((r) => !Object.hasOwn(rt.store.state.bundle.rbac.roles, r)))) invalid('Unknown role');
    if (k === 'compartments' && (!strings(v) || v.some((c) => !rt.store.state.bundle.schema.compartments.includes(c)))) invalid('Unknown compartment');
  }
}
export function proposalPermission(user: User, kind: string, review = false): void {
  // SCIM subject sets come only from the provisioning service, which can propose nothing else
  if (kind === 'scim_subjects' || user.roles.includes('scim_provisioner')) {
    if (kind === 'scim_subjects' && user.roles.includes('scim_provisioner')) return;
    throw new HttpError(403, 'forbidden');
  }
  // resource registrations come only from a PEP credential bound to resource types, which can propose nothing else
  if (kind === 'register_resources' || user.roles.includes('resource_registrar')) {
    if (kind === 'register_resources' && user.roles.includes('resource_registrar')) return;
    throw new HttpError(403, 'forbidden');
  }
  if (kind === 'erase_subject') { if (user.roles.includes('security_officer')) return; throw new HttpError(403, 'forbidden'); }
  // Clark-Wilson certification is the security officer's, never the access administrator's
  if (kind === 'certify_tp') { if (user.roles.includes('security_officer')) return; throw new HttpError(403, 'forbidden'); }
  if (user.roles.some((r) => ['access_admin', 'security_officer'].includes(r))) return;
  if (kind === 'publish_policy' && user.roles.includes('policy_author')) return;
  if (user.roles.includes('resource_owner') && (kind === 'remove_tuple' || review)) return;
  throw new HttpError(403, 'forbidden');
}
function tupleCandidate(rt: Runtime, user: User, p: Record<string, unknown>): { state: State; payload: Record<string, unknown> } {
  const s = rt.store.state;
  keys(p, ['object', 'relation', 'subject', 'subjectRelation', 'notBefore', 'notAfter', 'validFrom', 'validTo', 'reason', 'grantedBy', 'breakGlass', 'replacesTupleId']);
  if (p.breakGlass === true) throw new HttpError(403, 'forbidden', 'Use the break-glass endpoint');
  const obj = object(p.object, 'object must be an object {"type", "id"}'); const who = object(p.subject, 'subject must be an object {"type", "id"}');
  keys(obj, ['type', 'id']); keys(who, ['type', 'id']);
  const target = { type: string(obj.type), id: string(obj.id) };
  const person = { type: string(who.type), id: string(who.id) };
  const relation = string(p.relation);
  const def = (Object.hasOwn(s.bundle.schema.resourceTypes, target.type) ? s.bundle.schema.resourceTypes[target.type]?.relations : undefined) ?? (Object.hasOwn(s.bundle.schema.subjectRelations ?? {}, target.type) ? s.bundle.schema.subjectRelations?.[target.type] : undefined);
  if (!def || !Object.hasOwn(def, relation)) invalid('Unknown relation');
  if (!s.resources.some((r) => r.id === target.id && r.type === target.type) && !s.subjects.some((r) => r.id === target.id && r.type === target.type) && !s.tuples.some((t) => t.object.id === target.id && t.object.type === target.type)) invalid('Unknown tuple object');
  if (!s.subjects.some((r) => r.id === person.id && r.type === person.type) && !s.resources.some((r) => r.id === person.id && r.type === person.type) && !s.tuples.some((t) => t.object.id === person.id && t.object.type === person.type)) invalid('Unknown tuple subject');
  if (person.id === user.id) throw new HttpError(403, 'forbidden', 'Self-grant forbidden');
  if (ownerOnly(user)) resourceScope(rt, user, target);
  // CBAC grant duration: notBefore/notAfter; validFrom/validTo are the names this API took before them
  if ((p.notBefore !== undefined && p.validFrom !== undefined) || (p.notAfter !== undefined && p.validTo !== undefined)) invalid('Invalid validity window');
  const start = p.notBefore ?? p.validFrom; const end = p.notAfter ?? p.validTo;
  const from = start === undefined ? rt.now() : instant(start);
  if (Date.parse(from) > Date.parse(rt.now())) invalid('Future grants require a new proposal when effective');
  const to = end === undefined ? undefined : instant(end);
  if (['granted', 'allocated'].includes(relation) && (!to || Date.parse(to) > Date.parse(rt.now()) + 90 * 86400000)) invalid('Grant expiry required within 90 days');
  if (to && (Date.parse(to) <= Date.parse(rt.now()) || Date.parse(to) <= Date.parse(from))) invalid('Invalid validity window');
  if (p.grantedBy !== undefined) string(p.grantedBy);
  if (p.breakGlass !== undefined && typeof p.breakGlass !== 'boolean') invalid('breakGlass must be boolean');
  const subjectRelation = p.subjectRelation === undefined ? undefined : string(p.subjectRelation);
  if (subjectRelation && !Object.hasOwn((Object.hasOwn(s.bundle.schema.subjectRelations ?? {}, person.type) ? s.bundle.schema.subjectRelations?.[person.type] : undefined) ?? (Object.hasOwn(s.bundle.schema.resourceTypes, person.type) ? s.bundle.schema.resourceTypes[person.type]?.relations : undefined) ?? {}, subjectRelation)) invalid('Unknown subject relation');
  const replacesTupleId = p.replacesTupleId;
  if (replacesTupleId !== undefined) {
    const old = s.tuples.find((t) => t.id === replacesTupleId);
    if (!old || old.breakGlass || windowState(old, Date.parse(rt.now())) === 'expired' || old.subject.id === user.id || old.grantedBy === user.id || canonical(old.object) !== canonical(target) || canonical(old.subject) !== canonical(person) || old.relation !== relation || old.subjectRelation !== subjectRelation) invalid('Invalid certification');
  }
  const payload = { ...(replacesTupleId === undefined ? {} : { replacesTupleId }), object: target, relation, subject: person, notBefore: from, ...(to ? { notAfter: to } : {}),
    ...(subjectRelation ? { subjectRelation } : {}), grantedBy: user.id, ...(p.reason === undefined ? {} : { reason: string(p.reason) }) };
  const tuple = { ...payload, id: randomUUID() };
  const deltas: RecordDelta[] = [{ kind: 'tuple', op: 'put', type: '', id: tuple.id, value: tuple }];
  if (typeof replacesTupleId === 'string') deltas.unshift({ kind: 'tuple', op: 'delete', type: '', id: replacesTupleId });
  const state = withRecordDeltas({ ...s, tuples: [...s.tuples.filter((t) => t.id !== replacesTupleId), tuple] }, deltas);
  return { state, payload };
}
function scimCandidate(rt: Runtime, p: Record<string, unknown>): { state: State; payload: Record<string, unknown> } {
  keys(p, ['subjects']);
  const inputSubjects: unknown = p.subjects;
  if (!Array.isArray(inputSubjects) || inputSubjects.length < 1 || inputSubjects.length > 1000) return invalid('Invalid SCIM subject set');
  const subjects = inputSubjects.map((value) => {
    const input = object(value);
    keys(input, ['type', 'id', 'active', 'roles', 'clearance', 'compartments', 'integrity', 'attrs']);
    const subject = input as unknown as Subject;
    if (!['user', 'group'].includes(subject.type) || typeof subject.id !== 'string' || !subject.id || subject.id.length > 256 || typeof subject.active !== 'boolean' ||
      ![0, 1, 2, 3].includes(subject.clearance) || subject.integrity !== 'verified' || !strings(subject.roles) || !strings(subject.compartments)) invalid('Invalid SCIM subject');
    if (subject.roles.some((role) => !Object.hasOwn(rt.store.state.bundle.rbac.roles, role))) invalid('Unknown role');
    if (subject.type === 'group' && subject.roles.length) invalid('SCIM groups cannot hold roles themselves');
    const old = rt.store.state.subjects.find((item) => item.id === subject.id);
    if (old && (old.type !== subject.type || old.clearance !== subject.clearance || old.integrity !== subject.integrity || canonical(old.compartments) !== canonical(subject.compartments))) invalid('SCIM cannot change clearance, integrity, compartments or subject type');
    if (!old && (subject.clearance !== 0 || subject.compartments.length !== 0)) invalid('New SCIM subjects start without clearance or compartments');
    const attrs = subject.attrs === undefined ? {} : object(subject.attrs);
    const managed = ['name', 'scimUserName', 'scimExternalId', 'scimDisplayName'];
    if (Object.entries(attrs).some(([key, value]) => managed.includes(key) ? typeof value !== 'string' || value.length > 256 : !Object.hasOwn(old?.attrs ?? {}, key))) invalid('Unsupported SCIM subject attribute');
    for (const [key, value] of Object.entries(old?.attrs ?? {})) if (!managed.includes(key) && canonical(attrs[key]) !== canonical(value)) invalid('SCIM cannot change unmodelled attributes');
    // SCIM does not manage time-bounded role assignments: an update keeps the ones the access administrator set
    return old?.roleAssignments ? { ...subject, roleAssignments: old.roleAssignments } : subject;
  });
  if (new Set(subjects.map((subject) => subject.id)).size !== subjects.length) invalid('Duplicate SCIM subject');
  const ids = new Set(subjects.map((subject) => subject.id));
  const deltas = subjects.map((subject): RecordDelta => ({ kind: 'subject', op: 'put', type: subject.type, id: subject.id, value: subject }));
  return { state: withRecordDeltas({ ...rt.store.state, subjects: [...rt.store.state.subjects.filter((subject) => !ids.has(subject.id)), ...subjects] }, deltas), payload: { subjects } };
}
/** register_resources: what a PEP may not change alone (resource-registry.ts reviewReasons), with what each resource
 *  was when it was proposed (storedBasis); approval is refused (stale) once one of them changed. */
function registrationCandidate(rt: Runtime, p: Record<string, unknown>): { state: State; payload: Record<string, unknown> } {
  keys(p, ['resources', 'basis', 'retire', 'retireBasis']);
  const s = rt.store.state;
  const list = p.resources; const basis = p.basis; const gone = p.retire ?? []; const goneBasis = p.retireBasis ?? [];
  if (!Array.isArray(list) || !Array.isArray(basis) || basis.length !== list.length || !basis.every(validBasis) || !Array.isArray(gone) ||
    !Array.isArray(goneBasis) || goneBasis.length !== gone.length || !goneBasis.every(validBasis) ||
    list.length + gone.length < 1 || list.length + gone.length > MAX_BATCH) return invalid('Invalid resource registration');
  const resources = list.map((x, i) => parseResource(s.bundle, x, `resources[${i}]`));
  const refs = gone.map((x, i) => parseRef(x, `retire[${i}]`, s.bundle));
  if (resources.some((r) => r.version === undefined) || new Set([...resources, ...refs].map(resourceKey)).size !== resources.length + refs.length) invalid('Invalid resource registration');
  if (refs.some((r) => !findRef(s.resources, r.id, r.type))) invalid('Only a registered resource can be retired');
  const state = applyResources(s, resources, refs);
  checkResources(state, resources);
  return { state, payload: { resources, basis, ...(refs.length ? { retire: refs, retireBasis: goneBasis } : {}) } };
}
/** The tombstones of the live resources `refs` names (unknown ones are left out). */
const registrationMoved = (state: State, retired: RetiredLog, p: Record<string, unknown>): boolean =>
  (p.resources as Resource[]).some((r, i) => storedBasis(state, retired, r) !== (p.basis as string[])[i]) ||
  ((p.retire ?? []) as Array<{ type: string; id: string }>).some((r, i) => storedBasis(state, retired, r) !== (p.retireBasis as string[])[i]);
/** Denials that say nothing about the certifier: the item's current state, the missing record itself, the input, history. */
const STATE_ONLY = /^(?:DELEGATION\.)?(?:CW\.IVP\.|CW\.NOT_CERTIFIED$|CW\.CERTIFICATION_STALE$|CW\.POST_STATE_REQUIRED$|CW\.INPUT_REQUIRED$|CW\.INPUT\.|SOD\.)/;
/** Clark-Wilson E4: whoever certifies a procedure must not be able to execute it. The console user is the PDP subject
 *  with the same id (every type); none fails closed. A role granting the action counts at once; otherwise the engine
 *  decides on every item of the type, on the trusted network with an independent maker, so roles held through
 *  delegation, ABAC permits and relations all count, and a deny caused only by the item's state or history does not. */
function executes(rt: Runtime, id: string, type: string, action: string): boolean {
  const state = rt.store.state; const bundle = state.bundle;
  const who = state.subjects.filter((s) => s.id === id).map((s) => subject(state, s.id, s.type)).filter((s): s is Subject => s !== undefined);
  if (who.length === 0) return true;
  let maker = 'e4-independent-maker';
  while (state.subjects.some((s) => s.id === maker)) maker += '-';
  const context = withCertified(state, { network: 'trusted', now: rt.now(), makerId: maker });
  const graph = graphOf(state.tuples);
  // a role assignment counts unless it already ended: one starting later is a role the certifier will hold
  const later = (s: Subject): Subject => ({ ...s, roleAssignments: (s.roleAssignments ?? []).filter((a) => windowState(a, Date.parse(rt.now())) !== 'expired') });
  return who.some((s) => rbacGrant(bundle, later(s), type, action) !== null || state.resources.some((resource) => {
    if (resource.type !== type) return false;
    // as through a PEP bound to the certifier's population (E3 must not clear a certifier)
    const d = evaluate(bundle, { subject: s, resource, action, context: { ...context, pepSubjectTypes: [s.type] } }, graph);
    return d.decision || d.rules.every((rule) => STATE_ONLY.test(rule));
  }));
}
function certifyCandidate(rt: Runtime, user: User, p: Record<string, unknown>): { state: State; payload: Record<string, unknown> } {
  keys(p, ['resourceType', 'action']);
  const resourceType = string(p.resourceType); const action = string(p.action);
  const b = rt.store.state.bundle;
  if (!(Object.hasOwn(b.schema.resourceTypes, resourceType) && b.schema.resourceTypes[resourceType]?.constrained)) invalid('Not a constrained data item type');
  if (!actionDef(b, resourceType, action)?.certified) invalid('Not a certified transformation procedure of this type');
  if (executes(rt, user.id, resourceType, action)) throw new HttpError(403, 'forbidden', 'A certifier cannot execute the procedure');
  return { state: provisionallyCertified(rt.store.state, resourceType, action, user.id), payload: { resourceType, action } };
}
/** The state with a preview-only record, so the impact shows the access the certification opens. The checker is not
 *  known yet: the maker stands in, at proposal and at the approval recheck alike (decideChange writes the real record). */
function provisionallyCertified(state: State, resourceType: string, action: string, makerId: string): State {
  const record = { resourceType, action, certifiedBy: makerId, approvedBy: makerId, certifiedAt: '', policyVersion: policyVersion(state.bundle),
    changeId: '', reason: '', fingerprint: procedureFingerprint(state.bundle, resourceType, action) };
  return { ...state, certifications: [...(state.certifications ?? []), record] };
}
export function candidate(rt: Runtime, user: User, kind: string, raw: unknown, review = false, simulation = false): { state: State; payload: Record<string, unknown>; warnings?: string[] } {
  if (simulation) {
    allowed(user, ['access_admin', 'policy_author', 'approver', 'security_officer', 'resource_owner']);
    if (ownerOnly(user) && kind !== 'remove_tuple') throw new HttpError(403, 'forbidden');
  } else proposalPermission(user, kind, review);
  const p = object(raw); const s = rt.store.state;
  if (kind === 'erase_subject') { keys(p, ['id']); return { state: s, payload: { id: string(p.id) } }; }
  if (kind === 'scim_subjects') return scimCandidate(rt, p);
  if (kind === 'register_resources') return registrationCandidate(rt, p);
  if (kind === 'publish_policy') {
    keys(p, ['bundle']);
    let result: ReturnType<typeof validateBundle>;
    try { result = validateBundle(p.bundle); } catch { throw new HttpError(422, 'unprocessable', 'Invalid policy bundle', ['Malformed policy bundle']); }
    if (!result.ok) throw new HttpError(422, 'unprocessable', 'Invalid policy bundle', result.errors);
    const next = result.bundle;
    for (const x of [...s.subjects, ...s.resources]) {
      if (x.compartments.some((c) => !next.schema.compartments.includes(c))) invalid('Compartment is still in use');
    }
    for (const x of s.subjects) if ([...x.roles, ...(x.roleAssignments ?? []).map((a) => a.role)].some((r) => !Object.hasOwn(next.rbac.roles, r))) invalid('Role is still in use');
    for (const r of s.resources) if (!Object.hasOwn(next.schema.resourceTypes, r.type)) invalid('Resource type is still in use');
    const relations = (type: string) => Object.hasOwn(next.schema.resourceTypes, type) ? next.schema.resourceTypes[type]?.relations : Object.hasOwn(next.schema.subjectRelations ?? {}, type) ? next.schema.subjectRelations?.[type] : undefined;
    for (const t of s.tuples) {
      for (const ref of [t.object, t.subject]) if (Object.hasOwn(s.bundle.schema.resourceTypes, ref.type) && !Object.hasOwn(next.schema.resourceTypes, ref.type)) invalid('Resource type is still in use');
      if (!Object.hasOwn(relations(t.object.type) ?? {}, t.relation) || (t.subjectRelation && !Object.hasOwn(relations(t.subject.type) ?? {}, t.subjectRelation))) invalid('Relation is still in use');
    }
    return { state: { ...s, bundle: next }, payload: { bundle: next }, ...(result.warnings.length ? { warnings: result.warnings } : {}) };
  }
  if (kind === 'remove_tuple') {
    keys(p, ['tupleId']); const id = string(p.tupleId);
    const tuple = s.tuples.find((t) => t.id === id);
    if (!tuple || !inScope(rt, user, tuple.object)) throw new HttpError(404, 'not_found');
    if (tuple.breakGlass) throw new HttpError(403, 'forbidden', 'Use the break-glass endpoint');
    return { state: withRecordDeltas({ ...s, tuples: s.tuples.filter((t) => t.id !== id) }, [{ kind: 'tuple', op: 'delete', type: '', id, value: tuple }]), payload: { tupleId: id } };
  }
  if (kind === 'add_tuple') return tupleCandidate(rt, user, p);
  if (kind === 'certify_tp') return certifyCandidate(rt, user, p);
  if (kind === 'update_subject' || kind === 'update_resource') {
    keys(p, ['id', 'set']); const id = string(p.id); const set = object(p.set);
    attributes(rt, set, kind === 'update_subject');
    if (kind === 'update_subject') {
      if (id === user.id) throw new HttpError(403, 'forbidden', 'Self-grant forbidden');
      if (!s.subjects.some((x) => x.id === id)) throw new HttpError(404, 'not_found');
      const subjects = s.subjects.map((x) => x.id === id ? { ...x, ...set } as Subject : x);
      const deltas = subjects.filter((x) => x.id === id).map((value): RecordDelta => ({ kind: 'subject', op: 'put', type: value.type, id, value }));
      return { state: withRecordDeltas({ ...s, subjects }, deltas), payload: { id, set } };
    }
    resourceScope(rt, user, id);
    const resources = s.resources.map((x) => x.id === id ? { ...x, ...set, version: (x.version ?? 0) + 1 } as Resource : x);
    const levels = levelInheritanceErrors(resources);
    if (levels.length) throw new HttpError(422, 'unprocessable', 'A resource cannot sit below its parent level', levels);
    const deltas = resources.filter((x) => x.id === id).map((value): RecordDelta => ({ kind: 'resource', op: 'put', type: value.type, id, value }));
    return { state: withRecordDeltas({ ...s, resources }, deltas), payload: { id, set } };
  }
  return invalid('Unknown change kind');
}
const DEFAULT_IMPACT_EVALUATION_LIMIT = 100_000;
function configuredImpactLimit(): number {
  const raw = process.env.IMPACT_MAX_EVALUATIONS;
  if (raw === undefined) return DEFAULT_IMPACT_EVALUATION_LIMIT;
  const limit = Number(raw);
  if (!Number.isSafeInteger(limit) || limit < 1) throw new Error('IMPACT_MAX_EVALUATIONS must be a positive integer');
  return limit;
}
function usesHistory(expr: Expr): boolean {
  const path = (value: string): boolean => /^context\.(?:makerId|serverMakerId|priorActions)(?:\.|$)/.test(value);
  if (expr.op === 'and' || expr.op === 'or') return expr.args.some(usesHistory);
  if (expr.op === 'not') return usesHistory(expr.arg);
  if (expr.op === 'has') return path(expr.path);
  if (expr.op === 'true' || expr.op === 'unknown') return false;
  if ('left' in expr) return [expr.left, expr.right].some((operand) => 'path' in operand && path(operand.path));
  return false;
}
function impactActions(before: PolicyBundle, after: PolicyBundle): { ordinary: string[]; contextual: string[] } {
  const all = new Set<string>(); const contextual = new Set<string>();
  for (const bundle of [before, after]) {
    for (const type of Object.values(bundle.schema.resourceTypes)) {
      for (const [name, def] of Object.entries(type.actions)) {
        all.add(name);
        if (def.requiresSecondPerson) contextual.add(name);
      }
    }
    for (const rule of bundle.sod) for (const action of rule.conflicting) contextual.add(action);
    for (const rule of bundle.abac) if (usesHistory(rule.when)) for (const action of rule.actions ?? all) contextual.add(action);
    for (const rule of contentRules(bundle)) if (rule.unless && usesHistory(rule.unless)) for (const action of rule.actions ?? all) contextual.add(action);
  }
  return { ordinary: [...all].filter((action) => !contextual.has(action)), contextual: [...contextual].filter((action) => all.has(action)) };
}
function mergeImpacts(ordinary: Impact, contextual: Impact): Impact {
  const order = (x: Impact['gained'][number], y: Impact['gained'][number]) => `${x.subject}\u0000${x.resource}\u0000${x.action}`.localeCompare(`${y.subject}\u0000${y.resource}\u0000${y.action}`);
  return {
    evaluated: ordinary.evaluated + contextual.evaluated,
    gained: [...ordinary.gained, ...contextual.gained].sort(order),
    lost: [...ordinary.lost, ...contextual.lost].sort(order),
    obligationsLost: [...ordinary.obligationsLost, ...contextual.obligationsLost].sort(order),
    obligationsGained: [...ordinary.obligationsGained, ...contextual.obligationsGained].sort(order),
    policyVersionBefore: ordinary.policyVersionBefore || contextual.policyVersionBefore,
    policyVersionAfter: ordinary.policyVersionAfter || contextual.policyVersionAfter,
  };
}
function checkImpactLimit(cells: readonly ImpactCell[], ordinary: readonly string[], contextual: readonly string[], makers: number, classes: number, limit: number): void {
  // per network and context class, the ordinary affected set once and the maker-dependent set once per maker value
  const perNetwork = Math.floor(limit / 2);
  const ordinaryCount = cells.filter((cell) => ordinary.includes(cell.action)).length * classes;
  const contextualCount = cells.filter((cell) => contextual.includes(cell.action)).length * classes;
  const contextualLimit = Math.floor((perNetwork - Math.min(ordinaryCount, perNetwork)) / makers);
  if (ordinaryCount > perNetwork || contextualCount > contextualLimit) {
    invalid(`Impact exceeds the configured maximum of ${limit} evaluations; split the change into smaller proposals`);
  }
}
const uniqueRows = <T>(rows: readonly T[]): T[] => [...new Map(rows.map((row) => [canonical(row), row])).values()];
function combinedImpact(variants: readonly Impact[], analysis?: Impact['analysis']): Impact {
  const first = variants[0]!;
  return { ...first, evaluated: variants.reduce((n, x) => n + x.evaluated, 0), gained: uniqueRows(variants.flatMap((x) => x.gained)), lost: uniqueRows(variants.flatMap((x) => x.lost)),
    obligationsLost: uniqueRows(variants.flatMap((x) => x.obligationsLost)), obligationsGained: uniqueRows(variants.flatMap((x) => x.obligationsGained)), ...(analysis ? { analysis } : {}) };
}
export function impact(rt: Runtime, after: State, maximumEvaluations = configuredImpactLimit(), maximumContextClasses = IMPACT_CONTEXT_CLASS_LIMIT): Impact {
  const before = hydrated(rt.store.state); const candidate = hydrated(after);
  let affected: ReturnType<typeof affectedImpact>;
  try {
    affected = affectedImpact(before, candidate, rt.now(), rt.store.state.certifications, after.certifications, maximumEvaluations);
  } catch (error: unknown) {
    if (error instanceof AffectedSetLimit) invalid(`Impact exceeds the configured maximum of ${maximumEvaluations} evaluations; split the change into smaller proposals`);
    throw error;
  }
  const { ordinary, contextual } = impactActions(before.bundle, candidate.bundle);
  const ordinaryCells = affected.cells.filter((cell) => ordinary.includes(cell.action));
  const contextualCells = affected.cells.filter((cell) => contextual.includes(cell.action));
  const partition = impactContexts(before.bundle, candidate.bundle, rt.now(), maximumContextClasses);
  // SoD actions stay contextual because recorded history is decision input; maker variants cannot affect ordinary actions.
  const ids = [...new Set([...rt.store.state.subjects.map((s) => s.id), ...after.subjects.map((s) => s.id)])];
  let independent = 'impact-independent-maker';
  while (ids.includes(independent)) independent += '-';
  checkImpactLimit(affected.cells, ordinary, contextual, ids.length + 2, partition.contexts.length, maximumEvaluations);
  const graphs = { before: indexTuples(before.tuples), after: indexTuples(candidate.tuples) };
  const performedContext = (subject: Subject, resource: Resource, action: string, context: Context, world: typeof before): Context => {
    const state = world === before ? rt.store.state : after;
    const bound = sodInput(rt, world.bundle, resource.type, action, { ...context, pepSubjectTypes: [subject.type] });
    return withCertified(state, withPerformed(rt, subject, resource, bound));
  };
  const variants: Impact[] = [];
  const contextClasses: ImpactContextClass[] = [];
  for (const network of ['trusted', 'untrusted'] as const) for (const representative of partition.contexts) {
    const context = { ...representative, network };
    const classVariants: Impact[] = [];
    const run = (makerId: string | undefined, includeOrdinary: boolean): Impact => {
      const requested = { ...context, ...(makerId === undefined ? {} : { makerId }) };
      if (!includeOrdinary) return simulate(before, candidate, requested, contextual, graphs, performedContext, contextualCells);
      const base = simulate(before, candidate, requested, ordinary, graphs, performedContext, ordinaryCells);
      return contextualCells.length ? mergeImpacts(base, simulate(before, candidate, requested, contextual, graphs, performedContext, contextualCells)) : base;
    };
    classVariants.push(run(undefined, true));
    if (contextualCells.length) for (const makerId of [independent, ...ids]) classVariants.push(run(makerId, false));
    variants.push(...classVariants);
    const delta = combinedImpact(classVariants);
    if (delta.gained.length + delta.lost.length + delta.obligationsLost.length + delta.obligationsGained.length > 0) {
      contextClasses.push({ context, evaluated: delta.evaluated, gained: delta.gained, lost: delta.lost,
        obligationsLost: delta.obligationsLost, obligationsGained: delta.obligationsGained });
    }
  }
  return { ...combinedImpact(variants, affected.analysis), ...(partition.partitioned ? { contextAnalysis: {
    cap: maximumContextClasses, evaluatedClasses: partition.contexts.length * 2, truncated: partition.truncated,
    incomplete: partition.incomplete, unsupported: partition.unsupported, classes: contextClasses,
  } } : {}) };
}
/** Certification records in force now whose procedure the candidate bundle defines differently: they go stale. */
function invalidated(rt: Runtime, after: State): NonNullable<Change['invalidatesCertifications']> {
  const now = rt.store.state;
  return (now.certifications ?? []).filter((c) => certificationCurrent(now, c) && procedureFingerprint(after.bundle, c.resourceType, c.action) !== procedureFingerprint(now.bundle, c.resourceType, c.action))
    .map((c) => ({ resourceType: c.resourceType, action: c.action, changeId: c.changeId }));
}
/** Broadening: someone gains access, or keeps it with less protection (a lost obligation, KIMI-02). */
export const broadens = (delta: Impact): boolean => delta.gained.length > 0 || delta.obligationsLost.length > 0;
export function propose(rt: Runtime, user: User, b: Record<string, unknown>, review = false, scimCredential?: ScimCredentialOrigin, pepCredential?: PepCredentialOrigin): Change {
  const kind = string(b.kind); const why = reason(b.reason);
  const result = candidate(rt, user, kind, b.payload, review);
  const delta = impact(rt, result.state);
  const change: Change = { id: randomUUID(), kind, payload: result.payload, reason: why, makerId: user.id, createdAt: rt.now(), status: 'pending',
    ...(kind === 'publish_policy' ? { weakensMandatory: mandatoryWeakenings(rt.store.state.bundle, result.state.bundle), invalidatesCertifications: invalidated(rt, result.state) } : {}),
    ...(result.warnings ? { warnings: result.warnings } : {}),
    impact: delta, broadens: broadens(delta), stateDigest: rt.store.digest(), ...(scimCredential ? { scimCredential } : {}), ...(pepCredential ? { pepCredential } : {}) };
  rt.store.changes = [...rt.store.changes, change]; rt.store.save();
  rt.audit.append({ type: 'change', actor: user.id, action: 'propose', ...(review ? { rules: ['ADMIN.ACCESS_REVIEW'] } : {}), policyVersion: policyVersion(rt.store.state.bundle),
    details: { changeId: change.id, kind, ...(change.warnings ? { warnings: change.warnings } : {}), ...(scimCredential ? { credential: scimCredential.fingerprint } : {}), ...(pepCredential ? { credential: pepCredential.id } : {}) } });
  return change;
}
function apply(state: State, change: Change): State {
  const p = change.payload;
  if (change.kind === 'erase_subject') return state;
  if (change.kind === 'publish_policy') return { ...state, bundle: p.bundle as PolicyBundle };
  if (change.kind === 'remove_tuple') {
    const id = String(p.tupleId);
    return withRecordDeltas({ ...state, tuples: state.tuples.filter((t) => t.id !== id) }, [{ kind: 'tuple', op: 'delete', type: '', id }]);
  }
  if (change.kind === 'add_tuple') {
    const tuple = { ...p, id: randomUUID() } as unknown as StoredTuple;
    const deltas: RecordDelta[] = [{ kind: 'tuple', op: 'put', type: '', id: tuple.id, value: tuple }];
    if (typeof p.replacesTupleId === 'string') deltas.unshift({ kind: 'tuple', op: 'delete', type: '', id: p.replacesTupleId });
    return withRecordDeltas({ ...state, tuples: [...state.tuples.filter((t) => t.id !== p.replacesTupleId), tuple] }, deltas);
  }
  if (change.kind === 'certify_tp') return state; // the record needs the checker: written by decideChange
  // a queued retirement takes effect at approval (decideChange records the retired id then)
  if (change.kind === 'register_resources') return applyResources(state, p.resources as Resource[], (p.retire ?? []) as Array<{ type: string; id: string }>);
  if (change.kind === 'scim_subjects') {
    const subjects = p.subjects as Subject[]; const ids = new Set(subjects.map((subject) => subject.id));
    const deltas = subjects.map((value): RecordDelta => ({ kind: 'subject', op: 'put', type: value.type, id: value.id, value }));
    return withRecordDeltas({ ...state, subjects: [...state.subjects.filter((subject) => !ids.has(subject.id)), ...subjects] }, deltas);
  }
  const set = object(p.set);
  if (change.kind === 'update_subject') {
    const subjects = state.subjects.map((s) => s.id === p.id ? { ...s, ...set } as Subject : s);
    const deltas = subjects.filter((s) => s.id === p.id).map((value): RecordDelta => ({ kind: 'subject', op: 'put', type: value.type, id: value.id, value }));
    return withRecordDeltas({ ...state, subjects }, deltas);
  }
  const resources = state.resources.map((r) => r.id === p.id ? { ...r, ...set, version: (r.version ?? 0) + 1 } as Resource : r);
  const deltas = resources.filter((r) => r.id === p.id).map((value): RecordDelta => ({ kind: 'resource', op: 'put', type: value.type, id: value.id, value }));
  return withRecordDeltas({ ...state, resources }, deltas);
}
export function decideChange(rt: Runtime, user: User, id: string, approve: boolean, b: Record<string, unknown>): Change {
  const change = rt.store.changes.find((c) => c.id === id);
  if (!change) throw new HttpError(404, 'not_found');
  if (change.makerId === user.id) throw new HttpError(403, 'self_approval', 'The maker cannot review their own change');
  // whoever minted the SCIM credential can write through it: they are the maker of its proposals
  if (change.kind === 'scim_subjects' && (!change.scimCredential || change.scimCredential.rotatedBy === user.id)) {
    throw new HttpError(403, 'self_approval', 'The holder of the SCIM credential cannot review its proposals');
  }
  const registration = change.kind === 'register_resources';
  if (registration) {
    // whoever created or last rotated the PEP credential knows its secret: they are the maker of its proposals
    if (!change.pepCredential?.issuedBy || change.pepCredential.issuedBy === user.id) throw new HttpError(403, 'self_approval', 'Whoever issued the PEP credential cannot review its proposals');
  }
  allowed(user, ['approver', 'security_officer']);
  if (change.status !== 'pending') throw new HttpError(409, 'conflict');
  if (approve && change.kind === 'publish_policy') {
    const checked = candidate(rt, user, change.kind, change.payload, false, true);
    if (mandatoryWeakenings(rt.store.state.bundle, checked.state.bundle).length) allowed(user, ['security_officer']);
  }
  if (approve && (change.payload.breakGlass === true || (change.kind === 'remove_tuple' && rt.store.state.tuples.some((t) => t.id === change.payload.tupleId && t.breakGlass)))) throw new HttpError(403, 'forbidden', 'Use the break-glass endpoint');
  if (approve && change.payload.replacesTupleId !== undefined) {
    const old = rt.store.state.tuples.find((t) => t.id === change.payload.replacesTupleId);
    if (!old || windowState(old, Date.parse(rt.now())) === 'expired') throw new HttpError(409, 'stale', 'Grant has expired');
  }
  if (approve && ((change.kind === 'add_tuple' && object(change.payload.subject).id === user.id) || (change.kind === 'update_subject' && change.payload.id === user.id) ||
    (change.kind === 'scim_subjects' && (change.payload.subjects as Subject[]).some((s) => s.id === user.id)))) throw new HttpError(403, 'forbidden', 'Beneficiary cannot approve');
  if (approve && change.kind === 'certify_tp') {
    if (executes(rt, user.id, String(change.payload.resourceType), String(change.payload.action))) throw new HttpError(403, 'forbidden', 'A certifier cannot execute the procedure');
  }
  const why = string(b.reason);
  // a registration names the resources it changes: other registrations meanwhile (an application keeps registering
  // records) do not make it stale, a change to one of its resources or to who gains or loses access does
  const unchanged = registration ? !registrationMoved(rt.store.state, rt.store.retired, change.payload)
    : change.stateDigest.startsWith('v2.') ? rt.store.digest() === change.stateDigest : rt.store.legacyDigest() === change.stateDigest;
  if (approve && !unchanged) throw new HttpError(409, 'stale', 'State changed; submit a new proposal');
  const effect = (i: Impact): string => canonical(registration ? { ...i, evaluated: 0 } : i);
  if (approve) {
    const currentImpact = impact(rt, change.kind === 'certify_tp'
      ? provisionallyCertified(rt.store.state, String(change.payload.resourceType), String(change.payload.action), change.makerId) : apply(rt.store.state, change));
    if (currentImpact.contextAnalysis?.incomplete) allowed(user, ['security_officer']);
    if (effect(currentImpact) !== effect(change.impact)) throw new HttpError(409, 'stale', 'Impact changed; submit a new proposal');
  }
  const updated: Change = { ...change, status: approve ? 'applied' : 'rejected', checkerId: user.id, decidedAt: rt.now(), decisionReason: why };
  const appendDecision = (): void => rt.audit.append({ type: 'change', actor: user.id, action: approve ? 'approve' : 'reject', rules: ['ADMIN.TWO_PERSON'], policyVersion: policyVersion(rt.store.state.bundle),
    details: { changeId: id, makerId: change.makerId, checkerId: user.id, kind: change.kind, ...(change.warnings ? { warnings: change.warnings } : {}) } });
  if (approve) {
    // Recheck temporal constraints at approval, without accepting new payload fields.
    const until = change.kind === 'add_tuple' ? windowOf(change.payload as { notAfter?: string; validTo?: string }).to : undefined;
    if (until !== undefined && Date.parse(until) <= Date.parse(rt.now())) throw new HttpError(409, 'stale', 'Grant has expired');
    const next = apply(rt.store.state, change);
    if (registration) checkResources(next, change.payload.resources as Resource[]);
    const gone = registration ? ((change.payload.retire ?? []) as Array<{ type: string; id: string }>).flatMap((r) => {
      const live = findRef(rt.store.state.resources, r.id, r.type); return live ? [retiredId(live, rt.now())] : []; }) : [];
    // a failure past this point restores the state exactly (Store rolls back in-place record patches); the retired ids
    // are logged last, once nothing else can refuse
    const prior = rt.store.state; const priorHistory = rt.store.history;
    try {
      rt.store.state = next;
      if (change.kind === 'publish_policy') rt.store.publish(rt.store.state.bundle, change.makerId, user.id, change.reason, rt.now(), signPolicy(rt.tokens, rt.store.state.bundle));
      if (change.kind === 'certify_tp') {
        const record = { resourceType: String(change.payload.resourceType), action: String(change.payload.action), certifiedBy: change.makerId,
          approvedBy: user.id, certifiedAt: rt.now(), policyVersion: policyVersion(rt.store.state.bundle), changeId: id, reason: change.reason,
          fingerprint: procedureFingerprint(rt.store.state.bundle, String(change.payload.resourceType), String(change.payload.action)) };
        rt.store.state = { ...rt.store.state, certifications: [...(rt.store.state.certifications ?? []), record] };
      }
      // audited before anything is committed: a refused append leaves the change pending and the state as it was
      appendDecision();
      for (const r of gone) rt.store.retired.append(r);
    } catch (err) { rt.store.state = prior; rt.store.history = priorHistory; throw err; }
  } else appendDecision();
  rt.store.changes = rt.store.changes.map((c) => c.id === id ? updated : c); rt.store.save();
  return updated;
}
export function visibleChange(rt: Runtime, user: User, c: Change): boolean {
  if (!ownerOnly(user)) return true;
  if (c.kind === 'remove_tuple') {
    const tuple = rt.store.state.tuples.find((t) => t.id === c.payload.tupleId);
    return tuple ? inScope(rt, user, tuple.object) : c.makerId === user.id;
  }
  if (c.kind === 'add_tuple') return inScope(rt, user, c.payload.object as { type: string; id: string });
  return false;
}

export function scopedImpact(rt: Runtime, user: User, delta: Impact): Impact {
  if (!ownerOnly(user)) return delta;
  const owned = rt.store.state.resources.filter((r) => inScope(rt, user, r));
  const owns = (row: Impact['gained'][number]): boolean => owned.some((r) => r.type === row.resourceType && r.id === row.resource) && subjectInScope(rt, user, { type: row.subjectType, id: row.subject });
  const contextAnalysis = delta.contextAnalysis === undefined ? undefined : { ...delta.contextAnalysis, classes: delta.contextAnalysis.classes.flatMap((item) => {
    const scoped = { ...item, gained: item.gained.filter(owns), lost: item.lost.filter(owns),
      obligationsLost: item.obligationsLost.filter(owns), obligationsGained: item.obligationsGained.filter(owns) };
    return scoped.gained.length + scoped.lost.length + scoped.obligationsLost.length + scoped.obligationsGained.length > 0 ? [scoped] : [];
  }) };
  return { ...delta, evaluated: owned.reduce((n, r) => n + Object.keys(rt.store.state.bundle.schema.resourceTypes[r.type]?.actions ?? {}).length * rt.store.state.subjects.filter((s) => subjectInScope(rt, user, s)).length, 0),
    gained: delta.gained.filter(owns), lost: delta.lost.filter(owns),
    obligationsLost: (delta.obligationsLost ?? []).filter(owns), obligationsGained: (delta.obligationsGained ?? []).filter(owns),
    ...(contextAnalysis ? { contextAnalysis } : {}) };
}
export function changeView(rt: Runtime, user: User, change: Change): Change {
  return { ...change, impact: scopedImpact(rt, user, change.impact) };
}
