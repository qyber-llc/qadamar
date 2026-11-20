import { evaluate, policyVersion, principals, procedureFingerprint, validAuthMethods, validCountry, validInstant, validIp } from '../../core/src/index.ts';
import type { Context, Decision, PolicyBundle, Subject, World } from '../../core/src/index.ts';
import { findRef, graphOf } from './decision-index.ts';
export { findRef, graphOf } from './decision-index.ts';
import type { Backing, Certification, Performed, Store, State, StoredTuple } from './store.ts';
import type { ApprovalPrefs } from './admin/inbox.ts';
import type { AuditLog } from './audit.ts';
import { MAX_SESSION_TOKEN_CHARS, type Tokens } from './tokens.ts';
import type { BreakGlassNotice } from './notify.ts';
import type { User } from './auth.ts';
import { ownerOnly } from './auth.ts';
import { HttpError, object, string } from './http.ts';
import { childSpan, traceClock } from './tracing.ts';
import { SESSION_ID, TOKEN_SCOPE, type Sessions } from './sessions.ts';
import type { PepSessions } from './pep-sessions.ts';
import { authorizeContext, type ContextTrust } from './context-trust.ts';

export type SodHistory = 'caller' | 'server';
export interface Runtime {
  store: Store; audit: AuditLog; tokens: Tokens; now: () => string; started: number; decisions: number;
  /** Console user id -> further resource owner ids that user answers for (RESOURCE_OWNERS). */
  resourceOwners?: ReadonlyMap<string, readonly string[]>;
  /** "server": caller-supplied makerId and priorActions are ignored for SoD-constrained actions (SOD_HISTORY). */
  sodHistory?: SodHistory;
  /** Makes every change and audit row of the request durable before it is answered (PostgreSQL); file stores write at once. */
  commit?: () => Promise<void>;
  /** RFC 3161 anchoring of the audit head, when a timestamp authority is configured. */
  anchoring?: { url: string; lastError?: string };
  /** BREAK_GLASS_WEBHOOK notice, sent in the background (never delays or fails the request). */
  notifyBreakGlass?: (notice: BreakGlassNotice) => void;
  /** Secure-configuration baseline of this node, no secret values (profile.ts configurationBaseline). */
  baseline?: Readonly<Record<string, unknown>>;
  /** HMAC key for pseudonymised audit exports, derived from SIGNING_KEY_SEAL (admin/privacy.ts). */
  pseudonymKey?: Buffer;
  /** PostgreSQL: this node's role. A follower refuses the admin plane; a node whose shared state is older than the
   *  staleness bound refuses decisions (docs/API.md §3.9.1). */
  node?: NodeRole;
  /** BLP session high-water marks (sessions.ts); absent: no session is tracked. */
  sessions?: Sessions;
  /** PDP-issued session tokens and their open-session registry (pep-sessions.ts). */
  pepSessions?: PepSessions;
  /** Integration barrier after a mark-relevant decision. */
  afterDecision?: () => Promise<void>;
  /** The `approval_prefs` document (admin/inbox.ts): approval modes and snoozes; absent on a replica (no admin plane). */
  approvalPrefs?: Backing<ApprovalPrefs>;
}
export interface NodeRole {
  readonly id: string;
  leader(): boolean;
  fresh(): boolean;
  /** The admin plane's address the leader published (GATE_ADVERTISE_URL), if any. */
  leaderUrl(): string | null;
  /** "replica": a stateless replica (replica.ts) rather than a cluster follower. */
  readonly role?: 'replica';
  /** Prometheus lines of the node's own (replica.ts). */
  metrics?(): string[];
}
export function context(input: unknown, now: string, trust?: ContextTrust): Context {
  const c = input === undefined ? {} : object(input);
  if (trust) authorizeContext(input, trust, now);
  if (c.network !== undefined && c.network !== 'trusted' && c.network !== 'untrusted') throw new HttpError(400, 'bad_request');
  if (c.sessionLevel !== undefined && ![0, 1, 2, 3].includes(c.sessionLevel as number)) throw new HttpError(400, 'bad_request');
  if (c.priorActions !== undefined && (!Array.isArray(c.priorActions) || !c.priorActions.every((a) => typeof a === 'string'))) throw new HttpError(400, 'bad_request');
  if (c.makerId !== undefined) string(c.makerId);
  if (c.sessionId !== undefined && (typeof c.sessionId !== 'string' || !SESSION_ID.test(c.sessionId))) throw new HttpError(400, 'bad_request', 'context.sessionId must be 1..128 printable ASCII characters');
  if (c.sessionToken !== undefined && (typeof c.sessionToken !== 'string' || c.sessionToken.length > MAX_SESSION_TOKEN_CHARS)) throw new HttpError(400, 'bad_request', 'context.sessionToken must be a PDP-issued session token');
  if (c.sessionId !== undefined && c.sessionToken !== undefined) throw new HttpError(400, 'bad_request', 'Send context.sessionToken or legacy context.sessionId, not both');
  if (c.ip !== undefined && !validIp(c.ip)) throw new HttpError(400, 'bad_request', 'context.ip must be an IPv4 or IPv6 literal');
  if (c.country !== undefined && !validCountry(c.country)) throw new HttpError(400, 'bad_request', 'context.country must be an upper-case ISO country code');
  const device = c.device === undefined ? undefined : object(c.device);
  if (device && (typeof device.managed !== 'boolean' || typeof device.compliant !== 'boolean' || Object.keys(device).some((key) => !['managed', 'compliant', 'id'].includes(key)))) throw new HttpError(400, 'bad_request', 'context.device must contain managed and compliant booleans, with an optional id');
  if (device?.id !== undefined && (typeof device.id !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(device.id))) throw new HttpError(400, 'bad_request', 'context.device.id must be 1..128 printable ASCII characters');
  if (c.networkSensorId !== undefined && (typeof c.networkSensorId !== 'string' || !/^[\x21-\x7e]{1,128}$/.test(c.networkSensorId))) throw new HttpError(400, 'bad_request', 'context.networkSensorId must be 1..128 printable ASCII characters');
  if ((c.authTime !== undefined && !validInstant(c.authTime)) || (c.mfaTime !== undefined && !validInstant(c.mfaTime))) throw new HttpError(400, 'bad_request', 'Authentication times must be ISO-8601 instants');
  if (c.authMethods !== undefined && !validAuthMethods(c.authMethods)) throw new HttpError(400, 'bad_request', 'Invalid context.authMethods');
  if (c.sessionExpired !== undefined && typeof c.sessionExpired !== 'boolean') throw new HttpError(400, 'bad_request', 'context.sessionExpired must be a boolean');
  if (c.riskScore !== undefined && (!Number.isInteger(c.riskScore) || Number(c.riskScore) < 0 || Number(c.riskScore) > 100)) throw new HttpError(400, 'bad_request', 'context.riskScore must be an integer 0..100');
  // C5: the command's input, as the PEP will hand it over (the request body); the engine's validators judge it
  const given = c.input === undefined ? undefined : object(c.input);
  return { now, network: c.network === 'trusted' ? 'trusted' : 'untrusted',
    ...(given === undefined ? {} : { input: given as Context["input"] }),
    ...(c.sessionLevel === undefined ? {} : { sessionLevel: c.sessionLevel as Context['sessionLevel'] }),
    ...(c.sessionId === undefined ? {} : { sessionId: c.sessionId as string }),
    // the PEP's own session store may know the session ended: true only narrows, false changes nothing
    ...(c.sessionExpired === true ? { sessionExpired: true } : {}),
    ...(c.makerId === undefined ? {} : { makerId: c.makerId as string }),
    ...(c.priorActions === undefined ? {} : { priorActions: c.priorActions as string[] }),
    ...(c.ip === undefined ? {} : { ip: c.ip as string }), ...(c.country === undefined ? {} : { country: c.country as string }),
    ...(device === undefined ? {} : { device: { managed: device.managed, compliant: device.compliant } as Context['device'] }),
    ...(c.authTime === undefined ? {} : { authTime: c.authTime as string }), ...(c.mfaTime === undefined ? {} : { mfaTime: c.mfaTime as string }),
    ...(c.authMethods === undefined ? {} : { authMethods: c.authMethods as string[] }), ...(c.riskScore === undefined ? {} : { riskScore: c.riskScore as number }) };
}
export function subject(state: State, id: string, type?: string, seen = new Set<string>()): Subject | undefined {
  const s = findRef(state.subjects, id, type);
  if (!s) return undefined;
  if (seen.has(s.id)) return { ...s, active: false };
  const next = new Set([...seen, s.id]);
  const { delegator: ignored, ...own } = s;
  if (s.attrs?.delegatedBy === undefined) return own;
  const delegator = typeof s.attrs.delegatedBy === 'string' ? subject(state, s.attrs.delegatedBy, 'user', next) : undefined;
  return delegator ? { ...own, delegator } : { ...own, active: false };
}
export function hydrated(state: State): World {
  return { ...state, subjects: state.subjects.map((s) => subject(state, s.id, s.type) as Subject) };
}
// history arrays are replaced, never mutated (pdp.ts), so an index stays valid for the array it was built from
const performedIndexes = new WeakMap<readonly Performed[], Map<string, Performed[]>>();
const resourceKey = (r: { id: string; type: string }): string => JSON.stringify([r.type, r.id]);
function performedOn(performed: readonly Performed[], r: { id: string; type: string }): readonly Performed[] {
  let index = performedIndexes.get(performed);
  if (!index) {
    index = new Map();
    for (const p of performed) {
      const key = resourceKey(p.resource);
      const entries = index.get(key);
      if (entries) entries.push(p); else index.set(key, [p]);
    }
    performedIndexes.set(performed, index);
  }
  return index.get(resourceKey(r)) ?? [];
}
export function withPerformed(rt: Runtime, who: Subject, r: { id: string; type: string }, ctx: Context): Context {
  // a reservation counts while pending (two makers racing past the check is worse) and once completed; not once failed
  const onResource = performedOn(rt.store.performed, r).filter((p) => p.outcome !== 'failed');
  const chain = principals(who);
  const people = (p: Performed): Array<{ type: string; id: string }> => [p.subject, ...(p.onBehalfOf ?? [])];
  const mine = (p: Performed): boolean => people(p).some((x) => chain.some((s) => s.type === x.type && s.id === x.id));
  const actions = onResource.filter(mine).map((p) => p.action);
  // the maker is everyone on whose behalf the first action was done; the id passed on is the one this request can match
  const first = onResource[0];
  const makers = first ? people(first) : [];
  const maker = first === undefined ? undefined
    : makers.some((x) => x.id === ctx.makerId) ? ctx.makerId
    : chain.find((s) => makers.some((x) => x.type === s.type && x.id === s.id))?.id ?? first.subject.id;
  return { ...ctx, priorActions: [...new Set([...(ctx.priorActions ?? []), ...actions])], ...(maker === undefined ? {} : { serverMakerId: maker }) };
}
/** The bundle constrains this action by separation of duty: a two-person rule or an SoD conflict set. */
export function sodConstrained(bundle: PolicyBundle, type: string, action: string): boolean {
  const actions = Object.hasOwn(bundle.schema.resourceTypes, type) ? bundle.schema.resourceTypes[type]!.actions : {};
  return (Object.hasOwn(actions, action) && actions[action]!.requiresSecondPerson === true) || bundle.sod.some((rule) => rule.conflicting.includes(action));
}
/** SOD_HISTORY defaults to server: only the PDP's recorded history speaks for a constrained action. */
export function sodInput(rt: Runtime, bundle: PolicyBundle, type: string, action: string, ctx: Context): Context {
  if (rt.sodHistory === 'caller' || !sodConstrained(bundle, type, action)) return ctx;
  const { makerId: ignoredMaker, priorActions: ignoredPrior, ...rest } = ctx;
  return rest;
}
/** The procedure definition a record certified (core procedureFingerprint). A record written before fingerprints (0.4.0)
 *  only knows its policy version: it speaks for the definition in force only while that exact version is (fail closed). */
export function certifiedFingerprint(state: State, c: Certification): string | undefined {
  return c.fingerprint ?? (c.policyVersion === policyVersion(state.bundle) ? procedureFingerprint(state.bundle, c.resourceType, c.action) : undefined);
}
/** The record still certifies the procedure as the current bundle defines it. */
export const certificationCurrent = (state: State, c: Certification): boolean =>
  certifiedFingerprint(state, c) === procedureFingerprint(state.bundle, c.resourceType, c.action);
/** The certification records in force: only the server supplies them (a caller's context never carries this field). */
export function withCertified(state: State, ctx: Context): Context {
  // `by`: E4, the certifier and its checker never run the procedure they certified, whatever roles they hold later;
  // `fingerprint`: the engine accepts a record only for the definition it certified (CW.CERTIFICATION_STALE otherwise)
  return { ...ctx, certified: (state.certifications ?? []).map((c) => {
    const fingerprint = certifiedFingerprint(state, c);
    return { resourceType: c.resourceType, action: c.action, by: [c.certifiedBy, c.approvedBy], ...(fingerprint ? { fingerprint } : {}) };
  }) };
}
/** A PEP's decision on `s`: the high-water mark of its session (ctx.sessionId, already scoped to the PEP credential),
 *  whether that session is known expired, and BLP_SESSION_REQUIRED. Only the server sets the mark and the requirement
 *  (context() never reads them from the caller); a PEP may only add that its session expired. */
export function withSession(rt: Runtime, s: { id: string; type: string }, ctx: Context): Context {
  if (!rt.sessions) return ctx;
  // A legacy id: an expired mark is kept (level() would drop it), so the session stays known expired until the sweep
  // forgets it. A PDP-issued token was verified live before this (an expired one is refused with 403 and never gets
  // here); its scope is shared by every token of the subject, so a lapsed mark there is no expired session.
  const legacy = ctx.sessionId !== undefined && !ctx.sessionId.startsWith(TOKEN_SCOPE);
  const expired = legacy && rt.sessions.expired(ctx.sessionId as string, s);
  const mark = ctx.sessionId === undefined || expired ? undefined : rt.sessions.level(ctx.sessionId, s);
  return { ...ctx, ...(mark === undefined ? {} : { highWater: mark }), ...(expired ? { sessionExpired: true } : {}), ...(rt.sessions.required ? { sessionRequired: true } : {}) };
}
const EMPTY_OBLIGATIONS = { redact: [], maskClasses: [], notify: [] };
/** `veto`: a permit the caller cannot carry out (returns the rule and reason) is recorded and answered as that deny. */
export function decide(rt: Runtime, s: { id: string; type: string }, r: { id: string; type: string }, action: string, ctx: Context, actor = 'pep', state = rt.store.state, recordAudit = true,
  veto?: (d: Decision) => { rule: string; reason: string } | undefined, auditDetails?: Record<string, unknown>): Decision {
  const started = traceClock();
  const who = subject(state, s.id, s.type);
  const resource = findRef(state.resources, r.id, r.type);
  // E3: a PEP's decision carries the populations its credential is bound to (none: []); a console view (simulator,
  // matrix) answers what a PEP bound to the subject's population would get. Nothing a console view decides is released.
  const bound = actor === 'pep' ? withSession(rt, s, ctx) : ctx.pepSubjectTypes !== undefined ? ctx : { ...ctx, pepSubjectTypes: [s.type] };
  const derived = withCertified(state, who ? withPerformed(rt, who, r, sodInput(rt, state.bundle, r.type, action, bound)) : bound);
  const evaluated: Decision = who && resource ? evaluate(state.bundle, { subject: who, resource, action, context: derived }, graphOf(state.tuples)) : {
    decision: false, rules: ['CORE.UNKNOWN_ID'], reasons: ['Unknown subject or resource'],
    obligations: EMPTY_OBLIGATIONS, trace: [], wouldDeny: [], policyVersion: policyVersion(state.bundle),
  };
  const vetoed = evaluated.decision ? veto?.(evaluated) : undefined;
  const d: Decision = vetoed ? { ...evaluated, decision: false, rules: [vetoed.rule], reasons: [vetoed.reason], obligations: EMPTY_OBLIGATIONS,
    trace: [...evaluated.trace.filter((t) => t.outcome !== 'obligation'), { stage: 'engine', rule: vetoed.rule, outcome: 'deny', reason: vetoed.reason }] } : evaluated;
  const rules = [...new Set([...d.rules, ...d.trace.filter((t) => t.outcome === 'obligation').map((t) => t.rule)])];
  const effect = d.decision ? 'allow' : 'deny';
  if (recordAudit) {
    rt.decisions++;
    rt.audit.append({ type: 'decision', actor, action, subject: s.id, resource: r.id, effect, rules, policyVersion: d.policyVersion, ...(auditDetails ? { details: auditDetails } : {}) });
  }
  // effect and rule ids only: no subject, resource or action in a trace
  childSpan('gate.decision', started, { 'gate.decision.effect': effect, 'gate.decision.rules': rules });
  return d;
}
export function resourceScope(rt: Runtime, user: User, target: string | { type: string; id: string }): void {
  const matches = rt.store.state.resources.filter((r) => typeof target === 'string' ? r.id === target : r.id === target.id && r.type === target.type);
  if (matches.length !== 1 || !inScope(rt, user, matches[0]!)) throw new HttpError(404, 'not_found');
}
export function ref(input: unknown): { type: string; id: string } {
  const v = object(input); return { type: string(v.type), id: string(v.id) };
}
/** RESOURCE_OWNERS: a JSON object mapping a console user id to the extra resource owner ids it answers for. */
export function parseResourceOwners(raw: string | undefined): Map<string, string[]> | undefined {
  if (raw === undefined || raw.trim() === '') return undefined;
  const invalid = (): never => { throw new Error('RESOURCE_OWNERS must be a JSON object of console user id -> array of owner ids'); };
  let value: unknown;
  try { value = JSON.parse(raw); } catch { return invalid(); }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const map = new Map<string, string[]>();
  for (const [user, owners] of Object.entries(value)) {
    if (!user || !Array.isArray(owners) || !owners.every((o) => typeof o === 'string' && o.length > 0 && o.length <= 256)) invalid();
    map.set(user, [...new Set(owners as string[])]);
  }
  return map;
}
export function parseSodHistory(raw: string | undefined): SodHistory | undefined {
  if (raw === undefined || raw === '') return undefined;
  if (raw !== 'caller' && raw !== 'server') throw new Error('SOD_HISTORY must be "caller" or "server"');
  return raw;
}
/** The resource owner ids a console user answers for: its own authenticated id, plus those RESOURCE_OWNERS maps to it. */
export const ownerIds = (rt: Runtime, user: User): ReadonlySet<string> => new Set([user.id, ...(rt.resourceOwners?.get(user.id) ?? [])]);
export const inScope = (rt: Runtime, user: User, target: { type: string; id: string }): boolean => {
  if (!ownerOnly(user)) return true;
  const owners = ownerIds(rt, user);
  return rt.store.state.resources.some((r) => r.id === target.id && r.type === target.type && typeof r.owner === 'string' && owners.has(r.owner));
};
export const subjectInScope = (rt: Runtime, user: User, s: { type: string; id: string }): boolean => !ownerOnly(user) || rt.store.state.tuples.some((t) => t.subject.type === s.type && t.subject.id === s.id && inScope(rt, user, t.object));
