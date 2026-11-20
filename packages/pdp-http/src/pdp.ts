import { randomUUID } from 'node:crypto';
import { buildFilter, canonical, FALSE, TRUE, ivpsFor, policyVersion, principals, ResourceCandidates, subjectCandidates, verifyIntegrity } from '../../core/src/index.ts';
import { compile } from '../../sql/src/index.ts';
import type { Columns } from '../../sql/src/index.ts';
import type { Context, Decision, Resource } from '../../core/src/index.ts';
import type { AssertionClaims, Claims } from './tokens.ts';
import type { ActionOutcome, Performed, Reservation } from './store.ts';
import { applyPostState, checkPostState } from './resource-registry.ts';
import type { Runtime } from './runtime.ts';
import { context, decide, findRef, graphOf, ref, subject, withCertified, withSession } from './runtime.ts';
import { scopeSession, type MarkLoader } from './sessions.ts';
import { sessionTokenLocks, type SessionBindings, type StoredPepSession } from './pep-sessions.ts';
import { HttpError, object, string } from './http.ts';
import { authorizeContext, type ContextTrust } from './context-trust.ts';

/** Only decisions that can read or raise the mark pay for session ordering. Parsing here is speculative: the endpoint
 *  validates the same body again, and an id read from a token chooses a lock but is never trusted by the decision. */
function interacts(rt: Runtime, b: Record<string, unknown>): boolean {
  const s = b.subject as { type?: unknown; id?: unknown } | undefined;
  const r = b.resource as { type?: unknown; id?: unknown } | undefined;
  const action = (b.action as { name?: unknown } | undefined)?.name;
  if (typeof s?.type !== 'string' || typeof s.id !== 'string' || typeof r?.type !== 'string' || typeof action !== 'string') return false;
  const actions = Object.hasOwn(rt.store.state.bundle.schema.resourceTypes, r.type) ? rt.store.state.bundle.schema.resourceTypes[r.type]!.actions : {};
  if (!Object.hasOwn(actions, action)) return false;
  const kind = actions[action]!.kind;
  const who = findRef(rt.store.state.subjects, s.id, s.type);
  if (kind !== 'read') return who ? who.clearance > 0 : true;
  return typeof r.id === 'string' && (findRef(rt.store.state.resources, r.id, r.type)?.level ?? 0) > 0;
}

/** Scoped sessions named by point decisions that interact with the mark; L0 reads and requests without one return none. */
export function evaluationSessions(rt: Runtime, b: Record<string, unknown>, pep: string | undefined): string[] {
  const out = new Set<string>();
  if (!rt.sessions) return [];
  const walk = (value: unknown, depth: number): void => {
    if (depth > 8 || value === null || typeof value !== 'object' || Array.isArray(value)) return;
    const o = value as Record<string, unknown>;
    const ctx = o.context as { sessionId?: unknown; sessionToken?: unknown } | undefined;
    if (interacts(rt, o)) {
      if (typeof ctx?.sessionId === 'string') out.add(scopeSession(pep, ctx.sessionId));
      if (typeof ctx?.sessionToken === 'string') for (const lock of sessionTokenLocks(ctx.sessionToken, pep ?? '')) out.add(lock);
    }
    for (const child of Object.values(o)) walk(child, depth + 1);
  };
  walk(b, 0);
  return [...out];
}

export function decisionSessions(rt: Runtime, path: string, b: Record<string, unknown>, pep: string | undefined): string[] {
  if (path === '/access/v1/search/subject') {
    // no subject.id: any candidate's mark or expiry tombstone in the named session may decide, so the session scope is
    // locked and loaded whatever the subject (a session token is refused here, search() says why)
    const id = (b.context as { sessionId?: unknown } | undefined)?.sessionId;
    return rt.sessions && typeof id === 'string' ? [scopeSession(pep, id)] : [];
  }
  if (path === '/access/v1/search/action') {
    const type = (b.resource as { type?: unknown } | undefined)?.type;
    const actions = typeof type === 'string' && Object.hasOwn(rt.store.state.bundle.schema.resourceTypes, type)
      ? rt.store.state.bundle.schema.resourceTypes[type]!.actions : {};
    const write = Object.keys(actions).find((action) => actions[action]!.kind !== 'read');
    return evaluationSessions(rt, write === undefined ? b : { ...b, action: { name: write } }, pep);
  }
  if (path === '/access/v1/evaluations' && Array.isArray(b.evaluations)) {
    return [...new Set(b.evaluations.flatMap((entry) => entry !== null && typeof entry === 'object' && !Array.isArray(entry)
      ? evaluationSessions(rt, { ...b, ...entry }, pep) : []))];
  }
  if (path !== '/x/v1/tokens/consume' || !rt.sessions) return evaluationSessions(rt, b, pep);
  try {
    const token = string(b.token);
    const claims = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString()) as { sid?: unknown; sub?: unknown; act?: unknown; res?: unknown };
    if (typeof claims.sid !== 'string' || typeof claims.sub !== 'string' || typeof claims.act !== 'string') return [];
    const pair = JSON.parse(claims.sub) as unknown;
    const resource = JSON.parse(String(claims.res)) as unknown;
    if (!Array.isArray(pair) || pair.length !== 2 || !Array.isArray(resource) || resource.length !== 2) return [];
    const candidate = { subject: { type: pair[0], id: pair[1] }, resource: { type: resource[0], id: resource[1] }, action: { name: claims.act } };
    return interacts(rt, candidate) ? [claims.sid] : [];
  } catch { return []; }
}

// A mismatched declaration compiles to a constant, which a forbid's NOT turns into a wrong allow.
const BUILT_IN_TYPES: Readonly<Record<string, string>> = { 'resource.level': 'number', 'resource.compartments': 'text[]', 'resource.contentClasses': 'text[]',
  'resource.id': 'text', 'resource.type': 'text', 'resource.owner': 'text', 'resource.integrity': 'text' };
function builtInTypesOk(columns: Record<string, unknown>): boolean {
  return Object.entries(BUILT_IN_TYPES).every(([path, want]) => {
    if (!Object.hasOwn(columns, path)) return true;
    const spec = columns[path] as string | { kind?: string; type?: string };
    const got = typeof spec === 'string' ? 'text' : spec?.type ?? (spec?.kind === 'text[]' ? 'text[]' : 'text');
    return got === want;
  });
}
type Veto = Parameters<typeof decide>[8];
type Ref = { type: string; id: string };
/** The caller's context plus the subject populations its PEP credential is bound to (E3), and the server-derived mark
 *  scope. A session token is usable only after prepare() verified it inside this request's session locks. */
function pepContext(rt: Runtime, input: unknown, s: Ref, pepTypes: readonly string[], pep: string | undefined, bindings?: SessionBindings): Context {
  const c = context(input, rt.now()); const raw = input === undefined ? {} : object(input);
  let sessionId = c.sessionId;
  if (sessionId !== undefined) {
    if (!rt.sessions?.legacyId()) throw new HttpError(400, 'session_token_required', 'Raw context.sessionId is refused: open a PDP session and send context.sessionToken');
    sessionId = scopeSession(pep, sessionId);
  }
  if (typeof raw.sessionToken === 'string') {
    if (!rt.pepSessions) throw new HttpError(403, 'invalid_session_token', 'Session token is invalid, expired, closed, or not bound to this request');
    sessionId = rt.pepSessions.binding(raw.sessionToken, s, bindings).scope;
  }
  return { ...c, ...(sessionId === undefined ? {} : { sessionId }), pepSubjectTypes: pepTypes };
}
/** A permitted point read of a classified resource raises its session's high-water mark, before the permit is answered
 *  (and, with PostgreSQL, committed with it). Searches, filters, explanations and list assertions never raise it: they
 *  release ids or a residual, not the content. A mark that cannot be recorded refuses the read. */
function readMark(rt: Runtime, s: Ref, r: Ref, action: string, ctx: Context, pep: string | undefined): { rule: string; reason: string } | undefined {
  if (!rt.sessions || ctx.sessionId === undefined) return undefined;
  const state = rt.store.state;
  const actions = Object.hasOwn(state.bundle.schema.resourceTypes, r.type) ? state.bundle.schema.resourceTypes[r.type]!.actions : {};
  const resource = findRef(state.resources, r.id, r.type);
  if (!resource || resource.level === 0 || !Object.hasOwn(actions, action) || actions[action]!.kind !== 'read') return undefined;
  return rt.sessions.raise(ctx.sessionId, s, resource.level, pep) ? undefined
    : { rule: 'BLP.SESSION_LIMIT', reason: 'too many open sessions for this PEP credential to record this read: retry later' };
}
function request(rt: Runtime, b: Record<string, unknown>, veto?: Veto, pepTypes: readonly string[] = [], details?: Record<string, unknown>, pep?: string, mark = false, bindings?: SessionBindings): { d: Decision; s: Ref; r: Ref; action: string; ctx: Context } {
  const s = ref(b.subject); const r = ref(b.resource); const action = string(object(b.action).name);
  const ctx = pepContext(rt, b.context, s, pepTypes, pep, bindings);
  const vetoes: Veto = (d) => veto?.(d) ?? (mark ? readMark(rt, s, r, action, ctx, pep) : undefined);
  return { d: decide(rt, s, r, action, ctx, 'pep', rt.store.state, true, vetoes, details), s, r, action, ctx };
}
/** One AuthZEN evaluation; `veto` lets a mapping (XACML) turn a permit it cannot express into an audited deny. */
export function evaluation(rt: Runtime, b: Record<string, unknown>, veto?: Veto, pepTypes: readonly string[] = [], details?: Record<string, unknown>, pep?: string, bindings?: SessionBindings, trust?: ContextTrust): unknown {
  if (trust) {
    const token = (b.context as { sessionToken?: unknown } | undefined)?.sessionToken;
    const sessionId = typeof token === 'string' ? bindings?.get(token)?.sid : undefined;
    authorizeContext(b.context, trust, rt.now(), { subject: ref(b.subject), ...(sessionId ? { sessionId } : {}) });
  }
  const { d, s, r, action, ctx } = request(rt, b, veto, pepTypes, details, pep, true, bindings);
  const obligation = d.obligations.decisionToken;
  // `sid`: the issuing session, whose mark the consumption decides against (loaded first with PostgreSQL); `bsid`: the
  // BLP session the token came from (verified by prepare()), so closing, revoking or expiring it revokes the approval too
  const sessionToken = (b.context as { sessionToken?: unknown } | undefined)?.sessionToken;
  const bsid = typeof sessionToken === 'string' ? bindings?.get(sessionToken)?.sid : undefined;
  const token = d.decision && obligation ? rt.tokens.issue({ sub: JSON.stringify([s.type, s.id]), act: action, res: JSON.stringify([r.type, r.id]),
    ver: obligation.resourceVersion, pv: d.policyVersion, ...(ctx.sessionId === undefined ? {} : { sid: ctx.sessionId }), ...(bsid === undefined ? {} : { bsid }) },
    obligation.ttlSeconds, ctx) : undefined;
  return { decision: d.decision, context: { rules: d.rules, reasons: d.reasons, obligations: d.obligations,
    policy_version: d.policyVersion, would_deny: d.wouldDeny, ...(token ? { decision_token: token } : {}) } };
}
/** What the backend will check the forwarded request against: its origin, method, path with query, body digest. */
function binding(input: unknown): Pick<AssertionClaims, 'aud' | 'htm' | 'htp' | 'bsh'> {
  const q = object(input);
  const aud = string(q.audience); const htm = string(q.method); const htp = string(q.path); const bsh = string(q.bodySha256);
  let origin = '';
  try { origin = new URL(aud).origin; } catch { /* refused below */ }
  if (origin !== aud || !/^https?:\/\//.test(aud) || aud.length > 256 || !/^[A-Z]{1,16}$/.test(htm) || htp.length > 2048 || !/^\/[\x21-\x7e]*$/.test(htp) || !/^[A-Za-z0-9_-]{43}$/.test(bsh)) {
    throw new HttpError(400, 'bad_request', 'Invalid request binding');
  }
  return { aud, htm, htp, bsh };
}
/** Decision assertions (docs/API.md 2.0.2): the PDP signs, so the PEP asking never holds a signing key, and a deny gets none. */
function assertion(rt: Runtime, path: string, b: Record<string, unknown>, pepTypes: readonly string[], pep: string | undefined, bindings?: SessionBindings): unknown {
  const bound = binding(b.request);
  const did = randomUUID();
  const s = ref(b.subject); const act = string(object(b.action).name);
  if (path === '/x/v1/assertions/evaluation') {
    const e = evaluation(rt, b, undefined, pepTypes, { decisionId: did }, pep, bindings) as { decision: boolean; context: { policy_version: string } };
    return e.decision ? { ...e, assertion: rt.tokens.assertion({ sub: s, act, res: ref(b.resource), did, pv: e.context.policy_version, ...bound }) } : e;
  }
  // a list: the PEP releases items one by one after per-item decisions; this only proves the subject may act on some item of the type
  const type = string(object(b.resource).type); const state = rt.store.state;
  const who = subject(state, s.id, s.type);
  const residual = who ? buildFilter(state.bundle, who, type, act, withCertified(state, withSession(rt, s, pepContext(rt, b.context, s, pepTypes, pep, bindings))), graphOf(state.tuples)) : FALSE;
  const decision = canonical(residual) !== canonical(FALSE);
  const pv = policyVersion(state.bundle);
  rt.audit.append({ type: 'decision', actor: 'pep', action: act, subject: s.id, effect: decision ? 'allow' : 'deny', rules: [decision ? 'GATE.LIST_ASSERTION' : 'GATE.LIST_NONE'],
    policyVersion: pv, details: { decisionId: did, listOf: type } });
  return { decision, policy_version: pv, ...(decision ? { assertion: rt.tokens.assertion({ sub: s, act, res: { type }, did, pv, ...bound }) } : {}) };
}
/** subjectSearch: the calling credential may list who can access a resource (allowSubjectSearch, docs/API.md);
 *  pep: the calling credential's id, which a reservation keeps so that only that credential reports its outcome. */
export function pdp(rt: Runtime, path: string, b: Record<string, unknown>, pepTypes: readonly string[] = [], subjectSearch = true, pep?: string, bindings?: SessionBindings): unknown {
  if (path === '/access/v1/evaluation') return evaluation(rt, b, undefined, pepTypes, undefined, pep, bindings);
  if (path === '/x/v1/assertions/evaluation' || path === '/x/v1/assertions/list') return assertion(rt, path, b, pepTypes, pep, bindings);
  if (path === '/access/v1/evaluations') {
    if (!Array.isArray(b.evaluations) || b.evaluations.length > 1000) throw new HttpError(400, 'bad_request');
    const semantic = b.options === undefined ? 'execute_all' : object(b.options).evaluations_semantic ?? 'execute_all';
    if (!['execute_all', 'deny_on_first_deny', 'permit_on_first_permit'].includes(String(semantic))) throw new HttpError(400, 'bad_request');
    const evaluations: unknown[] = [];
    for (const entry of b.evaluations) {
      const merged = { ...b, ...object(entry) };
      const value = evaluation(rt, merged, undefined, pepTypes, undefined, pep, bindings) as { decision: boolean };
      evaluations.push(value);
      if ((semantic === 'deny_on_first_deny' && !value.decision) || (semantic === 'permit_on_first_permit' && value.decision)) break;
    }
    return { evaluations };
  }
  if (path === '/x/v1/explain') {
    const { d, s, r, ctx } = request(rt, b, undefined, pepTypes, undefined, pep, false, bindings);
    const read = decide(rt, s, r, 'read', ctx, 'pep', rt.store.state, false);
    if (!read.decision || d.rules.includes('CORE.UNKNOWN_ID')) throw new HttpError(404, 'not_found');
    return d;
  }
  if (path === '/x/v1/filter') {
    const s = ref(b.subject); const r = object(b.resource); const action = string(object(b.action).name);
    const type = string(r.type);
    if (b.dialect !== undefined && b.dialect !== 'postgres') throw new HttpError(400, 'bad_request');
    const who = subject(rt.store.state, s.id, s.type);
    const residual = who ? buildFilter(rt.store.state.bundle, who, type, action, withCertified(rt.store.state, withSession(rt, s, pepContext(rt, b.context, s, pepTypes, pep, bindings))), graphOf(rt.store.state.tuples)) : FALSE;
    const columns = object(b.columns);
    if (!builtInTypesOk(columns)) throw new HttpError(400, 'bad_request', 'Built-in field mapped with the wrong type');
    let sql: ReturnType<typeof compile>;
    try { sql = compile(residual, columns as Columns); }
    catch { throw new HttpError(400, 'bad_request', 'Invalid column mapping or residual'); }
    // list access is audited as /x/v1/assertions/list is: the predicate released, by its kind (the router commits it first)
    const kind = canonical(residual) === canonical(FALSE) ? 'false' : canonical(residual) === canonical(TRUE) ? 'true' : 'conditional';
    rt.audit.append({ type: 'decision', actor: 'pep', action, subject: s.id, effect: kind === 'false' ? 'deny' : 'allow', rules: [kind === 'false' ? 'GATE.FILTER_NONE' : 'GATE.FILTER'],
      policyVersion: policyVersion(rt.store.state.bundle), details: { listOf: type, residual: kind } });
    return { residual, sql };
  }
  if (path === '/x/v1/tokens/consume') {
    const r = ref(b.resource); const action = typeof b.action === 'string' ? b.action : string(object(b.action).name);
    // the item's attributes as the certified command will commit them (Clark-Wilson C2): checked by the IVPs too
    const proposed = b.attrs === undefined ? undefined : object(b.attrs);
    // refused before the token is touched: the PEP may retry with a valid post-state within the token's life
    if (proposed) checkPostState(rt.store.state.bundle, r.type, action, proposed);
    // the action is reserved inside the check (with PostgreSQL it commits in the consuming transaction); the PEP reports
    // its outcome once the command ran (/x/v1/tokens/outcome)
    const reservation = randomUUID();
    let sessionGone = false;
    const check = (claims: Claims, ctx: Context, session?: StoredPepSession): boolean => {
      const pair: unknown = JSON.parse(claims.sub);
      if (!Array.isArray(pair) || pair.length !== 2 || pair.some((v) => typeof v !== 'string')) return false;
      const s = { type: pair[0] as string, id: pair[1] as string };
      const resource = rt.store.state.resources.find((x) => x.id === r.id && x.type === r.type);
      if (!resource || claims.act !== action || claims.res !== JSON.stringify([r.type, r.id]) || claims.ver !== (b.resourceVersion ?? null) ||
        (resource.version ?? null) !== claims.ver || claims.pv !== policyVersion(rt.store.state.bundle)) return false;
      // minted in a BLP session: closed, revoked, expired, or another subject's or credential's now, the approval is gone with it
      if (claims.bsid !== undefined && !rt.pepSessions?.usable(claims.bsid, claims.sub, pep, session)) {
        sessionGone = true;
        rt.audit.append({ type: 'decision', actor: 'pep', action, subject: s.id, resource: r.id, effect: 'deny', rules: ['CBAC.SESSION_EXPIRED'],
          policyVersion: claims.pv, details: { phase: 'token_consume', session: 'closed_or_expired' } });
        return false;
      }
      // re-decided for the consuming PEP's binding (E3), with the post-state as the command's input (C5)
      const { input: decidedInput, ...rest } = ctx;
      if (!decide(rt, s, r, action, { ...rest, now: rt.now(), pepSubjectTypes: pepTypes, ...(proposed ? { input: proposed as Context['input'] } : {}) }).decision) return false;
      if (!proposed && ivpsFor(rt.store.state.bundle, r.type).length > 0) {
        // C1 on the state to be committed: without it the IVPs would only have seen the state before the command
        rt.audit.append({ type: 'decision', actor: 'pep', action, subject: s.id, resource: r.id, effect: 'deny', rules: ['CW.POST_STATE_REQUIRED'],
          policyVersion: claims.pv, details: { phase: 'token_consume', state: 'missing' } });
        return false;
      }
      if (proposed) {
        const failed = verifyIntegrity(rt.store.state.bundle, { ...resource, attrs: { ...resource.attrs, ...proposed } as typeof resource.attrs })
          .filter((x) => !x.ok).map((x) => `CW.IVP.${x.ivp}`);
        if (failed.length) {
          // refused, not consumed: the command must not run; the PEP may retry with a valid state within the token's life
          rt.audit.append({ type: 'decision', actor: 'pep', action, subject: s.id, resource: r.id, effect: 'deny', rules: failed,
            policyVersion: claims.pv, details: { phase: 'token_consume', state: 'proposed' } });
          return false;
        }
      }
      const actor = subject(rt.store.state, s.id, s.type);
      const onBehalfOf = actor ? principals(actor).slice(1).map((p) => ({ type: p.type, id: p.id })) : [];
      // the post-state rides with the reservation: the PDP's copy follows it once the PEP reports the command completed
      rt.store.recordPerformed({ id: reservation, ...(pep ? { pep } : {}), subject: s, resource: r, action, at: rt.now(), ...(onBehalfOf.length ? { onBehalfOf } : {}),
        ...(proposed ? { postState: proposed as NonNullable<Performed['postState']>, boundVersion: resource.version ?? 0 } : {}) });
      return true;
    };
    const refused = (err: unknown): never => {
      throw sessionGone ? new HttpError(409, 'conflict', 'Decision token cannot be consumed: the BLP session it was issued in is closed or expired') : err;
    };
    let consumed: void | Promise<void> = undefined;
    try { consumed = rt.tokens.consume(string(b.token), check, rt.sessions && decisionSessions(rt, path, b, pep).length > 0 ? (sid: string, load: MarkLoader) => rt.sessions!.refresh([sid], pep, load) : undefined); }
    catch (err) { refused(err); }
    return consumed ? consumed.then(() => ({ ok: true, reservation }), refused) : { ok: true, reservation };
  }
  if (path === '/x/v1/tokens/outcome') return outcome(rt, b, pep);
  if (path === '/access/v1/search/subject' && !subjectSearch) throw new HttpError(403, 'forbidden', 'This PEP credential may not search subjects (allowSubjectSearch is false)');
  if (path.startsWith('/access/v1/search/')) return search(rt, path, b, pepTypes, pep, bindings);
  throw new HttpError(404, 'not_found');
}
/** The PEP reports what became of a reserved action: "completed" keeps it in the history, "failed" takes it out of
 *  separation of duty. Once per reservation: the same report again is answered as before, another one is refused. */
function outcome(rt: Runtime, b: Record<string, unknown>, pep: string | undefined): { ok: true; reservation: string; outcome: ActionOutcome } | Promise<{ ok: true; reservation: string; outcome: ActionOutcome }> {
  const ref = string(b.reservation);
  const result = b.outcome;
  if (ref.length > 64 || (result !== 'completed' && result !== 'failed')) throw new HttpError(400, 'bad_request');
  let answer: 'recorded' | 'same' | 'conflict' | 'unknown' | 'leader' = 'unknown';
  const check = ({ reservation: r, outcome: before }: Reservation): boolean => {
    // another credential's reservation is answered as unknown: a PEP cannot erase what another one did
    if (!r || (r.pep ?? null) !== (pep ?? null)) { answer = 'unknown'; return false; }
    const row = { actor: 'pep', action: r.action, subject: r.subject.id, resource: r.resource.id };
    if (before) {
      answer = before === result ? 'same' : 'conflict';
      if (answer === 'conflict') {
        rt.audit.append({ type: 'decision', ...row, effect: 'deny', rules: ['GATE.OUTCOME_CONFLICT'], details: { phase: 'outcome', reservation: ref, reported: result, recorded: before } });
      }
      return false;
    }
    // a post-state writes the state document: only the leader settles such a completion (a follower passes it on)
    const post = result === 'completed' && r.postState !== undefined;
    if (post && rt.node && !rt.node.leader()) { answer = 'leader'; return false; }
    rt.store.recordOutcome({ ref, outcome: result, at: rt.now() });
    let postState: Record<string, unknown> | undefined;
    if (post) {
      const applied = applyPostState(rt.store.state, { ...r, id: ref }, rt.now());
      rt.store.state = applied.state; rt.store.save(); // committed with the outcome row (one transaction with PostgreSQL)
      postState = applied.applied ? { applied: true, version: applied.version } : { applied: false, reason: applied.reason };
    }
    rt.audit.append({ type: 'decision', ...row, rules: [result === 'completed' ? 'GATE.ACTION_COMPLETED' : 'GATE.ACTION_FAILED'],
      details: { phase: 'outcome', reservation: ref, outcome: result, reservedAt: r.at, ...(postState ? { postState } : {}) } });
    answer = 'recorded';
    return true;
  };
  const done = (): { ok: true; reservation: string; outcome: ActionOutcome } => {
    if (answer === 'unknown') throw new HttpError(404, 'not_found', 'Unknown reservation');
    if (answer === 'leader') throw new HttpError(409, 'not_leader', 'This completion carries a post-state: report it to the leader');
    if (answer === 'conflict') throw new HttpError(409, 'conflict', 'Another outcome was already reported for this reservation');
    return { ok: true, reservation: ref, outcome: result };
  };
  const settled = rt.store.settle(ref, check);
  return settled instanceof Promise ? settled.then(done) : done();
}
function searchPage(input: unknown): { limit: number; offset: number } {
  const page = input === undefined ? {} : object(input);
  const limit = page.limit ?? 100;
  if (!Number.isInteger(limit) || Number(limit) < 1 || Number(limit) > 1000) throw new HttpError(400, 'bad_request');
  const token = page.token === undefined ? '' : (page.token === '' ? '' : string(page.token));
  // "c" marks a candidate position: tokens from before lazy paging counted results and are refused
  const decoded = token ? Buffer.from(token, 'base64url').toString() : 'c0';
  if (token && (!/^c\d+$/.test(decoded) || Buffer.from(decoded).toString('base64url') !== token)) throw new HttpError(400, 'bad_request');
  const offset = Number(decoded.slice(1));
  if (!Number.isSafeInteger(offset) || offset < 0) throw new HttpError(400, 'bad_request');
  return { limit: Number(limit), offset };
}
const searchIndexes = new WeakMap<readonly Resource[], { revision: number; index: ResourceCandidates }>();
function indexedResources(rt: Runtime): ResourceCandidates {
  const state = rt.store.state, revision = rt.store.revision;
  const existing = searchIndexes.get(state.resources);
  if (existing?.revision === revision) return existing.index;
  const index = new ResourceCandidates(state.resources);
  searchIndexes.set(state.resources, { revision, index });
  return index;
}

function search(rt: Runtime, path: string, b: Record<string, unknown>, pepTypes: readonly string[], pep: string | undefined, bindings?: SessionBindings): unknown {
  const state = rt.store.state;
  const resourceSearch = path === '/access/v1/search/resource';
  const raw = b.context === undefined ? {} : object(b.context);
  if (path === '/access/v1/search/subject' && raw.sessionToken !== undefined) throw new HttpError(400, 'bad_request', 'A subject-bound session token cannot search other subjects');
  const s = path === '/access/v1/search/action' || resourceSearch ? ref(b.subject) : { type: '', id: '' };
  const ctx = pepContext(rt, b.context, s, pepTypes, pep, bindings);
  if (path === '/access/v1/search/action') {
    const r = ref(b.resource);
    const actions = Object.keys(Object.hasOwn(state.bundle.schema.resourceTypes, r.type) ? state.bundle.schema.resourceTypes[r.type]?.actions ?? {} : {});
    return { results: actions.filter((a) => decide(rt, s, r, a, ctx).decision).map((name) => ({ name })) };
  }
  const action = string(object(b.action).name);
  if (!resourceSearch && path !== '/access/v1/search/subject') throw new HttpError(404, 'not_found');
  const target = ref(resourceSearch ? b.subject : b.resource);
  const type = string(object(resourceSearch ? b.resource : b.subject).type);
  const { limit, offset } = searchPage(b.page);
  const who = resourceSearch ? subject(state, target.id, target.type) : undefined;
  const residual = who ? buildFilter(state.bundle, who, type, action, withCertified(state, withSession(rt, target, ctx)), graphOf(state.tuples)) : FALSE;
  const source = resourceSearch ? state.resources : state.subjects;
  const candidates = resourceSearch ? indexedResources(rt).match(residual, type)
    : subjectCandidates(state.bundle, state.subjects, type, findRef(state.resources, target.id, target.type), action, ctx, graphOf(state.tuples),
      (candidate) => withSession(rt, candidate, ctx));
  const results: { type: string; id: string }[] = [];
  let nextToken = '';
  for (let i = candidates.next(offset); i < candidates.length; i = candidates.next(i + 1)) {
    const candidate = source[i]!;
    // past a full page the scan only looks for a next item: not answered, so not audited (the next page decides it again)
    const allowed = decide(rt, resourceSearch ? target : candidate, resourceSearch ? candidate : target, action, ctx, 'pep', state, results.length < limit).decision;
    if (!allowed) continue;
    if (results.length === limit) {
      // Reconsider the lookahead at this original-array position on the next page rather than skipping it.
      nextToken = Buffer.from(`c${i}`).toString('base64url');
      break;
    }
    results.push({ type: candidate.type, id: candidate.id });
  }
  return { results, page: { next_token: nextToken } };
}
