import type { IncomingMessage, ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import type { Runtime } from './runtime.ts';
import type { Auth } from './auth.ts';
import { LeasedRateLimiter, RateLimiter, DEFAULT_RATE_LIMIT, DEFAULT_PEP_RATE_LIMIT, type LeaseRateLimit } from './ratelimit.ts';
import { HttpError, body, formBody, headers, json, failure, rawBody, secureFlag } from './http.ts';
import { safePath, serveStatic } from './static.ts';
import { decisionSessions, pdp } from './pdp.ts';
import { admin } from './admin/index.ts';
import { session } from './admin/session.ts';
import type { Oidc } from './oidc.ts';
import { SAML_ACS_PATH, SAML_LOGOUT_PATH, SAML_METADATA_PATH, type Saml } from './saml.ts';
import type { OidcSession, User } from './auth.ts';
import { metrics, metricsText, readiness, routeFamily } from './metrics.ts';
import type { Scim } from './scim.ts';
import { pullAudit } from './siem.ts';
import { pseudonymKey } from './admin/privacy.ts';
import { childSpan, endRequestSpan, traceClock, type Tracer } from './tracing.ts';
import { xacml, xacmlCost, xacmlMalformed, xacmlSessions } from './xacml.ts';
import { clientAddress } from './proxy.ts';
import type { BlockList } from 'node:net';
import { forwardToLeader, HOP_HEADER, hopNode, HopVerifier, leaderOrigin } from './forward.ts';
import { hopKeyOf, REPLICA_HOP_HEADER, REPLICA_PATHS, replicaKeyFor } from './replica-protocol.ts';
import type { ReplicaSource } from './replica-source.ts';
import { registrationCost, resources, RESOURCE_PATHS } from './resources.ts';
import { sessionTokensIn, type SessionBindings } from './pep-sessions.ts';
import { authorizeRequestContexts, type ContextTrust } from './context-trust.ts';

/** Console sign-in and transport settings; see docs/API.md (Console sign-in). */
export interface Security { publicOrigin?: string; oidc?: Oidc; saml?: Saml; passwordLogin?: boolean }
type SsoOutcome = { user: User; session: OidcSession } | { failure: string; subject?: string; quiet?: boolean };
/** A posted SAML message (base64 XML with the IdP certificate inside): far above any real one, far below the body cap. */
const SAML_MESSAGE_MAX = 262_144;

export function createHandler(rt: Runtime, auth: Auth, options: { rateLimit?: number; pepRateLimit?: number; blpSessionCreationRateLimit?: number; staticDir?: string; elapsed?: () => number; security?: Security; scim?: Scim; tracer?: Tracer;
  /** TRUSTED_PROXIES, parsed (proxy.ts): only then is X-Forwarded-For read. */ proxies?: BlockList;
  /** Cluster mode: the key that authenticates a follower's hop to the leader (forward.ts); without it followers answer 409. */ hopKey?: Buffer;
  /** Cluster mode: leases from the shared PostgreSQL buckets; absent keeps the single-node in-memory limiter. */ rateLimitLease?: LeaseRateLimit;
  /** True while the node listens on a non-loopback address: /metrics then requires METRICS_TOKEN. */ metricsTokenRequired?: () => boolean;
  /** Database node: GATE_REPLICA_KEYS (replica id -> key) and the feed it serves them (replica-source.ts). */ replicaKeys?: ReadonlyMap<string, Buffer>; replicaSource?: ReplicaSource;
  /** Replica mode (replica.ts): what it decides itself, and how it passes everything else to the database nodes. */
  replica?: { local(path: string, b: Record<string, unknown>): boolean; forward(req: IncomingMessage, res: ServerResponse, client: string): Promise<void> } },
  base: () => string): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const audit = rt.audit; const now = rt.now;
  const registry = metrics(rt);
  const refusalCap = refusalLimiter();
  const legacyContextWarnings = new Set<string>();
  const contextTrust = (caller: { credential: string; contextScopes?: ContextTrust['scopes'] }, res: ServerResponse): ContextTrust => ({
    credential: caller.credential, scopes: caller.contextScopes,
    legacyWarning: () => {
      res.setHeader('Deprecation', 'true');
      res.setHeader('Warning', '299 gate "Unscoped PEP context claims are deprecated; create a credential with contextScopes"');
      if (!legacyContextWarnings.has(caller.credential)) {
        legacyContextWarnings.add(caller.credential);
        console.warn(`WARNING: PEP credential ${caller.credential} asserted context without contextScopes (deprecated compatibility; production refuses it)`);
      }
    },
  });
  // console, SCIM and anonymous traffic per address and principal; the decision plane has its own, larger budget
  const limit = options.rateLimit ?? DEFAULT_RATE_LIMIT;
  const pepLimit = options.pepRateLimit ?? DEFAULT_PEP_RATE_LIMIT;
  const decisionPlane = (p: string): boolean => p.startsWith('/access/') || p.startsWith('/x/') || p === '/xacml/v3/authorize';
  const commit = async (): Promise<void> => {
    if (!rt.commit) return;
    const started = traceClock();
    try { await rt.commit(); childSpan('gate.commit', started); }
    catch (err) { childSpan('gate.commit', started, {}, true); throw err; }
  };
  const limiter = options.rateLimitLease ? new LeasedRateLimiter(options.rateLimitLease) : new RateLimiter();
  const hops = options.hopKey ? new HopVerifier(options.hopKey) : undefined;
  // one replay memory for every replica; each hop verifies under the key of the replica it names (replicaKeyFor)
  const replicaHops = new HopVerifier(Buffer.alloc(32));
  /** No decision on a shared state older than the staleness bound: 503, the PEP retries another node. */
  const fresh = (): void => {
    if (rt.node && !rt.node.fresh()) throw new HttpError(503, 'unavailable', 'This node has not confirmed the shared policy state within its staleness bound');
  };
  // throttling runs on real elapsed time: a pinned business clock (CLOCK=fixed demo) must not freeze the refill
  const elapsed = options.elapsed ?? ((): number => performance.now());
  const security = options.security ?? {};
  const hsts = Boolean(security.publicOrigin?.startsWith('https://'));
  /** Authorization-code sign-in. The state cookie is SameSite=Lax because the IdP returns by a cross-site top-level GET;
   *  __Host- prefixed so a sibling domain cannot plant one (login CSRF). */
  const sso = async (oidc: Oidc, path: string, url: URL, req: IncomingMessage, res: ServerResponse, client: string): Promise<void> => {
    const secure = secureFlag(req, security.publicOrigin);
    const stateCookie = (value: string, age: number): string => `__Host-gate_oidc=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${age}`;
    if (path === '/admin/v1/oidc/login') {
      let started: Awaited<ReturnType<Oidc['start']>>;
      try { started = await oidc.start(); } catch { redirect(res, '/?sso_error=sso_failed', []); return; }
      redirect(res, started.location, [stateCookie(started.cookie, 600)]); return;
    }
    const code = url.searchParams.get('code') ?? '', state = url.searchParams.get('state') ?? '';
    let outcome: Awaited<ReturnType<Oidc['finish']>> = { failure: 'sso_failed', quiet: true };
    if (!url.searchParams.has('error') && code && state && code.length <= 4096 && state.length <= 256) {
      try { outcome = await oidc.finish(code, state, cookie(req, '__Host-gate_oidc')); } catch { outcome = { failure: 'sso_failed' }; }
    }
    await signedIn('oidc', 'failure' in outcome ? outcome : { user: outcome.user, session: outcome.oidc }, res, stateCookie('', 0), secure, client);
  };
  /** The end of an IdP sign-in: a refusal is audited unless it never answered a sign-in started here (quiet). */
  const signedIn = async (method: 'oidc' | 'saml', outcome: SsoOutcome, res: ServerResponse, clear: string, secure: string, client: string): Promise<void> => {
    if ('failure' in outcome) {
      if (!outcome.quiet) audit.append({ type: 'session', actor: outcome.subject === undefined ? 'unknown' : auth.failedLoginActor(outcome.subject), action: 'login', effect: 'deny', details: { method, reason: outcome.failure, client } });
      await commit();
      redirect(res, `/?sso_error=${outcome.failure}`, [clear]); return;
    }
    const opened = auth.issue(outcome.user, method, outcome.session, undefined, client);
    await commit();
    redirect(res, '/', [clear, `sid=${opened.sid}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=28800${secure}`]);
  };
  /** SAML Web SSO. The IdP posts the Response cross-site, which a SameSite=Lax cookie does not survive: the request id is
   *  bound to the browser in a SameSite=None cookie, __Host- prefixed so a sibling domain cannot plant one (login CSRF). */
  const samlCookie = (value: string, age: number): string => `__Host-gate_saml=${value}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${age}`;
  const samlSso = async (saml: Saml, path: string, req: IncomingMessage, res: ServerResponse, client: string): Promise<void> => {
    if (path !== SAML_ACS_PATH) {
      let started: Awaited<ReturnType<Saml['start']>>;
      try { started = await saml.start(); } catch { redirect(res, '/?sso_error=sso_failed', []); return; }
      redirect(res, started.location, [samlCookie(started.requestId, 600)]); return;
    }
    const posted = (await formBody(req, SAML_MESSAGE_MAX)).getAll('SAMLResponse');
    let outcome: Awaited<ReturnType<Saml['finish']>> = { failure: 'sso_failed', quiet: true };
    if (posted.length === 1) {
      try { outcome = await saml.finish(posted[0]!, cookie(req, '__Host-gate_saml')); } catch { outcome = { failure: 'sso_failed' }; }
    }
    await signedIn('saml', 'failure' in outcome ? outcome : { user: outcome.user, session: outcome.idp }, res, samlCookie('', 0), secureFlag(req, security.publicOrigin), client);
  };
  /** Signed IdP messages need no browser session or CSRF token. */
  const samlLogout = async (saml: Saml, req: IncomingMessage, res: ServerResponse, client: string): Promise<void> => {
    const rawQuery = req.method === 'GET' ? (req.url ?? '').split('?').slice(1).join('?') : undefined;
    const form = rawQuery !== undefined ? new URLSearchParams(rawQuery) : await formBody(req, SAML_MESSAGE_MAX);
    const message = await saml.logoutMessage(form, rawQuery);
    if (!message) {
      const suppressed = refusalCap.admit(`${client} saml invalid_logout_request`);
      if (suppressed !== undefined) audit.append({ type: 'session', actor: 'unknown', action: 'saml_logout', effect: 'deny',
        details: { reason: 'invalid_logout_request', ...(suppressed ? { suppressedSinceLastRow: suppressed } : {}) } });
      await commit();
      json(res, { error: 'invalid_request', message: 'Invalid logout request' }, 400); return;
    }
    const sessionsEnded = message.target ? await auth.endOidcSessions(message.target, 'saml') : 0;
    audit.append({ type: 'session', actor: message.target?.sub ?? 'unknown', action: 'saml_logout', effect: 'allow', details: { sessionsEnded } });
    await commit();
    redirect(res, message.location, [`sid=; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=0${secureFlag(req, security.publicOrigin)}`]);
  };
  /** OpenID Connect Back-Channel Logout 1.0: the IdP posts a signed logout token, server to server (no session, no CSRF). */
  const backchannelLogout = async (oidc: Oidc, req: IncomingMessage, res: ServerResponse, client: string): Promise<void> => {
    const form = await formBody(req);
    const tokens = form.getAll('logout_token');
    const target = tokens.length === 1 && tokens[0] ? await oidc.verifyLogoutToken(tokens[0]) : null;
    if (!target) {
      const suppressed = refusalCap.admit(`${client} oidc invalid_logout_token`);
      if (suppressed !== undefined) audit.append({ type: 'session', actor: 'unknown', action: 'oidc_backchannel_logout', effect: 'deny',
        details: { reason: 'invalid_logout_token', ...(suppressed ? { suppressedSinceLastRow: suppressed } : {}) } });
      await commit();
      json(res, { error: 'invalid_request', message: 'Invalid logout token' }, 400); return;
    }
    const sessionsEnded = await auth.endOidcSessions(target);
    audit.append({ type: 'session', actor: target.sub ?? 'unknown', action: 'oidc_backchannel_logout', effect: 'allow', details: { sessionsEnded } });
    await commit();
    json(res, {});
  };
  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const requestStarted = performance.now();
    headers(res, true, hsts || Boolean('encrypted' in req.socket && req.socket.encrypted));
    // the Date header follows the server clock, so clients compute countdowns on server time (a pinned demo clock included)
    res.setHeader('Date', new Date(now()).toUTCString());
    let ip = clientAddress(req, options.proxies);
    const hop = req.headers[HOP_HEADER];
    let actor: string | undefined;
    let path = '';
    let validated: ReturnType<Auth['session']> | undefined;
    try {
      path = safePath(req.url ?? '/');
      const url = new URL(req.url ?? '/', 'http://localhost');
      const method = req.method ?? 'GET';
      const at = Date.parse(now());
      const tick = elapsed();
      if (typeof hop === 'string' && rt.node?.leader()) {
        // a follower's hop: believed only when its signature (method, path, body digest), window and single use hold;
        // it names the real client. A refused hop counts against the sending address like any request.
        const verified = hops?.plausible(hop) ? hops.verify(hop, method, req.url ?? '/', await rawBody(req)) : null;
        if (!verified) { await limiter.take(`ip:${ip}`, tick, limit); throw new HttpError(401, 'unauthenticated', 'Invalid cluster hop'); }
        ip = verified.client;
      }
      // a replica (GATE_REPLICA_KEYS): its own feed and audit requests, or a request it passes on for a PEP or the console
      let replicaId: string | undefined;
      const replicaHop = req.headers[REPLICA_HOP_HEADER];
      if (typeof replicaHop === 'string' && !options.replica) {
        const node = hopNode(replicaHop);
        const key = node === undefined ? undefined : replicaKeyFor(options.replicaKeys ?? new Map(), node);
        const verified = key && replicaHops.plausible(replicaHop) ? replicaHops.verify(replicaHop, method, req.url ?? '/', await rawBody(req), Date.now(), hopKeyOf(key)) : null;
        if (!verified || verified.node !== node) { await limiter.take(`ip:${ip}`, tick, limit); throw new HttpError(401, 'unauthenticated', 'Invalid replica hop'); }
        // the client a hop names is the replica's to choose: its budgets are keyed on its id, which it cannot vary. Its own
        // feed and audit shipping get a separate budget, so a burst of forwarded traffic cannot starve the feed and leave
        // the replica stale (the full-snapshot cap still applies inside the feed).
        if (replicaOwnPath(path)) await limiter.take(`replica-feed:${node}`, tick, REPLICA_FEED_RATE_LIMIT);
        else await limiter.take(`replica:${node}`, tick, pepLimit);
        ip = verified.client; replicaId = node;
      }
      const ownReplicaPath = replicaId !== undefined && replicaOwnPath(path); // charged above on the replica's feed budget
      // probes answer before the limiter: a full or drained bucket map must not take a healthy node out of its pool. All three
      // are cheap (readiness is cached, leadership is in memory) and reveal nothing a probe does not need.
      if (method === 'GET' && path === '/healthz') { json(res, { status: 'ok' }); return; }
      if (method === 'GET' && path === '/readyz') { await readiness(rt, res, tick); return; }
      if (method === 'GET' && path === '/leaderz') {
        // a load balancer sends /admin and /scim to the node answering 200 here
        const leader = rt.node ? rt.node.leader() : true;
        json(res, { leader, ...(rt.node ? { node: rt.node.id } : {}) }, leader ? 200 : 503); return;
      }
      if (!ownReplicaPath) await (decisionPlane(path) ? limiter.take(`pdp-ip:${ip}`, tick, pepLimit) : limiter.take(`ip:${ip}`, tick, limit));
      if (path.startsWith(REPLICA_PATHS)) {
        if (!replicaId || !options.replicaSource) throw new HttpError(401, 'unauthenticated', 'Replica requests need a valid replica hop');
        await options.replicaSource.handle(req, res, method, path, url, replicaId); return;
      }
      if (options.replica && (path.startsWith('/admin/') || path.startsWith('/scim/') || registrationRoute(path) || path === '/xacml/v3/authorize')) {
        await options.replica.forward(req, res, ip); return;
      }
      if (rt.node && !rt.node.leader() && (path.startsWith('/admin/') || path.startsWith('/scim/') || registrationRoute(path))) {
        // one writer for the state documents: a follower never takes an admin request, read or write (no audit row
        // either), nor a resource registration. It passes it to the leader it knows, once (a request that already made
        // a hop is not passed again).
        const leader = knownLeader(rt.node.leaderUrl());
        if (options.hopKey && leader && hop === undefined) { await forwardToLeader(req, res, leader, options.hopKey, rt.node.id, ip); return; }
        json(res, { error: 'not_leader', message: 'This node does not hold the admin plane: send console, SCIM and resource registration requests to the leader',
          leader: rt.node.leaderUrl() }, 409); return;
      }
      if (method === 'GET' && path === '/metrics') { metricsText(rt, req, res, options.metricsTokenRequired?.() ?? false); return; }
      if (method === 'GET' && path === '/.well-known/authzen-configuration') {
        json(res, { policy_decision_point: base(), access_evaluation_endpoint: `${base()}/access/v1/evaluation`,
          access_evaluations_endpoint: `${base()}/access/v1/evaluations`, search_subject_endpoint: `${base()}/access/v1/search/subject`,
          search_resource_endpoint: `${base()}/access/v1/search/resource`, search_action_endpoint: `${base()}/access/v1/search/action` }); return;
      }
      if (method === 'GET' && path === '/.well-known/jwks.json') {
        json(res, rt.tokens.jwks()); return;
      }
      if (method === 'GET' && path === '/admin/v1/auth-methods') {
        json(res, { password: security.passwordLogin !== false, sso: Boolean(security.oidc), saml: Boolean(security.saml) }); return;
      }
      if ((method === 'GET' && (path === '/admin/v1/saml/login' || path === SAML_METADATA_PATH || path === SAML_LOGOUT_PATH)) || (method === 'POST' && (path === SAML_ACS_PATH || path === SAML_LOGOUT_PATH))) {
        if (!security.saml) throw new HttpError(404, 'not_found');
        if (path === SAML_METADATA_PATH) { res.setHeader('Content-Type', 'application/samlmetadata+xml'); res.end(security.saml.metadata()); return; }
        if (path === SAML_LOGOUT_PATH) { await samlLogout(security.saml, req, res, ip); return; }
        await samlSso(security.saml, path, req, res, ip); return;
      }
      if (method === 'GET' && (path === '/admin/v1/oidc/login' || path === '/admin/v1/oidc/callback')) {
        if (!security.oidc) throw new HttpError(404, 'not_found');
        await sso(security.oidc, path, url, req, res, ip); return;
      }
      if (method === 'POST' && path === '/admin/v1/oidc/backchannel-logout') {
        if (!security.oidc) throw new HttpError(404, 'not_found');
        await backchannelLogout(security.oidc, req, res, ip); return;
      }
      // PostgreSQL: the sessions this request's cookies name, as stored (one indexed lookup); nothing to do with files
      if (path.startsWith('/admin/v1/')) await auth.load(req);
      if (method === 'POST' && path === '/admin/v1/saml/logout/start') {
        if (!security.saml) throw new HttpError(404, 'not_found');
        const loggedIn = auth.session(req, true);
        const target = auth.samlTarget(req);
        if (!target) throw new HttpError(400, 'invalid_request');
        const location = await security.saml.startLogout(target);
        const sessionsEnded = await auth.endOidcSessions(target, 'saml');
        audit.append({ type: 'session', actor: loggedIn.user.id, action: 'saml_logout', effect: 'allow', details: { sessionsEnded } });
        await commit();
        redirect(res, location, [`sid=; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=0${secureFlag(req, security.publicOrigin)}`]); return;
      }
      if (path === '/admin/v1/session' && ['POST', 'GET', 'DELETE'].includes(method)) {
        if (method !== 'POST') {
          const loggedIn = auth.session(req, false); actor = loggedIn.user.id;
          validated = loggedIn;
          if (method !== 'GET') auth.csrf(req, loggedIn.csrfToken);
          await limiter.take(`principal:${actor}`, tick, limit);
        }
        let b: Record<string, unknown> = {};
        if (method === 'POST') {
          try { b = await body(req); }
          catch (err) {
            const code = err instanceof HttpError ? err.code : 'internal';
            const suppressed = refusalCap.admit(`${ip} ${routeFamily(path)} ${code}`);
            if (suppressed !== undefined) audit.append({ type: 'session', actor: 'unknown', action: 'login', effect: 'deny',
              details: { client: ip, ...(suppressed ? { suppressedSinceLastRow: suppressed } : {}) } });
            throw err;
          }
        }
        await session(auth, req, res, b, ip, validated, security, commit); return;
      }
      if (path.startsWith('/admin/v1/')) {
        const loggedIn = auth.session(req, false); actor = loggedIn.user.id;
        if (method !== 'GET') auth.csrf(req, loggedIn.csrfToken);
        await limiter.take(`principal:${actor}`, tick, limit);
        if (method === 'GET' && path === '/admin/v1/audit/export') {
          const page = await pullAudit(audit, loggedIn.user, url, pseudonymKey(rt));
          res.setHeader('X-Audit-Next-From', String(page.next)); res.setHeader('Content-Type', page.contentType);
          res.end(page.body); return;
        }
        const b = method === 'POST' || method === 'PUT' ? await body(req) : {};
        const totp = method === 'POST' ? /^\/admin\/v1\/session\/totp\/(enrol|activate)$/.exec(path) : null;
        const result = totp ? { value: totp[1] === 'enrol' ? auth.enrolTotp(req, b.password) : auth.activateTotp(req, b.code), status: 200 }
          : method === 'GET' && path === '/admin/v1/session/totp' ? { value: auth.totpStatus(req), status: 200 }
          : path === '/admin/v1/scim/credential' && options.scim && (method === 'POST' || method === 'GET')
          ? method === 'POST' ? { value: options.scim.rotateCredential(loggedIn.user).body, status: 201 } : { value: options.scim.credentialInfo(loggedIn.user), status: 200 }
          : admin(rt, loggedIn.user, method, url, b, auth, { officersKnown: !(security.oidc || security.saml) });
        const value = await result.value;
        await commit();
        json(res, value, result.status); return;
      }
      if (registrationRoute(path)) {
        const caller = await auth.pepCallerAsync(req); actor = caller.actor;
        if (method !== 'POST') throw new HttpError(404, 'not_found');
        fresh();
        const b = await body(req);
        await limiter.take(`principal:${actor}`, tick, pepLimit, pepLimit, registrationCost(path, b));
        const result = resources(rt, path, b, caller);
        await commit();
        json(res, result.value, result.status); return;
      }
      if (path.startsWith('/access/') || path.startsWith('/x/')) {
        const caller = await auth.pepCallerAsync(req); actor = caller.actor;
        if (method !== 'POST') throw new HttpError(404, 'not_found');
        if (!options.replica) fresh();
        const b = await body(req);
        const cost = path === '/access/v1/evaluations' && Array.isArray(b.evaluations) ? Math.max(1, b.evaluations.length) : 1;
        await limiter.take(`principal:${actor}`, tick, pepLimit, pepLimit, cost);
        if (path === '/x/v1/sessions') await limiter.take(`blp-session:${caller.credential}`, tick, options.blpSessionCreationRateLimit ?? 60);
        // a replica passes on what its copy may not decide (whatever its freshness), and decides the rest only when fresh
        if (options.replica && !options.replica.local(path, b)) { await options.replica.forward(req, res, ip); return; }
        if (options.replica) fresh();
        if (path === '/x/v1/sessions' || path === '/x/v1/sessions/close') {
          if (!rt.pepSessions) throw new HttpError(503, 'unavailable', 'Session service unavailable');
          const opened = path === '/x/v1/sessions'
            ? await rt.pepSessions.open(b, caller.credential, caller.actor)
            : await rt.pepSessions.close(b.token, caller.credential, caller.actor);
          await commit(); json(res, opened, path === '/x/v1/sessions' ? 201 : 200); return;
        }
        let bindings: SessionBindings | undefined;
        const tokens = sessionTokensIn(b);
        const prepare = async (loader?: Parameters<NonNullable<Runtime['pepSessions']>['prepare']>[2]): Promise<void> => {
          bindings = await rt.pepSessions!.prepare(tokens, caller.credential, loader);
        };
        const decide = async (): Promise<unknown> => {
          authorizeRequestContexts(b, contextTrust(caller, res), now(), bindings, path === '/access/v1/evaluations');
          return pdp(rt, path, b, caller.subjectTypes, caller.allowSubjectSearch, caller.credential, bindings);
        };
        const marked = async (): Promise<unknown> => { const value = await decide(); await rt.afterDecision?.(); return value; };
        const sessions = decisionSessions(rt, path, b, caller.credential);
        let decided: unknown;
        try {
          if (sessions.length === 0 && tokens.length === 0) decided = await decide();
          else if (path === '/x/v1/tokens/consume') decided = await rt.sessions!.serial(sessions, async () => {
            // PostgreSQL reloads the sid after consumeToken takes its lock; file mode has no transaction to join.
            if (!rt.sessions!.shared) await rt.sessions!.refresh(sessions, caller.credential);
            return marked();
          });
          else decided = await rt.sessions!.ordered(sessions, caller.credential, marked, tokens.length ? prepare : undefined);
        } catch (err) {
          // a completion with a post-state is settled by the leader (it writes the state document): passed on once
          const leader = err instanceof HttpError && err.code === 'not_leader' && rt.node ? knownLeader(rt.node.leaderUrl()) : null;
          if (leader && options.hopKey && hop === undefined) { await forwardToLeader(req, res, leader, options.hopKey, rt.node!.id, ip); return; }
          throw err;
        }
        await commit();
        json(res, decided); return;
      }
      if (path === '/xacml/v3/authorize') {
        const caller = await auth.pepCallerAsync(req); actor = caller.actor;
        if (method !== 'POST') throw new HttpError(404, 'not_found');
        fresh();
        let b: Record<string, unknown> | undefined;
        // unparseable JSON is an XACML syntax error (Indeterminate), not an HTTP one; a wrong media type stays a 415
        try { b = await body(req); } catch (err) { if (!(err instanceof HttpError) || err.status !== 400) throw err; }
        await limiter.take(`principal:${actor}`, tick, pepLimit, pepLimit, b ? xacmlCost(b) : 1);
        const sessions = b ? xacmlSessions(rt, b, caller.credential) : [];
        const tokens = b ? sessionTokensIn(b) : [];
        let bindings: SessionBindings | undefined;
        const prepare = async (loader?: Parameters<NonNullable<Runtime['pepSessions']>['prepare']>[2]): Promise<void> => {
          bindings = await rt.pepSessions!.prepare(tokens, caller.credential, loader);
        };
        const decide = async (): Promise<unknown> => {
          const value = b ? xacml(rt, b, caller.subjectTypes, caller.credential, bindings, contextTrust(caller, res)) : xacmlMalformed(rt);
          if (sessions.length) await rt.afterDecision?.();
          return value;
        };
        const decided = sessions.length || tokens.length
          ? await rt.sessions!.ordered(sessions, caller.credential, decide, tokens.length ? prepare : undefined) : await decide();
        await commit();
        json(res, decided, 200, 'application/xacml+json'); return;
      }
      if (path.startsWith('/scim/v2/') && options.scim) {
        actor = await options.scim.authenticateAsync(req);
        await limiter.take(`principal:${actor}`, tick, limit);
        const b = ['POST', 'PUT', 'PATCH'].includes(method) ? await body(req) : {};
        const result = options.scim.handle(method, path, url.searchParams, b, actor);
        await commit();
        scimJson(res, result.body, result.status); return;
      }
      if (method !== 'GET') throw new HttpError(404, 'not_found');
      if (path === '/admin/v1' || /^\/admin\/v\d+(?:\/|$)/.test(path)) throw new HttpError(404, 'not_found');
      headers(res, false);
      res.removeHeader('Cache-Control');
      serveStatic(resolve(options.staticDir ?? 'apps/admin/dist'), path, res);
    } catch (err) {
      if (err instanceof HttpError && err.status === 429) res.setHeader('Retry-After', String(err.details?.[0] ?? 60));
      // a full sign-in queue (auth.ts SCRYPT_QUEUE) says when to come back
      if (err instanceof HttpError && err.status === 503 && typeof err.details?.[0] === 'number') res.setHeader('Retry-After', String(err.details[0]));
      if (err instanceof HttpError && err.status === 413) res.setHeader('Connection', 'close');
      if ((path.startsWith('/admin/') || path.startsWith('/scim/')) && !(path === '/admin/v1/session' && req.method === 'POST') && req.method !== 'GET') {
        const code = err instanceof HttpError ? err.code : 'internal';
        const suppressed = refusalCap.admit(`${ip} ${actor ?? 'unknown'} ${routeFamily(path)} ${code}`);
        if (suppressed !== undefined) try { audit.append({ type: path.includes('break-glass') ? 'break_glass' : path.includes('/changes') || path.includes('/reviews') || path.includes('/inbox') || path.includes('scim') ? 'change'
          : /session/.test(path) || path.includes('/oidc/') || path.includes('/saml/') ? 'session' : path.includes('/pep-credentials') || path.includes('/signing-keys') || path.includes('/integrity') || path.includes('/approval-modes') ? 'security' : 'simulation', actor: actor ?? 'unknown', action: 'refused', effect: 'deny',
          details: { route: personFree(path), error: code, ...(suppressed ? { suppressedSinceLastRow: suppressed } : {}) } }); }
        catch { /* Return the original sanitized error even if the audit is unavailable. */ }
      } else if (registrationRoute(path) && !(err instanceof HttpError && err.status === 401)) {
        // a refused registration is a refused change: audited, capped per source like the decision plane's refusals
        const code = err instanceof HttpError ? err.code : 'internal';
        const suppressed = refusalCap.admit(`${ip} resources ${code}`);
        if (suppressed !== undefined) try { audit.append({ type: 'change', actor: actor ?? 'unknown', action: 'refused', effect: 'deny',
          details: { route: path.slice(0, 200), error: code, ...(err instanceof HttpError && err.status < 500 ? { message: err.message.slice(0, 200) } : {}), ...(suppressed ? { suppressedSinceLastRow: suppressed } : {}) } }); }
        catch { /* Return the original sanitized error even if the audit is unavailable. */ }
      } else if (err instanceof HttpError && pdpRefusalAudited(path, err.status)) {
        // decision-plane credential failures and refused token consumptions: visible to the audit trail, capped per source
        const suppressed = refusalCap.admit(`${ip} ${routeFamily(path)} ${err.code}`);
        if (suppressed !== undefined) try { audit.append({ type: 'security', actor: actor ?? 'unknown', action: 'refused', effect: 'deny',
          details: { route: path.slice(0, 200), error: err.code, source: ip, ...(suppressed ? { suppressedSinceLastRow: suppressed } : {}) } }); }
        catch { /* Return the original sanitized error even if the audit is unavailable. */ }
      }
      // refusals are audited too: they reach the database before the answer does
      try { await commit(); } catch (stored) { failure(res, stored); return; }
      if (path.startsWith('/scim/')) { scimFailure(res, err); return; }
      failure(res, err);
    } finally {
      registry.observeRequest(routeFamily(path), (performance.now() - requestStarted) / 1000);
      endRequestSpan(req.method ?? 'GET', routeFamily(path), res.statusCode, ip);
    }
  };
  const tracer = options.tracer;
  return tracer ? (req, res) => tracer.trace(req.headers.traceparent, () => handle(req, res)) : handle;
}

/** The PEP-plane resource registration API (resources.ts). */
const registrationRoute = (path: string): boolean => path === RESOURCE_PATHS || path.startsWith(`${RESOURCE_PATHS}/`);

/** A replica's own feed and audit shipping (not traffic it forwards for a PEP or the console). */
const replicaOwnPath = (p: string): boolean => p === '/x/v1/replica/state' || p === '/x/v1/replica/audit';
/** Feed polls and audit shipments a minute per replica: a poll every few hundred ms plus shipping, with headroom. */
export const REPLICA_FEED_RATE_LIMIT = 1200;

/** Decision-plane refusals worth a security row: failed credentials, oversized bodies and refused token consumption. */
function pdpRefusalAudited(path: string, status: number): boolean {
  if (path === '/x/v1/tokens/consume' || path === '/x/v1/sessions' && status === 429) return true;
  return (status === 401 || status === 403 || status === 413) && (path.startsWith('/access/') || path.startsWith('/x/') || path.startsWith('/xacml/'));
}

/** At most one audit row per key (source, route family, error) a minute, on the real clock (a pinned business clock
 *  would freeze the window). admit() returns how many were left out since the last admitted row, or undefined when this
 *  one is left out. Bounded: past maxKeys the oldest key is forgotten. */
export function refusalLimiter(windowMs = 60_000, maxKeys = 10_000, now: () => number = Date.now) {
  const seen = new Map<string, { at: number; dropped: number }>();
  return {
    admit(key: string): number | undefined {
      const t = now(); const e = seen.get(key);
      if (e && t - e.at < windowMs) { e.dropped += 1; return undefined; }
      seen.delete(key); seen.set(key, { at: t, dropped: 0 });
      if (seen.size > maxKeys) seen.delete(seen.keys().next().value as string);
      return e?.dropped ?? 0;
    },
  };
}

/** The published leader address, when it is a valid origin; a malformed one (only a database writer could store it) is
 *  never contacted: the follower answers 409. */
/** A refused route is audited without the person id some paths carry (the row is not pseudonymised field by field). */
export const personFree = (path: string): string => path.replace(/^(\/admin\/v1\/privacy\/subjects|\/admin\/v1\/approval-modes|\/scim\/v2\/Users)\/[^/]+/, '$1/{id}');
function knownLeader(url: string | null): URL | null {
  if (!url) return null;
  try { return leaderOrigin(url); } catch { return null; }
}

/** RFC 7644 responses: application/scim+json, errors in the SCIM Error schema. */
function scimJson(res: ServerResponse, value: unknown, status: number): void {
  res.statusCode = status;
  if (status === 204) { res.end(); return; }
  res.setHeader('Content-Type', 'application/scim+json; charset=utf-8');
  res.end(JSON.stringify(value));
}
function scimFailure(res: ServerResponse, err: unknown): void {
  const e = err instanceof HttpError ? err : new HttpError(500, 'internal', 'Internal server error');
  scimJson(res, { schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: String(e.status), detail: e.message }, e.status);
}
function cookie(req: IncomingMessage, name: string): string {
  return [...(req.headers.cookie ?? '').matchAll(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`, 'g'))].map((m) => m[1]!)[0] ?? '';
}
function redirect(res: ServerResponse, location: string, cookies: string[]): void {
  res.statusCode = 302; res.setHeader('Location', location); res.setHeader('Set-Cookie', cookies); res.end();
}
