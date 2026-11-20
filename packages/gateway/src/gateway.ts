// The enforcing gateway: a reverse-proxy PEP in front of a JSON API (docs/ARCHITECTURE.md §5). For each declared route
// it asks the PDP before forwarding, refuses on deny, consumes the decision token of a certified command (and reports
// whether the upstream carried it out), carries out
// notifications through a configured hook, applies redaction, allowlists and masking to the JSON response, and refuses
// (fails closed) whatever it cannot enforce. Node standard library and the PEP SDK only.
import { Agent, createServer, request, type IncomingMessage, type OutgoingHttpHeaders, type ServerResponse } from 'node:http';
import { BlockList, isIP } from 'node:net';
import { ASSERTION_HEADER, bodySha256, enforce, ObligationError, PdpResponseError, PepError, type PepClient } from '../../sdk/src/index.ts';
import type { Evaluation, EvaluationContext, JsonObject, JsonValue, Ref, RequestBinding } from '../../sdk/src/index.ts';
import { allowedRequestHeaders, endToEnd, METHOD_OVERRIDE, REWRITE_DROP } from './headers.ts';
import { clientAddress, trustedProxies } from '../../pdp-http/src/proxy.ts';
import { Refusal } from './refusal.ts';
import { compileRoutes, fieldPath, match, type Route, type RouteConfig } from './routes.ts';

/** Who calls, as established by the deployment's own authentication; the network is resolved by the gateway. */
export interface Caller { readonly subject: Ref; readonly context?: Omit<EvaluationContext, 'network'> }
export interface NotifyEvent { readonly recipients: readonly string[]; readonly subject: Ref; readonly resource: Ref; readonly action: string; readonly policyVersion: string }
/** One line per decision or refusal: ids, rule ids and status only, never bodies, headers or credentials. */
export interface DecisionLog {
  readonly method: string; readonly route: string | null; readonly subject: string | null; readonly resourceType: string | null;
  readonly resource: string | null; readonly action: string | null; readonly outcome: 'allow' | 'deny' | 'refused';
  readonly status: number; readonly code?: string; readonly rules?: readonly string[]; readonly policyVersion?: string;
  /** A certified command: what the PDP's reservation was left as (pending: no answer known, or the report failed). */
  readonly reservation?: 'completed' | 'failed' | 'pending';
}
export interface GatewayOptions {
  /** Origin of the protected API (http, no path): the upstream sits on a private network next to the gateway. */
  readonly upstream: string;
  readonly pdp: PepClient;
  readonly routes: readonly RouteConfig[];
  readonly authenticate: (req: IncomingMessage) => Caller | undefined | Promise<Caller | undefined>;
  /** Fresh trusted-attester evidence for the fully resolved context (including its socket-derived IP and network). */
  readonly attestContext?: (context: EvaluationContext, req: IncomingMessage) => EvaluationContext['attestations'] | Promise<EvaluationContext['attestations']>;
  /** Client address ranges (CIDR) evaluated as the trusted network; everything else is untrusted. Applied to the client
   *  address: the socket's, or behind `trustedProxies` the one they forwarded. */
  readonly trustedNetworks?: readonly string[];
  /** The load balancers in front of the gateway, as the PDP's TRUSTED_PROXIES: comma-separated addresses or CIDR ranges.
   *  X-Forwarded-For is read only from a connection one of them opened, and the client is the rightmost hop that is
   *  not itself a trusted proxy. Unset: the header is ignored and the socket address is the client (context.ip). */
  readonly trustedProxies?: string;
  /** Carries out `notify` obligations; without it such a decision is refused. A rejection refuses the request. */
  readonly notify?: (event: NotifyEvent) => Promise<void>;
  readonly maxBodyBytes?: number;
  readonly maxResponseBytes?: number;
  /** Whole upstream exchange (connect, request, complete response), not only socket idleness. */
  readonly upstreamTimeoutMs?: number;
  readonly log?: (entry: DecisionLog) => void;
}
export interface Gateway { listen(port?: number, host?: string): Promise<void>; close(): Promise<void>; readonly url: string }

const MAX_LIST_ITEMS = 1000; // the PDP's batch limit
interface Upstream { status: number; headers: IncomingMessage['headers']; body: Buffer }
interface Exchange { req: IncomingMessage; res: ServerResponse; url: URL; body: Buffer; route: Route; subject: Ref; context: EvaluationContext; assertion?: string;
  reservation?: DecisionLog['reservation'] }
/** Socket errors raised before a connection exists: the upstream cannot have received anything. */
const NEVER_CONNECTED = new Set(['ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH']);

function trustedList(cidrs: readonly string[]): BlockList {
  const list = new BlockList();
  for (const cidr of cidrs) {
    const [address = '', bits = ''] = cidr.split('/');
    const family = isIP(address);
    const prefix = Number(bits);
    if (!family || !/^\d+$/.test(bits) || prefix > (family === 4 ? 32 : 128)) throw new TypeError(`Invalid trusted network: ${cidr}`);
    list.addSubnet(address, prefix, family === 4 ? 'ipv4' : 'ipv6');
  }
  return list;
}
function positive(value: number | undefined, fallback: number, name: string): number {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result <= 0) throw new TypeError(`${name} must be a positive integer`);
  return result;
}
const transforms = (d: Evaluation): boolean => {
  const o = d.context.obligations;
  return o.fieldAllowlist !== undefined || o.redact.length > 0 || o.maskClasses.length > 0;
};
const withoutNotify = (d: Evaluation): Evaluation => ({ ...d, context: { ...d.context, obligations: { ...d.context.obligations, notify: [] } } });
const jsonOf = (u: Upstream): JsonValue => {
  const type = String(u.headers['content-type'] ?? '');
  const encoding = String(u.headers['content-encoding'] ?? 'identity');
  if (!/^application\/json(?:\s*;|$)/i.test(type) || encoding !== 'identity') throw new Refusal(502, 'obligation_unenforceable');
  try { return JSON.parse(u.body.toString('utf8')) as JsonValue; } catch { throw new Refusal(502, 'obligation_unenforceable'); }
};
const isRecord = (v: JsonValue | undefined): v is JsonObject => v !== null && typeof v === 'object' && !Array.isArray(v);
/** True when an object in this (already valid) JSON text names one key twice. JSON.parse keeps the last one while other
 *  parsers keep the first: the PDP and the upstream would read two different commands from the same certified bytes. */
const duplicateKey = (text: string): boolean => {
  const scopes: (Set<string> | null)[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '{') scopes.push(new Set());
    else if (c === '[') scopes.push(null);
    else if (c === '}' || c === ']') scopes.pop();
    else if (c === '"') {
      const start = i;
      for (i++; text[i] !== '"'; i++) if (text[i] === '\\') i++;
      let next = i + 1;
      while (/\s/.test(text[next] ?? '')) next++;
      const scope = scopes.at(-1);
      if (text[next] !== ':' || !scope) continue;
      const key = JSON.parse(text.slice(start, i + 1)) as string;
      if (scope.has(key)) return true;
      scope.add(key);
    }
  }
  return false;
};

export function createGateway(options: GatewayOptions): Gateway {
  const upstream = new URL(options.upstream);
  if (upstream.protocol !== 'http:' || upstream.username || upstream.password || upstream.pathname !== '/' || upstream.search || upstream.hash) {
    throw new TypeError('upstream must be an http origin without credentials, path, query or fragment');
  }
  if (typeof options.authenticate !== 'function' || !options.pdp) throw new TypeError('authenticate and pdp are required');
  const routes = compileRoutes(options.routes);
  const trusted = trustedList(options.trustedNetworks ?? []);
  const maxBody = positive(options.maxBodyBytes, 1_048_576, 'maxBodyBytes');
  const maxResponse = positive(options.maxResponseBytes, 8_388_608, 'maxResponseBytes');
  const timeout = positive(options.upstreamTimeoutMs, 10_000, 'upstreamTimeoutMs');
  const log = options.log ?? ((entry: DecisionLog): void => console.info(JSON.stringify(entry)));
  const agent = new Agent({ keepAlive: true });

  const proxies = trustedProxies(options.trustedProxies);
  if (!proxies) console.warn('gateway: no trustedProxies: context.ip and the network are the socket address; behind a load balancer every client would share its address (DEPLOY.md)');
  const address = (req: IncomingMessage): string | undefined => {
    const client = clientAddress(req, proxies);
    return isIP(client) ? client : undefined;
  };
  const network = (req: IncomingMessage): 'trusted' | 'untrusted' => {
    const ip = address(req);
    const family = ip === undefined ? 0 : isIP(ip);
    return ip && family && trusted.check(ip, family === 4 ? 'ipv4' : 'ipv6') ? 'trusted' : 'untrusted';
  };
  const readBody = (req: IncomingMessage): Promise<Buffer> => new Promise((accept, reject) => {
    if (Number(req.headers['content-length'] ?? 0) > maxBody) { req.resume(); reject(new Refusal(413, 'payload_too_large')); return; }
    const chunks: Buffer[] = []; let size = 0; let done = false;
    req.on('data', (chunk: Buffer) => {
      if (done) return;
      size += chunk.length;
      if (size > maxBody) { done = true; reject(new Refusal(413, 'payload_too_large')); return; }
      chunks.push(chunk);
    });
    req.on('end', () => { if (!done) { done = true; accept(Buffer.concat(chunks)); } });
    req.on('error', () => { if (!done) { done = true; reject(new Refusal(400, 'bad_request')); } });
  });
  /** The path with the declared query parameters only: what the upstream receives and the assertion binds. */
  const forwardPath = (x: Exchange): string => {
    const query = new URLSearchParams([...x.url.searchParams].filter(([name]) => x.route.query?.includes(name)));
    return `${x.url.pathname}${query.size ? `?${query.toString()}` : ''}`;
  };
  const binding = (x: Exchange): RequestBinding => ({ audience: upstream.origin, method: x.route.method, path: forwardPath(x), bodySha256: bodySha256(x.body) });
  const forward = (x: Exchange): Promise<Upstream> => new Promise((accept, reject) => {
    const headers = allowedRequestHeaders(x.req.headers, x.route.headers);
    headers['accept-encoding'] = 'identity';
    if (x.body.length > 0 || !['GET', 'HEAD', 'DELETE'].includes(x.route.method)) headers['content-length'] = String(x.body.length);
    // the PDP's signed proof for the backend; without one nothing is forwarded
    if (!x.assertion) { reject(new Refusal(502, 'unenforceable_decision')); return; }
    headers[ASSERTION_HEADER] = x.assertion;
    const path = forwardPath(x);
    let settled = false;
    const finish = (fn: () => void): void => { if (!settled) { settled = true; clearTimeout(deadline); fn(); } };
    const out = request({ protocol: 'http:', hostname: upstream.hostname, port: upstream.port || 80, method: x.route.method, path, headers, agent, timeout }, (up) => {
      const chunks: Buffer[] = []; let size = 0;
      up.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > maxResponse) { up.destroy(); finish(() => reject(new Refusal(502, 'upstream_too_large'))); return; }
        chunks.push(chunk);
      });
      up.on('end', () => finish(() => accept({ status: up.statusCode ?? 502, headers: up.headers, body: Buffer.concat(chunks) })));
      up.on('error', () => finish(() => reject(new Refusal(502, 'upstream_unavailable'))));
    });
    // the socket timeout only measures idleness: an upstream dripping a byte at a time is cut by this overall deadline
    const deadline = setTimeout(() => { out.destroy(); finish(() => reject(new Refusal(504, 'upstream_timeout'))); }, timeout);
    out.on('timeout', () => { out.destroy(); finish(() => reject(new Refusal(504, 'upstream_timeout'))); });
    out.on('error', (err: NodeJS.ErrnoException) => finish(() => reject(new Refusal(502, 'upstream_unavailable', NEVER_CONNECTED.has(err.code ?? '')))));
    out.end(x.body);
  });
  /** The item's state the upstream is asked to commit: the request's JSON object body (routes with postState 'body'). */
  const postState = (x: Exchange): JsonObject => {
    if (!/^application\/json(?:\s*;|$)/i.test(String(x.req.headers['content-type'] ?? ''))) throw new Refusal(400, 'bad_request');
    const text = x.body.toString('utf8');
    let value: JsonValue;
    try { value = JSON.parse(text) as JsonValue; } catch { throw new Refusal(400, 'bad_request'); }
    // the bytes are forwarded and hashed unchanged, so they must have one meaning
    if (!isRecord(value) || duplicateKey(text)) throw new Refusal(400, 'bad_request');
    return value;
  };
  const send = (res: ServerResponse, status: number, body: Buffer, headers: OutgoingHttpHeaders = {}): void => {
    res.statusCode = status;
    for (const [k, v] of Object.entries(headers)) if (v !== undefined) res.setHeader(k, v);
    res.setHeader('cache-control', 'no-store');
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('content-length', String(body.length));
    res.end(body);
  };
  const sendJson = (res: ServerResponse, status: number, value: unknown, headers: OutgoingHttpHeaders = {}): void =>
    send(res, status, Buffer.from(JSON.stringify(value)), { ...headers, 'content-type': 'application/json; charset=utf-8' });
  /** Upstream failures carry no body: an error page could hold the very fields the obligations hide. */
  const upstreamOk = (u: Upstream): void => { if (u.status < 200 || u.status > 299) throw new Refusal(u.status >= 400 && u.status <= 599 ? u.status : 502, 'upstream_error'); };

  /** Obligations other than content are carried out before anything runs upstream, or the request is refused: the
   *  decision token is consumed first, and recipients are notified only of a request that will be forwarded or released.
   *  Returns the reservation of a consumed decision token, for its outcome report. */
  const consume = async (x: Exchange, resource: Ref, d: Evaluation, certified: boolean): Promise<string | undefined> => {
    const { notify, decisionToken } = d.context.obligations;
    if (notify.length > 0 && !options.notify) throw new Refusal(502, 'obligation_unenforceable');
    if (!decisionToken) return undefined;
    const token = d.context.decision_token;
    if (!certified || !token) throw new Refusal(502, 'obligation_unenforceable');
    // the PDP checks the integrity of the state to be committed: a route that cannot say what it commits is refused
    if (decisionToken.postState && x.route.postState !== 'body') throw new Refusal(502, 'obligation_unenforceable');
    const attrs = x.route.postState === 'body' ? postState(x) : undefined;
    try {
      const consumed = await options.pdp.consumeToken({ token, action: x.route.action, resource, resourceVersion: decisionToken.resourceVersion, ...(attrs ? { attrs } : {}) });
      return consumed.reservation;
    } catch (err) { throw err instanceof PepError && 'status' in err && err.status === 409 ? new Refusal(409, 'conflict') : err; }
  };
  const notifyOf = async (x: Exchange, resource: Ref, d: Evaluation): Promise<void> => {
    const { notify } = d.context.obligations;
    if (notify.length === 0 || !options.notify) return;
    try { await options.notify({ recipients: notify, subject: x.subject, resource, action: x.route.action, policyVersion: d.context.policy_version }); }
    catch { throw new Refusal(502, 'obligation_unenforceable'); }
  };
  const report = async (x: Exchange, reservation: string | undefined, outcome: 'completed' | 'failed'): Promise<void> => {
    if (!reservation) return;
    x.reservation = 'pending';
    try { await options.pdp.reportOutcome({ reservation, outcome }); x.reservation = outcome; } catch { /* stays reserved: logged as pending */ }
  };
  /** Forwards a consumed certified command and reports what became of it: 2xx completed, 4xx (except 408) failed (the
   *  upstream refused it); 3xx, 408 and 5xx stay reserved, since the command may have run before a proxy or the upstream
   *  answered an error. No answer settles it as failed only when the request certainly never left, otherwise it stays
   *  reserved (it counts for SoD) for an operator to reconcile. A failed report leaves it reserved too, never the client
   *  without its answer. */
  const forwardReported = async (x: Exchange, reservation: string | undefined): Promise<Upstream> => {
    let u: Upstream;
    try { u = await forward(x); } catch (err) {
      if (err instanceof Refusal && err.undelivered) await report(x, reservation, 'failed');
      else if (reservation) x.reservation = 'pending';
      throw err;
    }
    if (u.status >= 200 && u.status <= 299) await report(x, reservation, 'completed');
    else if (u.status >= 400 && u.status <= 499 && u.status !== 408) await report(x, reservation, 'failed');
    else if (reservation) x.reservation = 'pending';
    return u;
  };
  // consume spent any decision token before release is reached
  const release = (d: Evaluation, record: JsonValue): JsonObject => {
    if (!isRecord(record)) throw new Refusal(502, 'obligation_unenforceable');
    try { return enforce(withoutNotify(d), record, { decisionTokenConsumed: true }); } catch (err) {
      if (err instanceof ObligationError) throw new Refusal(502, 'obligation_unenforceable');
      throw err;
    }
  };
  const entry = (x: Partial<Exchange>, resource: string | null, outcome: DecisionLog['outcome'], status: number, extra: Partial<DecisionLog> = {}): DecisionLog => ({
    method: x.req?.method ?? '', route: x.route?.path ?? null, subject: x.subject?.id ?? null, resourceType: x.route?.resourceType ?? null,
    resource, action: x.route?.action ?? null, outcome, status, ...(x.reservation ? { reservation: x.reservation } : {}), ...extra,
  });

  const single = async (x: Exchange, id: string): Promise<void> => {
    const resource = { type: x.route.resourceType, id };
    // C5: a body that is the item's post-state is also the command's input the PDP validates
    const context = x.route.postState === 'body' ? { ...x.context, input: postState(x) } : x.context;
    const { assertion, ...d } = await options.pdp.evaluateAsserted({ subject: x.subject, action: { name: x.route.action }, resource, context, request: binding(x) });
    const facts = { rules: d.context.rules, policyVersion: d.context.policy_version };
    if (!d.decision) { log(entry(x, id, 'deny', 403, facts)); throw new Refusal(403, 'forbidden'); }
    x.assertion = assertion;
    const reservation = await consume(x, resource, d, true);
    // a failed notification refuses the command before it leaves: its reservation certainly failed
    try { await notifyOf(x, resource, d); } catch (err) { await report(x, reservation, 'failed'); throw err; }
    const u = await forwardReported(x, reservation);
    upstreamOk(u);
    if (!transforms(d) || u.body.length === 0) send(x.res, u.status, u.body, endToEnd(u.headers, ['content-length']));
    else sendJson(x.res, u.status, release(d, jsonOf(u)), endToEnd(u.headers, REWRITE_DROP));
    log(entry(x, id, 'allow', u.status, facts));
  };
  const list = async (x: Exchange, spec: NonNullable<Route['list']>): Promise<void> => {
    const path = fieldPath(spec.items); const idPath = fieldPath(spec.idField ?? 'id');
    const wrap = (items: JsonObject[]): JsonValue => path.reduceRight<JsonValue>((inner, key) => ({ [key]: inner }), items);
    const listed = await options.pdp.assertList({ subject: x.subject, action: { name: x.route.action }, resource: { type: x.route.resourceType }, context: x.context, request: binding(x) });
    if (!listed.decision) {
      // no item of the type can be released to this subject: hidden means absent, and the upstream is not asked
      log(entry(x, null, 'deny', 200, { policyVersion: listed.policy_version }));
      sendJson(x.res, 200, wrap([])); return;
    }
    x.assertion = listed.assertion;
    const u = await forward(x);
    upstreamOk(u);
    let items: JsonValue | undefined = jsonOf(u);
    for (const p of path) items = isRecord(items) ? items[p] : undefined;
    if (!Array.isArray(items) || items.length > MAX_LIST_ITEMS) throw new Refusal(502, 'list_unenforceable');
    const ids = items.map((item: JsonValue) => {
      let v: JsonValue | undefined = item;
      for (const p of idPath) v = isRecord(v) ? v[p] : undefined;
      if (typeof v !== 'string' || v.length === 0) throw new Refusal(502, 'list_unenforceable');
      return v;
    });
    const batch = ids.length === 0 ? [] : (await options.pdp.evaluateBatch({ subject: x.subject, action: { name: x.route.action }, context: x.context,
      evaluations: ids.map((id) => ({ resource: { type: x.route.resourceType, id } })), options: { evaluations_semantic: 'execute_all' } })).evaluations;
    if (batch.length !== ids.length) throw new Refusal(502, 'list_unenforceable');
    const released: JsonObject[] = []; const notices: [Ref, Evaluation][] = [];
    for (const [i, d] of batch.entries()) {
      const id = ids[i] as string;
      log(entry(x, id, d.decision ? 'allow' : 'deny', u.status, { rules: d.context.rules, policyVersion: d.context.policy_version }));
      if (!d.decision) continue; // hidden means absent
      await consume(x, { type: x.route.resourceType, id }, d, false);
      released.push(release(d, items[i] as JsonValue));
      notices.push([{ type: x.route.resourceType, id }, d]);
    }
    // recipients hear of items only once the whole list is releasable
    for (const [resource, d] of notices) await notifyOf(x, resource, d);
    // only the items are released: sibling fields (totals, cursors) may count what was hidden
    sendJson(x.res, u.status, wrap(released), endToEnd(u.headers, REWRITE_DROP));
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const x: Partial<Exchange> = { req, res };
    try {
      if (!req.url?.startsWith('/')) throw new Refusal(400, 'bad_request');
      x.url = new URL(req.url, 'http://gateway.invalid');
      // a permitted POST must not run as another method upstream
      if (METHOD_OVERRIDE.some((name) => req.headers[name] !== undefined) || x.url.searchParams.has('_method')) throw new Refusal(400, 'bad_request');
      const matched = match(routes, req.method ?? '', x.url.pathname);
      if (!matched) throw new Refusal(404, 'not_found');
      x.route = matched.route;
      const caller = await options.authenticate(req);
      if (!caller) throw new Refusal(401, 'unauthenticated');
      const { type, id } = caller.subject ?? {};
      if (typeof type !== 'string' || typeof id !== 'string' || !type || !id) throw new Refusal(401, 'unauthenticated');
      x.subject = { type, id };
      // Authentication facts come from the authenticated session, never request headers; the socket alone supplies IP.
      const { ip: ignored, ...session } = caller.context ?? {};
      const ip = address(req);
      x.context = { ...session, network: network(req), ...(ip === undefined ? {} : { ip }) };
      const attestations = await options.attestContext?.(x.context, req);
      if (attestations) x.context = { ...x.context, attestations };
      x.body = await readBody(req);
      const exchange = x as Exchange;
      if (matched.route.list) await list(exchange, matched.route.list);
      else await single(exchange, matched.id as string);
    } catch (err) {
      const refusal = err instanceof Refusal ? err
        : err instanceof PdpResponseError ? new Refusal(502, 'unenforceable_decision')
          : err instanceof PepError ? new Refusal(503, 'pdp_unavailable') : new Refusal(500, 'internal');
      if (refusal.status === 413) res.setHeader('connection', 'close');
      if (refusal.code !== 'forbidden') log(entry(x, null, 'refused', refusal.status, { code: refusal.code }));
      if (!res.headersSent) sendJson(res, refusal.status, { error: refusal.code });
      else res.destroy();
    }
  };

  const server = createServer((req, res) => { void handle(req, res); });
  server.requestTimeout = 30_000; server.headersTimeout = 10_000;
  let base = '';
  return {
    get url(): string { return base; },
    listen: (port = 0, host = '127.0.0.1') => new Promise<void>((accept, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => {
        server.off('error', reject);
        const address = server.address();
        if (!address || typeof address === 'string') { reject(new Error('No server address')); return; }
        base = `http://${host.includes(':') ? `[${host}]` : host}:${address.port}`;
        accept();
      });
    }),
    close: () => new Promise<void>((accept, reject) => {
      agent.destroy();
      if (!server.listening) { accept(); return; }
      server.close((err) => (err ? reject(err) : accept()));
      server.closeAllConnections();
    }),
  };
}
