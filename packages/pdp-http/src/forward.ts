// Cluster mode (docs/API.md §3.9.1): a follower reached through a plain Service passes admin and SCIM requests to the
// leader over the internal network instead of answering 409. The body (1 MB at most) is read first, the answer is
// streamed back (method, path, body, cookies, CSRF header kept); one hop header, signed with a key derived from
// SIGNING_KEY_SEAL, authenticates the follower to the leader, binds the method, path with query and body digest,
// carries the client address, and stops loops (a node never forwards a request that has one).
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { request as httpRequest, type IncomingHttpHeaders, type IncomingMessage, type OutgoingHttpHeaders, type ServerResponse } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { failure, rawBody } from './http.ts';

export const HOP_KEY_LABEL = 'qadamar/cluster-hop/hmac-sha256/v1';
export const HOP_HEADER = 'x-gate-hop';
/** A replica's hop (replica-protocol.ts REPLICA_HOP_HEADER), dropped like the cluster one when a request is passed on. */
const REPLICA_HOP = 'x-gate-replica-hop';
/** A hop is accepted this long either side of the leader's clock, once (its nonce is remembered for the window). */
export const HOP_WINDOW_MS = 30_000;
const MAX_REMEMBERED = 100_000;
/** No answer headers from the leader within this: 503, the client retries. The whole exchange is capped at 30 s. */
const CONNECT_TIMEOUT_MS = 10_000;
const TOTAL_TIMEOUT_MS = 30_000;
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer',
  'transfer-encoding', 'upgrade', 'host', 'expect', HOP_HEADER, REPLICA_HOP]); // content-length: set from the body read

const b64 = (s: string): string => Buffer.from(s, 'utf8').toString('base64url');
const unb64 = (s: string): string => Buffer.from(s, 'base64url').toString('utf8');
const mac = (key: Buffer, body: string): string => createHmac('sha256', key).update(body).digest('base64url');
const digest = (body: Buffer): string => createHash('sha256').update(body).digest('base64url');
// JSON framing: no field can be shifted into another (a method or a path may contain dots)
const signed = (fields: readonly string[], method: string, url: string, body: Buffer): string => JSON.stringify([...fields, method, url, digest(body)]);

/** v2.<ms>.<nonce>.<client>.<node>.<mac>; the mac covers those fields, the method, the path with its query and the
 *  SHA-256 of the body. */
export function signHop(key: Buffer, method: string, url: string, body: Buffer, client: string, node: string, at = Date.now()): string {
  const fields = ['v2', String(at), randomBytes(16).toString('base64url'), b64(client), b64(node)];
  return `${fields.join('.')}.${mac(key, signed(fields, method, url, body))}`;
}

/** The leader address a follower may forward to: http(s), an origin only (no credentials, path, query or fragment). */
export function leaderOrigin(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('GATE_ADVERTISE_URL must be an absolute http(s) URL'); }
  if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('GATE_ADVERTISE_URL must be an http(s) origin: no credentials, path, query or fragment');
  }
  return url;
}

/** The node a hop names, before any verification (it selects a replica's key); undefined when malformed. */
export function hopNode(header: string): string | undefined {
  const parts = header.split('.');
  return parts.length === 6 ? unb64(parts[4]!) : undefined;
}

/** Leader side: a hop is valid once, inside the window, for this method, path and body. */
export class HopVerifier {
  private readonly seen = new Map<string, number>();
  private readonly key: Buffer;
  constructor(key: Buffer) { this.key = key; }
  /** Shape and window only, before the body is read: a stale or malformed hop costs no body read. */
  plausible(header: string, at = Date.now()): boolean {
    const parts = header.split('.');
    return parts.length === 6 && parts[0] === 'v2' && /^\d{1,16}$/.test(parts[1]!) && Math.abs(at - Number(parts[1])) <= HOP_WINDOW_MS;
  }
  /** `key`: this hop's key when it depends on the node it names (replicas); the replay memory is shared either way. */
  verify(header: string, method: string, url: string, body: Buffer, at = Date.now(), key = this.key): { client: string; node: string } | null {
    if (!this.plausible(header, at)) return null;
    const parts = header.split('.');
    const expected = Buffer.from(mac(key, signed(parts.slice(0, 5), method, url, body)));
    const given = Buffer.from(parts[5]!);
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
    for (const [nonce, until] of this.seen) { if (until > at) break; this.seen.delete(nonce); } // insertion order ~ expiry order
    if (this.seen.has(parts[2]!) || this.seen.size >= MAX_REMEMBERED) return null; // replay, or flooded: fail closed
    this.seen.set(parts[2]!, at + 2 * HOP_WINDOW_MS);
    return { client: unb64(parts[3]!), node: unb64(parts[4]!) };
  }
}

function strip(headers: IncomingHttpHeaders): OutgoingHttpHeaders {
  const named = new Set(String(headers.connection ?? '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean));
  const out: OutgoingHttpHeaders = {};
  for (const [name, value] of Object.entries(headers)) if (value !== undefined && !HOP_BY_HOP.has(name) && !named.has(name)) out[name] = value;
  return out;
}

/** Sends req to the leader and streams its answer back. Resolves when the answer is complete or the exchange was
 *  abandoned. The body is read (and bounded) here, so its digest can be signed; a refusal is answered, never audited. */
export async function forwardToLeader(req: IncomingMessage, res: ServerResponse, leader: URL, key: Buffer, node: string, client: string,
  hop: { header?: string; ca?: Buffer } = {}): Promise<void> {
  let payload: Buffer;
  try { payload = await rawBody(req); } catch (err) { failure(res, err); return; }
  const path = req.url ?? '/';
  const target = new URL(`${leader.origin}${path.startsWith('/') ? path : `/${path}`}`); // the origin is the leader's, whatever the path says
  const method = req.method ?? 'GET';
  const headers = { ...strip(req.headers), host: target.host, 'content-length': String(payload.length),
    [hop.header ?? HOP_HEADER]: signHop(key, method, target.pathname + target.search, payload, client, node) };
  return new Promise<void>((done) => {
    const send = target.protocol === 'https:' ? httpsRequest : httpRequest;
    const upstream = send(target, { method, headers, timeout: CONNECT_TIMEOUT_MS, ...(hop.ca ? { ca: hop.ca } : {}) });
    const deadline = setTimeout(() => upstream.destroy(new Error('leader exchange timed out')), TOTAL_TIMEOUT_MS);
    deadline.unref();
    const finish = (): void => { clearTimeout(deadline); done(); };
    upstream.on('timeout', () => upstream.destroy(new Error('leader did not answer in time')));
    upstream.on('response', (answer) => {
      res.writeHead(answer.statusCode ?? 502, strip(answer.headers));
      answer.pipe(res);
      answer.on('error', () => res.destroy());
    });
    upstream.on('error', () => {
      if (!res.headersSent) {
        res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '1' });
        res.end(JSON.stringify({ error: 'unavailable', message: 'The leader could not be reached; retry' }));
      } else res.destroy();
    });
    res.on('close', () => { if (!upstream.destroyed && !res.writableFinished) upstream.destroy(); finish(); });
    upstream.end(payload);
  });
}
