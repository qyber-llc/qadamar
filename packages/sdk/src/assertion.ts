// Backend side of the gateway's decision assertions (docs/API.md 2.0.2): the request reached this backend through the
// PEP, the PDP allowed exactly this subject, action and resource, and the request is the one decided (method, path
// with query, body digest, audience). Ed25519 keys from the PDP's JWKS, cached and refreshed on an unknown kid; every
// nonce is accepted once while the assertion lives (per process by default; a ReplayStore shares that across replicas).
// Node standard library only.
import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { PepError } from './errors.ts';

export const ASSERTION_HEADER = 'gate-assertion';
export const ASSERTION_TYP = 'gate-assertion+jwt';
export const ASSERTION_MAX_TTL_SECONDS = 30;
const MAX_JWKS_BYTES = 65_536;

export interface AssertionClaims {
  readonly sub: { readonly type: string; readonly id: string };
  readonly act: string;
  /** No id: a list request, whose items the PEP releases one by one after per-item decisions. */
  readonly res: { readonly type: string; readonly id?: string };
  /** Decision id, also in the PDP's audit row (details.decisionId). */
  readonly did: string; readonly pv: string;
  readonly aud: string; readonly htm: string; readonly htp: string; readonly bsh: string;
  readonly iat: number; readonly exp: number; readonly nonce: string;
}
export interface AssertionVerifierOptions {
  /** The PDP's `/.well-known/jwks.json`. */
  readonly jwksUrl: string;
  /** This backend's origin exactly as the gateway's `upstream` names it, e.g. `http://10.0.0.5:8080`. */
  readonly audience: string;
  readonly fetch?: typeof globalThis.fetch;
  /** Tolerated clock difference with the PDP, 0..60 s (default 5). */
  readonly clockSkewSeconds?: number;
  /** How long fetched keys are trusted before a refetch (default 300 s); an unknown kid refetches at most every 10 s. */
  readonly jwksCacheSeconds?: number;
  readonly timeoutMs?: number;
  /** Milliseconds since the epoch (tests). */
  readonly now?: () => number;
  /** Where spent nonces are remembered. Default: this process only (MemoryReplayStore). Several replicas of one
   *  backend must share one store, or each accepts the same assertion once within its 30 s life (docs/API.md 2.0.2). */
  readonly replayStore?: ReplayStore;
}
/** Spends a nonce in one atomic check-and-set: true the first time, false when it was already spent. `expiresAt`
 *  (seconds since the epoch) is when the nonce may be forgotten. A store that throws fails the request closed (503). */
export interface ReplayStore { spend(nonce: string, expiresAt: number): boolean | Promise<boolean> }
/** The default store: a map in this process. */
export class MemoryReplayStore implements ReplayStore {
  /** nonce -> second after which it can be forgotten */
  readonly #seen = new Map<string, number>();
  readonly #now: () => number;
  constructor(now: () => number = Date.now) { this.#now = now; }
  spend(nonce: string, expiresAt: number): boolean {
    const now = Math.floor(this.#now() / 1000);
    // shortcut: a full scan per request, bounded by one TTL of traffic; index by expiry if that grows past ~100k
    for (const [n, until] of this.#seen) if (until < now) this.#seen.delete(n);
    if (this.#seen.has(nonce)) return false;
    this.#seen.set(nonce, expiresAt);
    return true;
  }
}
export interface ForwardedRequest { readonly method: string; readonly path: string; readonly body: Uint8Array; readonly header: string | string[] | undefined }

export class AssertionError extends PepError {}
const refuse = (code: string): never => { throw new AssertionError(code, 'The decision assertion is not acceptable'); };
export const bodySha256 = (body: Uint8Array): string => createHash('sha256').update(body).digest('base64url');

const B64 = /^[A-Za-z0-9_-]+$/;
function part(value: string): unknown {
  // one encoding per value: a re-encoded segment must equal the input, or a second spelling could pass
  if (!B64.test(value) || Buffer.from(value, 'base64url').toString('base64url') !== value) refuse('assertion_invalid');
  try { return JSON.parse(Buffer.from(value, 'base64url').toString('utf8')); } catch { return refuse('assertion_invalid'); }
}
const record = (v: unknown): Record<string, unknown> => (v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : refuse('assertion_invalid'));
const text = (v: unknown, max = 2048): string => (typeof v === 'string' && v.length > 0 && v.length <= max ? v : refuse('assertion_invalid'));
const exact = (o: Record<string, unknown>, keys: readonly string[], optional: readonly string[] = []): void => {
  if (Object.keys(o).some((k) => !keys.includes(k) && !optional.includes(k)) || keys.some((k) => !Object.hasOwn(o, k))) refuse('assertion_invalid');
};
const CLAIMS = ['sub', 'act', 'res', 'did', 'pv', 'aud', 'htm', 'htp', 'bsh', 'iat', 'exp', 'nonce'];

function claimsOf(value: unknown): AssertionClaims {
  const c = record(value);
  exact(c, CLAIMS);
  const sub = record(c.sub); exact(sub, ['type', 'id']);
  const res = record(c.res); exact(res, ['type'], ['id']);
  if (!Number.isSafeInteger(c.iat) || !Number.isSafeInteger(c.exp)) refuse('assertion_invalid');
  const iat = c.iat as number; const exp = c.exp as number;
  if (exp <= iat || exp - iat > ASSERTION_MAX_TTL_SECONDS) refuse('assertion_invalid');
  return { sub: { type: text(sub.type, 256), id: text(sub.id, 256) }, act: text(c.act, 256),
    res: { type: text(res.type, 256), ...(res.id === undefined ? {} : { id: text(res.id, 256) }) },
    did: text(c.did, 64), pv: text(c.pv, 256), aud: text(c.aud, 256), htm: text(c.htm, 16), htp: text(c.htp), bsh: text(c.bsh, 64),
    iat, exp, nonce: text(c.nonce, 64) };
}

export class AssertionVerifier {
  readonly #jwksUrl: string; readonly #audience: string; readonly #fetch: typeof globalThis.fetch;
  readonly #skew: number; readonly #cacheMs: number; readonly #timeoutMs: number; readonly #now: () => number;
  #keys = new Map<string, KeyObject>();
  #fetchedAt = Number.NEGATIVE_INFINITY;
  #refreshing: Promise<void> | undefined;
  readonly #replay: ReplayStore;

  constructor(options: AssertionVerifierOptions) {
    const jwks = new URL(options.jwksUrl);
    if (!['http:', 'https:'].includes(jwks.protocol) || jwks.username || jwks.password) throw new TypeError('jwksUrl must be an HTTP(S) URL without credentials');
    if (new URL(options.audience).origin !== options.audience) throw new TypeError('audience must be an origin (scheme, host, port)');
    const skew = options.clockSkewSeconds ?? 5; const cache = options.jwksCacheSeconds ?? 300; const timeout = options.timeoutMs ?? 5000;
    if (!Number.isInteger(skew) || skew < 0 || skew > 60) throw new TypeError('clockSkewSeconds must be an integer in 0..60');
    if (!Number.isInteger(cache) || cache < 10 || cache > 86_400) throw new TypeError('jwksCacheSeconds must be an integer in 10..86400');
    if (!Number.isFinite(timeout) || timeout <= 0) throw new TypeError('timeoutMs must be positive');
    this.#jwksUrl = jwks.toString(); this.#audience = options.audience; this.#fetch = options.fetch ?? globalThis.fetch;
    this.#skew = skew; this.#cacheMs = cache * 1000; this.#timeoutMs = timeout; this.#now = options.now ?? Date.now;
    this.#replay = options.replayStore ?? new MemoryReplayStore(this.#now);
  }

  async #refresh(): Promise<void> {
    const response = await this.#fetch(this.#jwksUrl, { headers: { accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(this.#timeoutMs) });
    const body = await response.text();
    if (!response.ok || body.length > MAX_JWKS_BYTES) throw new Error('JWKS unavailable');
    const keys = new Map<string, KeyObject>();
    for (const jwk of (JSON.parse(body) as { keys?: unknown }).keys as unknown[] ?? []) {
      const k = record(jwk);
      // public Ed25519 signing keys only; a private component or another algorithm is ignored, never trusted
      if (k.kty !== 'OKP' || k.crv !== 'Ed25519' || typeof k.x !== 'string' || typeof k.kid !== 'string' || k.d !== undefined) continue;
      if ((k.alg !== undefined && k.alg !== 'EdDSA') || (k.use !== undefined && k.use !== 'sig')) continue;
      keys.set(k.kid, createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: k.x }, format: 'jwk' }));
    }
    // replaced, not merged: a key the PDP retired stops verifying at the next refresh
    this.#keys = keys; this.#fetchedAt = this.#now();
  }

  async #key(kid: string): Promise<KeyObject | undefined> {
    const age = this.#now() - this.#fetchedAt;
    if (age >= this.#cacheMs || (!this.#keys.has(kid) && age >= 10_000)) {
      this.#refreshing ??= this.#refresh().finally(() => { this.#refreshing = undefined; });
      try { await this.#refreshing; } catch { refuse('jwks_unavailable'); }
    }
    return this.#keys.get(kid);
  }

  /** The verified claims; throws AssertionError otherwise. The nonce is spent only when every check passed. */
  async verify(request: ForwardedRequest): Promise<AssertionClaims> {
    const token = typeof request.header === 'string' && request.header.length <= 4096 ? request.header : refuse('assertion_missing');
    const [h = '', p = '', s = '', extra] = token.split('.');
    if (extra !== undefined || !h || !p || !s || !B64.test(s) || Buffer.from(s, 'base64url').toString('base64url') !== s) refuse('assertion_invalid');
    const header = record(part(h));
    exact(header, ['alg', 'typ', 'kid']);
    if (header.alg !== 'EdDSA' || header.typ !== ASSERTION_TYP) refuse('assertion_invalid');
    const claims = claimsOf(part(p));
    const key = await this.#key(text(header.kid, 128));
    if (!key) refuse('assertion_key_unknown');
    if (!verify(null, Buffer.from(`${h}.${p}`), key as KeyObject, Buffer.from(s, 'base64url'))) refuse('assertion_invalid');
    const now = Math.floor(this.#now() / 1000);
    if (claims.iat > now + this.#skew) refuse('assertion_invalid');
    if (claims.exp <= now - this.#skew) refuse('assertion_expired');
    if (claims.aud !== this.#audience || claims.htm !== request.method || claims.htp !== request.path || claims.bsh !== bodySha256(request.body)) refuse('assertion_mismatch');
    let fresh: boolean;
    try { fresh = await this.#replay.spend(claims.nonce, claims.exp + this.#skew); } catch { return refuse('replay_store_unavailable'); }
    if (fresh !== true) refuse('assertion_replayed');
    return claims;
  }
}

export type AssertedHandler = (req: IncomingMessage, res: ServerResponse, verified: { readonly claims: AssertionClaims; readonly body: Buffer }) => void | Promise<void>;

/** node:http middleware: reads the body (bounded), verifies the gateway's assertion, then runs `handler`; anything
 *  else answers 401 (no or a bad assertion), 413 or 503 (keys unavailable) and the handler never runs. */
export function withGateAssertion(verifier: AssertionVerifier, handler: AssertedHandler, options: { maxBodyBytes?: number } = {}): (req: IncomingMessage, res: ServerResponse) => void {
  const max = options.maxBodyBytes ?? 1_048_576;
  const fail = (res: ServerResponse, status: number, error: string): void => {
    res.statusCode = status; res.setHeader('content-type', 'application/json'); res.setHeader('cache-control', 'no-store');
    res.end(JSON.stringify({ error }));
  };
  return (req, res) => {
    const chunks: Buffer[] = []; let size = 0; let failed = false;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > max && !failed) { failed = true; fail(res, 413, 'payload_too_large'); req.destroy(); }
      if (!failed) chunks.push(chunk);
    });
    req.on('end', () => {
      if (failed) return;
      const body = Buffer.concat(chunks);
      verifier.verify({ method: req.method ?? '', path: req.url ?? '', body, header: req.headers[ASSERTION_HEADER] })
        .then((claims) => handler(req, res, { claims, body }))
        .catch((err: unknown) => {
          if (res.headersSent) { res.destroy(); return; }
          if (err instanceof AssertionError) fail(res, err.code === 'jwks_unavailable' || err.code === 'replay_store_unavailable' ? 503 : 401, err.code);
          else fail(res, 500, 'internal');
        });
    });
  };
}
