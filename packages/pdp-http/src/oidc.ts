import { createCipheriv, createDecipheriv, createHash, createPublicKey, randomBytes, verify, constants, type KeyObject } from 'node:crypto';
import { HttpError } from './http.ts';
import type { User } from './auth.ts';

/** Console sign-in through the organisation's identity provider: authorization code + PKCE (RFC 7636), signed ID token,
 *  MFA proven by the IdP (`amr` per RFC 8176, or a required `acr`), console roles read from one claim. */
export interface OidcConfig {
  issuer: string; clientId: string; clientSecret?: string;
  /** Claim holding console role names (Entra app roles: "roles"; Okta, Keycloak: often "groups"). */
  roleClaim?: string;
  /** Claim used as the console user id, compared as is. Required: it must be the id your applications send as
   *  subject, so self-grant and maker-checker rules see the same person. `email` is accepted only when verified. */
  idClaim: string;
  /** When set, sent as acr_values and the ID token's acr must equal it; otherwise amr must show MFA. */
  acr?: string;
}
export type OidcFailure = 'mfa_required' | 'no_role' | 'sso_failed';
export const CONSOLE_ROLES = new Set(['access_admin', 'policy_author', 'approver', 'security_officer', 'resource_owner', 'auditor']);
const MFA_AMR = new Set(['mfa', 'mca']);
const SKEW_S = 60;
const PENDING_MS = 10 * 60_000;
const LOGOUT_JTI_TTL_MS = 24 * 60 * 60_000;
const LOGOUT_JTI_LIMIT = 10_000;
const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
interface Discovery { issuer: string; authorization_endpoint: string; token_endpoint: string; jwks_uri: string }
/** Kept client-side in the state cookie, sealed with AES-256-GCM under a per-process key: no server table to fill. */
interface Pending { state: string; nonce: string; verifier: string; exp: number }
interface SignedToken { header: Record<string, unknown>; claims: Record<string, unknown> }
const b64url = (b: Buffer): string => b.toString('base64url');
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const decodeBase64url = (value: string): Buffer | undefined => {
  if (!value || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return undefined;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.toString('base64url') === value ? decoded : undefined;
};
const decodeJson = (value: string): Record<string, unknown> | undefined => {
  const bytes = decodeBase64url(value);
  if (!bytes) return undefined;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    return isObject(parsed) ? parsed : undefined;
  } catch { return undefined; }
};

export function isLoopback(url: URL): boolean { return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname); }
const secureUrl = (u: unknown): boolean => { try { const url = new URL(String(u)); return url.protocol === 'https:' || isLoopback(url); } catch { return false; } };

export class Oidc {
  private readonly cfg: Required<Pick<OidcConfig, 'issuer' | 'clientId' | 'roleClaim'>> & OidcConfig;
  private readonly redirectUri: string;
  private readonly sealKey = randomBytes(32);
  private discovery?: Discovery;
  private keys = new Map<string, KeyObject>();
  private keysFetched = -Infinity;
  private keysLoading?: Promise<void>;
  /** States already consumed, until their cookie would have expired: replay protection. Never refuses a new sign-in,
   *  so filling it cannot lock anyone out. */
  private readonly used = new Map<string, number>();
  private readonly logoutJtis = new Map<string, number>();
  private readonly wallClock: () => number;

  constructor(cfg: OidcConfig, publicOrigin: string, wallClock: () => number = Date.now) {
    const issuer = new URL(cfg.issuer);
    if (issuer.protocol !== 'https:' && !isLoopback(issuer)) throw new Error('OIDC_ISSUER must use https');
    if (!cfg.clientId) throw new Error('OIDC_CLIENT_ID is required');
    if (!cfg.idClaim) throw new Error('OIDC_ID_CLAIM is required: the claim that carries the subject id your applications use');
    this.cfg = { ...cfg, roleClaim: cfg.roleClaim ?? 'roles' };
    this.redirectUri = `${publicOrigin}/admin/v1/oidc/callback`;
    this.wallClock = wallClock;
  }

  /** Returns the IdP URL to redirect to and the sealed value for the state cookie. */
  async start(): Promise<{ location: string; cookie: string }> {
    const d = await this.meta();
    const state = b64url(randomBytes(24)), nonce = b64url(randomBytes(24)), verifier = b64url(randomBytes(32));
    const cookie = this.seal({ state, nonce, verifier, exp: this.wallClock() + PENDING_MS });
    const url = new URL(d.authorization_endpoint);
    const params: Record<string, string> = { response_type: 'code', client_id: this.cfg.clientId, redirect_uri: this.redirectUri,
      scope: 'openid profile email', state, nonce, code_challenge: b64url(createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256' };
    if (this.cfg.acr) params.acr_values = this.cfg.acr;
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    return { location: url.toString(), cookie };
  }

  /** Exchanges the code and returns the console user, or the reason sign-in is refused. `quiet` marks a callback that
   *  never matched a sign-in started here (forged or replayed): not worth an audit row. */
  async finish(code: string, state: string, cookie: string): Promise<{ user: User; oidc: { sub: string; sid?: string } } | { failure: OidcFailure; subject?: string; quiet?: boolean }> {
    const pending = this.unseal(cookie);
    if (!pending || pending.state !== state || this.wallClock() > pending.exp) return { failure: 'sso_failed', quiet: true };
    const at = this.wallClock();
    for (const [s, exp] of this.used) if (exp < at) this.used.delete(s);
    if (this.used.has(state)) return { failure: 'sso_failed', quiet: true };
    this.used.set(state, pending.exp);
    const d = await this.meta();
    const form = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: this.redirectUri, client_id: this.cfg.clientId, code_verifier: pending.verifier });
    if (this.cfg.clientSecret) form.set('client_secret', this.cfg.clientSecret);
    const res = await fetch(d.token_endpoint, { method: 'POST', body: form, headers: { accept: 'application/json' }, signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return { failure: 'sso_failed' };
    const idToken = ((await res.json()) as { id_token?: unknown }).id_token;
    if (typeof idToken !== 'string') return { failure: 'sso_failed' };
    const claims = await this.verifyIdToken(idToken, pending.nonce);
    if (!claims) return { failure: 'sso_failed' };
    const rawId = claims[this.cfg.idClaim];
    const subject = typeof rawId === 'string' && rawId.length > 0 && rawId.length <= 256 && rawId.trim() === rawId ? rawId : '';
    if (!subject || (this.cfg.idClaim === 'email' && claims.email_verified !== true)) return { failure: 'sso_failed' };
    const mfa = this.cfg.acr ? claims.acr === this.cfg.acr : Array.isArray(claims.amr) && claims.amr.some((m) => MFA_AMR.has(String(m)));
    if (!mfa) return { failure: 'mfa_required', subject };
    const raw = claims[this.cfg.roleClaim];
    const roles = [...new Set((Array.isArray(raw) ? raw : typeof raw === 'string' ? [raw] : []).map(String).filter((r) => CONSOLE_ROLES.has(r)))];
    if (!roles.length) return { failure: 'no_role', subject };
    const name = typeof claims.name === 'string' ? claims.name : typeof claims.email === 'string' ? claims.email : subject;
    return { user: { id: subject, name: name.slice(0, 120), roles }, oidc: { sub: claims.sub as string,
      ...(typeof claims.sid === 'string' && claims.sid ? { sid: claims.sid } : {}) } };
  }

  /** Signature (RS256, PS256, ES256 only), issuer, audience, authorized party, expiry, issue time and nonce. */
  async verifyIdToken(token: string, nonce: string): Promise<Record<string, unknown> | null> {
    const signed = await this.verifySignedToken(token);
    if (!signed) return null;
    const { claims } = signed;
    const now = this.wallClock() / 1000;
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (claims.iss !== this.cfg.issuer || !aud.includes(this.cfg.clientId)) return null;
    if (aud.length > 1 && claims.azp !== this.cfg.clientId) return null;
    if (typeof claims.exp !== 'number' || claims.exp + SKEW_S < now) return null;
    if (typeof claims.iat !== 'number' || claims.iat - SKEW_S > now) return null;
    if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || claims.nbf - SKEW_S > now)) return null;
    if (claims.nonce !== nonce || typeof claims.sub !== 'string' || !claims.sub) return null;
    return claims;
  }

  /** Back-Channel Logout 1.0 §2.6. `typ` is only RECOMMENDED there, so an untyped token is accepted: the required events
   *  claim and the forbidden nonce are what keep an ID token from passing as a logout token. */
  async verifyLogoutToken(token: string): Promise<{ sub?: string; sid?: string; jti: string } | null> {
    const signed = await this.verifySignedToken(token);
    if (!signed || (signed.header.typ !== undefined && signed.header.typ !== 'logout+jwt' && signed.header.typ !== 'JWT')) return null;
    const { claims } = signed;
    const nowMs = this.wallClock(), now = nowMs / 1000;
    const aud = typeof claims.aud === 'string' ? [claims.aud]
      : Array.isArray(claims.aud) && claims.aud.every((a) => typeof a === 'string') ? claims.aud : [];
    if (claims.iss !== this.cfg.issuer || !aud.includes(this.cfg.clientId) || !Number.isFinite(now)) return null;
    if (typeof claims.iat !== 'number' || !Number.isFinite(claims.iat) || claims.iat - SKEW_S > now || claims.iat * 1000 < nowMs - LOGOUT_JTI_TTL_MS - SKEW_S * 1000) return null;
    if (claims.exp !== undefined && (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp) || claims.exp + SKEW_S < now)) return null;
    if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || !Number.isFinite(claims.nbf) || claims.nbf - SKEW_S > now)) return null;
    if (typeof claims.jti !== 'string' || !claims.jti || Object.hasOwn(claims, 'nonce')) return null;
    const events = claims.events, logout = isObject(events) ? events[LOGOUT_EVENT] : undefined;
    if (!isObject(logout)) return null;
    const { sub, sid } = claims;
    if (sub !== undefined && (typeof sub !== 'string' || !sub)) return null;
    if (sid !== undefined && (typeof sid !== 'string' || !sid)) return null;
    if (sub === undefined && sid === undefined) return null;
    for (const [jti, expiry] of this.logoutJtis) if (expiry <= nowMs) this.logoutJtis.delete(jti);
    if (this.logoutJtis.has(claims.jti) || this.logoutJtis.size >= LOGOUT_JTI_LIMIT) return null;
    this.logoutJtis.set(claims.jti, nowMs + LOGOUT_JTI_TTL_MS);
    return { ...(typeof sub === 'string' ? { sub } : {}), ...(typeof sid === 'string' ? { sid } : {}), jti: claims.jti };
  }

  private async verifySignedToken(token: string): Promise<SignedToken | null> {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const header = decodeJson(parts[0]!), claims = decodeJson(parts[1]!), sig = decodeBase64url(parts[2]!);
    if (!header || !claims || !sig) return null;
    const { alg, kid } = header;
    if ((alg !== 'RS256' && alg !== 'PS256' && alg !== 'ES256') || (kid !== undefined && typeof kid !== 'string')) return null;
    if (header.crit !== undefined || header.b64 !== undefined) return null;
    const key = await this.key(kid as string | undefined);
    if (!key) return null;
    const data = Buffer.from(`${parts[0]}.${parts[1]}`);
    let ok: boolean;
    try {
      ok = alg === 'RS256' ? key.asymmetricKeyType === 'rsa' && verify('sha256', data, key, sig)
        : alg === 'PS256' ? key.asymmetricKeyType === 'rsa' && verify('sha256', data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, sig)
        : key.asymmetricKeyType === 'ec' && verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, sig);
    } catch { return null; }
    return ok ? { header, claims } : null;
  }

  private async meta(): Promise<Discovery> {
    if (this.discovery) return this.discovery;
    const res = await fetch(`${this.cfg.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw new HttpError(502, 'idp_unavailable', 'Identity provider unavailable');
    const d = (await res.json()) as Discovery;
    if (d.issuer !== this.cfg.issuer || ![d.authorization_endpoint, d.token_endpoint, d.jwks_uri].every(secureUrl)) {
      throw new HttpError(502, 'idp_unavailable', 'Identity provider metadata mismatch');
    }
    return (this.discovery = d);
  }

  /** Keys by kid; an unknown kid refetches the JWKS at most once a minute (IdP key rotation). */
  private async key(kid: string | undefined): Promise<KeyObject | undefined> {
    const pick = (): KeyObject | undefined => (kid ? this.keys.get(kid) : this.keys.size === 1 ? [...this.keys.values()][0] : undefined);
    if (pick()) return pick();
    if (!this.keysLoading && this.wallClock() - this.keysFetched >= 60_000) {
      this.keysFetched = this.wallClock(); // the attempt counts, so a failing JWKS endpoint is not hammered
      this.keysLoading = this.loadKeys().finally(() => { this.keysLoading = undefined; });
    }
    await this.keysLoading?.catch(() => undefined);
    return pick();
  }
  private async loadKeys(): Promise<void> {
    const d = await this.meta();
    const res = await fetch(d.jwks_uri, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) return;
    const { keys = [] } = (await res.json()) as { keys?: Array<Record<string, unknown>> };
    const next = new Map<string, KeyObject>();
    for (const jwk of keys) {
      if (jwk.use && jwk.use !== 'sig') continue;
      try {
        const key = createPublicKey({ key: jwk as never, format: 'jwk' });
        if (key.asymmetricKeyType === 'rsa' && (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) continue;
        next.set(String(jwk.kid ?? ''), key);
      } catch { /* skip keys Node cannot read */ }
    }
    this.keys = next;
  }
  private seal(p: Pending): string {
    const iv = randomBytes(12), c = createCipheriv('aes-256-gcm', this.sealKey, iv);
    const body = Buffer.concat([c.update(JSON.stringify(p), 'utf8'), c.final()]);
    return b64url(Buffer.concat([iv, c.getAuthTag(), body]));
  }
  private unseal(value: string): Pending | undefined {
    try {
      const raw = Buffer.from(value, 'base64url');
      if (raw.length < 29 || raw.length > 1024) return undefined;
      const d = createDecipheriv('aes-256-gcm', this.sealKey, raw.subarray(0, 12), { authTagLength: 16 });
      d.setAuthTag(raw.subarray(12, 28));
      return JSON.parse(Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8')) as Pending;
    } catch { return undefined; }
  }
}
