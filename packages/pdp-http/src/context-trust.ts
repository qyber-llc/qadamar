import { createPublicKey, timingSafeEqual, verify } from 'node:crypto';
import type { JsonWebKey, KeyObject } from 'node:crypto';
import { canonical, validCountry } from '../../core/src/index.ts';
import type { Ref } from '../../core/src/index.ts';
import { HttpError, object } from './http.ts';
import type { SessionBindings } from './pep-sessions.ts';

export const CONTEXT_SIGNALS = ['network', 'ip', 'country', 'device', 'authTime', 'mfaTime', 'authMethods', 'riskScore', 'sessionLevel'] as const;
export type ContextSignal = typeof CONTEXT_SIGNALS[number];
export interface ContextAttester { kid: string; alg: 'EdDSA' | 'ES256'; jwk: JsonWebKey }
export interface ContextAttestation { audience: string; keys: ContextAttester[] }
export interface ContextClaimScope {
  signal: ContextSignal;
  networks?: Array<'trusted' | 'untrusted'>;
  countries?: string[];
  attestation?: ContextAttestation;
}
export interface ContextTrust {
  credential: string;
  /** Undefined: one-version demo compatibility. Empty: no signal may be asserted (production's unscoped default). */
  scopes?: readonly ContextClaimScope[];
  legacyWarning?: () => void;
}
export interface AttestationBinding { subject?: Ref; sessionId?: string }

const MAX_ATTESTATION_CHARS = 8192;
const MAX_ATTESTATION_TTL_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 30;
const same = (a: unknown, b: string): boolean => {
  if (typeof a !== 'string') return false;
  const left = Buffer.from(a), right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};
const refused = (signal: string, reason: string): never => {
  throw new HttpError(403, 'context_claim_forbidden', `This PEP credential may not assert context.${signal}: ${reason}`);
};
const badAttestation = (signal: string): never => {
  throw new HttpError(403, 'invalid_context_attestation', `context.attestations.${signal} is missing, invalid, expired, or not bound to this request`);
};

export function contextClaimScopes(input: unknown, production: boolean): ContextClaimScope[] | undefined {
  if (input === undefined) {
    if (production) throw new HttpError(400, 'bad_request', 'contextScopes is required in the production profile (use [] to assert no context signals)');
    return undefined;
  }
  if (!Array.isArray(input) || input.length > CONTEXT_SIGNALS.length) throw new HttpError(400, 'bad_request', 'contextScopes must list each permitted context signal at most once');
  const scopes = input.map((entry) => {
    const value = object(entry);
    if (Object.keys(value).some((key) => !['signal', 'networks', 'countries', 'attestation'].includes(key)) || typeof value.signal !== 'string' || !CONTEXT_SIGNALS.includes(value.signal as ContextSignal)) {
      throw new HttpError(400, 'bad_request', 'Each contextScopes entry must name a supported signal and only its applicable constraints');
    }
    const signal = value.signal as ContextSignal;
    const networks = value.networks === undefined ? undefined : stringSet(value.networks, 'networks', 2);
    if (networks?.some((network) => network !== 'trusted' && network !== 'untrusted')) throw new HttpError(400, 'bad_request', 'contextScopes networks must be trusted or untrusted');
    if (networks !== undefined && signal !== 'network') throw new HttpError(400, 'bad_request', 'networks is a constraint of the network scope only');
    const countries = value.countries === undefined ? undefined : stringSet(value.countries, 'countries', 249);
    if (countries?.some((country) => !validCountry(country))) throw new HttpError(400, 'bad_request', 'contextScopes countries must be upper-case assigned ISO country codes');
    if (countries !== undefined && signal !== 'country') throw new HttpError(400, 'bad_request', 'countries is a constraint of the country scope only');
    const attestation = value.attestation === undefined ? undefined : attestationConfig(value.attestation);
    return { signal, ...(networks ? { networks: networks as Array<'trusted' | 'untrusted'> } : {}), ...(countries ? { countries } : {}), ...(attestation ? { attestation } : {}) };
  });
  if (new Set(scopes.map((scope) => scope.signal)).size !== scopes.length) throw new HttpError(400, 'bad_request', 'contextScopes must not repeat a signal');
  return scopes;
}

function stringSet(input: unknown, field: string, maximum: number): string[] {
  if (!Array.isArray(input) || input.length === 0 || input.length > maximum || !input.every((item) => typeof item === 'string')) {
    throw new HttpError(400, 'bad_request', `${field} must list 1..${maximum} strings`);
  }
  return [...new Set(input as string[])];
}

function attestationConfig(input: unknown): ContextAttestation {
  const value = object(input);
  if (Object.keys(value).some((key) => !['audience', 'keys'].includes(key)) || typeof value.audience !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(value.audience) || !Array.isArray(value.keys) || value.keys.length === 0 || value.keys.length > 8) {
    throw new HttpError(400, 'bad_request', 'attestation needs a printable audience and 1..8 trusted public keys');
  }
  const keys = value.keys.map((entry) => {
    const key = object(entry);
    if (Object.keys(key).some((name) => !['kid', 'alg', 'jwk'].includes(name)) || typeof key.kid !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(key.kid) || (key.alg !== 'EdDSA' && key.alg !== 'ES256')) {
      throw new HttpError(400, 'bad_request', 'Each attester needs kid, alg (EdDSA or ES256), and a public JWK');
    }
    const jwk = object(key.jwk) as JsonWebKey;
    const privateFields = ['d', 'k', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];
    if (privateFields.some((field) => jwk[field] !== undefined)) throw new HttpError(400, 'bad_request', 'An attester JWK must contain no private key material');
    try {
      const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
      if ((key.alg === 'EdDSA' && (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519')) || (key.alg === 'ES256' && (jwk.kty !== 'EC' || jwk.crv !== 'P-256'))) throw new Error();
      if (publicKey.asymmetricKeyType !== (key.alg === 'EdDSA' ? 'ed25519' : 'ec')) throw new Error();
    } catch { throw new HttpError(400, 'bad_request', 'Attester JWK does not match its alg or is not a supported public key'); }
    return { kid: key.kid, alg: key.alg as 'EdDSA' | 'ES256', jwk };
  });
  if (new Set(keys.map((key) => key.kid)).size !== keys.length) throw new HttpError(400, 'bad_request', 'Attester key ids must be unique within a scope');
  return { audience: value.audience, keys };
}

/** Scope and attestation checks run before a claim reaches the decision context. Nothing disallowed is silently removed. */
export function authorizeContext(input: unknown, trust: ContextTrust, now: string, binding: AttestationBinding = {}): void {
  if (input === undefined) return;
  const context = object(input);
  const asserted = CONTEXT_SIGNALS.filter((signal) => context[signal] !== undefined);
  const supplied = context.attestations === undefined ? {} : object(context.attestations);
  if (trust.scopes === undefined) {
    if ((asserted.length > 0 || Object.keys(supplied).length > 0) && trust.legacyWarning) trust.legacyWarning();
    return;
  }
  for (const signal of asserted) {
    const scope = trust.scopes.find((candidate) => candidate.signal === signal);
    if (!scope) return refused(signal, 'the signal is outside contextScopes');
    if (signal === 'network' && scope.networks && !scope.networks.includes(context.network as 'trusted' | 'untrusted')) refused(signal, 'the network value is outside its constraint');
    if (signal === 'country' && scope.countries && (typeof context.country !== 'string' || !scope.countries.includes(context.country))) refused(signal, 'the country value is outside its constraint');
    const source = signal === 'device' ? object(context.device).id : signal === 'network' ? context.networkSensorId : undefined;
    if (scope.attestation) verifyAttestation(supplied[signal], signal, context[signal], source, scope.attestation, trust.credential, now, binding);
    else if (supplied[signal] !== undefined) refused(signal, 'this scope configures no attester');
  }
  for (const signal of Object.keys(supplied)) if (!CONTEXT_SIGNALS.includes(signal as ContextSignal) || !asserted.includes(signal as ContextSignal)) refused(signal, 'an attestation must accompany its asserted signal');
}

function verifyAttestation(token: unknown, signal: ContextSignal, claim: unknown, source: unknown, config: ContextAttestation, credential: string, now: string, binding: AttestationBinding): void {
  try {
    if (typeof token !== 'string' || token.length > MAX_ATTESTATION_CHARS) throw new Error();
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part) || Buffer.from(part, 'base64url').toString('base64url') !== part)) throw new Error();
    const [encodedHeader, payload, signature] = parts;
    if (!encodedHeader || !payload || !signature) throw new Error();
    const header = object(JSON.parse(Buffer.from(encodedHeader, 'base64url').toString()));
    if (Object.keys(header).sort().join(',') !== 'alg,kid,typ' || header.typ !== 'gate-context-attestation+jwt' || (header.alg !== 'EdDSA' && header.alg !== 'ES256') || typeof header.kid !== 'string') throw new Error();
    const attester = config.keys.find((key) => same(header.kid, key.kid) && header.alg === key.alg);
    if (!attester) throw new Error();
    const key: KeyObject = createPublicKey({ key: attester.jwk, format: 'jwk' });
    const verified = attester.alg === 'EdDSA'
      ? verify(null, Buffer.from(`${encodedHeader}.${payload}`), key, Buffer.from(signature, 'base64url'))
      : verify('sha256', Buffer.from(`${encodedHeader}.${payload}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url'));
    if (!verified) throw new Error();
    const claims = object(JSON.parse(Buffer.from(payload, 'base64url').toString()));
    const required = ['aud', 'exp', 'iat', 'iss', 'jti', 'pep', 'signal', 'sub', 'value'];
    if (required.some((name) => claims[name] === undefined) || Object.keys(claims).some((name) => ![...required, 'sid', 'src'].includes(name))) throw new Error();
    if (!binding.subject || !same(canonical(claims.sub), canonical([binding.subject.type, binding.subject.id]))) throw new Error();
    if (binding.sessionId === undefined ? claims.sid !== undefined : !same(claims.sid, binding.sessionId)) throw new Error();
    const sourceRequired = signal === 'device' || signal === 'network';
    if (sourceRequired ? typeof source !== 'string' || source.length === 0 || !same(claims.src, source) : claims.src !== undefined) throw new Error();
    const at = Math.floor(Date.parse(now) / 1000);
    if (!same(claims.iss, attester.kid) || !same(claims.aud, config.audience) || !same(claims.pep, credential) || !same(claims.signal, signal) ||
      typeof claims.jti !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(claims.jti) || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) ||
      (claims.iat as number) > at + CLOCK_SKEW_SECONDS || (claims.exp as number) <= at || (claims.exp as number) - (claims.iat as number) <= 0 ||
      (claims.exp as number) - (claims.iat as number) > MAX_ATTESTATION_TTL_SECONDS ||
      !same(canonical(claims.value), canonical(claim))) throw new Error();
  } catch { badAttestation(signal); }
}

/** Every AuthZEN context in a point, batch, search or assertion request, before any endpoint-specific evaluation. */
export function authorizeRequestContexts(body: unknown, trust: ContextTrust, now: string, bindings?: SessionBindings, batch = false): void {
  const walk = (value: unknown, depth: number, inherited?: Ref): void => {
    if (depth > 8 || value === null || typeof value !== 'object') return;
    if (Array.isArray(value)) { for (const child of value) walk(child, depth + 1, inherited); return; }
    const record = value as Record<string, unknown>;
    const raw = record.subject as { type?: unknown; id?: unknown } | undefined;
    const subject = typeof raw?.type === 'string' && typeof raw.id === 'string' ? { type: raw.type, id: raw.id } : inherited;
    // Only the batch route merges entries over the request; elsewhere `evaluations` is ordinary data and must not skip the check below.
    if (batch && depth === 0 && Array.isArray(record.evaluations)) {
      const { evaluations, ...shared } = record;
      for (const entry of evaluations) if (entry !== null && typeof entry === 'object' && !Array.isArray(entry)) walk({ ...shared, ...entry }, depth + 1, subject);
      return;
    }
    if (record.context !== undefined) {
      const token = (record.context as { sessionToken?: unknown }).sessionToken;
      const sessionId = typeof token === 'string' ? bindings?.get(token)?.sid : undefined;
      authorizeContext(record.context, trust, now, { ...(subject ? { subject } : {}), ...(sessionId ? { sessionId } : {}) });
    }
    for (const child of Object.values(record)) walk(child, depth + 1, subject);
  };
  walk(body, 0);
}
