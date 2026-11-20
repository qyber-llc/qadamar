import { readFileSync } from 'node:fs';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { SAML, ValidateInResponseTo, type CacheItem, type CacheProvider, type Profile } from '@node-saml/node-saml';
import { decryptXml, parseDomFromString, xpath } from '@node-saml/node-saml/lib/xml.js';
import type { OidcSession, User } from './auth.ts';
import { CONSOLE_ROLES, isLoopback, type OidcFailure } from './oidc.ts';

/** Console sign-in through a SAML 2.0 identity provider (Web Browser SSO profile): SP-initiated, HTTP-Redirect
 *  AuthnRequest, HTTP-POST Response. XML signature checking, signature-wrapping defences, audience, issuer, timestamps
 *  and InResponseTo are @node-saml/node-saml's; what it only warns about or leaves out (the signature algorithms, the
 *  bearer Recipient, the Destination, the AuthnContextClassRef as MFA proof, a DOCTYPE) is checked here. */
export interface SamlConfig {
  /** The IdP entity id: the Issuer every assertion and logout request must carry. */
  idpEntityId: string;
  /** The IdP's SingleSignOnService URL for the HTTP-Redirect binding (https, or http on loopback). */
  idpSsoUrl: string;
  /** PEM text of the IdP signing certificate(s) (SAML_IDP_CERT_FILE): pinned, never fetched. */
  idpCert: string;
  /** This console's entity id, the audience assertions must name. Default: the metadata URL. */
  spEntityId?: string;
  /** Mounted PEM secrets; certificates alone are published in metadata. */
  decryptionKey?: string;
  decryptionCert?: string;
  signingKey?: string;
  signingCert?: string;
  /** The pinned IdP HTTP-Redirect SingleLogoutService URL. */
  idpSloUrl?: string;
  /** The assertion consumer service URL the IdP posts to. Default: PUBLIC_ORIGIN + /admin/v1/saml/acs. */
  acsUrl?: string;
  /** Accepted AuthnContextClassRef values, the IdP's multi-factor classes: requested (exact), and every AuthnStatement
   *  of the assertion must carry one of them. */
  authnContext: string[];
  /** Attribute holding console role names. Default: roles. */
  roleAttribute?: string;
  /** SAML_MAX_AUTH_AGE_SECONDS: the longest since the IdP authenticated the user (AuthnInstant). Default 12 h. */
  maxAuthAgeSeconds?: number;
  /** Attribute used as the console user id, compared as is (`NameID`: the subject's NameID). Required, as OIDC_ID_CLAIM:
   *  it must be the id your applications send as subject. */
  idAttribute: string;
}
export const SAML_ACS_PATH = '/admin/v1/saml/acs';
export const SAML_LOGOUT_PATH = '/admin/v1/saml/logout';
export const SAML_METADATA_PATH = '/admin/v1/saml/metadata';
const SKEW_MS = 60_000;
const PENDING_MS = 10 * 60_000;
const MAX_ASSERTION_AGE_MS = 5 * 60_000;
/** A LogoutRequest is accepted this long after its IssueInstant, and its ID once: the in-memory ID set only has to
 *  outlive that window, so a restart or failover reopens replay for at most a few minutes (ending sessions only). */
const LOGOUT_MAX_AGE_MS = 5 * 60_000;
/** SAML_MAX_AUTH_AGE_SECONDS default: an IdP session authenticated longer ago signs nobody in. */
export const DEFAULT_MAX_AUTH_AGE_SECONDS = 12 * 3600;
const CACHE_LIMIT = 10_000;
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
const DSIG = 'http://www.w3.org/2000/09/xmldsig#';
/** RSA with SHA-256 or SHA-512 (PKCS#1 v1.5 or PSS), as xml-crypto implements them; never SHA-1. */
const SIGNATURE_ALGORITHMS = new Set(['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
  'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1']);
const DIGEST_ALGORITHMS = new Set(['http://www.w3.org/2001/04/xmlenc#sha256', 'http://www.w3.org/2001/04/xmlenc#sha512']);

export function samlFromEnv(env: NodeJS.ProcessEnv): SamlConfig | undefined {
  if (!env.SAML_IDP_ENTITY_ID) return undefined;
  if (!env.SAML_IDP_CERT_FILE) throw new Error('SAML_IDP_CERT_FILE is required with SAML_IDP_ENTITY_ID: the IdP signing certificate (PEM)');
  return { idpEntityId: env.SAML_IDP_ENTITY_ID, idpSsoUrl: env.SAML_IDP_SSO_URL ?? '', idpCert: readFileSync(env.SAML_IDP_CERT_FILE, 'utf8'),
    decryptionKey: env.SAML_DECRYPTION_KEY_FILE ? readFileSync(env.SAML_DECRYPTION_KEY_FILE, 'utf8') : undefined,
    decryptionCert: env.SAML_DECRYPTION_CERT_FILE ? readFileSync(env.SAML_DECRYPTION_CERT_FILE, 'utf8') : undefined,
    signingKey: env.SAML_SIGNING_KEY_FILE ? readFileSync(env.SAML_SIGNING_KEY_FILE, 'utf8') : undefined,
    signingCert: env.SAML_SIGNING_CERT_FILE ? readFileSync(env.SAML_SIGNING_CERT_FILE, 'utf8') : undefined,
    idpSloUrl: env.SAML_IDP_SLO_URL, spEntityId: env.SAML_SP_ENTITY_ID, acsUrl: env.SAML_ACS_URL, roleAttribute: env.SAML_ROLE_ATTRIBUTE, idAttribute: env.SAML_ID_ATTRIBUTE ?? '',
    authnContext: (env.SAML_AUTHN_CONTEXT ?? '').split(',').map((c) => c.trim()).filter(Boolean),
    ...(env.SAML_MAX_AUTH_AGE_SECONDS ? { maxAuthAgeSeconds: Number(env.SAML_MAX_AUTH_AGE_SECONDS) } : {}) };
}

/** Pending request ids (single use) and the ids of messages already received, in this process: the admin plane runs on
 *  the leader only (followers forward /admin/, router.ts), as OIDC's consumed states do. Expired entries go on each
 *  write; past CACHE_LIMIT the oldest goes too (shortcut: a flood of sign-in starts from many addresses can retire a
 *  pending request early; move the entries to PostgreSQL rows if that is ever seen). */
class BoundedCache implements CacheProvider {
  private readonly items = new Map<string, { value: string; createdAt: number; expiresAt: number }>();
  private readonly ttlMs: number;
  constructor(ttlMs: number) { this.ttlMs = ttlMs; }
  private live(key: string): { value: string; createdAt: number; expiresAt: number } | undefined {
    const item = this.items.get(key);
    return item && item.expiresAt > Date.now() ? item : undefined;
  }
  private put(key: string, value: string, expiresAt: number): CacheItem {
    const now = Date.now();
    for (const [k, v] of this.items) if (v.expiresAt <= now) this.items.delete(k);
    while (this.items.size >= CACHE_LIMIT) this.items.delete(this.items.keys().next().value as string);
    this.items.set(key, { value, createdAt: now, expiresAt });
    return { value, createdAt: now };
  }
  async saveAsync(key: string, value: string): Promise<CacheItem | null> { return this.live(key) ? null : this.put(key, value, Date.now() + this.ttlMs); }
  async getAsync(key: string): Promise<string | null> { return this.live(key)?.value ?? null; }
  async removeAsync(key: string | null): Promise<string | null> { return key !== null && this.items.delete(key) ? key : null; }
  async consumeAsync(key: string): Promise<string | null> { const item = this.live(key); this.items.delete(key); return item?.value ?? null; }
  async saveIfAbsentAsync(key: string, value: string, expiresAtMs: number): Promise<boolean> {
    if (this.live(key)) return false;
    this.put(key, value, expiresAtMs);
    return true;
  }
}

type XmlNode = { $?: Record<string, string>; _?: string; [child: string]: unknown };
const kids = (node: XmlNode | undefined, name: string): XmlNode[] => (Array.isArray(node?.[name]) ? node[name] as XmlNode[] : []);
const sameUrl = (a: unknown, b: string): boolean => { try { return new URL(String(a)).href === new URL(b).href; } catch { return false; } };
const secureUrl = (raw: string): boolean => { try { const u = new URL(raw); return u.protocol === 'https:' || isLoopback(u); } catch { return false; } };

/** The certificates of a PEM file, each an RSA key of 2048 bits or more, or an EC key. */
function pinnedCertificates(pem: string): string[] {
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  if (!blocks.length) throw new Error('SAML_IDP_CERT_FILE holds no PEM certificate');
  for (const block of blocks) {
    const key = new X509Certificate(block).publicKey;
    if (!(key.asymmetricKeyType === 'ec' || (key.asymmetricKeyType === 'rsa' && (key.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048))) {
      throw new Error('SAML_IDP_CERT_FILE: each certificate must carry an RSA key of 2048 bits or more, or an EC key');
    }
  }
  return blocks;
}

/** A SAML message as posted: strict base64, no DOCTYPE (so no entity of any kind), parsed once. */
async function receivedXml(b64: string): Promise<{ xml: string; doc: Document } | undefined> {
  if (!b64 || !/^[A-Za-z0-9+/\r\n]+={0,2}$/.test(b64)) return undefined;
  const xml = Buffer.from(b64, 'base64').toString('utf8');
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) return undefined;
  try { return { xml, doc: await parseDomFromString(xml) }; } catch { return undefined; }
}
/** Every XML signature in the document uses an allowlisted signature and digest algorithm: a SHA-1 one anywhere refuses
 *  the whole message, whatever else is signed. */
function algorithmsAllowed(doc: Document): boolean {
  const used = (name: string): Array<string | null> => xpath.selectElements(doc, `//*[local-name()='${name}' and namespace-uri()='${DSIG}']`).map((e) => e.getAttribute('Algorithm'));
  return used('SignatureMethod').every((a) => a !== null && SIGNATURE_ALGORITHMS.has(a)) && used('DigestMethod').every((a) => a !== null && DIGEST_ALGORITHMS.has(a));
}
const rootAttribute = (doc: Document, name: string): string | null => doc.documentElement?.getAttribute(name) ?? null;

export class Saml {
  private readonly saml: SAML;
  private readonly logoutSaml: SAML;
  private readonly logoutPending = new BoundedCache(PENDING_MS);
  private readonly cfg: SamlConfig & { roleAttribute: string };
  readonly acsUrl: string;
  private readonly logoutUrl: string;
  private readonly pending = new BoundedCache(PENDING_MS);
  private readonly logouts = new BoundedCache(LOGOUT_MAX_AGE_MS);
  private readonly maxAuthAgeMs: number;

  constructor(cfg: SamlConfig, publicOrigin: string) {
    if (!cfg.idpEntityId) throw new Error('SAML_IDP_ENTITY_ID is required');
    if (!secureUrl(cfg.idpSsoUrl)) throw new Error('SAML_IDP_SSO_URL must be set and use https');
    if (!cfg.idAttribute) throw new Error('SAML_ID_ATTRIBUTE is required: the attribute (or NameID) that carries the subject id your applications use');
    if (!cfg.authnContext.length) throw new Error('SAML_AUTHN_CONTEXT is required: the AuthnContextClassRef values that prove multi-factor authentication');
    const maxAge = cfg.maxAuthAgeSeconds ?? DEFAULT_MAX_AUTH_AGE_SECONDS;
    if (!Number.isSafeInteger(maxAge) || maxAge < 60 || maxAge > 7 * 86_400) throw new Error('SAML_MAX_AUTH_AGE_SECONDS must be an integer in 60..604800');
    for (const [key, cert, label] of [[cfg.decryptionKey, cfg.decryptionCert, 'SAML_DECRYPTION'], [cfg.signingKey, cfg.signingCert, 'SAML_SIGNING']]) {
      if (Boolean(key) !== Boolean(cert)) throw new Error(`${label}_KEY_FILE and ${label}_CERT_FILE must be set together`);
      if (key && cert) {
        try {
          const privateKey = createPrivateKey(key);
          if (privateKey.asymmetricKeyType !== 'rsa' || (privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
            || !new X509Certificate(cert).checkPrivateKey(privateKey)) throw new Error();
        } catch { throw new Error(`${label}: expected a matching RSA 2048+ private key and certificate`); }
      }
    }
    if (cfg.idpSloUrl && (!secureUrl(cfg.idpSloUrl) || !cfg.signingKey)) throw new Error('SAML_IDP_SLO_URL needs https and SAML_SIGNING_KEY_FILE / SAML_SIGNING_CERT_FILE');
    this.maxAuthAgeMs = maxAge * 1000;
    this.acsUrl = cfg.acsUrl ?? `${publicOrigin}${SAML_ACS_PATH}`;
    if (!secureUrl(this.acsUrl) || new URL(this.acsUrl).pathname !== SAML_ACS_PATH) throw new Error(`SAML_ACS_URL must use https and end in ${SAML_ACS_PATH}`);
    this.logoutUrl = new URL(SAML_LOGOUT_PATH, this.acsUrl).href;
    const spEntityId = cfg.spEntityId || new URL(SAML_METADATA_PATH, this.acsUrl).href;
    this.cfg = { ...cfg, spEntityId, roleAttribute: cfg.roleAttribute || 'roles' };
    this.saml = new SAML({
      entryPoint: cfg.idpSsoUrl, issuer: spEntityId, audience: spEntityId, callbackUrl: this.acsUrl, logoutCallbackUrl: this.logoutUrl,
      decryptionPvk: cfg.decryptionKey, privateKey: cfg.signingKey, publicCert: cfg.signingCert,
      signatureAlgorithm: 'sha256', digestAlgorithm: 'sha256', logoutUrl: cfg.idpSloUrl,
      idpIssuer: cfg.idpEntityId, idpCert: pinnedCertificates(cfg.idpCert),
      // the assertion itself must be signed; a signature on the Response alone does not cover it
      wantAssertionsSigned: true, wantAuthnResponseSigned: false,
      validateInResponseTo: ValidateInResponseTo.always, requestIdExpirationPeriodMs: PENDING_MS, cacheProvider: this.pending,
      rejectReplayedAssertions: true, acceptedClockSkewMs: SKEW_MS, maxAssertionAgeMs: MAX_ASSERTION_AGE_MS,
      authnContext: cfg.authnContext, racComparison: 'exact', identifierFormat: null,
    });
    this.logoutSaml = new SAML({ ...this.saml.options, cacheProvider: this.logoutPending });
  }

  /** The IdP URL (HTTP-Redirect AuthnRequest) and the request id, which the router binds to the browser in a cookie. */
  async start(): Promise<{ location: string; requestId: string }> {
    const location = await this.saml.getAuthorizeUrlAsync('', {});
    const request = inflateRawSync(Buffer.from(new URL(location).searchParams.get('SAMLRequest') ?? '', 'base64')).toString('utf8');
    const requestId = /\sID="([^"]+)"/.exec(request)?.[1];
    if (!requestId) throw new Error('AuthnRequest without an ID');
    return { location, requestId };
  }

  /** Validates a posted Response for the request this browser started. `quiet`: it never answered that request (forged,
   *  replayed, or another browser's), not worth an audit row. */
  async finish(samlResponse: string, requestId: string): Promise<{ user: User; idp: OidcSession } | { failure: OidcFailure; subject?: string; quiet?: boolean }> {
    const received = requestId ? await receivedXml(samlResponse) : undefined;
    if (!received || rootAttribute(received.doc, 'InResponseTo') !== requestId) return { failure: 'sso_failed', quiet: true };
    const destination = rootAttribute(received.doc, 'Destination');
    if (!algorithmsAllowed(received.doc) || (destination !== null && !sameUrl(destination, this.acsUrl))) return { failure: 'sso_failed' };
    const encrypted = xpath.selectElements(received.doc, "/*[local-name()='Response']/*[local-name()='EncryptedAssertion']");
    if (encrypted.length) {
      try {
        if (!this.cfg.decryptionKey || encrypted.length !== 1) return { failure: 'sso_failed' };
        const xml = await decryptXml(encrypted[0]!.toString(), this.cfg.decryptionKey);
        const clear = await receivedXml(Buffer.from(xml).toString('base64'));
        if (!clear || !algorithmsAllowed(clear.doc)) return { failure: 'sso_failed' };
      } catch { return { failure: 'sso_failed' }; }
    }
    let profile: Profile | null;
    try { ({ profile } = await this.saml.validatePostResponseAsync({ SAMLResponse: samlResponse })); } catch { return { failure: 'sso_failed' }; }
    const assertion = (profile?.getAssertion?.() as { Assertion?: XmlNode } | undefined)?.Assertion;
    if (!profile || !assertion || profile.inResponseTo !== requestId) return { failure: 'sso_failed' };
    // SAML profiles 4.1.4.2-3: delivered through a bearer confirmation whose Recipient is this ACS (node-saml only warns)
    const confirmations = kids(kids(assertion, 'Subject')[0], 'SubjectConfirmation');
    if (!confirmations.some((c) => c.$?.Method === BEARER && sameUrl(kids(c, 'SubjectConfirmationData')[0]?.$?.Recipient, this.acsUrl))) return { failure: 'sso_failed' };
    const attributes = (profile.attributes ?? {}) as Record<string, unknown>;
    const rawId = this.cfg.idAttribute === 'NameID' ? profile.nameID : attributes[this.cfg.idAttribute];
    const subject = typeof rawId === 'string' && rawId.length > 0 && rawId.length <= 256 && rawId.trim() === rawId ? rawId : '';
    if (!subject) return { failure: 'sso_failed' };
    // an assertion is fresh (5 minutes) but may carry an IdP session authenticated days ago: bound that too
    const now = Date.now();
    const instants = kids(assertion, 'AuthnStatement').map((s) => Date.parse(s.$?.AuthnInstant ?? ''));
    if (!instants.length || !instants.every((i) => Number.isFinite(i) && i - SKEW_MS <= now && now - i <= this.maxAuthAgeMs + SKEW_MS)) return { failure: 'sso_failed', subject };
    const classes = kids(assertion, 'AuthnStatement').map((s) => kids(kids(s, 'AuthnContext')[0], 'AuthnContextClassRef')[0]?._);
    if (!classes.length || !classes.every((c) => c !== undefined && this.cfg.authnContext.includes(c))) return { failure: 'mfa_required', subject };
    const raw = attributes[this.cfg.roleAttribute];
    const roles = [...new Set((Array.isArray(raw) ? raw : [raw]).filter((r): r is string => typeof r === 'string' && CONSOLE_ROLES.has(r)))];
    if (!roles.length) return { failure: 'no_role', subject };
    const name = typeof attributes.displayName === 'string' ? attributes.displayName : subject;
    return { user: { id: subject, name: name.slice(0, 120), roles }, idp: { sub: profile.nameID, nameIDFormat: profile.nameIDFormat, nameQualifier: profile.nameQualifier, spNameQualifier: profile.spNameQualifier, ...(profile.sessionIndex ? { sid: profile.sessionIndex } : {}) } };
  }

  get logoutEnabled(): boolean { return Boolean(this.cfg.idpSloUrl); }

  /** Local sessions end before leaving Qadamar, even if the IdP never replies. */
  async startLogout(target: OidcSession): Promise<string> {
    if (!this.cfg.idpSloUrl) throw new Error('SAML single logout is not configured');
    return this.logoutSaml.getLogoutUrlAsync({ issuer: this.cfg.idpEntityId, nameID: target.sub, nameIDFormat: target.nameIDFormat ?? 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', nameQualifier: target.nameQualifier, spNameQualifier: target.spNameQualifier, sessionIndex: target.sid }, '', {});
  }

  /** Only the raw Redirect query is verified: parsing and rebuilding it would change the signed bytes. */
  async logoutMessage(form: URLSearchParams, rawQuery?: string): Promise<{ target?: { sub: string; sid?: string }; location: string } | null> {
    try {
      const requests = form.getAll('SAMLRequest'), responses = form.getAll('SAMLResponse');
      const isRequest = requests.length === 1 && responses.length === 0;
      if (!isRequest && !(responses.length === 1 && requests.length === 0)) return null;
      let encoded = (isRequest ? requests : responses)[0]!;
      if (rawQuery !== undefined) {
        if (rawQuery.length > 262144 || !SIGNATURE_ALGORITHMS.has(form.get('SigAlg') ?? '')) return null;
        encoded = inflateRawSync(Buffer.from(encoded, 'base64'), { maxOutputLength: 262144 }).toString('base64');
      }
      const received = await receivedXml(encoded);
      if (!received || !algorithmsAllowed(received.doc)) return null;
      const root = received.doc.documentElement;
      if (root.localName !== (isRequest ? 'LogoutRequest' : 'LogoutResponse') || root.namespaceURI !== 'urn:oasis:names:tc:SAML:2.0:protocol'
        || rootAttribute(received.doc, 'Version') !== '2.0') return null;
      const destination = rootAttribute(received.doc, 'Destination');
      if (destination !== null && !sameUrl(destination, this.logoutUrl)) return null;
      const issued = Date.parse(rootAttribute(received.doc, 'IssueInstant') ?? ''), now = Date.now();
      const id = rootAttribute(received.doc, 'ID');
      if (!id || !Number.isFinite(issued) || issued - SKEW_MS > now || issued < now - LOGOUT_MAX_AGE_MS) return null;
      const result = rawQuery !== undefined ? await this.logoutSaml.validateRedirectAsync(rawQuery)
        : isRequest ? await this.logoutSaml.validatePostRequestAsync({ SAMLRequest: encoded })
        : await this.logoutSaml.validatePostResponseAsync({ SAMLResponse: encoded });
      if (!(await this.logouts.saveIfAbsentAsync(id, '', now + LOGOUT_MAX_AGE_MS + SKEW_MS))) return null;
      if (!isRequest) return result.loggedOut ? { location: '/' } : null;
      const profile = result.profile;
      if (!profile?.ID || !profile.nameID) return null;
      const relay = rawQuery !== undefined ? ('relayState' in result ? result.relayState as string | undefined : undefined) : form.get('RelayState');
      if (form.getAll('RelayState').length > 1 || (relay && Buffer.byteLength(relay) > 80)) return null;
      const location = this.cfg.idpSloUrl ? await this.logoutSaml.getLogoutResponseUrlAsync(profile, relay ?? '', {}, true) : '/';
      return { target: { sub: profile.nameID, ...(profile.sessionIndex ? { sid: profile.sessionIndex } : {}) }, location };
    } catch { return null; }
  }

  /** SP metadata publishes only certificates, never private keys. */
  metadata(): string {
    const xml = this.saml.generateServiceProviderMetadata(this.cfg.decryptionCert ?? null, this.cfg.signingCert ?? null);
    return xml.replace(/<SingleLogoutService\b[^>]*\/>/, (post) => `${post}${post.replace('HTTP-POST', 'HTTP-Redirect')}`);
  }
}
