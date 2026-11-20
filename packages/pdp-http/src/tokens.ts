import { generateKeyPairSync, hkdfSync, createPrivateKey, createPublicKey, createCipheriv, createDecipheriv, sign, verify, randomBytes, randomUUID } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, renameSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { canonical } from '../../core/src/index.ts';
import type { Context } from '../../core/src/index.ts';
import { fileBacking, type Backing } from './store.ts';
import { HttpError, object } from './http.ts';
import type { MarkLoader } from './sessions.ts';
import type { StoredPepSession } from './pep-sessions.ts';

/** `sid`: the issuing session (scoped, sessions.ts), when the decision named one: its high-water mark decides the consumption.
 *  `bsid`: the PDP-issued BLP session (pep-sessions.ts) the decision ran in: the token dies with it (close, revocation or expiry). */
export interface Claims { sub: string; act: string; res: string; ver: number | null; pv: string; jti: string; iat: number; exp: number; sid?: string; bsid?: string }
interface Issued { claims: Claims; context: Context; used: boolean }
/** PostgreSQL: issued tokens are rows shared by every node; consumption is serialised by the database (postgres.ts). */
export interface TokenTable {
  insert(jti: string, entry: { claims: Claims; context: Context }): void;
  /** `resource`: the token's `res` claim; consumptions on one resource are serialised across nodes (separation of duty).
   *  `blpSession`: the token's `bsid`, whose row is locked and loaded in the consuming transaction and handed to `accept`. */
  consume(jti: string, resource: string, sid: string | undefined, accept: (entry: Issued | undefined, session?: StoredPepSession) => boolean,
    refresh?: (session: string, load: MarkLoader) => Promise<void>, blpSession?: string): Promise<boolean>;
}
export interface SigningKeyView { kid: string; created: string; active: boolean; verifyUntil?: string; sessionVerifyUntil?: string }
/** `introducedBy`: a rotated key, signed by the key it replaced (keyIntroduction), so a replica that trusts the old key
 *  can trust the new one without a new pin (replica.ts). Public keys outlive both windows for offline evidence. */
interface SigningKey { kid: string; created: string; publicKey: string; privateKey?: string; verifyUntil?: string; sessionVerifyUntil?: string; introducedBy?: { kid: string; jws: string } }
export interface SigningKeyDisk { keys: SigningKey[] }
export const MAX_DECISION_TOKEN_TTL_SECONDS = 300;
export const SESSION_TOKEN_TTL_SECONDS = 3600;
export const SESSION_TOKEN_TYP = 'gate-blp-session+jwt';
/** The longest context.sessionToken a decision accepts (runtime.ts): no longer token is ever issued. */
export const MAX_SESSION_TOKEN_CHARS = 4096;
export interface SessionTokenClaims { sid: string; sub: string; pep: string; iat: number; exp: number; idle: number }
/** What the previous key signs (detached) when a rotation introduces a new key. */
export const keyIntroduction = (kid: string, publicKey: string): Record<string, string> => ({ typ: 'gate-key-introduction', kid, publicKey });
/** Decision assertions forwarded to the backend (docs/API.md 2.0.2): short-lived, single-use at the backend. */
export const ASSERTION_TTL_SECONDS = 30;
export const ASSERTION_TYP = 'gate-assertion+jwt';
export interface AssertionClaims {
  sub: { type: string; id: string }; act: string; res: { type: string; id?: string }; did: string; pv: string;
  aud: string; htm: string; htp: string; bsh: string;
}
const encode = (v: unknown): string => Buffer.from(JSON.stringify(v)).toString('base64url');
/** v2 binds the key id as AES-GCM additional data, so a sealed key cannot be moved to another kid; v1 is read only. */
const SEALED_V1 = 'v1.';
const SEALED_V2 = 'v2.';
const sealed = (value: string): boolean => value.startsWith(SEALED_V1) || value.startsWith(SEALED_V2);
export class Tokens {
  private readonly backing: Backing<[string, Issued][]>;
  private readonly issued: Map<string, Issued>;
  private readonly now: () => string;
  private readonly dir: string;
  private readonly keyring: Backing<SigningKeyDisk>;
  /** File mode only: the keyring lives in DATA_DIR, next to signing-public.pem. */
  private readonly localFiles: boolean;
  private readonly sealKey?: Buffer;
  private readonly privateKeys = new Map<string, KeyObject>();
  private keys: SigningKey[];
  private readonly table?: TokenTable;
  private readonly previousSealKey?: Buffer;
  /** `keyring` set (PostgreSQL document): the keyring is shared by every node and no key file is written in `dir`.
   *  `table` set: issued tokens live there, not in `backing`. `signingKeySealPrevious`: still opens keys a leader has not
   *  re-sealed yet (seal-rotation.ts); nothing is ever sealed with it. */
  constructor(dir: string, now: () => string, backing?: Backing<[string, Issued][]>, options: { signingKeySeal?: string; signingKeySealPrevious?: string; keyring?: Backing<SigningKeyDisk>; table?: TokenTable } = {}) {
    this.now = now; this.backing = backing ?? fileBacking(join(dir, 'tokens.json')); this.dir = dir;
    this.localFiles = !options.keyring;
    this.table = options.table;
    this.keyring = options.keyring ?? fileBacking(join(dir, 'signing-keys.json')); this.sealKey = decodeSeal(options.signingKeySeal);
    this.previousSealKey = decodeSeal(options.signingKeySealPrevious, 'SIGNING_KEY_SEAL_PREVIOUS');
    this.keys = this.loadKeys();
    this.saveKeys(); this.writePublicFiles();
    this.issued = new Map(this.table ? [] : this.backing.load() ?? []);
  }
  /** Rereads the shared keyring a leader rotated (cluster follower). */
  reload(): void { this.keys = this.loadKeys(); }

  private loadKeys(): SigningKey[] {
    const disk = this.keyring.load();
    if (disk) {
      if (!Array.isArray(disk.keys) || !disk.keys.length) throw new Error('Invalid signing keyring');
      for (const key of disk.keys) if (key.privateKey) this.privateKey(key);
      return disk.keys;
    }
    const legacyFile = join(this.dir, 'signing-private.pem');
    let pair: { publicKey: KeyObject; privateKey: KeyObject };
    if (existsSync(legacyFile)) {
      const privateKey = createPrivateKey(readFileSync(legacyFile));
      pair = { privateKey, publicKey: createPublicKey(privateKey) };
    } else pair = generateKeyPairSync('ed25519');
    const publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const kid = Buffer.from(pair.publicKey.export({ type: 'spki', format: 'der' })).toString('base64url');
    return [{ kid, created: this.now(), publicKey: publicPem, privateKey: this.sealKey ? seal(privatePem, this.sealKey, kid) : privatePem }];
  }

  private privateKey(key: SigningKey): KeyObject {
    const cached = this.privateKeys.get(key.kid);
    if (cached) return cached;
    if (!key.privateKey) throw new Error('Signing key has no private component');
    if (sealed(key.privateKey) && !this.sealKey) throw new Error('SIGNING_KEY_SEAL is required to read sealed signing keys');
    const loaded = createPrivateKey(this.sealKey && sealed(key.privateKey) ? unsealAny(key.privateKey, [this.sealKey, this.previousSealKey], key.kid) : key.privateKey);
    this.privateKeys.set(key.kid, loaded);
    return loaded;
  }

  private active(): SigningKey {
    const active = [...this.keys].reverse().find((key) => key.privateKey);
    if (!active) throw new Error('No active decision-token signing key');
    return active;
  }

  private saveKeys(): void {
    // plaintext and v1 keys are (re)sealed as v2 at the next write
    const keys = this.keys.map((key) => {
      if (!key.privateKey || !this.sealKey || key.privateKey.startsWith(SEALED_V2)) return key;
      const plain = key.privateKey.startsWith(SEALED_V1) ? unsealAny(key.privateKey, [this.sealKey, this.previousSealKey], key.kid) : key.privateKey;
      return { ...key, privateKey: seal(plain, this.sealKey, key.kid) };
    });
    this.keys = keys;
    this.keyring.save({ keys });
  }

  /** The keyring is the only copy of the private keys: a legacy plaintext PEM goes once the keyring is sealed. */
  private writePublicFiles(): void {
    // shared keyring: a local copy would go stale on the other nodes, and a legacy PEM is kept until the operator
    // removes it, since the imported keyring only becomes durable at the first commit
    if (!this.localFiles) return;
    const publicFile = join(this.dir, 'signing-public.pem');
    const temporaryPublic = `${publicFile}.${randomUUID()}.tmp`;
    writeFileSync(temporaryPublic, this.active().publicKey, { mode: 0o600 });
    renameSync(temporaryPublic, publicFile);
    if (this.sealKey) rmSync(join(this.dir, 'signing-private.pem'), { force: true });
  }

  issue(claim: Omit<Claims, 'jti' | 'iat' | 'exp'>, ttl: number, context: Context): string {
    if (!Number.isInteger(ttl) || ttl <= 0 || ttl > MAX_DECISION_TOKEN_TTL_SECONDS) throw new Error('Invalid decision token TTL');
    const iat = Math.floor(Date.parse(this.now()) / 1000);
    const claims = { ...claim, jti: randomUUID(), iat, exp: iat + ttl };
    if (this.table) this.table.insert(claims.jti, { claims, context });
    else {
      for (const [id, entry] of this.issued) if (entry.claims.exp <= iat) this.issued.delete(id);
      this.issued.set(claims.jti, { claims, context, used: false }); this.save();
    }
    const active = this.active();
    const content = `${encode({ alg: 'EdDSA', typ: 'JWT', kid: active.kid })}.${encode(claims)}`;
    return `${content}.${sign(null, Buffer.from(content), this.privateKey(active)).toString('base64url')}`;
  }

  /** Once only, on any node: synchronous with files, a promise with the shared table (the database decides). */
  /** `check` gets the BLP session row the database loaded for a `bsid` claim (PostgreSQL); in file mode, none. */
  consume(token: string, check: (claims: Claims, context: Context, session?: StoredPepSession) => boolean,
    refresh?: (session: string, load: MarkLoader) => Promise<void>): void | Promise<void> {
    const claims = this.signedClaims(token);
    const accept = (issued: Issued | undefined, session?: StoredPepSession): boolean => {
      try {
        const at = Math.floor(Date.parse(this.now()) / 1000);
        if (!issued || issued.used || claims.exp <= at || claims.iat > at || canonical(claims) !== canonical(issued.claims)) return false;
        return check(claims, issued.context, session);
      } catch { return false; }
    };
    if (this.table) return this.table.consume(claims.jti, claims.res, claims.sid, accept, refresh, claims.bsid).then((ok) => { if (!ok) throw unconsumable(); });
    const issued = this.issued.get(claims.jti);
    if (!accept(issued)) throw unconsumable();
    this.issued.set(claims.jti, { ...issued!, used: true }); this.save();
  }

  /** The claims of a token this keyring signed, with a key still valid; anything else cannot be consumed. */
  private signedClaims(token: string): Claims {
    try {
      const parts = token.split('.');
      if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part) || Buffer.from(part, 'base64url').toString('base64url') !== part)) throw new Error();
      const [header, payload, signature] = parts;
      if (!header || !payload || !signature) throw new Error();
      const parsedHeader = object(JSON.parse(Buffer.from(header, 'base64url').toString()));
      if (parsedHeader.alg !== 'EdDSA' || parsedHeader.kid !== undefined && typeof parsedHeader.kid !== 'string') throw new Error();
      const key = parsedHeader.kid === undefined ? this.active() : this.keys.find((candidate) => candidate.kid === parsedHeader.kid);
      if (!key || key.verifyUntil && Date.parse(key.verifyUntil) <= Date.parse(this.now())) throw new Error();
      if (!verify(null, Buffer.from(`${header}.${payload}`), createPublicKey(key.publicKey), Buffer.from(signature, 'base64url'))) throw new Error();
      const claims = object(JSON.parse(Buffer.from(payload, 'base64url').toString())) as unknown as Claims;
      if (typeof claims.jti !== 'string' || !claims.jti || claims.jti.length > 64) throw new Error();
      return claims;
    } catch { throw unconsumable(); }
  }

  issueSession(claim: Omit<SessionTokenClaims, 'iat' | 'exp'>): string {
    const iat = Math.floor(Date.parse(this.now()) / 1000);
    const claims = { ...claim, iat, exp: iat + SESSION_TOKEN_TTL_SECONDS };
    const active = this.active();
    const content = `${encode({ alg: 'EdDSA', typ: SESSION_TOKEN_TYP, kid: active.kid })}.${encode(claims)}`;
    return `${content}.${sign(null, Buffer.from(content), this.privateKey(active)).toString('base64url')}`;
  }

  /** A session token has its own typ and claims, so neither a decision token nor an assertion can stand in for it. */
  verifySession(token: string): SessionTokenClaims {
    try {
      const parts = token.split('.');
      if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part) || Buffer.from(part, 'base64url').toString('base64url') !== part)) throw new Error();
      const [header, payload, signature] = parts;
      if (!header || !payload || !signature) throw new Error();
      const parsedHeader = object(JSON.parse(Buffer.from(header, 'base64url').toString()));
      if (parsedHeader.alg !== 'EdDSA' || parsedHeader.typ !== SESSION_TOKEN_TYP || typeof parsedHeader.kid !== 'string') throw new Error();
      const key = this.keys.find((candidate) => candidate.kid === parsedHeader.kid);
      const sessionUntil = key?.sessionVerifyUntil ?? key?.verifyUntil;
      if (!key || sessionUntil && Date.parse(sessionUntil) <= Date.parse(this.now())) throw new Error();
      if (!verify(null, Buffer.from(`${header}.${payload}`), createPublicKey(key.publicKey), Buffer.from(signature, 'base64url'))) throw new Error();
      const claims = object(JSON.parse(Buffer.from(payload, 'base64url').toString())) as unknown as SessionTokenClaims;
      if (!/^[0-9a-f-]{36}$/.test(claims.sid) || typeof claims.sub !== 'string' || typeof claims.pep !== 'string' || !claims.pep ||
        !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) || claims.exp !== claims.iat + SESSION_TOKEN_TTL_SECONDS ||
        !Number.isSafeInteger(claims.idle) || claims.idle < 1 || claims.idle > SESSION_TOKEN_TTL_SECONDS) throw new Error();
      return claims;
    } catch { throw new HttpError(403, 'invalid_session_token', 'Session token is invalid, expired, closed, or not bound to this request'); }
  }

  /** Signs a decision assertion with the active key: the PEP that asks never holds a private key. A typ of its own
   *  keeps it from being taken for a decision token or a bundle signature, which the same keyring signs. */
  assertion(claims: AssertionClaims): string {
    const iat = Math.floor(Date.parse(this.now()) / 1000);
    const active = this.active();
    const content = `${encode({ alg: 'EdDSA', typ: ASSERTION_TYP, kid: active.kid })}.${encode({ ...claims, iat, exp: iat + ASSERTION_TTL_SECONDS, nonce: randomBytes(16).toString('base64url') })}`;
    return `${content}.${sign(null, Buffer.from(content), this.privateKey(active)).toString('base64url')}`;
  }

  detached(pack: unknown): string {
    const active = this.active();
    const header = encode({ alg: 'EdDSA', kid: active.kid });
    const payload = Buffer.from(canonical(pack)).toString('base64url');
    return `${header}..${sign(null, Buffer.from(`${header}.${payload}`), this.privateKey(active)).toString('base64url')}`;
  }

  /** True when `jws` (from detached) signs canonical(pack) with a key inside its online acceptance window. */
  verifyDetached(pack: unknown, jws: string): boolean {
    try {
      const [header, empty, signature, extra] = jws.split('.');
      if (!header || empty !== '' || !signature || extra !== undefined) return false;
      const parsed = object(JSON.parse(Buffer.from(header, 'base64url').toString()));
      if (parsed.alg !== 'EdDSA' || typeof parsed.kid !== 'string') return false;
      const key = this.keys.find((candidate) => candidate.kid === parsed.kid);
      if (!key || (key.verifyUntil && Date.parse(key.verifyUntil) <= Date.parse(this.now()))) return false;
      const payload = Buffer.from(canonical(pack)).toString('base64url');
      return verify(null, Buffer.from(`${header}.${payload}`), createPublicKey(key.publicKey), Buffer.from(signature, 'base64url'));
    } catch { return false; }
  }

  /** Offline evidence has no online acceptance window: the retained public keyring and its introduction history
   *  authenticate old manifests, while policy and token verification continue to use verifyDetached/verifySession. */
  verifyManifest(pack: unknown, jws: string): boolean {
    try {
      if (pack === null || typeof pack !== 'object' || Array.isArray(pack) || (pack as { format?: unknown }).format !== 'gate-evidence-manifest/1') return false;
      const [header, empty, signature, extra] = jws.split('.');
      if (!header || empty !== '' || !signature || extra !== undefined) return false;
      const parsed = object(JSON.parse(Buffer.from(header, 'base64url').toString()));
      if (parsed.alg !== 'EdDSA' || typeof parsed.kid !== 'string') return false;
      const key = this.keys.find((candidate) => candidate.kid === parsed.kid);
      if (!key) return false;
      const payload = Buffer.from(canonical(pack)).toString('base64url');
      return verify(null, Buffer.from(`${header}.${payload}`), createPublicKey(key.publicKey), Buffer.from(signature, 'base64url'));
    } catch { return false; }
  }

  /** `beforeCommit` (the audit row) runs once the new key exists but before the keyring changes: if it throws, nothing
   *  is rotated. */
  rotate(beforeCommit?: (next: { kid: string; previousKid: string; previousVerifyUntil: string }) => void): { current: SigningKeyView; previous: SigningKeyView } {
    const at = Date.parse(this.now());
    const previous = this.active();
    const pair = generateKeyPairSync('ed25519');
    const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const kid = randomUUID();
    const introducedBy = { kid: previous.kid, jws: this.detached(keyIntroduction(kid, publicKey)) }; // the old key's last signature
    const verifyUntil = new Date(at + MAX_DECISION_TOKEN_TTL_SECONDS * 1000).toISOString();
    beforeCommit?.({ kid, previousKid: previous.kid, previousVerifyUntil: verifyUntil });
    previous.verifyUntil = verifyUntil;
    previous.sessionVerifyUntil = new Date(at + SESSION_TOKEN_TTL_SECONDS * 1000).toISOString();
    delete previous.privateKey; this.privateKeys.delete(previous.kid);
    const current: SigningKey = { kid, created: this.now(), publicKey, introducedBy,
      ...(this.sealKey ? { privateKey: seal(privatePem, this.sealKey, kid) } : { privateKey: privatePem }) };
    this.keys.push(current);
    this.saveKeys(); this.writePublicFiles();
    return { current: keyView(current, true), previous: keyView(previous, false) };
  }

  /** The active key's public entry (with the introduction its predecessor signed): replicas learn a rotated key from it. */
  activePublic(): SigningKeyDisk['keys'][number] {
    const { privateKey: _private, ...entry } = this.active();
    return entry;
  }

  signingKeys(): SigningKeyView[] {
    const active = this.active().kid;
    return this.keys.map((key) => keyView(key, key.kid === active));
  }

  jwks(): { keys: Array<Record<string, unknown>> } {
    const at = Date.parse(this.now());
    const published = this.keys.filter((key) => key.privateKey || !key.verifyUntil || Date.parse(key.verifyUntil) > at ||
      key.sessionVerifyUntil && Date.parse(key.sessionVerifyUntil) > at);
    return { keys: published.map((key) => ({ ...createPublicKey(key.publicKey).export({ format: 'jwk' }), kid: key.kid, use: 'sig', alg: 'EdDSA' })) };
  }

  private save(): void { this.backing.save([...this.issued]); }
}

const unconsumable = (): HttpError => new HttpError(409, 'conflict', 'Decision token cannot be consumed');
function keyView(key: SigningKey, active: boolean): SigningKeyView {
  return { kid: key.kid, created: key.created, active, ...(key.verifyUntil ? { verifyUntil: key.verifyUntil } : {}),
    ...(key.sessionVerifyUntil ? { sessionVerifyUntil: key.sessionVerifyUntil } : {}) };
}
/** SIGNING_KEY_SEAL decoded; it also seals the local accounts' TOTP secrets (auth.ts). */
export function decodeSeal(value: string | undefined, name = 'SIGNING_KEY_SEAL'): Buffer | undefined {
  if (value === undefined) return undefined;
  if (/^[a-f0-9]{64}$/i.test(value)) return Buffer.from(value, 'hex');
  const key = Buffer.from(value, 'base64url');
  if (key.length !== 32 || key.toString('base64url') !== value) throw new Error(`${name} must be 32 bytes as base64url or 64 hexadecimal characters`);
  return key;
}
/** Opens `value` with the first of `keys` that authenticates it (the current seal key, then the previous one). */
export function unsealAny(value: string, keys: ReadonlyArray<Buffer | undefined>, kid: string): string {
  let failure: unknown = new Error('No seal key');
  for (const key of keys) {
    if (!key) continue;
    try { return unseal(value, key, kid); } catch (err) { failure = err; }
  }
  throw failure;
}
/** A key for one purpose derived from SIGNING_KEY_SEAL (HKDF-SHA256, the label as info): never the seal key itself. */
export function derivedKey(signingKeySeal: string | undefined, label: string): Buffer | undefined {
  const seal = decodeSeal(signingKeySeal);
  return seal ? Buffer.from(hkdfSync('sha256', seal, Buffer.alloc(0), label, 32)) : undefined;
}
export const CHECKPOINT_KEY_LABEL = 'qadamar/audit-checkpoint/hmac-sha256/v1';
export function seal(plain: string, key: Buffer, kid: string): string {
  const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(kid, 'utf8'));
  const encrypted = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return `${SEALED_V2}${iv.toString('base64url')}.${cipher.getAuthTag().toString('base64url')}.${encrypted.toString('base64url')}`;
}
export function unseal(value: string, key: Buffer, kid: string): string {
  const [version, iv, tag, encrypted, extra] = value.split('.');
  if ((version !== 'v1' && version !== 'v2') || !iv || !tag || !encrypted || extra) throw new Error('Invalid sealed signing key');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'), { authTagLength: 16 }); // a shorter tag is refused
  if (version === 'v2') decipher.setAAD(Buffer.from(kid, 'utf8'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(encrypted, 'base64url')), decipher.final()]).toString('utf8');
}
