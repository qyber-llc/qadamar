import { createHash, createHmac, hkdfSync, randomBytes, randomUUID, scrypt, scryptSync, timingSafeEqual, type BinaryLike } from 'node:crypto';
import { existsSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { IncomingMessage } from 'node:http';
import { HttpError, string } from './http.ts';
import { fileBacking, type Backing } from './store.ts';
import type { AuditLog } from './audit.ts';
import { unknownLoginActor } from './audit-subjects.ts';
import { RateLimiter } from './ratelimit.ts';
import { decodeSeal, seal, unsealAny } from './tokens.ts';
import { fromBase32, newRecoveryCode, newTotpSecret, otpauthUri, recoveryDigest, totpStep } from './totp.ts';
import { contextClaimScopes, type ContextClaimScope } from './context-trust.ts';

export interface User { id: string; name: string; roles: string[] }
/** secret: base32, sealed with SIGNING_KEY_SEAL (AES-256-GCM, account id bound); lastStep: last accepted time step;
 *  recovery: SHA-256 of the unused recovery codes. Inactive until a first code proves the enrolment. */
interface TotpState { secret: string; active: boolean; lastStep?: number; recovery?: string[] }
interface Account extends User { hash: string; totp?: TotpState }
/** issuedBy: who held this secret (the credential's issuer before the rotation), so a proposal made with it during the
 *  grace period is still kept from that person's review. */
interface PreviousPepSecret { hash: string; validUntil: string; issuedBy?: string }
export interface PepCredentialView {
  id: string; name: string; created: string; lastUsed?: string; revoked?: string; rotated?: string; previousValidUntil?: string;
  /** Clark-Wilson E3: the subject types (populations) this PEP authenticates; fixed at creation, none when absent. */
  subjectTypes?: string[];
  /** May call /access/v1/search/subject (who can access a resource). Absent: true, as before; the production profile
   *  creates every credential with false and refuses subject search to all. */
  allowSubjectSearch?: boolean;
  /** The resource types this PEP may register, update and retire (/x/v1/resources); none when absent: a credential
   *  writes the resource inventory only when it was created for it. Fixed at creation. */
  resourceTypes?: string[];
  /** Context signals this PEP may assert, with value constraints and optional trusted-attester requirements. */
  contextScopes?: ContextClaimScope[];
  /** The console user who created or last rotated the credential (who knows its secret): it cannot approve what the
   *  credential proposes. "bootstrap" for the initial credential; absent on credentials of 0.5.0 and earlier. */
  issuedBy?: string;
}
/** The authenticated PEP: its audit actor, the subject populations its credential is bound to, and its capabilities. */
export interface PepCaller {
  actor: string; subjectTypes: readonly string[]; allowSubjectSearch: boolean; /** The credential's id (never its secret). */ credential: string;
  resourceTypes: readonly string[]; issuedBy?: string;
  /** Undefined only for pre-scope credentials in demo compatibility; production maps those to the empty scope. */
  contextScopes?: readonly ContextClaimScope[];
}
interface PepCredential extends PepCredentialView { hash: string; previous: PreviousPepSecret[] }
export interface Credentials { users: Account[]; pepCredentials: PepCredential[]; pepHash?: string }
/** The identity provider's session: OIDC sub and sid, or SAML NameID and SessionIndex (method saml). */
export interface OidcSession { sub: string; sid?: string; nameIDFormat?: string; nameQualifier?: string; spNameQualifier?: string }
/** A console session. Keyed by sessionKey(sid): the raw session id is never stored, and the CSRF token is derived from
 *  it (csrfToken), so neither can be read back from where sessions are kept. created/touched: real time, epoch ms. */
export interface Session { user: User; created: number; touched: number; method: 'password' | 'oidc' | 'saml'; oidc?: OidcSession }
/** PostgreSQL (gate_session): sessions shared by every node, so a failover or a new leader keeps them. Writes are staged
 *  and commit with the request's audit rows; reads and back-channel ends query the table. */
export interface SessionTable {
  /** The stored sessions among `keys` (one primary-key lookup). */
  load(keys: readonly string[]): Promise<Array<[string, Session]>>;
  insert(key: string, session: Session): void;
  /** Moves `touched` forward; never recreates a session ended meanwhile. */
  touch(key: string, at: number): void;
  remove(key: string): void;
  /** Ends sessions last used at or before `touchedBefore` or opened at or before `createdBefore` (expired, as auth.ts counts). */
  purge(touchedBefore: number, createdBefore: number): void;
  /** Ends the sessions of `method` (oidc by default) matching an IdP logout target; resolves to their keys. */
  endOidc(target: { sub?: string; sid?: string }, method?: 'oidc' | 'saml'): Promise<string[]>;
}
export interface Lock { failures: number; until: number; touched?: number }
export interface AuthOptions {
  pepRotationGraceSeconds?: number;
  initialCredentialsTtlSeconds?: number;
  onBootstrapStatus?: (message: string) => void;
  /** Where the accounts (with their sealed TOTP secrets) and PEP credentials, and the console lockouts, live: files in
   *  `dir` by default, PostgreSQL documents when shared. */
  credentials?: Backing<Credentials>;
  lockouts?: Backing<Array<[string, Lock]>>;
  /** SIGNING_KEY_SEAL: without it no TOTP enrolment is possible (secrets are never stored in clear). */
  signingKeySeal?: string;
  /** SIGNING_KEY_SEAL_PREVIOUS: still opens TOTP secrets not yet re-sealed under the current key (seal-rotation.ts). */
  signingKeySealPrevious?: string;
  /** PostgreSQL: console sessions in gate_session; in memory (this process only) without it. */
  sessions?: SessionTable;
  /** GATE_PROFILE=production: no PEP credential may search subjects, whatever it was created with. */
  production?: boolean;
}
const roles: Record<string, string[]> = {
  amira: ['access_admin', 'policy_author'], omar: ['approver'], lina: ['security_officer'], ruth: ['resource_owner'], sam: ['auditor'],
};
export const randomSecret = (): string => randomBytes(24).toString('base64url');
/** Console passwords: scrypt N=2^16, r=8, p=2, one of the OWASP settings equal to its N=2^17, r=8, p=1 minimum, at half
 *  the memory (64 MiB per hash), over the 0.8.3 key of the password (scrypt at the Node defaults N=2^14, r=8, p=1);
 *  about 200 ms on an Apple M5 Pro. Stored as `scrypt-wrap$<log2 N>$<r>$<p>$<inner salt>$<salt>$<key>` so the cost can
 *  rise again. The inner layer lets a 0.8.3 hash `<salt>:<key>` be wrapped at start without its password
 *  (wrapLegacyPasswords): every account, and the dummy for unknown ones, then runs the same two scrypt calls. A plain
 *  `scrypt$<log2 N>$<r>$<p>$<salt>$<key>` still verifies and is rehashed at the next sign-in. */
const PASSWORD_COST = { ln: 16, r: 8, p: 2 } as const;
const LEGACY_COST = { ln: 14, r: 8, p: 1 } as const;
interface Cost { ln: number; r: number; p: number }
/** PEP keys and the SCIM token are random (192 bits or more): `hmac-sha256$<salt>$<mac>`. Stretching adds nothing
 *  against 2^192 guesses, and a slow hash on a per-request credential would let any caller burn the event loop. */
interface Parsed { salt: string; bytes: Buffer; cost?: Cost; /** wrapped: the salt of the inner LEGACY_COST layer */ inner?: string }
const WRAPPED = 'scrypt-wrap';
const sameCost = (a: Cost, b: Cost): boolean => a.ln === b.ln && a.r === b.r && a.p === b.p;
// scrypt needs 128·N·r bytes whatever p (the lanes run one after the other)
const scryptOptions = (c: Cost): { N: number; r: number; p: number; maxmem: number } => ({ N: 2 ** c.ln, r: c.r, p: c.p, maxmem: 256 * 2 ** c.ln * c.r });
const inRange = (v: number, lo: number, hi: number): boolean => Number.isInteger(v) && v >= lo && v <= hi;
function parseHash(secret: string, hash: string): Parsed | undefined {
  if (secret.length > 256) return undefined;
  const parts = hash.split('$');
  const wrapped = parts[0] === WRAPPED && parts.length === 7;
  if (wrapped || (parts[0] === 'scrypt' && parts.length === 6)) {
    const [ln, r, p] = parts.slice(1, 4).map(Number) as [number, number, number];
    const [salt, key] = parts.slice(-2) as [string, string];
    // bounded: a tampered store cannot ask for more than 256 MiB or a long run per attempt
    return inRange(ln, 14, 18) && inRange(r, 1, 16) && 2 ** ln * r <= 2 ** 21 && inRange(p, 1, 8) && salt && key && (!wrapped || parts[4])
      ? { salt, bytes: Buffer.from(key, 'hex'), cost: { ln, r, p }, ...(wrapped ? { inner: parts[4] } : {}) } : undefined;
  }
  if (parts[0] === 'hmac-sha256' && parts.length === 3) return parts[1] && parts[2] ? { salt: parts[1], bytes: Buffer.from(parts[2], 'hex') } : undefined;
  const [salt, expected] = hash.split(':');
  return parts.length === 1 && salt && expected ? { salt, bytes: Buffer.from(expected, 'hex'), cost: LEGACY_COST } : undefined;
}
const newSalt = (): string => randomBytes(16).toString('hex');
const passwordHash = (inner: string, salt: string, key: Buffer): string => `${WRAPPED}$${PASSWORD_COST.ln}$${PASSWORD_COST.r}$${PASSWORD_COST.p}$${inner}$${salt}$${key.toString('hex')}`;
const mac = (secret: string, salt: string): Buffer => createHmac('sha256', salt).update(secret).digest();
/** At most two password checks on the thread pool at once: 128 MiB at most however many sign-ins arrive (a sprayed
 *  unknown user costs the same as a real one), and two of libuv's four threads stay free for files and DNS. */
const SCRYPT_SLOTS = 2;
/** A spray of unknown names must not build an endless backlog that admins queue behind: past 32 waiting, 503 at once.
 *  A full queue drains in about 3 s (32 / 2 slots x 200 ms). */
export const SCRYPT_QUEUE = 32;
const SCRYPT_RETRY_SECONDS = 3;
let scryptRunning = 0;
const scryptWaiting: Array<() => void> = [];
async function scryptSlot<T>(run: () => Promise<T>): Promise<T> {
  if (scryptRunning < SCRYPT_SLOTS) scryptRunning++;
  else if (scryptWaiting.length >= SCRYPT_QUEUE) throw new HttpError(503, 'unavailable', 'Too many sign-ins in progress', [SCRYPT_RETRY_SECONDS]);
  else await new Promise<void>((resolve) => scryptWaiting.push(resolve)); // the finishing run hands its slot over
  try {
    return await run();
  } finally {
    const next = scryptWaiting.shift();
    if (next) next(); else scryptRunning--;
  }
}
const kdf = (secret: BinaryLike, salt: string, c: Cost): Promise<Buffer> =>
  new Promise((resolve, reject) => scrypt(secret, salt, 32, scryptOptions(c), (err, key) => (err ? reject(err) : resolve(key))));
/** The stored key: scrypt at `cost` of the password or, wrapped, of its LEGACY_COST key; both runs hold one slot. */
const derive = (secret: string, s: Parsed & { cost: Cost }): Promise<Buffer> =>
  scryptSlot(async () => kdf(s.inner === undefined ? secret : await kdf(secret, s.inner, LEGACY_COST), s.salt, s.cost));
const deriveSync = (secret: string, s: Parsed & { cost: Cost }): Buffer =>
  scryptSync(s.inner === undefined ? secret : scryptSync(secret, s.inner, 32, scryptOptions(LEGACY_COST)), s.salt, 32, scryptOptions(s.cost));
const fresh = (): Parsed & { cost: Cost; inner: string } => ({ inner: newSalt(), salt: newSalt(), bytes: Buffer.alloc(0), cost: PASSWORD_COST });
/** A console password at the current cost. Blocks the event loop: seeding only; sign-in rehashes with hashSecretAsync. */
export function hashSecret(secret: string): string {
  const s = fresh();
  return passwordHash(s.inner, s.salt, deriveSync(secret, s));
}
export async function hashSecretAsync(secret: string): Promise<string> {
  const s = fresh();
  return passwordHash(s.inner, s.salt, await derive(secret, s));
}
/** A single-layer hash at LEGACY_COST (the 0.8.3 `<salt>:<key>`) wrapped at the current cost without its password:
 *  scrypt at PASSWORD_COST over the stored key. Anything else: undefined. Blocks the event loop: start only. */
export function wrapLegacyHash(hash: string): string | undefined {
  const s = parseHash('', hash);
  if (!s?.cost || s.inner !== undefined || !sameCost(s.cost, LEGACY_COST)) return undefined;
  const salt = newSalt();
  return passwordHash(s.salt, salt, scryptSync(s.bytes, salt, 32, scryptOptions(PASSWORD_COST)));
}
/** A random machine secret (PEP key, SCIM token). */
export function hashMachineSecret(secret: string): string {
  const salt = newSalt();
  return `hmac-sha256$${salt}$${mac(secret, salt).toString('hex')}`;
}
/** True when `hash` is not in the current form: a password below PASSWORD_COST, a machine secret not yet an HMAC. */
export function needsRehash(hash: string, machine = false): boolean {
  if (machine) return !hash.startsWith('hmac-sha256$');
  const s = parseHash('', hash);
  return !s?.cost || s.inner === undefined || !sameCost(s.cost, PASSWORD_COST);
}
/** Never matches, yet costs exactly what a current password hash costs: unknown accounts take as long as known ones. */
export const dummyPasswordHash = (): string => passwordHash(newSalt(), newSalt(), randomBytes(32));
const sameBytes = (a: Buffer, b: Buffer): boolean => a.length === b.length && timingSafeEqual(a, b);
export function verifySecret(secret: string, hash: string): boolean {
  const stored = parseHash(secret, hash);
  if (!stored) return false;
  return sameBytes(stored.bytes, stored.cost ? deriveSync(secret, { ...stored, cost: stored.cost }) : mac(secret, stored.salt));
}
/** verifySecret on the libuv thread pool: same hash formats and comparison, without blocking the event loop (sign-in). */
export async function verifySecretAsync(secret: string, hash: string): Promise<boolean> {
  const stored = parseHash(secret, hash);
  if (!stored) return false;
  return sameBytes(stored.bytes, stored.cost ? await derive(secret, { ...stored, cost: stored.cost }) : mac(secret, stored.salt));
}
export function allowed(user: User, permitted: readonly string[]): void {
  if (!user.roles.some((r) => permitted.includes(r))) throw new HttpError(403, 'forbidden');
}
export const ownerOnly = (user: User): boolean => user.roles.includes('resource_owner') && !user.roles.some((r) => r !== 'resource_owner');
const ABSOLUTE_MS = 8 * 3_600_000;
const IDLE_MS = 15 * 60_000;
/** A shared session's last use is written at most once a minute: it may expire up to a minute early, never late. */
const TOUCH_MS = 60_000;
/** 8 h absolute, 15 min idle. */
const expired = (s: { created: number; touched: number }, at: number): boolean => at - s.created >= ABSOLUTE_MS || at - s.touched >= IDLE_MS;
/** What a session is stored under: SHA-256 of its id (192 random bits, so no slow hash is needed). */
export const sessionKey = (sid: string): string => createHash('sha256').update(sid).digest('hex');
/** The CSRF token, an HMAC keyed by the raw session id: only the holder of the cookie can compute it, nothing stores it,
 *  and it reveals nothing about the id. */
const csrfToken = (sid: string): string => createHmac('sha256', sid).update('qadamar/console-csrf/v1').digest('base64url');
const boundedSeconds = (value: number | undefined, fallback: number, name: string): number => {
  const result = value ?? fallback;
  if (!Number.isInteger(result) || result < 0 || result > 86_400) throw new Error(`${name} must be an integer in 0..86400`);
  return result;
};
export class Auth {
  private credentials: Credentials;
  private readonly sessions = new Map<string, Session>();
  private locks: Map<string, Lock>;
  private readonly lockStore: Backing<Array<[string, Lock]>>;
  private readonly limiter = new RateLimiter();
  private readonly audit: AuditLog;
  private readonly now: () => string;
  private readonly elapsed: () => number;
  private readonly dummyHash: string;
  private readonly credentialStore: Backing<Credentials>;
  private readonly bootstrapFile: string;
  private readonly rotationGraceSeconds: number;
  private readonly report: (message: string) => void;
  private readonly sealKey?: Buffer;
  private readonly loginKey: Buffer;
  private readonly previousSealKey?: Buffer;
  private readonly table?: SessionTable;
  private readonly production: boolean;
  /** sha256 of secrets already checked against a stored scrypt hash: a PEP pays scrypt once per secret, not per call. */
  private readonly verified = new Map<string, Buffer>();
  private bootstrapTimer?: NodeJS.Timeout;
  /** `elapsed` is real wall time in ms (Date.now): it drives the login throttle and the PEP rotation grace period, so a
   *  pinned business clock (CLOCK=fixed) can neither freeze the refill nor keep a rotated-out secret alive. */
  constructor(dir: string, audit: AuditLog, now: () => string, elapsed: () => number = () => Date.now(), options: AuthOptions = {}) {
    this.audit = audit; this.now = now; this.elapsed = elapsed;
    this.lockStore = options.lockouts ?? fileBacking(join(dir, 'lockouts.json'));
    this.credentialStore = options.credentials ?? fileBacking(join(dir, 'credentials.json'));
    this.bootstrapFile = join(dir, 'INITIAL-CREDENTIALS.txt');
    this.rotationGraceSeconds = boundedSeconds(options.pepRotationGraceSeconds, 300, 'PEP_ROTATION_GRACE_SECONDS');
    this.report = options.onBootstrapStatus ?? ((): void => undefined);
    this.sealKey = decodeSeal(options.signingKeySeal);
    this.previousSealKey = decodeSeal(options.signingKeySealPrevious, 'SIGNING_KEY_SEAL_PREVIOUS');
    // shortcut: without SIGNING_KEY_SEAL (demo only) the key lives per process, so unknown-login hashes correlate within one run
    this.loginKey = this.sealKey ? Buffer.from(hkdfSync('sha256', this.sealKey, Buffer.alloc(0), 'qadamar/unknown-login/hmac-sha256/v1', 32)) : randomBytes(32);
    this.table = options.sessions;
    this.production = options.production === true;
    const bootstrapTtl = boundedSeconds(options.initialCredentialsTtlSeconds, 3600, 'INITIAL_CREDENTIALS_TTL_SECONDS');
    if (bootstrapTtl === 0) throw new Error('INITIAL_CREDENTIALS_TTL_SECONDS must be greater than zero');
    this.locks = new Map(this.lockStore.load() ?? []);
    const stored = this.credentialStore.load();
    if (stored) {
      this.credentials = stored;
      if (this.credentials.pepHash) this.migrateBootstrapCredential();
      this.wrapLegacyPasswords();
    } else {
      const passwords: Record<string, string> = {};
      const accounts = Object.entries(roles).map(([id, role]) => {
        const password = randomSecret();
        passwords[id] = password;
        return { id, name: id, roles: role, hash: hashSecret(password) };
      });
      const pepApiKey = randomSecret();
      this.credentials = { users: accounts, pepCredentials: [{ id: 'bootstrap', name: 'bootstrap', created: now(), hash: hashMachineSecret(pepApiKey), previous: [] }] };
      writeFileSync(this.bootstrapFile, JSON.stringify({ passwords, pepApiKey }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
      this.credentialStore.save(this.credentials);
    }
    this.dummyHash = dummyPasswordHash();
    this.expireBootstrap(bootstrapTtl);
  }

  /** Rereads the shared credentials and lockouts a leader changed (cluster follower): a PEP credential rotated or revoked
   *  there holds here from the next reload. */
  reload(): void {
    const stored = this.credentialStore.load();
    if (stored) this.credentials = stored;
    this.locks = new Map(this.lockStore.load() ?? []);
  }

  private migrateBootstrapCredential(): void {
    const hash = this.credentials.pepHash!;
    this.credentials.pepCredentials = [{ id: 'bootstrap', name: 'bootstrap', created: this.now(), hash, previous: [] }];
    delete this.credentials.pepHash;
    this.credentialStore.save(this.credentials);
  }

  /** Dormant 0.8.3 accounts would otherwise answer in a quarter of the dummy's time until their next sign-in: an
   *  enumeration oracle. Wrapping needs no password, so every legacy hash is upgraded at start. */
  private wrapLegacyPasswords(): void {
    let wrapped = 0;
    for (const user of this.credentials.users) {
      const hash = wrapLegacyHash(user.hash);
      if (hash) { user.hash = hash; wrapped++; }
    }
    if (wrapped) this.credentialStore.save(this.credentials);
  }

  /** The lifetime counts from the file's creation, so restarts do not extend it. */
  private expireBootstrap(ttlSeconds: number): void {
    if (!existsSync(this.bootstrapFile)) return;
    const expires = statSync(this.bootstrapFile).mtimeMs + ttlSeconds * 1000;
    this.report(`Initial credentials file will be deleted after the first successful sign-in or at ${new Date(expires).toISOString()}`);
    this.bootstrapTimer = setTimeout(() => {
      try { this.removeBootstrap('configured expiry'); }
      catch { console.error('Could not delete the initial credentials file'); }
    }, Math.max(0, expires - Date.now()));
    this.bootstrapTimer.unref();
  }

  private removeBootstrap(reason: string): void {
    clearTimeout(this.bootstrapTimer);
    if (!existsSync(this.bootstrapFile)) return;
    rmSync(this.bootstrapFile);
    this.report(`Initial credentials file deleted after ${reason}`);
  }

  /** Local accounts without active TOTP (all seeded accounts when none exist yet): the production profile refuses them. */
  static accountsWithoutTotp(dir: string): string[] {
    const file = join(dir, 'credentials.json');
    return Auth.withoutTotp(existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) as Credentials : undefined);
  }
  /** `credentials` undefined: nothing stored yet, so the first start creates the demo accounts, none with TOTP. */
  static withoutTotp(credentials: Credentials | undefined): string[] {
    return credentials ? credentials.users.filter((u) => !u.totp?.active).map((u) => u.id) : Object.keys(roles);
  }

  /** `code`: the current TOTP code or an unused recovery code, required once TOTP is active. Every failure is the same
   *  401 and counts towards the throttle, so a correct password is never confirmed without its second factor.
   *  Throttle (CWE-307): five failures from one client address on one account lock that pair, progressively (1 min,
   *  doubling, 60 min at most). Failures from every address also count per account; that progressive delay holds only
   *  for a client that has itself failed on the account, so nobody can lock an owner out from elsewhere by spraying
   *  failures. Wrong second factors after the right password are the exception: five of them, from any addresses, lock
   *  the account's sign-in for every client, with the same delay; a correct sign-in clears that counter. Locks run on real elapsed time (`elapsed`), never on the business clock (CLOCK=fixed). */
  async login(username: unknown, password: unknown, ip: string, code?: unknown): Promise<{ sid: string; user: User; csrfToken: string }> {
    const normalized = typeof username === 'string' && username.length <= 256 ? username.trim().toLowerCase() : '';
    let account = this.credentials.users.find((u) => u.id === normalized);
    const id = account?.id ?? 'unknown';
    const at = this.elapsed();
    const key = `${id}:${ip}`;
    const accountKey = `account:${id}`;
    const mfaKey = `account-mfa:${id}`;
    let denial: string | undefined;
    let lockedSeconds = 0;
    for (const [k, lock] of this.locks) if (lock.until <= at && at - (lock.touched ?? 0) > 3600000) this.locks.delete(k);
    const sessionAt = this.elapsed();
    for (const [k, s] of this.sessions) if (expired(s, sessionAt)) this.sessions.delete(k);
    const wait = (): number => {
      const pair = this.locks.get(key); const whole = account ? this.locks.get(accountKey) : undefined;
      const mfa = account ? this.locks.get(mfaKey) : undefined;
      return Math.max(pair && at < pair.until ? pair.until - at : 0, pair && whole && at < whole.until ? whole.until - at : 0, mfa && at < mfa.until ? mfa.until - at : 0);
    };
    try {
      const locked = wait();
      if (locked > 0) throw new HttpError(429, 'rate_limited', 'Login temporarily locked', [Math.ceil(locked / 1000)]);
      this.limiter.take(`login:${key}`, at, 5);
      const pass = string(password);
      // the lock check and the throttle token above run before the await, so parallel guesses cannot all pass them
      const checked = account?.hash ?? this.dummyHash;
      let correct = await verifySecretAsync(pass, checked);
      // a reload during the hash may have replaced the credentials: decide on the live record, and only if its hash is the one checked
      account = this.credentials.users.find((u) => u.id === normalized);
      correct = correct && account?.hash === checked;
      const factor = account && correct ? this.secondFactor(account, code) : undefined;
      if (factor === false) denial = 'second_factor';
      if (!account || !correct || factor === false) {
        // a wrong second factor after the right password proves the password is known: that locks the account for every client
        for (const k of [key, ...(account ? [accountKey] : []), ...(denial === 'second_factor' ? [mfaKey] : [])]) {
          const failures = (this.locks.get(k)?.failures ?? 0) + 1;
          this.locks.delete(k);
          this.locks.set(k, { failures, touched: at, until: failures >= 5 ? at + Math.min(60, 2 ** Math.min(6, failures - 5)) * 60_000 : 0 });
        }
        while (this.locks.size > 10000) {
          // Account counters survive churn in source IPs until they expire.
          for (const k of this.locks.keys()) if (!k.startsWith('account:') && !k.startsWith('account-mfa:')) { this.locks.delete(k); break; }
        }
        this.lockStore.save([...this.locks]);
        lockedSeconds = Math.ceil(wait() / 1000);
        throw new HttpError(401, 'unauthenticated');
      }
      if (needsRehash(checked)) await this.rehash(normalized, checked, pass);
      // only this client's record: the account counter stays, so a success elsewhere does not reopen it to the failing clients
      this.locks.delete(key);
      this.locks.delete(mfaKey);
      this.lockStore.save([...this.locks]);
      return this.issue({ id: account.id, name: account.name, roles: account.roles }, 'password', undefined, factor === 'none' ? undefined : factor, ip);
    } catch (err) {
      if (!(err instanceof HttpError && err.status === 429)) {
        // a full scrypt queue (503) is audited as such: a spray shows up in the log, not as wrong passwords
        const reason = denial ?? (err instanceof HttpError && err.status === 503 ? 'busy' : undefined);
        this.audit.append({ type: 'session', actor: account || !normalized ? id : this.failedLoginActor(normalized), action: 'login', effect: 'deny',
          details: { method: 'password', ...(reason ? { reason } : {}), client: ip, ...(lockedSeconds > 0 ? { lockedSeconds } : {}) } });
      }
      throw err;
    }
  }

  /** Brings a hash checked at an older cost up to PASSWORD_COST, unless a reload replaced it meanwhile. */
  private async rehash(id: string, checked: string, password: string): Promise<void> {
    let upgraded: string;
    try { upgraded = await hashSecretAsync(password); } catch (err) {
      // the sign-in itself succeeded: keep the old hash, it is tried again next time
      console.error(`Password rehash failed for ${id}: ${err instanceof Error ? err.message : String(err)}`);
      return;
    }
    const live = this.credentials.users.find((u) => u.id === id);
    if (live?.hash !== checked) return;
    live.hash = upgraded;
    this.credentialStore.save(this.credentials);
  }

  /** The audit actor of a failed sign-in: an id that already has a subject mapping (pseudonymised as usual), otherwise
   *  a keyed hash, never a newly minted mapping (unknownLoginActor). */
  failedLoginActor(id: string): string {
    return this.audit.subjectPseudonym?.(id) === undefined ? unknownLoginActor(this.loginKey, id) : id;
  }

  /** 'none' without active TOTP, else the factor that passed, or false: missing, wrong, replayed or used code. */
  private secondFactor(account: Account, code: unknown): 'none' | 'totp' | 'recovery' | false {
    const totp = account.totp;
    if (!totp?.active) return 'none';
    // without the seal key the factor cannot be checked: the generic 401, never a status that confirms the password
    if (!this.sealKey || typeof code !== 'string' || code.length > 64) return false;
    const isTotp = /^\d{6}$/.test(code);
    if (isTotp) {
      const step = totpStep(this.totpKey(account), code, this.elapsed());
      // a code is good once: its step, or an earlier one, after a sign-in is a replay
      if (step === undefined || step <= (totp.lastStep ?? -Infinity)) return false;
      account.totp = { ...totp, lastStep: step };
    } else {
      const digest = recoveryDigest(code);
      const recovery = totp.recovery ?? [];
      if (!recovery.includes(digest)) return false;
      account.totp = { ...totp, recovery: recovery.filter((r) => r !== digest) };
      this.audit.append({ type: 'security', actor: account.id, action: 'totp_recovery_code_used', details: { remaining: recovery.length - 1 } });
    }
    this.credentialStore.save(this.credentials);
    return isTotp ? 'totp' : 'recovery';
  }

  private totpKey(account: Account): Buffer {
    // fail closed: an enrolled account whose seal key is gone cannot sign in
    if (!this.sealKey) throw new HttpError(503, 'unavailable', 'SIGNING_KEY_SEAL is required for TOTP');
    return fromBase32(unsealAny(account.totp!.secret, [this.sealKey, this.previousSealKey], `totp:${account.id}`));
  }

  private localAccount(req: IncomingMessage): Account {
    const session = this.sessions.get(sessionKey(this.sid(req)));
    const account = session?.method === 'password' ? this.credentials.users.find((u) => u.id === session.user.id) : undefined;
    if (!account) throw new HttpError(403, 'forbidden', 'TOTP applies to local password accounts');
    return account;
  }

  /** The signed-in local account's second factor: active, enrolment pending, and whether enrolment is possible here. */
  totpStatus(req: IncomingMessage): { active: boolean; pending: boolean; available: boolean } {
    const totp = this.localAccount(req).totp;
    return { active: Boolean(totp?.active), pending: Boolean(totp && !totp.active), available: Boolean(this.sealKey) };
  }

  /** Starts (or restarts) enrolment for the signed-in local account, after re-authentication with its current password
   *  (a stolen session alone cannot bind a second factor). The URI carries the secret: it is returned once. */
  async enrolTotp(req: IncomingMessage, password: unknown): Promise<{ otpauthUri: string }> {
    const active = (a: Account): void => { if (a.totp?.active) throw new HttpError(409, 'conflict', 'TOTP is already active for this account'); };
    let account = this.localAccount(req);
    active(account);
    if (!this.sealKey) throw new HttpError(409, 'conflict', 'SIGNING_KEY_SEAL must be set: TOTP secrets are stored sealed');
    this.limiter.take(`totp-enrol:${account.id}`, this.elapsed(), 5);
    const checked = account.hash;
    const correct = typeof password === 'string' && await verifySecretAsync(password, checked);
    // decide on the live record (a reload or an activation may have happened during the hash), as login does
    account = this.localAccount(req);
    active(account);
    if (!correct || account.hash !== checked) {
      this.audit.append({ type: 'security', actor: account.id, action: 'totp_enrol', effect: 'deny', details: { reason: 'reauthentication' } });
      throw new HttpError(403, 'forbidden', 'The current password is required');
    }
    const secret = newTotpSecret();
    account.totp = { secret: seal(secret, this.sealKey, `totp:${account.id}`), active: false };
    this.credentialStore.save(this.credentials);
    this.audit.append({ type: 'security', actor: account.id, action: 'totp_enrol' });
    return { otpauthUri: otpauthUri(account.id, secret) };
  }

  /** A first valid code activates TOTP; the recovery codes are returned this once, only their hashes are kept. */
  activateTotp(req: IncomingMessage, code: unknown): { recoveryCodes: string[] } {
    const account = this.localAccount(req);
    const totp = account.totp;
    if (!totp || totp.active) throw new HttpError(409, 'conflict', 'No TOTP enrolment in progress');
    const step = totpStep(this.totpKey(account), code, this.elapsed());
    if (step === undefined) throw new HttpError(422, 'unprocessable', 'The code does not match');
    const recoveryCodes = Array.from({ length: 10 }, newRecoveryCode);
    account.totp = { ...totp, active: true, lastStep: step, recovery: recoveryCodes.map(recoveryDigest) };
    this.credentialStore.save(this.credentials);
    this.audit.append({ type: 'security', actor: account.id, action: 'totp_activate', details: { recoveryCodes: recoveryCodes.length } });
    return { recoveryCodes };
  }

  /** Opens a console session for a user already authenticated (password here, or the identity provider). */
  /** `client`: the request's client address (TRUSTED_PROXIES), recorded in the audit. */
  issue(user: User, method: 'password' | 'oidc' | 'saml', oidc?: OidcSession, mfa?: 'totp' | 'recovery', client?: string): { sid: string; user: User; csrfToken: string } {
    this.removeBootstrap('first successful sign-in');
    // session idle and absolute limits run on real time: a pinned business clock (CLOCK=fixed) must not freeze them
    const at = this.elapsed();
    const sid = randomSecret(); const key = sessionKey(sid);
    const session: Session = { user, created: at, touched: at, method, ...(oidc ? { oidc } : {}) };
    this.sessions.set(key, session);
    this.table?.purge(at - IDLE_MS, at - ABSOLUTE_MS);
    this.table?.insert(key, session);
    this.audit.append({ type: 'session', actor: user.id, action: 'login', effect: 'allow', details: { method, ...(mfa ? { mfa } : {}), ...(client ? { client } : {}) } });
    return { sid, user, csrfToken: csrfToken(sid) };
  }

  /** PostgreSQL: reads the sessions the request's cookies name, before the synchronous checks below. Whatever another
   *  node or an earlier leader ended is gone from memory too. Files: nothing to do. */
  async load(req: IncomingMessage): Promise<void> {
    if (!this.table) return;
    const keys = [...new Set(this.cookieIds(req).map(sessionKey))];
    if (!keys.length) return;
    const found = new Map(await this.table.load(keys));
    for (const key of keys) {
      const stored = found.get(key);
      if (stored) this.sessions.set(key, stored); else this.sessions.delete(key);
    }
  }

  session(req: IncomingMessage, mutate: boolean): { user: User; csrfToken: string } {
    const sid = this.sid(req); const key = sessionKey(sid);
    const session = this.sessions.get(key);
    const at = this.elapsed();
    if (!sid || !session || expired(session, at)) {
      if (session) { this.sessions.delete(key); this.table?.remove(key); }
      throw new HttpError(401, 'unauthenticated');
    }
    const token = csrfToken(sid);
    if (mutate) this.csrf(req, token);
    if (!this.table || at - session.touched >= TOUCH_MS) {
      this.sessions.set(key, { ...session, touched: at });
      this.table?.touch(key, at);
    }
    return { user: session.user, csrfToken: token };
  }

  samlTarget(req: IncomingMessage): OidcSession | undefined {
    const session = this.sessions.get(sessionKey(this.sid(req)));
    return session?.method === 'saml' ? session.oidc : undefined;
  }

  csrf(req: IncomingMessage, token: string): void {
    if (!secureEqual(req.headers['x-csrf-token'], token)) throw new HttpError(403, 'forbidden', 'CSRF token required');
  }

  logout(req: IncomingMessage, actor: string): void {
    const key = sessionKey(this.sid(req));
    this.sessions.delete(key); this.table?.remove(key);
    this.audit.append({ type: 'session', actor, action: 'logout' });
  }

  /** The number of sessions ended; with PostgreSQL every node's, as stored (a promise). */
  endOidcSessions(target: { sub?: string; sid?: string }, method: 'oidc' | 'saml' = 'oidc'): number | Promise<number> {
    if (this.table) {
      return this.table.endOidc(target, method).then((keys) => {
        for (const key of keys) this.sessions.delete(key);
        return keys.length;
      });
    }
    let ended = 0;
    for (const [id, session] of this.sessions) {
      if (!session.oidc || session.method !== method) continue;
      // a session opened without an IdP sid can only be matched by sub: ending it is the fail-closed choice
      const matches = target.sid && session.oidc.sid
        ? session.oidc.sid === target.sid && (!target.sub || session.oidc.sub === target.sub)
        : session.oidc.sub === target.sub;
      if (matches) { this.sessions.delete(id); ended++; }
    }
    return ended;
  }

  /** The local console accounts holding `role` (sign-in through an IdP has no list: its roles come with each sign-in). */
  holders(role: string): string[] { return this.credentials.users.filter((u) => u.roles.includes(role)).map((u) => u.id); }
  pepCredentials(): PepCredentialView[] {
    return this.credentials.pepCredentials.map(publicCredential);
  }

  createPepCredential(nameInput: unknown, actor: string, subjectTypesInput?: unknown, subjectSearchInput?: unknown, resourceTypesInput?: unknown, contextScopesInput?: unknown): { credential: PepCredentialView; secret: string } {
    const name = credentialName(nameInput);
    const subjectTypes = subjectTypesInput === undefined ? undefined : populations(subjectTypesInput);
    const resourceTypes = resourceTypesInput === undefined ? undefined : populations(resourceTypesInput, 'resourceTypes', 'resource');
    const contextScopes = contextClaimScopes(contextScopesInput, this.production);
    if (subjectSearchInput !== undefined && typeof subjectSearchInput !== 'boolean') throw new HttpError(400, 'bad_request', 'allowSubjectSearch must be a boolean');
    if (subjectSearchInput === true && this.production) throw new HttpError(400, 'bad_request', 'allowSubjectSearch must be false in the production profile');
    const allowSubjectSearch = this.production ? false : subjectSearchInput ?? true;
    if (this.credentials.pepCredentials.some((c) => c.name === name && !c.revoked)) throw new HttpError(409, 'conflict', 'Credential name already exists');
    const id = randomUUID();
    const secret = `pep.${id}.${randomSecret()}`;
    const credential: PepCredential = { id, name, created: this.now(), hash: hashMachineSecret(secret), previous: [], ...(subjectTypes ? { subjectTypes } : {}), allowSubjectSearch,
      ...(resourceTypes ? { resourceTypes } : {}), ...(contextScopes ? { contextScopes } : {}), issuedBy: actor };
    this.credentials.pepCredentials.push(credential);
    this.credentialStore.save(this.credentials);
    this.audit.append({ type: 'security', actor, action: 'pep_credential_create', details: { credentialId: id, name, ...(subjectTypes ? { subjectTypes } : {}), allowSubjectSearch, ...(resourceTypes ? { resourceTypes } : {}), ...(contextScopes ? { contextScopes } : {}) } });
    return { credential: publicCredential(credential), secret };
  }

  rotatePepCredential(id: string, actor: string): { credential: PepCredentialView; secret: string } {
    const credential = this.credentials.pepCredentials.find((c) => c.id === id);
    if (!credential) throw new HttpError(404, 'not_found');
    if (credential.revoked) throw new HttpError(409, 'conflict', 'Credential is revoked');
    const real = this.elapsed();
    const kept = credential.previous.filter((p) => Date.parse(p.validUntil) > real);
    this.forget(credential.previous.filter((p) => !kept.includes(p)).map((p) => p.hash));
    credential.previous = [...kept, { hash: credential.hash, validUntil: new Date(real + this.rotationGraceSeconds * 1000).toISOString(),
      ...(credential.issuedBy ? { issuedBy: credential.issuedBy } : {}) }];
    const secret = `pep.${credential.id}.${randomSecret()}`;
    credential.hash = hashMachineSecret(secret); credential.rotated = this.now(); credential.issuedBy = actor;
    this.credentialStore.save(this.credentials);
    this.audit.append({ type: 'security', actor, action: 'pep_credential_rotate', details: { credentialId: id, previousValidUntil: credential.previous.at(-1)!.validUntil } });
    return { credential: publicCredential(credential), secret };
  }

  revokePepCredential(id: string, actor: string): PepCredentialView {
    const credential = this.credentials.pepCredentials.find((c) => c.id === id);
    if (!credential) throw new HttpError(404, 'not_found');
    if (credential.revoked) throw new HttpError(409, 'conflict', 'Credential is already revoked');
    credential.revoked = this.now();
    this.forget([credential.hash, ...credential.previous.map((p) => p.hash)]);
    this.credentialStore.save(this.credentials);
    this.audit.append({ type: 'security', actor, action: 'pep_credential_revoke', details: { credentialId: id, name: credential.name } });
    return publicCredential(credential);
  }

  pep(req: IncomingMessage): string { return this.pepCaller(req).actor; }

  /** pepCaller for the router: a 0.8.3 scrypt hash is checked on the thread pool first (its digest cached on success),
   *  so a wrong key never runs a synchronous scrypt on the event loop. */
  async pepCallerAsync(req: IncomingMessage): Promise<PepCaller> {
    const authorization = req.headers.authorization ?? '';
    const secret = authorization.slice(7);
    const id = authorization.startsWith('Bearer ') && authorization.length <= 263 ? /^pep\.([0-9a-f-]{36})\./.exec(secret)?.[1] ?? 'bootstrap' : undefined;
    const credential = id === undefined ? undefined : this.credentials.pepCredentials.find((c) => c.id === id);
    if (credential && !credential.revoked) {
      const real = this.elapsed();
      const digest = createHash('sha256').update(secret).digest();
      for (const hash of [credential.hash, ...credential.previous.filter((p) => Date.parse(p.validUntil) > real).map((p) => p.hash)]) {
        if (needsRehash(hash, true) && !this.verified.has(hash) && await verifySecretAsync(secret, hash)) this.verified.set(hash, digest);
      }
    }
    return this.pepCaller(req, true);
  }

  /** `legacyChecked`: pepCallerAsync already tried the scrypt hashes, so an uncached one is a mismatch here. */
  pepCaller(req: IncomingMessage, legacyChecked = false): PepCaller {
    const authorization = req.headers.authorization ?? '';
    if (!authorization.startsWith('Bearer ') || authorization.length > 263) throw new HttpError(401, 'unauthenticated');
    const secret = authorization.slice(7);
    const id = /^pep\.([0-9a-f-]{36})\./.exec(secret)?.[1];
    const candidates = id ? this.credentials.pepCredentials.filter((c) => c.id === id)
      : this.credentials.pepCredentials.filter((c) => c.id === 'bootstrap');
    const credential = candidates[0];
    if (!credential || credential.revoked) throw new HttpError(401, 'unauthenticated');
    const at = Date.parse(this.now());
    const real = this.elapsed();
    const validPrevious = credential.previous.filter((p) => Date.parse(p.validUntil) > real);
    const digest = createHash('sha256').update(secret).digest();
    const current = this.matches(secret, digest, credential.hash, legacyChecked);
    const previous = current ? undefined : validPrevious.find((p) => this.matches(secret, digest, p.hash, legacyChecked));
    const valid = current || previous !== undefined;
    if (!valid) throw new HttpError(401, 'unauthenticated');
    const stale = !credential.lastUsed || at - Date.parse(credential.lastUsed) >= 60_000;
    const rehash = current && needsRehash(credential.hash, true);
    if (rehash) {
      // a 0.8.3 scrypt hash becomes an HMAC: from then on a wrong key costs microseconds, not a scrypt on the event loop
      this.forget([credential.hash]);
      credential.hash = hashMachineSecret(secret);
      this.verified.set(credential.hash, digest);
    }
    if (validPrevious.length !== credential.previous.length || stale || rehash) {
      // last use is kept to the minute: one disk write per credential per minute, not per decision
      this.forget(credential.previous.filter((p) => !validPrevious.includes(p)).map((p) => p.hash));
      credential.previous = validPrevious; credential.lastUsed = this.now();
      this.credentialStore.save(this.credentials);
    }
    const issuedBy = previous ? previous.issuedBy : credential.issuedBy ?? (credential.id === 'bootstrap' ? 'bootstrap' : undefined);
    return { actor: `pep:${createHash('sha256').update(`${credential.id}:${secret}`).digest('hex')}`, credential: credential.id, subjectTypes: credential.subjectTypes ?? [],
      allowSubjectSearch: !this.production && credential.allowSubjectSearch !== false, resourceTypes: credential.resourceTypes ?? [], ...(issuedBy ? { issuedBy } : {}),
      contextScopes: credential.contextScopes ?? (this.production ? [] : undefined) };
  }

  private forget(hashes: readonly string[]): void {
    for (const hash of hashes) this.verified.delete(hash);
  }

  private matches(secret: string, digest: Buffer, hash: string, legacyChecked = false): boolean {
    const known = this.verified.get(hash);
    if (known) return timingSafeEqual(known, digest);
    if (legacyChecked && needsRehash(hash, true)) return false;
    if (!verifySecret(secret, hash)) return false;
    this.verified.set(hash, digest);
    return true;
  }

  /** At most 8 sid cookies are considered: a request cannot make the PostgreSQL lookup arbitrarily wide. */
  private cookieIds(req: IncomingMessage): string[] {
    return [...(req.headers.cookie ?? '').matchAll(/(?:^|;\s*)sid=([^;]{1,256})/g)].slice(0, 8).map((m) => m[1]!);
  }

  /** The raw id of the first live session the cookies name, or ''. */
  private sid(req: IncomingMessage): string {
    const at = this.elapsed();
    return this.cookieIds(req).find((id) => { const s = this.sessions.get(sessionKey(id)); return s && !expired(s, at); }) ?? '';
  }
}

function publicCredential(credential: PepCredential): PepCredentialView {
  const { hash: current, previous, ...view } = credential;
  const validUntil = previous.map((p) => Date.parse(p.validUntil)).filter(Number.isFinite).sort((a, b) => b - a)[0];
  return { ...view, ...(validUntil === undefined ? {} : { previousValidUntil: new Date(validUntil).toISOString() }) };
}
function populations(input: unknown, field = 'subjectTypes', kind = 'subject'): string[] {
  if (!Array.isArray(input) || input.length === 0 || input.length > 16 || !input.every((t) => typeof t === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(t))) {
    throw new HttpError(400, 'bad_request', `${field} must list 1..16 ${kind} types`);
  }
  return [...new Set(input as string[])];
}
function credentialName(input: unknown): string {
  const name = string(input).trim();
  if (name.length < 1 || name.length > 80 || /[\u0000-\u001f\u007f]/.test(name)) throw new HttpError(400, 'bad_request', 'Credential name must be 1..80 printable characters');
  return name;
}
function secureEqual(input: unknown, expected: string): boolean {
  if (typeof input !== 'string') return false;
  const a = Buffer.from(input), b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}
