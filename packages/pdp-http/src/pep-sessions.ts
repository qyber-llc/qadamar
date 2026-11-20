// PDP-issued BLP sessions. A token authenticates the PDP-chosen sid, subject and PEP credential; the open-session row
// proves it has not been closed or revoked and carries the real-clock last use for idle expiry. All tokens of one (PEP, subject)
// share a mark scope, so opening or closing another session cannot lower the *-property floor.
import { randomUUID } from 'node:crypto';
import { canonical } from '../../core/src/index.ts';
import type { Ref } from '../../core/src/index.ts';
import type { AuditLog } from './audit.ts';
import { HttpError, object, string } from './http.ts';
import type { Backing } from './store.ts';
import { MARK_TOUCH_MS, TOKEN_SCOPE, scopeSession, type Sessions } from './sessions.ts';
import { MAX_SESSION_TOKEN_CHARS, type SessionTokenClaims, type Tokens } from './tokens.ts';

export const SESSION_IDLE_SECONDS = 15 * 60;
export const DEFAULT_SESSIONS_PER_SUBJECT = 4;
const MAX_SESSIONS_PER_SUBJECT = 1000;
/** BLP_SESSIONS_PER_CREDENTIAL default: open sessions of one PEP credential over all its subjects, so distinct subject
 *  ids cannot each take a per-subject share; the same as the marks it may hold (sessions.ts DEFAULT_SESSIONS_PER_PEP). */
export const DEFAULT_SESSIONS_PER_CREDENTIAL = 10_000;
const MAX_SESSIONS_PER_CREDENTIAL = 100_000;
/** A decision's subject type and id: 1..256 characters (core request.ts), so no session names a subject no decision can. */
const MAX_SUBJECT_FIELD = 256;

export interface StoredPepSession { sid: string; claims: SessionTokenClaims; seen: number }
export interface SessionRevocation { sid: string; sub: string; pep: string; revokedAt: string }
export interface SessionRevocationTarget { sessionId?: string; subject?: Ref; credential?: string }
export interface RevokedSessions { revoked: number; sessionIds: string[] }
export interface PepSessionLoader {
  load(sids: readonly string[]): Promise<StoredPepSession[]>;
  touch(sid: string, seen: number): Promise<void>;
  /** Holds the live mark of `subject` in token scope `session` until `until` (gate_blp_mark), in the caller's transaction. */
  hold(session: string, subject: string, until: number): Promise<void>;
}
export interface PepSessionTransaction extends PepSessionLoader {
  /** Live sessions of `pep` for `subject`, or over all its subjects when `subject` is undefined. */
  count(pep: string, subject?: string): Promise<number>;
  insert(row: StoredPepSession): Promise<void>;
  remove(sid: string): Promise<boolean>;
  /** Candidate sids and selector scopes are locked together in sorted order, then candidates revalidated. */
  revoke(target: SessionRevocationTarget, selectorLocks: readonly string[]): Promise<StoredPepSession[]>;
  purge(now: number): Promise<void>;
}
export interface PepSessionTable {
  /** The locks are the token sid and/or subject mark scope, shared with mark-relevant decisions. */
  transaction<T>(locks: readonly string[], task: (tx: PepSessionTransaction) => Promise<T>): Promise<T>;
}
export interface OpenedSession { token: string; sessionId: string; issuedAt: string; expiresAt: string; idleSeconds: number }
export type SessionBindings = ReadonlyMap<string, SessionTokenClaims>;

const subjectKey = (s: Ref): string => JSON.stringify([s.type, s.id]);
/** TOKEN_SCOPE marks the scope apart from a hashed legacy id (base64url never contains ':'), so no raw id can name it. */
export const subjectSessionScope = (pep: string, subject: Ref): string => `${TOKEN_SCOPE}${scopeSession(pep, `subject:${subjectKey(subject)}`)}`;
/** Serialises a credential's opens over all its subjects (its aggregate cap); only open takes it. */
const credentialScope = (pep: string): string => `${TOKEN_SCOPE}${scopeSession(pep, 'credential')}`;
const invalid = (): HttpError => new HttpError(403, 'invalid_session_token', 'Session token is invalid, expired, closed, or not bound to this request');
const sessionRef = (claims: SessionTokenClaims): Ref => {
  try {
    const pair: unknown = JSON.parse(claims.sub);
    if (!Array.isArray(pair) || pair.length !== 2 || pair.some((v) => typeof v !== 'string' || !v)) throw new Error();
    return { type: pair[0] as string, id: pair[1] as string };
  } catch { throw invalid(); }
};

/** The unverified claims only select queues and database locks; prepare() authenticates them before a decision. */
export function sessionTokenLocks(token: string, pep: string): string[] {
  try {
    const claims = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString()) as Partial<SessionTokenClaims>;
    if (typeof claims.sid !== 'string' || typeof claims.sub !== 'string') return [];
    return [claims.sid, subjectSessionScope(pep, sessionRef(claims as SessionTokenClaims))];
  } catch { return []; }
}

/** Every session token in AuthZEN contexts or XACML environment attributes, however deeply a batch nests them. */
export function sessionTokensIn(body: unknown): string[] {
  const out = new Set<string>();
  const walk = (value: unknown, depth: number): void => {
    if (depth > 8 || value === null || typeof value !== 'object') return;
    if (Array.isArray(value)) { for (const item of value) walk(item, depth + 1); return; }
    const o = value as Record<string, unknown>;
    if (typeof o.sessionToken === 'string') out.add(o.sessionToken);
    if (o.AttributeId === 'urn:qadamar:1.0:environment:session-token') {
      for (const item of [o.Value].flat()) if (typeof item === 'string') out.add(item);
    }
    for (const item of Object.values(o)) walk(item, depth + 1);
  };
  walk(body, 0);
  return [...out];
}

export function sessionsPerSubjectFromEnv(value: string | undefined): number | undefined {
  if (value === undefined || value === '') return undefined;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > MAX_SESSIONS_PER_SUBJECT) throw new Error(`BLP_SESSIONS_PER_SUBJECT must be an integer in 1..${MAX_SESSIONS_PER_SUBJECT}`);
  return n;
}
export function sessionsPerCredentialFromEnv(value: string | undefined): number | undefined {
  if (value === undefined || value === '') return undefined;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > MAX_SESSIONS_PER_CREDENTIAL) throw new Error(`BLP_SESSIONS_PER_CREDENTIAL must be an integer in 1..${MAX_SESSIONS_PER_CREDENTIAL}`);
  return n;
}

export class PepSessions {
  private readonly rows = new Map<string, StoredPepSession>();
  private readonly tokens: Tokens;
  private readonly marks: Sessions;
  private readonly audit: AuditLog;
  private readonly now: () => string;
  private readonly elapsed: () => number;
  private readonly backing?: Backing<StoredPepSession[]>;
  private readonly table?: PepSessionTable;
  private readonly cap: number;
  private readonly perCredential: number;
  private readonly revocationStore?: Backing<SessionRevocation[]>;
  private revoked = new Map<string, SessionRevocation>();

  constructor(tokens: Tokens, marks: Sessions, audit: AuditLog, now: () => string, elapsed: () => number = Date.now,
    backing?: Backing<StoredPepSession[]>, table?: PepSessionTable, cap = DEFAULT_SESSIONS_PER_SUBJECT, perCredential = DEFAULT_SESSIONS_PER_CREDENTIAL,
    revocationStore?: Backing<SessionRevocation[]>) {
    if (!Number.isInteger(cap) || cap < 1 || cap > MAX_SESSIONS_PER_SUBJECT) throw new Error(`BLP_SESSIONS_PER_SUBJECT must be an integer in 1..${MAX_SESSIONS_PER_SUBJECT}`);
    if (!Number.isInteger(perCredential) || perCredential < 1 || perCredential > MAX_SESSIONS_PER_CREDENTIAL) throw new Error(`BLP_SESSIONS_PER_CREDENTIAL must be an integer in 1..${MAX_SESSIONS_PER_CREDENTIAL}`);
    this.tokens = tokens; this.marks = marks; this.audit = audit; this.now = now; this.elapsed = elapsed; this.backing = backing; this.table = table; this.cap = cap;
    this.perCredential = perCredential; this.revocationStore = revocationStore;
    for (const row of backing?.load() ?? []) this.rows.set(row.sid, row);
    this.reload();
  }

  /** A cluster reload or replica feed replaces the shared tombstones; live rows are always read from their own store. */
  reload(): void { this.revoked = new Map((this.revocationStore?.load() ?? []).map((row) => [row.sid, row])); }
  revocations(): SessionRevocation[] { return [...this.revoked.values()]; }

  async open(input: unknown, credential: string, actor: string): Promise<OpenedSession> {
    const value = object(input); const raw = object(value.subject);
    const subject = { type: string(raw.type), id: string(raw.id) };
    if (subject.type.length > MAX_SUBJECT_FIELD || subject.id.length > MAX_SUBJECT_FIELD) throw new HttpError(400, 'bad_request', `subject.type and subject.id must be 1..${MAX_SUBJECT_FIELD} characters`);
    const scope = subjectSessionScope(credential, subject);
    const run = async (tx?: PepSessionTransaction): Promise<OpenedSession> => {
      const now = this.elapsed();
      if (tx) await tx.purge(now); else this.purge(now);
      const own = (row: StoredPepSession): boolean => row.claims.pep === credential;
      const count = tx ? await tx.count(credential, subjectKey(subject)) : [...this.rows.values()].filter((row) => own(row) && row.claims.sub === subjectKey(subject)).length;
      if (count >= this.cap) {
        this.record(actor, 'blp_session_open', 'deny', subject.id, credential, { reason: 'subject_session_cap', cap: this.cap });
        throw new HttpError(409, 'session_limit', 'Too many concurrently open sessions for this subject and PEP credential');
      }
      const total = tx ? await tx.count(credential) : [...this.rows.values()].filter(own).length;
      if (total >= this.perCredential) {
        this.record(actor, 'blp_session_open', 'deny', subject.id, credential, { reason: 'credential_session_cap', cap: this.perCredential });
        throw new HttpError(409, 'session_limit', 'Too many concurrently open sessions for this PEP credential');
      }
      const sid = randomUUID();
      const token = this.tokens.issueSession({ sid, sub: subjectKey(subject), pep: credential, idle: SESSION_IDLE_SECONDS });
      // a token decisions would refuse is never handed out (the subject bounds keep it far below; this is the backstop)
      if (token.length > MAX_SESSION_TOKEN_CHARS) throw new HttpError(400, 'bad_request', 'Session token would exceed the decision limit');
      const claims = this.tokens.verifySession(token);
      const row = { sid, claims, seen: now };
      if (tx) await tx.insert(row); else { this.rows.set(sid, row); this.backing?.save([...this.rows.values()]); }
      await this.hold(claims, now, tx);
      this.record(actor, 'blp_session_open', 'allow', subject.id, credential, { sessionId: sid, cap: this.cap });
      return { token, sessionId: sid, issuedAt: new Date(claims.iat * 1000).toISOString(), expiresAt: new Date(claims.exp * 1000).toISOString(), idleSeconds: claims.idle };
    };
    const locks = [scope, credentialScope(credential)];
    return this.table ? this.table.transaction(locks, run) : this.marks.serial(locks, () => run());
  }

  async close(tokenInput: unknown, credential: string, actor: string): Promise<{ ok: true }> {
    const token = string(tokenInput); const claims = this.tokens.verifySession(token);
    if (claims.pep !== credential) throw invalid();
    const subject = sessionRef(claims); const scope = subjectSessionScope(credential, subject);
    const run = async (tx?: PepSessionTransaction): Promise<{ ok: true }> => {
      const row = tx ? (await tx.load([claims.sid]))[0] : this.rows.get(claims.sid);
      if (!row || canonical(row.claims) !== canonical(claims)) {
        this.record(actor, 'blp_session_close', 'deny', subject.id, credential, { reason: 'unknown_session' });
        throw invalid();
      }
      if (tx) await tx.remove(claims.sid); else { this.rows.delete(claims.sid); this.backing?.save([...this.rows.values()]); }
      this.record(actor, 'blp_session_close', 'allow', subject.id, credential, { sessionId: claims.sid });
      return { ok: true };
    };
    return this.table ? this.table.transaction([claims.sid, scope], run) : this.marks.serial([claims.sid, scope], () => run());
  }

  async revoke(input: unknown, actor: string): Promise<RevokedSessions> {
    const value = object(input);
    if (Object.keys(value).some((key) => !['sessionId', 'subject', 'credential'].includes(key))) throw new HttpError(400, 'bad_request', 'Revoke by sessionId, subject (optionally narrowed by credential), or credential');
    const sessionId = value.sessionId === undefined ? undefined : string(value.sessionId);
    if (sessionId !== undefined && !/^[0-9a-f-]{36}$/.test(sessionId)) throw new HttpError(400, 'bad_request', 'sessionId must be a PDP-issued session id');
    const credential = value.credential === undefined ? undefined : string(value.credential);
    if (credential !== undefined && !/^[A-Za-z0-9_.-]{1,64}$/.test(credential)) throw new HttpError(400, 'bad_request', 'credential must be a PEP credential id');
    const raw = value.subject === undefined ? undefined : object(value.subject);
    const subject = raw === undefined ? undefined : { type: string(raw.type), id: string(raw.id) };
    if (subject && (subject.type.length > MAX_SUBJECT_FIELD || subject.id.length > MAX_SUBJECT_FIELD)) throw new HttpError(400, 'bad_request', `subject.type and subject.id must be 1..${MAX_SUBJECT_FIELD} characters`);
    if ((sessionId === undefined && subject === undefined && credential === undefined) || (sessionId !== undefined && (subject !== undefined || credential !== undefined))) {
      throw new HttpError(400, 'bad_request', 'Send exactly one of sessionId, subject (with optional credential), or credential');
    }
    const target: SessionRevocationTarget = { ...(sessionId ? { sessionId } : {}), ...(subject ? { subject } : {}), ...(credential ? { credential } : {}) };
    const matches = (row: StoredPepSession): boolean => sessionId !== undefined ? row.sid === sessionId
      : (credential === undefined || row.claims.pep === credential) && (subject === undefined || row.claims.sub === subjectKey(subject));
    const locks = sessionId ? [sessionId] : credential ? [credentialScope(credential), ...(subject ? [subjectSessionScope(credential, subject)] : [])] : [];
    const run = async (tx?: PepSessionTransaction): Promise<RevokedSessions> => {
      const rows = tx ? await tx.revoke(target, locks) : [...this.rows.values()].filter(matches);
      if (!tx) for (const row of rows) this.rows.delete(row.sid);
      const revokedAt = this.now();
      for (const row of rows) this.revoked.set(row.sid, { sid: row.sid, sub: row.claims.sub, pep: row.claims.pep, revokedAt });
      const cutoff = Date.parse(revokedAt) - 2 * 3_600_000;
      const kept = [...this.revoked.values()].filter((row) => Date.parse(row.revokedAt) >= cutoff);
      if (kept.length > 100_000) throw new HttpError(409, 'conflict', 'Session revocation list is full');
      this.revoked = new Map(kept.map((row) => [row.sid, row]));
      // Tombstones first in file mode: a crash can never bring a revoked live row back without its denial.
      this.revocationStore?.save(kept);
      if (!tx) this.backing?.save([...this.rows.values()]);
      this.audit.append({ type: 'session', actor, action: 'blp_session_revoke', effect: 'allow',
        ...(subject ? { subject: subject.id } : {}), details: { ...(sessionId ? { sessionId } : {}), ...(credential ? { credentialId: credential } : {}), ...(subject ? { subjectType: subject.type } : {}), revoked: rows.length } });
      return { revoked: rows.length, sessionIds: rows.slice(0, 100).map((row) => row.sid) };
    };
    return this.table ? this.table.transaction([], run) : this.marks.serial(locks, () => run());
  }

  /** Runs inside the decision's session locks and PostgreSQL transaction. The returned bindings are request-local. */
  async prepare(tokens: readonly string[], credential: string, loader?: PepSessionLoader): Promise<SessionBindings> {
    const verified = tokens.map((token) => this.tokens.verifySession(token));
    if (verified.some((claims) => claims.pep !== credential || this.revoked.has(claims.sid))) throw invalid();
    const stored = loader ? await loader.load(verified.map((claims) => claims.sid))
      : verified.map((claims) => this.rows.get(claims.sid)).filter((row) => row !== undefined);
    const rows = new Map(stored.map((row) => [row.sid, row]));
    const at = Math.floor(Date.parse(this.now()) / 1000); const elapsed = this.elapsed();
    for (const claims of verified) {
      const row = rows.get(claims.sid);
      if (!row || canonical(row.claims) !== canonical(claims) || claims.iat > at || claims.exp <= at || elapsed - row.seen >= claims.idle * 1000) throw invalid();
      sessionRef(claims);
      if (elapsed - row.seen >= MARK_TOUCH_MS) {
        if (loader) await loader.touch(claims.sid, elapsed);
        else { row.seen = elapsed; this.backing?.save([...this.rows.values()]); }
        await this.hold(claims, elapsed, loader);
      }
    }
    return new Map(tokens.map((token, i) => [token, verified[i]!]));
  }

  binding(token: string, subject: Ref, bindings: SessionBindings | undefined): { claims: SessionTokenClaims; scope: string } {
    const claims = bindings?.get(token);
    if (!claims || canonical(sessionRef(claims)) !== canonical(subject)) throw invalid();
    return { claims, scope: subjectSessionScope(claims.pep, subject) };
  }

  /** A decision token minted in BLP session `sid` stays consumable only while that session is open and live, for the
   *  same subject and PEP credential. `stored`: the row the consuming PostgreSQL transaction loaded under its lock. */
  usable(sid: string, sub: string, credential: string | undefined, stored?: StoredPepSession): boolean {
    const row = this.table ? stored : this.rows.get(sid);
    return !this.revoked.has(sid) && row !== undefined && row.sid === sid && row.claims.sid === sid && row.claims.sub === sub && row.claims.pep === credential && this.live(row, this.elapsed());
  }

  /** The token was used (its last use recorded) at `elapsed`: the shared mark it refers to must stay live as long as the
   *  token can still be used, its idle or absolute expiry whichever is first, plus one touch interval of grace. Without
   *  this the mark could lapse on its own schedule first and reset the *-property floor under a valid token. */
  private async hold(claims: SessionTokenClaims, elapsed: number, loader?: PepSessionLoader): Promise<void> {
    const at = Math.floor(Date.parse(this.now()) / 1000);
    const until = elapsed + Math.min((claims.exp - at) * 1000, claims.idle * 1000) + MARK_TOUCH_MS;
    const subject = sessionRef(claims); const scope = subjectSessionScope(claims.pep, subject);
    this.marks.hold(scope, subject, until);
    if (loader) await loader.hold(scope, subjectKey(subject), until);
  }

  private live(row: StoredPepSession, now: number): boolean {
    const at = Math.floor(Date.parse(this.now()) / 1000);
    return row.claims.iat <= at && row.claims.exp > at && now - row.seen < row.claims.idle * 1000;
  }
  private purge(now: number): void {
    for (const [sid, row] of this.rows) if (!this.live(row, now)) this.rows.delete(sid);
    this.backing?.save([...this.rows.values()]);
  }
  private record(actor: string, action: string, effect: 'allow' | 'deny', subject: string, credential: string, details: Record<string, unknown>): void {
    this.audit.append({ type: 'session', actor, action, effect, subject, details: { credentialId: credential, ...details } });
  }
}
