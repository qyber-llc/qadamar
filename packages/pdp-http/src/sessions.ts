// The Bell-LaPadula high-water mark of a working session (docs/API.md §2). A verified PDP token maps to a shared
// (credential, subject) scope; a legacy raw id maps to its own (credential, id) scope in demo compatibility mode.
// The highest permitted point read bounds later writes (core mandatory.ts: BLP.HIGH_WATER), however requests are split.
// Related decisions are linearizable through local queues and, with a database, their advisory locks. The mark only
// rises and lapses after 15 min idle or 8 h absolute on the real clock, never while an open token of its scope can still
// be used (Mark.hold): close/reopen cannot clear it.
// Kept in memory; in DATA_DIR/sessions.json without a database; in gate_blp_mark with one, shared by every node.
import { createHash } from 'node:crypto';
import type { Level } from '../../core/src/index.ts';
import type { Backing } from './store.ts';
import type { PepSessionLoader } from './pep-sessions.ts';

export const SESSION_IDLE_MS = 15 * 60_000;
export const SESSION_ABSOLUTE_MS = 8 * 3600_000;
/** An expired legacy session's mark is kept as a tombstone until SESSION_TOMBSTONE_MS after its start (absolute expiry
 *  plus a grace period): every node keeps answering CBAC.SESSION_EXPIRED and none writes a fresh mark under that id.
 *  Token scopes have none: their token is the session, and a lapsed shared mark makes room for a new one. */
export const SESSION_TOMBSTONE_MS = SESSION_ABSOLUTE_MS + SESSION_IDLE_MS;
/** Marks held in memory. Without a database a full table refuses new marks (the read is denied, BLP.SESSION_LIMIT);
 *  with one, memory is a cache of gate_blp_mark and the oldest entry makes room. */
export const MAX_SESSIONS = 100_000;
/** BLP_SESSIONS_PER_PEP default: the marks one PEP credential may hold, so a credential minting session ids exhausts
 *  its own share and not every other PEP's (MAX_SESSIONS stays the bound over all of them). */
export const DEFAULT_SESSIONS_PER_PEP = 10_000;
/** A use of a session is written (last use, gate_blp_mark) at most this often; idle expiry may come up to this early. */
export const MARK_TOUCH_MS = 60_000;
/** Without a database, raised marks reach DATA_DIR/sessions.json within this delay (one write per batch, not per raise);
 *  a crash loses only the marks raised in the last SAVE_DELAY_MS. close() (server.close) writes at once. */
export const SAVE_DELAY_MS = 1000;
/** context.sessionId: 1..128 printable ASCII characters, opaque to the PDP (send an id, not the session cookie). */
export const SESSION_ID = /^[\x21-\x7e]{1,128}$/;
/** The XACML environment attribute carrying context.sessionId. */
export const SESSION_ATTRIBUTE = 'urn:qadamar:1.0:environment:session-id';

/** BLP_SESSIONS_PER_PEP: an integer in 1..MAX_SESSIONS, or the default when unset. */
export function sessionsPerPepFromEnv(value: string | undefined): number | undefined {
  if (value === undefined || value === '') return undefined;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > MAX_SESSIONS) throw new Error(`BLP_SESSIONS_PER_PEP must be an integer in 1..${MAX_SESSIONS}`);
  return n;
}

/** `hold`: the real-clock instant until which an open PDP session token may still use this scope (pep-sessions.ts): the
 *  mark stays live until then whatever its own idle and absolute expiry, so it never lapses under a usable token. */
export interface Mark { readonly level: Level; readonly started: number; readonly seen: number; readonly hold?: number }
export interface StoredMark { readonly session: string; readonly subject: string; readonly mark: Mark }
export type MarkLoader = (sessions: readonly string[]) => Promise<StoredMark[]>;
/** PostgreSQL (gate_blp_mark): staged with the request, committed before it is answered; loaded before a decision. */
export interface MarkTable {
  stage(row: StoredMark): void;
  load: MarkLoader;
  /** Takes the session locks, supplies loaders on their transaction's connection, and commits before releasing them. */
  decision?<T>(sessions: readonly string[], task: (load: MarkLoader, pepSessions: PepSessionLoader) => Promise<T>): Promise<T>;
}
/** DATA_DIR/sessions.json: [key, mark, PEP credential] (files of 0.4.x betas lack the credential: counted as ''). */
export type MarkFile = Array<[string, Mark, string?]>;
type Ref = { readonly type: string; readonly id: string };

/** The server-side session: the PEP credential and its session id, hashed (the raw id is neither stored nor logged). */
/** Prefix of the (PEP credential, subject) mark scope shared by every PDP-issued session token (pep-sessions.ts). */
export const TOKEN_SCOPE = 'pdp:';
export const scopeSession = (pep: string | undefined, id: string): string =>
  createHash('sha256').update(JSON.stringify([pep ?? '', id])).digest('base64url');
const subjectKey = (s: Ref): string => JSON.stringify([s.type, s.id]);
const keyOf = (session: string, subject: string): string => JSON.stringify([session, subject]);
export const live = (m: Mark, now: number): boolean =>
  (now - m.seen < SESSION_IDLE_MS && now - m.started < SESSION_ABSOLUTE_MS) || (m.hold !== undefined && now < m.hold);
/** Two views of one live session: the higher mark, the earlier start, the later use. */
/** Expired and still remembered: a legacy session past its expiry, before its tombstone horizon. */
export const tombstone = (session: string, m: Mark, now: number): boolean =>
  !session.startsWith(TOKEN_SCOPE) && !live(m, now) && now - m.started < SESSION_TOMBSTONE_MS;
const merge = (a: Mark, b: Mark): Mark => {
  const hold = Math.max(a.hold ?? -Infinity, b.hold ?? -Infinity);
  return { level: Math.max(a.level, b.level) as Level, started: Math.min(a.started, b.started), seen: Math.max(a.seen, b.seen), ...(hold > -Infinity ? { hold } : {}) };
};

export class Sessions {
  private readonly marks = new Map<string, Mark>();
  /** Each PEP credential's keys, oldest first: its share is counted and evicted from its own set. */
  private readonly byPep = new Map<string, Set<string>>();
  private readonly owner = new Map<string, string>();
  /** The local decision queue of each session, including its database commit when a table is present. */
  private readonly queues = new Map<string, Promise<void>>();
  /** BLP_SESSION_REQUIRED. */
  /** Not readonly: a replica follows the database nodes' setting (replica.ts). */
  required: boolean;
  /** Production: only PDP-issued session tokens, never the deprecated PEP-chosen id. */
  requireTokens = false;
  private warnedLegacy = false;
  private readonly elapsed: () => number;
  private readonly backing?: Backing<MarkFile>;
  private readonly table?: MarkTable;
  private readonly perPep: number;
  private saveTimer?: ReturnType<typeof setTimeout>;
  /** When each scope (a PEP credential, or '*' for the whole table) last dropped its expired entries. */
  private readonly purged = new Map<string, number>();
  /** `elapsed`: real wall time in ms (a pinned business clock must not freeze expiry). Without `table`, `backing`
   *  keeps the marks across restarts. `perPep`: BLP_SESSIONS_PER_PEP. */
  constructor(required: boolean, elapsed: () => number = Date.now, backing?: Backing<MarkFile>, table?: MarkTable, perPep = DEFAULT_SESSIONS_PER_PEP) {
    this.required = required; this.elapsed = elapsed; this.backing = backing; this.table = table; this.perPep = perPep;
    for (const [key, mark, pep] of backing?.load() ?? []) this.put(key, mark, pep ?? '');
  }
  get size(): number { return this.marks.size; }
  get shared(): boolean { return this.table !== undefined; }
  /** Marks `pep` holds in memory. */
  held(pep: string | undefined): number { return this.byPep.get(pep ?? '')?.size ?? 0; }

  /** Joins every named queue in one synchronous step: a multi-session batch cannot partly acquire its sessions. */
  serial<T>(sessions: readonly string[], task: () => T | Promise<T>): Promise<T> {
    const keys = [...new Set(sessions)].sort();
    if (keys.length === 0) return Promise.resolve().then(task);
    const previous = keys.map((key) => this.queues.get(key) ?? Promise.resolve());
    const run = Promise.all(previous).then(task);
    const tail = run.then(() => undefined, () => undefined);
    for (const key of keys) this.queues.set(key, tail);
    return run.finally(() => { for (const key of keys) if (this.queues.get(key) === tail) this.queues.delete(key); });
  }

  legacyId(): boolean {
    if (this.requireTokens) return false;
    if (!this.warnedLegacy) {
      this.warnedLegacy = true;
      console.warn('WARNING: context.sessionId is deprecated compatibility mode; open a PDP session and send context.sessionToken');
    }
    return true;
  }

  /** A mark-relevant decision is refreshed, decided and (with PostgreSQL) committed while owning its session queues. */
  ordered<T>(sessions: readonly string[], pep: string | undefined, task: () => T | Promise<T>, prepare?: (loader?: PepSessionLoader) => Promise<void>): Promise<T> {
    return this.serial(sessions, () => {
      const run = async (load?: MarkLoader, pepSessions?: PepSessionLoader): Promise<T> => {
        await prepare?.(pepSessions); await this.refresh(sessions, pep, load); return task();
      };
      return this.table?.decision ? this.table.decision(sessions, run) : run();
    });
  }

  /** The PDP still holds the mark of `subject` in `session` and it passed its idle or absolute expiry (CBAC.SESSION_EXPIRED). */
  expired(session: string, subject: Ref): boolean {
    const key = keyOf(session, subjectKey(subject));
    const found = this.marks.get(key);
    const now = this.elapsed();
    if (!found || live(found, now)) return false;
    if (tombstone(session, found, now)) return true;
    this.drop(key); // past its horizon: forgotten, the id starts clean
    return false;
  }

  /** The live mark of `subject` in `session`, or undefined. A use keeps the session open; it is recorded at most once
   *  every MARK_TOUCH_MS (with a database: one gate_blp_mark write per session a minute, not one per decision). */
  level(session: string, subject: Ref): Level | undefined {
    const now = this.elapsed();
    const key = keyOf(session, subjectKey(subject));
    const found = this.marks.get(key);
    if (!found) return undefined;
    if (!live(found, now)) { if (!tombstone(session, found, now)) this.drop(key); return undefined; }
    if (now - found.seen < MARK_TOUCH_MS) return found.level;
    const touched = { ...found, seen: now };
    this.marks.set(key, touched);
    this.table?.stage({ session, subject: subjectKey(subject), mark: touched });
    return touched.level;
  }

  /** A permitted read at `level` in `session` of PEP credential `pep`: the mark rises to it. False when no mark can be
   *  recorded (the read must then be refused). Only a rise is written. */
  raise(session: string, subject: Ref, level: Level, pep?: string): boolean {
    const now = this.elapsed();
    const key = keyOf(session, subjectKey(subject));
    const found = this.marks.get(key);
    if (found && tombstone(session, found, now)) return false; // an expired session never gets a fresh mark
    const current = found && live(found, now) ? found : undefined;
    if (current && current.level >= level) return true;
    if (!current && !this.room(key, pep ?? '')) return false;
    const mark = current ? { ...current, level, seen: now } : { level, started: now, seen: now };
    this.put(key, mark, pep ?? '');
    if (this.table) this.table.stage({ session, subject: subjectKey(subject), mark });
    // shortcut: without a database only a raise is saved (a touch is not), so after a restart idle expiry may come
    // early; the database keeps the touches
    else this.scheduleSave();
    return true;
  }

  /** An open token of `subject` in token scope `session` may be used until `until`: its live mark (if any) is held that
   *  long. With a database the row is held by the caller in its transaction (pep-sessions.ts); this keeps the copy. */
  hold(session: string, subject: Ref, until: number): void {
    const key = keyOf(session, subjectKey(subject));
    const found = this.marks.get(key);
    if (!found || !live(found, this.elapsed()) || (found.hold ?? -Infinity) >= until) return;
    this.marks.set(key, { ...found, hold: until });
    if (!this.table) this.scheduleSave();
  }

  /** PostgreSQL: the marks other nodes recorded for these sessions (of PEP credential `pep`), before a decision reads them. */
  async refresh(sessions: readonly string[], pep?: string, load?: MarkLoader): Promise<void> {
    if (!this.table || sessions.length === 0) return;
    const rows = await (load ?? this.table.load)(sessions);
    const now = this.elapsed();
    for (const row of rows) {
      // a tombstone is loaded too: another node's expiry holds here before this node ever saw the session. A copy this
      // node holds always merges with the committed row (the earlier start wins), so it expires and is forgotten with it
      const key = keyOf(row.session, row.subject);
      const found = this.marks.get(key);
      if (found && (live(found, now) || tombstone(row.session, found, now))) this.marks.set(key, merge(found, row.mark));
      else if ((live(row.mark, now) || tombstone(row.session, row.mark, now)) && this.room(key, pep ?? '')) this.put(key, row.mark, pep ?? '');
    }
  }

  /** Writes the raised marks now (DATA_DIR/sessions.json); server.close calls it. */
  flush(): void {
    if (this.saveTimer) { clearTimeout(this.saveTimer); this.saveTimer = undefined; } else return;
    this.backing?.save([...this.marks].map(([key, mark]) => [key, mark, this.owner.get(key) ?? '']));
  }
  private scheduleSave(): void {
    if (!this.backing || this.saveTimer) return;
    this.saveTimer = setTimeout(() => this.flush(), SAVE_DELAY_MS);
    this.saveTimer.unref?.();
  }

  private put(key: string, mark: Mark, pep: string): void {
    if (!this.marks.has(key)) {
      this.owner.set(key, pep);
      const keys = this.byPep.get(pep) ?? new Set<string>();
      keys.add(key); this.byPep.set(pep, keys);
    }
    this.marks.set(key, mark);
  }
  private drop(key: string): void {
    if (!this.marks.delete(key)) return;
    const pep = this.owner.get(key) ?? '';
    this.owner.delete(key);
    const keys = this.byPep.get(pep);
    keys?.delete(key);
    if (keys?.size === 0) this.byPep.delete(pep);
  }
  /** Room for a new entry of `pep`: within its share and MAX_SESSIONS, expired entries going first. Then, with a
   *  database (which still holds what memory drops), the oldest entry of `pep` at its share, else the oldest of all. */
  private room(key: string, pep: string): boolean {
    if (this.marks.has(key)) return true;
    const fits = (): boolean => this.held(pep) < this.perPep && this.marks.size < MAX_SESSIONS;
    if (fits()) return true;
    const now = this.elapsed();
    // tombstones go too: a legacy id is the PEP's own choice, so evicting one gains that PEP nothing a new id would not
    // (with a database the row stays and is loaded again before the next decision on it)
    // a credential at its share purges only its own entries (at most perPep); the whole table only when it is full.
    // shortcut: a scope is purged at most once a second, so a credential kept at its share costs one scan a second,
    // not one per request; an expired slot may come free up to a second late (the read gets BLP.SESSION_LIMIT, retry)
    const own = this.held(pep) >= this.perPep;
    const name = own ? pep : '*';
    if (now - (this.purged.get(name) ?? -Infinity) >= 1000) {
      this.purged.set(name, now);
      for (const k of own ? [...this.byPep.get(pep) ?? []] : [...this.marks.keys()]) { const m = this.marks.get(k); if (m && !live(m, now)) this.drop(k); }
    }
    if (fits()) return true;
    if (!this.table) return false;
    const victim = this.held(pep) >= this.perPep ? this.byPep.get(pep)?.values().next().value : this.marks.keys().next().value;
    if (victim !== undefined) this.drop(victim);
    return true;
  }
}

/** Every session a decision-plane body names (AuthZEN context.sessionId, the XACML session-id attribute), scoped to
 *  the PEP credential, and the issuing session of a decision token (its `sid` claim): the marks to load before
 *  deciding. Read without verification: it only chooses what to load. */
export function sessionsIn(body: unknown, pep: string | undefined): string[] {
  const out = new Set<string>();
  const walk = (v: unknown, depth: number): void => {
    if (depth > 8 || v === null || typeof v !== 'object') return;
    if (Array.isArray(v)) { for (const x of v) walk(x, depth + 1); return; }
    const o = v as Record<string, unknown>;
    if (typeof o.sessionId === 'string') out.add(scopeSession(pep, o.sessionId));
    if (o.AttributeId === SESSION_ATTRIBUTE) for (const x of [o.Value].flat()) if (typeof x === 'string') out.add(scopeSession(pep, x));
    for (const x of Object.values(o)) walk(x, depth + 1);
  };
  walk(body, 0);
  const token = (body as { token?: unknown } | null)?.token;
  if (typeof token === 'string') {
    try {
      const sid: unknown = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString()).sid;
      if (typeof sid === 'string') out.add(sid);
    } catch { /* not a token: consume refuses it */ }
  }
  return [...out];
}
