// PostgreSQL control plane. Each node appends to its own hash chain, in the same transaction as the state its requests
// changed. The admin plane (state documents) has one writer: the leader, which holds a session advisory lock. Without
// cluster mode every other node waits for that lock (active/standby); with it every node decides and the followers keep
// the documents current from the database (LISTEN/NOTIFY plus a version number). docs/API.md §3.9.1.
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { canonical } from '../../core/src/index.ts';
import { boundEvent, GENESIS, LEGACY_NODE, sha256, type Anchor, type AuditEvent, type AuditEvidence, type AuditList, type AuditLog, type AuditPage, type AuditRecord, type ErasureReference, type ErasureResult, type Head } from './audit.ts';
import { segmentOf, validSegments, type AuditSegment } from './audit-integrity.ts';
import { idleCutoff, newSubjectIdentity, presentAuditRow, pseudonymiseEvent, SUBJECT_TOUCH_MS, validSubjectIdentity, type SubjectIdentity } from './audit-subjects.ts';
import { HttpError } from './http.ts';
import type { Backing, Performed, PerformedOutcome, PerformedRow, Reservation, RetiredId, RetiredLog } from './store.ts';
import { recordKey, type RecordDelta } from './record-deltas.ts';
import { loadRecordSnapshot, materializeState, migrateLegacyRecords, parseChange, stateWithoutRecords, writeRecordBatch, type ChangeRow, type RecordSnapshot } from './postgres-records.ts';
import { writeDecisionTransaction, writeRecordTransaction } from './postgres-fast-write.ts';
import { databaseTlsFromEnv, postgresClientConfig, type DatabaseTls } from './postgres-tls.ts';
import type { Session, SessionTable } from './auth.ts';
import { frameworks } from './admin/compliance-map.ts';
import { SCHEMA, SCHEMA_MARKER } from './postgres-schema.ts';
import { SESSION_ABSOLUTE_MS, SESSION_IDLE_MS, SESSION_TOMBSTONE_MS, TOKEN_SCOPE, type MarkLoader, type StoredMark } from './sessions.ts';
import { SESSION_IDLE_SECONDS, type PepSessionLoader, type PepSessionTable, type PepSessionTransaction, type SessionRevocationTarget, type StoredPepSession } from './pep-sessions.ts';
import {
  NODE_ID, anchorEntries, auditCursor, auditPoint, byName, checkpointBody, insertAudit, insertMetadata, judge, listNodes, liveHeads, metadataMatches,
  parseCheckpoint, sealedRecord, wanted, type AuditPoint, type ChainCheck, type ChainScan, type Checkpoint, type StoredAuditRow,
} from './postgres-chains.ts';
export { BACKUP_TABLES, RATE_LIMIT_POLICY, RATE_LIMIT_TABLE, RETIRED_POLICY, RETIRED_TABLE, SCHEMA, SESSION_POLICY, SESSION_TABLE, backupGrants, serviceGrants } from './postgres-schema.ts';
export { NODE_ID, anchorEntries, auditCursor, auditPoint, type AuditPoint } from './postgres-chains.ts';

/** pg_advisory_lock key held by the leader ("GATE"). */
const LEADER_LOCK = 0x47415445;
/** Two-key advisory lock (NODE_LOCK, hashtext(node id)) held by the one process writing that node's chain: a second
 *  process started with the same id waits for it like a standby. Two ids with the same hash also wait (never two writers). */
const NODE_LOCK = 0x47415446;
/** Transaction lock around the schema migration, so nodes starting together do not race on CREATE/ALTER. */
const MIGRATE_LOCK = 0x4741544d;
/** Cluster: transaction lock (PERFORMED_LOCK, hashtext(resource)) around a token consumption, so two nodes never decide
 *  separation of duty on one resource without each other's reservation. Two resources with the same hash also wait. */
const PERFORMED_LOCK = 0x47415450;
/** Transaction lock (BLP_LOCK, hashtext(session)) around a mark-relevant decision, including its mark commit. */
const BLP_LOCK = 0x47415442;
const AUDIT_STREAM_BATCH = 10_000;
/** Replica feed: record changes sent in one delta at most; a replica further behind gets a full snapshot. */
const FEED_MAX_CHANGES = 50_000;
/** Mapping changes kept for replica deltas; past this a new epoch makes every replica take the full mapping again. */
const SUBJECT_LOG_MAX = 100_000;
/** The documents a replica decides on (replica-source.ts strips what it does not need). */
const FEED_DOCS = ['state', 'credentials', 'signing_keys', 'blp_revocations'];
/** What a replica feed read returns: the shared generation, the documents, and either record changes or all records. */
export interface ReplicaFeed { version: number; records: number; docs?: Record<string, unknown>; deltas?: RecordDelta[]; snapshot?: RecordSnapshot }
/** Why a replica's audit batch was refused (docs/API.md §3.9.5). */
export type ReplicaAuditRefusal = 'tampered' | 'fork' | 'gap' | 'behind';
const VERIFY_RECHECK_INTERVAL = 60_000;
const TOKEN_SWEEP_INTERVAL = 60_000;
const SESSION_SWEEP_INTERVAL = 60_000;
/** gate_doc row with the last chain heads a full recheck verified, or null once tampering was seen. A single chain "0"
 *  keeps the earlier shape { seq, hash, verifiedAt, mac }; several chains are { heads: { node: { seq, hash } }, verifiedAt,
 *  mac }; both may carry `counters` (each chain's AuditCounters snapshot at its head). mac: HMAC-SHA256 under a key
 *  derived from SIGNING_KEY_SEAL, so a database writer cannot forge one. Every start (production included) verifies from
 *  it instead of from the genesis, then verifies the whole chain in the background (docs/API.md §3.9.1). */
const CHECKPOINT = 'audit_checkpoint';
interface EvidenceRow extends AuditEvidence { total: number; lastSeq: number }
/** A decision token as stored (gate_token.body), with its used flag. */
export interface StoredToken { claims: { jti: string; exp: number }; context: unknown; used: boolean }
export interface PgLedgerOptions {
  /** DATABASE_TLS and its CA/client-key files, resolved by main.ts or the operations entry point. */
  databaseTls?: DatabaseTls;
  now?: () => string;
  onScanStart?: () => Promise<void>;
  onScanBatch?: () => Promise<void>;
  afterCommit?: () => Promise<void>;
  /** Authenticates the audit checkpoint (derivedKey(SIGNING_KEY_SEAL, CHECKPOINT_KEY_LABEL)). Without it no checkpoint is
   *  written or trusted: every start reads the whole chain. */
  checkpointKey?: Buffer;
  /** Server mode: replace subjects by per-subject HMAC pseudonyms and keep their mappings here. */
  pseudonymiseSubjects?: boolean;
  /** The checkpoint key of SIGNING_KEY_SEAL_PREVIOUS: a checkpoint it authenticates is accepted and re-authenticated under
   *  checkpointKey at once (leader), so the previous key is not needed at the next start. */
  previousCheckpointKey?: Buffer;
  /** Whether a seal rotation is in progress: some sealed value in the loaded documents still opens only under the
   *  previous key (server.ts, seal-rotation.ts sealedUnderPrevious). A previous-key checkpoint is trusted only then;
   *  once everything is sealed under the new key it is not, and the start reads every chain from its genesis. */
  rotating?: (doc: (name: string) => unknown) => boolean;
  /** GATE_NODE_ID: the chain this process appends to. "0" (the default) continues the chain of earlier versions. */
  node?: string;
  /** GATE_CLUSTER: every node decides; the leader lock is tried, not waited for, and documents follow the database. */
  cluster?: boolean;
  /** GATE_MAX_STALENESS_MS: cluster nodes refuse decisions once the shared state was last confirmed longer ago (2000). */
  maxStalenessMs?: number;
  /** GATE_ADVERTISE_URL: published in gate_sync while this node leads, so followers can name the admin plane's address. */
  advertiseUrl?: string;
  /** Test hook, awaited before each synchronisation: holding it makes the node fall behind. */
  beforeSync?: () => Promise<void>;
  /** Test hook, awaited before each BLP decision lock: deterministic lock-order tests. */
  onDecisionLock?: (lock: string) => Promise<void>;
  /** Test hook, awaited before each open/close/revocation lock: deterministic deadlock retries. */
  onPepSessionLock?: (lock: string) => Promise<void>;
}
const EMPTY_EVIDENCE = (): EvidenceRow => ({ total: 0, decisions: 0, denies: 0, lastSeen: null, lastSeq: 0 });
const RULE_SETS = [...new Map(frameworks.flatMap((f) => f.controls.map((c) => [JSON.stringify(c.enforcedBy), c.enforcedBy] as const))).values()];
const START: Head = { seq: 0, hash: GENESIS };
const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));
type MarkRow = { session: string; subject: string; level: number; started: string; seen: string; held_until: string | null };
const MARK_COLUMNS = 'SELECT session, subject, level, started, seen, held_until FROM gate_blp_mark WHERE session = ANY($1::text[])';
const markOf = (r: MarkRow): StoredMark => ({ session: r.session, subject: r.subject,
  mark: { level: r.level as StoredMark['mark']['level'], started: Number(r.started), seen: Number(r.seen), ...(r.held_until === null ? {} : { hold: Number(r.held_until) }) } });
async function readMarks(c: pg.Client, sessions: readonly string[]): Promise<StoredMark[]> {
  return (await c.query<MarkRow>(MARK_COLUMNS, [sessions])).rows.map(markOf);
}
async function readPepSessions(c: pg.Client, sids: readonly string[]): Promise<StoredPepSession[]> {
  const rows = (await c.query<{ sid: string; body: string; seen: string }>('SELECT sid, body, seen FROM gate_blp_session WHERE sid = ANY($1::text[])', [sids])).rows;
  return rows.map((row) => ({ sid: row.sid, claims: (JSON.parse(row.body) as { claims: StoredPepSession['claims'] }).claims, seen: Number(row.seen) }));
}
function pepSessionLoader(c: pg.Client): PepSessionLoader {
  return {
    load: (sids) => readPepSessions(c, sids),
    touch: async (sid, seen) => { await c.query('UPDATE gate_blp_session SET seen = $2 WHERE sid = $1', [sid, seen]); },
    // a live mark only: a lapsed one (no usable token held it) is not brought back
    hold: async (session, subject, until) => {
      const now = Date.now();
      await c.query(`UPDATE gate_blp_mark SET held_until = GREATEST(held_until, $3) WHERE session = $1 AND subject = $2
        AND ((seen > $4 AND started > $5) OR held_until > $6)`, [session, subject, until, now - SESSION_IDLE_MS, now - SESSION_ABSOLUTE_MS, now]);
    },
  };
}

class AuditCounters {
  static empty(): AuditCounters { const c = new AuditCounters(); c.reset(0, [], EMPTY_EVIDENCE(), []); return c; }
  total = 0;
  decisions = 0;
  readonly types = new Map<string, number>();
  private all = EMPTY_EVIDENCE();
  private readonly controls = new Map<string, EvidenceRow>();

  reset(total: number, types: Array<{ type: string; count: string }>, all: EvidenceRow, controls: readonly EvidenceRow[]): void {
    this.total = total;
    this.decisions = all.decisions;
    this.types.clear();
    for (const row of types) this.types.set(row.type, Number(row.count));
    this.all = all;
    this.controls.clear();
    RULE_SETS.forEach((rules, i) => this.controls.set(JSON.stringify(rules), controls[i] ?? EMPTY_EVIDENCE()));
  }

  add(row: AuditRecord): void {
    this.total++;
    this.types.set(row.type, (this.types.get(row.type) ?? 0) + 1);
    if (row.type === 'decision') this.decisions++;
    incrementEvidence(this.all, row);
    for (const rules of RULE_SETS) {
      if (row.rules?.some((rule) => rules.includes(rule))) incrementEvidence(this.controls.get(JSON.stringify(rules))!, row);
    }
  }

  evidence(ruleIds: readonly string[], includeAll: boolean): AuditEvidence {
    const row = includeAll ? this.all : this.controls.get(JSON.stringify(ruleIds)) ?? EMPTY_EVIDENCE();
    return { decisions: row.decisions, denies: row.denies, lastSeen: row.lastSeen };
  }
  /** What the checkpoint stores for this chain (covered by its mac). */
  snapshot(): Record<string, unknown> {
    return { total: this.total, types: Object.fromEntries(this.types), all: { ...this.all }, controls: Object.fromEntries([...this.controls].map(([k, v]) => [k, { ...v }])) };
  }
  /** Retained-row counters from a checkpoint; sequence numbers may be higher after retention removed a prefix. */
  static restore(value: unknown): AuditCounters | undefined {
    const s = value as { total?: unknown; types?: Record<string, unknown>; all?: EvidenceRow; controls?: Record<string, EvidenceRow> } | undefined;
    const keys = RULE_SETS.map((rules) => JSON.stringify(rules));
    if (!s || !Number.isSafeInteger(s.total) || (s.total as number) < 0 || !s.types || !s.all || !s.controls || Object.keys(s.controls).length !== keys.length || !keys.every((k) => s.controls![k])) return undefined;
    const types = Object.entries(s.types).map(([type, count]) => ({ type, count: String(count) }));
    const c = new AuditCounters();
    c.reset(s.total as number, types, { ...s.all }, keys.map((k) => ({ ...s.controls![k]! })));
    return c;
  }
}

function incrementEvidence(counter: EvidenceRow, row: AuditRecord): void {
  counter.total++;
  if (row.type === 'decision') counter.decisions++;
  if (row.type === 'decision' && row.effect === 'deny') counter.denies++;
  counter.lastSeen = row.ts;
  counter.lastSeq = row.seq;
}

/** Only uncommitted rows are retained; the durable head and aggregate counters continue after they are drained. */
class StagedAudit implements AuditLog {
  readonly anchors: Anchor[];
  tampered = false;
  get segments(): readonly AuditSegment[] { return this.ledger.segments; }
  private failure?: { length: number; brokenAt?: number; node?: string };
  private readonly ledger: PgLedger;
  private readonly now: () => string;
  constructor(ledger: PgLedger, now: () => string) {
    this.ledger = ledger; this.now = now; this.anchors = ledger.anchors;
    const failure = ledger.integrityFailure ?? (!ledger.initial.verified ? ledger.initial : undefined);
    if (failure) this.checked(failure, false);
  }
  records(): AuditRecord[] { return this.ledger.pendingRecords(); }
  tip(): { seq: number; hash: string } { return this.ledger.head; }
  verify(): { verified: boolean; length: number; brokenAt?: number; node?: string; checkedAt?: string; fullChain?: boolean } {
    if (this.tampered) {
      const f = this.failure;
      return { verified: false, length: f?.length ?? this.ledger.auditTotal(), ...(f?.brokenAt === undefined ? {} : { brokenAt: f.brokenAt }),
        ...(f?.node === undefined || f.node === LEGACY_NODE ? {} : { node: f.node }), checkedAt: this.ledger.checkedAt };
    }
    return { verified: true, length: this.ledger.auditTotal(), checkedAt: this.ledger.checkedAt, fullChain: this.fullChainVerified };
  }
  /** False while the background verification of a start from the checkpoint runs, and after any integrity failure. */
  get fullChainVerified(): boolean { return !this.tampered && this.ledger.fullChainVerified; }
  list(query: AuditList): Promise<AuditPage> { return this.ledger.list(query); }
  exportBatch(after: ReadonlyMap<string, number>, limit: number, until?: ReadonlyMap<string, number>): Promise<AuditRecord[]> { return this.ledger.exportBatch(after, limit, until); }
  countScoped(resources: readonly string[], type?: string): Promise<number> { return this.ledger.countScoped(resources, type); }
  evidence(ruleIds: readonly string[], includeAll: boolean): AuditEvidence { return this.ledger.readEvidence(ruleIds, includeAll); }
  recheck(): Promise<AuditPoint | false> { return this.ledger.recheck(VERIFY_RECHECK_INTERVAL); }
  subjectPseudonym(id: string): string | undefined { return this.ledger.subjectPseudonym(id); }
  displayIdentity(pseudonym: string): string | undefined { return this.ledger.displayIdentity(pseudonym); }
  eraseSubject(id: string, actor: string, reference?: ErasureReference): Promise<ErasureResult> { return this.ledger.eraseSubject(id, actor, reference); }
  purgeSubjects(keep: readonly string[]): Promise<number> { return this.ledger.purgeSubjects(keep); }
  append(event: AuditEvent): void {
    if (this.tampered) throw new Error('Audit integrity failure'); // as the file log: no appending to a chain that disagrees with its store
    const head = this.ledger.head;
    const node = this.ledger.node === LEGACY_NODE ? {} : { node: this.ledger.node };
    const pseudonymised = pseudonymiseEvent(event, (id, decisionSubject) => this.ledger.subjectFor(id, decisionSubject));
    const record = JSON.parse(JSON.stringify({ ...boundEvent(pseudonymised), ...node, seq: head.seq + 1, ts: this.now(), prevHash: head.hash })) as Omit<AuditRecord, 'hash'>;
    this.ledger.stage({ ...record, hash: sha256(head.hash + canonical(record)) });
  }
  checked(chain: ChainCheck, ok: boolean): void {
    if (ok) return;
    this.tampered = true;
    this.failure = { length: chain.length, brokenAt: chain.brokenAt ?? this.ledger.committed.seq + 1,
      ...(chain.node === undefined ? {} : { node: chain.node }) };
  }
}

/** A console session write, staged and committed with the request's audit rows (gate_session, auth.ts SessionTable). */
type SessionOp = { op: 'insert'; key: string; session: Session } | { op: 'touch'; key: string; at: number } | { op: 'remove'; key: string }
  | { op: 'purge'; touchedBefore: number; createdBefore: number };
interface Batch { docs: ReadonlyArray<readonly [string, string]>; records: RecordDelta[]; recordSeq?: number; saves: number; rows: AuditRecord[]; tokens: Array<{ jti: string; body: string; exp: number }>; performed: PerformedRow[]; sessions: SessionOp[]; marks: StoredMark[]; retired: RetiredId[]; subjects: PendingSubject[] }
/** pin: the id was used as an actor or a person detail, so its mapping is never purged (used_at NULL). */
type PendingSubject = SubjectIdentity & { pin?: boolean };

export class PgLedger {
  readonly anchors: Anchor[] = [];
  readonly segments: AuditSegment[] = [];
  readonly node: string;
  /** Holds the leader lock: writes the state documents (the admin plane), anchors, exports and checkpoints. */
  leader = false;
  /** The admin plane's address the leader published (GATE_ADVERTISE_URL), for followers' 409 answers. */
  leaderUrl: string | null = null;
  /** Last head of this node's chain known to be in the database. */
  committed = { ...START };
  head = { ...START };
  initial: ChainCheck = { verified: true, length: 0, heads: new Map() };
  /** This node's chain, live; the other chains are counted at start and again at each recheck (otherCounters). */
  counters = AuditCounters.empty();
  private otherCounters = new Map<string, AuditCounters>();
  integrityFailure?: ChainCheck;
  /** How this start verified the log: from which checkpoint seq (sum over chains; 0: the genesis) and how many rows it read. */
  readonly startup = { from: 0, rowsRead: 0 };
  /** This start accepted a checkpoint authenticated by the previous seal key, and re-authenticates it under the current one. */
  checkpointRekeyed = false;
  /** When this process last verified every chain from its genesis (the start scan or a full recheck); undefined while a
   *  start from the checkpoint waits for its background verification. */
  fullChainAt?: string;
  get fullChainVerified(): boolean { return this.fullChainAt !== undefined && !this.integrityFailure; }
  /** Counters from the checkpoint plus the rows the start read after it; undefined: the start aggregates the table. */
  private startCounters?: Map<string, AuditCounters>;
  /** Set by the server: shared metadata plus record deltas, or a full snapshot when deltas are absent. */
  onReload?: (records?: readonly RecordDelta[]) => void;
  /** Set by the server: performed actions other nodes committed. Until then they queue here (takePerformed). */
  onPerformed?: (rows: PerformedRow[]) => void;
  private readonly docs = new Map<string, unknown>();
  private readonly dirty = new Set<string>();
  private stagedRecords = new Map<string, RecordDelta>();
  private pending: AuditRecord[] = [];
  private pendingTokens: Batch['tokens'] = [];
  private pendingPerformed: PerformedRow[] = [];
  private pendingSessions: SessionOp[] = [];
  private subjects = new Map<string, SubjectIdentity>();
  /** When this node last staged a last-used write per id: at most one per SUBJECT_TOUCH_MS, off the decision fast path otherwise. */
  private readonly touched = new Map<string, number>();
  /** Ids whose stored mapping is pinned (used_at NULL), as last loaded or pinned by this node. */
  private pinned = new Set<string>();
  private clock(): string { return (this.options.now ?? (() => new Date().toISOString()))(); }
  /** Every change to the subject mapping this process saw (pseudonym, or null once erased), for replica deltas. */
  readonly subjectLog = { epoch: randomUUID(), changes: [] as Array<readonly [string, string | null]> };
  private noteSubject(id: string, pseudonym: string | null): void {
    if (this.subjectLog.changes.length >= SUBJECT_LOG_MAX) { this.subjectLog.epoch = randomUUID(); this.subjectLog.changes = []; }
    this.subjectLog.changes.push([id, pseudonym]);
  }
  /** The current mapping, pseudonyms only (never the keys). */
  pseudonyms(): Record<string, string> { return Object.fromEntries([...this.subjects].map(([id, row]) => [id, row.pseudonym])); }
  /** Resolves at the next commit or reload that moved the shared state (long-polling replicas wait on it). */
  private readonly waiters = new Set<() => void>();
  /** Resolves at the next change, or after `timeoutMs`; a poll that times out leaves nothing behind. */
  changed(timeoutMs: number): Promise<void> {
    return new Promise((resolve) => {
      const done = (): void => { clearTimeout(timer); this.waiters.delete(done); resolve(); };
      const timer = setTimeout(done, timeoutMs);
      this.waiters.add(done);
    });
  }
  /** Long polls currently waiting for a change. */
  get waiting(): number { return this.waiters.size; }
  private wake(): void { for (const done of [...this.waiters]) done(); }
  /** Replica feed reads and replica audit ingestion each have a connection of their own: neither queues behind this
   *  node's own commits (the writer) or audit scans (the reader), nor delays them. */
  private readonly side = new Map<'feed' | 'ingest', pg.Client>();
  private ingestTail: Promise<unknown> = Promise.resolve();
  private feedTail: Promise<unknown> = Promise.resolve();
  private async sideClient(name: 'feed' | 'ingest'): Promise<pg.Client> {
    if (this.closing || this.failure) throw new HttpError(503, 'unavailable', 'Storage unavailable');
    const known = this.side.get(name);
    if (known) return known;
    const c = new pg.Client(postgresClientConfig(this.databaseUrl, this.options.databaseTls!, 'demo', { application_name: `gate_replica_${name}`, keepAlive: true, keepAliveInitialDelayMillis: 10_000 }));
    c.on('error', () => { if (this.side.get(name) === c) this.side.delete(name); void c.end().catch(() => undefined); });
    try { await c.connect(); await c.query(`SET statement_timeout = '15s'`); } catch { await c.end().catch(() => undefined); throw new HttpError(503, 'unavailable', 'Storage unavailable'); }
    this.side.set(name, c);
    return c;
  }
  private pendingSubjects: PendingSubject[] = [];
  /** Session marks to upsert, one per (session, subject): a statement may not update a row twice. */
  private pendingMarks = new Map<string, StoredMark>();
  private lastSessionSweep = Number.NEGATIVE_INFINITY;
  private queuedPerformed: PerformedRow[] = [];
  /** gate_retired as the leader knows it (type+id -> the latest retirement), loaded when it starts leading; followers
   *  never use it (registration is the leader's), so they do not keep it. */
  private readonly retired = new Map<string, RetiredId>();
  private pendingRetired: RetiredId[] = [];
  /** The retired-id log of the state document's writer (store.ts RetiredLog). */
  readonly retiredLog: RetiredLog = {
    get: (type, id) => this.retired.get(JSON.stringify([type, id])),
    list: (type) => [...this.retired.values()].filter((r) => r.type === type),
    append: (row) => { this.retired.set(JSON.stringify([row.type, row.id]), row); this.pendingRetired.push(row); },
  };
  private async loadRetired(c: pg.Client): Promise<void> {
    this.retired.clear();
    const rows = (await c.query<{ type: string; id: string; version: string; retired_at: string }>('SELECT type, id, version, retired_at FROM gate_retired ORDER BY version')).rows;
    for (const r of rows) this.retired.set(JSON.stringify([r.type, r.id]), { type: r.type, id: r.id, version: Number(r.version), at: r.retired_at });
  }
  private async loadSubjects(c: pg.Client): Promise<void> {
    const rows = (await c.query<SubjectIdentity & { pinned: boolean }>('SELECT pseudonym, id, key, used_at IS NULL AS pinned FROM gate_subject_identity')).rows;
    // Swap only after the read: a decision must never see an empty map during a cluster reload.
    // fail closed, as the file mapping: a row whose pseudonym is not HMAC(key, id) would re-link or mislink an erased subject
    const parsed = rows.map(({ pinned: ignored, ...row }) => ({ ...row, id: JSON.parse(row.id) as unknown }));
    this.pinned = new Set(rows.filter((row) => row.pinned).map((row) => JSON.parse(row.id) as string));
    if (!parsed.every(validSubjectIdentity) || new Set(parsed.map((row) => row.pseudonym)).size !== parsed.length) throw new Error('Invalid audit subject mapping');
    const next = new Map(parsed.map((row) => [row.id, row] as const));
    for (const [id, row] of next) if (this.subjects.get(id)?.pseudonym !== row.pseudonym) this.noteSubject(id, row.pseudonym);
    for (const id of this.subjects.keys()) if (!next.has(id)) this.noteSubject(id, null);
    for (const id of this.touched.keys()) if (!next.has(id)) this.touched.delete(id); // purged elsewhere: no entry kept here
    this.subjects = next;
  }
  private readonly ownPerformed = new Set<number>();
  /** Last document version, record generation and performed seq this node has applied. */
  private readonly synced = { version: 0, records: 0, performed: 0 };
  /** Heads of the other chains as last verified: a later read must extend them (a truncated chain shows). */
  private readonly seen = new Map<string, Head>();
  private confirmedAt = Number.NEGATIVE_INFINITY;
  private syncClient?: pg.Client;
  private syncing?: Promise<void>;
  private syncAgain = false;
  private syncTimer?: NodeJS.Timeout;
  private queuedWrite?: Promise<void>;
  /** Saves with record changes staged by this process, and how many of them are committed (or discarded by a reload):
   *  while they differ, memory is ahead of synced.records and stateVersion must not name a committed generation. */
  private recordSaves = 0;
  private committedSaves = 0;
  private readonly instance = randomUUID();
  private lastSweep = Number.NEGATIVE_INFINITY;
  private tail: Promise<void> = Promise.resolve();
  private failure?: Error;
  private readFailure?: Error;
  /** The recheck's REPEATABLE READ transaction is open on the read connection (loadMarks). */
  private readerSnapshot = false;
  private audit?: StagedAudit;
  private rechecking?: Promise<AuditPoint | false>;
  private lastRecheckAt = Number.NEGATIVE_INFINITY;
  private lastRecheckResult: AuditPoint | false = false;
  private lastCheckedAt?: string;
  private readonly metaRepairs: Array<{ node: string; seq: number }> = [];
  private reconnecting?: Promise<void>;
  private reconnectTimer?: NodeJS.Timeout;
  private reconnectWake?: () => void;
  private reconnectAttempts = 0;
  private periodicFailures = 0;
  private closing = false;
  private readonly client: pg.Client;
  private reader: pg.Client;
  private rateClient?: pg.Client;
  private lastRateSweep = Number.NEGATIVE_INFINITY;
  private readonly databaseUrl: string;
  private readonly onFatal: (err: Error) => void;
  private readonly options: PgLedgerOptions;
  private readonly maxStaleness: number;
  private rekeyed?: Checkpoint;
  private constructor(client: pg.Client, reader: pg.Client, databaseUrl: string, onFatal: (err: Error) => void, options: PgLedgerOptions) {
    this.client = client; this.reader = reader; this.databaseUrl = databaseUrl; this.onFatal = onFatal; this.options = options;
    this.node = options.node ?? LEGACY_NODE;
    this.maxStaleness = options.maxStalenessMs ?? 2000;
  }
  get checkedAt(): string | undefined { return this.lastCheckedAt; }
  /** The shared state generation this node last committed or applied. */
  get generation(): { version: number; records: number } { return { version: this.synced.version, records: this.synced.records }; }
  get cluster(): boolean { return this.options.cluster === true; }
  /** Cluster: the shared state was confirmed within the staleness bound (always true outside cluster mode). */
  fresh(): boolean { return !this.cluster || performance.now() - this.confirmedAt <= this.maxStaleness; }

  /** Connects, takes this node's chain (a second process with the same id waits), waits to become the leader unless in
   *  cluster mode, migrates, then loads the documents and streams and verifies every chain in one snapshot. */
  static async open(url: string, onFatal: (err: Error) => void, options: PgLedgerOptions = {}): Promise<PgLedger> {
    const node = options.node ?? LEGACY_NODE;
    if (!NODE_ID.test(node)) throw new Error('GATE_NODE_ID must be 1..64 characters from [A-Za-z0-9_.-], starting with a letter or digit');
    const staleness = options.maxStalenessMs ?? 2000;
    if (!Number.isInteger(staleness) || staleness < 100 || staleness > 60_000) throw new Error('GATE_MAX_STALENESS_MS must be an integer in 100..60000');
    const databaseTls = options.databaseTls ?? databaseTlsFromEnv();
    const client = new pg.Client(postgresClientConfig(url, databaseTls, 'demo', { keepAlive: true, keepAliveInitialDelayMillis: 10_000 }));
    const reader = createReader(url, databaseTls);
    await client.connect();
    const ledger = new PgLedger(client, reader, url, onFatal, { ...options, databaseTls });
    client.on('error', (err) => ledger.fail(err));
    try {
      await client.query('SELECT pg_advisory_lock($1, hashtext($2))', [NODE_LOCK, node]);
      if (!options.cluster) await client.query('SELECT pg_advisory_lock($1)', [LEADER_LOCK]);
      await client.query(`SET statement_timeout = '15s'`); // after the locks: a standby waits for them without limit
      await ledger.migrate();
      ledger.leader = !options.cluster || await ledger.tryLock();
      if (!ledger.leader) await ledger.waitForSeed();
      const confirmed = performance.now();
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ');
      try {
        const sync = (await client.query<{ version: string; records: string; leader: string | null }>('SELECT version, records, leader FROM gate_sync')).rows[0]!;
        ledger.synced.version = Number(sync.version);
        ledger.synced.records = Number(sync.records);
        ledger.leaderUrl = ledger.leader ? options.advertiseUrl ?? null : sync.leader;
        if (ledger.leader && options.cluster) await client.query('UPDATE gate_sync SET leader = $1', [options.advertiseUrl ?? null]);
        for (const row of (await client.query<{ name: string; body: string }>('SELECT name, body FROM gate_doc')).rows) ledger.docs.set(row.name, JSON.parse(row.body));
        materializeState(ledger.docs, await loadRecordSnapshot(client));
        const checkpoint = ledger.docs.get(CHECKPOINT);
        ledger.docs.delete(CHECKPOINT); // not a state document: only rechecks write it
        for (const row of (await client.query<{ seq: string; body: string }>('SELECT seq, body FROM gate_performed ORDER BY seq')).rows) {
          ledger.queuedPerformed.push(JSON.parse(row.body) as PerformedRow);
          ledger.synced.performed = Number(row.seq);
        }
        if (ledger.leader) await ledger.importLegacyTokens();
        if (ledger.leader) await ledger.loadRetired(client);
        await ledger.loadSubjects(client);
        await ledger.loadSegments(client);
        await ledger.loadAnchors(client);
        ledger.initial = await ledger.startupScan(client, checkpoint);
        await ledger.recordMetaRepair();
        ledger.installCounters(ledger.startCounters ?? await ledger.loadCounters(client), true);
        ledger.startCounters = undefined;
        await client.query('COMMIT');
      } catch (err) { await client.query('ROLLBACK').catch(() => undefined); throw err; }
      ledger.committed = { ...ledger.initial.heads.get(node) ?? START };
      ledger.head = { ...ledger.committed };
      for (const [other, head] of ledger.initial.heads) if (other !== node) ledger.seen.set(other, head);
      ledger.confirmedAt = confirmed;
      ledger.lastCheckedAt = new Date().toISOString();
      // a checkpoint the previous seal key authenticated, re-signed under the current key (counters included); never one
      // this start found broken, whose cleared row must stay cleared
      if (ledger.rekeyed && ledger.initial.verified) ledger.storeCheckpoint(ledger.rekeyed);
      if (ledger.startup.from === 0 && ledger.initial.verified) ledger.fullChainAt = ledger.lastCheckedAt;
      // what /readyz and /audit/verify answer while the background verification after a checkpointed start runs (recheck)
      ledger.lastRecheckResult = ledger.initial.verified ? auditPoint(ledger.initial.heads) : false;
      await reader.connect();
      await reader.query(`SET default_transaction_read_only = 'on'`);
      await reader.query(`SET statement_timeout = '15s'`);
      ledger.watchReader(reader);
      if (options.cluster) { await ledger.connectRateLimits(); await ledger.startSync(); }
    } catch (err) {
      if (ledger.syncTimer) clearInterval(ledger.syncTimer);
      await Promise.all([client.end().catch(() => undefined), reader.end().catch(() => undefined), ledger.syncClient?.end().catch(() => undefined), ledger.rateClient?.end().catch(() => undefined)]);
      throw err;
    }
    return ledger;
  }

  /** One atomic lease from a shared token bucket; the local caller consumes it without another database round trip. */
  async leaseRateLimit(key: string, capacity: number, perMinute: number, amount: number): Promise<{ granted: number; available: number }> {
    const c = this.rateClient;
    if (!c || this.closing) throw new HttpError(503, 'unavailable', 'Rate limit store unavailable');
    try {
      if (performance.now() - this.lastRateSweep >= 60_000) {
        this.lastRateSweep = performance.now();
        await c.query(`DELETE FROM gate_rate_limit WHERE at < (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::double precision - 3600000`);
      }
      const result = await c.query<{ tokens: number; leased: number }>(`
        WITH clock AS (SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::double precision AS ms)
        INSERT INTO gate_rate_limit AS bucket (key, tokens, at, leased)
        SELECT $1::text, $2::double precision - $3::double precision, clock.ms, $3::double precision FROM clock
        ON CONFLICT (key) DO UPDATE SET
          tokens = GREATEST(0, LEAST($2::double precision, GREATEST(0, bucket.tokens) + GREATEST(0, (SELECT ms FROM clock) - bucket.at) * $4::double precision / 60000) - $3::double precision),
          leased = LEAST($3::double precision, LEAST($2::double precision, GREATEST(0, bucket.tokens) + GREATEST(0, (SELECT ms FROM clock) - bucket.at) * $4::double precision / 60000)),
          at = (SELECT ms FROM clock)
        RETURNING bucket.tokens, bucket.leased`, [key, capacity, amount, perMinute]);
      const row = result.rows[0];
      if (!row || !Number.isFinite(row.tokens) || !Number.isFinite(row.leased)) throw new Error('Invalid shared rate bucket');
      return { granted: row.leased, available: Math.max(0, row.tokens) };
    } catch (err) {
      if (err instanceof HttpError) throw err;
      this.fail(err instanceof Error ? err : new Error(String(err)));
      throw new HttpError(503, 'unavailable', 'Rate limit store unavailable');
    }
  }

  private async connectRateLimits(): Promise<void> {
    const c = new pg.Client(postgresClientConfig(this.databaseUrl, this.options.databaseTls!, 'demo', { application_name: 'gate_rate_limit', keepAlive: true, keepAliveInitialDelayMillis: 10_000 }));
    this.rateClient = c;
    c.on('error', (err) => { if (!this.closing) this.fail(err); });
    try {
      await c.connect();
      await c.query(`SET statement_timeout = '15s'`);
    } catch (err) {
      await c.end().catch(() => undefined);
      this.rateClient = undefined;
      throw err;
    }
  }

  backing<T>(name: string): Backing<T> {
    if (name === 'state') return {
      records: true,
      stateVersion: () => this.recordSaves === this.committedSaves ? this.synced.records : `${this.synced.records}+${this.instance}.${this.recordSaves}`,
      load: () => this.docs.get(name) as T | undefined,
      save: (value, records = []) => {
        if (canonical(stateWithoutRecords(this.docs.get(name))) !== canonical(stateWithoutRecords(value))) this.dirty.add(name);
        this.docs.set(name, value);
        if (records.length) this.recordSaves++;
        for (const record of records) this.stagedRecords.set(recordKey(record.kind, record.type, record.id), record);
      },
    };
    return { load: () => this.docs.get(name) as T | undefined, save: (value) => { this.docs.set(name, value); this.dirty.add(name); } };
  }
  auditLog(now: () => string): StagedAudit { this.audit ??= new StagedAudit(this, now); return this.audit; }
  subjectPseudonym(id: string): string | undefined { return this.subjects.get(id)?.pseudonym; }
  displayIdentity(pseudonym: string): string | undefined { return [...this.subjects.values()].find((row) => row.pseudonym === pseudonym)?.id; }
  /** Known world subjects get one shared random mapping before any node decides; first-use races still fail closed. */
  ensureSubjects(ids: readonly string[]): Promise<void> {
    return this.serial(async () => {
      const missing = [...new Set(ids)].filter((id) => !this.subjects.has(id));
      if (!this.options.pseudonymiseSubjects || !missing.length) return;
      const created = missing.map((id) => newSubjectIdentity(id));
      await this.client.query('INSERT INTO gate_subject_identity (pseudonym, id, key) SELECT * FROM unnest($1::text[], $2::text[], $3::text[]) ON CONFLICT (id) DO NOTHING',
        [created.map((s) => s.pseudonym), created.map((s) => JSON.stringify(s.id)), created.map((s) => s.key)]);
      await this.loadSubjects(this.client);
    });
  }
  subjectFor(id: string, decisionSubject = false): string {
    if (!this.options.pseudonymiseSubjects) return id;
    let identity = this.subjects.get(id);
    const at = Date.parse(this.clock());
    if (!identity) {
      identity = newSubjectIdentity(id);
      this.subjects.set(id, identity); this.pendingSubjects.push(decisionSubject ? identity : { ...identity, pin: true }); this.noteSubject(id, identity.pseudonym);
      this.touched.set(id, at);
      if (!decisionSubject) this.pinned.add(id);
    } else if (!decisionSubject) {
      if (!this.pinned.has(id)) { this.pinned.add(id); this.pendingSubjects.push({ ...identity, pin: true }); } // an actor: never purged
    } else if (!this.pinned.has(id) && !(at - (this.touched.get(id) ?? Number.NEGATIVE_INFINITY) < SUBJECT_TOUCH_MS)) {
      this.touched.set(id, at); this.pendingSubjects.push(identity); // re-staged: the write path records its last use
    }
    return identity.pseudonym;
  }
  /** Leader only. Pins `keep` (the world subjects: never purged again), then deletes the mappings idle past idleCutoff, with
   *  one count-only audit row in the same transaction; followers drop them at their reload (version bump). */
  purgeSubjects(keep: readonly string[]): Promise<number> {
    return this.serial(async () => {
      if (!this.options.pseudonymiseSubjects || !this.leader) return 0;
      const now = this.clock();
      // an id this node staged but has not written yet is in use: it is kept
      const staged = this.pendingSubjects.map((s) => JSON.stringify(s.id));
      let gone: string[];
      try {
        await this.client.query('BEGIN');
        await this.client.query('UPDATE gate_subject_identity SET used_at = NULL WHERE used_at IS NOT NULL AND id = ANY($1::text[])', [keep.map((id) => JSON.stringify(id))]);
        // SKIP LOCKED: a row a write is touching right now is in use, and the purge never waits for it
        gone = (await this.client.query<{ id: string }>(`DELETE FROM gate_subject_identity WHERE pseudonym IN (SELECT pseudonym FROM gate_subject_identity
          WHERE used_at < $1 AND NOT (id = ANY($2::text[])) FOR UPDATE SKIP LOCKED) RETURNING id`, [idleCutoff(now), staged])).rows.map((row) => JSON.parse(row.id) as string);
        if (!gone.length) { await this.client.query('COMMIT'); return 0; }
      } catch (err) {
        // nothing staged yet: memory still matches the database, so maintenance trouble never takes the node down
        await this.client.query('ROLLBACK').catch(() => undefined);
        throw err;
      }
      try {
        this.auditLog(() => now).append({ type: 'security', actor: 'system', action: 'subject_mappings_purged', details: { count: gone.length } });
        const batch = this.drain();
        let version = await this.writeBatch(batch);
        if (version === undefined) {
          version = Number((await this.client.query<{ version: string }>('UPDATE gate_sync SET version = version + 1 RETURNING version')).rows[0]!.version);
          await this.client.query(`SELECT pg_notify('gate_sync', $1)`, [`v${version}`]);
        }
        await this.client.query('COMMIT');
        await this.options.afterCommit?.();
        this.applied(batch, version);
        const rewritten = new Set(batch.subjects.map((s) => s.id));
        for (const id of gone) if (!rewritten.has(id)) { this.subjects.delete(id); this.touched.delete(id); this.noteSubject(id, null); }
        return gone.length;
      } catch (err) {
        await this.client.query('ROLLBACK').catch(() => undefined);
        this.fail(err instanceof Error ? err : new Error(String(err)));
        throw new HttpError(503, 'unavailable', 'Storage unavailable');
      }
    });
  }
  eraseSubject(id: string, actor: string, reference?: ErasureReference): Promise<ErasureResult> {
    return this.serial(async () => {
      const identity = this.subjects.get(id);
      if (!identity) return { pseudonym: '', erased: false };
      this.auditLog(this.options.now ?? (() => new Date().toISOString())).append({ type: 'security', actor, action: 'subject_erased', details: { pseudonym: identity.pseudonym, ...(reference ?? {}) } });
      const batch = this.drain();
      try {
        await this.client.query('BEGIN');
        await this.client.query('DELETE FROM gate_subject_identity WHERE id = $1', [JSON.stringify(id)]);
        let version = await this.writeBatch(batch);
        if (version === undefined) {
          version = Number((await this.client.query<{ version: string }>('UPDATE gate_sync SET version = version + 1 RETURNING version')).rows[0]!.version);
          await this.client.query(`SELECT pg_notify('gate_sync', $1)`, [`v${version}`]);
        }
        await this.client.query('COMMIT');
        await this.options.afterCommit?.();
        this.applied(batch, version);
        this.subjects.delete(id); this.noteSubject(id, null);
        return { pseudonym: identity.pseudonym, erased: true, ...(reference ? { changeId: reference.changeId } : {}) };
      } catch (err) {
        await this.client.query('ROLLBACK').catch(() => undefined);
        this.fail(err instanceof Error ? err : new Error(String(err)));
        throw new HttpError(503, 'unavailable', 'Storage unavailable');
      }
    });
  }
  pendingRecords(): AuditRecord[] { return this.pending; }
  stage(row: AuditRecord): void {
    this.pending.push(row);
    this.head = { seq: row.seq, hash: row.hash };
    this.counters.add(row);
  }
  /** A decision token, inserted with the request's audit rows. */
  stageToken(jti: string, value: Omit<StoredToken, 'used'>): void {
    this.pendingTokens.push({ jti, body: JSON.stringify(value), exp: value.claims.exp });
  }
  /** A reservation or an outcome; it gets its shared seq at commit (the store already holds it in memory). */
  stagePerformed(row: PerformedRow): void { this.pendingPerformed.push(row); }
  /** Console sessions (gate_session): keyed by the hash of the session id, real-time limits checked by auth.ts. Writes go
   *  with the next commit; reads queue behind the writes already queued, so a session ended before is never read back. */
  sessionTable(): SessionTable {
    const stage = (op: SessionOp): void => { this.pendingSessions.push(op); };
    return {
      load: (keys) => this.sessionQuery<{ id: string; body: string; created: string; touched: string }>(
        'SELECT id, body, created, touched FROM gate_session WHERE id = ANY($1::text[])', [keys])
        .then((rows) => rows.map((row) => [row.id, { ...JSON.parse(row.body) as Pick<Session, 'user' | 'method' | 'oidc'>, created: Number(row.created), touched: Number(row.touched) }])),
      insert: (key, session) => stage({ op: 'insert', key, session }),
      touch: (key, at) => stage({ op: 'touch', key, at }),
      remove: (key) => stage({ op: 'remove', key }),
      purge: (touchedBefore, createdBefore) => stage({ op: 'purge', touchedBefore, createdBefore }),
      // a session opened without an IdP sid can only be matched by sub: ending it is the fail-closed choice (auth.ts)
      endOidc: (target, method = 'oidc') => this.sessionQuery<{ id: string }>(`
        DELETE FROM gate_session WHERE method = $3 AND CASE WHEN $1::text IS NOT NULL AND oidc_sid IS NOT NULL
          THEN oidc_sid = $1 AND ($2::text IS NULL OR oidc_sub = $2) ELSE oidc_sub = $2 END RETURNING id`, [target.sid ?? null, target.sub ?? null, method])
        .then((rows) => rows.map((row) => row.id)),
    };
  }
  /** Outside any request transaction; a failure fails this request alone (memory is not ahead of the database). */
  private sessionQuery<R extends pg.QueryResultRow>(text: string, values: unknown[]): Promise<R[]> {
    return this.serial(async () => {
      try { return (await this.client.query<R>(text, values)).rows; } catch { throw new HttpError(503, 'unavailable', 'Storage unavailable'); }
    });
  }
  /** A session's high-water mark as this node now holds it (sessions.ts), upserted with the request. */
  stageMark(row: StoredMark): void { this.pendingMarks.set(JSON.stringify([row.session, row.subject]), row); }
  /** The committed marks of these sessions, every node's. Never inside the recheck's REPEATABLE READ transaction on the
   *  read connection: its snapshot would hide a mark committed since, so meanwhile the writer connection reads them. */
  loadMarks(sessions: readonly string[]): Promise<StoredMark[]> {
    return this.read(async () => (this.readerSnapshot ? await this.sessionQuery<MarkRow>(MARK_COLUMNS, [sessions]) : (await this.reader.query<MarkRow>(MARK_COLUMNS, [sessions])).rows)
      .map(markOf));
  }
  /** Performed rows loaded at start or received before the store took over (onPerformed). */
  takePerformed(): PerformedRow[] { const rows = this.queuedPerformed; this.queuedPerformed = []; return rows; }
  /** Total rows over every chain: this node's live, the others' as of the last recheck. */
  auditTotal(): number {
    let total = this.counters.total;
    for (const c of this.otherCounters.values()) total += c.total;
    return total;
  }
  list(query: AuditList): Promise<AuditPage> {
    return this.read(async () => {
      const after = query.node ?? (query.cursor > 0 ? LEGACY_NODE : null);
      const result = await this.reader.query<StoredAuditRow>(`
        SELECT a.node, a.seq, a.record, m.seq AS meta_seq, m.ts, m.type, m.effect, m.subject, m.resource, m.rules
        FROM gate_audit a LEFT JOIN gate_audit_meta m ON m.node = a.node AND m.seq = a.seq
        WHERE ($8::text IS NULL OR (a.node, a.seq) > ($8::text, $1::bigint))
          AND ($2::text IS NULL OR m.effect = $2)
          AND ($3::text IS NULL OR $3 = ANY(m.rules))
          AND ($4::text IS NULL OR m.subject = $4)
          AND ($5::text IS NULL OR m.resource = $5)
          AND ($6::text IS NULL OR m.type = $6)
          -- shortcut: the actor is not in gate_audit_meta, so this scans the stored JSON text (no jsonb cast: jsonb refuses
          -- the NUL escapes some rows hold); the exact match is checked below. Add a meta column if subject reports grow slow
          AND ($9::text IS NULL OR strpos(a.record, $9) > 0)
        ORDER BY a.node, a.seq LIMIT $7`, [query.cursor, query.effect ?? null, query.rule === undefined ? null : JSON.stringify(query.rule),
        query.subject === undefined ? null : JSON.stringify(query.subject), query.resource === undefined ? null : JSON.stringify(query.resource), query.type ?? null, query.limit + 1, after,
        query.actor === undefined ? null : `"actor":${JSON.stringify(query.actor)}`]);
      const rows = result.rows.map((row) => this.listedRecord(row));
      const items = rows.slice(0, query.limit);
      const last = items.at(-1);
      // the cursor follows every row read; the actor text may also occur in another field, so the page keeps exact matches
      return { items: query.actor === undefined ? items : items.filter((row) => row.actor === query.actor), next: rows.length > query.limit && last ? auditCursor(last) : null };
    });
  }
  /** Up to `limit` committed rows after the per-chain positions in `after` (absent: from the start), chain by chain;
   *  with `until`, only the chains it names and up to their seq there. */
  exportBatch(after: ReadonlyMap<string, number>, limit: number, until?: ReadonlyMap<string, number>): Promise<AuditRecord[]> {
    return this.read(async () => {
      const out: AuditRecord[] = [];
      for (const node of await listNodes(this.reader)) {
        if (out.length >= limit) break;
        if (until && !until.has(node)) continue;
        const result = await this.reader.query<StoredAuditRow>(`
          SELECT a.node, a.seq, a.record, m.seq AS meta_seq, m.ts, m.type, m.effect, m.subject, m.resource, m.rules
          FROM gate_audit a LEFT JOIN gate_audit_meta m ON m.node = a.node AND m.seq = a.seq
          WHERE a.node = $1 AND a.seq > $2::bigint AND ($4::bigint IS NULL OR a.seq <= $4::bigint) ORDER BY a.seq LIMIT $3`,
        [node, after.get(node) ?? 0, limit - out.length, until?.get(node) ?? null]);
        out.push(...result.rows.map((row) => this.listedRecord(row)));
      }
      return out;
    });
  }
  countScoped(resources: readonly string[], type?: string): Promise<number> {
    if (!resources.length) { this.ensureReadable(); return Promise.resolve(0); }
    return this.read(async () => {
      const result = await this.reader.query<{ count: string; audit_count: string; meta_count: string }>(`
        SELECT
          (SELECT count(*) FROM gate_audit a JOIN gate_audit_meta m ON m.node = a.node AND m.seq = a.seq
            WHERE m.resource = ANY($1::text[]) AND ($2::text IS NULL OR m.type = $2)) AS count,
          (SELECT count(*) FROM gate_audit) AS audit_count,
          (SELECT count(*) FROM gate_audit_meta) AS meta_count`, [resources.map((id) => JSON.stringify(id)), type ?? null]);
      const row = result.rows[0]!;
      if (row.audit_count !== row.meta_count) {
        this.markIntegrity({ verified: false, length: this.auditTotal(), heads: new Map() }, false);
        throw new HttpError(503, 'unavailable', 'Audit integrity failure');
      }
      return Number(row.count);
    });
  }
  readEvidence(ruleIds: readonly string[], includeAll: boolean): AuditEvidence {
    this.ensureReadable();
    const result = this.counters.evidence(ruleIds, includeAll);
    for (const other of this.otherCounters.values()) {
      const e = other.evidence(ruleIds, includeAll);
      result.decisions += e.decisions; result.denies += e.denies;
      if (e.lastSeen !== null && (result.lastSeen === null || e.lastSeen > result.lastSeen)) result.lastSeen = e.lastSeen;
    }
    return result;
  }

  /** Writes every change and audit row staged so far in one transaction (group commit). A failed write stops the node:
   *  memory may be ahead of the database, so it must not answer again; a standby or a restart reloads from the database. */
  /** Group commit: a caller joins the write still waiting in the queue, which drains everything staged before it starts
   *  (this caller's rows included), instead of queueing a transaction of its own behind it. Each caller still resolves
   *  only after the COMMIT that holds its rows. A failed write fails every caller that shared it, as a write already
   *  carried every request staged before it: the node is latched (fail) either way, since memory is ahead of the database. */
  commit(): Promise<void> {
    return this.queuedWrite ??= this.serial(() => { this.queuedWrite = undefined; return this.write(); });
  }
  pepSessionTable(): PepSessionTable {
    return { transaction: (locks, task) => this.pepSessionTransaction(locks, task) };
  }
  /** Open, close, revocation and cap checks share the decision locks; their audit rows commit in the same transaction. */
  private pepSessionTransaction<T>(locks: readonly string[], task: (tx: PepSessionTransaction) => Promise<T>): Promise<T> {
    return this.serial(async () => {
      for (let attempt = 1; attempt <= 3; attempt++) {
        let value!: T; let decisionError: unknown; let failed = false; let batch: Batch | undefined; let version: number | undefined;
        let taskStarted = false;
        try {
          await this.client.query('BEGIN');
          for (const lock of [...new Set(locks)].sort()) {
            await this.options.onPepSessionLock?.(lock);
            await this.client.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [BLP_LOCK, lock]);
          }
          const at = (): number => Math.floor(Date.parse((this.options.now ?? (() => new Date().toISOString()))()) / 1000);
          const tx: PepSessionTransaction = {
            ...pepSessionLoader(this.client),
            count: async (pep, subject) => Number((await this.client.query<{ n: string }>(
              'SELECT count(*) AS n FROM gate_blp_session WHERE pep = $1 AND ($2::text IS NULL OR subject = $2) AND exp > $3 AND seen > $4',
              [pep, subject ?? null, at(), Date.now() - SESSION_IDLE_SECONDS * 1000])).rows[0]!.n),
            insert: async (row) => {
              await this.client.query('INSERT INTO gate_blp_session (sid, pep, subject, body, seen, exp) VALUES ($1, $2, $3, $4, $5, $6)',
                [row.sid, row.claims.pep, row.claims.sub, JSON.stringify({ claims: row.claims }), row.seen, row.claims.exp]);
            },
            remove: async (sid) => (await this.client.query('DELETE FROM gate_blp_session WHERE sid = $1', [sid])).rowCount === 1,
            revoke: async (target, selectorLocks) => {
              const values = [target.sessionId ?? target.credential ?? null, target.subject ? JSON.stringify([target.subject.type, target.subject.id]) : null];
              const select = async (forUpdate: boolean): Promise<Array<{ sid: string }>> => target.sessionId
                ? (await this.client.query<{ sid: string }>(`SELECT sid FROM gate_blp_session WHERE sid = $1${forUpdate ? ' FOR UPDATE' : ''}`, [values[0]])).rows
                : (await this.client.query<{ sid: string }>(`SELECT sid FROM gate_blp_session WHERE ($1::text IS NULL OR pep = $1)
                  AND ($2::text IS NULL OR subject = $2) ORDER BY sid${forUpdate ? ' FOR UPDATE' : ''}`, values)).rows;
              const candidates = await select(false);
              const ordered = [...new Set([...candidates.map((row) => row.sid), ...selectorLocks])].sort();
              for (const lock of ordered) {
                await this.options.onPepSessionLock?.(lock);
                await this.client.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [BLP_LOCK, lock]);
              }
              const revalidated = await select(true);
              if (canonical(revalidated.map((row) => row.sid)) !== canonical(candidates.map((row) => row.sid))) {
                throw Object.assign(new Error('Session candidates changed while locking'), { code: '40P01' });
              }
              const removed = (await this.client.query<{ sid: string; body: string; seen: string }>('DELETE FROM gate_blp_session WHERE sid = ANY($1::text[]) RETURNING sid, body, seen',
                [revalidated.map((row) => row.sid)])).rows;
              return removed.map((row) => ({ sid: row.sid, claims: (JSON.parse(row.body) as { claims: StoredPepSession['claims'] }).claims, seen: Number(row.seen) }));
            },
            purge: async (now) => {
              await this.client.query('DELETE FROM gate_blp_session WHERE exp <= $1 OR seen <= $2', [at(), now - SESSION_IDLE_SECONDS * 1000]);
            },
          };
          taskStarted = true;
          try { value = await task(tx); }
          catch (err) {
            if ((err as { code?: unknown })?.code === '40P01') throw err;
            decisionError = err; failed = true;
          }
          batch = this.drain(); version = await this.writeBatch(batch);
          await this.client.query('COMMIT'); await this.options.afterCommit?.();
        } catch (err) {
          await this.client.query('ROLLBACK').catch(() => undefined);
          if ((err as { code?: unknown })?.code === '40P01' && batch === undefined) {
            if (attempt < 3) continue;
            throw new HttpError(503, 'unavailable', 'Storage unavailable');
          }
          if (!taskStarted) throw new HttpError(503, 'unavailable', 'Storage unavailable');
          this.fail(err instanceof Error ? err : new Error(String(err)));
          throw new HttpError(503, 'unavailable', 'Storage unavailable');
        }
        this.applied(batch, version);
        if (failed) throw decisionError;
        return value;
      }
      throw new HttpError(503, 'unavailable', 'Storage unavailable');
    });
  }
  /** A mark-relevant decision owns its session locks from before the mark reload until after the request's commit. */
  decision<T>(sessions: readonly string[], task: (load: MarkLoader, pepSessions: PepSessionLoader) => Promise<T>): Promise<T> {
    return this.serial(async () => {
      try {
        this.ensureReadable();
        await this.client.query('BEGIN');
        for (const session of [...new Set(sessions)].sort()) {
          await this.options.onDecisionLock?.(session);
          await this.client.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [BLP_LOCK, session]);
        }
      } catch {
        await this.client.query('ROLLBACK').catch(() => undefined);
        throw new HttpError(503, 'unavailable', 'Storage unavailable');
      }
      let value!: T;
      let decisionError: unknown;
      let failed = false;
      let batch: Batch | undefined;
      let version: number | undefined;
      const load: MarkLoader = async (keys) => {
        try { return await readMarks(this.client, keys); } catch { throw new HttpError(503, 'unavailable', 'Storage unavailable'); }
      };
      try {
        try { value = await task(load, pepSessionLoader(this.client)); } catch (err) { decisionError = err; failed = true; }
        // Even a refused request commits its audit rows here, while the session is still locked; the router's later
        // error-path commit then finds nothing new to write.
        batch = this.drain();
        version = await this.writeBatch(batch);
        await this.client.query('COMMIT');
        await this.options.afterCommit?.();
      } catch (err) {
        await this.client.query('ROLLBACK').catch(() => undefined);
        this.fail(err instanceof Error ? err : new Error(String(err)));
        throw new HttpError(503, 'unavailable', 'Storage unavailable');
      }
      this.applied(batch, version);
      if (batch.marks.length && performance.now() - this.lastSessionSweep >= SESSION_SWEEP_INTERVAL) this.sweepSessions();
      if (failed) throw decisionError;
      return value;
    });
  }
  /** Consumes decision token `jti` once across every node: the row is locked (SELECT ... FOR UPDATE, so a concurrent
   *  consumer on another node waits for this transaction), `check` runs on what is stored (it may stage audit rows and a
   *  performed action), and only when it accepts is the token marked used, in the same transaction as everything staged.
   *  A refusal writes nothing here: the audit rows it staged go with the request's next commit.
   *  Cluster: consumptions on one `resource` (the token's res claim) are serialised by a transaction advisory lock, and
   *  the performed actions other nodes committed are loaded under it, so `check` decides separation of duty on every
   *  reservation committed before it, not on what this node's last synchronisation brought. A token with a mark-relevant
   *  sid also holds that session's lock and reloads its mark before `check`; one minted in a BLP session (`blpSession`)
   *  holds that session's lock too, as close does, and hands its row (or none, once closed) to `check`. */
  consumeToken(jti: string, resource: string, check: (stored: StoredToken | undefined, session?: StoredPepSession) => boolean, sid?: string,
    refresh?: (session: string, load: MarkLoader) => Promise<void>, blpSession?: string): Promise<boolean> {
    return this.serial(async () => {
      let accepted = false;
      let batch: Batch | undefined;
      let version: number | undefined;
      let row: { body: string; used: boolean } | undefined;
      let session: StoredPepSession | undefined;
      try {
        await this.client.query('BEGIN');
        row = (await this.client.query<{ body: string; used: boolean }>('SELECT body, used FROM gate_token WHERE jti = $1 FOR UPDATE', [jti])).rows[0];
        if (row && !row.used) {
          // sorted, as open/close and decisions take them, so a consumption and a close cannot deadlock
          const locks = [...(blpSession ? [blpSession] : []), ...(sid && refresh ? [sid] : [])].sort();
          for (const lock of locks) await this.client.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [BLP_LOCK, lock]);
          if (sid && refresh) await refresh(sid, (sessions) => readMarks(this.client, sessions));
          if (blpSession) session = (await readPepSessions(this.client, [blpSession]))[0];
        }
        if (row && !row.used && this.options.cluster) {
          await this.client.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [PERFORMED_LOCK, resource]);
          await this.loadPerformed(this.client);
        }
      } catch {
        // nothing drained yet: memory is not ahead of the database, so this request fails alone (a lock wait timed out)
        await this.client.query('ROLLBACK').catch(() => undefined);
        throw new HttpError(503, 'unavailable', 'Storage unavailable');
      }
      try {
        try { accepted = check(row ? { ...JSON.parse(row.body) as Omit<StoredToken, 'used'>, used: row.used } : undefined, session); } catch { accepted = false; }
        if (accepted) {
          await this.client.query('UPDATE gate_token SET used = true WHERE jti = $1', [jti]);
          batch = this.drain();
          version = await this.writeBatch(batch);
          await this.client.query('COMMIT');
          await this.options.afterCommit?.();
        } else await this.client.query('ROLLBACK');
      } catch (err) {
        this.fail(err instanceof Error ? err : new Error(String(err)));
        throw new HttpError(503, 'unavailable', 'Storage unavailable');
      }
      if (batch) this.applied(batch, version);
      return accepted;
    });
  }
  /** Settles reservation `ref` once across every node: the gate_sync row is locked first (every performed write takes
   *  it, so a report on another node waits for this transaction and then sees its outcome), `check` runs on the rows
   *  stored for `ref` (it may stage audit rows and the outcome), and what it staged commits only when it accepts. The
   *  unique (ref, kind) index refuses a second outcome should anything else write one. */
  settleReservation(ref: string, check: (stored: Reservation) => boolean): Promise<boolean> {
    return this.serial(async () => {
      let rows: Array<{ kind: string | null; body: string }>;
      try {
        await this.client.query('BEGIN');
        await this.client.query('SELECT 1 FROM gate_sync FOR UPDATE');
        rows = (await this.client.query<{ kind: string | null; body: string }>('SELECT kind, body FROM gate_performed WHERE ref = $1', [ref])).rows;
      } catch {
        await this.client.query('ROLLBACK').catch(() => undefined);
        throw new HttpError(503, 'unavailable', 'Storage unavailable');
      }
      const reservation = rows.find((r) => r.kind === 'reservation');
      const outcome = rows.find((r) => r.kind === 'outcome');
      const stored: Reservation = { ...(reservation ? { reservation: JSON.parse(reservation.body) as Performed } : {}),
        ...(outcome ? { outcome: (JSON.parse(outcome.body) as PerformedOutcome).outcome } : {}) };
      let accepted = false;
      let batch: Batch | undefined;
      let version: number | undefined;
      try {
        try { accepted = check(stored); } catch { accepted = false; }
        if (accepted) {
          batch = this.drain();
          version = await this.writeBatch(batch);
          await this.client.query('COMMIT');
          await this.options.afterCommit?.();
        } else await this.client.query('ROLLBACK');
      } catch (err) {
        this.fail(err instanceof Error ? err : new Error(String(err)));
        throw new HttpError(503, 'unavailable', 'Storage unavailable');
      }
      if (batch) this.applied(batch, version);
      return accepted;
    });
  }
  /** Rereads on the read-only connection; concurrent callers share one scan and /verify reuses a recent result. */
  recheck(minInterval = 0): Promise<AuditPoint | false> {
    // until the first full verification after a start from the checkpoint ends, a cached caller (/readyz, /audit/verify)
    // takes the start's result instead of waiting for that scan; anchoring (minInterval 0) always waits for it
    if (this.rechecking) return minInterval > 0 && this.fullChainAt === undefined && this.lastRecheckResult ? Promise.resolve(this.lastRecheckResult) : this.rechecking;
    if (minInterval > 0 && performance.now() - this.lastRecheckAt < minInterval) return Promise.resolve(this.lastRecheckResult);
    const run = this.runRecheck().finally(() => { this.rechecking = undefined; });
    this.rechecking = run;
    return run;
  }
  periodicRecheck(): Promise<AuditPoint | false> {
    return this.recheck().then((result) => { this.periodicFailures = 0; return result; }, (err: unknown) => {
      this.periodicFailures++;
      const failure = err instanceof Error ? err : new Error(String(err));
      console.error(`Audit periodic recheck failed (${this.periodicFailures}/3): ${failure.message}`);
      if (this.periodicFailures >= 3) this.fail(new Error('Audit integrity rechecks remain unavailable'));
      throw failure;
    });
  }
  saveAnchor(a: Anchor): Promise<void> {
    return this.serial(async () => {
      await this.client.query('INSERT INTO gate_anchor (seq, hash, tsa, gen_time, token, heads) VALUES ($1, $2, $3, $4, $5, $6)',
        [a.seq, a.hash, a.tsa, a.genTime, Buffer.from(a.token, 'base64'), a.heads ? JSON.stringify(a.heads) : null]);
    });
  }
  async close(): Promise<void> {
    this.closing = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.syncTimer) clearInterval(this.syncTimer);
    this.reconnectWake?.();
    await this.tail;
    await this.rechecking?.catch(() => undefined);
    await this.syncing;
    await this.tail; // the checkpoint that recheck queued
    await this.reconnecting;
    // ending the writer session releases the node and leader locks
    this.wake();
    await Promise.all([this.ingestTail.catch(() => undefined), this.feedTail.catch(() => undefined)]);
    await Promise.all([this.client.end().catch(() => undefined), this.reader.end().catch(() => undefined), this.syncClient?.end().catch(() => undefined), this.rateClient?.end().catch(() => undefined),
      ...[...this.side.values()].map((c) => c.end().catch(() => undefined))]);
  }

  // --- replicas (replica-source.ts): the signed feed reads the database, never this node's memory ------------------
  /** One repeatable-read snapshot on a connection of its own (never queued behind an audit scan): the generation, the
   *  documents unless `after.version` is current, and the record changes after `after.records`, or every record row
   *  when there is no `after`, the replica is too far behind, or the log has a gap or a reorder. */
  replicaFeed(after?: { version: number; records: number }): Promise<ReplicaFeed> {
    // one transaction at a time on the feed connection: interleaved polls would share (and end) each other's snapshot
    const run = this.feedTail.then(() => this.readFeed(after));
    this.feedTail = run.catch(() => undefined);
    return run;
  }
  private async readFeed(after?: { version: number; records: number }): Promise<ReplicaFeed> {
    const c = await this.sideClient('feed');
    try {
      await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      try {
        const sync = (await c.query<{ version: string; records: string }>('SELECT version, records FROM gate_sync')).rows[0]!;
        const feed: ReplicaFeed = { version: Number(sync.version), records: Number(sync.records) };
        if (!after || feed.version !== after.version) {
          const rows = (await c.query<{ name: string; body: string }>('SELECT name, body FROM gate_doc WHERE name = ANY($1::text[])', [FEED_DOCS])).rows;
          feed.docs = Object.fromEntries(rows.map((row) => [row.name, JSON.parse(row.body) as unknown]));
        }
        let full = !after || feed.records < after.records || feed.records - after.records > FEED_MAX_CHANGES;
        if (!full && after && feed.records > after.records) {
          const changes = (await c.query<ChangeRow>(`SELECT seq, kind, type, id, op, position, body, move FROM gate_state_change
            WHERE seq > $1 AND seq <= $2 ORDER BY seq, kind, position NULLS FIRST, type, id`, [after.records, feed.records])).rows;
          const generations = new Set(changes.map((row) => Number(row.seq)));
          full = generations.size !== feed.records - after.records || changes.some((row) => row.move);
          if (!full) feed.deltas = changes.map(parseChange);
        } else if (!full) feed.deltas = [];
        if (full) {
          feed.snapshot = await loadRecordSnapshot(c);
          if (!feed.docs) feed.docs = Object.fromEntries((await c.query<{ name: string; body: string }>('SELECT name, body FROM gate_doc WHERE name = ANY($1::text[])', [FEED_DOCS])).rows
            .map((row) => [row.name, JSON.parse(row.body) as unknown]));
        }
        await c.query('COMMIT');
        return feed;
      } catch (err) { await c.query('ROLLBACK').catch(() => undefined); throw err; }
    } catch (err) {
      if (err instanceof HttpError) throw err;
      throw new HttpError(503, 'unavailable', 'Storage unavailable');
    }
  }
  /** Appends a replica's own chain (`node` = its id) to gate_audit after continuity checks: every row links and hashes
   *  and names that chain; `base` (the replica's head before `rows`) must be this table's head, or an earlier row whose
   *  hash matches (a resend: the rows already stored must be the same ones). Serialised with that chain's other
   *  writers by the node advisory lock, so no chain has two. Resolves to the stored head, or the refusal. */
  ingestReplica(node: string, base: Head, rows: readonly AuditRecord[]): Promise<{ head: Head; refused?: ReplicaAuditRefusal }> {
    let expected = base;
    for (const row of rows) {
      const { hash, ...rest } = row;
      if (!row || typeof row !== 'object' || rest.node !== node || rest.seq !== expected.seq + 1 || rest.prevHash !== expected.hash ||
        sha256(rest.prevHash + canonical(rest)) !== hash) return Promise.resolve({ head: base, refused: 'tampered' });
      expected = { seq: row.seq, hash };
    }
    const run = this.ingestTail.then(async () => {
      const c = await this.sideClient('ingest');
      let outcome: { head: Head; refused?: ReplicaAuditRefusal };
      try {
        await c.query('BEGIN');
        await c.query('SELECT pg_advisory_xact_lock($1, hashtext($2))', [NODE_LOCK, node]);
        const top = (await c.query<{ seq: string; record: string }>('SELECT seq, record FROM gate_audit WHERE node = $1 ORDER BY seq DESC LIMIT 1', [node])).rows[0];
        const head: Head = top ? { seq: Number(top.seq), hash: (JSON.parse(top.record) as AuditRecord).hash } : { ...START };
        const storedAt = async (seq: number): Promise<string | undefined> => {
          if (seq === 0) return GENESIS;
          const row = (await c.query<{ record: string }>('SELECT record FROM gate_audit WHERE node = $1 AND seq = $2', [node, seq])).rows[0];
          return row ? (JSON.parse(row.record) as AuditRecord).hash : undefined;
        };
        const last = base.seq + rows.length;
        // an empty batch is the replica's start: it names its local head and learns this one
        if (base.seq > head.seq) outcome = rows.length ? { head, refused: 'gap' } : { head };
        else if (base.seq === head.seq) outcome = base.hash === head.hash ? { head: expected } : { head, refused: 'fork' };
        else if (!rows.length) outcome = { head, refused: 'behind' };
        else if (last <= head.seq) outcome = await storedAt(last) === expected.hash ? { head } : { head, refused: 'fork' };
        else outcome = rows[head.seq - base.seq - 1]?.hash === head.hash ? { head: expected } : { head, refused: 'fork' };
        const fresh = outcome.refused ? [] : rows.filter((row) => row.seq > head.seq);
        if (fresh.length) await insertAudit(c, node, fresh);
        await c.query('COMMIT');
      } catch (err) {
        await c.query('ROLLBACK').catch(() => undefined);
        console.error(`Replica audit ingestion failed for ${node}: ${message(err)}`);
        throw new HttpError(503, 'unavailable', 'Storage unavailable');
      }
      return outcome;
    });
    this.ingestTail = run.catch(() => undefined);
    return run;
  }

  private serial<T>(task: () => Promise<T>): Promise<T> {
    const run = this.tail.then(() => {
      if (this.failure) throw new HttpError(503, 'unavailable', 'Storage unavailable');
      return task();
    });
    this.tail = run.then(() => undefined, () => undefined);
    return run;
  }
  /** Takes everything staged in one synchronous step, so the snapshot matches the audit rows it ships with. A follower
   *  never writes documents: what a request changed in them (a PEP credential's last use) stays in memory until the next
   *  reload. */
  private drain(): Batch {
    const docs = this.leader ? [...this.dirty].map((name) => [name, JSON.stringify(name === 'state' ? stateWithoutRecords(this.docs.get(name)) : this.docs.get(name))] as const) : [];
    const batch: Batch = { docs, records: this.leader ? [...this.stagedRecords.values()] : [], saves: this.recordSaves, rows: this.pending, tokens: this.pendingTokens, performed: this.pendingPerformed, sessions: this.pendingSessions,
      marks: [...this.pendingMarks.values()], retired: this.leader ? this.pendingRetired : [], subjects: this.pendingSubjects };
    this.pendingRetired = []; this.pendingSubjects = [];
    this.stagedRecords.clear();
    this.dirty.clear(); this.pending = []; this.pendingTokens = []; this.pendingPerformed = []; this.pendingSessions = []; this.pendingMarks = new Map();
    return batch;
  }
  private decisionOnly(b: Batch): boolean {
    return b.rows.length > 0 && !b.docs.length && !b.records.length && !b.performed.length && !b.sessions.length && !b.retired.length && !b.subjects.length;
  }
  /** Returns the new state version when metadata or records were written. */
  private async writeBatch(b: Batch): Promise<number | undefined> {
    const c = this.client;
    if (this.decisionOnly(b)) { await writeDecisionTransaction(c, this.node, b); return undefined; }
    // new subject mappings take the general path: their rows must commit with the pseudonymised audit rows that use them
    if ((b.docs.length || b.records.length) && !b.tokens.length && !b.performed.length && !b.sessions.length && !b.marks.length && !b.subjects.length && b.records.every((r) => !r.move)) {
      const fast = await writeRecordTransaction(c, this.node, b);
      b.recordSeq = fast.recordSeq;
      return fast.version;
    }
    let version: number | undefined;
    if (b.docs.length) {
      for (const [name, body] of b.docs) {
        await c.query('INSERT INTO gate_doc (name, body) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET body = EXCLUDED.body, updated_at = now()', [name, body]);
      }
    }
    if (b.docs.length || b.records.length) {
      version = Number((await c.query<{ version: string }>('UPDATE gate_sync SET version = version + 1 RETURNING version')).rows[0]!.version);
      if (b.records.length) {
        b.recordSeq = Number((await c.query<{ records: string }>('UPDATE gate_sync SET records = records + 1 RETURNING records')).rows[0]!.records);
        await writeRecordBatch(c, b.records, version, b.recordSeq);
      }
      await c.query(`SELECT pg_notify('gate_sync', $1)`, [`v${version}`]); // delivered at commit
    }
    if (b.subjects.length) {
      const ids = b.subjects.map((s) => JSON.stringify(s.id));
      const usedAt = this.clock();
      // last use of the ids already stored (NULL, a world subject's pin, stays NULL), first: the row lock keeps a concurrent
      // purge (SKIP LOCKED) off it until this commits, and a row the purge already removed is inserted again below
      await c.query('UPDATE gate_subject_identity SET used_at = $2 WHERE id = ANY($1::text[]) AND used_at < $2', [ids, usedAt]);
      const pins = b.subjects.filter((s) => s.pin).map((s) => JSON.stringify(s.id));
      const inserted = (await c.query('INSERT INTO gate_subject_identity (pseudonym, id, key, used_at) SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::timestamptz[]) ON CONFLICT (id) DO NOTHING RETURNING id',
        [b.subjects.map((s) => s.pseudonym), ids, b.subjects.map((s) => s.key), b.subjects.map((s) => s.pin ? null : usedAt)])).rowCount ?? 0;
      // pin after the insert: a row purged and re-inserted by another node in between is pinned too
      if (pins.length) await c.query('UPDATE gate_subject_identity SET used_at = NULL WHERE id = ANY($1::text[]) AND used_at IS NOT NULL', [pins]);
      const stored = (await c.query<SubjectIdentity>('SELECT pseudonym, id, key FROM gate_subject_identity WHERE id = ANY($1::text[])', [ids])).rows;
      // another node stored its mapping first (a follower decided on the id): adopt it. Only this batch's uncommitted rows
      // carry the local pseudonym, so no committed row ever changes mapping; anything unexpected still fails closed.
      const swap = new Map<string, string>();
      for (const s of b.subjects) {
        const row = stored.find((r) => r.id === JSON.stringify(s.id));
        if (!row) throw new Error('A subject mapping changed concurrently; restart to load the shared mapping before deciding again');
        if (row.pseudonym === s.pseudonym && row.key === s.key) continue;
        const actual = { ...row, id: s.id };
        if (!validSubjectIdentity(actual) || [...this.subjects.values()].some((known) => known.pseudonym === actual.pseudonym && known.id !== s.id)) throw new Error('Invalid audit subject mapping');
        swap.set(s.pseudonym, actual.pseudonym);
        this.subjects.set(s.id, actual); this.noteSubject(s.id, actual.pseudonym);
      }
      if (swap.size) this.rechain(b, swap);
      if (inserted || swap.size) { // a last-use write alone changes no mapping: no reload anywhere
        version = Number((await c.query<{ version: string }>('UPDATE gate_sync SET version = version + 1 RETURNING version')).rows[0]!.version);
        await c.query(`SELECT pg_notify('gate_sync', $1)`, [`v${version}`]);
      }
    }
    if (b.rows.length) await insertAudit(c, this.node, b.rows);
    if (b.tokens.length) {
      await c.query('INSERT INTO gate_token (jti, node, body, exp) SELECT jti, $2, body, exp FROM unnest($1::text[], $3::text[], $4::bigint[]) AS v(jti, body, exp)',
        [b.tokens.map((t) => t.jti), this.node, b.tokens.map((t) => t.body), b.tokens.map((t) => t.exp)]);
    }
    if (b.performed.length) {
      // the gate_sync row lock orders these seqs by commit: a reader that sees seq n also sees every seq below it
      const last = Number((await c.query<{ performed: string }>('UPDATE gate_sync SET performed = performed + $1 RETURNING performed', [b.performed.length])).rows[0]!.performed);
      const seqs = b.performed.map((_, i) => last - b.performed.length + 1 + i);
      for (const seq of seqs) this.ownPerformed.add(seq); // before COMMIT: a sync that sees them must skip them
      const outcome = (p: PerformedRow): p is PerformedOutcome => 'ref' in p;
      await c.query('INSERT INTO gate_performed (seq, node, body, ref, kind) SELECT seq, $2, body, ref, kind FROM unnest($1::bigint[], $3::text[], $4::text[], $5::text[]) AS v(seq, body, ref, kind)',
        [seqs, this.node, b.performed.map((p) => JSON.stringify(p)), b.performed.map((p) => outcome(p) ? p.ref : p.id ?? null),
          b.performed.map((p) => outcome(p) ? 'outcome' : p.id === undefined ? null : 'reservation')]);
      await c.query(`SELECT pg_notify('gate_sync', 'p')`);
    }
    if (b.retired.length) {
      await c.query('INSERT INTO gate_retired (type, id, version, retired_at, node) SELECT type, id, version, retired_at, $5 FROM unnest($1::text[], $2::text[], $3::bigint[], $4::text[]) AS v(type, id, version, retired_at) ON CONFLICT DO NOTHING',
        [b.retired.map((r) => r.type), b.retired.map((r) => r.id), b.retired.map((r) => r.version), b.retired.map((r) => r.at), this.node]);
    }
    for (const s of b.sessions) await writeSession(c, s);
    if (b.marks.length) {
      // last, in key order: every transaction takes the gate_sync row (above) before any mark, and marks in one order,
      // so two nodes cannot deadlock. A mark only rises within a live session; an expired row is replaced, not merged, unless it is a legacy session's tombstone (left as it is).
      // A row held by an open token (held_until) is live too.
      const now = Date.now(); const live = '((m.seen > $6 AND m.started > $7) OR m.held_until > $10)';
      const rows = [...b.marks].sort((x, y) => x.session < y.session ? -1 : x.session > y.session ? 1 : x.subject < y.subject ? -1 : x.subject > y.subject ? 1 : 0);
      await c.query(`INSERT INTO gate_blp_mark AS m (session, subject, level, started, seen, held_until)
        SELECT * FROM unnest($1::text[], $2::text[], $3::int[], $4::bigint[], $5::bigint[], $11::bigint[])
        ON CONFLICT (session, subject) DO UPDATE SET
          level = CASE WHEN ${live} THEN GREATEST(m.level, EXCLUDED.level) ELSE EXCLUDED.level END,
          started = CASE WHEN ${live} THEN LEAST(m.started, EXCLUDED.started) ELSE EXCLUDED.started END,
          held_until = CASE WHEN ${live} THEN GREATEST(m.held_until, EXCLUDED.held_until) ELSE EXCLUDED.held_until END,
          seen = GREATEST(m.seen, EXCLUDED.seen)
        WHERE ${live} OR starts_with(m.session, $9) OR m.started <= $8`,
      [rows.map((r) => r.session), rows.map((r) => r.subject), rows.map((r) => r.mark.level), rows.map((r) => r.mark.started), rows.map((r) => r.mark.seen),
        now - SESSION_IDLE_MS, now - SESSION_ABSOLUTE_MS, now - SESSION_TOMBSTONE_MS, TOKEN_SCOPE, now, rows.map((r) => r.mark.hold ?? null)]);
    }
    return version;
  }
  /** Replaces local pseudonyms in the uncommitted rows (this batch, then those staged since it was drained) and hashes
   *  them again from the same base: their seqs are unchanged, only their content and hashes. */
  private rechain(b: Batch, swap: ReadonlyMap<string, string>): void {
    const rows = [...b.rows, ...this.pending];
    let prev = rows[0]?.prevHash;
    if (prev === undefined) return;
    const next = rows.map((row) => {
      const { hash: _, ...record } = { ...presentAuditRow(row, (p) => swap.get(p)), prevHash: prev! };
      const hash = sha256(prev + canonical(record));
      prev = hash;
      return { ...record, hash } as AuditRecord;
    });
    b.rows = next.slice(0, b.rows.length);
    this.pending = next.slice(b.rows.length);
    const last = next.at(-1)!;
    this.head = { seq: last.seq, hash: last.hash };
  }
  private applied(b: Batch, version: number | undefined): void {
    const last = b.rows.at(-1);
    if (last) this.committed = { seq: last.seq, hash: last.hash };
    if (version !== undefined) this.synced.version = version;
    if (b.recordSeq !== undefined) this.synced.records = b.recordSeq;
    this.committedSaves = b.saves;
    if (version !== undefined) this.wake();
  }
  private async write(): Promise<void> {
    const batch = this.drain();
    if (!batch.docs.length && !batch.records.length && !batch.rows.length && !batch.tokens.length && !batch.performed.length && !batch.sessions.length && !batch.marks.length && !batch.retired.length && !batch.subjects.length) return;
    let version: number | undefined;
    const direct = this.decisionOnly(batch);
    try {
      if (!direct) await this.client.query('BEGIN');
      version = await this.writeBatch(batch);
      if (!direct) await this.client.query('COMMIT');
      await this.options.afterCommit?.();
    } catch (err) {
      this.fail(err instanceof Error ? err : new Error(String(err)));
      throw new HttpError(503, 'unavailable', 'Storage unavailable');
    }
    this.applied(batch, version);
    if (batch.marks.length && performance.now() - this.lastSessionSweep >= SESSION_SWEEP_INTERVAL) this.sweepSessions();
  }
  /** Expired session marks are removed by the nodes that write marks, at most once a minute each, through the writer
   *  queue and never inside a request's transaction. SKIP LOCKED: the sweep never waits for a row a request holds. */
  /** A legacy session's expired mark stays as its tombstone until SESSION_TOMBSTONE_MS (sessions.ts). A mark an open
   *  token still holds (held_until) is never swept: that would reset the floor under the token. */
  private sweepSessions(): void {
    this.lastSessionSweep = performance.now();
    const now = Date.now();
    void this.serial(async () => {
      await this.client.query(`DELETE FROM gate_blp_mark WHERE (session, subject) IN (SELECT session, subject FROM gate_blp_mark
        WHERE ((starts_with(session, $4) AND (seen <= $1 OR started <= $2)) OR started <= $3) AND NOT COALESCE(held_until > $5, false) FOR UPDATE SKIP LOCKED)`,
      [now - SESSION_IDLE_MS, now - SESSION_ABSOLUTE_MS, now - SESSION_TOMBSTONE_MS, TOKEN_SCOPE, now]);
    }).catch((err: unknown) => console.error(`Session mark sweep failed: ${message(err)}`));
  }
  private async migrate(): Promise<void> {
    const state = (await this.client.query<{ current: boolean; foreign: boolean }>(`
      SELECT to_regclass($1) IS NOT NULL AS current,
        EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'gate_audit' AND tableowner <> current_user) AS foreign`, [SCHEMA_MARKER])).rows[0]!;
    if (state.current) {
      const migrated = (await this.client.query<{ migrated: boolean }>('SELECT records_migrated AS migrated FROM gate_sync')).rows[0]!.migrated;
      if (migrated) return; // no schema locks on an ordinary start
    } else if (state.foreign) {
      // tables someone else owns are migrated by that owner; the service can still run the data import after that
      throw new Error('The database schema is from an earlier version: run SCHEMA (packages/pdp-http/src/postgres.ts) as the owner role first');
    }
    await this.client.query('BEGIN');
    try {
      await this.client.query('SELECT pg_advisory_xact_lock($1)', [MIGRATE_LOCK]);
      if (!(await this.client.query<{ current: boolean }>(`SELECT to_regclass($1) IS NOT NULL AS current`, [SCHEMA_MARKER])).rows[0]!.current) await this.client.query(SCHEMA);
      await migrateLegacyRecords(this.client);
      await this.client.query('COMMIT');
    } catch (err) { await this.client.query('ROLLBACK').catch(() => undefined); throw err; }
  }
  private async tryLock(): Promise<boolean> {
    return (await this.client.query<{ ok: boolean }>('SELECT pg_try_advisory_lock($1) AS ok', [LEADER_LOCK])).rows[0]!.ok;
  }
  /** A follower decides only on state some leader seeded: it waits for the first leader's first commit, or leads itself. */
  private async waitForSeed(): Promise<void> {
    for (;;) {
      const seeded = (await this.client.query<{ n: string }>(`SELECT count(*) AS n FROM gate_doc WHERE name IN ('state', 'credentials')`)).rows[0]!.n === '2';
      if (seeded) return;
      if (await this.tryLock()) { this.leader = true; return; }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }
  /** Decision tokens an earlier version kept in the "tokens" document, still unexpired: consumable after the upgrade. */
  private async importLegacyTokens(): Promise<void> {
    const legacy = this.docs.get('tokens');
    if (!Array.isArray(legacy) || !legacy.length) return;
    const at = Math.floor(Date.parse((this.options.now ?? (() => new Date().toISOString()))()) / 1000);
    const live = (legacy as Array<[unknown, { claims?: { exp?: unknown }; context?: unknown; used?: unknown } | undefined]>)
      .filter((entry): entry is [string, { claims: { exp: number }; context?: unknown; used?: unknown }] =>
        typeof entry[0] === 'string' && typeof entry[1]?.claims?.exp === 'number' && entry[1].claims.exp > at);
    if (!live.length) return;
    await this.client.query('INSERT INTO gate_token (jti, node, body, exp, used) SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::bigint[], $5::boolean[]) ON CONFLICT (jti) DO NOTHING',
      [live.map(([jti]) => jti), live.map(() => this.node), live.map(([, e]) => JSON.stringify({ claims: e.claims, context: e.context })),
        live.map(([, e]) => e.claims.exp), live.map(([, e]) => e.used === true)]);
  }

  // --- cluster: keeping documents and performed actions current, and taking the lead ------------------------------
  private get pollMs(): number { return Math.max(20, Math.min(500, Math.floor(this.maxStaleness / 4))); }
  private async startSync(): Promise<void> {
    await this.connectSync();
    this.syncTimer = setInterval(() => void this.sync(), this.pollMs); this.syncTimer.unref();
  }
  private async connectSync(): Promise<void> {
    const c = new pg.Client(postgresClientConfig(this.databaseUrl, this.options.databaseTls!, 'demo', { application_name: 'gate_sync', keepAlive: true, keepAliveInitialDelayMillis: 10_000 }));
    c.on('error', (err) => this.syncLost(c, err));
    c.on('notification', () => void this.sync());
    try {
      await c.connect();
      await c.query(`SET statement_timeout = '15s'`);
      await c.query('LISTEN gate_sync');
    } catch (err) { await c.end().catch(() => undefined); throw err; }
    this.syncClient = c;
  }
  private syncLost(c: pg.Client, err: unknown): void {
    if (this.syncClient !== c) return;
    this.syncClient = undefined;
    void c.end().catch(() => undefined);
    // decisions stop once the bound passes; the next tick reconnects and reloads
    if (!this.closing) console.error(`State sync connection lost: ${message(err)}; reconnecting`);
  }
  /** One synchronisation at a time; a notification during one runs another right after. */
  sync(): Promise<void> {
    if (this.syncing) { this.syncAgain = true; return this.syncing; }
    this.syncing = (async () => {
      do { this.syncAgain = false; await this.syncOnce(); } while (this.syncAgain && !this.closing);
    })().catch((err: unknown) => console.error(`State sync failed: ${message(err)}`))
      .finally(() => { this.syncing = undefined; });
    return this.syncing;
  }
  private async syncOnce(): Promise<void> {
    if (this.closing || this.failure) return;
    await this.options.beforeSync?.();
    if (this.closing) return;
    if (!this.syncClient) {
      try { await this.connectSync(); } catch (err) { console.error(`State sync reconnect failed: ${message(err)}`); return; }
    }
    const c = this.syncClient!;
    const sent = performance.now();
    try {
      const row = (await c.query<{ version: string; records: string; performed: string; leader: string | null }>('SELECT version, records, performed, leader FROM gate_sync')).rows[0]!;
      // the leader is the only state writer: it never reloads (a reload could drop its unwritten changes)
      if (!this.leader && (Number(row.version) > this.synced.version || Number(row.records) > this.synced.records) && !await this.reloadDocs(c)) return;
      if (Number(row.performed) > this.synced.performed) await this.loadPerformed(c);
      if (!this.leader) this.leaderUrl = row.leader;
      this.confirmedAt = sent; // everything committed before `sent` is applied
    } catch (err) { this.syncLost(c, err); return; }
    if (!this.leader) await this.lead();
    else if (performance.now() - this.lastSweep >= TOKEN_SWEEP_INTERVAL) await this.sweepTokens();
  }
  /** False when the server refused the state (onReload threw): the node is then stale until a later reload holds. */
  private async reloadDocs(c: pg.Client, full = false): Promise<boolean> {
    await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    let version: number; let generation: number; let rows: Array<{ name: string; body: string }>;
    let deltas: RecordDelta[] | undefined;
    let snapshot: Awaited<ReturnType<typeof loadRecordSnapshot>> | undefined;
    try {
      const sync = (await c.query<{ version: string; records: string }>('SELECT version, records FROM gate_sync')).rows[0]!;
      version = Number(sync.version); generation = Number(sync.records);
      rows = (await c.query<{ name: string; body: string }>('SELECT name, body FROM gate_doc')).rows;
      await this.loadSubjects(c);
      if (!full && generation > this.synced.records) {
        // in the leader's order: deletes, then appends by the position the leader allocated in its array order
        const changes = (await c.query<ChangeRow>(`SELECT seq, kind, type, id, op, position, body, move FROM gate_state_change
          WHERE seq > $1 AND seq <= $2 ORDER BY seq, kind, position NULLS FIRST, type, id`, [this.synced.records, generation])).rows;
        const generations = new Set(changes.map((row) => Number(row.seq)));
        if (generations.size !== generation - this.synced.records || changes.length === 0 ||
          Number(changes[0]!.seq) !== this.synced.records + 1 || Number(changes.at(-1)!.seq) !== generation) {
          console.warn('State change log has a gap: reloading the record snapshot');
          full = true;
        } else if (changes.some((row) => row.move)) full = true; // a reorder: the snapshot is ordered by position
        else deltas = changes.map(parseChange);
      } else if (!full) deltas = [];
      if (full) snapshot = await loadRecordSnapshot(c);
      await c.query('COMMIT');
    } catch (err) { await c.query('ROLLBACK').catch(() => undefined); throw err; }
    const previous = this.docs.get('state') as { state: Awaited<ReturnType<typeof loadRecordSnapshot>> } | undefined;
    this.docs.clear();
    for (const row of rows) if (row.name !== CHECKPOINT) this.docs.set(row.name, JSON.parse(row.body));
    if (snapshot) materializeState(this.docs, snapshot);
    else if (previous) materializeState(this.docs, previous.state);
    this.dirty.clear(); this.stagedRecords.clear(); this.committedSaves = this.recordSaves;
    try { this.onReload?.(deltas); } catch (err) {
      // a bundle whose signature does not verify stays stale; retry the same generation at every tick
      this.confirmedAt = Number.NEGATIVE_INFINITY;
      console.error(`Shared state refused, not deciding until it verifies: ${message(err)}`);
      return false;
    }
    this.synced.version = version;
    this.synced.records = generation;
    this.wake();
    return true;
  }
  private async loadPerformed(c: pg.Client): Promise<void> {
    const rows = (await c.query<{ seq: string; body: string }>('SELECT seq, body FROM gate_performed WHERE seq > $1 ORDER BY seq', [this.synced.performed])).rows;
    const arrived: PerformedRow[] = [];
    for (const row of rows) {
      const seq = Number(row.seq);
      // a consumption (consumeToken) and the synchronisation may both load a row: it is applied once
      if (this.ownPerformed.delete(seq) || seq <= this.synced.performed) { this.synced.performed = Math.max(this.synced.performed, seq); continue; }
      this.synced.performed = seq;
      arrived.push(JSON.parse(row.body) as PerformedRow);
    }
    if (!arrived.length) return;
    if (this.onPerformed) this.onPerformed(arrived); else this.queuedPerformed.push(...arrived);
  }
  private async loadSegments(c: pg.Client): Promise<void> {
    const rows = (await c.query<{ node: string; body: string }>('SELECT node, body FROM gate_audit_segment ORDER BY node, seq')).rows;
    if (rows.length && !this.options.checkpointKey) throw new Error('Audit integrity failure: retention seals need SIGNING_KEY_SEAL');
    const grouped = new Map<string, unknown[]>();
    for (const row of rows) {
      let body: unknown; try { body = JSON.parse(row.body); } catch { throw new Error('Audit integrity failure: malformed retention seal'); }
      grouped.set(row.node, [...grouped.get(row.node) ?? [], body]);
    }
    const segments: AuditSegment[] = [];
    for (const [node, values] of grouped) {
      const valid = validSegments(values, this.options.checkpointKey!, node);
      if (!valid) throw new Error(`Audit integrity failure: retention seal of chain ${node}`);
      segments.push(...valid);
    }
    this.segments.splice(0, this.segments.length, ...segments);
  }
  /** In place: StagedAudit shares this array. */
  private async loadAnchors(c: pg.Client): Promise<void> {
    const rows = (await c.query<{ seq: string; hash: string; tsa: string; gen_time: Date; token: Buffer; heads: string | null }>('SELECT seq, hash, tsa, gen_time, token, heads FROM gate_anchor ORDER BY seq')).rows;
    this.anchors.splice(0, this.anchors.length, ...rows.map((row) => ({ seq: Number(row.seq), hash: row.hash, tsa: row.tsa, genTime: row.gen_time.toISOString(),
      token: row.token.toString('base64'), ...(row.heads === null ? {} : { heads: JSON.parse(row.heads) as Record<string, Head> }) })));
  }
  /** Tries the leader lock; on success the documents are reloaded first (the previous leader's session is over, so all it
   *  committed is visible), then this node writes them. Never two writers: the lock is held until this session ends. */
  private lead(): Promise<void> {
    return this.serial(async () => {
      if (this.leader || this.closing) return;
      if (!await this.tryLock()) return;
      try {
        if (!await this.reloadDocs(this.client, true)) {
          await this.client.query('SELECT pg_advisory_unlock($1)', [LEADER_LOCK]); // another node may lead on what it can verify
          return;
        }
        await this.loadAnchors(this.client); // the anchors the previous leader added since this node started
        await this.loadRetired(this.client); // every id retired so far: registering one again is reviewed
        await this.client.query('UPDATE gate_sync SET leader = $1', [this.options.advertiseUrl ?? null]);
      } catch (err) {
        // never hold the lock without leading: release it so this node or another can take over on the next attempt
        await this.client.query('SELECT pg_advisory_unlock($1)', [LEADER_LOCK]).catch(() => undefined);
        throw err;
      }
      this.leaderUrl = this.options.advertiseUrl ?? null;
      this.leader = true;
      console.info(`Node ${this.node} took the leader lock: the admin plane is served here`);
    }).catch((err: unknown) => console.error(`Leader takeover failed: ${message(err)}`));
  }
  /** Expired decision tokens can no longer be consumed; the leader deletes them once a minute. */
  private sweepTokens(): Promise<void> {
    this.lastSweep = performance.now();
    const at = Math.floor(Date.parse((this.options.now ?? (() => new Date().toISOString()))()) / 1000);
    return this.serial(async () => { await this.client.query('DELETE FROM gate_token WHERE exp < $1', [at - 60]); })
      .catch((err: unknown) => console.error(`Decision token sweep failed: ${message(err)}`));
  }

  // --- verification -----------------------------------------------------------------------------------------------
  private async runRecheck(): Promise<AuditPoint | false> {
    const expected = new Map<string, Head>([...this.seen, [this.node, { ...this.committed }]]);
    const anchors = [...this.anchors];
    let scans: Map<string, ChainScan>;
    let counters: Map<string, AuditCounters>;
    try {
      await this.ensureReader();
      this.readerSnapshot = true; // set before BEGIN is queued: a query queued after it would run inside the snapshot
      await this.reader.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      try {
        scans = await this.scan(this.reader, false, wanted(anchors, expected));
        counters = await this.loadCounters(this.reader);
        await this.reader.query('COMMIT');
      } catch (err) { await this.reader.query('ROLLBACK').catch(() => undefined); throw err; } finally { this.readerSnapshot = false; }
    } catch { throw new HttpError(503, 'unavailable', 'Storage unavailable'); }
    await this.tail; // a visible committed row must also have run the writer continuation that advances this.committed
    let chain = judge(scans, anchors, expected, undefined, this.sealedHeads());
    // rows in this node's chain that it never wrote
    if (chain.verified && (scans.get(this.node)?.head.seq ?? 0) > this.committed.seq) chain = { ...chain, verified: false, node: this.node, brokenAt: this.committed.seq + 1 };
    const live = liveHeads(chain.heads);
    // before installCounters takes this node's counters out of the map
    const snapshot = Object.fromEntries([...live.keys()].map((node) => [node, (counters.get(node) ?? AuditCounters.empty()).snapshot()]));
    if (chain.verified) {
      for (const [node, head] of chain.heads) if (node !== this.node) this.seen.set(node, head);
      this.installCounters(counters, false);
    }
    const result = chain.verified ? auditPoint(chain.heads) : false;
    this.markIntegrity(chain, chain.verified);
    this.lastRecheckAt = performance.now();
    this.lastCheckedAt = new Date().toISOString();
    this.lastRecheckResult = result;
    if (result) {
      if (this.fullChainAt === undefined && this.startup.from > 0) console.info(`Audit background verification complete: every chain verified from its genesis (${chain.length} rows)`);
      this.fullChainAt = this.lastCheckedAt;
    }
    if (result && result.seq > 0) this.storeCheckpoint({ heads: live, verifiedAt: this.lastCheckedAt, counters: snapshot });
    return result;
  }
  /** Through the writer queue, after the commits already queued; never part of a request's transaction. Leader only. */
  private storeCheckpoint(value: Checkpoint | null): void {
    const key = this.options.checkpointKey;
    if (!this.leader) return;
    if (value && !key) return; // an unauthenticated checkpoint would only be ignored
    const body = value && key ? checkpointBody(key, value) : null;
    void this.serial(async () => {
      await this.client.query('INSERT INTO gate_doc (name, body) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET body = EXCLUDED.body, updated_at = now()', [CHECKPOINT, JSON.stringify(body)]);
    }).catch((err: unknown) => console.error(`Audit checkpoint not ${value ? 'saved' : 'cleared'}: ${message(err)}`));
  }
  /** No checkpoint: every chain from its genesis. A checkpoint: for each chain it names, the rows up to it must all exist,
   *  the row at its seq and every anchored row must hash to themselves and to the recorded hashes, then the chain is
   *  followed from it to the head. A row rewritten before the checkpoint is left to the full recheck that starts in the
   *  background (docs/API.md §3.9.1). */
  private sealedHeads(): Map<string, Head> {
    return new Map(this.segments.map((segment) => [segment.node, segment.head] as const));
  }
  private async startupScan(client: pg.Client, stored: unknown): Promise<ChainCheck> {
    const key = this.options.checkpointKey;
    const sealed = this.sealedHeads();
    const full = async (): Promise<ChainCheck> => judge(await this.scan(client, true, wanted(this.anchors, new Map())), this.anchors, new Map(), undefined, sealed);
    // no key, or a checkpoint without a mac (older version, or stripped): the whole log, which never trusts less than a
    // checkpoint would
    const unauthenticated = !!stored && typeof stored === 'object' && !Array.isArray(stored) && !Object.hasOwn(stored, 'mac');
    if (stored === undefined || stored === null || !key || unauthenticated) return full();
    let checkpoint = parseCheckpoint(stored, key);
    const previous = this.options.previousCheckpointKey;
    if (!checkpoint && previous) {
      const old = parseCheckpoint(stored, previous);
      if (old && !this.options.rotating?.((name) => this.docs.get(name))) {
        // the previous key may be the one that leaked: after the rotation it vouches for nothing
        console.warn('Audit checkpoint authenticated only by SIGNING_KEY_SEAL_PREVIOUS while nothing at rest is sealed under it any more (the rotation is complete): not trusted; verifying every chain from its genesis before serving. Remove SIGNING_KEY_SEAL_PREVIOUS.');
        return full();
      }
      if (old) { checkpoint = old; this.rekeyed = old; this.checkpointRekeyed = true; }
    }
    if (!checkpoint) {
      console.error('Audit checkpoint does not match the stored chain (at seq 1): treated as tampering');
      return { verified: false, length: 0, brokenAt: 1, heads: new Map() };
    }
    for (const [node, head] of checkpoint.heads) {
      const broken = await this.checkPrefix(client, node, head);
      if (broken === 'rescan') return full();
      if (broken !== undefined) {
        console.error(`Audit checkpoint does not match the stored chain ${node} (at seq ${broken}): treated as tampering`);
        return { verified: false, length: head.seq, brokenAt: broken, node, heads: new Map() };
      }
    }
    this.startup.from = [...checkpoint.heads.values()].reduce((sum, h) => sum + h.seq, 0);
    const counts = new Map([...checkpoint.heads].map(([node]) => [node, AuditCounters.restore(checkpoint.counters?.[node])] as const));
    this.startCounters = [...counts.values()].every((c) => c !== undefined) ? counts as Map<string, AuditCounters> : undefined;
    return judge(await this.scan(client, true, wanted(this.anchors, new Map()), checkpoint.heads, this.startCounters), this.anchors, new Map(), checkpoint.heads, sealed);
  }
  /** The seq that breaks the prefix, 'rescan' when only derived metadata is off (the full scan repairs it), or undefined. */
  private async checkPrefix(client: pg.Client, node: string, checkpoint: Head): Promise<number | 'rescan' | undefined> {
    const sealed = segmentOf(this.segments, node)?.lastSeq ?? 0;
    if (checkpoint.seq < sealed) return checkpoint.seq;
    const counts = (await client.query<{ rows: string; meta: string }>(`
      SELECT (SELECT count(*) FROM gate_audit WHERE node = $2 AND seq > $3 AND seq <= $1) AS rows,
        (SELECT count(*) FROM gate_audit_meta WHERE node = $2 AND seq > $3 AND seq <= $1) AS meta`, [checkpoint.seq, node, sealed])).rows[0]!;
    const expected = checkpoint.seq - sealed;
    if (Number(counts.rows) !== expected) return checkpoint.seq;
    if (Number(counts.meta) !== expected) return 'rescan';
    const anchored = new Map(this.anchors.flatMap((a) => anchorEntries(a) ?? []).filter((e) => e.node === node && e.seq > sealed && e.seq <= checkpoint.seq).map((e) => [e.seq, e.hash]));
    const result = await client.query<StoredAuditRow>(`
      SELECT a.node, a.seq, a.record, m.seq AS meta_seq, m.ts, m.type, m.effect, m.subject, m.resource, m.rules
      FROM gate_audit a LEFT JOIN gate_audit_meta m ON m.node = a.node AND m.seq = a.seq
      WHERE a.node = $2 AND a.seq = ANY($1::bigint[]) ORDER BY a.seq`, [[checkpoint.seq, ...anchored.keys()], node]);
    this.startup.rowsRead += result.rows.length;
    for (const stored of result.rows) {
      const seq = Number(stored.seq);
      const row = sealedRecord(stored);
      if (!row || (seq === checkpoint.seq && row.hash !== checkpoint.hash) || (anchored.has(seq) && anchored.get(seq) !== row.hash)) return seq;
      if (!metadataMatches(row, stored)) return 'rescan';
    }
    return undefined;
  }
  /** Every chain in the table, plus those something expects (so a chain deleted whole still shows). `index`: the start,
   *  which repairs derived metadata; otherwise a recheck, for which a metadata mismatch is a break. */
  /** `counts`: per-chain counters each row read is added to (a start from the checkpoint; a chain it lacks starts empty). */
  private async scan(client: pg.Client, index: boolean, want: ReadonlyMap<string, ReadonlySet<number>>, from?: ReadonlyMap<string, Head>,
    counts?: Map<string, AuditCounters>): Promise<Map<string, ChainScan>> {
    if (!index) await this.options.onScanStart?.();
    const nodes = new Set([...await listNodes(client), ...want.keys(), ...(from?.keys() ?? []), this.node]);
    const scans = new Map<string, ChainScan>();
    for (const node of [...nodes].sort(byName)) {
      if (counts && !counts.has(node)) counts.set(node, AuditCounters.empty());
      scans.set(node, await this.scanChain(client, node, index, want.get(node) ?? new Set(), from?.get(node), counts?.get(node)));
    }
    return scans;
  }
  private async scanChain(client: pg.Client, node: string, index: boolean, want: ReadonlySet<number>, from?: Head, count?: AuditCounters): Promise<ChainScan> {
    const sealed = segmentOf(this.segments, node)?.head ?? START;
    const start = from ?? sealed;
    if (start.seq < sealed.seq) return { length: 0, brokenAt: start.seq, head: start, at: new Map() };
    let cursor = start.seq, length = count?.total ?? (from ? from.seq - sealed.seq : 0), expected = cursor + 1;
    let brokenAt: number | undefined, prev = start.hash;
    const at = new Map<number, string>([[cursor, prev]]);
    for (;;) {
      const result = await client.query<StoredAuditRow>(`
        SELECT a.node, a.seq, a.record, m.seq AS meta_seq, m.ts, m.type, m.effect, m.subject, m.resource, m.rules
        FROM gate_audit a LEFT JOIN gate_audit_meta m ON m.node = a.node AND m.seq = a.seq
        WHERE a.node = $1 AND a.seq > $2::bigint ORDER BY a.seq LIMIT $3`, [node, cursor, AUDIT_STREAM_BATCH]);
      if (!result.rows.length) break;
      if (!index) await this.options.onScanBatch?.();
      else this.startup.rowsRead += result.rows.length;
      const repairs: AuditRecord[] = [];
      for (const stored of result.rows) {
        length++;
        if (brokenAt !== undefined) continue;
        const row = sealedRecord(stored);
        if (!row || row.seq !== expected || row.prevHash !== prev) { brokenAt = expected; continue; }
        if (!metadataMatches(row, stored)) {
          if (!index) { brokenAt = expected; continue; }
          repairs.push(row); this.metaRepairs.push({ node, seq: row.seq });
        }
        prev = row.hash; expected++;
        count?.add(row);
        if (want.has(row.seq)) at.set(row.seq, prev);
      }
      if (repairs.length) await insertMetadata(client, node, repairs);
      cursor = Number(result.rows.at(-1)!.seq);
      if (result.rows.length < AUDIT_STREAM_BATCH) break;
    }
    return { length, ...(brokenAt === undefined ? {} : { brokenAt }), head: { seq: expected - 1, hash: prev }, at };
  }
  private async recordMetaRepair(): Promise<void> {
    if (!this.metaRepairs.length) return;
    const seqs = this.metaRepairs.map((r) => r.seq);
    const chains = [...new Set(this.metaRepairs.map((r) => r.node))];
    const foreign = chains.some((n) => n !== LEGACY_NODE);
    const details = { seqs: seqs.slice(0, 100), count: seqs.length, first: seqs[0]!, last: seqs.at(-1)!, ...(foreign ? { chains: chains.slice(0, 100) } : {}) };
    console.warn(`Audit metadata repaired: count=${details.count}, range=${details.first}-${details.last}, first sequences=${details.seqs.join(',')}${foreign ? `, chains=${chains.join(',')}` : ''}`);
    if (this.initial.verified) {
      const head = this.initial.heads.get(this.node) ?? START;
      const record = JSON.parse(JSON.stringify({ type: 'security', actor: 'system', action: 'meta_repaired', details,
        ...(this.node === LEGACY_NODE ? {} : { node: this.node }),
        seq: head.seq + 1, ts: (this.options.now ?? (() => new Date().toISOString()))(), prevHash: head.hash })) as Omit<AuditRecord, 'hash'>;
      const row = { ...record, hash: sha256(record.prevHash + canonical(record)) };
      await insertAudit(this.client, this.node, [row]);
      this.startCounters?.get(this.node)?.add(row);
      this.initial = { verified: true, length: this.initial.length + 1, heads: new Map(this.initial.heads).set(this.node, { seq: row.seq, hash: row.hash }) };
    }
    this.metaRepairs.length = 0;
  }
  private listedRecord(stored: StoredAuditRow): AuditRecord {
    try {
      const row = JSON.parse(stored.record) as AuditRecord;
      if (Number(stored.seq) !== row.seq || (row.node ?? LEGACY_NODE) !== stored.node || !metadataMatches(row, stored)) throw new Error('Audit metadata mismatch');
      return row;
    } catch {
      const chain: ChainCheck = { verified: false, length: this.auditTotal(), brokenAt: Number(stored.seq), node: stored.node, heads: new Map() };
      this.markIntegrity(chain, false);
      throw new HttpError(503, 'unavailable', 'Audit integrity failure');
    }
  }
  private watchReader(client: pg.Client): void {
    client.on('error', (err) => {
      if (client !== this.reader || this.closing) return;
      this.readFailure = err;
      console.error(`Audit read connection failed: ${err.message}; reconnecting`);
      void client.end().catch(() => undefined);
      void this.scheduleReaderReconnect();
    });
  }
  private scheduleReaderReconnect(): Promise<void> {
    if (this.reconnecting) return this.reconnecting;
    const delay = Math.min(100 * 2 ** this.reconnectAttempts++, 2000);
    this.reconnecting = (async () => {
      await new Promise<void>((resolve) => {
        this.reconnectWake = resolve;
        this.reconnectTimer = setTimeout(resolve, delay); this.reconnectTimer.unref();
      });
      this.reconnectTimer = undefined; this.reconnectWake = undefined;
      if (this.closing) return;
      const replacement = createReader(this.databaseUrl, this.options.databaseTls!);
      try {
        await replacement.connect();
        await replacement.query(`SET default_transaction_read_only = 'on'`);
        await replacement.query(`SET statement_timeout = '15s'`);
        this.reader = replacement;
        this.readFailure = undefined;
        this.reconnectAttempts = 0;
        this.watchReader(replacement);
        console.error('Audit read connection restored');
      } catch (err) {
        await replacement.end().catch(() => undefined);
        this.readFailure = err instanceof Error ? err : new Error(String(err));
        console.error(`Audit read reconnect failed: ${this.readFailure.message}`);
      }
    })().finally(() => {
      this.reconnecting = undefined;
      if (this.readFailure && !this.closing) void this.scheduleReaderReconnect();
    });
    return this.reconnecting;
  }
  private async ensureReader(): Promise<void> {
    if (this.closing) throw new HttpError(503, 'unavailable', 'Storage unavailable');
    if (this.readFailure) await this.scheduleReaderReconnect();
    if (this.readFailure) throw new HttpError(503, 'unavailable', 'Storage unavailable');
  }
  private async read<T>(task: () => Promise<T>): Promise<T> {
    try {
      await this.ensureReader();
      this.ensureReadable();
      const value = await task();
      this.ensureReadable();
      return value;
    } catch (err) {
      if (err instanceof HttpError) throw err;
      throw new HttpError(503, 'unavailable', 'Storage unavailable');
    }
  }
  private markIntegrity(chain: ChainCheck, ok: boolean): void {
    if (!ok) {
      // the next start must read the whole chain again: it is the one that refuses to serve a tampered log
      if (!this.integrityFailure) {
        this.storeCheckpoint(null);
        if (this.audit) console.error(`AUDIT INTEGRITY FAILURE: chain ${chain.node ?? LEGACY_NODE} breaks at seq ${chain.brokenAt ?? '?'}. Audit appends are refused, so decisions and audited writes fail and /readyz answers 503; the checkpoint is cleared, so a restart verifies the whole chain and refuses it. Follow docs/handbook/operations/audit-tamper-response.md`);
      }
      this.integrityFailure = chain;
      this.lastCheckedAt = new Date().toISOString();
      if (!this.audit) this.initial = chain;
    }
    this.audit?.checked(chain, ok);
  }
  private ensureReadable(): void {
    if (this.readFailure || this.integrityFailure || !this.initial.verified || this.audit?.tampered) throw new HttpError(503, 'unavailable', 'Audit unavailable');
  }
  /** `own`: the start, which also counts this node's chain; a recheck replaces only the others' (this node's are live). */
  private installCounters(counters: Map<string, AuditCounters>, own: boolean): void {
    if (own) this.counters = counters.get(this.node) ?? AuditCounters.empty();
    counters.delete(this.node);
    this.otherCounters = counters;
  }
  private async loadCounters(client: pg.Client): Promise<Map<string, AuditCounters>> {
    const totals = (await client.query<{ node: string; count: string }>('SELECT node, count(*) AS count FROM gate_audit GROUP BY node')).rows;
    const types = (await client.query<{ node: string; type: string; count: string }>(`
      SELECT m.node, m.type, count(*) AS count FROM gate_audit a JOIN gate_audit_meta m ON m.node = a.node AND m.seq = a.seq GROUP BY m.node, m.type`)).rows;
    const all = await this.loadEvidence(client);
    const controls: Array<Map<string, EvidenceRow>> = [];
    for (const rules of RULE_SETS) controls.push(await this.loadEvidence(client, rules));
    const result = new Map<string, AuditCounters>();
    for (const { node, count } of totals) {
      const counters = new AuditCounters();
      counters.reset(Number(count), types.filter((t) => t.node === node), all.get(node) ?? EMPTY_EVIDENCE(), controls.map((c) => c.get(node) ?? EMPTY_EVIDENCE()));
      result.set(node, counters);
    }
    return result;
  }
  private async loadEvidence(client: pg.Client, rules?: readonly string[]): Promise<Map<string, EvidenceRow>> {
    const result = await client.query<{ node: string; total: string; decisions: string; denies: string; last_seen: string | null; last_seq: string | null }>(`
      SELECT m.node, count(*) AS total, count(*) FILTER (WHERE m.type = 'decision') AS decisions,
        count(*) FILTER (WHERE m.type = 'decision' AND m.effect = 'deny') AS denies,
        (array_agg(m.ts ORDER BY m.seq DESC))[1] AS last_seen, max(m.seq) AS last_seq
      FROM gate_audit a JOIN gate_audit_meta m ON m.node = a.node AND m.seq = a.seq
      ${rules ? 'WHERE m.rules && $1::text[]' : ''} GROUP BY m.node`, rules ? [rules.map((rule) => JSON.stringify(rule))] : []);
    return new Map(result.rows.map((row) => [row.node, { total: Number(row.total), decisions: Number(row.decisions), denies: Number(row.denies), lastSeen: row.last_seen, lastSeq: Number(row.last_seq ?? 0) }]));
  }
  private fail(err: Error): void {
    if (this.failure) return;
    this.failure = err;
    this.onFatal(err);
  }
}

async function writeSession(c: pg.Client, s: SessionOp): Promise<void> {
  if (s.op === 'insert') {
    const { user, method, oidc, created, touched } = s.session;
    await c.query('INSERT INTO gate_session (id, body, method, oidc_sub, oidc_sid, created, touched) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [s.key, JSON.stringify({ user, method, ...(oidc ? { oidc } : {}) }), method, oidc?.sub ?? null, oidc?.sid ?? null, created, touched]);
  } else if (s.op === 'touch') await c.query('UPDATE gate_session SET touched = $2 WHERE id = $1 AND touched < $2', [s.key, s.at]);
  else if (s.op === 'remove') await c.query('DELETE FROM gate_session WHERE id = $1', [s.key]);
  else await c.query('DELETE FROM gate_session WHERE touched <= $1 OR created <= $2', [s.touchedBefore, s.createdBefore]);
}

function createReader(url: string, databaseTls: DatabaseTls): pg.Client {
  return new pg.Client(postgresClientConfig(url, databaseTls, 'demo', { application_name: 'gate_audit_reader', keepAlive: true, keepAliveInitialDelayMillis: 10_000 }));
}

