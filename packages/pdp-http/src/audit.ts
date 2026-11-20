import { appendFileSync, closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, statSync, writeFileSync, writeSync } from 'node:fs';
import { open, type FileHandle } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { canonical } from '../../core/src/index.ts';
import { auditMac, macMatches, sealSegment, segmentOf, validSegments, type AuditSegment, type RetentionPlan, type SegmentSeal } from './audit-integrity.ts';
import { pseudonymiseEvent, type SubjectIdentities } from './audit-subjects.ts';

export interface AuditRecord {
  /** The node whose chain holds the row (PostgreSQL cluster); absent for chain "0", the single chain of earlier versions. */
  node?: string;
  seq: number; ts: string; type: string; actor: string; action: string;
  subject?: string; resource?: string; effect?: 'allow' | 'deny'; rules?: readonly string[];
  policyVersion?: string; details?: Record<string, unknown>; prevHash: string; hash: string;
}
/** Every row type the server writes; the audit API's type filter accepts exactly these (test: audit-types.test.ts). */
export const AUDIT_TYPES = ['decision', 'change', 'session', 'break_glass', 'security', 'simulation'] as const;
export type AuditType = typeof AUDIT_TYPES[number];
export type AuditEvent = Omit<AuditRecord, 'seq' | 'ts' | 'prevHash' | 'hash' | 'type'> & { type: AuditType };
export const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');
/** Longest string kept whole in an audit row, and the largest row: a sign-in name, a refused route or an XACML attribute
 *  id comes from unauthenticated callers, so nothing they send grows the hash-chained log without bound. */
export const AUDIT_MAX_STRING = 512;
export const AUDIT_MAX_ROW = 16_384;
/** A long string keeps a prefix, a marker and the SHA-256 of the full value (evidence of what was sent, at a fixed cost). */
export function boundString(value: string): string {
  return value.length <= AUDIT_MAX_STRING ? value : `${value.slice(0, 128)}…[truncated ${value.length} chars, sha256:${sha256(value)}]`;
}
const bounded = (value: unknown): unknown => typeof value === 'string' ? boundString(value)
  : Array.isArray(value) ? value.map(bounded)
  : value !== null && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([k, v]) => [boundString(k), bounded(v)])) : value;
/** Every string bounded; a row still over AUDIT_MAX_ROW keeps its identity fields, its rules and details replaced by a digest. */
export function boundEvent(event: AuditEvent): AuditEvent {
  const e = bounded(JSON.parse(JSON.stringify(event))) as AuditEvent;
  if (JSON.stringify(e).length <= AUDIT_MAX_ROW) return e;
  const dropped = JSON.stringify({ rules: e.rules, details: e.details });
  const { rules: _rules, ...rest } = e;
  return { ...rest, details: { truncated: true, bytes: dropped.length, sha256: sha256(dropped) } };
}
export const GENESIS = '0'.repeat(64);
/** The chain of a single node, and of every row written before chains were per node. */
export const LEGACY_NODE = '0';
export interface Head { seq: number; hash: string }
/** A chain head timestamped by an RFC 3161 authority (token: DER TimeStampToken, base64). With several chains, `heads`
 *  lists each chain's head, `hash` is sha256(canonical(heads)) and `seq` the sum of their seqs. */
export interface Anchor { seq: number; hash: string; tsa: string; genTime: string; token: string; heads?: Record<string, Head> }
export interface AuditList {
  /** Rows after (node, cursor); node absent: chain "0" when cursor > 0, else from the first row of the first chain. */
  cursor: number; limit: number; node?: string;
  effect?: 'allow' | 'deny'; rule?: string; subject?: string; resource?: string;
  /** The stored actor (a pseudonym when the subject mapping is on); every `list` implementation must apply it. */
  actor?: string;
  type?: AuditType;
}
export interface AuditPage { items: AuditRecord[]; next: string | null }
export interface AuditEvidence { decisions: number; denies: number; lastSeen: string | null }
export interface ErasureResult { pseudonym: string; erased: boolean; changeId?: string }
export interface ErasureReference { changeId: string; approvedBy: string }
/** What the runtime needs from an audit log, whichever store keeps it. */
export interface AuditLog {
  readonly anchors: Anchor[];
  readonly segments?: readonly AuditSegment[];
  records(): AuditRecord[];
  tip(): { seq: number; hash: string };
  verify(): { verified: boolean; length: number; brokenAt?: number; node?: string; checkedAt?: string; fullChain?: boolean };
  /** PostgreSQL: every chain verified from its genesis or sealed head since this process started (false while a start
   *  from the checkpoint waits for its background verification, and after an integrity failure). The file log verifies it all. */
  readonly fullChainVerified?: boolean;
  append(event: AuditEvent): void;
  list?(query: AuditList): Promise<AuditPage>;
  /** Committed rows after each chain's position in `after`, chain by chain (export and SIEM push); with `until`, only
   *  the chains it names, up to their seq there (inclusive). */
  exportBatch?(after: ReadonlyMap<string, number>, limit: number, until?: ReadonlyMap<string, number>): Promise<AuditRecord[]>;
  countScoped?(resources: readonly string[], type?: string): Promise<number>;
  evidence?(ruleIds: readonly string[], includeAll: boolean): AuditEvidence;
  recheck?(): Promise<{ seq: number; hash: string; heads?: Record<string, Head> } | false>;
  /** Existing mapping only: looking up an erased or unknown id never creates a fresh link. */
  subjectPseudonym?(id: string): string | undefined;
  /** Admin display only: the raw id while its mapping exists, never a new mapping after erasure. */
  displayIdentity?(pseudonym: string): string | undefined;
  eraseSubject?(id: string, actor: string, reference?: ErasureReference): Promise<ErasureResult>;
  /** Deletes the mappings of ids outside `keep` (the world subjects) idle for SUBJECT_IDLE_DAYS; returns how many. */
  purgeSubjects?(keep: readonly string[]): Promise<number>;
}
/** Hash chain check. After retention, an authenticated segment supplies the starting head and old anchors are covered by it. */
export function verifyChain(rows: readonly unknown[], anchors: readonly Anchor[] = [], segments: readonly AuditSegment[] = [], node = LEGACY_NODE): { verified: boolean; length: number; brokenAt?: number; head: string } {
  const sealed = segmentOf(segments, node);
  let prev = sealed?.head.hash ?? GENESIS;
  let expected = (sealed?.lastSeq ?? 0) + 1;
  const hashes = new Map<number, string>();
  for (const row of rows) {
    const broken = { verified: false, length: rows.length, brokenAt: expected, head: prev };
    if (!row || typeof row !== 'object' || Array.isArray(row)) return broken;
    const { hash, ...rest } = row as AuditRecord;
    if (rest.seq !== expected || rest.prevHash !== prev || sha256(prev + canonical(rest)) !== hash) return broken;
    prev = hash; hashes.set(expected, prev); expected++;
  }
  const bad = anchors.find((a) => a.seq > (sealed?.lastSeq ?? 0) && hashes.get(a.seq) !== a.hash);
  if (bad) return { verified: false, length: rows.length, brokenAt: bad.seq, head: prev };
  return { verified: true, length: rows.length, head: prev };
}

interface FileCheckpoint { seq: number; hash: string; verifiedAt: string; mac: string }
export interface AuditOptions {
  checkpointKey?: Buffer;
  previousCheckpointKey?: Buffer;
  /** True only while values at rest still need the previous seal; otherwise a full scan re-keys, never trusts, its checkpoint. */
  checkpointRotationInProgress?: boolean;
  /** AUDIT_CHECKPOINT_MIGRATE: the reviewed head hash of an older unkeyed, non-empty chain, authenticated once at its first
   *  keyed start. Any other head (a rewritten chain, or the same chain after it grew) is refused as before. */
  checkpointMigration?: string;
  subjects?: SubjectIdentities;
  /** The chain id written into every row (a replica's own chain, shipped to gate_audit as that node's chain). */
  node?: string;
  /** Replica mode: rows are answered only once flush() made them durable (one fdatasync per group). Every row carries an
   *  HMAC under checkpointKey (rowMac), so the file is authenticated row by row; the keyed checkpoint, written at most
   *  once a second off the answer path, still detects a truncation below it. */
  durable?: boolean;
  /** Durable mode: the rows each flush made durable, in order (the replica ships them to the leader). */
  onDurable?: (rows: readonly AuditRecord[]) => void;
}
const checkpointBody = (key: Buffer, head: Head, verifiedAt: string): FileCheckpoint => {
  const signed = { seq: head.seq, hash: head.hash, verifiedAt };
  return { ...signed, mac: auditMac(key, signed) };
};
const parseCheckpoint = (value: unknown, key: Buffer): Head | undefined => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const { seq, hash, verifiedAt, mac } = value as Record<string, unknown>;
  if (!Number.isSafeInteger(seq) || (seq as number) < 0 || typeof hash !== 'string' || !/^[0-9a-f]{64}$/.test(hash) ||
    typeof verifiedAt !== 'string' || typeof mac !== 'string' || !macMatches(key, { seq, hash, verifiedAt }, mac)) return undefined;
  return { seq: seq as number, hash };
};
const atomicText = (file: string, text: string): void => {
  const temp = `${file}.${randomUUID()}.tmp`;
  writeFileSync(temp, text, { mode: 0o600 });
  renameSync(temp, file);
};
const atomic = (file: string, value: unknown): void => atomicText(file, JSON.stringify(value, null, 2) + '\n');
const syncDir = (file: string): void => { const fd = openSync(dirname(file), 'r'); try { fsyncSync(fd); } finally { closeSync(fd); } };
/** atomicText that survives a power loss: the temporary file and the directory entry are fsynced around the rename. */
const durableText = (file: string, text: string): void => {
  const temp = `${file}.${randomUUID()}.tmp`;
  const fd = openSync(temp, 'w', 0o600);
  try { writeFileSync(fd, text); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(temp, file); syncDir(file);
};
/** Durable mode keeps its keyed checkpoint in two fixed slots of one file, overwritten in place in turn (one write and
 *  one fdatasync per group, no rename): a write torn by a crash leaves the other slot, the previous checkpoint, valid. */
const SLOT = 512;
const CHECKPOINT_EVERY_MS = 1000;
/** Durable chains: HMAC-SHA256 of a row without its hash and mac (prevHash included, so the MACs chain too). */
export const rowMac = (key: Buffer, row: object): string => {
  const { hash: _hash, mac: _mac, ...rest } = row as Record<string, unknown>;
  return auditMac(key, rest);
};
export const rowMacValid = (key: Buffer, row: unknown): boolean => {
  const mac = (row as { mac?: unknown } | null)?.mac;
  return typeof mac === 'string' && /^[0-9a-f]{64}$/.test(mac) && macMatches(key, (({ hash: _h, mac: _m, ...rest }) => rest)(row as Record<string, unknown>), mac);
};
const slotText = (body: unknown): Buffer => {
  const text = JSON.stringify(body);
  if (text.length >= SLOT) throw new Error('Audit checkpoint does not fit its slot');
  return Buffer.from(text.padEnd(SLOT - 1, ' ') + '\n');
};

export class Audit implements AuditLog {
  readonly file: string;
  readonly checkpointFile: string;
  readonly segmentFile: string;
  anchors: Anchor[] = [];
  segments: AuditSegment[] = [];
  private stamp?: string;
  private fingerprint(): string {
    if (!existsSync(this.file)) return 'absent';
    const s = statSync(this.file, { bigint: true });
    return `${s.dev}:${s.ino}:${s.size}:${s.mtimeNs}:${s.ctimeNs}`;
  }
  private head?: Head;
  /** What this start's verification accepted beyond an exact checkpoint match: audited once the chain is open. */
  private startNotice?: { action: 'checkpoint_migrated' | 'checkpoint_completed' | 'torn_row_dropped'; seq: number };
  /** Durable mode: appended rows the next flush makes durable, the last durable head, and the flush queue. */
  private unflushed: AuditRecord[] = [];
  private durableHead?: Head;
  private flushTail: Promise<void> = Promise.resolve();
  private slots?: FileHandle;
  private checkpointedAt = Number.NEGATIVE_INFINITY;
  /** The slot the next durable checkpoint overwrites: never the one holding the newest valid checkpoint. */
  private slot = 0;
  private queuedFlush?: Promise<void>;
  private broken?: Error;
  private readonly now: () => string;
  private readonly options: AuditOptions;
  constructor(file: string, now: () => string, options: AuditOptions = {}) {
    this.file = file; this.now = now; this.options = options;
    if (options.durable && !options.checkpointKey) throw new Error('A durable audit chain needs a checkpoint key');
    this.checkpointFile = resolve(dirname(file), options.durable ? 'audit-checkpoint.slots' : 'audit-checkpoint.json');
    this.segmentFile = resolve(dirname(file), 'audit-segments.json');
    this.verify();
    this.durableHead = this.head;
    if (this.startNotice) this.append({ type: 'security', actor: 'system', action: this.startNotice.action,
      details: { seq: this.startNotice.seq, hash: this.tip().hash } });
  }
  records(): AuditRecord[] {
    if (!existsSync(this.file)) return [];
    return readFileSync(this.file, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line) as AuditRecord);
  }
  private readSegments(): AuditSegment[] | undefined {
    if (!existsSync(this.segmentFile)) return [];
    if (!this.options.checkpointKey) return undefined;
    let stored: unknown;
    try { stored = JSON.parse(readFileSync(this.segmentFile, 'utf8')); } catch { return undefined; }
    if (!Array.isArray(stored)) return undefined;
    const current = validSegments(stored, this.options.checkpointKey, LEGACY_NODE);
    if (current) return current;
    if (!this.options.previousCheckpointKey) return undefined;
    const previous = validSegments(stored, this.options.previousCheckpointKey, LEGACY_NODE);
    if (!previous) return undefined;
    const rekeyed = previous.map(({ mac: ignored, ...signed }) => sealSegment(this.options.checkpointKey!, signed));
    atomic(this.segmentFile, rekeyed);
    return rekeyed;
  }
  private storeCheckpoint(head: Head): void {
    if (!this.options.checkpointKey) return;
    const body = checkpointBody(this.options.checkpointKey, head, this.now());
    if (!this.options.durable) { atomic(this.checkpointFile, body); return; }
    const fresh = !existsSync(this.checkpointFile);
    const fd = openSync(this.checkpointFile, fresh ? 'w' : 'r+', 0o600);
    // a new file gets both slots; afterwards only the older one is overwritten
    try { for (const slot of fresh ? [0, 1] : [this.slot]) writeSync(fd, slotText(body), 0, SLOT, slot * SLOT); fsyncSync(fd); } finally { closeSync(fd); }
    if (fresh) syncDir(this.checkpointFile);
    this.slot ^= 1;
  }
  /** Durable mode: the newest valid slot must name a row of the chain (or its sealed head) at or below its head. Rows
   *  past it are authenticated by their own MACs; a chain shorter than its checkpoint was truncated. */
  private durableCheckpoint(rows: readonly AuditRecord[], sealed: Head | undefined, actual: Head): Head | undefined {
    if (!existsSync(this.checkpointFile)) {
      if (actual.seq !== 0) return undefined;
      this.storeCheckpoint(actual);
      return actual;
    }
    const raw = readFileSync(this.checkpointFile);
    const slots = [0, 1].map((slot) => {
      try { return parseCheckpoint(JSON.parse(raw.subarray(slot * SLOT, (slot + 1) * SLOT).toString('utf8')), this.options.checkpointKey!); } catch { return undefined; }
    });
    const newest = slots[1] && (!slots[0] || slots[1].seq > slots[0].seq) ? 1 : 0;
    const checkpoint = slots[newest];
    if (!checkpoint || checkpoint.seq > actual.seq) return undefined;
    if (!this.head) this.slot = newest ^ 1; // at runtime a flush may be writing the other slot right now
    const base = sealed ?? { seq: 0, hash: GENESIS };
    const at = checkpoint.seq === base.seq ? base : rows.find((row) => row.seq === checkpoint.seq);
    return at && at.hash === checkpoint.hash ? actual : undefined;
  }
  private checkpoint(actual: Head, previous?: Head): boolean {
    const key = this.options.checkpointKey;
    if (!existsSync(this.checkpointFile)) {
      if (!key) return true; // legacy demo without a keyed checkpoint
      if (actual.seq === 0) { this.storeCheckpoint(actual); return true; }
      // a deleted checkpoint is never re-minted: that would authenticate whatever chain an attacker rewrote (downgrade)
      if (this.options.checkpointMigration !== actual.hash) {
        console.error(`Audit integrity failure: no checkpoint for a non-empty chain (head seq ${actual.seq}, hash ${actual.hash}). ` +
          'Only for the first keyed start of a reviewed older chain: set AUDIT_CHECKPOINT_MIGRATE to that hash, once (docs/DEPLOY.md).');
        return false;
      }
      this.storeCheckpoint(actual); this.startNotice = { action: 'checkpoint_migrated', seq: actual.seq };
      return true;
    }
    if (!key) return false;
    let stored: unknown;
    try { stored = JSON.parse(readFileSync(this.checkpointFile, 'utf8')); } catch { return false; }
    const accepts = (checkpoint: Head): boolean => {
      if (checkpoint.seq === actual.seq && checkpoint.hash === actual.hash) return true;
      // appendFileSync preceded the checkpoint rename: only that one-row crash window may be completed.
      // At runtime the in-memory head refuses any external row first, so this applies at start only, and is audited.
      if (previous && checkpoint.seq === actual.seq - 1 && checkpoint.hash === previous.hash) {
        this.storeCheckpoint(actual); this.startNotice = { action: 'checkpoint_completed', seq: actual.seq };
        return true;
      }
      return false;
    };
    const current = parseCheckpoint(stored, key);
    if (current && accepts(current)) return true;
    if (this.options.previousCheckpointKey) {
      const previousKey = parseCheckpoint(stored, this.options.previousCheckpointKey);
      if (previousKey && (this.options.checkpointRotationInProgress || this.options.checkpointRotationInProgress === false) && accepts(previousKey)) {
        this.storeCheckpoint(actual);
        return true;
      }
    }
    return false;
  }
  verify(): { verified: boolean; length: number; brokenAt?: number } {
    const raw = existsSync(this.file) ? readFileSync(this.file, 'utf8') : '';
    if (this.options.durable && !this.head && raw && !raw.endsWith('\n')) {
      // a crash during an append: that row never reached an fdatasync, so it was never answered
      durableText(this.file, raw.slice(0, raw.lastIndexOf('\n') + 1));
      this.startNotice = { action: 'torn_row_dropped', seq: 0 };
      return this.verify();
    }
    const lines = raw === '' ? [] : (raw.endsWith('\n') ? raw.slice(0, -1) : raw).split('\n');
    const rows: unknown[] = [];
    for (const [i, line] of lines.entries()) {
      try { rows.push(JSON.parse(line)); } catch { return { verified: false, length: lines.length, brokenAt: i + 1 }; }
    }
    const segments = this.readSegments();
    if (!segments) return { verified: false, length: lines.length, brokenAt: 1 };
    const latest = segmentOf(segments, LEGACY_NODE);
    const pending = latest ? rows.slice(0, latest.removed) as AuditRecord[] : [];
    // a crash after the segment rename left the old prefix: its authenticated seal lets this start finish the truncation
    if (latest && pending.length === latest.removed && latest.removed > 0 && pending.every((row, i) => row.seq === latest.firstSeq + i) &&
      sha256(canonical(pending)) === latest.prefixHash && pending.at(-1)?.hash === latest.head.hash) {
      const kept = rows.slice(latest.removed);
      const write = this.options.durable ? durableText : atomicText;
      write(this.file, kept.map((row) => JSON.stringify(row)).join('\n') + (kept.length ? '\n' : ''));
      return this.verify();
    }
    const chain = verifyChain(rows, this.anchors, segments);
    if (!chain.verified) return { verified: false, length: lines.length, brokenAt: chain.brokenAt };
    if (raw && !raw.endsWith('\n')) return { verified: false, length: lines.length, brokenAt: (rows.at(-1) as AuditRecord | undefined)?.seq ?? 1 };
    const sealed = segmentOf(segments, LEGACY_NODE);
    const last = rows.at(-1) as AuditRecord | undefined;
    const actual = { seq: last?.seq ?? sealed?.lastSeq ?? 0, hash: chain.head };
    if (this.head && (actual.seq < this.head.seq || (this.head.seq > 0 && actual.hash !== this.head.hash))) {
      return { verified: false, length: lines.length, brokenAt: Math.min(this.head.seq, actual.seq + 1) };
    }
    let accepted: Head = actual;
    if (this.options.durable) {
      const forged = (rows as AuditRecord[]).find((row) => !rowMacValid(this.options.checkpointKey!, row));
      if (forged) return { verified: false, length: lines.length, brokenAt: forged.seq };
      const durable = this.durableCheckpoint(rows as AuditRecord[], sealed ? { seq: sealed.lastSeq, hash: sealed.head.hash } : undefined, actual);
      if (!durable) return { verified: false, length: lines.length, brokenAt: actual.seq || 1 };
      accepted = durable;
    } else {
      const prior = rows.at(-2) as AuditRecord | undefined;
      const previous = actual.seq === 0 ? undefined : prior ? { seq: prior.seq, hash: prior.hash }
        : actual.seq - 1 === (sealed?.lastSeq ?? 0) ? { seq: sealed?.lastSeq ?? 0, hash: sealed?.head.hash ?? GENESIS } : undefined;
      if (!this.checkpoint(actual, previous)) return { verified: false, length: lines.length, brokenAt: actual.seq || 1 };
    }
    this.head = accepted; this.segments = segments;
    this.stamp = this.fingerprint();
    return { verified: true, length: lines.length };
  }
  /** Last verified record or sealed segment head; anchoring timestamps this. */
  tip(): Head { return this.head ?? { seq: 0, hash: GENESIS }; }
  subjectPseudonym(id: string): string | undefined { return this.options.subjects?.lookup(id); }
  displayIdentity(pseudonym: string): string | undefined { return this.options.subjects?.identity(pseudonym); }
  async eraseSubject(id: string, actor: string, reference?: ErasureReference): Promise<ErasureResult> {
    if (!this.options.subjects) throw new Error('Audit subject mapping is not configured');
    const pseudonym = this.options.subjects.lookup(id);
    if (!pseudonym) return { pseudonym: '', erased: false };
    // audited first, as in PostgreSQL mode: an erasure the audit refuses erases nothing
    this.append({ type: 'security', actor, action: 'subject_erased', details: { pseudonym, ...(reference ?? {}) } });
    this.options.subjects.erase(id);
    return { pseudonym, erased: true, ...(reference ? { changeId: reference.changeId } : {}) };
  }
  async purgeSubjects(keep: readonly string[]): Promise<number> {
    // audited first, as erasure: a purge the audit refuses removes nothing; the row carries the count, never an id
    return this.options.subjects?.purgeIdle?.(keep, (count) => this.append({ type: 'security', actor: 'system', action: 'subject_mappings_purged', details: { count } })) ?? 0;
  }
  append(event: AuditEvent): void {
    if (this.broken) throw new Error('Audit storage failed');
    if ((!this.head || this.stamp !== this.fingerprint()) && !this.verify().verified) throw new Error('Audit integrity failure');
    const pseudonymised = this.options.subjects ? pseudonymiseEvent(event, (id, decisionSubject) => this.options.subjects!.pseudonym(id, decisionSubject)) : event;
    const prevHash = this.head!.hash;
    const node = this.options.node ? { node: this.options.node } : {};
    const unsigned = JSON.parse(JSON.stringify({ ...boundEvent(pseudonymised), ...node, seq: this.head!.seq + 1, ts: this.now(), prevHash })) as Omit<AuditRecord, 'hash'>;
    const record = this.options.durable ? { ...unsigned, mac: rowMac(this.options.checkpointKey!, unsigned) } : unsigned;
    const hash = sha256(prevHash + canonical(record));
    appendFileSync(this.file, JSON.stringify({ ...record, hash }) + '\n', { mode: 0o600 });
    this.head = { seq: record.seq, hash };
    this.stamp = this.fingerprint();
    if (this.options.durable) this.unflushed.push({ ...record, hash } as AuditRecord);
    else this.storeCheckpoint(this.head);
  }
  /** Durable mode: resolves once every row appended before the call, and the keyed checkpoint naming the last of them,
   *  are on disk (group commit: callers that arrive during a flush share the next one). A failed flush latches. */
  flush(): Promise<void> {
    if (!this.options.durable) return Promise.resolve();
    if (this.queuedFlush) return this.queuedFlush;
    const run = this.flushTail.then(() => { this.queuedFlush = undefined; return this.flushOnce(); });
    this.queuedFlush = run;
    this.flushTail = run.catch(() => undefined);
    return run;
  }
  /** The head the last flush made durable (durable mode); the tip otherwise. */
  durable(): Head { return this.options.durable ? this.durableHead ?? this.tip() : this.tip(); }
  private async flushOnce(): Promise<void> {
    if (this.broken) throw this.broken;
    const head = this.head!; const rows = this.unflushed;
    if (!rows.length && this.durableHead?.seq === head.seq) return;
    this.unflushed = [];
    try {
      const file = await open(this.file, 'a');
      try { await file.datasync(); } finally { await file.close(); }
      if (performance.now() - this.checkpointedAt >= CHECKPOINT_EVERY_MS) {
        this.slots ??= await open(this.checkpointFile, 'r+');
        await this.slots.write(slotText(checkpointBody(this.options.checkpointKey!, head, this.now())), 0, SLOT, this.slot * SLOT);
        await this.slots.datasync();
        this.slot ^= 1; this.checkpointedAt = performance.now();
      }
    } catch (err) {
      this.broken = err instanceof Error ? err : new Error(String(err));
      throw this.broken;
    }
    this.durableHead = head;
    this.stamp = this.fingerprint();
    this.options.onDurable?.(rows);
  }
  /** The contiguous expired prefix, still present and verified. The caller anchors plan.head before applying it. */
  planRetention(cutoff: string | { seq: number }): RetentionPlan | undefined {
    if (!this.options.checkpointKey) throw new Error('AUDIT_RETENTION_DAYS requires SIGNING_KEY_SEAL');
    if (!this.verify().verified) throw new Error('Audit integrity failure');
    const sealed = segmentOf(this.segments, LEGACY_NODE);
    const rows = this.records();
    const expired = rows.filter((row) => typeof cutoff === 'string' ? row.ts < cutoff : row.seq <= cutoff.seq);
    if (!expired.length || expired.some((row, i) => row.seq !== (sealed?.lastSeq ?? 0) + i + 1)) return undefined;
    const last = expired.at(-1)!;
    const signed: SegmentSeal = { version: 1, node: LEGACY_NODE, firstSeq: (sealed?.lastSeq ?? 0) + 1, lastSeq: last.seq,
      removed: expired.length, prefixHash: sha256(canonical(expired)), head: { seq: last.seq, hash: last.hash }, sealedAt: this.now() };
    return { ...signed, rows: expired };
  }
  applyRetention(plan: RetentionPlan, anchor?: Anchor): void {
    if (!this.verify().verified) throw new Error('Audit integrity failure');
    const sealed = segmentOf(this.segments, LEGACY_NODE);
    const rows = this.records();
    const removed = rows.slice(0, plan.removed);
    if (removed.length !== plan.removed || removed.some((row, i) => row.seq !== plan.firstSeq + i) ||
      sha256(canonical(removed)) !== plan.prefixHash || rows[plan.removed - 1]?.hash !== plan.head.hash) throw new Error('Audit retention prefix changed');
    const { rows: _removed, ...signed } = plan;
    const segment = sealSegment(this.options.checkpointKey!, { ...signed, ...(anchor ? { anchor } : {}) });
    const write = this.options.durable ? durableText : atomicText;
    write(this.segmentFile, JSON.stringify([...this.segments, segment], null, 2) + '\n');
    const kept = rows.slice(plan.removed);
    write(this.file, kept.map((row) => JSON.stringify(row)).join('\n') + (kept.length ? '\n' : ''));
    this.segments = [...this.segments, segment]; this.stamp = this.fingerprint();
    if (anchor && !this.anchors.some((a) => a.seq === anchor.seq && a.hash === anchor.hash)) this.anchors.push(anchor);
    this.append({ type: 'security', actor: 'system', action: 'audit_retention', details: { firstSeq: plan.firstSeq, lastSeq: plan.lastSeq, removed: plan.removed,
      prefixHash: plan.prefixHash, sealedHead: plan.head.hash, ...(sealed ? { previousSeal: sealed.lastSeq } : {}) } });
  }
  retain(cutoff: string | { seq: number }, anchor?: Anchor): boolean {
    const plan = this.planRetention(cutoff);
    if (!plan) return false;
    this.applyRetention(plan, anchor);
    return true;
  }
}
