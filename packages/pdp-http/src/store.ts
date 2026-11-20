import { appendFileSync, mkdirSync, existsSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { canonical, levelInheritanceErrors, policyVersion, validateBundle, windowOf } from '../../core/src/index.ts';
import type { Json, PolicyBundle, Subject, Resource, Tuple, Impact, World } from '../../core/src/index.ts';
import { sha256 } from './audit.ts';
import { diffRecordDeltas, recordDeltasApplied, recordDeltasOf, recordKey, withRecordDeltas, type RecordDelta, type StoredTuple } from './record-deltas.ts';
import { forgetPatches, patchDecisionState, patchMark, primeDecisionIndexes, rollbackPatches, type PatchMark } from './decision-index.ts';
export type { RecordDelta, StoredTuple } from './record-deltas.ts';

export interface State extends World {
  readonly tuples: readonly StoredTuple[];
  /** Clark-Wilson certification records, append-only; absent until the first certification is approved. */
  readonly certifications?: readonly Certification[];

  /** Post-states of completed certified commands the PDP could not apply to its copy (the item changed or went away
   *  since the token was consumed): left for reconciliation, listed by GET /admin/v1/integrity/reservations. */
  readonly unappliedPostStates?: readonly UnappliedPostState[];
}
export interface UnappliedPostState {
  readonly reservation: string; readonly resource: { type: string; id: string }; readonly action: string;
  readonly boundVersion: number; readonly storedVersion: number | null; readonly reason: string; readonly at: string;
}
/** A resource id a PEP retired, with its version then (resource-registry.ts): registering it again is always reviewed. */
export interface RetiredId { readonly type: string; readonly id: string; readonly version: number; readonly at: string }
/** Retired ids, append-only and outside the state document and per-record tables: gate_retired with PostgreSQL,
 *  retired.jsonl in DATA_DIR otherwise. `get` answers the latest retirement of an id, `list` that of every id of a type. */
export interface RetiredLog { get(type: string, id: string): RetiredId | undefined; append(row: RetiredId): void; list(type: string): RetiredId[] }
/** File mode: one JSON line per retirement, appended (mode 600), read once at start. */
export function fileRetiredLog(file: string): RetiredLog {
  const known = new Map<string, RetiredId>();
  if (existsSync(file)) {
    const lines = readFileSync(file, 'utf8').split('\n');
    for (const [n, line] of lines.entries()) {
      if (!line.trim()) continue;
      let r: RetiredId;
      // a crash can tear only the last line (appends are not fsynced): ignore it; a bad line elsewhere is corruption
      try { r = JSON.parse(line) as RetiredId; } catch (err) { if (n >= lines.length - 2) { console.warn(`${file}: incomplete last line ignored`); continue; } throw err; }
      known.set(JSON.stringify([r.type, r.id]), r);
    }
  }
  return {
    get: (type, id) => known.get(JSON.stringify([type, id])),
    list: (type) => [...known.values()].filter((r) => r.type === type),
    append: (row) => { appendFileSync(file, `${JSON.stringify(row)}\n`, { mode: 0o600 }); known.set(JSON.stringify([row.type, row.id]), row); },
  };
}
/** Who certified which transformation procedure (a certified action) for which constrained type, and when. */
export interface Certification {
  readonly resourceType: string; readonly action: string; readonly certifiedBy: string; readonly approvedBy: string;
  readonly certifiedAt: string; readonly policyVersion: string; readonly changeId: string; readonly reason: string;
  /** The procedure definition certified (core procedureFingerprint); absent on records of 0.4.0 and earlier. */
  readonly fingerprint?: string;
}
export interface Change {
  id: string; kind: string; payload: Record<string, unknown>; reason: string; makerId: string;
  createdAt: string; status: 'pending' | 'applied' | 'rejected'; impact: Impact; broadens: boolean;
  weakensMandatory?: string[]; stateDigest: string; checkerId?: string; decidedAt?: string; decisionReason?: string;
  /** SCIM proposals: who last minted the SCIM credential ("env" for SCIM_BEARER_TOKEN) and its short fingerprint. */
  scimCredential?: ScimCredentialOrigin;
  /** register_resources: the PEP credential that proposed it, and who issued (created or last rotated) that credential. */
  pepCredential?: PepCredentialOrigin;
  /** publish_policy: certification records in force now that the new bundle would make stale (recertify after it). */
  invalidatesCertifications?: Array<{ resourceType: string; action: string; changeId: string }>;
  /** publish_policy: deprecations validateBundle reported (DEPRECATED_CBAC_FIELD), kept for the approver and the audit. */
  warnings?: string[];
}
export interface ScimCredentialOrigin { rotatedBy: string; fingerprint: string }
/** issuedBy: absent for a credential issued before this field existed; nobody can then approve its proposals. */
export interface PepCredentialOrigin { id: string; issuedBy?: string }
export interface Emergency {
  id: string; subjectId: string; resourceId: string; reason: string; openedBy: string; openedAt: string;
  expiresAt: string; status: 'active' | 'revoked' | 'reviewed'; tupleId: string;
  /** Absent on emergencies opened before 0.11.1: those match any resource type with this id (fail closed). */
  resourceType?: string;
  reviewedBy?: string; outcome?: string; note?: string;
  /** Set once its expiry was audited and notified (server.ts), so a restart does not notify it again. */
  expiryNotified?: boolean;
}
export interface Publication {
  version: string; publishedAt: string; publishedBy: string; approvedBy: string; reason: string;
  /** Ed25519 detached JWS over canonical(bundle), by the decision-token keyring (docs/API.md, policy signature). */
  signature?: PolicySignature;
}
export interface PolicySignature { alg: 'EdDSA'; kid: string; jws: string }
/** A certified action, reserved when its decision token is consumed (before the PEP runs it). It counts for separation
 *  of duty from then on, unless its PEP reports it failed (docs/API.md, action outcomes). */
export interface Performed {
  subject: { type: string; id: string }; resource: { type: string; id: string }; action: string; at: string;
  /** The people the performer acted for (its delegation chain): their history includes this action. */
  onBehalfOf?: Array<{ type: string; id: string }>;
  /** Reservation id; absent on actions recorded before reservations (0.4.0), which count as completed. */
  id?: string;
  /** The PEP credential id that consumed the token: only that credential reports the outcome. */
  pep?: string;
  /** What the PEP reported; absent while the reservation is pending (it still counts). */
  outcome?: ActionOutcome;
  outcomeAt?: string;
  /** The item's attributes as the certified command commits them (token consumption with attrs), and the item version
   *  the token was bound to: applied to the PDP's copy when the PEP reports the action completed. */
  postState?: Readonly<Record<string, Json>>;
  boundVersion?: number;
}
export type ActionOutcome = 'completed' | 'failed';
/** A reported outcome as the shared log carries it: PostgreSQL rows are append-only, so it is a row of its own. */
export interface PerformedOutcome { ref: string; outcome: ActionOutcome; at: string }
export type PerformedRow = Performed | PerformedOutcome;
/** What is stored for a reservation: the reservation and the outcome already reported, if any. */
export interface Reservation { reservation?: Performed; outcome?: ActionOutcome }
export interface Disk { state: State; changes: Change[]; emergencies: Emergency[]; history: Publication[]; performed?: Performed[]; revision?: number }
/** Where a document lives: a local file by default, PostgreSQL metadata and record rows when DATABASE_URL is set. */
export interface Backing<T> { readonly records?: boolean; stateVersion?(): number | string; load(): T | undefined; save(value: T, records?: readonly RecordDelta[]): void }
/** PostgreSQL: performed actions are rows shared by every node (gate_performed), not part of the state document. */
export interface PerformedLog {
  load(): PerformedRow[]; append(row: PerformedRow): void;
  /** Runs `check` on what the database holds for reservation `ref`, serialised with every other node's reports; commits
   *  what `check` staged when it accepts. */
  settle(ref: string, check: (stored: Reservation) => boolean): Promise<boolean>;
}
const isOutcome = (row: PerformedRow): row is PerformedOutcome => 'ref' in row;
export const fileBacking = <T>(file: string): Backing<T> => ({
  load: () => existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) as T : undefined,
  save: (value) => atomic(file, value),
});
export function atomic(file: string, value: unknown): void {
  const temp = `${file}.${randomUUID()}.tmp`;
  writeFileSync(temp, JSON.stringify(value, null, 2), { mode: 0o600 });
  renameSync(temp, file);
}
export class Store {
  private currentState!: State;
  private stagedRecords = new Map<string, RecordDelta>();
  private revisionValue = 0;
  get revision(): number { return this.revisionValue; }
  /** Every state current since the last commit point, with how far its arrays were patched and what was staged then:
   *  assigning one of them back is a rollback (a failed request restoring what it saved), in file and PostgreSQL modes. */
  private marks = new Map<State, { patches: PatchMark; staged: Map<string, RecordDelta> }>();
  get state(): State { return this.currentState; }
  set state(next: State) {
    const saved = next === this.currentState ? undefined : this.marks.get(next);
    if (saved) {
      rollbackPatches(next, saved.patches);
      this.currentState = next; this.stagedRecords = new Map(saved.staged); this.revisionValue++;
      return;
    }
    const annotated = recordDeltasOf(next);
    const deltas = this.backing.records ? annotated ?? diffRecordDeltas(this.currentState ?? { subjects: [], resources: [], tuples: [] }, next) : [];
    if (this.backing.records && this.currentState && deltas.length && !recordDeltasApplied(next)) this.currentState = patchDecisionState(this.currentState, next, deltas);
    else {
      this.currentState = next;
      if (this.backing.records) primeDecisionIndexes(next);
    }
    for (const delta of deltas) {
      const key = recordKey(delta.kind, delta.type, delta.id);
      const staged = this.stagedRecords.get(key);
      // deleted then put again in one batch: in memory it went to the end, so it is written (and replayed) as a move
      if (staged?.op === 'delete' && delta.op === 'put') { this.stagedRecords.delete(key); this.stagedRecords.set(key, { ...delta, move: true }); }
      else this.stagedRecords.set(key, delta);
    }
    this.revisionValue++;
    this.mark();
  }
  private mark(): void { this.marks.set(this.currentState, { patches: patchMark(this.currentState), staged: new Map(this.stagedRecords) }); }
  // The undo log is store-wide: a rollback undoes every unsaved in-place change. Request handlers assign the state,
  // validate and save (or restore) without awaiting in between; an await there would let one request's rollback undo
  // another's unsaved change, so keep that section synchronous.
  /** Nothing before this point can be rolled back any more (saved, or replaced by what the database holds). */
  private commitPoint(): void {
    for (const state of this.marks.keys()) forgetPatches(state);
    this.marks.clear(); this.mark();
  }
  changes: Change[];
  emergencies: Emergency[];
  history: Publication[];
  performed: Performed[];
  readonly dir: string;
  /** True when this constructor created the state from the world files (nothing was stored yet). */
  readonly fresh: boolean;
  private readonly backing: Backing<Disk>;
  private readonly log?: PerformedLog;
  /** Retired resource ids (RetiredLog): retired.jsonl here unless the server passes the database's. */
  readonly retired: RetiredLog;
  /** With a performed log: the history an earlier version kept in the state document, saved back unchanged. */
  private performedBase: Performed[] = [];
  /** Outcomes whose reservation this node has not received yet (another node consumed it): applied when it arrives. */
  private early = new Map<string, PerformedOutcome>();
  /** `refuseDemoWorld` (GATE_PROFILE=production): a first start does not seed from a world marked `"demo": true`. */
  constructor(dir: string, worldDir: string, now: string, backing?: Backing<Disk>, log?: PerformedLog, options: { refuseDemoWorld?: boolean; retired?: RetiredLog } = {}) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.retired = options.retired ?? fileRetiredLog(join(dir, 'retired.jsonl'));
    this.backing = backing ?? fileBacking(join(dir, 'state.json'));
    this.log = log;
    const disk = this.backing.load();
    this.fresh = !disk;
    if (disk) {
      this.state = disk.state; this.changes = disk.changes; this.emergencies = disk.emergencies; this.history = disk.history;
      this.revisionValue = disk.revision ?? 0;
      this.performedBase = disk.performed ?? [];
      this.performed = this.performedBase;
      if (log) this.addPerformed(log.load());
    } else {
      const world = JSON.parse(readFileSync(join(worldDir, 'world.json'), 'utf8')) as {
        subjects: Subject[]; resources: Resource[]; tuples: Tuple[]; demo?: unknown;
      };
      if (options.refuseDemoWorld && world.demo === true) {
        throw new Error(`GATE_PROFILE=production refused to start: WORLD_DIR (${worldDir}) is a demo world with fictional people; point WORLD_DIR at the tenant's own world.json and bundle.json (ALLOW_DEMO_WORLD=true only for local test deployments)`);
      }
      const candidate: unknown = JSON.parse(readFileSync(join(worldDir, 'bundle.json'), 'utf8'));
      const valid = validateBundle(candidate);
      if (!valid.ok) throw new Error('Invalid startup bundle');
      this.state = { bundle: valid.bundle, subjects: world.subjects, resources: world.resources,
        tuples: world.tuples.map((t, i) => ({ ...t, id: `seed-${i + 1}` })) };
      this.changes = [];
      this.emergencies = this.state.tuples.filter((t) => t.breakGlass && windowOf(t).from && windowOf(t).to).map((t) => ({
        id: t.id, tupleId: t.id, subjectId: t.subject.id, resourceId: t.object.id, resourceType: t.object.type,
        openedBy: t.grantedBy ?? 'bootstrap', openedAt: windowOf(t).from as string, expiresAt: windowOf(t).to as string,
        reason: t.reason ?? 'Initial demo emergency', status: 'active',
      }));
      this.history = [{ version: policyVersion(valid.bundle), publishedAt: now, publishedBy: 'bootstrap', approvedBy: 'bootstrap', reason: 'Initial demo policy' }];
      this.performed = [];
      if (log) this.addPerformed(log.load());
      this.save();
    }
    if (disk) { this.stagedRecords.clear(); this.commitPoint(); }
    if (!validateBundle(this.state.bundle).ok) throw new Error('Invalid stored bundle');
    const levels = levelInheritanceErrors(this.state.resources);
    if (levels.length) throw new Error(`Invalid resource levels: ${levels.join('; ')}`);
  }
  save(): void {
    const records = [...this.stagedRecords.values()];
    this.backing.save({ state: this.state, changes: this.changes, emergencies: this.emergencies, history: this.history, performed: this.log ? this.performedBase : this.performed,
      ...(this.backing.records ? {} : { revision: this.revisionValue }) }, records);
    this.stagedRecords.clear();
    this.commitPoint();
  }
  /** A performed action: in the shared log when there is one (committed with the request), else in the state file. */
  recordPerformed(row: Performed): void {
    this.performed = [...this.performed, row];
    if (this.log) this.log.append(row); else this.save();
  }
  /** The outcome of a reservation: in the shared log as a row of its own when there is one, else in the state file. */
  recordOutcome(row: PerformedOutcome): void {
    this.addPerformed([row]);
    if (this.log) this.log.append(row); else this.save();
  }
  /** What is stored for reservation `ref`, for `check` (synchronous with files; the database decides with a log). */
  settle(ref: string, check: (stored: Reservation) => boolean): boolean | Promise<boolean> {
    if (this.log) return this.log.settle(ref, check);
    const found = this.performed.find((p) => p.id === ref);
    if (!found) return check({});
    const { outcome, outcomeAt: ignored, ...reservation } = found;
    return check({ reservation, ...(outcome ? { outcome } : {}) });
  }
  /** Reservations no PEP reported an outcome for: they still count for separation of duty until reconciled. */
  pendingReservations(): Performed[] { return this.performed.filter((p) => p.id !== undefined && p.outcome === undefined); }
  /** Performed rows other nodes committed, or loaded at start: reservations and outcomes, in any order (history arrays
   *  are replaced, never mutated). One pass over the history per batch. */
  addPerformed(rows: readonly PerformedRow[]): void {
    const outcomes = rows.filter(isOutcome);
    for (const o of outcomes) this.early.set(o.ref, o);
    const settle = (p: Performed): Performed => {
      const o = p.id === undefined ? undefined : this.early.get(p.id);
      if (!o) return p;
      this.early.delete(o.ref);
      return { ...p, outcome: o.outcome, outcomeAt: o.at };
    };
    const added = rows.filter((r): r is Performed => !isOutcome(r));
    this.performed = [...(outcomes.length ? this.performed.map(settle) : this.performed), ...added.map(settle)];
  }
  /** Rereads shared metadata, applying record deltas when supplied; undefined means a full snapshot fallback. */
  reload(records?: readonly RecordDelta[]): void {
    const disk = this.backing.load();
    if (!disk) return;
    const shared = this.performed.slice(this.performedBase.length);
    if (records === undefined) {
      this.currentState = disk.state;
      if (this.backing.records) primeDecisionIndexes(this.currentState);
      this.stagedRecords.clear();
    } else this.state = withRecordDeltas(disk.state, records);
    this.stagedRecords.clear();
    this.commitPoint();
    this.changes = disk.changes; this.emergencies = disk.emergencies; this.history = disk.history;
    this.performedBase = this.log ? disk.performed ?? [] : [];
    this.performed = this.log ? [...this.performedBase, ...shared] : disk.performed ?? [];
  }
  /** The state a proposal is previewed on (Change.stateDigest); approval refuses when it differs (admin/changes.ts).
   *  v2 = version + SHA-256 of the canonical state without its record arrays (subjects, resources, tuples):
   *  - the hash covers everything else in the state: the policy bundle, certification records, unapplied post-states;
   *  - the version covers the records. With PostgreSQL it is the record generation (gate_sync.records), which every
   *    commit carrying a subject, resource or tuple change moves (retirements included: a retirement deletes its
   *    resource row), the same on every node, so a failover keeps pending proposals valid; while this process holds
   *    record changes not yet committed it carries a per-process suffix, never equal to a committed generation.
   *    With files it is this store's revision, moved by every state assignment and saved with the state.
   *  Sufficient because every path that changes the world assigns `state` (in-place registration patches included),
   *  so no record change leaves the version where it was; a false refusal (a no-op assignment) only asks for a new
   *  proposal. What lies outside the state (the clock, performed actions, the retired-id log) is not in the digest:
   *  approval recomputes the impact on the live state and refuses when it differs, and a registration proposal checks
   *  the stored basis of its own resources and retired ids instead (registrationMoved). */
  digest(): string {
    const { subjects: _subjects, resources: _resources, tuples: _tuples, ...state } = this.state;
    const version = this.backing.stateVersion?.() ?? this.revisionValue;
    return `v2.${version}.${sha256(canonical(state))}`;
  }
  /** Pre-v2 proposals used SHA-256 over the whole canonical world; honor exactly that when reviewing them. */
  legacyDigest(): string { return sha256(canonical(this.state)); }
  publish(bundle: PolicyBundle, maker: string, checker: string, reason: string, now: string, signature?: PolicySignature): void {
    this.history = [...this.history, { version: policyVersion(bundle), publishedAt: now, publishedBy: maker, approvedBy: checker, reason, ...(signature ? { signature } : {}) }];
  }
}
