// A stateless decision replica (GATE_REPLICA_OF, docs/API.md §3.9.5): no database. It bootstraps from a signed snapshot
// of a database node, follows signed deltas by long poll, decides locally only what its copy may decide (no session
// mark, no separation of duty, no decision token), forwards everything else, writes every local decision to its own
// durable keyed audit chain before answering, and ships that chain to the database, which checks its continuity.
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { request as httpRequest, type ClientRequest, type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { resolve } from 'node:path';
import { auditMac, macMatches, segmentOf } from './audit-integrity.ts';
import { GENESIS, LEGACY_NODE, type Audit, type AuditRecord, type Head } from './audit.ts';
import type { SubjectIdentities } from './audit-subjects.ts';
import { forwardToLeader, signHop } from './forward.ts';
import { isLoopback } from './oidc.ts';
import { materializeState, type RecordSnapshot } from './postgres-records.ts';
import type { RecordDelta } from './record-deltas.ts';
import { sodConstrained } from './runtime.ts';
import type { Backing, Disk, State } from './store.ts';
import type { SigningKeyDisk } from './tokens.ts';
import { derive, hopKeyOf, MAX_WAIT_MS, REPLICA_HOP_HEADER, REPLICA_SIGNATURE_HEADER, REPLICA_TRUST_LABEL, REPLICA_TYP, TrustedKeys,
  type AuditMessage, type Generation, type ReplicaDocs, type Signer, type StateMessage } from './replica-protocol.ts';

export interface ReplicaOptions {
  tenantId?: string;
  /** GATE_REPLICA_OF: the database nodes' origin (https; plain http only on loopback). */
  leader: string;
  /** GATE_NODE_ID: this replica's id, which is also its audit chain on the database. */
  id: string;
  /** GATE_REPLICA_KEY: this replica's secret; the database nodes hold the same value in GATE_REPLICA_KEYS. */
  key: Buffer;
  dataDir: string;
  /** GATE_REPLICA_PIN: Ed25519 public keys (JWK x) the first snapshot must be signed by; unset: the JWKS over verified TLS. */
  pins?: readonly string[];
  /** GATE_REPLICA_CA_FILE: the CA that verifies the database nodes' TLS certificate (unset: the system store). */
  ca?: Buffer;
  /** GATE_MAX_STALENESS_MS: no decision on a state confirmed longer ago (default 2000). */
  maxStalenessMs?: number;
  /** GATE_REPLICA_AUDIT_LAG_MS: no decision while a durable row waits longer than this to reach the database (10000). */
  maxAuditLagMs?: number;
}

/** What a replica answers itself; everything else goes to the database nodes. */
const LOCAL_PATHS = new Set(['/access/v1/evaluation', '/access/v1/evaluations', '/access/v1/search/resource', '/x/v1/explain', '/x/v1/filter']);
const SHIP_BATCH = 1000;
/** A shipment stays well under the database nodes' 1 MB request body cap (http.ts: larger bodies are refused with 413). */
const SHIP_MAX_BYTES = 768 * 1024;
/** Rows are coalesced this long before a batch is sent (one ingestion transaction on the database per batch). */
const SHIP_PAUSE_MS = 50;
/** Shipped rows are sealed out of the local file (an authenticated retention segment) once this many accumulate. */
const RETAIN_EVERY = 10_000;
const START: Head = { seq: 0, hash: GENESIS };
const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));
const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

export function replicaOrigin(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('GATE_REPLICA_OF must be an absolute https URL'); }
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('GATE_REPLICA_OF must be an origin: no credentials, path, query or fragment');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url))) throw new Error('GATE_REPLICA_OF must use https (plain http only on loopback, for tests)');
  return url;
}

export class Replica {
  private readonly tenantId?: string;
  readonly id: string; readonly leader: URL; readonly key: Buffer;
  /** Set by the server once its store exists: the state local() judges requests on. */
  state?: () => State;
  /** Set by the server: applies the documents and record changes (as a cluster follower's reload does). */
  onReload?: (records?: readonly RecordDelta[]) => void;
  config: StateMessage['config'] = { blpSessionRequired: false };
  private readonly docs = new Map<string, unknown>();
  private at?: Generation;
  /** The newest generation this replica (or its last run, replica-trust.json) accepted: nothing older is applied. */
  private floor?: Generation;
  private docsHash = '';
  private subjects = { epoch: '', n: 0 };
  private readonly mapping = new Map<string, string>();
  private readonly reverse = new Map<string, string>();
  private readonly trust = new TrustedKeys([]);
  private readonly hopKey: Buffer; private readonly trustKey: Buffer; private readonly trustFile: string;
  private readonly ca?: Buffer; private readonly pins: readonly string[];
  private readonly maxStaleness: number; private readonly maxAuditLag: number;
  private confirmedAt = Number.NEGATIVE_INFINITY;
  private closing = false;
  private following?: Promise<void>;
  private readonly inflight = new Set<ClientRequest>();
  private readonly sleepers = new Set<() => void>();
  private audit?: Audit;
  private acked: Head = START;
  private queue: Array<{ row: AuditRecord; at: number }> = [];
  private shipping?: Promise<void>;
  private auditFailure?: string;
  private retainedTo = 0;
  /** Pseudonyms come from the database's mapping: a subject without one is decided by the database (local()). */
  readonly identities: SubjectIdentities = {
    pseudonym: (id) => { const p = this.mapping.get(id); if (!p) throw new Error('No pseudonym for this subject on the replica'); return p; },
    lookup: (id) => this.mapping.get(id),
    identity: (pseudonym) => this.reverse.get(pseudonym),
    erase: () => { throw new Error('Subjects are erased on the database nodes'); },
  };

  private constructor(o: ReplicaOptions) {
    this.tenantId = o.tenantId;
    this.id = o.id; this.leader = replicaOrigin(o.leader); this.key = o.key; this.ca = o.ca; this.pins = o.pins ?? [];
    this.hopKey = hopKeyOf(o.key); this.trustKey = derive(o.key, REPLICA_TRUST_LABEL);
    this.trustFile = resolve(o.dataDir, 'replica-trust.json');
    this.maxStaleness = o.maxStalenessMs ?? 2000; this.maxAuditLag = o.maxAuditLagMs ?? 10_000;
    if (!Number.isInteger(this.maxStaleness) || this.maxStaleness < 100 || this.maxStaleness > 60_000) throw new Error('GATE_MAX_STALENESS_MS must be an integer in 100..60000');
    if (!Number.isInteger(this.maxAuditLag) || this.maxAuditLag < 100 || this.maxAuditLag > 3_600_000) throw new Error('GATE_REPLICA_AUDIT_LAG_MS must be an integer in 100..3600000');
  }

  /** Trust (the stored set, else the pins, else the JWKS over verified TLS), then the first signed snapshot. */
  static async open(o: ReplicaOptions): Promise<Replica> {
    const r = new Replica(o);
    const stored = r.loadTrust();
    const initial = stored?.trusted ?? (r.pins.length ? r.pins : await r.jwks());
    for (const x of initial) r.trust.x.add(x);
    r.floor = stored?.at;
    await r.followOnce(0);
    return r;
  }

  backing<T>(name: string): Backing<T> {
    if (name === 'state') return { records: true, stateVersion: () => this.at?.records ?? 0, load: () => this.docs.get(name) as T | undefined, save: (value) => { this.docs.set(name, value); } };
    return { load: () => this.docs.get(name) as T | undefined, save: (value) => { this.docs.set(name, value); } };
  }

  /** Confirmed within the staleness bound, and every durable audit row on its way within the audit-lag bound. */
  fresh(): boolean {
    const oldest = this.queue[0];
    return !this.closing && !this.auditFailure && performance.now() - this.confirmedAt <= this.maxStaleness &&
      (oldest === undefined || performance.now() - oldest.at <= this.maxAuditLag);
  }

  /** The replica answers a decision request itself only when its copy decides it exactly as a database node would:
   *  no context.sessionId (the BLP high-water mark is shared state), no action under separation of duty (performed
   *  history), no certified action (it issues a decision token, a database row), and a subject the database already
   *  gave a pseudonym (the audit row needs it). Malformed requests are refused here. */
  local(path: string, b: Record<string, unknown>): boolean {
    if (!LOCAL_PATHS.has(path) || !this.state) return false;
    const state = this.state();
    const items = path === '/access/v1/evaluations' && Array.isArray(b.evaluations) ? b.evaluations.map((e) => ({ ...b, ...(isObject(e) ? e : {}) })) : [b];
    return items.every((item) => {
      if (isObject(item.context) && (item.context.sessionId !== undefined || item.context.sessionToken !== undefined)) return false;
      const subject = isObject(item.subject) ? item.subject.id : undefined;
      const type = isObject(item.resource) ? item.resource.type : undefined;
      const action = isObject(item.action) ? item.action.name : undefined;
      if (typeof subject !== 'string' || typeof type !== 'string' || typeof action !== 'string') return true;
      if (!this.mapping.has(subject)) return false;
      const actions = Object.hasOwn(state.bundle.schema.resourceTypes, type) ? state.bundle.schema.resourceTypes[type]!.actions : {};
      return !(Object.hasOwn(actions, action) && actions[action]!.certified) && !sodConstrained(state.bundle, type, action);
    });
  }

  forward(req: IncomingMessage, res: ServerResponse, client: string): Promise<void> {
    return forwardToLeader(req, res, this.leader, this.hopKey, this.id, client, { header: REPLICA_HOP_HEADER, ...(this.ca ? { ca: this.ca } : {}) });
  }

  /** After the server built its runtime: agrees on the audit chain with the database, then follows and ships. */
  async start(audit: Audit): Promise<void> {
    this.audit = audit;
    await audit.flush();
    const local = audit.durable();
    const { status, message: m } = await this.signed<AuditMessage>('POST', '/x/v1/replica/audit', 'audit', Buffer.from(JSON.stringify({ base: local, rows: [] })));
    if (status !== 200) {
      throw new Error(`The database refused this replica's audit chain (${m.refused}; local head ${local.seq}, stored head ${m.head.seq}). ` +
        'If this replica lost or replaced its disk, the rows it had not shipped are lost (at most GATE_REPLICA_AUDIT_LAG_MS of decisions): start it with a new GATE_NODE_ID');
    }
    if (m.head.seq < local.seq) this.resendFrom(m.head); else this.acked = m.head;
    this.follow();
    this.ship();
  }

  /** Audit.onDurable: rows now on disk, shipped in order. */
  durable(rows: readonly AuditRecord[]): void {
    const at = performance.now();
    for (const row of rows) this.queue.push({ row, at });
    this.ship();
  }

  metrics(): string[] {
    const oldest = this.queue[0];
    return ['# HELP gate_replica_state_age_seconds Time since this replica last confirmed the shared state (signed feed).',
      '# TYPE gate_replica_state_age_seconds gauge', `gate_replica_state_age_seconds ${Number.isFinite(this.confirmedAt) ? (performance.now() - this.confirmedAt) / 1000 : -1}`,
      '# HELP gate_replica_audit_unshipped_rows Durable local audit rows not yet stored by the database.',
      '# TYPE gate_replica_audit_unshipped_rows gauge', `gate_replica_audit_unshipped_rows ${this.queue.length}`,
      '# HELP gate_replica_audit_lag_seconds Age of the oldest durable audit row not yet stored by the database (0 when none).',
      '# TYPE gate_replica_audit_lag_seconds gauge', `gate_replica_audit_lag_seconds ${oldest ? (performance.now() - oldest.at) / 1000 : 0}`,
      '# HELP gate_replica_audit_refused 1 once the database refused this replica\'s chain (decisions stop).',
      '# TYPE gate_replica_audit_refused gauge', `gate_replica_audit_refused ${this.auditFailure ? 1 : 0}`];
  }

  async close(): Promise<void> {
    this.closing = true;
    for (const wake of this.sleepers) wake();
    for (const req of this.inflight) req.destroy(new Error('closing'));
    await Promise.all([this.following?.catch(() => undefined), this.shipping?.catch(() => undefined)]);
  }

  // --- state ------------------------------------------------------------------------------------------------------
  private follow(): void {
    const wait = Math.max(50, Math.min(MAX_WAIT_MS, Math.floor(this.maxStaleness / 4)));
    this.following = (async () => {
      let failures = 0;
      while (!this.closing) {
        try { await this.followOnce(wait); failures = 0; } catch (err) {
          if (this.closing) break;
          failures++;
          if (failures === 1 || failures % 20 === 0) console.error(`Replica state feed failed (${failures}): ${message(err)}`);
          await this.sleep(Math.min(2000, 25 * 2 ** Math.min(failures, 7)));
        }
      }
    })();
  }
  private async followOnce(wait: number): Promise<void> {
    const sent = performance.now();
    const q = new URLSearchParams({ wait: String(wait) });
    if (this.at) { q.set('after', `${this.at.version}.${this.at.records}`); q.set('docs', this.docsHash); q.set('subjects', `${this.subjects.epoch}.${this.subjects.n}`); }
    const { message: m } = await this.signed<StateMessage>('GET', `/x/v1/replica/state?${q}`, 'state', undefined, wait + 15_000);
    this.apply(m);
    this.confirmedAt = sent; // everything the database committed before `sent` is applied
  }
  private apply(m: StateMessage): void {
    const floor = this.at ?? this.floor;
    if (floor && (m.at.version < floor.version || m.at.records < floor.records)) {
      throw new Error(`state ${m.at.version}.${m.at.records} is older than ${floor.version}.${floor.records}: rollback refused`);
    }
    if (!this.at && (!m.docs || !m.records)) throw new Error('the first state message must be a full snapshot');
    const changed = !this.at || Boolean(m.docs || m.records || m.deltas?.length) || m.at.version !== this.at.version || m.at.records !== this.at.records;
    if (changed) {
      const previous = this.docs.get('state') as Disk | undefined;
      if (m.docs) for (const [name, doc] of Object.entries(m.docs)) this.docs.set(name, doc);
      const records = m.records ?? (m.docs && previous ? previous.state as unknown as RecordSnapshot : undefined);
      if (records) materializeState(this.docs, records);
    }
    if (m.subjects.full) {
      this.mapping.clear(); this.reverse.clear();
      for (const [id, pseudonym] of Object.entries(m.subjects.full)) { this.mapping.set(id, pseudonym); this.reverse.set(pseudonym, id); }
    }
    for (const [id, pseudonym] of m.subjects.changes ?? []) {
      const before = this.mapping.get(id);
      if (before) this.reverse.delete(before);
      if (pseudonym === null) this.mapping.delete(id); else { this.mapping.set(id, pseudonym); this.reverse.set(pseudonym, id); }
    }
    this.subjects = { epoch: m.subjects.epoch, n: m.subjects.n };
    this.config = m.config;
    if (changed && this.onReload) {
      try { this.onReload(m.records ? undefined : m.deltas ?? []); } catch (err) {
        // refused (a bundle whose signature does not verify): stale until a full snapshot applies
        this.floor = this.at ?? this.floor; this.at = undefined; this.docsHash = '';
        throw err;
      }
    }
    const before = [...this.trust.x].sort().join();
    if (m.docs) this.trust.keep(m.docs.signing_keys);
    const moved = !this.at || m.at.version !== this.at.version || m.at.records !== this.at.records;
    this.at = m.at; this.docsHash = m.docsHash;
    if (moved || before !== [...this.trust.x].sort().join()) this.saveTrust();
  }

  // --- audit shipping ---------------------------------------------------------------------------------------------
  private ship(): void {
    if (this.shipping || this.closing || this.auditFailure || !this.audit) return;
    this.shipping = (async () => {
      let failures = 0;
      while (!this.closing && !this.auditFailure) {
        const next = this.queue.findIndex((e) => e.row.seq > this.acked.seq);
        this.queue = next < 0 ? [] : this.queue.slice(next);
        if (!this.queue.length) break;
        const waited = performance.now() - this.queue[0]!.at;
        if (this.queue.length < SHIP_BATCH && waited < SHIP_PAUSE_MS) { await this.sleep(SHIP_PAUSE_MS - waited); continue; }
        try { await this.post(this.acked, this.batch()); failures = 0; } catch (err) {
          if (this.closing) break;
          failures++;
          if (failures === 1 || failures % 20 === 0) console.error(`Replica audit shipping failed (${failures}): ${message(err)}`);
          await this.sleep(Math.min(2000, 25 * 2 ** Math.min(failures, 7)));
        }
      }
    })().finally(() => {
      this.shipping = undefined;
      if (this.queue.some((e) => e.row.seq > this.acked.seq)) this.ship();
    });
  }
  /** The next shipment: queued rows in order, at most SHIP_BATCH of them and SHIP_MAX_BYTES of JSON (always at least one). */
  private batch(): AuditRecord[] {
    const rows: AuditRecord[] = [];
    let bytes = 64;
    for (const { row } of this.queue) {
      bytes += Buffer.byteLength(JSON.stringify(row)) + 1;
      if (rows.length && (rows.length >= SHIP_BATCH || bytes > SHIP_MAX_BYTES)) break;
      rows.push(row);
    }
    return rows;
  }
  private async post(base: Head, rows: AuditRecord[]): Promise<void> {
    const { status, message: m } = await this.signed<AuditMessage>('POST', '/x/v1/replica/audit', 'audit', Buffer.from(JSON.stringify({ base, rows })));
    if (status === 200) {
      if (m.head.seq > this.audit!.durable().seq) { this.refuse('behind', m.head); return; }
      this.acked = m.head;
      if (this.acked.seq - this.retainedTo >= RETAIN_EVERY) this.retain();
      return;
    }
    // the database stores fewer rows than this replica shipped (a restored database): send them again from its head
    if (m.refused === 'gap' && m.head.seq < base.seq) { this.resendFrom(m.head); return; }
    this.refuse(m.refused ?? 'refused', m.head);
  }
  private refuse(reason: string, head: Head): void {
    this.auditFailure = reason;
    console.error(`REPLICA AUDIT REFUSED by the database (${reason}, stored head ${head.seq}, local head ${this.audit?.durable().seq ?? 0}): this replica stops deciding (/readyz 503). ` +
      'Investigate the local chain; a replica whose disk was lost or replaced starts with a new GATE_NODE_ID (docs/API.md §3.9.5)');
  }
  /** Queues every durable local row after `head`, chained from this replica's own row at head.seq. */
  private resendFrom(head: Head): void {
    const audit = this.audit!;
    const durable = audit.durable().seq;
    const rows = audit.records().filter((r) => r.seq > head.seq && r.seq <= durable);
    const sealed = segmentOf(audit.segments, LEGACY_NODE);
    const own = head.seq === 0 ? GENESIS : head.seq === sealed?.lastSeq ? sealed.head.hash : audit.records().find((r) => r.seq === head.seq)?.hash;
    if (own === undefined || (rows.length && rows[0]!.seq !== head.seq + 1)) { this.refuse('gap', head); return; }
    const at = performance.now();
    this.acked = { seq: head.seq, hash: own };
    this.queue = rows.map((row) => ({ row, at }));
  }
  private retain(): void {
    try {
      if (this.audit!.retain({ seq: this.acked.seq })) { this.retainedTo = this.acked.seq; void this.audit!.flush().catch(() => undefined); }
    } catch (err) { console.error(`Replica audit retention failed: ${message(err)}`); }
  }

  // --- transport and trust ----------------------------------------------------------------------------------------
  private keyring(): SigningKeyDisk | undefined { return this.docs.get('signing_keys') as SigningKeyDisk | undefined; }
  /** A request to the database nodes with the replica hop, answered with a message signed by a trusted key and bound
   *  to this request (type, audience, nonce): a replayed, swapped or forged answer is refused. */
  private async signed<T extends { typ: string; kind: string; aud: string; nonce: string }>(method: string, path: string, kind: T['kind'], body?: Buffer, timeout = 15_000): Promise<{ status: number; message: T }> {
    const nonce = randomBytes(18).toString('base64url');
    const answer = await this.send(method, `${path}${path.includes('?') ? '&' : '?'}nonce=${nonce}`, body, timeout);
    if (answer.status !== 200 && answer.status !== 409) throw new Error(`the database node answered ${answer.status}: ${answer.body.toString('utf8').slice(0, 200)}`);
    let parsed: T & { docs?: ReplicaDocs; signer?: Signer };
    try { parsed = JSON.parse(answer.body.toString('utf8')) as T & { docs?: ReplicaDocs; signer?: Signer }; } catch { throw new Error(`the database node answered ${answer.status} without a replica message`); }
    const signature = answer.headers[REPLICA_SIGNATURE_HEADER];
    const jws = typeof signature === 'string' ? signature : undefined;
    // keys named by the message itself only resolve a kid: a key is trusted only as TrustedKeys allows
    const keys = { keys: [...parsed.docs?.signing_keys.keys ?? [], ...this.keyring()?.keys ?? [], ...isObject(parsed.signer) ? [parsed.signer] : []] };
    if (!this.trust.verifies(answer.body, jws, keys)) {
      throw new Error('the answer is not signed by a key this replica trusts');
    }
    if (parsed.typ !== REPLICA_TYP || parsed.kind !== kind || parsed.aud !== this.id || parsed.nonce !== nonce) throw new Error('the answer is not bound to this request (type, audience or nonce)');
    return { status: answer.status, message: parsed };
  }
  private send(method: string, path: string, body: Buffer | undefined, timeout: number, hop = true): Promise<{ status: number; headers: IncomingHttpHeaders; body: Buffer }> {
    const url = new URL(path, this.leader);
    const payload = body ?? Buffer.alloc(0);
    const headers = { 'content-length': String(payload.length), ...(this.tenantId ? { 'x-gate-tenant': this.tenantId } : {}), ...(body ? { 'content-type': 'application/json' } : {}),
      ...(hop ? { [REPLICA_HOP_HEADER]: signHop(this.hopKey, method, url.pathname + url.search, payload, `replica:${this.id}`, this.id) } : {}) };
    return new Promise((done, fail) => {
      const req = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, { method, headers, timeout, ...(this.ca ? { ca: this.ca } : {}) }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => done({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
        res.on('error', fail);
      });
      this.inflight.add(req);
      req.on('close', () => this.inflight.delete(req));
      req.on('timeout', () => req.destroy(new Error('the database node did not answer in time')));
      req.on('error', fail);
      req.end(payload);
    });
  }
  /** Bootstrap without a pin: the JWKS, over TLS verified against GATE_REPLICA_CA_FILE (or the system store). */
  private async jwks(): Promise<string[]> {
    const answer = await this.send('GET', '/.well-known/jwks.json', undefined, 15_000, false);
    if (answer.status !== 200) throw new Error(`JWKS bootstrap failed: ${answer.status}`);
    const keys = (JSON.parse(answer.body.toString('utf8')) as { keys?: Array<Record<string, unknown>> }).keys ?? [];
    const x = keys.filter((k) => k.kty === 'OKP' && k.crv === 'Ed25519' && typeof k.x === 'string').map((k) => k.x as string);
    if (!x.length) throw new Error('JWKS bootstrap failed: no Ed25519 key');
    return x;
  }
  private loadTrust(): { trusted: string[]; at: Generation } | undefined {
    if (!existsSync(this.trustFile)) return undefined;
    const fail = (): never => { throw new Error(`${this.trustFile} does not verify under GATE_REPLICA_KEY: restore it, or delete it to bootstrap trust (and the rollback floor) again`); };
    let stored: unknown;
    try { stored = JSON.parse(readFileSync(this.trustFile, 'utf8')); } catch { return fail(); }
    if (!isObject(stored) || typeof stored.mac !== 'string') return fail();
    const { mac, ...signed } = stored as { mac: string; trusted: string[]; at: Generation };
    if (!macMatches(this.trustKey, signed, mac) || !Array.isArray(signed.trusted) || !isObject(signed.at)) return fail();
    return signed;
  }
  private saveTrust(): void {
    const signed = { trusted: [...this.trust.x].sort(), at: this.at! };
    const temp = `${this.trustFile}.${randomBytes(6).toString('hex')}.tmp`;
    writeFileSync(temp, JSON.stringify({ ...signed, mac: auditMac(this.trustKey, signed) }), { mode: 0o600 });
    renameSync(temp, this.trustFile);
  }
  private sleep(ms: number): Promise<void> {
    return new Promise((done) => {
      const wake = (): void => { clearTimeout(timer); this.sleepers.delete(wake); done(); };
      const timer = setTimeout(wake, ms); timer.unref();
      this.sleepers.add(wake);
    });
  }
}

/** GATE_REPLICA_PIN: comma-separated Ed25519 public keys, each its JWK `x` as /.well-known/jwks.json lists it. */
export function parsePins(raw: string | undefined): string[] | undefined {
  if (raw === undefined || raw.trim() === '') return undefined;
  return raw.split(',').map((p) => p.trim()).filter(Boolean).map((p) => {
    if (/^[A-Za-z0-9_-]{43}$/.test(p)) return p;
    throw new Error('GATE_REPLICA_PIN must list Ed25519 public keys as their JWK x values (43 base64url characters)');
  });
}
