// A database node's side of stateless replicas (docs/API.md §3.9.5): the signed state feed (snapshot, then long-polled
// deltas of the gate_state_change generations) and the ingestion of each replica's own audit chain into gate_audit.
// Every answer is signed (replica-protocol.ts); every request was authenticated by the router (replica hop).
import type { IncomingMessage, ServerResponse } from 'node:http';
import { rowMacValid, type AuditLog, type AuditRecord, type Head } from './audit.ts';
import type { Credentials } from './auth.ts';
import { HttpError, object, rawBody } from './http.ts';
import type { PgLedger } from './postgres.ts';
import type { Disk } from './store.ts';
import type { SigningKeyDisk, Tokens } from './tokens.ts';
import { RateLimiter } from './ratelimit.ts';
import { derive, digest, MAX_WAIT_MS, REPLICA_CHECKPOINT_LABEL, replicaKeyFor, REPLICA_SIGNATURE_HEADER, REPLICA_TYP, signBody, type AuditBatch, type AuditMessage, type Generation, type ReplicaDocs,
  type StateMessage, type SubjectsUpdate } from './replica-protocol.ts';

const NONCE = /^[A-Za-z0-9_-]{16,64}$/;
const GENERATION = /^(\d{1,15})\.(\d{1,15})$/;
/** Full snapshots (a poll without `after`) per replica: a burst for restarts, then a few a minute. */
const FULL_SNAPSHOTS_PER_MINUTE = 6;
/** At most one refusal row per replica and reason this often on the database node's chain; the rest are counted. */
const REFUSAL_ROW_INTERVAL_MS = 60_000;

/** Only what a decision needs: no pending changes or emergencies, the latest publication (its signature), PEP
 *  credentials without the console accounts, and the keyring's public half. */
export function replicaDocs(docs: Record<string, unknown>): ReplicaDocs {
  const disk = docs.state as Disk | undefined; const credentials = docs.credentials as Credentials | undefined;
  const keyring = docs.signing_keys as SigningKeyDisk | undefined;
  if (!disk?.state || !credentials || !keyring) throw new HttpError(503, 'unavailable', 'The shared state is not seeded yet');
  return {
    state: { ...disk, changes: [], emergencies: [], history: disk.history.slice(-1), performed: [] },
    credentials: { users: [], pepCredentials: credentials.pepCredentials },
    signing_keys: { keys: keyring.keys.map(({ privateKey: _private, ...key }) => key) },
    blp_revocations: (docs.blp_revocations ?? []) as ReplicaDocs['blp_revocations'],
  };
}

export class ReplicaSource {
  private readonly ledger: PgLedger; private readonly tokens: Tokens; private readonly audit: AuditLog;
  private readonly commit: () => Promise<void>; private readonly config: StateMessage['config'];
  /** GATE_REPLICA_KEYS: each replica's audit key is derived from its own key (replicaKeyFor), as the replica derives it. */
  private readonly keys: ReadonlyMap<string, Buffer>;
  private readonly snapshots = new RateLimiter();
  private readonly refusals = new Map<string, { at: number; suppressed: number }>();
  constructor(ledger: PgLedger, tokens: Tokens, audit: AuditLog, commit: () => Promise<void>, config: StateMessage['config'], keys: ReadonlyMap<string, Buffer>) {
    this.ledger = ledger; this.tokens = tokens; this.audit = audit; this.commit = commit; this.config = config;
    this.keys = keys;
  }

  async handle(req: IncomingMessage, res: ServerResponse, method: string, path: string, url: URL, replica: string): Promise<void> {
    const nonce = url.searchParams.get('nonce') ?? '';
    if (!NONCE.test(nonce)) throw new HttpError(400, 'bad_request', 'nonce must be 16..64 base64url characters');
    if (method === 'GET' && path === '/x/v1/replica/state') { this.send(res, 200, await this.state(url, replica, nonce)); return; }
    if (method === 'POST' && path === '/x/v1/replica/audit') { const [status, message] = await this.ingest(req, replica, nonce); this.send(res, status, message); return; }
    throw new HttpError(404, 'not_found');
  }

  private async state(url: URL, replica: string, nonce: string): Promise<StateMessage> {
    const q = url.searchParams;
    const after = generation(q.get('after'));
    if (!after) this.snapshots.take(`snapshot:${replica}`, performance.now(), FULL_SNAPSHOTS_PER_MINUTE);
    const wait = Math.min(MAX_WAIT_MS, Math.max(0, Number(q.get('wait') ?? 0) || 0));
    const [epoch, n] = (q.get('subjects') ?? '').split('.');
    const known = Number(n);
    const log = this.ledger.subjectLog;
    const current = (): boolean => {
      const at = this.ledger.generation;
      return Boolean(after && at.version === after.version && at.records === after.records && epoch === log.epoch && known === log.changes.length);
    };
    // nothing new: hold the request until this node commits or applies a change, or the wait ends (a heartbeat)
    if (wait > 0 && current()) {
      await this.ledger.changed(wait);
    }
    const feed = await this.ledger.replicaFeed(after);
    const docs = feed.docs ? replicaDocs(feed.docs) : undefined;
    const docsHash = docs ? digest(JSON.stringify(docs)) : q.get('docs') ?? '';
    const subjects: SubjectsUpdate = epoch === log.epoch && Number.isSafeInteger(known) && known >= 0 && known <= log.changes.length
      ? { epoch: log.epoch, n: log.changes.length, changes: log.changes.slice(known) }
      : { epoch: log.epoch, n: log.changes.length, full: this.ledger.pseudonyms() };
    return { typ: REPLICA_TYP, kind: 'state', aud: replica, nonce, at: { version: feed.version, records: feed.records },
      ...(docs && (docsHash !== q.get('docs') || !after) ? { docs } : {}), docsHash,
      ...(feed.snapshot ? { records: feed.snapshot } : { deltas: feed.deltas ?? [] }), subjects, config: this.config };
  }

  private async ingest(req: IncomingMessage, replica: string, nonce: string): Promise<[number, AuditMessage]> {
    let batch: AuditBatch;
    try {
      const b = object(JSON.parse((await rawBody(req)).toString('utf8')));
      const base = object(b.base);
      if (!Number.isSafeInteger(base.seq) || (base.seq as number) < 0 || typeof base.hash !== 'string' || !/^[0-9a-f]{64}$/.test(base.hash) ||
        !Array.isArray(b.rows) || b.rows.length > 5000) throw new Error();
      batch = { base: { seq: base.seq as number, hash: base.hash }, rows: b.rows as AuditRecord[] };
    } catch { throw new HttpError(400, 'bad_request', 'Expected { base: { seq, hash }, rows: [...] }'); }
    const own = replicaKeyFor(this.keys, replica);
    const key = own && derive(own, REPLICA_CHECKPOINT_LABEL);
    // a row without the replica's MAC was not written by its audit (forged at rest, or by anything else holding the hop)
    const { head, refused } = key && batch.rows.every((row) => rowMacValid(key, row))
      ? await this.ledger.ingestReplica(replica, batch.base, batch.rows) : { head: batch.base, refused: 'tampered' as const };
    if (refused) await this.alert(replica, refused, batch.base, head);
    return [refused ? 409 : 200, { typ: REPLICA_TYP, kind: 'audit', aud: replica, nonce, head, ...(refused ? { refused } : {}) }];
  }

  /** A refused replica chain is a security event on this node's own chain (and in its metrics), and in its log. */
  private async alert(replica: string, reason: string, base: Head, head: Head): Promise<void> {
    // a key holder resending refused batches must not grow this node's chain row by row: one row per minute and reason
    const key = `${replica}\n${reason}`, at = performance.now(), last = this.refusals.get(key);
    if (last && at - last.at < REFUSAL_ROW_INTERVAL_MS) { last.suppressed++; return; }
    this.refusals.delete(key); this.refusals.set(key, { at, suppressed: 0 });
    while (this.refusals.size > 10_000) this.refusals.delete(this.refusals.keys().next().value!);
    console.error(`REPLICA AUDIT REFUSED: replica ${replica}, ${reason} (its head ${base.seq}, stored head ${head.seq}). Its chain is not extended; ` +
      'a replica that lost or replaced its disk must start with a new GATE_NODE_ID (docs/API.md §3.9.5)');
    this.audit.append({ type: 'security', actor: 'system', action: 'replica_audit_refused', effect: 'deny',
      details: { replica, reason, replicaHead: base.seq, storedHead: head.seq, ...(last?.suppressed ? { suppressed: last.suppressed } : {}) } });
    await this.commit();
  }

  private send(res: ServerResponse, status: number, message: StateMessage | AuditMessage): void {
    const text = JSON.stringify({ ...message, signer: this.tokens.activePublic() });
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader(REPLICA_SIGNATURE_HEADER, signBody(this.tokens, text));
    res.end(text);
  }
}

function generation(value: string | null): Generation | undefined {
  if (value === null || value === '') return undefined;
  const m = GENERATION.exec(value);
  if (!m) throw new HttpError(400, 'bad_request', 'after must be <version>.<records>');
  return { version: Number(m[1]), records: Number(m[2]) };
}
