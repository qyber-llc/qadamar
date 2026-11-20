import pg from 'pg';
import { canonical } from '../../core/src/index.ts';
import { LEGACY_NODE, sha256, verifyChain, type Anchor, type AuditRecord, type Head } from './audit.ts';
import { sealSegment, validSegments, type AuditSegment, type SegmentSeal } from './audit-integrity.ts';
import { requestAnchor } from './anchor.ts';
import { anchorEntries, auditPoint, insertAudit, parseCheckpoint } from './postgres-chains.ts';
import { databaseTlsFromEnv, postgresClientConfig, type DatabaseTls } from './postgres-tls.ts';

export interface RetentionOptions {
  databaseUrl: string;
  databaseTls?: DatabaseTls;
  checkpointKey: Buffer;
  previousCheckpointKey?: Buffer;
  retentionDays: number;
  now?: () => string;
  tsa?: { url: string; caFile?: string };
}
interface Planned { node: string; seal: SegmentSeal; rows: AuditRecord[] }
const LEADER_LOCK = 0x47415445;

/** Owner-only, with every Qadamar writer stopped. The seal (and its optional TSA anchor) commits in the same transaction as
 *  the deletion and the retention marker. The service role never needs DELETE on gate_audit. */
export async function retainPostgres(options: RetentionOptions): Promise<AuditSegment[]> {
  if (!Number.isSafeInteger(options.retentionDays) || options.retentionDays < 1 || options.retentionDays > 36_500) throw new Error('AUDIT_RETENTION_DAYS must be an integer in 1..36500');
  const now = options.now ?? (() => new Date().toISOString());
  const sealedAt = now();
  if (!Number.isFinite(Date.parse(sealedAt))) throw new Error('Invalid clock');
  const cutoff = new Date(Date.parse(sealedAt) - options.retentionDays * 86_400_000).toISOString();
  const client = new pg.Client(postgresClientConfig(options.databaseUrl, options.databaseTls ?? databaseTlsFromEnv(), 'demo', { application_name: 'gate_audit_retention' }));
  await client.connect();
  try {
    // Active/standby nodes hold this lock. Cluster writers must also be stopped, as the runbook requires.
    await client.query('SELECT pg_advisory_lock($1)', [LEADER_LOCK]);
    const owned = await client.query<{ owner: boolean }>(`SELECT bool_and(pg_has_role(current_user, c.relowner, 'MEMBER')) AS owner
      FROM pg_class c WHERE c.relname IN ('gate_audit', 'gate_audit_meta', 'gate_audit_segment', 'gate_anchor', 'gate_doc')`);
    if (owned.rows[0]?.owner !== true) throw new Error('Audit retention requires the table owner/maintenance role, not the Qadamar service role');
    // SCHEMA revokes these from a first-start service owner. This explicit owner operation never changes serviceGrants.
    await client.query('GRANT DELETE ON gate_audit, gate_audit_meta TO CURRENT_USER');
    await client.query('GRANT UPDATE ON gate_audit_segment TO CURRENT_USER');
    const segmentRows = (await client.query<{ node: string; body: string }>('SELECT node, body FROM gate_audit_segment ORDER BY node, seq')).rows;
    const grouped = new Map<string, unknown[]>();
    for (const row of segmentRows) grouped.set(row.node, [...grouped.get(row.node) ?? [], JSON.parse(row.body) as unknown]);
    const segments: AuditSegment[] = [];
    const rekey: AuditSegment[] = [];
    for (const [node, values] of grouped) {
      let valid = validSegments(values, options.checkpointKey, node);
      if (!valid && options.previousCheckpointKey) {
        const previous = validSegments(values, options.previousCheckpointKey, node);
        if (previous) {
          valid = previous.map(({ mac: ignored, ...signed }) => sealSegment(options.checkpointKey, signed));
          rekey.push(...valid);
        }
      }
      if (!valid) throw new Error(`Audit integrity failure: retention seal of chain ${node}`);
      segments.push(...valid);
    }
    const anchorRows = (await client.query<{ seq: string; hash: string; tsa: string; gen_time: Date; token: Buffer; heads: string | null }>('SELECT seq, hash, tsa, gen_time, token, heads FROM gate_anchor ORDER BY seq')).rows;
    const anchors: Anchor[] = anchorRows.map((row) => ({ seq: Number(row.seq), hash: row.hash, tsa: row.tsa, genTime: row.gen_time.toISOString(),
      token: row.token.toString('base64'), ...(row.heads === null ? {} : { heads: JSON.parse(row.heads) as Record<string, Head> }) }));
    const nodes = (await client.query<{ node: string }>('SELECT node FROM (SELECT node FROM gate_audit UNION SELECT node FROM gate_audit_segment) chains ORDER BY node')).rows.map((row) => row.node);
    const plans: Planned[] = [];
    const heads = new Map<string, Head>();
    const hashes = new Map<string, Map<number, string>>(); // per chain: every retained row and sealed head, by seq
    for (const node of nodes) {
      const rows = (await client.query<{ record: string }>('SELECT record FROM gate_audit WHERE node = $1 ORDER BY seq', [node])).rows.map((row) => JSON.parse(row.record) as AuditRecord);
      const ownAnchors = anchors.flatMap((anchor) => (anchorEntries(anchor) ?? []).filter((entry) => entry.node === node)
        .map((entry) => ({ ...anchor, seq: entry.seq, hash: entry.hash, heads: undefined })));
      if (!verifyChain(rows, ownAnchors, segments, node).verified) throw new Error(`Audit integrity failure: chain ${node}`);
      hashes.set(node, new Map([...segments.filter((segment) => segment.node === node).map((segment) => [segment.head.seq, segment.head.hash] as const),
        ...rows.map((row) => [row.seq, row.hash] as const)]));
      const sealed = segments.filter((segment) => segment.node === node).at(-1);
      const expired = rows.filter((row) => row.ts < cutoff);
      if (expired.length && expired.some((row, i) => row.seq !== (sealed?.lastSeq ?? 0) + i + 1)) throw new Error(`Audit retention prefix is not contiguous in chain ${node}`);
      const head: Head | undefined = rows.length ? rows.at(-1)! : sealed?.head;
      if (head) heads.set(node, { seq: head.seq, hash: head.hash });
      if (!expired.length) continue;
      const last = expired.at(-1)!;
      plans.push({ node, rows: expired, seal: { version: 1, node, firstSeq: (sealed?.lastSeq ?? 0) + 1, lastSeq: last.seq, removed: expired.length,
        prefixHash: sha256(canonical(expired)), head: { seq: last.seq, hash: last.hash }, sealedAt } });
    }
    const stored = (await client.query<{ body: string | null }>(`SELECT body FROM gate_doc WHERE name = 'audit_checkpoint'`)).rows[0]?.body;
    const storedValue: unknown = stored ? JSON.parse(stored) : null;
    let checkpoint = parseCheckpoint(storedValue, options.checkpointKey);
    if (!checkpoint && options.previousCheckpointKey) checkpoint = parseCheckpoint(storedValue, options.previousCheckpointKey);
    if ((heads.size > 0 && !checkpoint) || (storedValue !== null && !checkpoint)) throw new Error('Audit integrity failure: missing or unauthenticated checkpoint');
    // the live chains must extend the last authenticated checkpoint (it may lag the heads by the rows written after the last
    // recheck, as at a node start): a chain rehashed with plain SHA-256 cannot reproduce the hash it names
    if (checkpoint && [...checkpoint.heads].some(([node, head]) => hashes.get(node)?.get(head.seq) !== head.hash)) {
      throw new Error('Audit integrity failure: the live chains do not extend the authenticated checkpoint');
    }
    for (const segment of rekey) await client.query('UPDATE gate_audit_segment SET body = $1 WHERE node = $2 AND seq = $3', [JSON.stringify(segment), segment.node, segment.lastSeq]);
    if (options.previousCheckpointKey) await client.query(`INSERT INTO gate_doc (name, body) VALUES ('audit_checkpoint', 'null')
      ON CONFLICT (name) DO UPDATE SET body = 'null', updated_at = now()`);
    if (!plans.length) return [];
    const sealedHeads = new Map(heads);
    for (const plan of plans) sealedHeads.set(plan.node, plan.seal.head);
    const point = auditPoint(sealedHeads);
    const anchor = options.tsa ? await requestAnchor(options.tsa.url, point, options.tsa.caFile) : undefined;
    const stamped = anchor ? { ...anchor, ...(point.heads ? { heads: point.heads } : {}) } : undefined;
    const sealed = plans.map((plan) => sealSegment(options.checkpointKey, { ...plan.seal, ...(stamped ? { anchor: stamped } : {}) }));
    await client.query('BEGIN');
    try {
      if (stamped) await client.query('INSERT INTO gate_anchor (seq, hash, tsa, gen_time, token, heads) VALUES ($1, $2, $3, $4, $5, $6)',
        [stamped.seq, stamped.hash, stamped.tsa, stamped.genTime, Buffer.from(stamped.token, 'base64'), stamped.heads ? JSON.stringify(stamped.heads) : null]);
      for (const [i, plan] of plans.entries()) {
        const segment = sealed[i]!;
        await client.query('INSERT INTO gate_audit_segment (node, seq, body) VALUES ($1, $2, $3)', [plan.node, segment.lastSeq, JSON.stringify(segment)]);
        await client.query('DELETE FROM gate_audit_meta WHERE node = $1 AND seq BETWEEN $2 AND $3', [plan.node, segment.firstSeq, segment.lastSeq]);
        await client.query('DELETE FROM gate_audit WHERE node = $1 AND seq BETWEEN $2 AND $3', [plan.node, segment.firstSeq, segment.lastSeq]);
        const node = plan.node === LEGACY_NODE ? {} : { node: plan.node };
        const live = heads.get(plan.node) ?? segment.head;
        const record = JSON.parse(JSON.stringify({ type: 'security', actor: 'system', action: 'audit_retention', ...node,
          details: { firstSeq: segment.firstSeq, lastSeq: segment.lastSeq, removed: segment.removed, prefixHash: segment.prefixHash, sealedHead: segment.head.hash },
          seq: live.seq + 1, ts: sealedAt, prevHash: live.hash })) as Omit<AuditRecord, 'hash'>;
        await insertAudit(client, plan.node, [{ ...record, hash: sha256(record.prevHash + canonical(record)) }]);
      }
      await client.query(`INSERT INTO gate_doc (name, body) VALUES ('audit_checkpoint', 'null')
        ON CONFLICT (name) DO UPDATE SET body = 'null', updated_at = now()`);
      await client.query('COMMIT');
    } catch (err) { await client.query('ROLLBACK').catch(() => undefined); throw err; }
    return sealed;
  } finally {
    await client.query('REVOKE DELETE ON gate_audit, gate_audit_meta FROM CURRENT_USER').catch(() => undefined);
    await client.query('REVOKE UPDATE ON gate_audit_segment FROM CURRENT_USER').catch(() => undefined);
    await client.query('SELECT pg_advisory_unlock($1)', [LEADER_LOCK]).catch(() => undefined);
    await client.end();
  }
}
