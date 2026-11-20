// Per-node hash chains in PostgreSQL: reading, judging and checkpointing them (pure helpers of postgres.ts).
import { createHmac, timingSafeEqual } from 'node:crypto';
import type pg from 'pg';
import { canonical } from '../../core/src/index.ts';
import { GENESIS, LEGACY_NODE, sha256, type Anchor, type AuditRecord, type Head } from './audit.ts';

/** GATE_NODE_ID: starts with a letter or digit, so no id sorts before "0" and a legacy cursor never skips a chain. */
export const NODE_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const START: Head = { seq: 0, hash: GENESIS };
export const byName = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

export interface StoredMetadata {
  meta_seq: string | null; ts: string | null; type: string | null; effect: string | null;
  subject: string | null; resource: string | null; rules: string[] | null;
}
export interface StoredAuditRow extends StoredMetadata { node: string; seq: string; record: string }
/** One chain read from the database: its length, first break, last good head, and the hashes at the requested seqs. */
export interface ChainScan { length: number; brokenAt?: number; head: Head; at: Map<number, string> }
export interface ChainCheck { verified: boolean; length: number; brokenAt?: number; node?: string; heads: Map<string, Head> }
/** `counters`: each chain's audit counters at its head (postgres.ts AuditCounters), so a start from the checkpoint adds
 *  the rows after it instead of aggregating the whole table; covered by the mac, absent in checkpoints of 0.4.2 and before. */
export interface Checkpoint { heads: Map<string, Head>; verifiedAt: string; counters?: Record<string, unknown> }
/** What a recheck verified and anchoring timestamps: one chain "0" is its own head (as before); several chains are
 *  { seq: sum of the head seqs, hash: sha256(canonical(heads)), heads }. */
export interface AuditPoint { seq: number; hash: string; heads?: Record<string, Head> }

/** Chains with retained rows or only a retention seal (a chain whose whole prefix was removed still continues). */
export async function listNodes(client: pg.Client): Promise<string[]> {
  const result = await client.query<{ node: string }>(`
    SELECT node FROM (SELECT node FROM gate_audit UNION SELECT node FROM gate_audit_segment) AS chains ORDER BY node`);
  return result.rows.map((row) => row.node);
}

/** "seq" for chain "0" (the cursor of earlier versions), "node:seq" otherwise. */
export const auditCursor = (row: AuditRecord): string => (row.node ?? LEGACY_NODE) === LEGACY_NODE ? String(row.seq) : `${row.node}:${row.seq}`;

export function auditCtes(node: string, rows: readonly AuditRecord[], param: (value: unknown, type: string) => string): string[] {
  return [
    `audit AS (INSERT INTO gate_audit (node, seq, record) SELECT ${param(node, 'text')}, seq, record FROM unnest(
      ${param(rows.map((r) => r.seq), 'bigint[]')}, ${param(rows.map((r) => JSON.stringify(r)), 'text[]')}) AS v(seq, record))`,
    `audit_meta AS (INSERT INTO gate_audit_meta (node, seq, ts, type, effect, subject, resource, rules)
      SELECT ${param(node, 'text')}, seq, ts, type, effect, subject, resource, rules::text[] FROM unnest(
        ${param(rows.map((r) => r.seq), 'bigint[]')}, ${param(rows.map((r) => r.ts), 'text[]')}, ${param(rows.map((r) => r.type), 'text[]')},
        ${param(rows.map((r) => r.effect ?? null), 'text[]')}, ${param(rows.map((r) => r.subject === undefined ? null : JSON.stringify(r.subject)), 'text[]')},
        ${param(rows.map((r) => r.resource === undefined ? null : JSON.stringify(r.resource)), 'text[]')},
        ${param(rows.map((r) => textArray([...r.rules ?? []].map((rule) => JSON.stringify(rule)))), 'text[]')})
        AS v(seq, ts, type, effect, subject, resource, rules)
      ON CONFLICT (node, seq) DO UPDATE SET ts = EXCLUDED.ts, type = EXCLUDED.type, effect = EXCLUDED.effect,
        subject = EXCLUDED.subject, resource = EXCLUDED.resource, rules = EXCLUDED.rules)`,
  ];
}

export async function insertAudit(client: pg.Client, node: string, rows: readonly AuditRecord[]): Promise<void> {
  if (!rows.length) return;
  const values: unknown[] = [];
  const param = (value: unknown, type: string): string => `$${values.push(value)}::${type}`;
  await client.query({ name: 'gate_audit_insert', text: `WITH ${auditCtes(node, rows, param).join(',\n')} SELECT 1`, values });
}

export async function insertMetadata(client: pg.Client, node: string, rows: readonly AuditRecord[]): Promise<void> {
  if (!rows.length) return;
  await client.query(`
    INSERT INTO gate_audit_meta (node, seq, ts, type, effect, subject, resource, rules)
    SELECT $8, seq, ts, type, effect, subject, resource, rules::text[] FROM
      unnest($1::bigint[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[])
      AS v(seq, ts, type, effect, subject, resource, rules)
    ON CONFLICT (node, seq) DO UPDATE SET ts = EXCLUDED.ts, type = EXCLUDED.type, effect = EXCLUDED.effect,
      subject = EXCLUDED.subject, resource = EXCLUDED.resource, rules = EXCLUDED.rules`, [
    rows.map((r) => r.seq), rows.map((r) => r.ts), rows.map((r) => r.type), rows.map((r) => r.effect ?? null),
    rows.map((r) => r.subject === undefined ? null : JSON.stringify(r.subject)), rows.map((r) => r.resource === undefined ? null : JSON.stringify(r.resource)),
    rows.map((r) => textArray([...r.rules ?? []].map((rule) => JSON.stringify(rule)))), node,
  ]);
}

/** The stored record when it parses, carries its table node and seq and hashes to its own hash; its link to the row
 *  before is the caller's to check. */
export function sealedRecord(stored: StoredAuditRow): AuditRecord | undefined {
  let value: unknown;
  try { value = JSON.parse(stored.record); } catch { return undefined; }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const row = value as AuditRecord;
  const { hash, ...rest } = row;
  return Number(stored.seq) === rest.seq && (rest.node ?? LEGACY_NODE) === stored.node && typeof rest.prevHash === 'string' &&
    sha256(rest.prevHash + canonical(rest)) === hash ? row : undefined;
}

/** The chain heads an anchor names: its `heads`, or for an anchor of the single chain "0" (every anchor before this
 *  version) its own seq and hash. Undefined when `heads` does not hash to the anchored value (a rewritten anchor row). */
export function anchorEntries(a: Anchor): Array<{ node: string; seq: number; hash: string }> | undefined {
  if (!a.heads) return [{ node: LEGACY_NODE, seq: a.seq, hash: a.hash }];
  const entries = Object.entries(a.heads);
  if (!entries.every(([node, h]) => NODE_ID.test(node) && validHead(h))) return undefined;
  const point = auditPoint(new Map(entries));
  if (point.hash !== a.hash || point.seq !== a.seq) return undefined;
  return entries.map(([node, h]) => ({ node, seq: h.seq, hash: h.hash }));
}
export function liveHeads(heads: ReadonlyMap<string, Head>): Map<string, Head> {
  return new Map([...heads].filter(([, h]) => h.seq > 0).sort(([a], [b]) => byName(a, b)));
}
export function auditPoint(heads: ReadonlyMap<string, Head>): AuditPoint {
  const live = liveHeads(heads);
  if (!live.size) return { ...START };
  if (live.size === 1 && live.has(LEGACY_NODE)) return { ...live.get(LEGACY_NODE)! };
  const record = Object.fromEntries([...live].map(([node, h]) => [node, { seq: h.seq, hash: h.hash }]));
  return { seq: [...live.values()].reduce((sum, h) => sum + h.seq, 0), hash: sha256(canonical(record)), heads: record };
}
/** The seqs whose hash a scan must report, per chain: anchored heads and the expected heads. */
export function wanted(anchors: readonly Anchor[], expected: ReadonlyMap<string, Head>): Map<string, Set<number>> {
  const want = new Map<string, Set<number>>();
  const add = (node: string, seq: number): void => { const set = want.get(node) ?? new Set<number>(); set.add(seq); want.set(node, set); };
  for (const a of anchors) for (const e of anchorEntries(a) ?? []) add(e.node, e.seq);
  for (const [node, h] of expected) add(node, h.seq);
  return want;
}
/** First failure, in this order: a chain that does not link, an anchored head that differs, one that is missing, an
 *  expected head (this node's commits, the other chains as last verified) that differs or is missing. */
export function judge(scans: ReadonlyMap<string, ChainScan>, anchors: readonly Anchor[], expected: ReadonlyMap<string, Head>, from?: ReadonlyMap<string, Head>, sealed?: ReadonlyMap<string, Head>): ChainCheck {
  const heads = new Map([...scans].map(([node, s]) => [node, s.head] as const));
  const length = [...scans.values()].reduce((sum, s) => sum + s.length, 0);
  const broken = (node: string, brokenAt: number): ChainCheck => ({ verified: false, length, brokenAt, node, heads });
  for (const [node, s] of scans) if (s.brokenAt !== undefined) return broken(node, s.brokenAt);
  const entries: Array<{ node: string; seq: number; hash: string }> = [];
  for (const a of anchors) {
    const listed = anchorEntries(a);
    if (!listed) return broken(Object.keys(a.heads ?? {})[0] ?? LEGACY_NODE, a.seq);
    // A checkpoint covers anchors up to itself; an authenticated retention seal covers those in its removed prefix.
    entries.push(...listed.filter((e) => e.seq > Math.max(from?.get(e.node)?.seq ?? 0, sealed?.get(e.node)?.seq ?? 0)));
  }
  for (const e of entries) {
    const s = scans.get(e.node);
    if (s && e.seq <= s.head.seq && s.at.get(e.seq) !== e.hash) return broken(e.node, e.seq);
  }
  for (const e of entries) {
    const head = scans.get(e.node)?.head.seq ?? 0;
    if (head < e.seq) return broken(e.node, Math.min(e.seq, head + 1));
  }
  for (const [node, h] of expected) {
    const s = scans.get(node);
    const head = s?.head.seq ?? 0;
    if (head < h.seq || (h.seq > 0 && s?.at.get(h.seq) !== h.hash)) return broken(node, Math.min(h.seq, head + 1));
  }
  return { verified: true, length, heads };
}

const macOf = (key: Buffer, signed: unknown): string => createHmac('sha256', key).update(canonical(signed)).digest('hex');
export function checkpointBody(key: Buffer, c: Checkpoint): Record<string, unknown> {
  const only = c.heads.size === 1 ? c.heads.get(LEGACY_NODE) : undefined;
  const counters = c.counters ? { counters: c.counters } : {};
  const signed = only ? { seq: only.seq, hash: only.hash, verifiedAt: c.verifiedAt, ...counters } : { heads: Object.fromEntries(c.heads), verifiedAt: c.verifiedAt, ...counters };
  return { ...signed, mac: macOf(key, signed) };
}
export function validHead(h: unknown): h is Head {
  if (!h || typeof h !== 'object' || Array.isArray(h)) return false;
  const { seq, hash } = h as Record<string, unknown>;
  return typeof seq === 'number' && Number.isSafeInteger(seq) && seq >= 1 && typeof hash === 'string' && /^[0-9a-f]{64}$/.test(hash);
}
/** A well-formed checkpoint whose mac verifies; anything else is undefined, which the start treats as tampering. */
export function parseCheckpoint(value: unknown, key: Buffer): Checkpoint | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const { seq, hash, heads, verifiedAt, mac, counters } = value as Record<string, unknown>;
  if (typeof verifiedAt !== 'string' || typeof mac !== 'string' || !/^[0-9a-f]{64}$/.test(mac)) return undefined;
  if (counters !== undefined && (!counters || typeof counters !== 'object' || Array.isArray(counters))) return undefined;
  const counted = counters === undefined ? {} : { counters: counters as Record<string, unknown> };
  let parsed: Map<string, Head>; let signed: unknown;
  if (heads !== undefined) {
    if (!heads || typeof heads !== 'object' || Array.isArray(heads)) return undefined;
    const entries = Object.entries(heads as Record<string, unknown>);
    if (!entries.length || !entries.every(([node, h]) => NODE_ID.test(node) && validHead(h))) return undefined;
    parsed = new Map(entries.map(([node, h]) => [node, { seq: (h as Head).seq, hash: (h as Head).hash }]));
    signed = { heads: Object.fromEntries(parsed), verifiedAt, ...counted };
  } else {
    const head = { seq, hash };
    if (!validHead(head)) return undefined;
    parsed = new Map([[LEGACY_NODE, head]]);
    signed = { seq, hash, verifiedAt, ...counted };
  }
  return timingSafeEqual(Buffer.from(mac, 'hex'), Buffer.from(macOf(key, signed), 'hex')) ? { heads: parsed, verifiedAt, ...counted } : undefined;
}

export function metadataMatches(row: AuditRecord, stored: StoredMetadata): boolean {
  const rules = [...row.rules ?? []].map((rule) => JSON.stringify(rule));
  return stored.meta_seq !== null && Number(stored.meta_seq) === row.seq && stored.ts === row.ts && stored.type === row.type && stored.effect === (row.effect ?? null) &&
    stored.subject === (row.subject === undefined ? null : JSON.stringify(row.subject)) &&
    stored.resource === (row.resource === undefined ? null : JSON.stringify(row.resource)) &&
    stored.rules?.length === rules.length && stored.rules.every((rule, i) => rule === rules[i]);
}

export function textArray(values: readonly string[]): string {
  return `{${values.map((value) => `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`).join(',')}}`;
}
