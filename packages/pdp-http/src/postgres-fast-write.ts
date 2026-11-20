import type pg from 'pg';
import { windowOf } from '../../core/src/index.ts';
import type { AuditRecord } from './audit.ts';
import type { RecordDelta, RecordKind, StoredTuple } from './record-deltas.ts';
import type { RetiredId } from './store.ts';
import { auditCtes, textArray } from './postgres-chains.ts';
import { SESSION_ABSOLUTE_MS, SESSION_IDLE_MS, SESSION_TOMBSTONE_MS, TOKEN_SCOPE, type StoredMark } from './sessions.ts';

export interface RecordWrite {
  docs: ReadonlyArray<readonly [string, string]>;
  records: readonly RecordDelta[];
  rows: readonly AuditRecord[];
  retired: readonly RetiredId[];
}

export interface DecisionWrite {
  rows: readonly AuditRecord[];
  tokens: ReadonlyArray<{ jti: string; body: string; exp: number }>;
  marks: readonly StoredMark[];
}

/** A decision-only batch needs no explicit transaction: this one statement commits its rows durably before it resolves. */
export async function writeDecisionTransaction(client: pg.Client, node: string, b: DecisionWrite): Promise<void> {
  const values: unknown[] = [];
  const param = (value: unknown, type: string): string => `$${values.push(value)}::${type}`;
  const ctes = auditCtes(node, b.rows, param);
  if (b.tokens.length) ctes.push(`decision_tokens AS (INSERT INTO gate_token (jti, node, body, exp)
    SELECT jti, ${param(node, 'text')}, body, exp FROM unnest(${param(b.tokens.map((t) => t.jti), 'text[]')},
      ${param(b.tokens.map((t) => t.body), 'text[]')}, ${param(b.tokens.map((t) => t.exp), 'bigint[]')}) AS v(jti, body, exp))`);
  if (b.marks.length) {
    // Key order matches the general writer, so concurrent nodes cannot deadlock on two marks.
    const rows = [...b.marks].sort((x, y) => x.session < y.session ? -1 : x.session > y.session ? 1 : x.subject < y.subject ? -1 : x.subject > y.subject ? 1 : 0);
    const now = Date.now();
    // a row an open token holds (held_until, pep-sessions.ts) is live too
    const live = `((m.seen > ${param(now - SESSION_IDLE_MS, 'bigint')} AND m.started > ${param(now - SESSION_ABSOLUTE_MS, 'bigint')}) OR m.held_until > ${param(now, 'bigint')})`;
    ctes.push(`blp_marks AS (INSERT INTO gate_blp_mark AS m (session, subject, level, started, seen, held_until)
      SELECT * FROM unnest(${param(rows.map((r) => r.session), 'text[]')}, ${param(rows.map((r) => r.subject), 'text[]')},
        ${param(rows.map((r) => r.mark.level), 'int[]')}, ${param(rows.map((r) => r.mark.started), 'bigint[]')}, ${param(rows.map((r) => r.mark.seen), 'bigint[]')},
        ${param(rows.map((r) => r.mark.hold ?? null), 'bigint[]')})
      ON CONFLICT (session, subject) DO UPDATE SET
        level = CASE WHEN ${live} THEN GREATEST(m.level, EXCLUDED.level) ELSE EXCLUDED.level END,
        started = CASE WHEN ${live} THEN LEAST(m.started, EXCLUDED.started) ELSE EXCLUDED.started END,
        held_until = CASE WHEN ${live} THEN GREATEST(m.held_until, EXCLUDED.held_until) ELSE EXCLUDED.held_until END,
        seen = GREATEST(m.seen, EXCLUDED.seen)
      WHERE ${live} OR starts_with(m.session, ${param(TOKEN_SCOPE, 'text')}) OR m.started <= ${param(now - SESSION_TOMBSTONE_MS, 'bigint')})`);
  }
  const shape = `${Number(b.tokens.length > 0)}${Number(b.marks.length > 0)}`;
  await client.query({ name: `gate_decision_${shape}`, text: `WITH ${ctes.join(',\n')} SELECT 1`, values });
}

/** One server round trip for a record/metadata commit and its audit evidence; the caller still COMMITs separately. */
export async function writeRecordTransaction(client: pg.Client, node: string, b: RecordWrite): Promise<{ version: number; recordSeq: number }> {
  const values: unknown[] = [];
  const param = (value: unknown, type: string): string => `$${values.push(value)}::${type}`;
  const ctes: string[] = [];
  if (b.docs.length) ctes.push(`docs AS (INSERT INTO gate_doc (name, body)
    SELECT name, body FROM unnest(${param(b.docs.map((d) => d[0]), 'text[]')}, ${param(b.docs.map((d) => d[1]), 'text[]')}) AS v(name, body)
    ON CONFLICT (name) DO UPDATE SET body = EXCLUDED.body, updated_at = now())`);
  const counts = Object.fromEntries(['subject', 'resource', 'tuple'].map((kind) => [kind, b.records.filter((r) => r.kind === kind && r.op === 'put').length])) as Record<RecordKind, number>;
  ctes.push(`sync AS (UPDATE gate_sync SET version = version + 1, records = records + ${b.records.length ? 1 : 0},
    subject_position = subject_position + ${counts.subject}, resource_position = resource_position + ${counts.resource}, tuple_position = tuple_position + ${counts.tuple}
    RETURNING version, records, subject_position, resource_position, tuple_position)`);
  for (const kind of ['subject', 'resource', 'tuple'] as const) {
    const rows = b.records.filter((r) => r.kind === kind);
    const removed = rows.filter((r) => r.op === 'delete');
    if (removed.length) {
      ctes.push(`delete_${kind} AS (${kind === 'tuple'
        ? `DELETE FROM gate_tuple WHERE id = ANY(${param(removed.map((r) => r.id), 'text[]')})`
        : `DELETE FROM gate_${kind} WHERE (type, id) IN (SELECT * FROM unnest(${param(removed.map((r) => r.type), 'text[]')}, ${param(removed.map((r) => r.id), 'text[]')}))`})`);
    }
    const puts = rows.filter((r) => r.op === 'put');
    if (!puts.length) continue;
    const positions = `ARRAY(SELECT ${kind}_position - ${puts.length} + i FROM sync, generate_series(1, ${puts.length}) AS i)`;
    if (kind === 'tuple') {
      const tuples = puts.map((r) => r.value as StoredTuple);
      ctes.push(`put_tuple AS (INSERT INTO gate_tuple (id, position, state_version, object_type, object_id, subject_type, subject_id, body, not_before, not_after)
        SELECT id, position, (SELECT version FROM sync), object_type, object_id, subject_type, subject_id, body, not_before, not_after FROM unnest(
          ${param(puts.map((r) => r.id), 'text[]')}, ${positions}, ${param(tuples.map((r) => r.object.type), 'text[]')},
          ${param(tuples.map((r) => r.object.id), 'text[]')}, ${param(tuples.map((r) => r.subject.type), 'text[]')},
          ${param(tuples.map((r) => r.subject.id), 'text[]')}, ${param(puts.map((r) => JSON.stringify(r.value)), 'text[]')},
          ${param(tuples.map((r) => windowOf(r).from ?? null), 'text[]')}, ${param(tuples.map((r) => windowOf(r).to ?? null), 'text[]')})
          AS v(id, position, object_type, object_id, subject_type, subject_id, body, not_before, not_after)
        ON CONFLICT (id) DO UPDATE SET state_version = EXCLUDED.state_version, object_type = EXCLUDED.object_type,
          object_id = EXCLUDED.object_id, subject_type = EXCLUDED.subject_type, subject_id = EXCLUDED.subject_id, body = EXCLUDED.body,
          not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after)`);
    } else {
      ctes.push(`put_${kind} AS (INSERT INTO gate_${kind} (type, id, position, state_version, body)
        SELECT type, id, position, (SELECT version FROM sync), body FROM unnest(${param(puts.map((r) => r.type), 'text[]')},
          ${param(puts.map((r) => r.id), 'text[]')}, ${positions}, ${param(puts.map((r) => JSON.stringify(r.value)), 'text[]')})
          AS v(type, id, position, body)
        ON CONFLICT (type, id) DO UPDATE SET state_version = EXCLUDED.state_version, body = EXCLUDED.body)`);
    }
  }
  if (b.records.length) {
    const putIndexes = new Map<RecordKind, number>([['subject', 0], ['resource', 0], ['tuple', 0]]);
    const positions = b.records.map((r) => r.op === 'put' ? putIndexes.set(r.kind, putIndexes.get(r.kind)! + 1).get(r.kind)! : null);
    const position = `CASE v.kind WHEN 'subject' THEN (SELECT subject_position FROM sync) - ${counts.subject} + v.put_index
      WHEN 'resource' THEN (SELECT resource_position FROM sync) - ${counts.resource} + v.put_index
      ELSE (SELECT tuple_position FROM sync) - ${counts.tuple} + v.put_index END`;
    ctes.push(`change_log AS (INSERT INTO gate_state_change (seq, version, kind, type, id, op, position, body)
      SELECT (SELECT records FROM sync), (SELECT version FROM sync), kind, type, id, op,
        CASE WHEN op = 'delete' THEN NULL ELSE ${position} END, body FROM unnest(
        ${param(b.records.map((r) => r.kind), 'text[]')}, ${param(b.records.map((r) => r.type), 'text[]')},
        ${param(b.records.map((r) => r.id), 'text[]')}, ${param(b.records.map((r) => r.op), 'text[]')},
        ${param(positions, 'int[]')}, ${param(b.records.map((r) => r.value ? JSON.stringify(r.value) : null), 'text[]')})
        AS v(kind, type, id, op, put_index, body))`);
  }
  if (b.rows.length) {
    ctes.push(`audit AS (INSERT INTO gate_audit (node, seq, record) SELECT ${param(node, 'text')}, seq, record FROM unnest(
      ${param(b.rows.map((r) => r.seq), 'bigint[]')}, ${param(b.rows.map((r) => JSON.stringify(r)), 'text[]')}) AS v(seq, record))`);
    ctes.push(`audit_meta AS (INSERT INTO gate_audit_meta (node, seq, ts, type, effect, subject, resource, rules)
      SELECT ${param(node, 'text')}, seq, ts, type, effect, subject, resource, rules::text[] FROM unnest(
        ${param(b.rows.map((r) => r.seq), 'bigint[]')}, ${param(b.rows.map((r) => r.ts), 'text[]')}, ${param(b.rows.map((r) => r.type), 'text[]')},
        ${param(b.rows.map((r) => r.effect ?? null), 'text[]')}, ${param(b.rows.map((r) => r.subject === undefined ? null : JSON.stringify(r.subject)), 'text[]')},
        ${param(b.rows.map((r) => r.resource === undefined ? null : JSON.stringify(r.resource)), 'text[]')},
        ${param(b.rows.map((r) => textArray([...r.rules ?? []].map((rule) => JSON.stringify(rule)))), 'text[]')})
        AS v(seq, ts, type, effect, subject, resource, rules)
      ON CONFLICT (node, seq) DO UPDATE SET ts = EXCLUDED.ts, type = EXCLUDED.type, effect = EXCLUDED.effect,
        subject = EXCLUDED.subject, resource = EXCLUDED.resource, rules = EXCLUDED.rules)`);
  }
  if (b.retired.length) ctes.push(`retired AS (INSERT INTO gate_retired (type, id, version, retired_at, node)
    SELECT type, id, version, retired_at, ${param(node, 'text')} FROM unnest(
      ${param(b.retired.map((r) => r.type), 'text[]')}, ${param(b.retired.map((r) => r.id), 'text[]')},
      ${param(b.retired.map((r) => r.version), 'bigint[]')}, ${param(b.retired.map((r) => r.at), 'text[]')})
      AS v(type, id, version, retired_at) ON CONFLICT DO NOTHING)`);
  ctes.push(`notification AS (SELECT pg_notify('gate_sync', 'v' || (SELECT version FROM sync)) AS delivered)`);
  const result = await client.query<{ version: string; records: string }>(`WITH ${ctes.join(',\n')} SELECT version, records FROM sync, notification`, values);
  return { version: Number(result.rows[0]!.version), recordSeq: Number(result.rows[0]!.records) };
}
