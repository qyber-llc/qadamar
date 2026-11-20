import pg from 'pg';
import { windowOf, type Resource, type Subject } from '../../core/src/index.ts';
import type { Disk } from './store.ts';
import type { RecordDelta, RecordKind, StoredTuple } from './record-deltas.ts';
import { RECORD_POLICIES, RECORD_SYNC, RECORD_TABLES } from './postgres-schema.ts';
import { databaseTlsFromEnv, postgresClientConfig } from './postgres-tls.ts';

const BATCH = 1000;
const MIGRATE_LOCK = 0x4741544d;
export interface RecordSnapshot { subjects: Subject[]; resources: Resource[]; tuples: StoredTuple[] }
interface SyncRow { records_migrated: boolean; version: string }
const table = (kind: RecordKind): string => `gate_${kind}`;
const column = (kind: RecordKind): string => `${kind}_position`;

export function stateWithoutRecords(value: unknown): unknown {
  const disk = value as Disk | undefined;
  if (!disk?.state || !Array.isArray(disk.state.subjects) || !Array.isArray(disk.state.resources) || !Array.isArray(disk.state.tuples)) return value;
  const { subjects: _subjects, resources: _resources, tuples: _tuples, ...state } = disk.state;
  return { ...disk, state };
}

export function materializeState(docs: Map<string, unknown>, records: RecordSnapshot): void {
  const disk = docs.get('state') as Disk | undefined;
  if (!disk?.state) return;
  docs.set('state', { ...disk, state: { ...disk.state, subjects: records.subjects, resources: records.resources, tuples: records.tuples } });
}

/** Inside the schema transaction and MIGRATE_LOCK: a 0.6.0 document becomes rows and metadata in one commit. */
export async function migrateLegacyRecords(client: pg.Client): Promise<boolean> {
  const sync = (await client.query<SyncRow>('SELECT records_migrated, version FROM gate_sync FOR UPDATE')).rows[0]!;
  if (sync.records_migrated) return false;
  const stored = (await client.query<{ body: string }>(`SELECT body FROM gate_doc WHERE name = 'state'`)).rows[0]?.body;
  if (stored !== undefined) {
    const disk = JSON.parse(stored) as Disk;
    if (!Array.isArray(disk.state?.subjects) || !Array.isArray(disk.state.resources) || !Array.isArray(disk.state.tuples)) {
      if (!disk.state) throw new Error('Stored state is malformed: no state object');
    } else {
      refuseDuplicates(disk.state);
      await importRows(client, 'subject', disk.state.subjects, Number(sync.version));
      await importRows(client, 'resource', disk.state.resources, Number(sync.version));
      await importRows(client, 'tuple', disk.state.tuples, Number(sync.version));
      await client.query('UPDATE gate_sync SET subject_position = $1, resource_position = $2, tuple_position = $3',
        [disk.state.subjects.length, disk.state.resources.length, disk.state.tuples.length]);
      await client.query(`UPDATE gate_doc SET body = $1, updated_at = now() WHERE name = 'state'`, [JSON.stringify(stateWithoutRecords(disk))]);
    }
  }
  await client.query('UPDATE gate_sync SET records_migrated = true');
  return true;
}

/** One row per (type, id) (tuples: id): an earlier version could store a duplicate, which one row cannot hold. Refused
 *  before anything is written (the caller's transaction rolls back), naming them, rather than keeping one silently. */
function refuseDuplicates(state: Disk['state']): void {
  const duplicates: string[] = [];
  for (const [kind, values] of [['subject', state.subjects], ['resource', state.resources], ['tuple', state.tuples]] as const) {
    const seen = new Set<string>();
    for (const value of values as ReadonlyArray<{ id: string; type?: string }>) {
      const key = kind === 'tuple' ? value.id : `${value.type}:${value.id}`;
      if (seen.has(key)) duplicates.push(`${kind} ${key}`); else seen.add(key);
    }
  }
  if (duplicates.length) {
    throw new Error(`Record migration refused, nothing was changed: the stored state holds duplicate records (${duplicates.length}): ` +
      `${[...new Set(duplicates)].slice(0, 20).join(', ')}. Remove the duplicates from the 'state' document, then start again.`);
  }
}

async function importRows(client: pg.Client, kind: RecordKind, values: readonly (Subject | Resource | StoredTuple)[], version: number): Promise<void> {
  for (let start = 0; start < values.length; start += BATCH) {
    const rows = values.slice(start, start + BATCH).map((value, index): RecordDelta => ({
      kind, op: 'put', type: kind === 'tuple' ? '' : (value as Subject | Resource).type, id: value.id, value, position: start + index + 1,
    }));
    await putRows(client, kind, rows, version);
  }
}

export async function loadRecordSnapshot(client: pg.Client): Promise<RecordSnapshot> {
  const subjects = (await client.query<{ body: string }>('SELECT body FROM gate_subject ORDER BY position, type, id')).rows;
  const resources = (await client.query<{ body: string }>('SELECT body FROM gate_resource ORDER BY position, type, id')).rows;
  const tuples = (await client.query<{ body: string }>('SELECT body FROM gate_tuple ORDER BY position, id')).rows;
  return {
    subjects: subjects.map((row) => JSON.parse(row.body) as Subject),
    resources: resources.map((row) => JSON.parse(row.body) as Resource),
    tuples: tuples.map((row) => JSON.parse(row.body) as StoredTuple),
  };
}

/** Allocates durable array positions and writes only this batch's rows and change records. */
export async function writeRecordBatch(client: pg.Client, records: readonly RecordDelta[], version: number, seq: number): Promise<void> {
  let positioned = records;
  for (const kind of ['subject', 'resource', 'tuple'] as const) {
    const count = records.filter((row) => row.kind === kind && row.op === 'put').length;
    if (!count) continue;
    const last = Number((await client.query<{ position: string }>(
      `UPDATE gate_sync SET ${column(kind)} = ${column(kind)} + $1 RETURNING ${column(kind)} AS position`, [count])).rows[0]!.position);
    let next = last - count + 1;
    positioned = positioned.map((row) => row.kind === kind && row.op === 'put' ? { ...row, position: next++ } : row);
  }
  for (const kind of ['subject', 'resource', 'tuple'] as const) {
    const rows = positioned.filter((row) => row.kind === kind);
    const removed = rows.filter((row) => row.op === 'delete');
    if (removed.length) {
      if (kind === 'tuple') await client.query(`DELETE FROM gate_tuple WHERE id = ANY($1::text[])`, [removed.map((row) => row.id)]);
      else await client.query(`DELETE FROM ${table(kind)} WHERE (type, id) IN (SELECT * FROM unnest($1::text[], $2::text[]))`,
        [removed.map((row) => row.type), removed.map((row) => row.id)]);
    }
    await putRows(client, kind, rows.filter((row) => row.op === 'put'), version);
  }
  // move: a reorder followers cannot replay from single rows; they reload the ordered snapshot instead (postgres.ts)
  await client.query(`INSERT INTO gate_state_change (seq, version, kind, type, id, op, position, body, move)
    SELECT $1, $2, kind, type, id, op, position, body, move FROM unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::bigint[], $8::text[], $9::boolean[])
      AS v(kind, type, id, op, position, body, move)`,
  [seq, version, positioned.map((row) => row.kind), positioned.map((row) => row.type), positioned.map((row) => row.id),
    positioned.map((row) => row.op), positioned.map((row) => row.position ?? null), positioned.map((row) => row.value ? JSON.stringify(row.value) : null), positioned.map((row) => row.move === true)]);
}

async function putRows(client: pg.Client, kind: RecordKind, rows: readonly RecordDelta[], version: number): Promise<void> {
  for (const move of [false, true]) {
    const selected = rows.filter((row) => (row.move === true) === move);
    if (!selected.length) continue;
    const position = move ? ', position = EXCLUDED.position' : '';
    if (kind === 'tuple') {
      const values = selected.map((row) => row.value as StoredTuple);
      await client.query(`INSERT INTO gate_tuple (id, position, state_version, object_type, object_id, subject_type, subject_id, body, not_before, not_after)
        SELECT id, position, $3, object_type, object_id, subject_type, subject_id, body, not_before, not_after
          FROM unnest($1::text[], $2::bigint[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[])
          AS v(id, position, object_type, object_id, subject_type, subject_id, body, not_before, not_after)
        ON CONFLICT (id) DO UPDATE SET state_version = EXCLUDED.state_version, object_type = EXCLUDED.object_type,
          object_id = EXCLUDED.object_id, subject_type = EXCLUDED.subject_type, subject_id = EXCLUDED.subject_id,
          body = EXCLUDED.body, not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after${position}`,
      [selected.map((row) => row.id), selected.map((row) => row.position ?? 0), version, values.map((row) => row.object.type),
        values.map((row) => row.object.id), values.map((row) => row.subject.type), values.map((row) => row.subject.id), selected.map((row) => JSON.stringify(row.value)),
        values.map((row) => windowOf(row).from ?? null), values.map((row) => windowOf(row).to ?? null)]);
      continue;
    }
    await client.query(`INSERT INTO ${table(kind)} (type, id, position, state_version, body)
      SELECT type, id, position, $3, body FROM unnest($1::text[], $2::text[], $4::bigint[], $5::text[]) AS v(type, id, position, body)
      ON CONFLICT (type, id) DO UPDATE SET state_version = EXCLUDED.state_version, body = EXCLUDED.body${position}`,
    [selected.map((row) => row.type), selected.map((row) => row.id), version, selected.map((row) => row.position ?? 0), selected.map((row) => JSON.stringify(row.value))]);
  }
}

export interface ChangeRow { seq: string; kind: RecordKind; type: string; id: string; op: 'put' | 'delete'; position: string | null; body: string | null; move: boolean }
export const parseChange = (row: ChangeRow): RecordDelta => ({ kind: row.kind, type: row.type, id: row.id, op: row.op,
  ...(row.position === null ? {} : { position: Number(row.position) }), ...(row.body === null ? {} : { value: JSON.parse(row.body) as RecordDelta['value'] }) });

/** Restore entry point: adds the record schema to an older archive before importing its state document. */
export async function migrateRecordStore(url: string, databaseTls = databaseTlsFromEnv()): Promise<boolean> {
  const client = new pg.Client(postgresClientConfig(url, databaseTls));
  await client.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [MIGRATE_LOCK]);
    await client.query(RECORD_SYNC);
    await client.query(RECORD_TABLES);
    await client.query(`DO $$ BEGIN ${RECORD_POLICIES} END $$`);
    await client.query('REVOKE UPDATE, DELETE, TRUNCATE ON gate_state_change FROM CURRENT_USER');
    const migrated = await migrateLegacyRecords(client);
    await client.query('COMMIT');
    return migrated;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally { await client.end(); }
}
