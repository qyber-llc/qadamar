// Executes the real backup/restore scripts only when TEST_DATABASE_URL supplies a PostgreSQL administrator connection.
// Without local PostgreSQL client tools, PG_TOOLS_CONTAINER names a running postgres container whose tools are used instead.
import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { createServer, type PdpServer } from '../src/server.ts';
import { evaluation, FIXED, WHY } from './helpers.ts';

const admin = process.env.TEST_DATABASE_URL;
const skip = admin ? false : 'TEST_DATABASE_URL is not set';
const tables = ['gate_doc', 'gate_audit', 'gate_audit_meta', 'gate_anchor', 'gate_audit_segment', 'gate_subject_identity', 'gate_sync', 'gate_token', 'gate_performed', 'gate_session', 'gate_blp_mark', 'gate_blp_session', 'gate_retired', 'gate_subject', 'gate_resource', 'gate_tuple', 'gate_state_change', 'gate_rate_limit'] as const;
const order: Record<Table, string> = { gate_doc: 'name', gate_audit: 'node, seq', gate_audit_meta: 'node, seq', gate_anchor: 'seq', gate_audit_segment: 'node, seq', gate_subject_identity: 'pseudonym', gate_sync: 'id', gate_token: 'jti', gate_performed: 'seq', gate_session: 'id', gate_blp_mark: 'session, subject', gate_blp_session: 'sid', gate_retired: 'type, id, version', gate_subject: 'type, id', gate_resource: 'type, id', gate_tuple: 'id', gate_state_change: 'seq, kind, type, id', gate_rate_limit: 'key' };
type Table = typeof tables[number];
const scripts = fileURLToPath(new URL('../../../scripts/ops/', import.meta.url));
const pgTools = ['pg_dump', 'pg_restore', 'createdb', 'dropdb', 'psql'];

// test-only shim: the container reaches the database on its own port, and archives cross docker exec on stdin/stdout
const SHIM = `#!/usr/bin/env bash
set -euo pipefail
tool=\${0##*/}
args=() input='' output='' from="@$PG_SHIM_FROM/" to='@127.0.0.1:5432/'
for arg in "$@"; do
  arg=\${arg//"$from"/$to}
  case $arg in
    --file=*) output=\${arg#--file=} ;;
    -*|postgres://*|postgresql://*) args+=("$arg") ;;
    *) if [[ -f $arg ]]; then input=$arg; else args+=("$arg"); fi ;;
  esac
done
if [[ -n $output ]]; then exec docker exec -e PGPASSWORD "$PG_TOOLS_CONTAINER" "$tool" "\${args[@]}" >"$output"; fi
if [[ -n $input ]]; then exec docker exec -i -e PGPASSWORD "$PG_TOOLS_CONTAINER" "$tool" "\${args[@]}" <"$input"; fi
exec docker exec -e PGPASSWORD "$PG_TOOLS_CONTAINER" "$tool" "\${args[@]}"
`;
const installed = (env: NodeJS.ProcessEnv): boolean => pgTools.every((command) => {
  const probe = spawnSync(command, ['--version'], { encoding: 'utf8', env });
  return !probe.error && probe.status === 0;
});
/** Local client tools when present, otherwise shims into PG_TOOLS_CONTAINER; undefined when neither works. */
function toolEnv(dir: string): NodeJS.ProcessEnv | undefined {
  if (installed(process.env)) return process.env;
  if (!process.env.PG_TOOLS_CONTAINER) return undefined;
  const bin = resolve(dir, 'bin'); mkdirSync(bin);
  writeFileSync(resolve(bin, 'pg-shim'), SHIM); chmodSync(resolve(bin, 'pg-shim'), 0o700);
  for (const command of pgTools) symlinkSync('pg-shim', resolve(bin, command));
  const url = new URL(admin!);
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH ?? ''}`, PG_SHIM_FROM: `${url.hostname}:${url.port || '5432'}` };
  return installed(env) ? env : undefined;
}

function backupTools(t: TestContext, dir: string): NodeJS.ProcessEnv | undefined {
  const tools = toolEnv(dir);
  if (tools) return tools;
  const message = 'PostgreSQL client tools unavailable: install pg_dump, pg_restore, createdb, dropdb and psql, or set PG_TOOLS_CONTAINER';
  if (process.env.BACKUP_TESTS_REQUIRED === '1') assert.fail(`${message}: BACKUP_TESTS_REQUIRED=1 forbids skipping`);
  t.skip(message);
  return undefined;
}

function targetUrl(base: string, database: string): string {
  const url = new URL(base);
  url.pathname = `/${database}`;
  url.hash = '';
  return url.toString();
}

async function sql(url: string, statement: string, values: unknown[] = []): Promise<pg.QueryResult> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try { return await client.query(statement, values); } finally { await client.end(); }
}

async function snapshot(url: string): Promise<Record<Table, pg.QueryResultRow[]>> {
  const rows = async (table: Table): Promise<pg.QueryResultRow[]> => (await sql(url, `SELECT * FROM ${table} ORDER BY ${order[table]}`)).rows;
  const result: Partial<Record<Table, pg.QueryResultRow[]>> = {};
  for (const table of tables) result[table] = await rows(table);
  return result as Record<Table, pg.QueryResultRow[]>;
}
/** Keys, indexes and row-level security: what a table-only restore silently loses. */
async function schemaObjects(url: string): Promise<string[]> {
  return (await sql(url, `SELECT 'index ' || indexdef AS o FROM pg_indexes WHERE schemaname = 'public' AND tablename LIKE 'gate\\_%'
    UNION ALL SELECT 'policy ' || tablename || ' ' || policyname || ' ' || cmd FROM pg_policies WHERE schemaname = 'public'
    UNION ALL SELECT 'rls ' || relname || ' ' || relrowsecurity || ' ' || relforcerowsecurity FROM pg_class
      WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' AND relname LIKE 'gate\\_%' ORDER BY 1`)).rows.map((row) => String(row.o));
}

interface Reply { status: number; data: Record<string, unknown>; headers: Headers }
async function call(server: PdpServer, path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}): Promise<Reply> {
  const response = await fetch(`${server.url}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  return { status: response.status, data: text ? JSON.parse(text) as Record<string, unknown> : {}, headers: response.headers };
}

test('custom-format backup restores all Qadamar tables and a node verifies recovered state and audit', { skip, timeout: 120_000 }, async (t) => {
  const suffix = `${process.pid}_${randomBytes(6).toString('hex')}`;
  const seal = randomBytes(32).toString('base64url');
  const key = randomBytes(32).toString('hex');
  const sourceName = `gate_drill_source_${suffix}`;
  const restoredName = `gate_drill_restored_${suffix}`;
  const sourceUrl = targetUrl(admin!, sourceName);
  const restoredUrl = targetUrl(admin!, restoredName);
  const dir = mkdtempSync('/tmp/gate-backup-drill-');
  const archive = resolve(dir, 'gate-backup.dump');
  const tools = backupTools(t, dir);
  if (!tools) { rmSync(dir, { recursive: true, force: true }); return; }
  const root = new pg.Client({ connectionString: admin });
  await root.connect();
  let server: PdpServer | undefined;
  t.after(async () => {
    await server?.close().catch(() => undefined);
    for (const name of [restoredName, sourceName]) {
      await root.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`).catch(() => undefined);
    }
    await root.end().catch(() => undefined);
    rmSync(dir, { recursive: true, force: true });
  });
  await root.query(`CREATE DATABASE "${sourceName}"`);

  const redact = (value: string): string => {
    let safe = value;
    const url = new URL(admin!);
    const secrets = [admin!, sourceUrl, restoredUrl, url.password, key];
    try { secrets.push(decodeURIComponent(url.password)); } catch { /* Keep the encoded form only. */ }
    for (const secret of new Set(secrets)) if (secret) safe = safe.replaceAll(secret, '[redacted]');
    return safe;
  };
  const exec = (name: 'backup.sh' | 'restore.sh', databaseUrl: string, extra: Record<string, string> = {}) => {
    const env = { ...tools, DATABASE_URL: databaseUrl, MAINTENANCE_DATABASE_URL: admin!, BACKUP_FILE: archive, BACKUP_ENCRYPTION_KEY: key, ...extra };
    const result = spawnSync('bash', [resolve(scripts, name)], { env, encoding: 'utf8', timeout: 60_000 });
    const output = `${result.stdout}${result.stderr}`;
    for (const secret of [admin!, sourceUrl, restoredUrl, new URL(admin!).password, env.BACKUP_ENCRYPTION_KEY]) {
      if (secret) assert.ok(!output.includes(secret), `${name} must not print connection credentials or the backup key`);
    }
    return result;
  };
  const runScript = (name: 'backup.sh' | 'restore.sh', databaseUrl: string): void => {
    const result = exec(name, databaseUrl);
    assert.equal(result.status, 0, `${name} failed: ${redact(result.stderr || result.stdout || String(result.error ?? 'unknown error'))}`);
  };
  const refused = async (label: string, extra: Record<string, string>): Promise<void> => {
    const result = exec('restore.sh', restoredUrl, extra);
    assert.notEqual(result.status, 0, `${label}: restore.sh must fail`);
    assert.match(result.stderr, /Restore refused: /, `${label}: restore.sh prints a refusal`);
    assert.equal((await root.query('SELECT 1 FROM pg_database WHERE datname = $1', [restoredName])).rowCount, 0, `${label}: no target database was created`);
  };

  server = createServer({ port: 0, dataDir: dir, databaseUrl: sourceUrl, clock: `fixed:${FIXED}`, signingKeySeal: seal });
  await server.listen();
  const credentials = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as {
    pepApiKey: string; passwords: Record<string, string>;
  };
  const login = async (id: string): Promise<Record<string, string>> => {
    const password = credentials.passwords[id];
    assert.ok(password);
    const response = await call(server!, '/admin/v1/session', 'POST', { username: id, password });
    assert.equal(response.status, 200);
    const cookie = response.headers.get('set-cookie')?.split(';')[0];
    assert.ok(cookie);
    assert.equal(typeof response.data.csrfToken, 'string');
    return { cookie, 'x-csrf-token': String(response.data.csrfToken) };
  };
  const decide = async (): Promise<void> => {
    const response = await call(server!, '/access/v1/evaluation', 'POST', evaluation(), { authorization: `Bearer ${credentials.pepApiKey}` });
    assert.equal(response.status, 200);
  };

  await decide();
  const maker = await login('amira');
  const proposed = await call(server, '/admin/v1/changes', 'POST', {
    kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY,
  }, maker);
  assert.equal(proposed.status, 201);
  const changeId = proposed.data.id;
  assert.equal(typeof changeId, 'string');
  await server.close();
  server = undefined;

  const before = await snapshot(sourceUrl);
  const objects = await schemaObjects(sourceUrl);
  assert.ok(objects.some((o) => o.startsWith('policy ')) && objects.some((o) => o.includes('PRIMARY KEY') || o.includes('_pkey')), 'the source has keys and policies to restore');
  assert.ok(before.gate_audit.length > 0, 'the source contains committed audit rows');
  assert.ok(before.gate_doc.some((row) => row.name === 'state' && String(row.body).includes(String(changeId))), 'the source contains the proposed state change');
  const backupStarted = performance.now();
  runScript('backup.sh', sourceUrl);
  const backupMs = performance.now() - backupStarted;
  const archiveBytes = statSync(archive).size;
  const sealed = readFileSync(archive);
  assert.deepEqual([...sealed.subarray(0, 7)], [...Buffer.from('GATEBK'), 1], 'the archive starts with the GATEBK version 1 header');
  for (const name of tables) assert.ok(!sealed.includes(name), `the archive does not show ${name} in clear`);
  // wipe: the source is gone, so everything after this point comes from the archive
  await root.query(`DROP DATABASE "${sourceName}" WITH (FORCE)`);
  assert.equal((await root.query('SELECT 1 FROM pg_database WHERE datname = $1', [sourceName])).rowCount, 0);

  // a tampered byte in the ciphertext, then the wrong key: both refused before any database is created
  const tampered = Buffer.from(sealed);
  const middle = 19 + Math.floor((tampered.length - 35) / 2);
  tampered[middle] = tampered[middle]! ^ 1;
  writeFileSync(resolve(dir, 'tampered.dump'), tampered, { mode: 0o600 });
  await refused('tampered archive', { BACKUP_FILE: resolve(dir, 'tampered.dump') });
  await refused('wrong key', { BACKUP_ENCRYPTION_KEY: randomBytes(32).toString('hex') });

  const recoveryStarted = performance.now();
  runScript('restore.sh', restoredUrl);
  const restoreMs = performance.now() - recoveryStarted;
  assert.deepEqual(await snapshot(restoredUrl), before, 'fresh-database restore exactly matches every gate table at the backup snapshot');
  assert.deepEqual(await schemaObjects(restoredUrl), objects, 'keys, indexes and row-level security are restored before any node could recreate them');

  server = createServer({ port: 0, dataDir: dir, databaseUrl: restoredUrl, clock: `fixed:${FIXED}`, signingKeySeal: seal });
  await server.listen();
  const restoredMaker = await login('amira');
  const changes = await call(server, '/admin/v1/changes', 'GET', undefined, restoredMaker);
  assert.equal(changes.status, 200);
  const items = changes.data.items as Array<{ id?: unknown; status?: unknown }>;
  assert.ok(items.some((change) => change.id === changeId && change.status === 'pending'), 'the recovered node serves the state written before backup');

  const auditor = await login('sam');
  let verified = await call(server, '/admin/v1/audit/verify', 'GET', undefined, auditor);
  assert.equal(verified.status, 200);
  assert.equal(verified.data.verified, true);
  assert.equal(verified.data.length, (await snapshot(restoredUrl)).gate_audit.length);
  await decide();
  verified = await call(server, '/admin/v1/audit/verify', 'GET', undefined, auditor);
  assert.equal(verified.data.verified, true, 'the recovered chain accepts a new committed decision');
  assert.equal(verified.data.length, (await snapshot(restoredUrl)).gate_audit.length);
  const recoveryMs = performance.now() - recoveryStarted;

  const via = tools === process.env ? 'local client tools' : `client tools in container ${process.env.PG_TOOLS_CONTAINER}`;
  t.diagnostic(`Drill via ${via}: ${before.gate_audit.length} audit rows, archive ${archiveBytes} bytes`);
  t.diagnostic(`Observed backup time: ${Math.round(backupMs)} ms (this run only)`);
  t.diagnostic(`Observed restore script time: ${Math.round(restoreMs)} ms (this run only)`);
  t.diagnostic(`Observed recovery time through state/audit verification and one new decision: ${Math.round(recoveryMs)} ms (this run only, not an RTO objective)`);
  t.diagnostic('Observed quiesced-drill RPO: zero committed gate-table changes lost at the backup snapshot (not a production RPO objective)');
});

test('an archive from before gate_session (0.4.x backup.sh) restores, with gate_session created empty and usable', { skip, timeout: 120_000 }, async (t) => {
  const suffix = `${process.pid}_${randomBytes(6).toString('hex')}`;
  const seal = randomBytes(32).toString('base64url');
  const key = randomBytes(32).toString('hex');
  const sourceName = `gate_legacy_source_${suffix}`, restoredName = `gate_legacy_restored_${suffix}`, freshName = `gate_legacy_fresh_${suffix}`;
  const sourceUrl = targetUrl(admin!, sourceName), restoredUrl = targetUrl(admin!, restoredName), freshUrl = targetUrl(admin!, freshName);
  const dir = mkdtempSync('/tmp/gate-backup-legacy-');
  const tools = backupTools(t, dir);
  if (!tools) { rmSync(dir, { recursive: true, force: true }); return; }
  const root = new pg.Client({ connectionString: admin }); await root.connect();
  let server: PdpServer | undefined;
  t.after(async () => {
    await server?.close().catch(() => undefined);
    for (const name of [restoredName, sourceName, freshName]) await root.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`).catch(() => undefined);
    await root.end().catch(() => undefined);
    rmSync(dir, { recursive: true, force: true });
  });
  for (const name of [sourceName, freshName]) await root.query(`CREATE DATABASE "${name}"`);
  // the backup.sh of 0.4.x: no session/BLP/retired or per-record tables, next to its archive-crypt.ts
  const old = resolve(dir, 'ops'); mkdirSync(old);
  const current = readFileSync(resolve(scripts, 'backup.sh'), 'utf8');
  const legacyScript = current.replace(' gate_audit_segment gate_subject_identity', '').replace(' gate_session gate_blp_mark gate_blp_session gate_retired gate_subject gate_resource gate_tuple gate_state_change gate_rate_limit)', ')').replace('  --table=public.gate_session \\\n', '')
    .replace('  --table=public.gate_audit_segment \\\n', '').replace('  --table=public.gate_subject_identity \\\n', '')
    .replace('  --table=public.gate_blp_mark \\\n', '').replace('  --table=public.gate_blp_session \\\n', '').replace('  --table=public.gate_retired \\\n', '')
    .replace('  --table=public.gate_subject \\\n', '').replace('  --table=public.gate_resource \\\n', '')
    .replace('  --table=public.gate_tuple \\\n', '').replace('  --table=public.gate_state_change \\\n', '').replace('  --table=public.gate_rate_limit \\\n', '');
  assert.ok(!/gate_audit_segment|gate_subject_identity|gate_session|gate_blp_mark|gate_blp_session|gate_retired|gate_subject|gate_resource|gate_tuple|gate_state_change|gate_rate_limit/.test(legacyScript), 'the legacy script names none of these tables');
  writeFileSync(resolve(old, 'backup.sh'), legacyScript);
  writeFileSync(resolve(old, 'archive-crypt.ts'), readFileSync(resolve(scripts, 'archive-crypt.ts')));
  symlinkSync(resolve(scripts, 'database-tls.ts'), resolve(old, 'database-tls.ts'));
  const run = (script: string, databaseUrl: string): ReturnType<typeof spawnSync> => spawnSync('bash', [script], { encoding: 'utf8', timeout: 60_000,
    env: { ...tools, DATABASE_URL: databaseUrl, MAINTENANCE_DATABASE_URL: admin!, BACKUP_FILE: resolve(dir, 'legacy.dump'), BACKUP_ENCRYPTION_KEY: key } });

  server = createServer({ port: 0, dataDir: dir, databaseUrl: sourceUrl, signingKeySeal: seal });
  await server.listen();
  const { passwords } = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<'amira', string> };
  assert.equal((await call(server, '/admin/v1/session', 'POST', { username: 'amira', password: passwords.amira })).status, 200);
  await server.close(); server = undefined;
  const legacy = JSON.parse(String((await sql(sourceUrl, `SELECT body FROM gate_doc WHERE name = 'state'`)).rows[0].body)) as { state: Record<string, unknown> };
  for (const [key, table] of [['subjects', 'gate_subject'], ['resources', 'gate_resource'], ['tuples', 'gate_tuple']] as const) {
    legacy.state[key] = (await sql(sourceUrl, `SELECT body FROM ${table} ORDER BY position`)).rows.map((row) => JSON.parse(String(row.body)));
  }
  await sql(sourceUrl, `UPDATE gate_doc SET body = $1 WHERE name = 'state'`, [JSON.stringify(legacy)]);
  await sql(sourceUrl, `ALTER TABLE gate_sync DROP COLUMN records, DROP COLUMN records_migrated, DROP COLUMN subject_position, DROP COLUMN resource_position, DROP COLUMN tuple_position`);
  await sql(sourceUrl, `DROP TABLE gate_audit_segment, gate_subject_identity, gate_session, gate_blp_mark, gate_blp_session, gate_retired, gate_subject, gate_resource, gate_tuple, gate_state_change, gate_rate_limit`); // the database as 0.4.x left it
  const backup = run(resolve(old, 'backup.sh'), sourceUrl);
  assert.equal(backup.status, 0, String(backup.stderr));

  const restore = run(resolve(scripts, 'restore.sh'), restoredUrl);
  assert.equal(restore.status, 0, String(restore.stderr));
  assert.match(String(restore.stdout), /predates gate_session: created empty/);
  assert.match(String(restore.stdout), /predates gate_blp_mark: created empty/);
  assert.match(String(restore.stdout), /predates gate_blp_session: created empty/);
  assert.equal((await sql(restoredUrl, 'SELECT count(*) AS n FROM gate_session')).rows[0].n, '0');
  assert.equal((await sql(restoredUrl, 'SELECT count(*) AS n FROM gate_blp_mark')).rows[0].n, '0');
  assert.equal((await sql(restoredUrl, 'SELECT count(*) AS n FROM gate_blp_session')).rows[0].n, '0');
  assert.match(String(restore.stdout), /predates gate_retired: created empty/);
  assert.equal((await sql(restoredUrl, 'SELECT count(*) AS n FROM gate_retired')).rows[0].n, '0');
  assert.match(String(restore.stdout), /Legacy state document migrated into per-record tables/);
  for (const [key, table] of [['subjects', 'gate_subject'], ['resources', 'gate_resource'], ['tuples', 'gate_tuple']] as const) {
    assert.equal((await sql(restoredUrl, `SELECT count(*) AS n FROM ${table}`)).rows[0].n, String((legacy.state[key] as unknown[]).length), `${table} is populated during restore`);
  }
  // the same index, row-level security and policy as a schema created by the server
  const sessionObjects = async (url: string): Promise<string[]> => (await schemaObjects(url)).filter((o) => o.includes('gate_session'));
  const fresh = createServer({ port: 0, dataDir: mkdtempSync(resolve(dir, 'fresh-')), databaseUrl: freshUrl, signingKeySeal: seal });
  await fresh.listen(); await fresh.close();
  assert.deepEqual(await sessionObjects(restoredUrl), await sessionObjects(freshUrl));
  assert.ok((await sessionObjects(restoredUrl)).length >= 4, 'primary key, touched index, forced RLS, policy');

  server = createServer({ port: 0, dataDir: dir, databaseUrl: restoredUrl, signingKeySeal: seal });
  await server.listen();
  const signIn = await call(server, '/admin/v1/session', 'POST', { username: 'amira', password: passwords.amira });
  assert.equal(signIn.status, 200, 'the restored node opens sessions in the created table');
  const cookie = String(signIn.headers.get('set-cookie')).split(';')[0]!;
  assert.equal((await call(server, '/admin/v1/session', 'GET', undefined, { cookie })).status, 200);
  assert.equal((await sql(restoredUrl, 'SELECT count(*) AS n FROM gate_session')).rows[0].n, '1');
});

// Stand-ins for the client tools record their argument lists: what `ps` would show while the scripts run.
const RECORDER = `#!/usr/bin/env bash
tool=\${0##*/}
printf '%s\\t%s\\t%s\\n' "$tool" "\${PGPASSWORD-}" "$*" >>"$STUB_LOG"
case $tool in
  pg_dump) for a in "$@"; do [[ $a == --file=* ]] && printf 'archive' >"\${a#--file=}"; done ;;
  pg_restore) if [[ " $* " == *" --list "* ]]; then
    for t in \${STUB_TABLES:-gate_doc gate_audit gate_audit_meta gate_anchor gate_audit_segment gate_subject_identity gate_sync gate_token gate_performed gate_session gate_blp_mark gate_blp_session gate_retired gate_subject gate_resource gate_tuple gate_state_change gate_rate_limit}; do [[ " \${STUB_SKIP-} " == *" $t "* ]] && continue; printf '1; 0 0 TABLE public %s gate\\n' "$t"; done
    for t in \${STUB_DATA:-\${STUB_TABLES:-gate_doc gate_audit gate_audit_meta gate_anchor gate_audit_segment gate_subject_identity gate_sync gate_token gate_performed gate_session gate_blp_mark gate_blp_session gate_retired gate_subject gate_resource gate_tuple gate_state_change gate_rate_limit}}; do [[ " \${STUB_SKIP-} " == *" $t "* ]] && continue; printf '2; 0 0 TABLE DATA public %s gate\\n' "$t"; done
  fi ;;
  psql) if [[ $* == *current_database* ]]; then printf '%s\\n' "$STUB_DB"; else printf 't\\n'; fi ;;
esac
exit 0
`;
const NODE_RECORDER = `#!/usr/bin/env bash
if [[ \${1-} == *migrate-records.ts ]]; then printf 'node\\t%s\\t%s\\n' "\${PGPASSWORD-}" "$*" >>"$STUB_LOG"; exit 0; fi
exec "$REAL_NODE" "$@"
`;
function stubNode(bin: string): void {
  writeFileSync(resolve(bin, 'node'), NODE_RECORDER); chmodSync(resolve(bin, 'node'), 0o700);
}

test('backup and restore pass database passwords and the backup key through the environment, never as process arguments', (t) => {
  const dir = mkdtempSync('/tmp/gate-backup-argv-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = resolve(dir, 'bin'); mkdirSync(bin);
  writeFileSync(resolve(bin, 'recorder'), RECORDER); chmodSync(resolve(bin, 'recorder'), 0o700);
  for (const command of pgTools) symlinkSync('recorder', resolve(bin, command));
  stubNode(bin);
  const log = resolve(dir, 'calls.log');
  const tmp = resolve(dir, 'tmp'); mkdirSync(tmp);
  const backupFile = resolve(dir, 'gate.dump');
  const target = 'p@ss:w/rd%-target', maintenance = 'maintenance-secret-value', key = randomBytes(32).toString('base64url');
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH ?? ''}`, STUB_LOG: log, STUB_DB: 'gate_restored', BACKUP_FILE: backupFile,
    BACKUP_ENCRYPTION_KEY: key, TMPDIR: tmp, REAL_NODE: process.execPath, GATE_PROFILE: 'demo' }; // stub hosts: the demo TLS profile
  const exec = (name: string, extra: Record<string, string>) => {
    const result = spawnSync('bash', [resolve(scripts, name)], { env: { ...env, ...extra }, encoding: 'utf8', timeout: 30_000 });
    assert.ok(!`${result.stdout}${result.stderr}`.includes(key), `${name} must not print the backup key`);
    return result;
  };
  const run = (name: string, extra: Record<string, string>): void => {
    const result = exec(name, extra);
    assert.equal(result.status, 0, `${name}: ${result.stderr}`);
  };
  const restoreUrls = { DATABASE_URL: `postgresql://gate:${encodeURIComponent(target)}@db.internal/gate_restored`,
    MAINTENANCE_DATABASE_URL: `postgresql://admin@db.internal/postgres?password=${maintenance}` };
  assert.notEqual(exec('backup.sh', { DATABASE_URL: 'postgres://gate@db.internal/gate', BACKUP_ENCRYPTION_KEY: '' }).status, 0, 'backup.sh requires a key');
  run('backup.sh', { DATABASE_URL: `postgres://gate:${encodeURIComponent(target)}@db.internal:5432/gate`, DATABASE_TLS: 'require' });
  assert.equal(statSync(backupFile).mode & 0o777, 0o600);
  assert.ok(readFileSync(backupFile).subarray(0, 6).equals(Buffer.from('GATEBK')) && !readFileSync(backupFile).includes('archive'), 'BACKUP_FILE holds the encrypted archive');
  const before = readFileSync(log, 'utf8');
  const wrong = exec('restore.sh', { ...restoreUrls, BACKUP_ENCRYPTION_KEY: randomBytes(32).toString('hex') });
  assert.notEqual(wrong.status, 0);
  assert.match(wrong.stderr, /Restore refused: /);
  assert.equal(readFileSync(log, 'utf8'), before, 'a wrong key stops restore.sh before any client tool runs');
  run('restore.sh', restoreUrls);
  assert.deepEqual(readdirSync(tmp), [], 'no plaintext left in the temporary directory');
  assert.deepEqual(readdirSync(dir).sort(), ['bin', 'calls.log', 'gate.dump', 'tmp'], 'no staging file left next to BACKUP_FILE');
  const calls = readFileSync(log, 'utf8').trim().split('\n').map((line) => line.split('\t') as [string, string, string]);
  assert.deepEqual([...new Set(calls.map(([tool]) => tool))].sort(), ['createdb', 'node', 'pg_dump', 'pg_restore', 'psql']);
  for (const [tool, password, args] of calls) {
    assert.ok(!args.includes(key) && password !== key, `${tool} never sees the backup key`);
    for (const secret of [target, encodeURIComponent(target), maintenance]) assert.ok(!args.includes(secret), `${tool} got a password as an argument`);
    if (tool !== 'pg_restore' || !args.includes('--list')) assert.equal(password, tool === 'createdb' ? maintenance : target, `${tool} reads its password from PGPASSWORD`);
  }
  assert.ok(calls.some(([tool, , args]) => tool === 'pg_dump' && args.includes('postgres://gate@db.internal:5432/gate')), 'the URL keeps its non-TLS connection options');
  assert.ok(calls.every(([, , args]) => !args.includes('sslmode=require')), 'DATABASE_TLS, not a URL sslmode, governs the client tools');
  assert.ok(!calls.some(([tool, , args]) => tool === 'psql' && args.includes('CREATE TABLE')), 'a current archive restores gate_session as it is');

  // an archive from before gate_session (0.4.x): restored, with the table created empty; any other gap is still refused
  const older = 'gate_doc gate_audit gate_audit_meta gate_anchor gate_sync gate_token gate_performed';
  writeFileSync(log, '');
  const legacy = exec('restore.sh', { ...restoreUrls, STUB_TABLES: older });
  assert.equal(legacy.status, 0, legacy.stderr);
  assert.match(legacy.stdout, /predates gate_session: created empty/);
  const created = readFileSync(log, 'utf8').split('\n').filter((line) => line.startsWith('psql\t') && line.includes('CREATE TABLE IF NOT EXISTS gate_session'));
  assert.equal(created.length, 1, 'gate_session is created once, after pg_restore');
  for (const [label, extra] of [['gate_token missing', { STUB_TABLES: older.replace(' gate_token', '') }],
    ['gate_session schema without data', { STUB_DATA: older, STUB_SKIP: 'gate_audit_segment gate_subject_identity gate_blp_mark gate_blp_session gate_retired' }]] as const) {
    const result = exec('restore.sh', { ...restoreUrls, ...extra });
    assert.notEqual(result.status, 0, label);
    assert.match(result.stderr, /Restore refused: archive is missing schema or data for gate_(token|session)\./, label);
  }
});

test('restore.sh restores an archive from before gate_blp_mark with the table created empty; any other missing table is refused', (t) => {
  const dir = mkdtempSync('/tmp/gate-restore-old-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = resolve(dir, 'bin'); mkdirSync(bin);
  writeFileSync(resolve(bin, 'recorder'), RECORDER); chmodSync(resolve(bin, 'recorder'), 0o700);
  for (const command of pgTools) symlinkSync('recorder', resolve(bin, command));
  stubNode(bin);
  const log = resolve(dir, 'calls.log');
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH ?? ''}`, STUB_LOG: log, STUB_DB: 'gate_restored', BACKUP_FILE: resolve(dir, 'gate.dump'),
    BACKUP_ENCRYPTION_KEY: randomBytes(32).toString('base64url'), TMPDIR: dir, REAL_NODE: process.execPath, GATE_PROFILE: 'demo' };
  const exec = (name: string, extra: Record<string, string> = {}) => spawnSync('bash', [resolve(scripts, name)], { env: { ...env, ...extra }, encoding: 'utf8', timeout: 30_000 });
  assert.equal(exec('backup.sh', { DATABASE_URL: 'postgres://gate@db.internal/gate' }).status, 0);
  const restore = { DATABASE_URL: 'postgresql://gate@db.internal/gate_restored' };
  const old = exec('restore.sh', { ...restore, STUB_SKIP: 'gate_blp_mark gate_blp_session gate_retired' });
  assert.equal(old.status, 0, old.stderr);
  assert.match(old.stdout, /predates gate_blp_mark: created empty/);
  assert.match(old.stdout, /predates gate_retired: created empty/);
  const ddl = readFileSync(log, 'utf8').split('\n').filter((line) => line.startsWith('psql') && line.includes('CREATE TABLE IF NOT EXISTS gate_blp_mark'));
  assert.equal(ddl.length, 1, 'the table is created once, after the archive is restored');
  for (const strict of ['gate_performed', 'gate_audit']) {
    const refused = exec('restore.sh', { ...restore, STUB_SKIP: strict });
    assert.notEqual(refused.status, 0);
    assert.match(refused.stderr, new RegExp(`missing schema or data for ${strict}`));
  }
  const current = exec('restore.sh', restore);
  assert.equal(current.status, 0, current.stderr);
  assert.doesNotMatch(current.stdout, /created empty/, 'a current archive restores the table it carries');
});
