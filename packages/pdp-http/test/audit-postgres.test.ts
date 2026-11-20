import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import pg from 'pg';
import { canonical } from '../../core/src/index.ts';
import { GENESIS, sha256, type AuditRecord } from '../src/audit.ts';
import { PgLedger, SCHEMA, serviceGrants } from '../src/postgres.ts';
import { retainPostgres } from '../src/audit-maintenance.ts';
import { CHECKPOINT_KEY_LABEL, derivedKey } from '../src/tokens.ts';
import { FIXED } from './helpers.ts';
import { hasOpensslTs, startTsa } from './tsa.ts';

const admin = process.env.TEST_DATABASE_URL;
const skip = admin ? false : 'TEST_DATABASE_URL is not set';
const SEAL = randomBytes(32).toString('base64url');
const KEY = derivedKey(SEAL, CHECKPOINT_KEY_LABEL)!;

async function database(t: TestContext) {
  const tag = randomBytes(5).toString('hex');
  const name = `gate_audit_${tag}`, owner = `audit_owner_${tag}`, app = `audit_app_${tag}`;
  const password = randomBytes(16).toString('base64url');
  const root = new pg.Client({ connectionString: admin }); await root.connect();
  await root.query(`CREATE DATABASE ${name}`);
  await root.query(`CREATE ROLE ${owner} LOGIN PASSWORD '${password}'`);
  await root.query(`CREATE ROLE ${app} LOGIN PASSWORD '${password}'`);
  await root.end();
  const url = (role: string): string => {
    const value = new URL(admin!); value.pathname = `/${name}`; value.username = role; value.password = password;
    return value.toString();
  };
  t.after(async () => {
    const c = new pg.Client({ connectionString: admin }); await c.connect();
    await c.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    for (const role of [app, owner]) await c.query(`DROP ROLE IF EXISTS ${role}`);
    await c.end();
  });
  const ownerUrl = url(owner), appUrl = url(app);
  const setupUrl = new URL(admin!); setupUrl.pathname = `/${name}`;
  const setup = new pg.Client({ connectionString: setupUrl.toString() }); await setup.connect();
  await setup.query('GRANT CREATE ON SCHEMA public TO ' + owner);
  await setup.query(`SET ROLE ${owner}`); await setup.query(SCHEMA); await setup.query('RESET ROLE');
  await setup.query(serviceGrants(app)); await setup.end();
  const sql = async (text: string, values: unknown[] = []): Promise<pg.QueryResult> => {
    const c = new pg.Client({ connectionString: ownerUrl }); await c.connect();
    try { return await c.query(text, values); } finally { await c.end(); }
  };
  return { ownerUrl, appUrl, sql };
}

test('PostgreSQL owner retention seals before deleting, verifies from the sealed head after restart, and keeps service DELETE forbidden', { skip }, async (t) => {
  const db = await database(t);
  let ledger = await PgLedger.open(db.appUrl, () => undefined, { checkpointKey: KEY });
  let at = Date.parse(FIXED);
  for (const subject of ['alice', 'bob', 'carol']) {
    ledger.auditLog(() => new Date(at).toISOString()).append({ type: 'decision', actor: 'pep', action: 'read', subject, effect: 'allow' });
    at += 86_400_000;
  }
  await ledger.commit(); assert.ok(await ledger.recheck()); await ledger.close();
  const app = new pg.Client({ connectionString: db.appUrl }); await app.connect();
  await assert.rejects(app.query('DELETE FROM gate_audit'), /permission denied/);
  await assert.rejects(app.query('DELETE FROM gate_audit_segment'), /permission denied/);
  await app.end();

  const sealed = await retainPostgres({ databaseUrl: db.ownerUrl, checkpointKey: KEY, retentionDays: 1, now: () => new Date(at).toISOString() });
  assert.equal(sealed.length, 1); assert.equal(sealed[0]?.removed, 2); assert.equal(sealed[0]?.lastSeq, 2);
  assert.equal(Number((await db.sql('SELECT count(*) AS n FROM gate_audit')).rows[0].n), 2, 'one live decision and its retention marker');
  assert.equal(Number((await db.sql('SELECT count(*) AS n FROM gate_audit_segment')).rows[0].n), 1);
  const privileges = (await db.sql(`SELECT has_table_privilege(current_user, 'gate_audit', 'DELETE') AS del,
    has_table_privilege(current_user, 'gate_audit_meta', 'DELETE') AS meta_del,
    has_table_privilege(current_user, 'gate_audit_segment', 'UPDATE') AS seal_update`)).rows[0];
  assert.deepEqual(privileges, { del: false, meta_del: false, seal_update: false }, 'temporary owner privileges are revoked');

  ledger = await PgLedger.open(db.appUrl, () => undefined, { checkpointKey: KEY });
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => new Date(at).toISOString());
  assert.equal(audit.verify().verified, true);
  assert.equal(audit.verify().length, 2);
  assert.equal(audit.verify().fullChain, true);
  assert.equal(audit.tip().seq, 4);
  assert.ok(await ledger.recheck());
  audit.append({ type: 'session', actor: 'sam', action: 'login' });
  await ledger.commit(); assert.equal(audit.tip().seq, 5);
  await ledger.close();

  ledger = await PgLedger.open(db.appUrl, () => undefined, { checkpointKey: KEY });
  assert.equal(ledger.auditLog(() => FIXED).verify().verified, true);
  assert.ok(await ledger.recheck());
  assert.equal(ledger.auditLog(() => FIXED).tip().seq, 5);
  await ledger.close();

  const next = derivedKey(randomBytes(32).toString('base64url'), CHECKPOINT_KEY_LABEL)!;
  const unchanged = await retainPostgres({ databaseUrl: db.ownerUrl, checkpointKey: next, previousCheckpointKey: KEY, retentionDays: 1, now: () => new Date(at).toISOString() });
  assert.deepEqual(unchanged, [], 're-keying seals does not delete another prefix');
  ledger = await PgLedger.open(db.appUrl, () => undefined, { checkpointKey: next });
  assert.equal(ledger.auditLog(() => FIXED).verify().verified, true);
  assert.ok(await ledger.recheck());
});

test('PostgreSQL retention refuses a rehashed chain against a stale genuine checkpoint, and a missing one: nothing sealed or deleted', { skip }, async (t) => {
  const db = await database(t);
  let ledger = await PgLedger.open(db.appUrl, () => undefined, { checkpointKey: KEY });
  let at = Date.parse(FIXED);
  for (const subject of ['alice', 'bob', 'carol']) {
    ledger.auditLog(() => new Date(at).toISOString()).append({ type: 'decision', actor: 'pep', action: 'read', subject, effect: 'allow' });
    at += 86_400_000;
  }
  await ledger.commit(); assert.ok(await ledger.recheck()); await ledger.close();
  const stale = String((await db.sql(`SELECT body FROM gate_doc WHERE name = 'audit_checkpoint'`)).rows[0].body);
  ledger = await PgLedger.open(db.appUrl, () => undefined, { checkpointKey: KEY });
  ledger.auditLog(() => new Date(at).toISOString()).append({ type: 'session', actor: 'sam', action: 'logout' });
  await ledger.commit(); await ledger.close();
  await db.sql(`UPDATE gate_doc SET body = $1 WHERE name = 'audit_checkpoint'`, [stale]); // genuine, one row behind
  assert.deepEqual(await retainPostgres({ databaseUrl: db.ownerUrl, checkpointKey: KEY, retentionDays: 36_500, now: () => new Date(at).toISOString() }), [],
    'a genuine chain that extends a lagging checkpoint passes the check');
  // an owner-level attacker rewrites every row (one more than the checkpoint names) and rehashes the chain with plain SHA-256
  const genuine = (await db.sql('SELECT record FROM gate_audit ORDER BY seq')).rows.map((row) => JSON.parse(String(row.record)) as AuditRecord);
  let prev = GENESIS;
  const forged = [...genuine, { ...genuine.at(-1)!, seq: genuine.length + 1 }].map((row) => {
    const { hash: ignored, ...rest } = { ...row, actor: 'mallory', prevHash: prev }; void ignored;
    prev = sha256(prev + canonical(rest));
    return { ...rest, hash: prev };
  });
  await db.sql('GRANT DELETE ON gate_audit TO CURRENT_USER'); await db.sql('DELETE FROM gate_audit');
  for (const row of forged) await db.sql('INSERT INTO gate_audit (node, seq, record) VALUES ($1, $2, $3)', ['0', row.seq, JSON.stringify(row)]);
  await db.sql('REVOKE DELETE ON gate_audit FROM CURRENT_USER');
  const retain = (): Promise<unknown> => retainPostgres({ databaseUrl: db.ownerUrl, checkpointKey: KEY, retentionDays: 1, now: () => new Date(at).toISOString() });
  await assert.rejects(retain(), /do not extend the authenticated checkpoint/);
  await db.sql(`UPDATE gate_doc SET body = 'null' WHERE name = 'audit_checkpoint'`);
  await assert.rejects(retain(), /missing or unauthenticated checkpoint/);
  assert.equal(Number((await db.sql('SELECT count(*) AS n FROM gate_audit')).rows[0].n), forged.length, 'no row deleted');
  assert.equal(Number((await db.sql('SELECT count(*) AS n FROM gate_audit_segment')).rows[0].n), 0, 'no segment written');
  const privileges = (await db.sql(`SELECT has_table_privilege(current_user, 'gate_audit', 'DELETE') AS del`)).rows[0];
  assert.deepEqual(privileges, { del: false }, 'a refused run revokes its temporary privileges too');
});

test('PostgreSQL refuses a subject mapping row whose pseudonym is not the HMAC of its id', { skip }, async (t) => {
  const db = await database(t);
  const ledger = await PgLedger.open(db.appUrl, () => undefined, { checkpointKey: KEY, pseudonymiseSubjects: true });
  ledger.auditLog(() => FIXED).append({ type: 'decision', actor: 'pep', action: 'read', subject: 'alice@example.test', effect: 'allow' });
  ledger.auditLog(() => FIXED).append({ type: 'decision', actor: 'pep', action: 'read', subject: 'bob@example.test', effect: 'allow' });
  await ledger.commit(); await ledger.close();
  // relink alice's pseudonym to bob's key: an erased or other person's rows would resolve to the wrong id
  await db.sql(`UPDATE gate_subject_identity SET key = (SELECT key FROM gate_subject_identity WHERE id = $1) WHERE id = $2`, [JSON.stringify('bob@example.test'), JSON.stringify('alice@example.test')]);
  await assert.rejects(PgLedger.open(db.appUrl, () => undefined, { checkpointKey: KEY, pseudonymiseSubjects: true }), /Invalid audit subject mapping/);
});

test('PostgreSQL decision-only groups commit audit, metadata, tokens and marks in one reusable statement', { skip }, async (t) => {
  const db = await database(t);
  const ledger = await PgLedger.open(db.appUrl, () => undefined, { checkpointKey: KEY });
  t.after(() => ledger.close());
  const writer = (ledger as unknown as { client: pg.Client }).client;
  const original = writer.query;
  const bound = original.bind(writer) as (...args: unknown[]) => Promise<pg.QueryResult>;
  const statements: string[] = [];
  writer.query = (async (...args: unknown[]) => {
    const config = args[0] as string | pg.QueryConfig<unknown[]>;
    statements.push(typeof config === 'string' ? config : config.text);
    return bound(...args);
  }) as unknown as typeof writer.query;
  const audit = ledger.auditLog(() => FIXED);
  const now = Date.now();
  const group = async (base: number): Promise<void> => {
    for (let i = base; i < base + 16; i++) {
      const jti = `decision-${i}`;
      audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: `subject-${i}`, resource: `case-${i}`, effect: 'allow' });
      ledger.stageToken(jti, { claims: { jti, exp: 2_000_000_000 }, context: {} });
      ledger.stageMark({ session: `session-${i}`, subject: `subject-${i}`, mark: { level: 1, started: now, seen: now } });
    }
    await ledger.commit();
  };
  await group(0);
  await group(16);
  writer.query = original;
  const decisions = statements.filter((text) => text.startsWith('WITH audit AS'));
  assert.equal(decisions.length, 2, 'one round trip per group');
  assert.equal(new Set(decisions).size, 1, 'the same prepared statement serves every group');
  assert.equal(statements.filter((text) => text === 'BEGIN' || text === 'COMMIT').length, 0, 'each statement is its own durable transaction');
  for (const table of ['gate_audit', 'gate_audit_meta', 'gate_token', 'gate_blp_mark']) {
    assert.equal(Number((await db.sql(`SELECT count(*) AS n FROM ${table}`)).rows[0].n), 32, table);
  }
  assert.equal(ledger.committed.seq, 32);
  assert.ok(await ledger.recheck(), 'the chained rows and derived metadata still verify');
});

test('PostgreSQL subject erasure removes the mapping atomically with its audit event and preserves verification', { skip }, async (t) => {
  const db = await database(t);
  let ledger = await PgLedger.open(db.appUrl, () => undefined, { checkpointKey: KEY, pseudonymiseSubjects: true });
  const audit = ledger.auditLog(() => FIXED);
  audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'alice@example.test', effect: 'allow' });
  await ledger.commit();
  const stored = JSON.parse(String((await db.sql('SELECT record FROM gate_audit WHERE seq = 1')).rows[0].record)) as { subject: string; hash: string };
  assert.match(stored.subject, /^ps\.[0-9a-f]{32}$/);
  assert.notEqual(stored.subject, 'alice@example.test');
  assert.equal(audit.subjectPseudonym('alice@example.test'), stored.subject);

  assert.deepEqual(await audit.eraseSubject('alice@example.test', 'lina'), { pseudonym: stored.subject, erased: true });
  assert.equal(Number((await db.sql('SELECT count(*) AS n FROM gate_subject_identity WHERE id = $1', [JSON.stringify('alice@example.test')])).rows[0].n), 0);
  const erasedRow = JSON.parse(String((await db.sql('SELECT record FROM gate_audit WHERE seq = 2')).rows[0].record)) as AuditRecord;
  assert.match(erasedRow.actor, /^ps\./, 'the officer who erased is a pseudonym too');
  assert.equal(audit.subjectPseudonym('alice@example.test'), undefined);
  assert.ok(await ledger.recheck());
  const rows = await audit.list({ cursor: 0, limit: 10 });
  assert.equal(rows.items[0]?.hash, stored.hash);
  assert.deepEqual(rows.items[1]?.details, { pseudonym: stored.subject });
  assert.ok(!JSON.stringify(rows.items).includes('alice@example.test'));
  await ledger.close();

  ledger = await PgLedger.open(db.appUrl, () => undefined, { checkpointKey: KEY, pseudonymiseSubjects: true });
  t.after(() => ledger.close());
  assert.equal(ledger.auditLog(() => FIXED).verify().verified, true);
  assert.ok(await ledger.recheck());
});


test('PostgreSQL retention anchors the sealed head before deletion when a TSA is configured', { skip: skip || (hasOpensslTs ? false : 'openssl ts unavailable') }, async (t) => {
  const db = await database(t); const tsa = await startTsa(t);
  let ledger = await PgLedger.open(db.appUrl, () => undefined, { checkpointKey: KEY });
  let at = Date.parse(FIXED);
  for (const subject of ['alice', 'bob']) {
    ledger.auditLog(() => new Date(at).toISOString()).append({ type: 'decision', actor: 'pep', action: 'read', subject, effect: 'allow' });
    at += 86_400_000;
  }
  await ledger.commit(); assert.ok(await ledger.recheck()); await ledger.close();
  const sealed = await retainPostgres({ databaseUrl: db.ownerUrl, checkpointKey: KEY, retentionDays: 1, now: () => new Date(at).toISOString(),
    tsa: { url: tsa.url, caFile: resolve(tsa.dir, 'ca.crt') } });
  assert.equal(sealed[0]?.anchor?.hash, sealed[0]?.head.hash);
  assert.match(tsa.verify(sealed[0]!.anchor!.token, sealed[0]!.head.hash), /Verification: OK/);
  assert.equal(Number((await db.sql('SELECT count(*) AS n FROM gate_anchor')).rows[0].n), 1);
  ledger = await PgLedger.open(db.appUrl, () => undefined, { checkpointKey: KEY });
  t.after(() => ledger.close());
  assert.equal(ledger.auditLog(() => FIXED).verify().verified, true);
  assert.ok(await ledger.recheck());
});
