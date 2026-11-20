// Runs against a real PostgreSQL when TEST_DATABASE_URL (a superuser URL on a throwaway database) is set; skipped otherwise.
import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import pg from 'pg';
import { canonical, policyVersion, type PolicyBundle } from '../../core/src/index.ts';
import { createServer, type PdpServer, type ServerOptions } from '../src/server.ts';
import { PgLedger, SCHEMA, serviceGrants } from '../src/postgres.ts';
import { GENESIS, sha256, type AuditEvent } from '../src/audit.ts';
import { audit as auditRoute } from '../src/admin/audit.ts';
import { compliance } from '../src/admin/compliance.ts';
import { overview } from '../src/admin/overview.ts';
import { evidencePack } from '../src/admin/evidence.ts';
import { subjectReport } from '../src/admin/privacy.ts';
import { HttpError } from '../src/http.ts';
import { digestMutations, evaluation, FIXED, WHY, fixture, users } from './helpers.ts';
import { hasOpensslTs, startTsa } from './tsa.ts';
import { fromBase32, hotp } from '../src/totp.ts';
import { CHECKPOINT_KEY_LABEL, derivedKey } from '../src/tokens.ts';
import { SESSION_ABSOLUTE_MS, SESSION_TOMBSTONE_MS } from '../src/sessions.ts';
import { Store, type Disk } from '../src/store.ts';
import { applyResourcesInPlace } from '../src/resource-registry.ts';
import { withRecordDeltas } from '../src/record-deltas.ts';
import type { Resource } from '../../core/src/index.ts';
import { AssertionVerifier, bodySha256 } from '../../sdk/src/index.ts';

const admin = process.env.TEST_DATABASE_URL;
const skip = admin ? false : 'TEST_DATABASE_URL is not set';
const SEAL = randomBytes(32).toString('base64url');
const GATE_TABLES = 'gate_doc, gate_audit, gate_audit_meta, gate_anchor, gate_audit_segment, gate_subject_identity, gate_sync, gate_token, gate_performed, gate_session, gate_blp_mark, gate_blp_session, gate_retired, gate_subject, gate_resource, gate_tuple, gate_state_change, gate_rate_limit';
const DROP_GATE_TABLES = `DROP TABLE IF EXISTS ${GATE_TABLES}`;
/** The checkpoint key a node with SIGNING_KEY_SEAL=SEAL derives. */
const CHECKPOINT = { checkpointKey: derivedKey(SEAL, CHECKPOINT_KEY_LABEL) };

/** Fresh tables owned by a non-superuser role, as in production; returns that role's URL. */
async function reset(): Promise<{ appUrl: string; sql: (text: string, values?: unknown[]) => Promise<pg.QueryResult> }> {
  const root = new pg.Client({ connectionString: admin }); await root.connect();
  const password = randomBytes(12).toString('hex');
  await root.query(DROP_GATE_TABLES);
  for (const role of ['gate_app', 'gate_owner']) {
    await root.query(`DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname = '${role}') THEN EXECUTE 'DROP OWNED BY ${role}'; EXECUTE 'DROP ROLE ${role}'; END IF; END $$`);
  }
  // production layout: an owner role migrates, the service role may only read and append (and update derived metadata)
  await root.query('CREATE ROLE gate_owner NOLOGIN');
  await root.query('GRANT CREATE ON SCHEMA public TO gate_owner');
  await root.query('SET ROLE gate_owner'); await root.query(SCHEMA); await root.query('RESET ROLE');
  await root.query(`CREATE ROLE gate_app LOGIN PASSWORD '${password}'`);
  await root.query(serviceGrants('gate_app'));
  await root.end();
  const url = new URL(admin!); url.username = 'gate_app'; url.password = password;
  const sql = async (text: string, values?: unknown[]): Promise<pg.QueryResult> => {
    const c = new pg.Client({ connectionString: admin }); await c.connect();
    try { return await c.query(text, values); } finally { await c.end(); }
  };
  return { appUrl: url.toString(), sql };
}
// the file is deleted at the first sign-in (docs/API.md §1): read it once per data directory
const credentialCache = new Map<string, { pepApiKey: string; passwords: Record<string, string> }>();
function initialCredentials(dir: string): { pepApiKey: string; passwords: Record<string, string> } {
  let found = credentialCache.get(dir);
  if (!found) { found = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string; passwords: Record<string, string> }; credentialCache.set(dir, found); }
  return found;
}

async function client(server: PdpServer, dataDir: string) {
  const credentials = initialCredentials(dataDir);
  const call = async (path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; data: Record<string, unknown>; headers: Headers }> => {
    const res = await fetch(`${server.url}${path}`, { method, headers: { 'content-type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const text = await res.text();
    return { status: res.status, data: text ? JSON.parse(text) as Record<string, unknown> : {}, headers: res.headers };
  };
  const login = async (id: string): Promise<Record<string, string>> => {
    const r = await call('/admin/v1/session', 'POST', { username: id, password: credentials.passwords[id] });
    assert.equal(r.status, 200);
    return { cookie: String(r.headers.get('set-cookie')).split(';')[0]!, 'x-csrf-token': String(r.data.csrfToken) };
  };
  const decide = async (): Promise<void> => { assert.equal((await call('/access/v1/evaluation', 'POST', evaluation(), { authorization: `Bearer ${credentials.pepApiKey}` })).status, 200); };
  return { call, login, decide };
}
const count = async (sql: Awaited<ReturnType<typeof reset>>['sql']): Promise<number> => Number((await sql('SELECT count(*) AS n FROM gate_audit')).rows[0].n);
function auditShape(audit: { verify(): { verified: boolean; length: number; brokenAt?: number; checkedAt?: string; fullChain?: boolean } }): { verified: boolean; length: number; brokenAt?: number } {
  const { checkedAt, fullChain: _fullChain, ...result } = audit.verify();
  assert.ok(checkedAt && Number.isFinite(Date.parse(checkedAt)), 'PostgreSQL verification includes its check time');
  return result;
}

test('changes and audit rows are in PostgreSQL before the answer, and a standby takes over with all of it', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const dir = mkdtempSync('/tmp/pdp-pg-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const options = { port: 0, dataDir: dir, databaseUrl: appUrl, signingKeySeal: SEAL, clock: `fixed:${FIXED}` };
  const a = createServer(options); await a.listen(); t.after(() => a.close());
  const ca = await client(a, dir);
  const before = await count(sql);
  await ca.decide();
  const ready = await ca.call('/readyz');
  assert.equal(ready.status, 200); assert.equal(ready.data.active, true);
  assert.deepEqual(ready.data.audit, { verified: true, fullChain: true }, 'readiness does not report the audit length; a start without checkpoint verified the whole chain');
  assert.equal(await count(sql), before + 1, 'the decision row is stored before the PEP gets its answer');
  const maker = await ca.login('amira');
  const proposed = await ca.call('/admin/v1/changes', 'POST', { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY }, maker);
  assert.equal(proposed.status, 201);
  const stored = JSON.parse((await sql(`SELECT body FROM gate_doc WHERE name = 'state'`)).rows[0].body as string) as { changes: Array<{ id: string }> };
  assert.ok(stored.changes.some((c) => c.id === proposed.data.id), 'the proposal is stored before the console gets its answer');

  const b = createServer(options);
  let bUp = false;
  const bListening = b.listen().then(() => { bUp = true; });
  t.after(() => b.close());
  await new Promise((r) => setTimeout(r, 400));
  assert.equal(bUp, false, 'the standby waits while the active node holds the database');
  await a.close();
  await bListening;
  const cb = await client(b, dir);
  const auditor = await cb.login('sam');
  const verified = await cb.call('/admin/v1/audit/verify', 'GET', undefined, auditor);
  assert.equal(verified.data.verified, true);
  assert.equal(verified.data.length, await count(sql));
  const filtered = await cb.call('/admin/v1/audit?type=decision&limit=1', 'GET', undefined, auditor);
  assert.equal(filtered.status, 200);
  assert.equal((filtered.data.items as Array<{ type: string }>).length, 1);
  assert.equal((filtered.data.items as Array<{ type: string }>)[0]?.type, 'decision');
  const changes = await cb.call('/admin/v1/changes', 'GET', undefined, await cb.login('amira'));
  assert.ok((changes.data.items as Array<{ id: string }>).some((c) => c.id === proposed.data.id));
  const n = await count(sql);
  await cb.decide();
  assert.equal(await count(sql), n + 1);
  assert.equal((await cb.call('/admin/v1/audit/verify', 'GET', undefined, auditor)).data.verified, true, 'the chain continues across the takeover');
});

test('the application role cannot rewrite the audit; a rewrite by a superuser is caught at anchoring and at restart', { skip: skip || (hasOpensslTs ? false : 'openssl ts unavailable') }, async (t) => {
  const { appUrl, sql } = await reset();
  const tsa = await startTsa(t);
  const dir = mkdtempSync('/tmp/pdp-pg-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const options = { port: 0, dataDir: dir, databaseUrl: appUrl, signingKeySeal: SEAL, clock: `fixed:${FIXED}`, tsa: { url: tsa.url, caFile: resolve(tsa.dir, 'ca.crt') } };
  const a = createServer(options); await a.listen(); t.after(() => a.close());
  const ca = await client(a, dir);
  await ca.decide(); await ca.decide();
  await a.anchor();
  const anchor = (await sql('SELECT seq, hash, token FROM gate_anchor')).rows[0] as { seq: string; hash: string; token: Buffer };
  assert.match(tsa.verify(anchor.token.toString('base64'), anchor.hash), /Verification: OK/);

  const app = new pg.Client({ connectionString: appUrl }); await app.connect();
  t.after(() => app.end());
  await assert.rejects(app.query('UPDATE gate_audit SET record = record'), /permission denied/);
  await assert.rejects(app.query('DELETE FROM gate_audit'), /permission denied/);
  await assert.rejects(app.query('TRUNCATE gate_audit'), /permission denied/);
  await assert.rejects(app.query('DELETE FROM gate_anchor'), /permission denied/);
  await assert.rejects(app.query('ALTER TABLE gate_audit DISABLE ROW LEVEL SECURITY'), /must be owner/);
  await app.query('GRANT UPDATE ON gate_audit TO gate_app'); // a non-owner's grant is a no-op (warning only)
  await assert.rejects(app.query('UPDATE gate_audit SET record = record'), /permission denied/);

  const auditor = await ca.login('sam'); // signed in before: once tampering is found, nothing more is appended, sign-ins included
  await sql(`UPDATE gate_audit SET record = jsonb_set(record::jsonb, '{actor}', '"mallory"')::text WHERE seq = 1`);
  await ca.decide();
  await a.anchor();
  const anchors = await ca.call('/admin/v1/audit/anchors', 'GET', undefined, auditor);
  assert.match(String(anchors.data.lastError), /differ/);
  assert.equal((anchors.data.items as unknown[]).length, 1, 'a tampered chain is not anchored');
  assert.equal((await ca.call('/admin/v1/audit/verify', 'GET', undefined, auditor)).data.verified, false);
  assert.equal((await ca.call('/access/v1/evaluation', 'POST', evaluation(), { authorization: `Bearer ${initialCredentials(dir).pepApiKey}` })).status, 500, 'nothing more is appended to a chain that disagrees with the database');
  await a.close();
  await assert.rejects(createServer(options).listen(), /Audit integrity failure/);
});

test('a node that loses its database stops answering (503) and another node resumes from what was stored', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const dir = mkdtempSync('/tmp/pdp-pg-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  let fatal: Error | undefined;
  const a = createServer({ port: 0, dataDir: dir, databaseUrl: appUrl, signingKeySeal: SEAL, clock: `fixed:${FIXED}`, onFatal: (err) => { fatal = err; } });
  await a.listen(); t.after(() => a.close());
  const ca = await client(a, dir);
  await ca.decide();
  const credentials0 = initialCredentials(dir);
  for (const id of ['\u0000', 'a\ud800b']) {
    const odd = await ca.call('/access/v1/evaluation', 'POST', evaluation(id), { authorization: `Bearer ${credentials0.pepApiKey}` });
    assert.equal(odd.status, 200, 'a NUL or a lone surrogate in an id is stored, it does not stop the node');
  }
  assert.equal(fatal, undefined);
  const stored = await count(sql);
  await sql(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'gate_app'`);
  await new Promise((r) => setTimeout(r, 200));
  const credentials = initialCredentials(dir);
  const refused = await ca.call('/access/v1/evaluation', 'POST', evaluation(), { authorization: `Bearer ${credentials.pepApiKey}` });
  assert.equal(refused.status, 503);
  assert.ok(fatal, 'the node reports the failure so its supervisor restarts it');
  assert.equal(await count(sql), stored, 'nothing unanswered was half-written');
  const b = createServer({ port: 0, dataDir: dir, databaseUrl: appUrl, signingKeySeal: SEAL, clock: `fixed:${FIXED}` });
  await b.listen(); t.after(() => b.close());
  const cb = await client(b, dir);
  await cb.decide();
  assert.equal((await cb.call('/admin/v1/audit/verify', 'GET', undefined, await cb.login('sam'))).data.verified, true);
});


test('PostgreSQL audit routes, scoped counters and compliance exactly match file audit after restart', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const file = fixture(t);
  const events: AuditEvent[] = [
    { type: 'decision', actor: 'pep', action: 'read', subject: 'bob', resource: 'CASE-14', effect: 'allow', rules: ['RBAC.NOT_ELIGIBLE', 'NTK.NO_REASON'] },
    { type: 'decision', actor: 'pep', action: 'read', subject: 'bob', resource: 'CASE-7', effect: 'deny', rules: ['NTK.NO_REASON', 'BLP.NO_READ_UP'] },
    { type: 'decision', actor: 'pep', action: 'write', subject: 'alice', resource: 'CASE-11', effect: 'deny', rules: ['NTK.NO_REASON'] },
    { type: 'change', actor: 'amira', action: 'approve', effect: 'allow', rules: ['ADMIN.TWO_PERSON'], details: { changeId: 'c-1' } },
    { type: 'session', actor: 'bob', action: 'login', effect: 'deny' },
    { type: 'break_glass', actor: 'lina', action: 'open', subject: 'dan', resource: 'CASE-12', effect: 'allow', rules: ['CW.DECISION_TOKEN'] },
    { type: 'decision', actor: 'pep', action: 'read', subject: '\u0000', resource: 'a\ud800b', effect: 'deny', rules: ['NTK.NO_REASON', 'odd"\\\u0000'] },
    { type: 'decision', actor: 'pep', action: 'read', subject: 'bob', resource: 'CASE-14', effect: 'allow' },
  ];
  let ledger = await PgLedger.open(appUrl!, () => undefined);
  t.after(() => ledger.close());
  let stamp = FIXED;
  const pgAudit = () => ledger.auditLog(() => stamp);
  for (const event of events) {
    stamp = new Date(Date.parse(FIXED) + ledger.head.seq * 1000).toISOString();
    file.setClock(stamp);
    file.rt.audit.append(event);
    pgAudit().append(event);
  }
  await ledger.commit();
  await ledger.close();
  await sql('DELETE FROM gate_audit_meta');
  const warning = t.mock.method(console, 'warn', () => undefined);
  stamp = new Date(Date.parse(FIXED) + events.length * 1000).toISOString();
  ledger = await PgLedger.open(appUrl!, () => undefined, { now: () => stamp });
  const repaired = { type: 'security', actor: 'system', action: 'meta_repaired',
    details: { seqs: events.map((_, i) => i + 1), count: events.length, first: 1, last: events.length } } as const;
  file.setClock(stamp);
  file.rt.audit.append(repaired);
  assert.ok(warning.mock.calls.some((call) => String(call.arguments[0]).includes('1,2,3,4,5,6,7,8')));
  const rt = { ...file.rt, audit: pgAudit() };
  assert.equal(rt.audit.records().length, 0, 'a restart retains no committed audit rows');
  assert.equal((await rt.audit.list({ cursor: 8, limit: 1 })).items[0]?.action, 'meta_repaired');

  const queries = ['', '?limit=1', '?limit=1&cursor=1', '?limit=3', '?limit=3&cursor=6', '?cursor=999',
    '?effect=deny', '?effect=allow&type=decision&cursor=1&limit=2', '?type=session', '?type=change',
    '?type=decision&rule=NTK.NO_REASON&subject=bob&resource=CASE-7', '?rule=NTK.NO_REASON&limit=1',
    `?subject=${encodeURIComponent('\u0000')}`, '?resource=CASE-14',
    `?rule=${encodeURIComponent('odd"\\\u0000')}`, '?rule=&subject=&resource=', '?cursor=01&limit=1.0'];
  for (const query of queries) {
    const url = new URL(`http://local/admin/v1/audit${query}`);
    const expected = auditRoute(file.rt, users.sam, url);
    const actual = await auditRoute(rt, users.sam, url);
    assert.deepEqual(actual, expected, query || 'unfiltered');
  }
  assert.deepEqual(await rt.audit.list?.({ cursor: 0, limit: 50, resource: 'a\ud800b' }),
    { items: file.rt.audit.records().filter((row) => row.resource === 'a\ud800b'), next: null });
  const verification = await auditRoute(rt, users.sam, new URL('http://local/admin/v1/audit/verify')) as { checkedAt?: string; fullChain?: boolean };
  assert.ok(verification.checkedAt && Number.isFinite(Date.parse(verification.checkedAt)));
  const { checkedAt, fullChain, ...verificationShape } = verification;
  assert.equal(fullChain, true);
  assert.deepEqual(verificationShape, auditRoute(file.rt, users.sam, new URL('http://local/admin/v1/audit/verify')));
  assert.deepEqual(compliance(rt, users.sam, true), compliance(file.rt, users.sam, true));
  for (const user of [users.ruth, users.sam]) assert.deepEqual(await overview(rt, user), overview(file.rt, user));
  // evidence packs and subject reports read the committed rows through list(): same sections as from the file audit
  const evidenceUrl = new URL('http://local/admin/v1/compliance/evidence?framework=soc2');
  const [fromPg, fromFile] = [await evidencePack(rt, users.sam, evidenceUrl), await evidencePack(file.rt, users.sam, evidenceUrl)] as Array<{ pack: { sections: Record<string, unknown> } }>;
  for (const name of ['securityEvents', 'breakGlass', 'accessReviews', 'approvals', 'policy']) assert.deepEqual(fromPg!.pack.sections[name], fromFile!.pack.sections[name], name);
  assert.deepEqual((await subjectReport(rt, users.lina, 'bob')).audit, (await subjectReport(file.rt, users.lina, 'bob')).audit);
});

test('PostgreSQL recheck catches deletion of an unanchored committed tail and latches fail-closed', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const ledger = await PgLedger.open(appUrl!, () => undefined);
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => FIXED);
  for (const subject of ['alice', 'bob', 'carol']) audit.append({ type: 'decision', actor: 'pep', action: 'read', subject, effect: 'allow' });
  await ledger.commit();
  await sql('DELETE FROM gate_audit WHERE seq = 3');
  assert.equal(await ledger.recheck(), false);
  assert.deepEqual(auditShape(audit), { verified: false, length: 2, brokenAt: 3 });
  assert.throws(() => audit.append({ type: 'session', actor: 'sam', action: 'login' }), /Audit integrity failure/);
});

test('50,000 audited decisions retain only pending rows and stream verification with bounded memory', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  let ledger = await PgLedger.open(appUrl!, () => undefined);
  t.after(() => ledger.close());
  for (let i = 1; i <= 50_000; i++) {
    const audit = ledger.auditLog(() => FIXED);
    audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: `user-${i % 100}`, resource: `CASE-${i % 200}`, effect: i % 3 ? 'allow' : 'deny', rules: [i % 2 ? 'NTK.NO_REASON' : 'RBAC.NOT_ELIGIBLE', `UNIQUE-${i}`] });
    assert.ok(audit.records().length <= 1000, 'only the current commit batch is retained');
    if (i % 1000 === 0) {
      await ledger.commit();
      assert.equal(audit.records().length, 0, 'committed rows are released');
    }
  }
  assert.equal(await count(sql), 50_000);
  const retained = ledger as unknown as { counters: { types: Map<string, number>; controls: Map<string, unknown> } };
  assert.equal(retained.counters.types.size, 1);
  assert.ok(retained.counters.controls.size <= 13, 'unique rule ids do not grow the aggregate counters');
  let audit = ledger.auditLog(() => FIXED);
  assert.deepEqual(auditShape(audit), { verified: true, length: 50_000 });
  assert.equal(audit.tip().seq, 50_000);
  assert.equal(audit.evidence?.(['AUDIT.APPEND'], true).decisions, 50_000);
  await ledger.close();

  ledger = await PgLedger.open(appUrl!, () => undefined);
  audit = ledger.auditLog(() => FIXED);
  assert.equal(audit.records().length, 0);
  assert.deepEqual(auditShape(audit), { verified: true, length: 50_000 });
  assert.ok(await ledger.recheck());
  assert.equal(audit.evidence?.(['AUDIT.APPEND'], true).decisions, 50_000);
  const page = await audit.list({ cursor: 49_000, limit: 1000 });
  assert.equal(page.items.length, 1000);
  assert.equal(page.items[0]?.seq, 49_001);
  assert.equal(page.items.at(-1)?.seq, 50_000);
  assert.equal(page.next, null);
});


test('PostgreSQL recheck fails closed on malformed stored records and changed filter metadata', { skip }, async (t) => {
  for (const stored of ['null', '{}', '[]', '{bad']) {
    const { appUrl, sql } = await reset();
    const ledger = await PgLedger.open(appUrl!, () => undefined);
    const audit = ledger.auditLog(() => FIXED);
    audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'deny' });
    await ledger.commit();
    await sql('UPDATE gate_audit SET record = $1 WHERE seq = 1', [stored]);
    assert.equal(await ledger.recheck(), false, stored);
    assert.deepEqual(auditShape(audit), { verified: false, length: 1, brokenAt: 1 });
    assert.throws(() => audit.append({ type: 'session', actor: 'sam', action: 'login' }), /Audit integrity failure/);
    await ledger.close();
  }
  const { appUrl, sql } = await reset();
  const ledger = await PgLedger.open(appUrl!, () => undefined);
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => FIXED);
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'deny' });
  await ledger.commit();
  await sql(`UPDATE gate_audit_meta SET effect = 'allow' WHERE seq = 1`);
  assert.equal(await ledger.recheck(), false);
  assert.deepEqual(auditShape(audit), { verified: false, length: 1, brokenAt: 1 });
  assert.throws(() => audit.append({ type: 'session', actor: 'sam', action: 'login' }), /Audit integrity failure/);
});


const unavailable = (err: unknown): boolean => err instanceof HttpError && err.status === 503;

test('read-only rechecks do not delay commits, concurrent verifies share a scan, and filter indexes exist', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  let scans = 0, shouldBlock = true;
  let signalStarted!: () => void, releaseScan!: () => void;
  const started = new Promise<void>((resolve) => { signalStarted = resolve; });
  const gate = new Promise<void>((resolve) => { releaseScan = resolve; });
  const ledger = await PgLedger.open(appUrl!, () => undefined, { onScanStart: async () => {
    scans++;
    if (shouldBlock) { shouldBlock = false; signalStarted(); await gate; }
  } });
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => FIXED);
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'allow' });
  await ledger.commit();

  const first = audit.recheck();
  await started;
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'deny' });
  let committed = false;
  const write = ledger.commit().then(() => { committed = true; });
  const shared = [first, audit.recheck(), audit.recheck(), ledger.recheck()];
  // no sleep: the scan stays blocked until the commit resolves, so a commit queued behind the scan never resolves
  // here; the guard only turns that deadlock into a failure, long after any loaded machine would have committed
  let released = false;
  const guard = setTimeout(() => { released = true; releaseScan(); }, 20_000);
  try {
    await write;
    assert.equal(released, false, 'the writer commits while the read scan is blocked');
    assert.equal(committed, true);
    assert.equal(scans, 1, 'all concurrent callers use the same recheck');
  } finally { clearTimeout(guard); releaseScan(); }
  for (const result of await Promise.all(shared)) assert.ok(result);
  assert.equal(scans, 1, 'the callers that arrived during the blocked scan shared it');
  assert.ok(await audit.recheck(), 'a verify inside the interval reuses the result');
  assert.equal(scans, 1);
  assert.ok(await ledger.recheck(), 'periodic and anchoring callers can force a fresh recheck');
  assert.equal(scans, 2);

  const indexes = (await sql(`SELECT indexname FROM pg_indexes WHERE tablename = 'gate_audit_meta'`)).rows.map((row) => row.indexname);
  for (const name of ['gate_audit_meta_subject_seq', 'gate_audit_meta_resource_seq', 'gate_audit_meta_type_seq', 'gate_audit_meta_rules']) assert.ok(indexes.includes(name), name);
});

test('audit listing validates returned metadata and all audit reads refuse after tampering', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const ledger = await PgLedger.open(appUrl!, () => undefined);
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => FIXED);
  audit.append({ type: 'decision', actor: 'pep', action: 'read', resource: 'CASE-14', effect: 'deny' });
  await ledger.commit();
  await sql(`UPDATE gate_audit_meta SET effect = 'allow' WHERE seq = 1`);

  assert.deepEqual(await audit.list({ cursor: 0, limit: 50, effect: 'deny' }), { items: [], next: null });
  assert.equal(await ledger.recheck(), false, 'a row hidden from its filter is caught by recheck');
  await ledger.close();
  const second = await reset();
  const other = await PgLedger.open(second.appUrl, () => undefined);
  t.after(() => other.close());
  const visible = other.auditLog(() => FIXED);
  visible.append({ type: 'decision', actor: 'pep', action: 'read', resource: 'CASE-14', effect: 'deny' });
  await other.commit();
  await second.sql(`UPDATE gate_audit_meta SET effect = 'allow' WHERE seq = 1`);
  await assert.rejects(visible.list({ cursor: 0, limit: 50, effect: 'allow' }), unavailable);
  assert.deepEqual(auditShape(visible), { verified: false, length: 1, brokenAt: 1 });
  await assert.rejects(audit.list({ cursor: 0, limit: 50 }), unavailable);
  await assert.rejects(audit.countScoped(['CASE-14']), unavailable);
  assert.throws(() => audit.countScoped([]), unavailable);
  assert.throws(() => audit.evidence(['AUDIT.APPEND'], true), unavailable);
  assert.throws(() => audit.append({ type: 'session', actor: 'sam', action: 'login' }), /Audit integrity failure/);
});

test('startup records and logs altered metadata repairs', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  let ledger = await PgLedger.open(appUrl!, () => undefined);
  const audit = ledger.auditLog(() => FIXED);
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'deny' });
  await ledger.commit();
  await ledger.close();
  await sql(`UPDATE gate_audit_meta SET effect = 'allow' WHERE seq = 1`);
  const warning = t.mock.method(console, 'warn', () => undefined);

  ledger = await PgLedger.open(appUrl!, () => undefined, { now: () => FIXED });
  t.after(() => ledger.close());
  const repaired = ledger.auditLog(() => FIXED);
  const rows = await repaired.list({ cursor: 0, limit: 50 });
  assert.equal(rows.items.length, 2);
  assert.equal(rows.items[0]?.effect, 'deny');
  assert.deepEqual(rows.items[1]?.details, { seqs: [1], count: 1, first: 1, last: 1 });
  assert.equal(rows.items[1]?.type, 'security');
  assert.equal(rows.items[1]?.action, 'meta_repaired');
  assert.equal(repaired.verify().verified, true);
  assert.equal(warning.mock.callCount(), 1);
});

test('scan rejects a table sequence that differs from the record sequence', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const ledger = await PgLedger.open(appUrl!, () => undefined);
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => FIXED);
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'allow' });
  await ledger.commit();
  await sql('UPDATE gate_audit SET seq = 2 WHERE seq = 1');
  assert.equal(await ledger.recheck(), false);
  assert.deepEqual(auditShape(audit), { verified: false, length: 1, brokenAt: 1 });
});


test('recheck waits for the writer continuation when its snapshot contains a newer commit', { skip }, async (t) => {
  const { appUrl } = await reset();
  let armed = false;
  let scanStarted!: () => void, writerVisible!: () => void, releaseScan!: () => void, releaseWriter!: () => void;
  const scanning = new Promise<void>((resolve) => { scanStarted = resolve; });
  const committed = new Promise<void>((resolve) => { writerVisible = resolve; });
  const scanGate = new Promise<void>((resolve) => { releaseScan = resolve; });
  const writerGate = new Promise<void>((resolve) => { releaseWriter = resolve; });
  const ledger = await PgLedger.open(appUrl!, () => undefined, {
    onScanStart: async () => { if (armed) { scanStarted(); await scanGate; } },
    afterCommit: async () => { if (armed) { writerVisible(); await writerGate; } },
  });
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => FIXED);
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'allow' });
  await ledger.commit();

  armed = true;
  const checking = ledger.recheck();
  await scanning;
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'deny' });
  const writing = ledger.commit();
  await committed;
  try {
    releaseScan();
    await new Promise((resolve) => setTimeout(resolve, 50));
  } finally { releaseScan(); releaseWriter(); }
  assert.equal(await writing.then(() => true), true);
  assert.ok(await checking, 'a valid row whose writer continuation was pending is not tampering');
  assert.equal(audit.verify().verified, true);
});

test('a recheck failure before auditLog creation remains latched', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const ledger = await PgLedger.open(appUrl!, () => undefined);
  t.after(() => ledger.close());
  const record = { type: 'decision', actor: 'pep', action: 'read', effect: 'allow', seq: 1, ts: FIXED, prevHash: GENESIS } as const;
  ledger.stage({ ...record, hash: sha256(GENESIS + canonical(record)) });
  await ledger.commit();
  await sql('DELETE FROM gate_audit WHERE seq = 1');

  assert.equal(await ledger.recheck(), false);
  const audit = ledger.auditLog(() => FIXED);
  assert.equal(audit.verify().verified, false);
  await assert.rejects(audit.list({ cursor: 0, limit: 50 }), unavailable);
  assert.throws(() => audit.append({ type: 'session', actor: 'sam', action: 'login' }), /Audit integrity failure/);
});

test('recheck validates the anchor snapshot from its start', { skip }, async (t) => {
  const { appUrl } = await reset();
  let armed = false, started!: () => void, release!: () => void;
  const scanning = new Promise<void>((resolve) => { started = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const ledger = await PgLedger.open(appUrl!, () => undefined, { onScanStart: async () => { if (armed) { started(); await gate; } } });
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => FIXED);
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'allow' });
  await ledger.commit();

  armed = true;
  const checking = ledger.recheck();
  await scanning;
  ledger.anchors.push({ seq: 1, hash: ledger.committed.hash, tsa: 'test', genTime: FIXED, token: '' });
  release();
  assert.ok(await checking);
  assert.ok(await ledger.recheck(), 'the new anchor is validated by the next scan');
});


test('anchoring uses the head returned by a shared older recheck', { skip: skip || (hasOpensslTs ? false : 'openssl ts unavailable') }, async (t) => {
  const { appUrl, sql } = await reset();
  const tsa = await startTsa(t);
  const dir = mkdtempSync('/tmp/pdp-pg-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  let armed = false, started!: () => void, release!: () => void;
  const scanning = new Promise<void>((resolve) => { started = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const a = createServer({ port: 0, dataDir: dir, databaseUrl: appUrl, signingKeySeal: SEAL, clock: `fixed:${FIXED}`, recheckIntervalMs: 50,
    databaseHooks: { onScanBatch: async () => { if (armed) { armed = false; started(); await gate; } } },
    tsa: { url: tsa.url, caFile: resolve(tsa.dir, 'ca.crt') } });
  await a.listen(); t.after(() => a.close());
  const ca = await client(a, dir);
  await ca.decide();
  armed = true;
  await scanning;
  await ca.decide();
  const anchoring = a.anchor();
  release();
  await anchoring;
  assert.deepEqual((await sql('SELECT seq FROM gate_anchor ORDER BY seq')).rows.map((row) => Number(row.seq)), [1],
    'the first anchor covers the verified snapshot head, not the newer unverified head');
  await a.anchor();
  assert.deepEqual((await sql('SELECT seq FROM gate_anchor ORDER BY seq')).rows.map((row) => Number(row.seq)), [1, 2]);
});

test('a terminated audit reader reconnects with backoff while the writer keeps committing', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const ledger = await PgLedger.open(appUrl!, () => undefined);
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => FIXED);
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'allow' });
  await ledger.commit();
  const errors = t.mock.method(console, 'error', () => undefined);
  const terminated = await sql(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity
    WHERE usename = 'gate_app' AND application_name = 'gate_audit_reader'`);
  assert.ok(terminated.rowCount && terminated.rowCount > 0);
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'deny' });
  await ledger.commit();
  await new Promise((resolve) => setTimeout(resolve, 100));

  const verified = await ledger.recheck();
  assert.ok(verified);
  assert.equal(verified.seq, 2);
  assert.equal((await audit.list({ cursor: 0, limit: 50 })).items.length, 2);
  assert.ok(errors.mock.calls.some((call) => String(call.arguments[0]).includes('reconnecting')));
  assert.ok(errors.mock.calls.some((call) => String(call.arguments[0]).includes('restored')));
});

test('three consecutive periodic recheck failures are fatal', { skip }, async (t) => {
  const { appUrl } = await reset();
  let armed = false, fatal: Error | undefined;
  const ledger = await PgLedger.open(appUrl!, (err) => { fatal = err; }, { onScanStart: async () => {
    if (armed) throw new Error('forced recheck failure');
  } });
  t.after(() => ledger.close());
  t.mock.method(console, 'error', () => undefined);
  const audit = ledger.auditLog(() => FIXED);
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'allow' });
  await ledger.commit();
  armed = true;
  for (let i = 0; i < 3; i++) await assert.rejects(ledger.periodicRecheck(), unavailable);
  assert.match(fatal?.message ?? '', /rechecks remain unavailable/);
  await assert.rejects(ledger.commit(), unavailable);
});

test('deleted metadata is detected immediately by scoped counts and unfiltered listings', { skip }, async (t) => {
  for (const operation of ['count', 'list'] as const) {
    const { appUrl, sql } = await reset();
    const ledger = await PgLedger.open(appUrl!, () => undefined);
    const audit = ledger.auditLog(() => FIXED);
    audit.append({ type: 'decision', actor: 'pep', action: 'read', resource: 'CASE-14', effect: 'allow' });
    await ledger.commit();
    await sql('DELETE FROM gate_audit_meta WHERE seq = 1');
    if (operation === 'count') await assert.rejects(audit.countScoped(['CASE-14']), unavailable);
    else await assert.rejects(audit.list({ cursor: 0, limit: 50 }), unavailable);
    assert.equal(audit.verify().verified, false);
    await ledger.close();
  }
});

test('metadata repair events and logs cap sequence lists at 100 and retain count and range', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  let ledger = await PgLedger.open(appUrl!, () => undefined);
  const audit = ledger.auditLog(() => FIXED);
  for (let i = 0; i < 105; i++) audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'allow' });
  await ledger.commit();
  await ledger.close();
  await sql('DELETE FROM gate_audit_meta');
  const warning = t.mock.method(console, 'warn', () => undefined);
  ledger = await PgLedger.open(appUrl!, () => undefined, { now: () => FIXED });
  t.after(() => ledger.close());
  const repaired = ledger.auditLog(() => FIXED);
  const event = (await repaired.list({ cursor: 105, limit: 1 })).items[0]!;
  const details = event.details as { seqs: number[]; count: number; first: number; last: number };
  assert.equal(details.seqs.length, 100);
  assert.deepEqual([details.count, details.first, details.last], [105, 1, 105]);
  assert.equal(details.seqs.at(-1), 100);
  assert.match(String(warning.mock.calls[0]?.arguments[0]), /count=105, range=1-105/);
  assert.ok(String(warning.mock.calls[0]?.arguments[0]).length < 500);
});

test('audit verify exposes checkedAt and reuses it inside the cache interval', { skip }, async (t) => {
  const { appUrl } = await reset();
  const ledger = await PgLedger.open(appUrl!, () => undefined);
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => FIXED);
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'allow' });
  await ledger.commit();
  const rt = { ...fixture(t).rt, audit };
  const first = await auditRoute(rt, users.sam, new URL('http://local/admin/v1/audit/verify')) as { checkedAt: string };
  const second = await auditRoute(rt, users.sam, new URL('http://local/admin/v1/audit/verify')) as { checkedAt: string };
  assert.ok(Number.isFinite(Date.parse(first.checkedAt)));
  assert.equal(second.checkedAt, first.checkedAt);
  assert.ok(await ledger.recheck());
  const third = await auditRoute(rt, users.sam, new URL('http://local/admin/v1/audit/verify')) as { checkedAt: string };
  assert.ok(Date.parse(third.checkedAt) >= Date.parse(first.checkedAt));
});

const storedDoc = async (sql: Awaited<ReturnType<typeof reset>>['sql'], name: string): Promise<unknown> =>
  JSON.parse(String((await sql('SELECT body FROM gate_doc WHERE name = $1', [name])).rows[0]?.body ?? 'null')) as unknown;
const bearer = (secret: string): Record<string, string> => ({ authorization: `Bearer ${secret}` });
const SECURITY_FILES = ['credentials.json', 'lockouts.json', 'signing-keys.json', 'signing-public.pem', 'scim-credential.json', 'siem-cursor.json'];

test('PostgreSQL mode refuses to start without SIGNING_KEY_SEAL unless clear signing keys are acknowledged', () => {
  const databaseUrl = 'postgresql://unused@127.0.0.1:1/none';
  assert.throws(() => createServer({ databaseUrl }), /SIGNING_KEY_SEAL is required with DATABASE_URL/);
  assert.doesNotThrow(() => createServer({ databaseUrl, allowClearSigningKeys: true }));
  assert.doesNotThrow(() => createServer({ databaseUrl, signingKeySeal: SEAL }));
});

test('PEP credentials, signing keys, the SCIM credential and lockouts are shared in PostgreSQL: what A rotates and revokes holds on B with no file copied', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const dirA = mkdtempSync('/tmp/pdp-pg-'), dirB = mkdtempSync('/tmp/pdp-pg-');
  t.after(() => { rmSync(dirA, { recursive: true, force: true }); rmSync(dirB, { recursive: true, force: true }); });
  const options = { port: 0, databaseUrl: appUrl, signingKeySeal: SEAL, clock: `fixed:${FIXED}`, pepRotationGraceSeconds: 0 };
  const a = createServer({ ...options, dataDir: dirA }); await a.listen(); t.after(() => a.close());
  const ca = await client(a, dirA);
  const bootstrapKey = initialCredentials(dirA).pepApiKey;
  const officer = await ca.login('lina');
  const created = await ca.call('/admin/v1/pep-credentials', 'POST', { name: 'gateway' }, officer);
  assert.equal(created.status, 201);
  const id = (created.data.credential as { id: string }).id;
  const oldSecret = String(created.data.secret);
  const rotated = await ca.call(`/admin/v1/pep-credentials/${id}/rotate`, 'POST', {}, officer);
  assert.equal(rotated.status, 200);
  const newSecret = String(rotated.data.secret);
  assert.equal((await ca.call('/admin/v1/pep-credentials/bootstrap/revoke', 'POST', {}, officer)).status, 200);
  const keys = await ca.call('/admin/v1/signing-keys/rotate', 'POST', {}, officer);
  assert.equal(keys.status, 201);
  const kid = (keys.data.current as { kid: string }).kid;
  const issued = await ca.call('/access/v1/evaluation', 'POST', evaluation('grace', 'PAY-3', 'create', 'trusted'), bearer(newSecret));
  assert.equal(issued.status, 200, JSON.stringify(issued.data));
  const token = String((issued.data.context as { decision_token?: string }).decision_token);
  assert.equal((JSON.parse(Buffer.from(token.split('.')[0]!, 'base64url').toString()) as { kid: string }).kid, kid, 'the token is signed with the key rotated on A');
  const scim = await ca.call('/admin/v1/scim/credential', 'POST', {}, await ca.login('amira'));
  assert.equal(scim.status, 201);
  for (let i = 0; i < 5; i++) assert.equal((await ca.call('/admin/v1/session', 'POST', { username: 'omar', password: 'wrong' })).status, 401);

  const keyring = await storedDoc(sql, 'signing_keys') as { keys: Array<{ kid: string; privateKey?: string }> };
  assert.ok(keyring.keys.some((key) => key.kid === kid));
  for (const key of keyring.keys) if (key.privateKey) assert.match(key.privateKey, /^v2\./, 'no private key is stored in clear');
  assert.ok(await storedDoc(sql, 'credentials') && await storedDoc(sql, 'lockouts') && await storedDoc(sql, 'scim'));
  for (const file of SECURITY_FILES) assert.equal(existsSync(resolve(dirA, file)), false, `${file} is not written in PostgreSQL mode`);

  const b = createServer({ ...options, dataDir: dirB });
  const bListening = b.listen(); t.after(() => b.close());
  await a.close();
  await bListening;
  const cb = await client(b, dirA); // the passwords A printed at its first start; nothing is copied into B's DATA_DIR
  const evaluate = async (secret: string): Promise<number> => (await cb.call('/access/v1/evaluation', 'POST', evaluation(), bearer(secret))).status;
  assert.equal(await evaluate(bootstrapKey), 401, 'the key revoked on A is refused by B');
  assert.equal(await evaluate(oldSecret), 401, 'the secret rotated out on A is refused by B');
  assert.equal(await evaluate(newSecret), 200);
  const consumed = await cb.call('/x/v1/tokens/consume', 'POST', { token, action: 'create', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 }, bearer(newSecret));
  assert.equal(consumed.status, 200, 'B verifies a token signed with the key rotated on A');
  const jwks = await cb.call('/.well-known/jwks.json');
  assert.ok((jwks.data.keys as Array<{ kid: string }> | undefined)?.some((key) => key.kid === kid), JSON.stringify(jwks));
  assert.equal((await cb.call('/scim/v2/Groups', 'GET', undefined, bearer(String(scim.data.credential)))).status, 200, 'the SCIM credential minted on A works on B');
  assert.equal((await cb.call('/admin/v1/session', 'POST', { username: 'omar', password: initialCredentials(dirA).passwords.omar })).status, 429, 'the lockout set on A holds on B');
  for (const file of [...SECURITY_FILES, 'INITIAL-CREDENTIALS.txt']) assert.equal(existsSync(resolve(dirB, file)), false, `${file} is not written by B`);
});

test('TOTP secrets are sealed in the PostgreSQL credentials row and the policy signature verifies against the shared keyring after takeover', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const dirA = mkdtempSync('/tmp/pdp-pg-'), dirB = mkdtempSync('/tmp/pdp-pg-');
  t.after(() => { rmSync(dirA, { recursive: true, force: true }); rmSync(dirB, { recursive: true, force: true }); });
  const options = { port: 0, databaseUrl: appUrl, signingKeySeal: SEAL, clock: `fixed:${FIXED}` };
  const a = createServer({ ...options, dataDir: dirA }); await a.listen(); t.after(() => a.close());
  const ca = await client(a, dirA);
  const amira = await ca.login('amira');
  const enrol = await ca.call('/admin/v1/session/totp/enrol', 'POST', { password: initialCredentials(dirA).passwords.amira }, amira);
  assert.equal(enrol.status, 200);
  const key = fromBase32(new URL(String(enrol.data.otpauthUri)).searchParams.get('secret')!);
  const step = Math.floor(Date.now() / 30_000); // TOTP runs on wall time, not the fixed business clock
  assert.equal((await ca.call('/admin/v1/session/totp/activate', 'POST', { code: hotp(key, step) }, amira)).status, 200);
  const stored = await storedDoc(sql, 'credentials') as { users: Array<{ id: string; totp?: { secret: string; active: boolean } }> };
  const totp = stored.users.find((u) => u.id === 'amira')?.totp;
  assert.equal(totp?.active, true);
  assert.match(String(totp?.secret), /^v2\./, 'the TOTP secret is sealed with SIGNING_KEY_SEAL');
  assert.equal(existsSync(resolve(dirA, 'credentials.json')), false);
  // a signing key rotated on A re-signs the bundle in force; the signature is checked by B against the keyring in PostgreSQL
  const rotated = await ca.call('/admin/v1/signing-keys/rotate', 'POST', {}, await ca.login('lina'));
  assert.equal(rotated.status, 201);
  const kid = (rotated.data.current as { kid: string }).kid;
  const history = (await storedDoc(sql, 'state') as { history: Array<{ signature?: { kid: string } }> }).history;
  assert.equal(history.at(-1)?.signature?.kid, kid);

  const b = createServer({ ...options, dataDir: dirB });
  const bListening = b.listen(); t.after(() => b.close());
  await a.close();
  await bListening; // B refuses to start on a bundle whose signature does not verify against its keyring
  const cb = await client(b, dirA);
  const password = initialCredentials(dirA).passwords.amira;
  const signIn = async (code?: string): Promise<number> => (await cb.call('/admin/v1/session', 'POST', { username: 'amira', password, ...(code ? { code } : {}) })).status;
  assert.equal(await signIn(), 401, 'B requires the second factor enrolled on A');
  assert.equal(await signIn(hotp(key, step)), 401, 'the code used on A is a replay on B');
  assert.equal(await signIn(hotp(key, step + 1)), 200);
});

test('the first PostgreSQL start imports the DATA_DIR security files once, then neither reads nor writes them', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const dir = mkdtempSync('/tmp/pdp-pg-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const fileNode = createServer({ port: 0, dataDir: dir, clock: `fixed:${FIXED}` });
  await fileNode.listen();
  const cf = await client(fileNode, dir);
  const officer = await cf.login('lina');
  const created = await cf.call('/admin/v1/pep-credentials', 'POST', { name: 'gateway' }, officer);
  const kid = ((await cf.call('/admin/v1/signing-keys/rotate', 'POST', {}, officer)).data.current as { kid: string }).kid;
  const scimToken = String((await cf.call('/admin/v1/scim/credential', 'POST', {}, await cf.login('amira'))).data.credential);
  await fileNode.close();
  writeFileSync(resolve(dir, 'siem-cursor.json'), JSON.stringify({ seq: 7 }));
  const files = ['credentials.json', 'signing-keys.json', 'scim-credential.json', 'siem-cursor.json'];
  const before = files.map((file) => readFileSync(resolve(dir, file), 'utf8'));
  assert.ok(!before[1]!.includes('"v2.'), 'file mode without a seal kept the keys in clear');

  const options = { port: 0, dataDir: dir, databaseUrl: appUrl, signingKeySeal: SEAL, clock: `fixed:${FIXED}` };
  const pgNode = createServer(options); await pgNode.listen(); t.after(() => pgNode.close());
  const cp = await client(pgNode, dir);
  assert.equal((await cp.call('/access/v1/evaluation', 'POST', evaluation(), bearer(String(created.data.secret)))).status, 200, 'the imported PEP credential works');
  assert.equal((await cp.call('/scim/v2/Groups', 'GET', undefined, bearer(scimToken))).status, 200, 'the imported SCIM credential works');
  const keyring = await storedDoc(sql, 'signing_keys') as { keys: Array<{ kid: string; privateKey?: string }> };
  assert.ok(keyring.keys.some((key) => key.kid === kid && key.privateKey?.startsWith('v2.')), 'the imported clear key is sealed before it reaches the database');
  assert.deepEqual(await storedDoc(sql, 'siem'), { seq: 7 });
  assert.equal((await cp.call('/admin/v1/pep-credentials', 'POST', { name: 'second' }, await cp.login('lina'))).status, 201);
  assert.deepEqual(files.map((file) => readFileSync(resolve(dir, file), 'utf8')), before, 'PostgreSQL mode writes no file');
  await pgNode.close();

  await sql(`DELETE FROM gate_doc WHERE name = 'siem'`);
  const again = createServer(options); await again.listen(); t.after(() => again.close());
  assert.equal(await storedDoc(sql, 'siem'), null, 'the import ran once: the files are not read again');
  const cg = await client(again, dir);
  const names = ((await cg.call('/admin/v1/pep-credentials', 'GET', undefined, await cg.login('lina'))).data.items as Array<{ name: string }>).map((c) => c.name);
  assert.ok(names.includes('second'), 'the credentials come from the database, not from the file');
});

test('a start from the verified checkpoint reads only the rows after it, not the whole log', { skip, timeout: 180_000 }, async (t) => {
  const { appUrl, sql } = await reset();
  let ledger = await PgLedger.open(appUrl!, () => undefined, CHECKPOINT);
  t.after(() => ledger.close());
  const append = async (n: number): Promise<void> => {
    const audit = ledger.auditLog(() => FIXED);
    for (let i = 1; i <= n; i++) {
      audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: `user-${i % 50}`, effect: i % 3 ? 'allow' : 'deny' });
      if (i % 1000 === 0) await ledger.commit();
    }
    await ledger.commit();
  };
  await append(20_000);
  assert.ok(await ledger.recheck(), 'a full recheck on the active node writes the checkpoint');
  await append(10);
  const counted = { total: ledger.auditTotal(), all: ledger.readEvidence([], true) };
  await ledger.close();
  assert.equal((await storedDoc(sql, 'audit_checkpoint') as { seq: number }).seq, 20_000);

  ledger = await PgLedger.open(appUrl!, () => undefined, CHECKPOINT);
  const checkpointed = { ...ledger.startup };
  assert.deepEqual(auditShape(ledger.auditLog(() => FIXED)), { verified: true, length: 20_010 });
  assert.equal(checkpointed.from, 20_000);
  assert.ok(checkpointed.rowsRead <= 11, `the checkpoint row and the 10 after it, not ${checkpointed.rowsRead}`);
  assert.deepEqual({ total: ledger.auditTotal(), all: ledger.readEvidence([], true) }, counted, 'counters: the checkpoint\'s plus the rows after it');
  assert.equal(ledger.fullChainVerified, false, 'not every row verified yet: the background verification is pending');
  assert.equal(ledger.auditLog(() => FIXED).verify().fullChain, false);
  assert.ok(await ledger.recheck(), 'the background recheck still verifies everything');
  assert.equal(ledger.fullChainVerified, true);
  await ledger.close();

  await sql(`UPDATE gate_doc SET body = 'null' WHERE name = 'audit_checkpoint'`);
  ledger = await PgLedger.open(appUrl!, () => undefined, CHECKPOINT);
  assert.equal(ledger.startup.from, 0);
  assert.equal(ledger.startup.rowsRead, 20_010, 'without a checkpoint the start reads every row');
  assert.ok(checkpointed.rowsRead * 1000 < ledger.startup.rowsRead);
  assert.equal(ledger.fullChainVerified, true, 'a start without checkpoint verified every row before serving');
  assert.deepEqual({ total: ledger.auditTotal(), all: ledger.readEvidence([], true) }, counted);
});

test('while the background verification after a checkpointed start runs, cached callers get the start result; anchoring waits', { skip }, async (t) => {
  const { appUrl } = await reset();
  let ledger = await PgLedger.open(appUrl!, () => undefined, CHECKPOINT);
  const audit = ledger.auditLog(() => FIXED);
  for (const subject of ['alice', 'bob']) audit.append({ type: 'decision', actor: 'pep', action: 'read', subject, effect: 'allow' });
  await ledger.commit();
  assert.ok(await ledger.recheck());
  await ledger.close();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  ledger = await PgLedger.open(appUrl!, () => undefined, { ...CHECKPOINT, onScanStart: () => gate });
  t.after(() => { release(); return ledger.close(); });
  const late = (p: Promise<unknown>): Promise<unknown> => Promise.race([p, new Promise((r) => setTimeout(() => r('waiting'), 200))]);
  const background = ledger.recheck(); // what server.ts starts right after a checkpointed start
  const cached = await late(ledger.auditLog(() => FIXED).recheck());
  assert.equal((cached as { seq: number }).seq, 2, '/readyz and /audit/verify answer with the start result at once');
  assert.equal(await late(ledger.recheck()), 'waiting', 'anchoring waits for the whole chain');
  assert.equal(ledger.fullChainVerified, false);
  release();
  assert.ok(await background);
  assert.equal(ledger.fullChainVerified, true);
});

test('seal rotation re-signs a checkpoint with counters under the new key only while rotating, and the next start uses it', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const NEXT = { checkpointKey: derivedKey(randomBytes(32).toString('base64url'), CHECKPOINT_KEY_LABEL) };
  let ledger = await PgLedger.open(appUrl!, () => undefined, CHECKPOINT);
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => FIXED);
  for (const subject of ['alice', 'bob', 'carol']) audit.append({ type: 'decision', actor: 'pep', action: 'read', subject, effect: 'allow' });
  await ledger.commit();
  assert.ok(await ledger.recheck());
  const counted = { total: ledger.auditTotal(), all: ledger.readEvidence([], true) };
  await ledger.close();
  const old = await storedDoc(sql, 'audit_checkpoint') as { counters?: unknown; mac: string };
  assert.ok(old.counters, 'the checkpoint under the old key carries counters');
  const counters = () => ({ total: ledger.auditTotal(), all: ledger.readEvidence([], true) });
  // SIGNING_KEY_SEAL=new, SIGNING_KEY_SEAL_PREVIOUS=old
  // rotation complete (nothing sealed under the old key any more): the old key's checkpoint is not trusted
  const warnings: string[] = [];
  const spy = t.mock.method(console, 'warn', (...args: unknown[]) => { warnings.push(args.map(String).join(' ')); });
  ledger = await PgLedger.open(appUrl!, () => undefined, { ...NEXT, previousCheckpointKey: CHECKPOINT.checkpointKey, rotating: () => false });
  spy.mock.restore();
  assert.equal(ledger.checkpointRekeyed, false);
  assert.equal(ledger.startup.from, 0, 'the whole chain is read before serving');
  assert.equal(ledger.auditLog(() => FIXED).verify().verified, true);
  assert.equal(ledger.fullChainVerified, true);
  assert.match(warnings.join('\n'), /authenticated only by SIGNING_KEY_SEAL_PREVIOUS .* not trusted/);
  await ledger.close();
  assert.equal((await storedDoc(sql, 'audit_checkpoint') as { mac: string }).mac, old.mac, 'and not re-signed');
  // rotation in progress (sealed material still under the old key)
  ledger = await PgLedger.open(appUrl!, () => undefined, { ...NEXT, previousCheckpointKey: CHECKPOINT.checkpointKey, rotating: () => true });
  assert.equal(ledger.checkpointRekeyed, true);
  assert.equal(ledger.startup.from, 3, 'the old key\'s checkpoint shortens the rotating start');
  assert.deepEqual(counters(), counted, 'its counters are used');
  await ledger.close();
  const rekeyed = await storedDoc(sql, 'audit_checkpoint') as { counters?: unknown; mac: string };
  assert.notEqual(rekeyed.mac, old.mac);
  assert.deepEqual(rekeyed.counters, old.counters, 're-signed with the counters, not stripped of them');
  // the new key alone: the re-signed checkpoint and its counters are trusted
  ledger = await PgLedger.open(appUrl!, () => undefined, NEXT);
  assert.equal(ledger.checkpointRekeyed, false);
  assert.equal(ledger.startup.from, 3);
  assert.equal(ledger.auditLog(() => FIXED).verify().verified, true);
  assert.deepEqual(counters(), counted);
  await ledger.close();
});

test('a forged checkpoint is tampering, and a row rewritten before the checkpoint is caught by the full recheck after takeover', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const dir = mkdtempSync('/tmp/pdp-pg-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  let ledger = await PgLedger.open(appUrl!, () => undefined, CHECKPOINT);
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => FIXED);
  for (const subject of ['alice', 'bob', 'carol', 'dan']) audit.append({ type: 'decision', actor: 'pep', action: 'read', subject, effect: 'allow' });
  await ledger.commit();
  assert.ok(await ledger.recheck());
  await ledger.close();
  const genuine = await storedDoc(sql, 'audit_checkpoint') as { seq: number; hash: string; verifiedAt: string; mac: string };
  assert.equal(genuine.seq, 4);
  assert.match(genuine.mac, /^[0-9a-f]{64}$/, 'the checkpoint is authenticated');
  const store = (body: unknown): Promise<pg.QueryResult> => sql(`UPDATE gate_doc SET body = $1 WHERE name = 'audit_checkpoint'`, [JSON.stringify(body)]);
  // a database writer cannot produce a mac: any change to the fields, or a mac of its own, is tampering
  const ownMac = (await import('node:crypto')).createHmac('sha256', 'guessed').update(canonical({ seq: 2, hash: genuine.hash, verifiedAt: genuine.verifiedAt })).digest('hex');
  for (const forged of [{ ...genuine, hash: sha256('forged') }, { ...genuine, seq: 2 }, { ...genuine, seq: 9 }, { ...genuine, seq: 2, mac: ownMac },
    { ...genuine, mac: 'f'.repeat(64) }, { ...genuine, mac: 'x' }, { seq: 'x', mac: genuine.mac }, 'text']) {
    await store(forged);
    ledger = await PgLedger.open(appUrl!, () => undefined, CHECKPOINT);
    assert.equal(ledger.auditLog(() => FIXED).verify().verified, false, JSON.stringify(forged));
    await ledger.close();
  }
  // the audit rows above were written without a state document: a server start must adopt the store it creates (M5)
  const options = { port: 0, dataDir: dir, databaseUrl: appUrl, signingKeySeal: SEAL, clock: `fixed:${FIXED}`, policySignatureAdopt: true };
  await store({ ...genuine, hash: sha256('forged') });
  await assert.rejects(createServer(options).listen(), /Audit integrity failure/, 'no node serves past a forged checkpoint');

  await store(genuine);
  await sql(`UPDATE gate_audit SET record = jsonb_set(record::jsonb, '{actor}', '"mallory"')::text WHERE seq = 2`);
  ledger = await PgLedger.open(appUrl!, () => undefined, CHECKPOINT);
  assert.equal(ledger.startup.from, 4);
  assert.equal(ledger.auditLog(() => FIXED).verify().verified, true, 'the documented window: a row before the checkpoint is not read at start');
  await ledger.close();
  const node = createServer(options); await node.listen(); t.after(() => node.close());
  for (let i = 0; i < 100 && await storedDoc(sql, 'audit_checkpoint') !== null; i++) await new Promise((r) => setTimeout(r, 50));
  assert.equal(await storedDoc(sql, 'audit_checkpoint'), null, 'the full recheck started at takeover caught the rewrite and cleared the checkpoint');
  assert.equal((await fetch(`${node.url}/readyz`)).status, 503, 'the node leaves the pool once the background verification fails');
  assert.match(await (await fetch(`${node.url}/metrics`)).text(), /^gate_audit_full_chain_verified 0$/m);
  const refused = await fetch(`${node.url}/access/v1/evaluation`, { method: 'POST', body: '{}' });
  assert.notEqual(refused.status, 200, 'and decides nothing more');
  await node.close();
  ledger = await PgLedger.open(appUrl!, () => undefined, CHECKPOINT);
  assert.deepEqual(auditShape(ledger.auditLog(() => FIXED)), { verified: false, length: 5, brokenAt: 2 }, 'the next start reads the whole chain (4 rows and the adoption) and refuses it');
});

test('the checkpoint shortens a start only when authenticated, its counters included', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  let ledger = await PgLedger.open(appUrl!, () => undefined, CHECKPOINT);
  t.after(() => ledger.close());
  const audit = ledger.auditLog(() => FIXED);
  for (const subject of ['alice', 'bob', 'carol']) audit.append({ type: 'decision', actor: 'pep', action: 'read', subject, effect: 'allow' });
  await ledger.commit();
  assert.ok(await ledger.recheck());
  await ledger.close();
  const genuine = await storedDoc(sql, 'audit_checkpoint') as { seq: number; mac: string };
  const startFrom = async (options: Parameters<typeof PgLedger.open>[2]): Promise<number> => {
    ledger = await PgLedger.open(appUrl!, () => undefined, options);
    assert.equal(ledger.auditLog(() => FIXED).verify().verified, true);
    const from = ledger.startup.from; await ledger.close(); return from;
  };
  assert.equal(await startFrom(CHECKPOINT), 3, 'an authenticated checkpoint is used (in every profile since 0.5.0)');
  assert.equal(await startFrom({}), 0, 'without the key a checkpoint is not trusted');
  const withCounters = genuine as unknown as { seq: number; hash: string; verifiedAt: string; counters: Record<string, { total: number }> };
  assert.equal(withCounters.counters['0']!.total, 3, 'the checkpoint carries the counters at its head');
  await sql(`UPDATE gate_doc SET body = $1 WHERE name = 'audit_checkpoint'`, [JSON.stringify({ ...genuine, counters: { 0: { ...withCounters.counters['0'], total: 99 } } })]);
  ledger = await PgLedger.open(appUrl!, () => undefined, CHECKPOINT);
  assert.equal(ledger.auditLog(() => FIXED).verify().verified, false, 'counters changed under the mac are tampering');
  await ledger.close();
  // a 0.4.2 checkpoint (mac, no counters): used, the counters aggregated from the table
  const legacy = { seq: withCounters.seq, hash: withCounters.hash, verifiedAt: withCounters.verifiedAt };
  const legacyMac = (await import('node:crypto')).createHmac('sha256', CHECKPOINT.checkpointKey!).update(canonical(legacy)).digest('hex');
  await sql(`UPDATE gate_doc SET body = $1 WHERE name = 'audit_checkpoint'`, [JSON.stringify({ ...legacy, mac: legacyMac })]);
  ledger = await PgLedger.open(appUrl!, () => undefined, CHECKPOINT);
  assert.equal(ledger.startup.from, 3);
  assert.deepEqual(auditShape(ledger.auditLog(() => FIXED)), { verified: true, length: 3 });
  assert.equal(ledger.readEvidence([], true).decisions, 3);
  await ledger.close();
  await sql(`UPDATE gate_doc SET body = $1 WHERE name = 'audit_checkpoint'`, [JSON.stringify(genuine)]);
  ledger = await PgLedger.open(appUrl!, () => undefined, { checkpointKey: derivedKey(randomBytes(32).toString('base64url'), CHECKPOINT_KEY_LABEL) });
  assert.equal(ledger.auditLog(() => FIXED).verify().verified, false, 'a mac under another key is tampering');
  await ledger.close();
  const { mac: _mac, ...stripped } = genuine;
  await sql(`UPDATE gate_doc SET body = $1 WHERE name = 'audit_checkpoint'`, [JSON.stringify(stripped)]);
  assert.equal(await startFrom(CHECKPOINT), 0, 'a checkpoint without a mac (older version) is ignored: the whole chain is read');
  // without a key nothing is written: a recheck by a keyless node leaves no unauthenticated checkpoint
  await sql(`UPDATE gate_doc SET body = 'null' WHERE name = 'audit_checkpoint'`);
  ledger = await PgLedger.open(appUrl!, () => undefined);
  assert.ok(await ledger.recheck());
  await ledger.close();
  for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 20));
  assert.equal(await storedDoc(sql, 'audit_checkpoint'), null);
});

test('a standby waiting for the lock exits at once on SIGTERM instead of taking the lock while terminating', { skip }, async (t) => {
  const { appUrl } = await reset();
  const holder = new pg.Client({ connectionString: admin }); await holder.connect();
  t.after(() => holder.end());
  await holder.query('SELECT pg_advisory_lock($1)', [0x47415445]); // plays the active node
  const dir = mkdtempSync(resolve(tmpdir(), 'gate-standby-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const main = resolve(import.meta.dirname, '../src/main.ts');
  const node = spawn(process.execPath, [main], { env: { ...process.env, DATABASE_URL: appUrl, SIGNING_KEY_SEAL: SEAL, DATA_DIR: dir, PORT: '0', CLOCK: `fixed:${FIXED}` }, stdio: 'ignore' });
  const exited = new Promise<number | null>((done) => node.once('exit', (code) => done(code)));
  await new Promise((r) => setTimeout(r, 1500)); // connected and blocked in pg_advisory_lock
  assert.equal(node.exitCode, null, 'the standby waits while the lock is held');
  node.kill('SIGTERM');
  // an explicit handler exits 0; the default disposition would end by signal (code null), and PID 1 would ignore it
  const code = await Promise.race([exited, new Promise<string>((r) => setTimeout(() => r('timeout'), 5000))]);
  if (code === 'timeout') node.kill('SIGKILL');
  assert.equal(code, 0);
});

// --- cluster mode: several nodes decide, one leads the admin plane (docs/API.md §3.9.1) ------------------------------
const BOUND = 500;
async function clusterNode(t: TestContext, appUrl: string, nodeId: string, extra: Partial<ServerOptions> = {}): Promise<PdpServer> {
  const dir = mkdtempSync('/tmp/pdp-pg-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const server = createServer({ port: 0, dataDir: dir, databaseUrl: appUrl, signingKeySeal: SEAL, clock: `fixed:${FIXED}`, rateLimit: 1_000_000,
    cluster: true, nodeId, maxStalenessMs: BOUND, sodHistory: 'caller', ...extra });
  await server.listen(); t.after(() => server.close());
  return server;
}
/** A cluster of `n` nodes ("a" leads and seeded the database: its DATA_DIR holds the initial credentials). */
async function cluster(t: TestContext, n: number, extra: (id: string) => Partial<ServerOptions> = () => ({})) {
  const { appUrl, sql } = await reset();
  const leaderDir = mkdtempSync('/tmp/pdp-pg-'); t.after(() => rmSync(leaderDir, { recursive: true, force: true }));
  const nodes = [await clusterNode(t, appUrl, 'a', { dataDir: leaderDir, advertiseUrl: 'http://127.0.0.1:9', ...extra('a') })];
  for (const id of ['b', 'c'].slice(0, n - 1)) nodes.push(await clusterNode(t, appUrl, id, extra(id)));
  const clients = await Promise.all(nodes.map((node) => client(node, leaderDir)));
  const key = initialCredentials(leaderDir).pepApiKey;
  const decision = async (node: number, body = evaluation()): Promise<{ status: number; decision?: boolean }> => {
    const r = await clients[node]!.call('/access/v1/evaluation', 'POST', body, bearer(key));
    return { status: r.status, decision: r.data.decision as boolean | undefined };
  };
  /** amira proposes, omar approves, on the leader `at`. */
  const change = async (at: number, payload: Record<string, unknown>): Promise<void> => {
    const c = clients[at]!;
    const proposed = await c.call('/admin/v1/changes', 'POST', { kind: 'update_subject', payload, reason: WHY }, await c.login('amira'));
    assert.equal(proposed.status, 201, JSON.stringify(proposed.data));
    assert.equal((await c.call(`/admin/v1/changes/${String(proposed.data.id)}/approve`, 'POST', { reason: WHY }, await c.login('omar'))).status, 200);
  };
  return { appUrl, sql, nodes, clients, key, decision, change, leaderDir };
}
const chainRows = async (sql: Awaited<ReturnType<typeof reset>>['sql']): Promise<Record<string, number>> =>
  Object.fromEntries((await sql('SELECT node, count(*)::int AS n FROM gate_audit GROUP BY node ORDER BY node')).rows.map((r) => [r.node as string, r.n as number]));
/** Polls until `check` holds; returns the elapsed milliseconds (fails after `limit`). */
async function within(limit: number, check: () => Promise<boolean>): Promise<number> {
  const started = performance.now();
  while (!await check()) {
    if (performance.now() - started > limit) assert.fail(`not within ${limit} ms`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  return performance.now() - started;
}

test('two cluster nodes share general and PEP rate budgets through PostgreSQL leases', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 2, () => ({ rateLimit: 20, pepRateLimit: 1000, onFatal: (err) => t.diagnostic(`storage failure: ${err.message}`) }));
  const first = await c.clients[0]!.call('/.well-known/authzen-configuration');
  assert.equal(first.status, 200, JSON.stringify(first.data));
  const general: number[] = [first.status];
  for (let i = 1; i < 40; i++) general.push((await c.clients[i % 2]!.call('/.well-known/authzen-configuration')).status);
  assert.equal(general.filter((status) => status === 200).length, 20, 'the two nodes admitted 20 requests in total, not 20 each');
  assert.equal(general.filter((status) => status === 429).length, 20);

  const batch = { evaluations: Array.from({ length: 1000 }, () => evaluation()) };
  const pep = [
    (await c.clients[0]!.call('/access/v1/evaluations', 'POST', batch, bearer(c.key))).status,
    (await c.clients[1]!.call('/access/v1/evaluations', 'POST', batch, bearer(c.key))).status,
  ];
  assert.deepEqual(pep, [200, 429], 'a 1000-item batch consumes the one shared PEP budget');
  assert.equal((await c.sql('SELECT count(*) AS n FROM gate_rate_limit')).rows[0]!.n, '3', 'general IP, PEP IP and PEP principal buckets');
});

for (const size of [2, 3]) {
  test(`${size} cluster nodes decide at once on their own chains, and a policy change on the leader reaches every follower within the bound`, { skip, timeout: 60_000 }, async (t) => {
    const c = await cluster(t, size);
    assert.equal((await c.clients[0]!.call('/leaderz')).status, 200);
    for (let i = 1; i < size; i++) {
      assert.equal((await c.clients[i]!.call('/leaderz')).status, 503);
      const ready = await c.clients[i]!.call('/readyz');
      assert.equal(ready.status, 200); assert.equal(ready.data.role, 'follower');
      // one writer: a follower never takes an admin request. It forwards it to the advertised leader (here nothing
      // listens there: 503), and a request that already made a hop gets the 409 fallback naming the leader
      const proposal = { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY };
      const unreachable = await c.clients[i]!.call('/admin/v1/changes', 'POST', proposal);
      assert.equal(unreachable.status, 503, 'forwarded to an unreachable leader');
      const refused = await c.clients[i]!.call('/admin/v1/changes', 'POST', proposal, { 'x-gate-hop': 'v1.0.x.x.x.x' });
      assert.equal(refused.status, 409, 'a hopped request is never forwarded again');
      assert.deepEqual({ error: refused.data.error, leader: refused.data.leader }, { error: 'not_leader', leader: 'http://127.0.0.1:9' });
    }
    const before = await chainRows(c.sql);
    const answers = await Promise.all(c.nodes.flatMap((_, node) => Array.from({ length: 40 }, () => c.decision(node))));
    assert.ok(answers.every((a) => a.status === 200 && a.decision === true), 'every node decides, concurrently');
    const after = await chainRows(c.sql);
    for (const id of ['a', 'b', 'c'].slice(0, size)) assert.equal((after[id] ?? 0) - (before[id] ?? 0), 40, `node ${id} wrote its own 40 rows`);
    const sample = (await c.sql(`SELECT record FROM gate_audit WHERE node = 'b' ORDER BY seq DESC LIMIT 1`)).rows[0];
    assert.equal((JSON.parse(String(sample?.record)) as { node?: string }).node, 'b', 'the node id is in every hashed record');

    await c.change(0, { id: 'bob', set: { active: false } });
    const committedAt = performance.now();
    for (let i = 1; i < size; i++) {
      await within(BOUND, async () => (await c.decision(i)).decision === false);
    }
    t.diagnostic(`policy change visible on ${size - 1} follower(s) after ${(performance.now() - committedAt).toFixed(1)} ms (bound ${BOUND} ms)`);
    const auditor = await c.clients[0]!.login('sam');
    const verified = await c.clients[0]!.call('/admin/v1/audit/verify', 'GET', undefined, auditor);
    assert.equal(verified.data.verified, true);
    assert.equal(verified.data.length, Object.values(await chainRows(c.sql)).reduce((a, b) => a + b, 0), 'verify counts every chain');
    const exported = await fetch(`${c.nodes[0]!.url}/admin/v1/audit/export?limit=1000`, { headers: auditor });
    const lines = (await exported.text()).trim().split('\n').map((line) => JSON.parse(line) as { node?: string });
    assert.equal(lines.length, verified.data.length, 'the export pages through every chain');
    assert.match(String(exported.headers.get('x-audit-next-from')), size === 2 ? /^a:\d+,b:\d+$/ : /^a:\d+,b:\d+,c:\d+$/);
    // until (the signed manifest's heads) stops each chain there and leaves out the chains it does not name
    const bounded = await fetch(`${c.nodes[0]!.url}/admin/v1/audit/export?limit=1000&until=a:3,b:2`, { headers: auditor });
    const kept = (await bounded.text()).trim().split('\n').map((line) => JSON.parse(line) as { node?: string; seq: number });
    assert.deepEqual(kept.map((r) => `${r.node}:${r.seq}`), ['a:1', 'a:2', 'a:3', 'b:1', 'b:2']);
  });
}

test('a follower that falls behind or loses its notification connection refuses decisions, then catches up by reloading', { skip, timeout: 60_000 }, async (t) => {
  let hold: Promise<void> | undefined; let release = (): void => undefined;
  const c = await cluster(t, 2, (id) => (id === 'b' ? { databaseHooks: { beforeSync: () => hold ?? Promise.resolve() } } : {}));
  assert.equal((await c.decision(1)).decision, true);
  hold = new Promise<void>((resolve) => { release = () => { hold = undefined; resolve(); }; });
  await new Promise((resolve) => setTimeout(resolve, BOUND + 200));
  const stale = await c.decision(1);
  assert.equal(stale.status, 503, 'no decision on a state last confirmed longer ago than the bound');
  assert.equal((await c.clients[1]!.call('/readyz')).status, 503);
  await c.change(0, { id: 'bob', set: { active: false } });
  assert.equal((await c.decision(1)).status, 503, 'still behind: the change is not decided on stale policy');
  release();
  await within(2000, async () => (await c.decision(1)).status === 200);
  assert.equal((await c.decision(1)).decision, false, 'caught up: the reload brought the change');

  await c.sql(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = 'gate_sync'`);
  const restored = await within(5000, async () => { const r = await c.decision(1); return r.status === 200 && r.decision === false; });
  t.diagnostic(`deciding again ${restored.toFixed(0)} ms after the sync connections were terminated`);
});

test('a follower does not decide on a state document whose policy signature does not verify, as a start would not', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 2);
  const genuine = String((await c.sql(`SELECT body FROM gate_doc WHERE name = 'state'`)).rows[0]?.body);
  const forged = JSON.parse(genuine) as { state: { bundle: { sod: unknown[] } } };
  assert.ok(forged.state.bundle.sod.length > 0);
  forged.state.bundle.sod = []; // separation of duty removed behind the leader, unsigned
  const publish = async (body: string): Promise<void> => {
    await c.sql(`UPDATE gate_doc SET body = $1 WHERE name = 'state'`, [body]);
    await c.sql(`UPDATE gate_sync SET version = version + 1`);
    await c.sql(`NOTIFY gate_sync`);
  };
  await publish(JSON.stringify(forged));
  await within(BOUND, async () => (await c.decision(1)).status === 503);
  assert.equal((await c.decision(0)).status, 200, 'the leader keeps the state it wrote');
  await publish(genuine);
  await within(2000, async () => (await c.decision(1)).status === 200);
});

test('a decision token is consumed once across nodes, also when two nodes race for it', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 3);
  const issue = async (node: number): Promise<string> => {
    const r = await c.clients[node]!.call('/access/v1/evaluation', 'POST', evaluation('grace', 'PAY-3', 'create', 'trusted'), bearer(c.key));
    return String((r.data.context as { decision_token: string }).decision_token);
  };
  const consume = async (node: number, token: string): Promise<number> =>
    (await c.clients[node]!.call('/x/v1/tokens/consume', 'POST', { token, action: 'create', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 }, bearer(c.key))).status;
  const token = await issue(0);
  assert.equal(await consume(1, token), 200, 'issued on a, consumed on b');
  assert.equal(await consume(2, token), 409, 'refused on c');
  assert.equal(await consume(0, token), 409, 'refused on a');
  for (let round = 0; round < 5; round++) {
    const raced = await issue(round % 3);
    const statuses = (await Promise.all([consume(1, raced), consume(2, raced), consume(0, raced)])).sort();
    assert.deepEqual(statuses, [200, 409, 409], 'the database serialises consumption: exactly one node consumes');
  }
  assert.equal(Number((await c.sql('SELECT count(*) AS n FROM gate_performed')).rows[0].n), 6, 'one performed action per consumed token, shared by every node');
});

test('separation of duty holds across nodes: two tokens for conflicting actions on one resource are not both consumed, whatever either node has synced', { skip, timeout: 60_000 }, async (t) => {
  let hold: Promise<void> | undefined; let release = (): void => undefined;
  const c = await cluster(t, 2, (id) => (id === 'b' ? { databaseHooks: { beforeSync: () => hold ?? Promise.resolve() } } : {}));
  // henry may both create and approve; only separation of duty stands between the two on one payment
  await c.change(0, { id: 'henry', set: { roles: ['finance_clerk', 'finance_approver'] } });
  const ask = async (node: number, action: string): Promise<string> => {
    const r = await c.clients[node]!.call('/access/v1/evaluation', 'POST', { subject: { type: 'user', id: 'henry' }, action: { name: action },
      resource: { type: 'payment', id: 'PAY-3' }, context: { network: 'trusted', ...(action === 'approve' ? { makerId: 'grace' } : {}) } }, bearer(c.key));
    assert.equal(r.data.decision, true, `${action} on node ${node}: ${JSON.stringify(r.data)}`);
    return String((r.data.context as { decision_token: string }).decision_token);
  };
  await within(2000, async () => { try { await ask(1, 'create'); return true; } catch { return false; } });
  const consume = async (node: number, token: string, action: string): Promise<{ status: number; reservation?: string }> => {
    const r = await c.clients[node]!.call('/x/v1/tokens/consume', 'POST', { token, action, resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 }, bearer(c.key));
    return { status: r.status, ...(r.data.reservation ? { reservation: String(r.data.reservation) } : {}) };
  };
  const stall = (): void => { hold = new Promise<void>((resolve) => { release = () => { hold = undefined; resolve(); }; }); };
  // in turn: b has not synced a's reservation when it consumes (its synchronisation is held)
  const create = await ask(0, 'create'); const approve = await ask(1, 'approve');
  stall();
  try {
    const made = await consume(0, create, 'create');
    assert.equal(made.status, 200);
    assert.equal((await consume(1, approve, 'approve')).status, 409, 'b decides on the history the database holds, not on its cache');
    release();
    assert.equal((await c.clients[0]!.call('/x/v1/tokens/outcome', 'POST', { reservation: made.reservation, outcome: 'failed' }, bearer(c.key))).status, 200);
    // at the same moment: exactly one of the two conflicting actions is reserved
    const [create2, approve2] = [await ask(0, 'create'), await ask(1, 'approve')];
    stall();
    const raced = await Promise.all([consume(0, create2, 'create'), consume(1, approve2, 'approve')]);
    assert.deepEqual(raced.map((r) => r.status).sort(), [200, 409], 'the per-resource lock orders the two consumptions');
  } finally { release(); }
});

test('a session mark recorded on one node holds on the next decision of another, with no wait for synchronisation', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 2);
  const ask = async (node: number, resource: string, action: string, context: Record<string, unknown>): Promise<{ decision: boolean; context: { rules: string[] } }> =>
    (await c.clients[node]!.call('/access/v1/evaluation', 'POST', { subject: { type: 'user', id: 'carol' }, action: { name: action },
      resource: { type: 'case', id: resource }, context: { network: 'trusted', ...context } }, bearer(c.key))).data as { decision: boolean; context: { rules: string[] } };
  const write = (node: number, sessionId: string) => ask(node, 'CASE-11', 'update', { sessionId, sessionLevel: 1 });
  assert.equal((await write(1, 's1')).decision, true);
  assert.equal((await ask(0, 'CASE-14', 'read', { sessionId: 's1' })).decision, true);
  // the read's mark was committed before it was answered; b loads it before deciding (not at its next sync)
  assert.deepEqual((await write(1, 's1')).context.rules, ['BLP.HIGH_WATER']);
  const rows = (await c.sql('SELECT session, subject, level FROM gate_blp_mark')).rows;
  assert.deepEqual(rows.map((r) => [r.subject, r.level]), [['["user","carol"]', 2]]);
  assert.ok(!JSON.stringify(rows).includes('s1'), 'the session id is stored hashed with the PEP credential');
  // a row past its tombstone horizon decides nothing, and a new read in that session replaces it instead of merging into it
  assert.equal((await ask(0, 'CASE-14', 'read', { sessionId: 's2' })).decision, true);
  await c.sql(`UPDATE gate_blp_mark SET started = started - $1, seen = seen - $1 WHERE level = 2`, [SESSION_TOMBSTONE_MS + 1000]);
  assert.equal((await write(1, 's2')).decision, true, 'b never held s2: the forgotten row is ignored');
  assert.equal((await ask(1, 'CASE-11', 'read', { sessionId: 's2' })).decision, true);
  const replaced = (await c.sql(`SELECT level, started FROM gate_blp_mark ORDER BY level`)).rows;
  assert.ok(replaced.some((r) => r.level === 1 && Date.now() - Number(r.started) < 60_000), JSON.stringify(replaced));
});

test('CBAC.SESSION_EXPIRED sticks across nodes: an expired legacy session stays expired until its tombstone horizon', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 2);
  const ask = async (node: number, resource: string, action: string): Promise<{ decision: boolean; context: { rules: string[] } }> =>
    (await c.clients[node]!.call('/access/v1/evaluation', 'POST', { subject: { type: 'user', id: 'carol' }, action: { name: action },
      resource: { type: 'case', id: resource }, context: { network: 'trusted', sessionId: 's3', ...(action === 'read' ? {} : { sessionLevel: 1 }) } }, bearer(c.key))).data as { decision: boolean; context: { rules: string[] } };
  assert.equal((await ask(0, 'CASE-14', 'read')).decision, true);
  // the session passes its absolute expiry (the marks use the real clock: the row is aged instead)
  await c.sql('UPDATE gate_blp_mark SET started = started - $1', [SESSION_ABSOLUTE_MS]);
  const row = async () => (await c.sql('SELECT level, started, seen FROM gate_blp_mark')).rows;
  const before = await row();
  for (const node of [1, 0, 1]) {
    assert.deepEqual((await ask(node, 'CASE-11', 'update')).context.rules, ['CBAC.SESSION_EXPIRED'], `write on node ${node}`);
    assert.deepEqual((await ask(node, 'CASE-14', 'read')).context.rules, ['CBAC.SESSION_EXPIRED'], `read on node ${node}: no fresh mark`);
  }
  assert.deepEqual(await row(), before, 'nothing revived or replaced the expired mark');
  // past absolute expiry plus the grace period, the tombstone is forgotten and the id starts clean
  await c.sql('UPDATE gate_blp_mark SET started = started - $1', [SESSION_TOMBSTONE_MS - SESSION_ABSOLUTE_MS + 1000]);
  assert.equal((await ask(1, 'CASE-11', 'update')).decision, true);
});

test('a read and write of one session are linearizable across nodes, while another session and non-session traffic proceed', { skip, timeout: 60_000 }, async (t) => {
  let hold = true;
  let entered!: () => void;
  let release!: () => void;
  const reading = new Promise<void>((resolve) => { entered = resolve; });
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const c = await cluster(t, 2, (id) => id === 'a' ? { decisionHooks: { afterDecision: async () => {
    if (hold) { hold = false; entered(); await gate; }
  } } } : {});
  const ask = async (node: number, resource: string, action: string, context: Record<string, unknown>): Promise<{ decision: boolean; context: { rules: string[] } }> =>
    (await c.clients[node]!.call('/access/v1/evaluation', 'POST', { subject: { type: 'user', id: 'carol' }, action: { name: action },
      resource: { type: 'case', id: resource }, context: { network: 'trusted', ...context } }, bearer(c.key))).data as { decision: boolean; context: { rules: string[] } };
  const read = ask(0, 'CASE-14', 'read', { sessionId: 's1' });
  await reading;
  assert.equal((await ask(1, 'CASE-14', 'read', { sessionId: 's2' })).decision, true, 'another session does not wait for s1');
  assert.equal((await c.decision(1)).decision, true, 'non-session traffic does not wait for s1');
  let writeSettled = false;
  const write = ask(1, 'CASE-11', 'update', { sessionId: 's1', sessionLevel: 1 }).then((answer) => { writeSettled = true; return answer; });
  try {
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(writeSettled, false, 'b waits for the mark transaction on a, not for its next state synchronisation');
  } finally { release(); }
  assert.equal((await read).decision, true);
  assert.deepEqual((await write).context.rules, ['BLP.HIGH_WATER'], 'the write reloads the committed mark under the session lock');
});

test('a session decision token is consumed under its session lock on another node', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 2);
  const issued = await c.clients[0]!.call('/access/v1/evaluation', 'POST', { subject: { type: 'user', id: 'henry' }, action: { name: 'approve' },
    resource: { type: 'payment', id: 'PAY-3' }, context: { network: 'trusted', makerId: 'grace', sessionId: 'token-session' } }, bearer(c.key));
  assert.equal(issued.data.decision, true);
  const token = String((issued.data.context as { decision_token: string }).decision_token);
  const consumed = await c.clients[1]!.call('/x/v1/tokens/consume', 'POST', { token, action: 'approve',
    resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 }, bearer(c.key));
  assert.equal(consumed.status, 200, JSON.stringify(consumed.data));
});

test('throughput: independent sessions complete across nodes and non-session traffic keeps its existing path', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 2);
  const perNode = 24;
  const measure = async (session: boolean): Promise<number> => {
    const started = performance.now();
    const answers = await Promise.all(c.nodes.flatMap((_, node) => Array.from({ length: perNode }, (_, i) => {
      const body = session ? { subject: { type: 'user', id: 'carol' }, action: { name: 'read' }, resource: { type: 'case', id: 'CASE-14' },
        context: { network: 'trusted', sessionId: `throughput-${node}-${i}` } } : evaluation();
      return c.decision(node, body);
    })));
    assert.ok(answers.every((answer) => answer.status === 200 && answer.decision === true));
    return performance.now() - started;
  };
  const plainMs = await measure(false);
  const sessionsMs = await measure(true);
  t.diagnostic(`${perNode * 2} decisions on two nodes: no session ${(perNode * 2 / plainMs * 1000).toFixed(1)}/s (${plainMs.toFixed(1)} ms); independent sessions ${(perNode * 2 / sessionsMs * 1000).toFixed(1)}/s (${sessionsMs.toFixed(1)} ms)`);
});

test('a session mark committed while an audit recheck holds its snapshot is still loaded before the next decision', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  let armed = false; let scanStarted!: () => void; let releaseScan!: () => void;
  const scanning = new Promise<void>((resolve) => { scanStarted = resolve; });
  const gate = new Promise<void>((resolve) => { releaseScan = resolve; });
  const ledger = await PgLedger.open(appUrl!, () => undefined, { onScanStart: async () => { if (armed) { scanStarted(); await gate; } } });
  t.after(() => ledger.close());
  ledger.auditLog(() => FIXED).append({ type: 'decision', actor: 'pep', action: 'read', effect: 'allow' });
  await ledger.commit();
  armed = true;
  const checking = ledger.recheck();
  await scanning; // the recheck's REPEATABLE READ transaction is open on the read connection
  try {
    assert.deepEqual(await ledger.loadMarks(['s']), []);
    await sql(`INSERT INTO gate_blp_mark (session, subject, level, started, seen) VALUES ('s', '["user","carol"]', 2, $1, $1)`, [Date.now()]);
    assert.deepEqual((await ledger.loadMarks(['s'])).map((m) => m.mark.level), [2], 'another node\'s mark, committed after the recheck began');
  } finally { releaseScan(); }
  assert.ok(await checking);
});

test('a reservation is settled once across nodes: any node takes the report, a contrary one is refused, racing reports agree', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 3);
  const reserve = async (node: number): Promise<string> => {
    const r = await c.clients[node]!.call('/access/v1/evaluation', 'POST', evaluation('grace', 'PAY-3', 'create', 'trusted'), bearer(c.key));
    const token = String((r.data.context as { decision_token: string }).decision_token);
    const consumed = await c.clients[node]!.call('/x/v1/tokens/consume', 'POST', { token, action: 'create', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 }, bearer(c.key));
    assert.equal(consumed.status, 200);
    return String(consumed.data.reservation);
  };
  const report = async (node: number, reservation: string, outcome: string): Promise<number> =>
    (await c.clients[node]!.call('/x/v1/tokens/outcome', 'POST', { reservation, outcome }, bearer(c.key))).status;
  const first = await reserve(0);
  assert.equal(await report(1, first, 'failed'), 200, 'reserved on a, settled on b (which may not have synced it yet)');
  assert.equal(await report(2, first, 'completed'), 409);
  assert.equal(await report(0, first, 'failed'), 200, 'the same report again');
  assert.equal(await report(2, 'unknown-reservation', 'failed'), 404);
  for (let round = 0; round < 3; round++) {
    const raced = await reserve(round);
    const statuses = await Promise.all([report(0, raced, 'completed'), report(1, raced, 'failed'), report(2, raced, 'completed')]);
    const won = (await c.sql(`SELECT body FROM gate_performed WHERE ref = $1 AND kind = 'outcome'`, [raced])).rows.map((r) => JSON.parse(String(r.body)).outcome as string);
    assert.equal(won.length, 1, 'one outcome row per reservation');
    assert.deepEqual(statuses, [won[0] === 'completed' ? 200 : 409, won[0] === 'failed' ? 200 : 409, won[0] === 'completed' ? 200 : 409]);
  }
  const leader = c.clients[0]!;
  const pending = async (): Promise<unknown[]> => ((await leader.call('/admin/v1/integrity/reservations', 'GET', undefined, await leader.login('sam'))).data.items as unknown[]);
  await within(BOUND, async () => (await pending()).length === 0);
  await reserve(1);
  await within(BOUND, async () => (await pending()).length === 1);
});

test('per-node chains verify; a node restarts on its own chain; a rewritten or missing row in one chain is caught and named', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 3);
  await Promise.all(c.nodes.map((_, node) => Promise.all([c.decision(node), c.decision(node), c.decision(node)])));
  const watcher = await PgLedger.open(c.appUrl, () => undefined, { node: 'w', cluster: true, maxStalenessMs: BOUND });
  t.after(() => watcher.close());
  assert.ok(await watcher.recheck(), 'every chain verifies');
  const audit = watcher.auditLog(() => FIXED);
  assert.equal(audit.verify().length, Object.values(await chainRows(c.sql)).reduce((a, b) => a + b, 0));
  // an anchor names every chain's head; heads that do not hash to the anchored value break the chain
  const point = await watcher.recheck();
  assert.ok(point && point.heads && Object.keys(point.heads).join() === 'a,b,c', 'several chains: the anchored value covers every head');
  const anchored = await PgLedger.open(c.appUrl, () => undefined, { node: 'u', cluster: true, maxStalenessMs: BOUND });
  anchored.anchors.push({ ...point, tsa: 'test', genTime: FIXED, token: '' });
  assert.ok(await anchored.recheck(), 'the anchored heads verify');
  anchored.anchors.push({ ...point, tsa: 'test', genTime: FIXED, token: '', heads: { ...point.heads, a: { ...point.heads.a!, seq: point.heads.a!.seq - 1 } } });
  assert.equal(await anchored.recheck(), false, 'a rewritten list of heads is caught');
  await anchored.close();

  const chainOfB = async (): Promise<number[]> => (await c.sql(`SELECT seq FROM gate_audit WHERE node = 'b' ORDER BY seq`)).rows.map((r) => Number(r.seq));
  const written = (await chainOfB()).length;
  await c.nodes[1]!.close();
  const restarted = await clusterNode(t, c.appUrl, 'b');
  assert.equal((await (await client(restarted, c.leaderDir)).call('/access/v1/evaluation', 'POST', evaluation(), bearer(c.key))).status, 200);
  assert.deepEqual(await chainOfB(), Array.from({ length: written + 1 }, (_, i) => i + 1), 'node b continues its own chain after a restart');
  assert.ok(await watcher.recheck(), 'and it still verifies');

  await c.sql(`UPDATE gate_audit SET record = jsonb_set(record::jsonb, '{actor}', '"mallory"')::text WHERE node = 'c' AND seq = 2`);
  assert.equal(await watcher.recheck(), false);
  assert.deepEqual(auditShape(audit), { verified: false, length: audit.verify().length, brokenAt: 2, node: 'c' });
  await assert.rejects(clusterNode(t, c.appUrl, 'd'), /Audit integrity failure/, 'a node does not start on a tampered log');
  await c.sql(`UPDATE gate_audit SET record = jsonb_set(record::jsonb, '{actor}', '"pep"')::text WHERE node = 'c' AND seq = 2`); // as written

  const second = await PgLedger.open(c.appUrl, () => undefined, { node: 'v', cluster: true, maxStalenessMs: BOUND });
  t.after(() => second.close());
  assert.ok(await second.recheck(), 'the row restored as written verifies again');
  const last = Math.max(...await chainOfB());
  await c.sql(`DELETE FROM gate_audit_meta WHERE node = 'b' AND seq = $1`, [last]);
  await c.sql(`DELETE FROM gate_audit WHERE node = 'b' AND seq = $1`, [last]);
  assert.equal(await second.recheck(), false, 'the head of chain b seen before is missing');
  assert.equal(second.auditLog(() => FIXED).verify().node, 'b');
});

test('leader failover: the followers keep deciding, one of them takes the admin plane, and its changes reach the other', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 3);
  let running = true; const failures: number[] = []; let decided = 0;
  const loop = async (node: number): Promise<void> => {
    while (running) { const r = await c.decision(node); if (r.status !== 200) failures.push(r.status); else decided++; }
  };
  const loops = [loop(1), loop(2)];
  await new Promise((resolve) => setTimeout(resolve, 200));
  const stopped = performance.now();
  await c.nodes[0]!.close();
  let leader = -1;
  const takeover = await within(5000, async () => {
    for (const node of [1, 2]) if ((await c.clients[node]!.call('/leaderz')).status === 200) leader = node;
    return leader > 0;
  });
  t.diagnostic(`node ${leader === 1 ? 'b' : 'c'} took the admin plane ${takeover.toFixed(0)} ms after the leader stopped (${(performance.now() - stopped).toFixed(0)} ms)`);
  await c.change(leader, { id: 'bob', set: { active: false } });
  const other = leader === 1 ? 2 : 1;
  await within(BOUND, async () => (await c.decision(other)).decision === false);
  running = false; await Promise.all(loops);
  assert.deepEqual(failures, [], 'no follower refused a decision during the failover');
  assert.ok(decided > 20, `followers kept deciding (${decided})`);
  const verified = await c.clients[leader]!.call('/admin/v1/audit/verify', 'GET', undefined, await c.clients[leader]!.login('sam'));
  assert.equal(verified.data.verified, true);
});

test('a takeover that fails while reloading the documents releases the leader lock', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 2);
  await c.sql(`INSERT INTO gate_doc (name, body) VALUES ('unreadable', 'not json')`); // the takeover's full reload throws on it
  await c.nodes[0]!.close();
  const held: number[] = [];
  for (let i = 0; i < 6; i++) {
    await new Promise((resolve) => setTimeout(resolve, 250));
    held.push((await c.sql(`SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND objid = $1 AND granted`, [0x47415445])).rows[0]!.n as number);
  }
  assert.ok(held.includes(0), `the failing follower released the leader lock between attempts (held: ${held.join(',')})`);
  await c.sql(`DELETE FROM gate_doc WHERE name = 'unreadable'`);
  await within(5000, async () => (await c.clients[1]!.call('/leaderz')).status === 200);
});

test('a 0.4.0 database gains the reservation columns; its performed rows load unchanged, as completed actions', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const v040 = SCHEMA.split('\n').filter((line) => !/gate_performed ADD COLUMN|gate_performed_ref/.test(line)).join('\n');
  await sql(`${DROP_GATE_TABLES}; SET ROLE gate_owner; ${v040} RESET ROLE; ${serviceGrants('gate_app')}`);
  const legacy = JSON.stringify({ subject: { type: 'user', id: 'grace' }, resource: { type: 'payment', id: 'PAY-3' }, action: 'create', at: FIXED });
  await sql(`INSERT INTO gate_performed (seq, node, body) VALUES (1, '0', $1)`, [legacy]);
  await sql('UPDATE gate_sync SET performed = 1');
  assert.equal((await sql(`SELECT to_regclass('gate_performed_ref') AS r`)).rows[0]?.r, null);
  await sql(`SET ROLE gate_owner; ${SCHEMA} RESET ROLE`); // the owner's migration (gate-migrate), idempotent
  assert.deepEqual((await sql('SELECT body, ref, kind FROM gate_performed')).rows, [{ body: legacy, ref: null, kind: null }]);
  const ledger = await PgLedger.open(appUrl, () => undefined);
  t.after(() => ledger.close());
  assert.deepEqual(ledger.takePerformed(), [JSON.parse(legacy)]);
  ledger.stagePerformed({ ...JSON.parse(legacy) as object, id: 'r-1' } as never);
  ledger.stagePerformed({ ref: 'r-1', outcome: 'failed', at: FIXED });
  await ledger.commit();
  assert.deepEqual((await sql('SELECT seq::int, ref, kind FROM gate_performed ORDER BY seq')).rows,
    [{ seq: 1, ref: null, kind: null }, { seq: 2, ref: 'r-1', kind: 'reservation' }, { seq: 3, ref: 'r-1', kind: 'outcome' }]);
  await assert.rejects(sql(`INSERT INTO gate_performed (seq, node, body, ref, kind) VALUES (4, '0', '{}', 'r-1', 'outcome')`), /duplicate key/, 'one outcome per reservation');
});

test('an earlier version\'s single chain becomes chain "0" without rewriting a row, and continues there', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  // the tables as the previous version created them
  await sql(`${DROP_GATE_TABLES}; SET ROLE gate_owner;
    CREATE TABLE gate_doc (name text PRIMARY KEY, body text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE gate_audit (seq bigint PRIMARY KEY CHECK (seq > 0), record text NOT NULL);
    CREATE TABLE gate_audit_meta (seq bigint PRIMARY KEY, ts text NOT NULL, type text NOT NULL, effect text, subject text, resource text, rules text[] NOT NULL);
    CREATE TABLE gate_anchor (seq bigint PRIMARY KEY, hash text NOT NULL, tsa text NOT NULL, gen_time timestamptz NOT NULL, token bytea NOT NULL);
    RESET ROLE`);
  let prev = GENESIS;
  for (let seq = 1; seq <= 3; seq++) {
    const record = { type: 'decision', actor: 'pep', action: 'read', subject: 'bob', effect: 'allow', rules: [], seq, ts: FIXED, prevHash: prev };
    const hash = sha256(prev + canonical(record));
    await sql('INSERT INTO gate_audit (seq, record) VALUES ($1, $2)', [seq, JSON.stringify({ ...record, hash })]);
    await sql(`INSERT INTO gate_audit_meta (seq, ts, type, effect, subject, rules) VALUES ($1, $2, 'decision', 'allow', '"bob"', '{}')`, [seq, FIXED]);
    prev = hash;
  }
  const rows = async (): Promise<string[]> => (await sql('SELECT record FROM gate_audit WHERE seq <= 3 ORDER BY seq')).rows.map((r) => String(r.record));
  const legacy = await rows();
  await sql(`SET ROLE gate_owner; ${SCHEMA} RESET ROLE; ${serviceGrants('gate_app')}`);
  assert.deepEqual(await rows(), legacy, 'no stored record changed');
  assert.deepEqual((await sql('SELECT DISTINCT node FROM gate_audit')).rows.map((r) => r.node), ['0']);
  const zero = await PgLedger.open(appUrl, () => undefined);
  const audit = zero.auditLog(() => FIXED);
  assert.deepEqual(auditShape(audit), { verified: true, length: 3 });
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'allow' });
  await zero.commit();
  await zero.close();
  const stored = JSON.parse(String((await sql(`SELECT record FROM gate_audit WHERE node = '0' AND seq = 4`)).rows[0]?.record)) as { prevHash: string; node?: string };
  assert.equal(stored.prevHash, prev, 'node "0" continues the old chain');
  assert.equal(stored.node, undefined, 'and writes rows of the same shape');
  const b = await PgLedger.open(appUrl, () => undefined, { node: 'b' });
  t.after(() => b.close());
  b.auditLog(() => FIXED).append({ type: 'decision', actor: 'pep', action: 'read', effect: 'deny' });
  await b.commit();
  assert.ok(await b.recheck(), 'chain "0" and chain "b" verify together');
  assert.equal(b.auditLog(() => FIXED).verify().length, 5);
});

// --- cluster mode with what loop 3 added next to it: assertions (trust boundary), evidence packs and subject reports
// (compliance), TRUSTED_PROXIES (managed offer) --------------------------------------------------------------------
test('cluster: a follower signs decision assertions the leader\'s JWKS verifies, with the leader\'s rotated key once synced; evidence, export and subject report cover every chain', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 2, (id) => (id === 'a' ? { trustedProxies: '127.0.0.1, ::1' } : {}));
  const request = { audience: 'http://backend.internal:8080', method: 'GET', path: '/cases/CASE-14', bodySha256: bodySha256(Buffer.alloc(0)) };
  const asserted = async (node: number): Promise<string> => {
    const r = await c.clients[node]!.call('/x/v1/assertions/evaluation', 'POST', { ...evaluation(), request }, bearer(c.key));
    assert.equal(r.status, 200, JSON.stringify(r.data));
    return String(r.data.assertion);
  };
  const kid = (jws: string): string => (JSON.parse(Buffer.from(jws.split('.')[0]!, 'base64url').toString()) as { kid: string }).kid;
  let clock = Date.parse(FIXED); // the verifier refetches the JWKS for an unknown kid at most every 10 s
  const verifier = new AssertionVerifier({ jwksUrl: `${c.nodes[0]!.url}/.well-known/jwks.json`, audience: request.audience, now: () => clock });
  const verify = (header: string) => verifier.verify({ method: 'GET', path: request.path, body: Buffer.alloc(0), header });

  assert.equal((await c.decision(0)).decision, true, 'a decision about bob on the leader\'s chain too');
  const first = await asserted(1);
  const claims = await verify(first);
  const audited = (await c.sql(`SELECT node FROM gate_audit WHERE record LIKE $1`, [`%${claims.did}%`])).rows.map((r) => r.node);
  assert.deepEqual(audited, ['b'], 'the assertion\'s decision is audited on the follower\'s own chain');

  const lina = await c.clients[0]!.login('lina');
  const rotated = await c.clients[0]!.call('/admin/v1/signing-keys/rotate', 'POST', {}, lina);
  assert.equal(rotated.status, 201);
  const current = String((rotated.data.current as { kid: string }).kid);
  let after = '';
  await within(BOUND, async () => { after = await asserted(1); return kid(after) === current; });
  clock += 11_000;
  assert.equal((await verify(after)).sub.id, 'bob', 'the backend refreshes the JWKS on the new kid and accepts the follower\'s assertion');

  // a failed sign-in through a trusted proxy records the client address, on the leader's chain
  const refused = await c.clients[0]!.call('/admin/v1/session', 'POST', { username: 'sam', password: 'wrong' }, { 'x-forwarded-for': '203.0.113.7' });
  assert.equal(refused.status, 401);
  const denial = (await c.sql(`SELECT node, record FROM gate_audit WHERE record LIKE '%"login"%' AND record LIKE '%203.0.113.7%'`)).rows;
  assert.deepEqual(denial.map((r) => r.node), ['a']);

  const total = Object.values(await chainRows(c.sql)).reduce((a, b) => a + b, 0);
  const sam = await c.clients[0]!.login('sam');
  const withLogin = Object.values(await chainRows(c.sql)).reduce((a, b) => a + b, 0);
  assert.ok(withLogin >= total);
  const evidence = await c.clients[0]!.call('/admin/v1/compliance/evidence?framework=iso27001', 'GET', undefined, sam);
  assert.equal(evidence.status, 200, JSON.stringify(evidence.data));
  const section = (evidence.data.pack as { sections: { audit: { verification: { verified: boolean; length: number }; heads?: Record<string, unknown> } } }).sections.audit;
  assert.deepEqual([section.verification.verified, section.verification.length], [true, withLogin], 'the pack counts the rows of every chain');
  assert.deepEqual(Object.keys(section.heads ?? {}).sort(), ['a', 'b'], 'and names each chain\'s head');

  const exported = await fetch(`${c.nodes[0]!.url}/admin/v1/audit/export?limit=1000&pseudonymise=1`, { headers: sam });
  const lines = (await exported.text()).trim().split('\n').map((line) => JSON.parse(line) as { node?: string; subject?: string; pseudonymised?: boolean });
  assert.deepEqual([...new Set(lines.map((l) => l.node))].sort(), ['a', 'b']);
  assert.ok(lines.every((l) => l.pseudonymised === true && l.subject !== 'bob'));
  assert.match(String(exported.headers.get('x-audit-next-from')), /^a:\d+,b:\d+$/, 'the pseudonymised export pages through every chain');

  const report = await c.clients[0]!.call('/admin/v1/privacy/subjects/bob', 'GET', undefined, lina);
  assert.equal(report.status, 200, JSON.stringify(report.data));
  const rows = (report.data.audit as { rows: Array<{ node?: string }>; complete: boolean });
  assert.equal(rows.complete, true);
  assert.deepEqual([...new Set(rows.rows.map((r) => r.node))].sort(), ['a', 'b'], 'the subject access report reads every chain');
});

test('cluster: a resource registered through the PEP API is decided by every follower within the bound; a declassification waits for a second person', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 2);
  const leader = c.clients[0]!;
  const issued = await leader.call('/admin/v1/pep-credentials', 'POST', { name: 'case-app', resourceTypes: ['case', 'folder'] }, await leader.login('lina'));
  assert.equal(issued.status, 201, JSON.stringify(issued.data));
  const app = bearer(String(issued.data.secret));
  const record = (level: number) => ({ type: 'case', id: 'CASE-100', level, compartments: [], integrity: 'system', owner: 'carol', contentClasses: [], parent: { type: 'folder', id: 'FOLDER-A' } });
  const onFollower = async (): Promise<boolean | undefined> => (await c.decision(1, evaluation('bob', 'CASE-100'))).decision;
  assert.equal(await onFollower(), false, 'unknown before registration');
  const metadataBefore = (await c.sql(`SELECT body, updated_at FROM gate_doc WHERE name = 'state'`)).rows[0]!;
  const unrelatedBefore = String((await c.sql(`SELECT body FROM gate_resource WHERE type = 'case' AND id = 'CASE-14'`)).rows[0]!.body);
  const created = await leader.call('/x/v1/resources', 'POST', { resource: record(1) }, app);
  assert.equal(created.status, 201, JSON.stringify(created.data));
  const metadataAfter = (await c.sql(`SELECT body, updated_at FROM gate_doc WHERE name = 'state'`)).rows[0]!;
  assert.deepEqual(metadataAfter, metadataBefore, 'a record-only write does not rewrite state metadata');
  assert.equal(String((await c.sql(`SELECT body FROM gate_resource WHERE type = 'case' AND id = 'CASE-14'`)).rows[0]!.body), unrelatedBefore, 'an unrelated resource row is untouched');
  assert.equal((await c.sql(`SELECT count(*) AS n FROM gate_resource WHERE type = 'case' AND id = 'CASE-100'`)).rows[0]!.n, '1');
  assert.deepEqual((await c.sql('SELECT kind, op FROM gate_state_change WHERE seq = (SELECT max(seq) FROM gate_state_change) ORDER BY kind')).rows, [{ kind: 'resource', op: 'put' }, { kind: 'tuple', op: 'put' }]);
  const storedMetadata = JSON.parse(String(metadataAfter.body)) as { state: Record<string, unknown> };
  assert.equal(Object.hasOwn(storedMetadata.state, 'resources'), false);
  assert.equal(Object.hasOwn(storedMetadata.state, 'subjects'), false);
  assert.equal(Object.hasOwn(storedMetadata.state, 'tuples'), false);
  t.diagnostic(`registration visible on the follower after ${(await within(BOUND, async () => await onFollower() === true)).toFixed(1)} ms (bound ${BOUND} ms)`);
  const listed = async (): Promise<boolean> => {
    const reply = await c.clients[1]!.call('/access/v1/search/resource', 'POST', {
      subject: { type: 'user', id: 'bob' }, action: { name: 'read' }, resource: { type: 'case' }, page: { limit: 1000 },
    }, app);
    assert.equal(reply.status, 200);
    return (reply.data.results as Array<{ id: string }>).some((r) => r.id === 'CASE-100');
  };
  await within(BOUND, async () => await listed() === true);
  // one writer: the follower forwards (its advertised leader is unreachable here: 503) and never writes itself
  assert.equal((await c.clients[1]!.call('/x/v1/resources', 'POST', { resource: { ...record(1), id: 'CASE-101' } }, app)).status, 503);
  assert.equal((await c.clients[1]!.call('/x/v1/resources', 'POST', { resource: { ...record(1), id: 'CASE-101' } }, { ...app, 'x-gate-hop': 'v1.0.x.x.x.x' })).status, 409);

  assert.equal((await leader.call('/x/v1/resources', 'POST', { resource: record(3) }, app)).status, 200);
  await within(BOUND, async () => await onFollower() === false);
  await within(BOUND, async () => await listed() === false);
  const lowered = await leader.call('/x/v1/resources', 'POST', { resource: record(1) }, app);
  assert.equal(lowered.status, 202);
  const changeId = String((lowered.data.items as Array<{ changeId: string }>)[0]!.changeId);
  assert.equal((await leader.call(`/admin/v1/changes/${changeId}/approve`, 'POST', { reason: WHY }, await leader.login('lina'))).status, 403, 'the issuer of the credential cannot approve');
  assert.equal((await leader.call(`/admin/v1/changes/${changeId}/approve`, 'POST', { reason: WHY }, await leader.login('omar'))).status, 200);
  await within(BOUND, async () => await onFollower() === true);
  await within(BOUND, async () => await listed() === true);
  assert.equal((await leader.call('/x/v1/resources/retire', 'POST', { resource: { type: 'case', id: 'CASE-100' } }, app)).status, 200);
  await within(BOUND, async () => (await c.decision(1, evaluation('bob', 'CASE-100'))).decision === false);
  await within(BOUND, async () => await listed() === false);
  // the retired id is a row of its own (not in the state document), committed with the retirement; it comes back only through review
  assert.deepEqual((await c.sql(`SELECT type, id, version, node FROM gate_retired`)).rows, [{ type: 'case', id: 'CASE-100', version: '3', node: 'a' }]);
  assert.equal(String((await c.sql(`SELECT body FROM gate_doc WHERE name = 'state'`)).rows[0]?.body).includes('retired'), false);
  assert.equal((await leader.call('/x/v1/resources', 'POST', { resource: record(1) }, app)).status, 202, 'a reused id waits for a second person');
  const rows = (await c.sql(`SELECT record FROM gate_audit WHERE record::jsonb->>'action' LIKE 'resource_%'`)).rows.map((r) => (JSON.parse(String(r.record)) as { action: string }).action);
  assert.deepEqual(rows.sort(), ['resource_register', 'resource_register', 'resource_register', 'resource_register', 'resource_retire']);
});

test('a 0.6.0 state document migrates automatically, losslessly and idempotently into ordered record rows', { skip }, async (t) => {
  const { sql } = await reset();
  const v060 = SCHEMA.split('\n').filter((line) => !/gate_(?:subject|resource|tuple|state_change|audit_segment|subject_identity|blp_session|rate_limit)|records_migrated|records bigint|subject_position|resource_position|tuple_position/.test(line)).join('\n');
  await sql(`${DROP_GATE_TABLES}; ${v060}`);
  const world = JSON.parse(readFileSync(resolve('examples/toy-domain/world.json'), 'utf8')) as { subjects: unknown[]; resources: unknown[]; tuples: Array<Omit<Disk['state']['tuples'][number], 'id'>> };
  const bundle = JSON.parse(readFileSync(resolve('examples/toy-domain/bundle.json'), 'utf8')) as unknown;
  const legacy: Disk = {
    state: { bundle: bundle as Disk['state']['bundle'], subjects: world.subjects as Disk['state']['subjects'], resources: world.resources as Disk['state']['resources'],
      tuples: world.tuples.map((tuple, i) => ({ ...tuple, id: `seed-${i + 1}` })) as Disk['state']['tuples'] },
    changes: [], emergencies: [], history: [], performed: [],
  };
  await sql(`INSERT INTO gate_doc (name, body) VALUES ('state', $1)`, [JSON.stringify(legacy)]);
  await sql('UPDATE gate_sync SET version = 7');
  const dir = mkdtempSync('/tmp/pdp-pg-migration-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  // every table added after 0.6.0, by the audit (seals, subject mappings) and the per-record storage work alike
  const added = ['gate_audit_segment', 'gate_subject_identity', 'gate_subject', 'gate_resource', 'gate_tuple', 'gate_state_change'];
  const present = async (): Promise<string[]> => (await sql(`SELECT relname FROM pg_class WHERE relname = ANY($1) AND relkind = 'r' AND relrowsecurity AND relforcerowsecurity ORDER BY relname`, [added])).rows.map((row) => String(row.relname));
  assert.deepEqual(await present(), [], 'the 0.6.0 schema has none of them');
  let ledger = await PgLedger.open(admin!, () => undefined);
  assert.deepEqual(await present(), [...added].sort(), 'the automatic migration creates all of them with forced row-level security');
  let store = new Store(dir, resolve('examples/toy-domain'), FIXED, ledger.backing('state'));
  assert.deepEqual(store.state, legacy.state, 'every record and its original order survive');
  assert.equal(store.legacyDigest(), sha256(canonical(legacy.state)), 'pending state digests still mean the same state');
  assert.deepEqual((await sql('SELECT records_migrated, subject_position, resource_position, tuple_position FROM gate_sync')).rows,
    [{ records_migrated: true, subject_position: String(legacy.state.subjects.length), resource_position: String(legacy.state.resources.length), tuple_position: String(legacy.state.tuples.length) }]);
  assert.equal((await sql('SELECT count(*) AS n FROM gate_subject')).rows[0]!.n, String(legacy.state.subjects.length));
  assert.equal((await sql('SELECT count(*) AS n FROM gate_resource')).rows[0]!.n, String(legacy.state.resources.length));
  assert.equal((await sql('SELECT count(*) AS n FROM gate_tuple')).rows[0]!.n, String(legacy.state.tuples.length));
  assert.equal((await sql('SELECT count(*) AS n FROM gate_state_change')).rows[0]!.n, '0', 'the baseline needs no catch-up log');
  const metadata = JSON.parse(String((await sql(`SELECT body FROM gate_doc WHERE name = 'state'`)).rows[0]!.body)) as { state: Record<string, unknown> };
  for (const key of ['subjects', 'resources', 'tuples']) assert.equal(Object.hasOwn(metadata.state, key), false);
  await ledger.close();
  const bodies = (await sql('SELECT type, id, body, position FROM gate_resource ORDER BY type, id')).rows;
  ledger = await PgLedger.open(admin!, () => undefined);
  t.after(() => ledger.close());
  store = new Store(dir, resolve('examples/toy-domain'), FIXED, ledger.backing('state'));
  assert.deepEqual(store.state, legacy.state, 'a second start is a no-op');
  assert.deepEqual((await sql('SELECT type, id, body, position FROM gate_resource ORDER BY type, id')).rows, bodies);
});

test('a follower falls back to a full record snapshot when the incremental change log has a gap', { skip, timeout: 60_000 }, async (t) => {
  let hold: Promise<void> | undefined; let release = (): void => undefined;
  const c = await cluster(t, 2, (id) => (id === 'b' ? { databaseHooks: { beforeSync: () => hold ?? Promise.resolve() } } : {}));
  const leader = c.clients[0]!;
  const issued = await leader.call('/admin/v1/pep-credentials', 'POST', { name: 'case-app', resourceTypes: ['case', 'folder'] }, await leader.login('lina'));
  const app = bearer(String(issued.data.secret));
  hold = new Promise<void>((resolve) => { release = () => { hold = undefined; resolve(); }; });
  const resource = { type: 'case', id: 'CASE-GAP', level: 1, compartments: [], integrity: 'system', owner: 'carol', contentClasses: [], parent: { type: 'folder', id: 'FOLDER-A' } };
  assert.equal((await leader.call('/x/v1/resources', 'POST', { resource }, app)).status, 201);
  assert.ok(Number((await c.sql('SELECT count(*) AS n FROM gate_state_change')).rows[0]!.n) > 0);
  await c.sql('DELETE FROM gate_state_change');
  release();
  await within(2000, async () => (await c.decision(1, evaluation('bob', 'CASE-GAP'))).decision === true);
});

test('a record-only registration commit notifies followers itself: catch-up never waits for the poll', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 1);
  const leader = c.clients[0]!;
  const issued = await leader.call('/admin/v1/pep-credentials', 'POST', { name: 'case-app', resourceTypes: ['case', 'folder'] }, await leader.login('lina'));
  const app = bearer(String(issued.data.secret));
  const listener = new pg.Client({ connectionString: admin }); await listener.connect(); t.after(() => listener.end());
  const payloads: string[] = [];
  listener.on('notification', (n) => payloads.push(String(n.payload)));
  await listener.query('LISTEN gate_sync');
  const resource = { type: 'case', id: 'CASE-NOTIFY', level: 1, compartments: [], integrity: 'system', owner: 'carol', contentClasses: [], parent: { type: 'folder', id: 'FOLDER-A' } };
  assert.equal((await leader.call('/x/v1/resources', 'POST', { resource }, app)).status, 201);
  const version = String((await c.sql('SELECT version FROM gate_sync')).rows[0]!.version);
  // the single-statement write (postgres-fast-write.ts) must reference its pg_notify CTE, or PostgreSQL never runs it
  await within(2000, async () => payloads.includes(`v${version}`));
});

test('PostgreSQL v2 digest: every committed record, policy or certification change moves it, a change in flight never matches a committed generation, a restart keeps it', { skip }, async (t) => {
  await reset();
  const dir = mkdtempSync('/tmp/pdp-pg-digest-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  let ledger = await PgLedger.open(admin!, () => undefined);
  t.after(() => ledger.close()); // the ledger open at the end, also when an assertion fails
  const store = new Store(dir, resolve('examples/toy-domain'), FIXED, ledger.backing('state'));
  await ledger.commit();
  const seen = new Set([store.digest()]);
  for (const [name, mutate] of digestMutations) {
    mutate({ store, now: () => FIXED }); store.save();
    const inFlight = store.digest();
    assert.ok(!seen.has(inFlight), `${name}: changed state, uncommitted`);
    await ledger.commit();
    const committed = store.digest();
    assert.ok(!committed.includes('+') && (committed === inFlight || !seen.has(committed)), `${name}: committed`);
    seen.add(inFlight); seen.add(committed);
  }
  const last = store.digest();
  await ledger.close();
  ledger = await PgLedger.open(admin!, () => undefined);
  assert.equal(new Store(dir, resolve('examples/toy-domain'), FIXED, ledger.backing('state')).digest(), last, 'the same committed state, the same digest');
});

test('cluster: a resource registered in place after a preview makes the pending grant stale', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 1);
  const leader = c.clients[0]!;
  const issued = await leader.call('/admin/v1/pep-credentials', 'POST', { name: 'case-app', resourceTypes: ['case', 'folder'] }, await leader.login('lina'));
  const app = bearer(String(issued.data.secret));
  const grant = { kind: 'add_tuple', reason: WHY, payload: { object: { type: 'case', id: 'CASE-15' }, relation: 'allocated', subject: { type: 'user', id: 'bob' }, validTo: '2026-12-08T10:00:00Z' } };
  const proposed = await leader.call('/admin/v1/changes', 'POST', grant, await leader.login('amira'));
  assert.equal(proposed.status, 201, JSON.stringify(proposed.data));
  const resource = { type: 'case', id: 'CASE-DIGEST', level: 1, compartments: [], integrity: 'system', owner: 'carol', contentClasses: [], parent: { type: 'folder', id: 'FOLDER-A' } };
  assert.equal((await leader.call('/x/v1/resources', 'POST', { resource }, app)).status, 201);
  const approved = await leader.call(`/admin/v1/changes/${String(proposed.data.id)}/approve`, 'POST', { reason: WHY }, await leader.login('omar'));
  assert.deepEqual([approved.status, approved.data.message], [409, 'State changed; submit a new proposal']);
});

test('group commit: concurrent registrations share transactions, and each is answered only once its row is committed', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 1);
  const leader = c.clients[0]!;
  const issued = await leader.call('/admin/v1/pep-credentials', 'POST', { name: 'case-app', resourceTypes: ['case', 'folder'] }, await leader.login('lina'));
  const app = bearer(String(issued.data.secret));
  const before = Number((await c.sql('SELECT version FROM gate_sync')).rows[0]!.version);
  // closed loop, as PEPs send: 16 clients, each sending its next registration once the previous one is answered
  const clients = 16, each = 8, n = clients * each;
  const probe = new pg.Client({ connectionString: admin }); await probe.connect(); t.after(() => probe.end());
  await Promise.all(Array.from({ length: clients }, async (_, client) => {
    for (let k = 0; k < each; k++) {
      const resource = { type: 'case', id: `CASE-GROUP-${client}-${k}`, level: 1, compartments: [], integrity: 'system', owner: 'carol', contentClasses: [], parent: { type: 'folder', id: 'FOLDER-A' } };
      assert.equal((await leader.call('/x/v1/resources', 'POST', { resource }, app)).status, 201);
      assert.equal((await probe.query(`SELECT count(*) AS n FROM gate_resource WHERE type = 'case' AND id = $1`, [resource.id])).rows[0]!.n, '1', 'durable before the answer');
    }
  }));
  const transactions = Number((await c.sql('SELECT version FROM gate_sync')).rows[0]!.version) - before;
  t.diagnostic(`${n} registrations from ${clients} clients in ${transactions} transactions`);
  assert.ok(transactions <= n / 3, `${transactions} transactions for ${n} registrations`);
  const audited = (await c.sql(`SELECT count(*) AS n FROM gate_audit WHERE record::jsonb->>'action' = 'resource_register'`)).rows[0]!.n;
  assert.equal(audited, String(n), 'one audit row per request');
});

test('group-committed record writes keep audit pseudonymisation: rows written by the single-statement path carry no raw id and their new mappings commit with them', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 1);
  const leader = c.clients[0]!;
  const issued = await leader.call('/admin/v1/pep-credentials', 'POST', { name: 'case-app', resourceTypes: ['case', 'folder'] }, await leader.login('lina'));
  const app = bearer(String(issued.data.secret));
  const fresh = Array.from({ length: 24 }, (_, i) => `fastpath-person-${i}`);
  // a registration (records only: the single-statement path) and a decision about a never-seen subject share one drain
  await Promise.all(fresh.map(async (id, i) => {
    const resource = { type: 'case', id: `CASE-PSEUDO-${i}`, level: 1, compartments: [], integrity: 'system', owner: 'carol', contentClasses: [], parent: { type: 'folder', id: 'FOLDER-A' } };
    const [registered, decided] = await Promise.all([
      leader.call('/x/v1/resources', 'POST', { resource }, app),
      leader.call('/access/v1/evaluation', 'POST', { ...evaluation(), subject: { type: 'user', id } }, bearer(c.key)),
    ]);
    assert.equal(registered.status, 201); assert.equal(decided.status, 200);
  }));
  for (const table of ['gate_audit', 'gate_audit_meta']) {
    const leaked = (await c.sql(`SELECT count(*) AS n FROM ${table} t WHERE t::text LIKE '%fastpath-person-%'`)).rows[0]!.n;
    assert.equal(leaked, '0', `no raw subject id in ${table}`);
  }
  const subjects = (await c.sql(`SELECT DISTINCT record::jsonb->>'subject' AS s FROM gate_audit WHERE record::jsonb->>'type' = 'decision' AND record::jsonb->>'subject' IS NOT NULL`)).rows.map((row) => String(row.s));
  const mapped = new Set((await c.sql('SELECT pseudonym FROM gate_subject_identity')).rows.map((row) => String(row.pseudonym)));
  for (const pseudonym of subjects) assert.ok(mapped.has(pseudonym), `${pseudonym} has its mapping row`);
  const ids = new Set((await c.sql('SELECT id FROM gate_subject_identity')).rows.map((row) => JSON.parse(String(row.id)) as string));
  for (const id of fresh) assert.ok(ids.has(id), `${id} was mapped in the same commit as its row`);
  // a start validates and loads the whole mapping (it fails closed on a mismatch)
  const restarted = await clusterNode(t, c.appUrl, 'b');
  assert.ok(restarted.url);
});

test('a username spray against PostgreSQL creates no subject mapping rows', { skip, timeout: 60_000 }, async (t) => {
  const c = await cluster(t, 1);
  const before = Number((await c.sql('SELECT count(*) AS n FROM gate_subject_identity')).rows[0]!.n);
  for (let i = 0; i < 5; i++) { // the per-client login limit is five tries
    const r = await c.clients[0]!.call('/admin/v1/session', 'POST', { username: `spray-${i}@example.test`, password: 'wrong' });
    assert.equal(r.status, 401);
  }
  assert.equal(Number((await c.sql('SELECT count(*) AS n FROM gate_subject_identity')).rows[0]!.n), before, 'no mapping row per tried username');
  const actors = (await c.sql(`SELECT record::jsonb->>'actor' AS a FROM gate_audit WHERE record::jsonb->>'action' = 'login' AND record::jsonb->>'effect' = 'deny'`)).rows.map((row) => String(row.a));
  assert.equal(actors.length, 5);
  for (const actor of actors) assert.match(actor, /^unknown:[0-9a-f]{32}$/);
  assert.equal((await c.sql(`SELECT count(*) AS n FROM gate_audit WHERE record LIKE '%spray-%'`)).rows[0]!.n, '0');
});


test('a follower keeps the leader\'s record order and legacy digest through inserts, retirements, re-adds and reorders', { skip, timeout: 60_000 }, async (t) => {
  const { sql } = await reset();
  const dirs = [mkdtempSync('/tmp/pdp-pg-order-a-'), mkdtempSync('/tmp/pdp-pg-order-b-'), mkdtempSync('/tmp/pdp-pg-order-c-')];
  t.after(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });
  const leader = await PgLedger.open(admin!, () => undefined, { cluster: true, node: 'a' });
  t.after(() => leader.close());
  const store = new Store(dirs[0]!, resolve('examples/toy-domain'), FIXED, leader.backing('state'));
  await leader.commit();
  // a follower starts once the database is seeded (state and credentials; no Auth runs here)
  await sql(`INSERT INTO gate_doc (name, body) VALUES ('credentials', '{}')`);
  const follower = await PgLedger.open(admin!, () => undefined, { cluster: true, node: 'b' });
  t.after(() => follower.close());
  const mirror = new Store(dirs[1]!, resolve('examples/toy-domain'), FIXED, follower.backing('state'));
  follower.onReload = (records) => mirror.reload(records);
  const resource = (id: string): Resource => ({ type: 'case', id, level: 1, compartments: [], integrity: 'system', owner: 'carol', contentClasses: [], version: 1 }) as Resource;
  const steps: Array<[string, () => void]> = [
    // one batch of appends whose ids sort the other way round
    ['inserts', () => { store.state = applyResourcesInPlace(store.state, [resource('ORDER-Z'), resource('ORDER-M'), resource('ORDER-A')]); }],
    ['retire and insert', () => { store.state = applyResourcesInPlace(store.state, [resource('ORDER-B')], [{ type: 'case', id: 'ORDER-M' }]); }],
    // retired and registered again in one batch: in memory it moved to the end
    ['re-add', () => {
      store.state = applyResourcesInPlace(store.state, [], [{ type: 'case', id: 'ORDER-Z' }]);
      store.state = applyResourcesInPlace(store.state, [resource('ORDER-Y')]);
      store.state = applyResourcesInPlace(store.state, [resource('ORDER-Z')]);
    }],
    // an unannotated reorder (the whole-record fallback)
    ['reorder', () => { const list = store.state.resources; store.state = { ...store.state, resources: [list.at(-1)!, ...list.slice(0, -1)] }; }],
    ['tuples', () => {
      const grants = ['t-z', 't-a'].map((id) => ({ id, object: { type: 'case', id: 'ORDER-A' }, relation: 'allocated', subject: { type: 'user', id: 'bob' } }));
      store.state = withRecordDeltas({ ...store.state, tuples: [...store.state.tuples, ...grants] }, grants.map((value) => ({ kind: 'tuple', op: 'put', type: '', id: value.id, value })));
    }],
  ];
  for (const [name, step] of steps) {
    step(); store.save(); await leader.commit();
    await follower.sync();
    for (const key of ['subjects', 'resources', 'tuples'] as const) {
      assert.deepEqual(mirror.state[key].map((r) => r.id), store.state[key].map((r) => r.id), `${name}: ${key} in the leader's order`);
    }
    assert.equal(mirror.legacyDigest(), store.legacyDigest(), `${name}: the same legacy digest`);
  }
  // and a fresh start reads the same order from the stored positions
  const fresh = await PgLedger.open(admin!, () => undefined, { cluster: true, node: 'c' });
  t.after(() => fresh.close());
  assert.equal(new Store(dirs[2]!, resolve('examples/toy-domain'), FIXED, fresh.backing('state')).legacyDigest(), store.legacyDigest());
});

test('a 0.6.0 state document with duplicate records is refused by name, and nothing is migrated or dropped', { skip }, async () => {
  const { sql } = await reset();
  const v060 = SCHEMA.split('\n').filter((line) => !/gate_(?:subject|resource|tuple|state_change|audit_segment|subject_identity|blp_session|rate_limit)|records_migrated|records bigint|subject_position|resource_position|tuple_position/.test(line)).join('\n');
  await sql(`${DROP_GATE_TABLES}; ${v060}`);
  const world = JSON.parse(readFileSync(resolve('examples/toy-domain/world.json'), 'utf8')) as { subjects: Array<{ id: string }>; resources: Array<{ type: string; id: string }>; tuples: object[] };
  const bundle = JSON.parse(readFileSync(resolve('examples/toy-domain/bundle.json'), 'utf8')) as unknown;
  const first = world.resources[0]!, tuple = { ...world.tuples[0]!, id: 'seed-1' };
  const legacy = { state: { bundle, subjects: world.subjects, resources: [...world.resources, { ...first, attrs: { copy: true } }],
    tuples: [tuple, tuple, ...world.tuples.slice(1).map((value, i) => ({ ...value, id: `seed-${i + 2}` }))] }, changes: [], emergencies: [], history: [], performed: [] };
  const body = JSON.stringify(legacy);
  await sql(`INSERT INTO gate_doc (name, body) VALUES ('state', $1)`, [body]);
  await assert.rejects(PgLedger.open(admin!, () => undefined),
    (err: Error) => err.message.includes('duplicate records (2)') && err.message.includes(`resource ${first.type}:${first.id}`) && err.message.includes('tuple seed-1'));
  assert.equal((await sql(`SELECT body FROM gate_doc WHERE name = 'state'`)).rows[0]!.body, body, 'the document is untouched');
  assert.equal((await sql(`SELECT to_regclass('gate_resource') IS NULL AS absent`)).rows[0]!.absent, true, 'the whole migration rolled back');
});

test('a database at the 0.8.3 schema, or with only the BLP session table, migrates to the BLP-token and grant-window schema', { skip }, async (t) => {
  const { sql } = await reset();
  const v083 = readFileSync(resolve('packages/pdp-http/test/fixtures/schema-0.8.3.sql'), 'utf8');
  // the loop-9 interim: the BLP session registry without the grant-window columns
  const blpOnly = SCHEMA.split('\n').filter((line) => !/not_before|not_after|used_at/.test(line)).join('\n');
  const state = async () => (await sql(`SELECT to_regclass('gate_blp_session') IS NOT NULL AS blp, to_regclass('gate_tuple_not_after') IS NOT NULL AS marker,
    (SELECT count(*) FROM information_schema.columns WHERE table_name = 'gate_tuple' AND column_name IN ('not_before', 'not_after')) AS columns`)).rows[0];
  for (const [name, schema, before] of [['0.8.3', v083, { blp: false, marker: false, columns: '0' }], ['BLP only', blpOnly, { blp: true, marker: false, columns: '0' }]] as const) {
    await sql(`${DROP_GATE_TABLES}; ${schema}`);
    await sql(`INSERT INTO gate_tuple (id, position, state_version, object_type, object_id, subject_type, subject_id, body) VALUES ('t1', 1, 1, 'case', 'CASE-1', 'user', 'bob', $1)`,
      [JSON.stringify({ object: { type: 'case', id: 'CASE-1' }, relation: 'allocated', subject: { type: 'user', id: 'bob' }, validTo: '2026-12-31T00:00:00Z' })]);
    assert.deepEqual(await state(), before, name);
    const ledger = await PgLedger.open(admin!, () => undefined);
    await ledger.close();
    assert.deepEqual(await state(), { blp: true, marker: true, columns: '2' }, `${name}: migrated`);
    assert.deepEqual((await sql(`SELECT not_before, not_after FROM gate_tuple WHERE id = 't1'`)).rows[0], { not_before: null, not_after: '2026-12-31T00:00:00Z' }, `${name}: backfilled`);
    assert.equal((await sql(`SELECT relforcerowsecurity AS forced FROM pg_class WHERE relname = 'gate_blp_session'`)).rows[0]!.forced, true);
  }
});

test('gate_tuple derives the CBAC grant window (not_before, not_after) on write and backfills it on migration; a stored legacy bundle loads', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const dir = mkdtempSync('/tmp/pdp-pg-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const options = { port: 0, dataDir: dir, databaseUrl: appUrl, signingKeySeal: SEAL, clock: `fixed:${FIXED}` };
  const a = createServer(options); await a.listen(); t.after(() => a.close());
  const ca = await client(a, dir);
  const window = async (id: string) => (await sql('SELECT not_before, not_after FROM gate_tuple WHERE id = $1', [id])).rows[0] as { not_before: string | null; not_after: string | null };
  // a seeded tuple carries the legacy names: the columns read them
  assert.deepEqual(await window('seed-4'), { not_before: '2026-09-01T00:00:00Z', not_after: '2026-12-31T23:59:59Z' });
  const proposed = await ca.call('/admin/v1/changes', 'POST', { kind: 'add_tuple', reason: WHY,
    payload: { object: { type: 'case', id: 'CASE-15' }, relation: 'allocated', subject: { type: 'user', id: 'bob' }, notAfter: '2026-11-20T00:00:00Z' } }, await ca.login('amira'));
  assert.equal(proposed.status, 201);
  assert.equal((await ca.call(`/admin/v1/changes/${String(proposed.data.id)}/approve`, 'POST', { reason: WHY }, await ca.login('omar'))).status, 200);
  const added = (await sql(`SELECT id FROM gate_tuple WHERE body::json ->> 'grantedBy' = 'amira'`)).rows[0] as { id: string };
  assert.deepEqual(await window(added.id), { not_before: '2026-11-08T10:00:00.000Z', not_after: '2026-11-20T00:00:00.000Z' });
  assert.equal((await sql(`SELECT count(*) AS n FROM pg_indexes WHERE indexname = 'gate_tuple_not_after'`)).rows[0].n, '1');
  await a.close();
  // an upgraded database: the columns are empty until SCHEMA backfills them from each body
  await sql('UPDATE gate_tuple SET not_before = NULL, not_after = NULL');
  await sql('SET ROLE gate_owner; ' + SCHEMA);
  assert.deepEqual(await window('seed-4'), { not_before: '2026-09-01T00:00:00Z', not_after: '2026-12-31T23:59:59Z' });
  assert.deepEqual(await window(added.id), { not_before: '2026-11-08T10:00:00.000Z', not_after: '2026-11-20T00:00:00.000Z' });
  // a bundle published before the rename (content rules under cbac) keeps loading and masking, under its own version
  const doc = JSON.parse((await sql(`SELECT body FROM gate_doc WHERE name = 'state'`)).rows[0].body as string) as Disk;
  const { abacContent, ...rest } = doc.state.bundle;
  const legacy = { ...rest, cbac: abacContent } as PolicyBundle;
  const { signature: unsigned, ...latest } = doc.history.at(-1)!;
  const stored = { ...doc, state: { ...doc.state, bundle: legacy }, history: [...doc.history.slice(0, -1), { ...latest, version: policyVersion(legacy) }] };
  await sql(`UPDATE gate_doc SET body = $1 WHERE name = 'state'`, [JSON.stringify(stored)]);
  // the publication is re-signed as the earlier version had signed it (POLICY_SIGNATURE_ADOPT stands in for its key)
  const b = createServer({ ...options, policySignatureAdopt: true }); await b.listen(); t.after(() => b.close());
  const read = await (await client(b, dir)).call('/access/v1/evaluation', 'POST', evaluation('bob', 'CASE-14', 'read', 'trusted'), { authorization: `Bearer ${initialCredentials(dir).pepApiKey}` });
  assert.equal(read.data.decision, true);
  assert.deepEqual((read.data.context as { obligations: { maskClasses: string[] } }).obligations.maskClasses, ['finance.amount']);
});

test('approval modes and snoozes are the shared approval_prefs document in PostgreSQL: set on A, in force on B, no file written', { skip }, async (t) => {
  const { appUrl, sql } = await reset();
  const dirA = mkdtempSync('/tmp/pdp-pg-'), dirB = mkdtempSync('/tmp/pdp-pg-');
  t.after(() => { rmSync(dirA, { recursive: true, force: true }); rmSync(dirB, { recursive: true, force: true }); });
  const options = { port: 0, databaseUrl: appUrl, signingKeySeal: SEAL, clock: `fixed:${FIXED}` };
  const a = createServer({ ...options, dataDir: dirA }); await a.listen(); t.after(() => a.close());
  const ca = await client(a, dirA);
  const amira = await ca.login('amira'); const omar = await ca.login('omar');
  assert.equal((await ca.call('/admin/v1/approval-modes/omar', 'PUT', { mode: 'list' }, amira)).status, 200);
  const proposed = await ca.call('/admin/v1/changes', 'POST', { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY }, amira);
  const item = `change:${String(proposed.data.id)}`;
  assert.equal((await ca.call('/admin/v1/inbox/snoozes', 'POST', { item, until: '2026-11-10' }, omar)).status, 201);
  const stored = await storedDoc(sql, 'approval_prefs') as { modes: Record<string, { mode: string; setBy: string }>; snoozes: Record<string, Record<string, unknown>> };
  assert.equal(stored.modes.omar?.mode, 'list'); assert.equal(stored.modes.omar?.setBy, 'amira');
  assert.ok(stored.snoozes.omar?.[item]);
  assert.equal(existsSync(resolve(dirA, 'approval-prefs.json')), false);
  const b = createServer({ ...options, dataDir: dirB });
  const bListening = b.listen(); t.after(() => b.close());
  await a.close(); await bListening;
  const cb = await client(b, dirA);
  const omarB = await cb.login('omar');
  assert.deepEqual((await cb.call('/admin/v1/inbox', 'GET', undefined, omarB)).data, { approvalMode: 'list', snoozes: [{ item, until: '2026-11-10' }] });
  const decided = await cb.call('/admin/v1/changes/decide', 'POST', { ids: [String(proposed.data.id)], approve: false, reason: WHY }, omarB);
  assert.deepEqual(decided.data.results, [{ id: proposed.data.id, ok: true, status: 'rejected' }]);
  assert.equal(existsSync(resolve(dirB, 'approval-prefs.json')), false);
});
