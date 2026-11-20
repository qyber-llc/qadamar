// The database half runs when TEST_DATABASE_URL (a superuser URL on a throwaway cluster) is set; skipped otherwise.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { TestContext } from 'node:test';
import pg from 'pg';
import { Audit } from '../src/audit.ts';
import { Auth } from '../src/auth.ts';
import { createServer, isLoopbackHost, type ServerOptions } from '../src/server.ts';
import { Store } from '../src/store.ts';
import { SCHEMA, serviceGrants } from '../src/postgres.ts';
import { configurationBaseline, databaseRoleFailures, DEMO_WORLD_WARNING, productionFailures, profileOf } from '../src/profile.ts';
import { hotp, fromBase32 } from '../src/totp.ts';
import { FIXED, req } from './helpers.ts';

const admin = process.env.TEST_DATABASE_URL;
const skip = admin ? false : 'TEST_DATABASE_URL is not set';
const SEAL = 'b'.repeat(64);
const METRICS = 'metrics-token-for-tests-0123456789abcdef';

function good(t: TestContext, databaseUrl = 'postgres://gate_app@db.example/gate'): ServerOptions {
  const dataDir = mkdtempSync('/tmp/pdp-profile-');
  t.after(() => rmSync(dataDir, { recursive: true, force: true }));
  return { profile: 'production', port: 0, dataDir, publicOrigin: 'https://gate.example',
    oidc: { issuer: 'https://idp.example', clientId: 'gate', idClaim: 'sub' }, databaseUrl, signingKeySeal: SEAL,
    tsa: { url: 'https://tsa.example/tsr', caFile: '/etc/gate/tsa-ca.pem' },
    breakGlass: { url: 'https://hooks.example/break-glass', secret: 'c'.repeat(32) }, sodHistory: 'server', blpSessionRequired: true, allowDemoWorld: true };
}
/** Each requirement removed on its own, and the line the refusal must carry. */
const missing: Array<[string, (o: ServerOptions) => ServerOptions, RegExp]> = [
  ['plain http origin', (o) => ({ ...o, publicOrigin: 'http://localhost:8787' }), /PUBLIC_ORIGIN must be https/],
  ['no IdP', (o) => ({ ...o, oidc: undefined }), /OIDC_ISSUER or SAML_IDP_ENTITY_ID must be configured/],
  ['password login without TOTP', (o) => ({ ...o, passwordLogin: true }), /PASSWORD_LOGIN is on but these local accounts have no active TOTP: amira, omar, lina, ruth, sam/],
  ['no database', (o) => ({ ...o, databaseUrl: undefined }), /DATABASE_URL must be set/],
  ['remote database TLS disabled', (o) => ({ ...o, databaseTls: { mode: 'disable' } }), /DATABASE_TLS=verify-full is required/],
  ['remote database TLS without hostname verification', (o) => ({ ...o, databaseTls: { mode: 'require' } }), /DATABASE_TLS=verify-full is required/],
  ['no seal key', (o) => ({ ...o, signingKeySeal: undefined }), /SIGNING_KEY_SEAL must be set/],
  ['no TSA', (o) => ({ ...o, tsa: undefined }), /TSA_URL \(https\) and TSA_CA_FILE must be set/],
  ['TSA without CA file', (o) => ({ ...o, tsa: { url: 'https://tsa.example/tsr' } }), /TSA_URL \(https\) and TSA_CA_FILE must be set/],
  ['fixed clock', (o) => ({ ...o, clock: 'fixed:2026-11-08T10:00:00Z' }), /CLOCK must not be set/],
  ['no break-glass webhook', (o) => ({ ...o, breakGlass: undefined }), /BREAK_GLASS_WEBHOOK and BREAK_GLASS_WEBHOOK_SECRET must be set/],
  ['SoD history from the caller', (o) => ({ ...o, sodHistory: 'caller' }), /SOD_HISTORY must be server/],
  ['BLP session ids optional', (o) => ({ ...o, blpSessionRequired: undefined }), /BLP_SESSION_REQUIRED must be true/],
  ['clear signing keys allowed', (o) => ({ ...o, allowClearSigningKeys: true }), /ALLOW_CLEAR_SIGNING_KEYS must be off/],
  ['policy signature adoption', (o) => ({ ...o, policySignatureAdopt: true }), /POLICY_SIGNATURE_ADOPT must be off/],
  ['break-glass webhook over plain http', (o) => ({ ...o, breakGlass: { url: 'http://hooks.example/break-glass', secret: 'c'.repeat(32) } }), /BREAK_GLASS_WEBHOOK must use https/],
  ['OTEL collector over plain http', (o) => ({ ...o, tracing: { endpoint: 'http://otel.example:4318' } }), /OTEL_EXPORTER_OTLP_ENDPOINT must use https/],
  ['native TLS without an https PUBLIC_ORIGIN', (o) => ({ ...o, publicOrigin: undefined, tls: { cert: 'c', key: 'k' } }), /PUBLIC_ORIGIN must be https/],
];
/** Checked against the credentials document once there is a database (databaseRoleFailures), not in the preflight. */
const DATABASE_CHECKED = 'password login without TOTP';

test('GATE_PROFILE: demo by default, production on request, anything else refused', () => {
  assert.equal(profileOf(undefined), 'demo');
  assert.equal(profileOf('demo'), 'demo');
  assert.equal(profileOf('production'), 'production');
  assert.throws(() => profileOf('prod'), /GATE_PROFILE must be demo or production/);
});

test('production preflight: a complete configuration passes, each missing item is named', (t) => {
  const base = good(t);
  assert.deepEqual(productionFailures(base, METRICS), []);
  assert.deepEqual(productionFailures({ ...base, tls: { cert: 'c', key: 'k' } }, METRICS), [], 'native TLS behind an https origin');
  assert.deepEqual(productionFailures({ ...base, sodHistory: undefined }, METRICS), [], 'server history is the default, not a required explicit setting');
  assert.equal(configurationBaseline({}).separationOfDuty, 'server');
  assert.deepEqual(productionFailures(base, undefined), ['METRICS_TOKEN must be set, at least 32 characters']);
  assert.deepEqual(productionFailures(base, 'x'.repeat(31)), ['METRICS_TOKEN must be set, at least 32 characters'], 'a short token is refused');
  assert.deepEqual(productionFailures({ ...base, tracing: { endpoint: 'http://127.0.0.1:4318' } }, METRICS), [], 'plain http on loopback stays allowed');
  assert.deepEqual(productionFailures({ ...base, breakGlass: { url: 'http://127.0.0.1:9/hook', secret: 'c'.repeat(32) } }, METRICS),
    ['BREAK_GLASS_WEBHOOK must use https'], 'the notifier refuses plain http even on loopback, so the profile says so');
  assert.deepEqual(productionFailures({ ...base, tracing: { endpoint: 'https://otel.example' } }, METRICS), []);
  for (const [name, change, expected] of missing.filter(([n]) => n !== DATABASE_CHECKED)) {
    const failures = productionFailures(change(base), METRICS);
    assert.ok(failures.some((f) => expected.test(f)), `${name}: ${failures.join(' | ')}`);
  }
  assert.ok(productionFailures({ ...base, tsa: { url: 'http://localhost:9/tsr', caFile: '/x' } }, METRICS)[0]?.startsWith('TSA_URL'));
  // with a database the accounts are in PostgreSQL: the preflight leaves them to the database check
  assert.deepEqual(productionFailures({ ...base, passwordLogin: true }, METRICS), []);
  assert.ok(productionFailures({ ...base, passwordLogin: true, databaseUrl: undefined }, METRICS).some((f) => /PASSWORD_LOGIN is on/.test(f)));
});

test('demo profile: loopback only unless DEMO_ALLOW_REMOTE, and /metrics needs METRICS_TOKEN on a non-loopback bind', async (t) => {
  const saved = process.env.METRICS_TOKEN;
  delete process.env.METRICS_TOKEN;
  t.after(() => { if (saved === undefined) delete process.env.METRICS_TOKEN; else process.env.METRICS_TOKEN = saved; });
  for (const h of ['127.0.0.1', '127.1.2.3', 'localhost', '::1', '[::1]']) assert.ok(isLoopbackHost(h), h);
  for (const h of ['0.0.0.0', '::', '10.0.0.1', '128.0.0.1', '127.example']) assert.ok(!isLoopbackHost(h), h);
  const dir = (): string => { const d = mkdtempSync('/tmp/pdp-demo-bind-'); t.after(() => rmSync(d, { recursive: true, force: true })); return d; };
  await assert.rejects(createServer({ dataDir: dir(), port: 0, host: '0.0.0.0' }).listen(), /DEMO_ALLOW_REMOTE=true/);
  const loopback = createServer({ dataDir: dir(), port: 0 });
  await loopback.listen(); t.after(() => loopback.close());
  assert.equal((await fetch(`${loopback.url}/metrics`)).status, 200, 'loopback demo keeps an open /metrics');
  const warnings: string[] = [];
  t.mock.method(console, 'warn', (m: string) => { warnings.push(m); });
  const remote = createServer({ dataDir: dir(), port: 0, host: '0.0.0.0', allowRemoteDemo: true });
  await remote.listen(); t.after(() => remote.close());
  assert.ok(warnings.some((w) => /^WARNING: DEMO_ALLOW_REMOTE=true/.test(w)));
  const local = remote.url.replace('0.0.0.0', '127.0.0.1');
  assert.equal((await fetch(`${local}/metrics`)).status, 403, 'never unauthenticated on a non-loopback bind');
  process.env.METRICS_TOKEN = 'm'.repeat(32);
  assert.equal((await fetch(`${local}/metrics`)).status, 401);
  assert.equal((await fetch(`${local}/metrics`, { headers: { authorization: `Bearer ${'m'.repeat(32)}` } })).status, 200);
});

test('production does not seed its first start from a world marked demo', (t) => {
  const d = mkdtempSync('/tmp/pdp-demo-world-'); t.after(() => rmSync(d, { recursive: true, force: true }));
  const world = resolve(import.meta.dirname, '../../../examples/toy-domain');
  assert.throws(() => new Store(d, world, FIXED, undefined, undefined, { refuseDemoWorld: true }), /WORLD_DIR .* is a demo world/);
  assert.ok(new Store(d, world, FIXED).state.subjects.length > 0, 'demo (and ALLOW_DEMO_WORLD) seed it as before');
});

test('production without a database refuses at once, listing every failure in one error', (t) => {
  const saved = process.env.METRICS_TOKEN;
  delete process.env.METRICS_TOKEN;
  t.after(() => { if (saved === undefined) delete process.env.METRICS_TOKEN; else process.env.METRICS_TOKEN = saved; });
  const dataDir = mkdtempSync('/tmp/pdp-profile-');
  t.after(() => rmSync(dataDir, { recursive: true, force: true }));
  assert.throws(() => createServer({ profile: 'production', dataDir, clock: 'fixed:2026-11-08T10:00:00Z' }), (err: Error) => {
    const lines = err.message.split('\n');
    assert.equal(lines[0], 'GATE_PROFILE=production refused to start:');
    for (const expected of [/PUBLIC_ORIGIN/, /OIDC_ISSUER/, /PASSWORD_LOGIN/, /DATABASE_URL/, /SIGNING_KEY_SEAL/, /METRICS_TOKEN/, /TSA_URL/, /CLOCK/, /BREAK_GLASS_WEBHOOK/, /BLP_SESSION_REQUIRED/]) {
      assert.equal(lines.filter((l) => expected.test(l)).length, 1, String(expected));
    }
    return true;
  });
  // demo keeps today's behaviour with the same settings
  const demo = createServer({ dataDir, clock: 'fixed:2026-11-08T10:00:00Z' });
  assert.equal(typeof demo.listen, 'function');
});

test('password login stays possible in production when every local account has active TOTP', async (t) => {
  const o = { ...good(t), passwordLogin: true, databaseUrl: undefined };
  const totpLine = (): string | undefined => productionFailures(o, METRICS).find((f) => /PASSWORD_LOGIN is on/.test(f));
  const audit = new Audit(resolve(o.dataDir!, 'audit.jsonl'), () => FIXED);
  const auth = new Auth(o.dataDir!, audit, () => FIXED, () => Date.parse(FIXED), { signingKeySeal: SEAL });
  const { passwords } = JSON.parse(readFileSync(resolve(o.dataDir!, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<string, string> };
  const ids = Object.keys(passwords);
  for (const [i, id] of ids.entries()) {
    const session = req({ cookie: `sid=${(await auth.login(id, passwords[id], `ip-${i}`)).sid}` });
    assert.ok(totpLine()?.includes(id));
    const key = fromBase32(new URL((await auth.enrolTotp(session, passwords[id])).otpauthUri).searchParams.get('secret')!);
    auth.activateTotp(session, hotp(key, Math.floor(Date.parse(FIXED) / 30_000)));
  }
  assert.equal(totpLine(), undefined);
});

/** A throwaway database with an owner role that migrates and a service role that only reads and appends. */
async function database(t: TestContext) {
  const tag = randomBytes(4).toString('hex');
  const name = `gate_profile_${tag}`, owner = `gp_owner_${tag}`, app = `gp_app_${tag}`, member = `gp_member_${tag}`;
  const password = randomBytes(12).toString('hex');
  const root = new pg.Client({ connectionString: admin }); await root.connect();
  await root.query(`CREATE DATABASE ${name}`);
  await root.query(`CREATE ROLE ${owner} NOLOGIN`);
  await root.query(`CREATE ROLE ${app} LOGIN PASSWORD '${password}'`);
  await root.query(`CREATE ROLE ${member} LOGIN PASSWORD '${password}' IN ROLE ${owner}`);
  await root.end();
  const url = (user?: string): string => {
    const u = new URL(admin!); u.pathname = `/${name}`;
    if (user) { u.username = user; u.password = password; }
    return u.toString();
  };
  t.after(async () => {
    const c = new pg.Client({ connectionString: admin }); await c.connect();
    await c.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
    for (const role of [member, app, owner]) await c.query(`DROP ROLE IF EXISTS ${role}`);
    await c.end();
  });
  const sql = async (text: string): Promise<pg.QueryResult> => {
    const c = new pg.Client({ connectionString: url() }); await c.connect();
    try { return await c.query(text); } finally { await c.end(); }
  };
  const migrate = async (): Promise<void> => {
    await sql(`GRANT CREATE ON SCHEMA public TO ${owner}; SET ROLE ${owner}; ${SCHEMA} RESET ROLE;
      ${serviceGrants(app)}`);
  };
  return { url, sql, migrate, app, member };
}

test('production checks the database role before migrating: superuser, owner and missing tables are refused', { skip }, async (t) => {
  const saved = process.env.METRICS_TOKEN;
  process.env.METRICS_TOKEN = METRICS;
  t.after(() => { if (saved === undefined) delete process.env.METRICS_TOKEN; else process.env.METRICS_TOKEN = saved; });
  const db = await database(t);
  // a superuser on an empty database: refused, and nothing was created under it
  await assert.rejects(createServer(good(t, db.url())).listen(), (err: Error) => /a superuser/.test(err.message) && /tables missing/.test(err.message));
  assert.equal((await db.sql(`SELECT to_regclass('gate_audit') AS t`)).rows[0].t, null);
  await db.migrate();
  assert.deepEqual(await databaseRoleFailures(db.url(db.app)), []);
  assert.deepEqual(await databaseRoleFailures(db.url()), ['DATABASE_URL role is (or is a member of) a superuser',
    'DATABASE_URL role has (or is a member of a role with) BYPASSRLS or CREATEROLE',
    'DATABASE_URL role owns (or is a member of the owner of) gate_doc, gate_audit, gate_audit_meta, gate_anchor, gate_audit_segment, gate_subject_identity, gate_sync, gate_token, gate_performed, gate_session, gate_blp_mark, gate_blp_session, gate_retired, gate_subject, gate_resource, gate_tuple, gate_state_change, gate_rate_limit',
    'DATABASE_URL role may UPDATE, DELETE or TRUNCATE gate_audit, gate_anchor, gate_audit_segment, gate_performed, gate_retired, gate_state_change']);
  assert.deepEqual(await databaseRoleFailures(db.url(db.member)), ['DATABASE_URL role owns (or is a member of the owner of) gate_doc, gate_audit, gate_audit_meta, gate_anchor, gate_audit_segment, gate_subject_identity, gate_sync, gate_token, gate_performed, gate_session, gate_blp_mark, gate_blp_session, gate_retired, gate_subject, gate_resource, gate_tuple, gate_state_change, gate_rate_limit']);
  // each privilege that lets the service role rewrite the audit or escape RLS is named, then taken back
  const tag = randomBytes(4).toString('hex');
  const elevated: Array<[string, string, RegExp]> = [
    [`GRANT UPDATE ON gate_audit TO ${db.app}`, `REVOKE UPDATE ON gate_audit FROM ${db.app}`, /may UPDATE, DELETE or TRUNCATE gate_audit$/],
    [`GRANT TRUNCATE ON gate_anchor TO ${db.app}`, `REVOKE TRUNCATE ON gate_anchor FROM ${db.app}`, /may UPDATE, DELETE or TRUNCATE gate_anchor$/],
    [`ALTER ROLE ${db.app} CREATEROLE`, `ALTER ROLE ${db.app} NOCREATEROLE`, /BYPASSRLS or CREATEROLE/],
    [`ALTER ROLE ${db.app} BYPASSRLS`, `ALTER ROLE ${db.app} NOBYPASSRLS`, /BYPASSRLS or CREATEROLE/],
    [`CREATE ROLE gp_super_${tag} SUPERUSER NOLOGIN; CREATE ROLE gp_mid_${tag} NOLOGIN IN ROLE gp_super_${tag}; GRANT gp_mid_${tag} TO ${db.app}`,
      `DROP ROLE gp_mid_${tag}; DROP ROLE gp_super_${tag}`, /a superuser/],
  ];
  for (const [grant, revoke, expected] of elevated) {
    await db.sql(grant);
    try { assert.ok((await databaseRoleFailures(db.url(db.app))).some((f) => expected.test(f)), grant); } finally { await db.sql(revoke); }
  }
  assert.deepEqual(await databaseRoleFailures(db.url(db.app)), []);
  const wrong = new URL(db.url(db.app)); wrong.password = 'not-the-password';
  assert.match((await databaseRoleFailures(wrong.toString()))[0]!, /^DATABASE_URL: the role could not be checked/);
  // every other requirement is still listed alongside the database ones
  // (a plain-http webhook and a dummy TLS key are refused by their own constructors before listen: preflight-only cases)
  const constructorChecked = ['no database', 'remote database TLS disabled', 'remote database TLS without hostname verification', 'break-glass webhook over plain http', 'native TLS without an https PUBLIC_ORIGIN'];
  for (const [name, change, expected] of missing.filter(([n]) => !constructorChecked.includes(n))) {
    await assert.rejects(createServer(change(good(t, db.url(db.member)))).listen(), (err: Error) => expected.test(err.message) && /owns/.test(err.message), name);
  }
  // the service role with everything set: the node starts and serves
  const server = createServer(good(t, db.url(db.app)));
  t.after(() => server.close());
  await server.listen();
  assert.equal((await fetch(`${server.url}/healthz`)).status, 200);
});

test('production password login reads TOTP enrolment from the PostgreSQL credentials document, not DATA_DIR', { skip }, async (t) => {
  const db = await database(t);
  await db.migrate();
  const dir = mkdtempSync('/tmp/pdp-profile-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const account = (id: string, active: boolean) => ({ id, name: id, roles: [], hash: 'x', ...(active ? { totp: { secret: 'v2.x', active: true } } : {}) });
  const store = async (users: unknown[]): Promise<void> => {
    await db.sql(`INSERT INTO gate_doc (name, body) VALUES ('credentials', '${JSON.stringify({ users, pepCredentials: [] })}')
      ON CONFLICT (name) DO UPDATE SET body = EXCLUDED.body`);
  };
  const totpLine = async (): Promise<string | undefined> => (await databaseRoleFailures(db.url(db.app), dir)).find((f) => /PASSWORD_LOGIN/.test(f));
  // nothing stored yet and no file to import: the first start would create the demo accounts without TOTP
  assert.match(String(await totpLine()), /amira, omar, lina, ruth, sam/);
  // a stale DATA_DIR file claiming TOTP everywhere does not count once the document exists
  writeFileSync(resolve(dir, 'credentials.json'), JSON.stringify({ users: [account('amira', true), account('omar', true)], pepCredentials: [] }));
  await store([account('amira', true), account('omar', false)]);
  assert.match(String(await totpLine()), /no active TOTP: omar \(/);
  await store([account('amira', true), account('omar', true)]);
  assert.equal(await totpLine(), undefined);
  assert.deepEqual(await databaseRoleFailures(db.url(db.app)), [], 'without password login the document is not read');
});

test('ALLOW_DEMO_WORLD in the production profile is a warning of the configuration baseline', () => {
  assert.deepEqual(configurationBaseline({ profile: 'production', allowDemoWorld: true }).warnings, [DEMO_WORLD_WARNING]);
  assert.deepEqual(configurationBaseline({ profile: 'demo', allowDemoWorld: true }).warnings, []);
  assert.equal(configurationBaseline({}).demoWorldAllowed, false);
});
