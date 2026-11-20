// Console sessions shared through PostgreSQL (gate_session): failover keeps them, logout and expiry hold on every node,
// only the hash of the session id is stored and the CSRF token is derived. The unit half runs without a database.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { Audit } from '../src/audit.ts';
import { Auth, sessionKey, type Session, type SessionTable } from '../src/auth.ts';
import { HttpError } from '../src/http.ts';
import { createServer, type PdpServer } from '../src/server.ts';
import { PgLedger } from '../src/postgres.ts';
import { FIXED, req } from './helpers.ts';
import { skip, throwawayDatabase } from './pg-database.ts';

const status = (code: number) => (err: unknown): boolean => err instanceof HttpError && err.status === code;
const SEAL = randomBytes(32).toString('base64url');
const MINUTE = 60_000;

/** The SessionTable contract over a Map, as gate_session behaves (touch never recreates a row). */
function memoryTable(): SessionTable & { rows: Map<string, Session>; ops: string[] } {
  const rows = new Map<string, Session>(); const ops: string[] = [];
  return {
    rows, ops,
    load: async (keys) => keys.flatMap((k): Array<[string, Session]> => { const s = rows.get(k); return s ? [[k, structuredClone(s)]] : []; }),
    insert: (k, s) => { ops.push('insert'); rows.set(k, structuredClone(s)); },
    touch: (k, at) => { ops.push('touch'); const s = rows.get(k); if (s && s.touched < at) rows.set(k, { ...s, touched: at }); },
    remove: (k) => { ops.push('remove'); rows.delete(k); },
    purge: (touchedBefore, createdBefore) => { ops.push('purge'); for (const [k, s] of rows) if (s.touched <= touchedBefore || s.created <= createdBefore) rows.delete(k); },
    endOidc: async ({ sub, sid }, method = 'oidc') => {
      const ended = [...rows].filter(([, s]) => s.oidc && s.method === method && (sid && s.oidc.sid ? s.oidc.sid === sid && (!sub || s.oidc.sub === sub) : s.oidc.sub === sub)).map(([k]) => k);
      for (const k of ended) rows.delete(k);
      return ended;
    },
  };
}

test('a shared session table: two runtimes share sessions; only the id hash is stored; touches at most once a minute; logout and real-time expiry propagate', async (t) => {
  const dir = mkdtempSync('/tmp/pdp-sessions-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const audit = new Audit(resolve(dir, 'audit.jsonl'), () => FIXED);
  let ms = Date.parse(FIXED);
  const table = memoryTable();
  const a = new Auth(dir, audit, () => FIXED, () => ms, { sessions: table });
  const { passwords } = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<'amira' | 'omar' | 'lina' | 'ruth' | 'sam', string> };
  const b = new Auth(dir, audit, () => FIXED, () => ms, { sessions: table }); // the node that takes over

  const login = await a.login('amira', passwords.amira, 'ip');
  const cookie = { cookie: `sid=${login.sid}`, 'x-csrf-token': login.csrfToken };
  assert.deepEqual([...table.rows.keys()], [createHash('sha256').update(login.sid).digest('hex')], 'stored under the SHA-256 of the id');
  const stored = JSON.stringify([...table.rows]);
  assert.ok(!stored.includes(login.sid) && !stored.includes(login.csrfToken), 'neither the session id nor the CSRF token is stored');

  assert.throws(() => b.session(req(cookie), false), status(401), 'nothing is known before the lookup');
  await b.load(req(cookie));
  assert.equal(b.session(req(cookie), true).csrfToken, login.csrfToken, 'the other runtime derives the same CSRF token');
  assert.throws(() => b.session(req({ cookie: cookie.cookie, 'x-csrf-token': 'forged' }), true), status(403));

  table.ops.length = 0;
  ms += 30_000; await b.load(req(cookie)); b.session(req(cookie), false);
  assert.deepEqual(table.ops, [], 'no write within a minute of the last one');
  ms += 31_000; await b.load(req(cookie)); b.session(req(cookie), false);
  assert.deepEqual(table.ops, ['touch']);
  assert.equal(table.rows.get(sessionKey(login.sid))?.touched, ms);

  b.logout(req(cookie), 'amira');
  await a.load(req(cookie));
  assert.throws(() => a.session(req(cookie), false), status(401), 'a logout on one runtime holds on the other');

  const idle = await a.login('omar', passwords.omar, 'ip');
  ms += 15 * MINUTE; await b.load(req({ cookie: `sid=${idle.sid}` }));
  assert.throws(() => b.session(req({ cookie: `sid=${idle.sid}` }), false), status(401), 'idle for 15 minutes of real time');
  const kept = await a.login('lina', passwords.lina, 'ip');
  for (let i = 0; i < 47; i++) { ms += 10 * MINUTE; await a.load(req({ cookie: `sid=${kept.sid}` })); a.session(req({ cookie: `sid=${kept.sid}` }), false); }
  ms += 10 * MINUTE; await a.load(req({ cookie: `sid=${kept.sid}` }));
  assert.throws(() => a.session(req({ cookie: `sid=${kept.sid}` }), false), status(401), '8 hours after sign-in, however active');
  await a.login('sam', passwords.sam, 'ip');
  assert.equal(table.rows.size, 1, 'a sign-in purges the expired rows');

  a.issue({ id: 'u1', name: 'u1', roles: ['auditor'] }, 'oidc', { sub: 'u1', sid: 'idp-1' });
  a.issue({ id: 'u1', name: 'u1', roles: ['auditor'] }, 'oidc', { sub: 'u1' });
  assert.equal(await b.endOidcSessions({ sub: 'u1', sid: 'idp-1' }), 2, 'back-channel logout ends the stored sessions');
  assert.equal(table.rows.size, 1);
  const actions = audit.records().filter((r) => r.type === 'session').map((r) => r.action);
  assert.ok(actions.includes('login') && actions.includes('logout'), 'sign-in and logout are audited as before');
});

async function consoleClient(server: PdpServer) {
  const call = async (path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; data: Record<string, unknown> }> => {
    const res = await fetch(`${server.url}${path}`, { method, headers: { 'content-type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const text = await res.text();
    return { status: res.status, data: text ? JSON.parse(text) as Record<string, unknown> : {} };
  };
  const login = async (id: string, password: string): Promise<{ cookie: string; 'x-csrf-token': string; sid: string }> => {
    const res = await fetch(`${server.url}/admin/v1/session`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: id, password }) });
    assert.equal(res.status, 200);
    const cookie = String(res.headers.get('set-cookie')).split(';')[0]!;
    return { cookie, 'x-csrf-token': String((await res.json() as { csrfToken: string }).csrfToken), sid: cookie.slice(4) };
  };
  return { call, login };
}

test('PostgreSQL: a console session survives failover to the standby; logout, expiry and purge hold on the next leader', { skip, timeout: 120_000 }, async (t) => {
  const { url, sql } = await throwawayDatabase(t, 'gate_sessions');
  const dir = mkdtempSync('/tmp/pdp-sessions-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const options = { port: 0, dataDir: dir, databaseUrl: url, signingKeySeal: SEAL };
  const a = createServer(options); await a.listen(); t.after(() => a.close());
  const { passwords } = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<'amira' | 'omar' | 'lina' | 'ruth' | 'sam', string> };
  const ca = await consoleClient(a);
  const first = await ca.login('amira', passwords.amira);
  const second = await ca.login('sam', passwords.sam);
  const rows = (await sql('SELECT id, body FROM gate_session ORDER BY id')).rows as Array<{ id: string; body: string }>;
  assert.deepEqual(rows.map((r) => r.id), [sessionKey(first.sid), sessionKey(second.sid)].sort());
  assert.ok(rows.every((r) => !r.body.includes(first.sid) && !r.body.includes(first['x-csrf-token'])), 'no session id or CSRF token in the table');

  // the standby takes over: the sessions opened on A hold on B
  const b = createServer(options); const bUp = b.listen(); t.after(() => b.close());
  await a.close(); await bUp;
  const cb = await consoleClient(b);
  const kept = await cb.call('/admin/v1/session', 'GET', undefined, { cookie: first.cookie });
  assert.equal(kept.status, 200);
  assert.equal(kept.data.csrfToken, first['x-csrf-token'], 'the CSRF token is the same on the new leader');
  assert.equal((await cb.call('/admin/v1/session/totp', 'GET', undefined, first)).status, 200);

  // touches: at most once a minute, written with the request's commit
  const touched = async (sid: string): Promise<{ created: number; touched: number }> => {
    const row = (await sql('SELECT created, touched FROM gate_session WHERE id = $1', [sessionKey(sid)])).rows[0] as { created: string; touched: string };
    return { created: Number(row.created), touched: Number(row.touched) };
  };
  const before = await touched(second.sid);
  await cb.call('/admin/v1/session/totp', 'GET', undefined, second);
  assert.deepEqual(await touched(second.sid), before, 'no write within a minute');
  await sql('UPDATE gate_session SET created = created - 120000, touched = touched - 120000 WHERE id = $1', [sessionKey(second.sid)]);
  await cb.call('/admin/v1/session/totp', 'GET', undefined, second);
  const after = await touched(second.sid);
  assert.ok(after.touched > before.touched - 120_000 + 60_000, 'touched moves forward after a minute');

  // logout on B, real-time expiry by the stored timestamps
  assert.equal((await cb.call('/admin/v1/session', 'DELETE', undefined, first)).status, 204);
  assert.equal((await sql('SELECT count(*) AS n FROM gate_session WHERE id = $1', [sessionKey(first.sid)])).rows[0].n, '0', 'logout deletes the row');
  const idle = await cb.login('omar', passwords.omar);
  const old = await cb.login('lina', passwords.lina);
  await sql('UPDATE gate_session SET touched = touched - 16 * 60000 WHERE id = $1', [sessionKey(idle.sid)]);
  await sql('UPDATE gate_session SET created = created - 8 * 3600000 WHERE id = $1', [sessionKey(old.sid)]);

  const c = createServer(options); const cUp = c.listen(); t.after(() => c.close());
  await b.close(); await cUp;
  const cc = await consoleClient(c);
  assert.equal((await cc.call('/admin/v1/session', 'GET', undefined, { cookie: first.cookie })).status, 401, 'logged out on B, out on C');
  assert.equal((await cc.call('/admin/v1/session', 'GET', undefined, { cookie: idle.cookie })).status, 401, 'idle for 16 minutes');
  assert.equal((await cc.call('/admin/v1/session', 'GET', undefined, { cookie: old.cookie })).status, 401, 'older than 8 hours');
  assert.equal((await cc.call('/admin/v1/session', 'GET', undefined, { cookie: second.cookie })).status, 200);
  const ruth = await cc.login('ruth', passwords.ruth);
  const left = (await sql('SELECT id FROM gate_session')).rows.map((r: { id: string }) => r.id).sort();
  assert.deepEqual(left, [sessionKey(second.sid), sessionKey(ruth.sid)].sort(), 'a sign-in purges the expired rows: sam and ruth remain');
  const audited = (await sql(`SELECT record FROM gate_audit WHERE record LIKE '%"type":"session"%'`)).rows.map((r: { record: string }) => JSON.parse(r.record) as { action: string });
  assert.ok(audited.some((r) => r.action === 'logout') && audited.filter((r) => r.action === 'login').length >= 5, 'sessions are audited as before');
  assert.ok(!JSON.stringify(audited).includes(first.sid));
  await c.close(); // before the database is dropped
});

test('PostgreSQL: back-channel logout ends stored OIDC sessions by IdP sid, or by sub when a session has none', { skip, timeout: 60_000 }, async (t) => {
  const { url } = await throwawayDatabase(t, 'gate_sessions_oidc');
  const ledger = await PgLedger.open(url, () => undefined);
  try {
  const table = ledger.sessionTable();
  const at = Date.now();
  const user = { id: 'u', name: 'u', roles: ['auditor'] };
  table.insert('k1', { user, created: at, touched: at, method: 'oidc', oidc: { sub: 'u1', sid: 's1' } });
  table.insert('k2', { user, created: at, touched: at, method: 'oidc', oidc: { sub: 'u1' } });
  table.insert('k3', { user, created: at, touched: at, method: 'oidc', oidc: { sub: 'u2', sid: 's1' } });
  table.insert('k4', { user, created: at, touched: at, method: 'password' });
  // a SAML session (NameID, SessionIndex) is ended only by a SAML logout, even with the same ids
  table.insert('k5', { user, created: at, touched: at, method: 'saml', oidc: { sub: 'u1', sid: 's1' } });
  await ledger.commit();
  assert.deepEqual((await table.endOidc({ sub: 'u1', sid: 's1' })).sort(), ['k1', 'k2']);
  assert.deepEqual(await table.endOidc({ sub: 'u1', sid: 's1' }, 'saml'), ['k5']);
  assert.deepEqual(await table.endOidc({ sid: 's1' }), ['k3']);
  assert.deepEqual(await table.endOidc({ sub: 'nobody' }), []);
  const left = await table.load(['k1', 'k2', 'k3', 'k4']);
  assert.deepEqual(left.map(([k]) => k), ['k4']);
  assert.deepEqual(left[0]![1], { user, created: at, touched: at, method: 'password' });
  } finally { await ledger.close(); }
});

test('PostgreSQL SAML logout revokes cookie and CSRF authority in another runtime', { skip, timeout: 60_000 }, async (t) => {
  const { url } = await throwawayDatabase(t, 'gate_sessions_saml');
  const ledger = await PgLedger.open(url, () => undefined);
  const dir = mkdtempSync('/tmp/gate-saml-sessions-');
  try {
    const audit = new Audit(resolve(dir, 'audit.jsonl'), () => FIXED);
    const options = { sessions: ledger.sessionTable() };
    const a = new Auth(dir, audit, () => FIXED, Date.now, options);
    const b = new Auth(dir, audit, () => FIXED, Date.now, options);
    const user = { id: 'omar', name: 'Omar', roles: ['approver'] };
    const opened = a.issue(user, 'saml', { sub: 'name-id', sid: 'session-index', nameIDFormat: 'persistent' });
    const other = a.issue(user, 'oidc', { sub: 'name-id', sid: 'session-index' });
    await ledger.commit();
    const request = req({ cookie: `sid=${opened.sid}`, 'x-csrf-token': opened.csrfToken });
    await b.load(request);
    assert.equal(b.session(request, true).user.id, 'omar');
    assert.equal(b.samlTarget(request)?.nameIDFormat, 'persistent');
    assert.equal(await a.endOidcSessions({ sub: 'name-id', sid: 'session-index' }, 'saml'), 1);
    await b.load(request);
    assert.throws(() => b.session(request, false), status(401));
    assert.throws(() => b.session(request, true), status(401), 'the old CSRF token grants no authority');
    const unrelated = req({ cookie: `sid=${other.sid}`, 'x-csrf-token': other.csrfToken });
    await b.load(unrelated);
    assert.equal(b.session(unrelated, true).user.id, 'omar');
  } finally { await ledger.close(); rmSync(dir, { recursive: true, force: true }); }
});
