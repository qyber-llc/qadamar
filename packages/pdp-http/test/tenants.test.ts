import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { request } from 'node:http';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { createServer, type PdpServer, type ServerOptions } from '../src/server.ts';
import { createTenantServer, tenantManifest, tenantSelection, tenantConfigFromEnv } from '../src/tenants.ts';
import { signHop } from '../src/forward.ts';
import { hopKeyOf, REPLICA_HOP_HEADER } from '../src/replica-protocol.ts';
import { evaluation, FIXED, WHY } from './helpers.ts';
import { skip, throwawayDatabase } from './pg-database.ts';

function directory(t: TestContext): string {
  const dir = mkdtempSync('/tmp/gate-tenants-');
  t.after(() => rmSync(dir, { recursive: true, force: true })); return dir;
}
const options: ServerOptions = { port: 0, clock: `fixed:${FIXED}`, rateLimit: 100000, pepRateLimit: 100000 };
function manifest(dir: string, extras: Record<string, Partial<Omit<ServerOptions, 'replicaKeys' | 'replicaPins'>> & { replicaKeys?: string; replicaPins?: string }> = {}): Map<string, ServerOptions> {
  return tenantManifest(JSON.stringify(Object.fromEntries(['alpha', 'beta'].map((id) => [id, {
    dataDir: resolve(dir, id), worldDir: 'examples/toy-domain', ...extras[id],
  }]))));
}
const key = (dir: string): string => (JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string }).pepApiKey;
async function call(server: PdpServer, tenant: string | undefined, path = '/access/v1/evaluation', value: unknown = evaluation(), secret?: string) {
  const response = await fetch(server.url + path, { method: 'POST', headers: { 'content-type': 'application/json',
    ...(tenant === undefined ? {} : { 'x-gate-tenant': tenant }), ...(secret ? { authorization: `Bearer ${secret}` } : {}) }, body: JSON.stringify(value) });
  return { status: response.status, data: await response.json() };
}
const paths: Array<[string, unknown]> = [
  ['/access/v1/evaluation', evaluation()],
  ['/access/v1/evaluation', evaluation('bob', 'CASE-14', 'write')],
  ['/access/v1/evaluations', { evaluations: [evaluation(), evaluation('alice')] }],
  ['/access/v1/search/resource', { subject: { type: 'user', id: 'bob' }, action: { name: 'read' }, resource: { type: 'case' } }],
  ['/access/v1/search/subject', { subject: { type: 'user' }, action: { name: 'read' }, resource: { type: 'case', id: 'CASE-14' } }],
  ['/x/v1/filter', { subject: { type: 'user', id: 'bob' }, action: { name: 'read' }, resource: { type: 'case' }, columns: { 'resource.level': { column: 'level', type: 'number' }, 'resource.compartments': { column: 'compartments', kind: 'text[]' }, 'resource.id': 'id' } }],
];
async function equalResults(a: PdpServer, b: PdpServer, secret: string, tenant?: string, partitionSecret = secret): Promise<void> {
  for (const [path, body] of paths) {
    const expected = await call(a, tenant, path, body, secret);
    assert.equal(expected.status, 200, `${path}: ${JSON.stringify(expected.data)}`);
    assert.deepEqual(await call(b, 'alpha', path, body, partitionSecret), expected, path);
  }
}

test('tenant selection and manifest reject malformed or overlapping namespaces without reporting secrets', () => {
  const base = { alpha: { dataDir: '/tmp/a', worldDir: 'examples/toy-domain' }, beta: { dataDir: '/tmp/b', worldDir: 'examples/toy-domain' } };
  assert.equal(tenantManifest(JSON.stringify(base)).size, 2);
  assert.deepEqual(tenantSelection(undefined, ['alpha', 'beta']), ['alpha', 'beta']);
  assert.deepEqual(tenantSelection(' alpha ', ['alpha']), ['alpha']);
  for (const value of ['', 'alpha,alpha', 'other', 'Alpha', 'alpha,']) assert.throws(() => tenantSelection(value, ['alpha']));
  for (const value of ['bad', '[]', '{}', 'null', '{"ALPHA":{}}', '{"alpha":{}}']) assert.throws(() => tenantManifest(value));
  assert.throws(() => tenantManifest(JSON.stringify({ alpha: { ...base.alpha, unknown: 'secret' } })), /field/);
  assert.throws(() => tenantManifest(JSON.stringify({ alpha: { ...base.alpha, worldDir: 1 } })), /field/);
  assert.throws(() => tenantManifest(JSON.stringify({ ...base, beta: { ...base.beta, dataDir: '/tmp/a/sub' } })), /overlap/);
  const seal = randomBytes(32).toString('hex');
  const db = { databaseUrl: 'postgres://user:secret@localhost/alpha', signingKeySeal: seal };
  assert.throws(() => tenantManifest(JSON.stringify({ alpha: { ...base.alpha, databaseUrl: 'secret' } })), /Invalid tenant database URL/);
  assert.throws(() => tenantManifest(JSON.stringify({ alpha: { ...base.alpha, databaseUrl: db.databaseUrl } })), /signingKeySeal/);
  assert.throws(() => tenantManifest(JSON.stringify({ alpha: { ...base.alpha, ...db }, beta: { ...base.beta, ...db } })), /separate databases/);
  assert.throws(() => tenantManifest(JSON.stringify({ alpha: { ...base.alpha, ...db }, beta: { ...base.beta, signingKeySeal: seal } })), /distinct/);
  assert.equal(tenantConfigFromEnv({}), undefined);
  assert.throws(() => tenantConfigFromEnv({ GATE_SERVE_TENANTS: 'alpha' }), /needs/);
});

test('a partition opens only selected worlds; decisions, searches and filters equal the standalone engine', async (t) => {
  const dir = directory(t);
  const tenants = manifest(dir);
  const file = resolve(dir, 'tenants.json');
  writeFileSync(file, JSON.stringify(Object.fromEntries(tenants)));
  assert.deepEqual(tenantConfigFromEnv({ GATE_TENANTS_FILE: file, GATE_SERVE_TENANTS: 'alpha' })?.selected, ['alpha']);
  symlinkSync(resolve(dir, 'alpha'), resolve(dir, 'alias'));
  assert.throws(() => tenantManifest(JSON.stringify({ alpha: tenants.get('alpha'), beta: { ...tenants.get('beta'), dataDir: resolve(dir, 'alias') } })), /overlap/);
  const partition = createTenantServer(options, tenants, ['alpha']);
  await partition.listen(); t.after(() => partition.close());
  assert.equal(existsSync(resolve(dir, 'beta')), false);
  for (const tenant of ['beta', 'other']) {
    const refused = await call(partition, tenant);
    assert.equal(refused.status, 421); assert.equal(refused.data.error, 'tenant_not_served');
  }
  assert.equal((await call(partition, undefined)).status, 400);
  assert.equal((await call(partition, 'Alpha')).status, 400);
  assert.throws(() => tenantManifest(JSON.stringify({ alpha: tenants.get('alpha'), beta: { ...tenants.get('beta'), dataDir: resolve(dir, 'alias') } })), /overlap/);
  const duplicate = await new Promise<number>((done, fail) => {
    const req = request(partition.url, { headers: { 'x-gate-tenant': ['alpha', 'alpha'] } }, (res) => { res.resume(); res.on('end', () => done(res.statusCode!)); });
    req.on('error', fail); req.end();
  });
  assert.equal(duplicate, 400);
  const standaloneDir = resolve(dir, 'standalone');
  const standalone = createServer({ ...options, worldDir: 'examples/toy-domain', dataDir: standaloneDir });
  await standalone.listen(); t.after(() => standalone.close());
  await equalResults(standalone, partition, key(standaloneDir), undefined, key(resolve(dir, 'alpha')));
  await partition.anchor(); await partition.exportAudit(); await partition.notifyExpired(); await partition.flushTraces();
});

test('tenant credentials, local audit and rate budgets stay isolated', async (t) => {
  const dir = directory(t);
  const partition = createTenantServer({ ...options, pepRateLimit: 1 }, manifest(dir), ['alpha', 'beta']);
  await partition.listen(); t.after(() => partition.close());
  const alpha = key(resolve(dir, 'alpha')), beta = key(resolve(dir, 'beta'));
  assert.equal((await call(partition, 'alpha', undefined, undefined, alpha)).status, 200);
  assert.equal((await call(partition, 'alpha', undefined, undefined, alpha)).status, 429);
  assert.equal((await call(partition, 'beta', undefined, undefined, beta)).status, 200);
  assert.ok(existsSync(resolve(dir, 'alpha/audit.jsonl'))); assert.ok(existsSync(resolve(dir, 'beta/audit.jsonl')));
});

test('credentials from another tenant are refused', async (t) => {
  const dir = directory(t);
  const partition = createTenantServer(options, manifest(dir), ['alpha', 'beta']);
  await partition.listen(); t.after(() => partition.close());
  assert.equal((await call(partition, 'beta', undefined, undefined, key(resolve(dir, 'alpha')))).status, 401);
});

test('partition startup failure releases already opened runtimes', async (t) => {
  const dir = directory(t);
  const tenants = manifest(dir, { beta: { worldDir: resolve(dir, 'absent') } });
  const partition = createTenantServer(options, tenants, ['alpha', 'beta']);
  await assert.rejects(partition.listen()); await partition.close();
});

test('PostgreSQL cluster partitions match all-tenant nodes and preserve per-tenant chains and budgets', { skip }, async (t) => {
  const servers: PdpServer[] = [];
  t.after(async () => { for (const server of servers.reverse()) await server.close(); });
  const alpha = await throwawayDatabase(t, 'tenant_alpha'), beta = await throwawayDatabase(t, 'tenant_beta');
  const dir = directory(t);
  const dbOptions = { alpha: { databaseUrl: alpha.url, signingKeySeal: randomBytes(32).toString('hex') }, beta: { databaseUrl: beta.url, signingKeySeal: randomBytes(32).toString('hex') } };
  const all = createTenantServer({ ...options, cluster: true, nodeId: 'all' }, manifest(resolve(dir, 'all'), dbOptions), ['alpha', 'beta']);
  await all.listen(); servers.push(all);
  const part = createTenantServer({ ...options, cluster: true, nodeId: 'part' }, manifest(resolve(dir, 'part'), dbOptions), ['alpha']);
  await part.listen(); servers.push(part);
  assert.equal(existsSync(resolve(dir, 'part/beta')), false);
  await equalResults(all, part, key(resolve(dir, 'all/alpha')), 'alpha');
  assert.equal((await call(part, 'beta')).status, 421);
  assert.ok(Number((await alpha.sql("SELECT count(*) AS n FROM gate_audit WHERE node='part'")).rows[0].n) > 0);
  assert.equal(Number((await beta.sql("SELECT count(*) AS n FROM gate_audit WHERE node='part'")).rows[0].n), 0);
  await equalSqlResults(all, part, key(resolve(dir, 'all/alpha')), alpha.sql);
  const secret = key(resolve(dir, 'all/alpha'));
  await disableBob(all, resolve(dir, 'all/alpha'));
  await eventually(async () => (await call(part, 'alpha', undefined, evaluation(), secret)).data.decision === false);
  await equalResults(all, part, secret, 'alpha');
  await equalSqlResults(all, part, secret, alpha.sql);
});

async function disableBob(server: PdpServer, dir: string): Promise<void> {
  const passwords = (JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<string, string> }).passwords;
  const adminCall = async (path: string, value: unknown, headers: Record<string, string> = {}) => {
    const response = await fetch(server.url + path, { method: 'POST', headers: { 'content-type': 'application/json', 'x-gate-tenant': 'alpha', ...headers }, body: JSON.stringify(value) });
    return { status: response.status, data: await response.json(), headers: response.headers };
  };
  const login = async (id: string) => {
    const response = await adminCall('/admin/v1/session', { username: id, password: passwords[id] });
    assert.equal(response.status, 200);
    return { cookie: response.headers.get('set-cookie')!.split(';')[0]!, 'x-csrf-token': response.data.csrfToken as string };
  };
  const proposed = await adminCall('/admin/v1/changes', { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY }, await login('amira'));
  assert.equal(proposed.status, 201);
  assert.equal((await adminCall(`/admin/v1/changes/${proposed.data.id}/approve`, { reason: WHY }, await login('omar'))).status, 200);
}

async function eventually(check: () => Promise<boolean>): Promise<void> {
  const deadline = performance.now() + 5000;
  while (!await check()) {
    assert.ok(performance.now() < deadline, 'partition did not converge');
    await new Promise((done) => setTimeout(done, 20));
  }
}

test('partitioned replicas receive only their tenant feed, forward mutations and ship the correct audit chain', { skip }, async (t) => {
  const servers: PdpServer[] = [];
  t.after(async () => { for (const server of servers.reverse()) await server.close(); });
  const alpha = await throwawayDatabase(t, 'replica_alpha'), beta = await throwawayDatabase(t, 'replica_beta');
  const dir = directory(t);
  const ka = randomBytes(32).toString('hex'), kb = randomBytes(32).toString('hex');
  const source = createTenantServer({ ...options, cluster: true, nodeId: 'db' }, manifest(resolve(dir, 'source'), {
    alpha: { databaseUrl: alpha.url, signingKeySeal: randomBytes(32).toString('hex'), replicaKeys: `r1=${ka}` },
    beta: { databaseUrl: beta.url, signingKeySeal: randomBytes(32).toString('hex'), replicaKeys: `r1=${kb}` },
  }), ['alpha', 'beta']);
  await source.listen(); servers.push(source);
  const keys = await fetch(source.url + '/.well-known/jwks.json', { headers: { 'x-gate-tenant': 'alpha' } }).then((r) => r.json());
  const replica = createTenantServer({ ...options, nodeId: 'r1' }, manifest(resolve(dir, 'replica'), {
    alpha: { replicaOf: source.url, replicaKey: ka, replicaPins: keys.keys.map((k: { x: string }) => k.x).join(',') },
    beta: { replicaOf: source.url, replicaKey: kb },
  }), ['alpha']);
  await replica.listen(); servers.push(replica);
  assert.equal(existsSync(resolve(dir, 'replica/beta')), false);
  const secret = key(resolve(dir, 'source/alpha'));
  await equalResults(source, replica, secret, 'alpha');
  await eventually(async () => Number((await alpha.sql("SELECT count(*) AS n FROM gate_audit WHERE node='r1'")).rows[0].n) > 0);
  assert.equal(Number((await beta.sql("SELECT count(*) AS n FROM gate_audit WHERE node='r1'")).rows[0].n), 0);
  // An admin request passes through the replica with its tenant header and existing hop authentication.
  await disableBob(replica, resolve(dir, 'source/alpha'));
  await eventually(async () => (await call(replica, 'alpha', undefined, evaluation(), secret)).data.decision === false);
  await equalResults(source, replica, secret, 'alpha');
  assert.equal((await call(source, 'beta', undefined, evaluation(), key(resolve(dir, 'source/beta')))).data.decision, true);
});

async function equalSqlResults(all: PdpServer, part: PdpServer, secret: string, sql: Awaited<ReturnType<typeof throwawayDatabase>>['sql']): Promise<void> {
  const request = paths.find(([path]) => path === '/x/v1/filter')![1];
  const results = [];
  for (const server of [all, part]) {
    const response = await call(server, 'alpha', '/x/v1/filter', request, secret);
    assert.equal(response.status, 200);
    const compiled = response.data.sql as { text: string; params: unknown[] };
    const rows = await sql(`WITH cases AS (SELECT body::jsonb->>'id' AS id, (body::jsonb->>'level')::numeric AS level,
      ARRAY(SELECT jsonb_array_elements_text(body::jsonb->'compartments')) AS compartments FROM gate_resource WHERE type='case')
      SELECT id FROM cases WHERE ${compiled.text} ORDER BY id`, compiled.params);
    results.push(rows.rows);
  }
  assert.deepEqual(results[0], results[1]);
}

test('PostgreSQL rate leases are shared within a tenant and independent across tenants', { skip }, async (t) => {
  const servers: PdpServer[] = [];
  t.after(async () => { for (const server of servers.reverse()) await server.close(); });
  const alpha = await throwawayDatabase(t, 'budget_alpha'), beta = await throwawayDatabase(t, 'budget_beta');
  const dir = directory(t);
  const config = { alpha: { databaseUrl: alpha.url, signingKeySeal: randomBytes(32).toString('hex') }, beta: { databaseUrl: beta.url, signingKeySeal: randomBytes(32).toString('hex') } };
  const limited = { ...options, cluster: true, pepRateLimit: 1 };
  const all = createTenantServer({ ...limited, nodeId: 'all' }, manifest(resolve(dir, 'all'), config), ['alpha', 'beta']);
  await all.listen(); servers.push(all);
  const part = createTenantServer({ ...limited, nodeId: 'part' }, manifest(resolve(dir, 'part'), config), ['alpha']);
  await part.listen(); servers.push(part);
  const secret = key(resolve(dir, 'all/alpha'));
  assert.equal((await call(all, 'alpha', undefined, evaluation(), secret)).status, 200);
  assert.equal((await call(part, 'alpha', undefined, evaluation(), secret)).status, 429);
  assert.equal((await call(all, 'beta', undefined, evaluation(), key(resolve(dir, 'all/beta')))).status, 200);
});

test('memory benchmark reports real samples and selected-world index cardinalities', () => {
  const result = spawnSync(process.execPath, ['scripts/bench/memory.ts', '100'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const [machine, full, partition] = result.stdout.trim().split('\n').map((line) => JSON.parse(line));
  assert.equal(machine.node, process.version);
  assert.equal(full.loadedPerKind, 100); assert.equal(partition.loadedPerKind, 10);
  assert.equal(full.relationObjectKeys, 100); assert.equal(partition.relationSubjectKeys, 10);
  for (const row of [full, partition]) {
    assert.ok(row.baseline.rss > 0 && row.loaded.heapUsed > 0 && row.indexed.rss > 0);
    assert.ok(Number.isFinite(row.indexHeapBytes));
  }
  assert.notEqual(spawnSync(process.execPath, ['scripts/bench/memory.ts', '0'], { encoding: 'utf8' }).status, 0);
});


test('session revocation stays tenant-local and its signed replica feed carries only that tenant tombstone', { skip, timeout: 60_000 }, async (t) => {
  const servers: PdpServer[] = [];
  t.after(async () => { for (const server of servers.reverse()) await server.close(); });
  const alpha = await throwawayDatabase(t, 'tenant_revocation_alpha'), beta = await throwawayDatabase(t, 'tenant_revocation_beta');
  const dir = directory(t);
  const ka = randomBytes(32).toString('hex'), kb = randomBytes(32).toString('hex');
  const source = createTenantServer({ ...options, cluster: true, nodeId: 'db' }, manifest(resolve(dir, 'source'), {
    alpha: { databaseUrl: alpha.url, signingKeySeal: randomBytes(32).toString('hex'), replicaKeys: `r1=${ka}` },
    beta: { databaseUrl: beta.url, signingKeySeal: randomBytes(32).toString('hex'), replicaKeys: `r1=${kb}` },
  }), ['alpha', 'beta']);
  await source.listen(); servers.push(source);
  const keys = await fetch(source.url + '/.well-known/jwks.json', { headers: { 'x-gate-tenant': 'alpha' } }).then((r) => r.json()) as { keys: Array<{ x: string }> };
  const replica = createTenantServer({ ...options, nodeId: 'r1' }, manifest(resolve(dir, 'replica'), {
    alpha: { replicaOf: source.url, replicaKey: ka, replicaPins: keys.keys.map((k) => k.x).join(',') },
    beta: { replicaOf: source.url, replicaKey: kb },
  }), ['alpha']);
  await replica.listen(); servers.push(replica);

  const open = async (tenant: 'alpha' | 'beta', secret: string): Promise<{ token: string; sessionId: string }> => {
    const answer = await call(source, tenant, '/x/v1/sessions', { subject: { type: 'user', id: 'carol' } }, secret);
    assert.equal(answer.status, 201, JSON.stringify(answer.data));
    return answer.data as { token: string; sessionId: string };
  };
  const alphaSecret = key(resolve(dir, 'source/alpha')), betaSecret = key(resolve(dir, 'source/beta'));
  const alphaSession = await open('alpha', alphaSecret), betaSession = await open('beta', betaSecret);
  const seeded = JSON.parse(readFileSync(resolve(dir, 'source/alpha/INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<string, string> };
  const login = await fetch(replica.url + '/admin/v1/session', { method: 'POST', headers: { 'content-type': 'application/json', 'x-gate-tenant': 'alpha' },
    body: JSON.stringify({ username: 'lina', password: seeded.passwords.lina }) });
  assert.equal(login.status, 200);
  const loggedIn = await login.json() as { csrfToken: string };
  const revoked = await fetch(replica.url + '/admin/v1/blp-sessions/revoke', { method: 'POST', headers: {
    'content-type': 'application/json', 'x-gate-tenant': 'alpha', cookie: String(login.headers.get('set-cookie')).split(';')[0]!, 'x-csrf-token': loggedIn.csrfToken,
  }, body: JSON.stringify({ sessionId: alphaSession.sessionId }) });
  assert.equal(revoked.status, 200);
  assert.deepEqual(await revoked.json(), { revoked: 1, sessionIds: [alphaSession.sessionId] });

  const withToken = (token: string): Record<string, unknown> => ({ ...evaluation('carol', 'CASE-14'), context: { network: 'trusted', sessionToken: token } });
  assert.equal((await call(replica, 'alpha', undefined, withToken(alphaSession.token), alphaSecret)).status, 403);
  assert.equal((await call(source, 'beta', undefined, withToken(betaSession.token), betaSecret)).status, 200, 'the other tenant session remains live');
  const alphaDoc = await alpha.sql("SELECT body FROM gate_doc WHERE name = 'blp_revocations'");
  assert.ok(alphaDoc.rows[0] && String(alphaDoc.rows[0].body).includes(alphaSession.sessionId));
  assert.equal(Number((await beta.sql("SELECT count(*) AS n FROM gate_doc WHERE name = 'blp_revocations'")).rows[0].n), 0);

  const feed = async (tenant: 'alpha' | 'beta', secret: string): Promise<Array<{ sid: string }>> => {
    const path = `/x/v1/replica/state?nonce=${randomBytes(18).toString('base64url')}`;
    const hop = signHop(hopKeyOf(Buffer.from(secret, 'hex')), 'GET', path, Buffer.alloc(0), 'test', 'r1');
    const response = await fetch(source.url + path, { headers: { 'x-gate-tenant': tenant, [REPLICA_HOP_HEADER]: hop } });
    assert.equal(response.status, 200);
    const message = await response.json() as { docs?: { blp_revocations?: Array<{ sid: string }> } };
    return message.docs?.blp_revocations ?? [];
  };
  assert.ok((await feed('alpha', ka)).some((row) => row.sid === alphaSession.sessionId));
  assert.ok(!(await feed('beta', kb)).some((row) => row.sid === alphaSession.sessionId || row.sid === betaSession.sessionId));
});
