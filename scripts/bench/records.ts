// Per-record storage against a migrated whole-document baseline: registration throughput and held-follower catch-up.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { policyVersion, type PolicyBundle, type Resource, type Subject, type Tuple } from '../../packages/core/src/index.ts';
import { createServer, type PdpServer } from '../../packages/pdp-http/src/server.ts';
import { PgLedger } from '../../packages/pdp-http/src/postgres.ts';
import type { Disk } from '../../packages/pdp-http/src/store.ts';
import { adminClient, commandLine, databaseUrl, intOption, options, resetDatabase } from './common.ts';

async function post(base: string, path: string, body: unknown, headers: Record<string, string> = {}) {
  const response = await fetch(`${base}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  const text = await response.text();
  return { status: response.status, json: (text ? JSON.parse(text) : {}) as Record<string, unknown>, headers: Object.fromEntries(response.headers) };
}

const args = options();
const count = intOption(args, 'resources', 100_000, 1);
const registrations = intOption(args, 'registrations', 100, 1);
const concurrency = intOption(args, 'concurrency', 16, 1);
const batchSize = intOption(args, 'batch', 1000, 0);
const followerCount = intOption(args, 'followers', 1, 0);
const catchupWrites = intOption(args, 'catchup', 20, 0);
const worldDir = resolve('examples/toy-domain');
const bundle = JSON.parse(readFileSync(resolve(worldDir, 'bundle.json'), 'utf8')) as PolicyBundle;
const world = JSON.parse(readFileSync(resolve(worldDir, 'world.json'), 'utf8')) as { subjects: Subject[]; resources: Resource[]; tuples: Tuple[] };
const resources: Resource[] = [...world.resources];
for (let i = resources.length; i < count; i++) resources.push({ type: 'case', id: `SYN-C${String(i).padStart(7, '0')}`, level: 1,
  compartments: [], integrity: 'verified', owner: 'carol', contentClasses: [], version: 1, attrs: { title: `Synthetic case ${i}`, status: 'open' } });
const legacy: Disk = {
  state: { bundle, subjects: world.subjects, resources, tuples: world.tuples.map((tuple, i) => ({ ...tuple, id: `seed-${i + 1}` })) },
  changes: [], emergencies: [], history: [{ version: policyVersion(bundle), publishedAt: '2026-11-08T10:00:00Z', publishedBy: 'bootstrap', approvedBy: 'bootstrap', reason: 'Benchmark seed' }], performed: [],
};
const url = databaseUrl();
await resetDatabase();
const admin = adminClient();
await admin.connect();
try { await admin.query(`INSERT INTO gate_doc (name, body) VALUES ('state', $1)`, [JSON.stringify(legacy)]); }
finally { await admin.end(); }
const migrationStarted = performance.now();
const migration = await PgLedger.open(url, () => undefined, { node: 'migration', cluster: true });
await migration.close();
const migrationMs = performance.now() - migrationStarted;

const dir = mkdtempSync(resolve(tmpdir(), 'gate-record-bench-'));
const seal = randomBytes(32).toString('base64url');
const optionsFor = (nodeId: string, beforeSync?: () => Promise<void>) => ({ port: 0, dataDir: dir, worldDir, databaseUrl: url, signingKeySeal: seal,
  clock: 'fixed:2026-11-08T10:00:00Z', cluster: true, nodeId, maxStalenessMs: 60_000, policySignatureAdopt: true,
  rateLimit: 1_000_000_000, pepRateLimit: 1_000_000_000, ...(beforeSync ? { databaseHooks: { beforeSync } } : {}) });
let hold: Promise<void> | undefined;
let release = (): void => undefined;
const leader = createServer(optionsFor('a'));
let follower: PdpServer | undefined;
try {
  await leader.listen();
  if (followerCount) {
    follower = createServer(optionsFor('b', () => hold ?? Promise.resolve()));
    await follower.listen();
  }
  const credentials = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<string, string>; pepApiKey: string };
  const login = await post(leader.url, '/admin/v1/session', { username: 'lina', password: credentials.passwords.lina });
  if (login.status !== 200) throw new Error(`Sign-in failed with status ${login.status}`);
  const cookie = String(login.headers['set-cookie']).split(';')[0];
  const csrf = String((login.json as { csrfToken: unknown }).csrfToken);
  const issued = await post(leader.url, '/admin/v1/pep-credentials', { name: 'record-bench', resourceTypes: ['case', 'folder'] }, { cookie, 'x-csrf-token': csrf });
  if (issued.status !== 201) throw new Error(`Credential issue failed with status ${issued.status}`);
  const authorization = `Bearer ${String((issued.json as { secret: unknown }).secret)}`;
  const record = (i: number) => ({ type: 'case', id: `BENCH-${i}`, level: 1, compartments: [], integrity: 'system', owner: 'carol', contentClasses: [], parent: { type: 'folder', id: 'FOLDER-A' } });
  const register = async (i: number): Promise<void> => {
    const result = await post(leader.url, '/x/v1/resources', { resource: record(i) }, { authorization });
    if (result.status !== 201) throw new Error(`Registration ${i} failed with status ${result.status}`);
  };
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const i = next++;
      if (i >= registrations) return;
      await register(i);
    }
  };
  const started = performance.now();
  await Promise.all(Array.from({ length: Math.min(concurrency, registrations) }, worker));
  const registrationMs = performance.now() - started;
  let batchMs = 0;
  if (batchSize) {
    const batchStarted = performance.now();
    const result = await post(leader.url, '/x/v1/resources/sync', { resources: Array.from({ length: batchSize }, (_, i) => record(registrations + i)) }, { authorization });
    if (result.status !== 200) throw new Error(`Batch sync failed with status ${result.status}`);
    batchMs = performance.now() - batchStarted;
  }
  let catchupMs = 0;
  if (follower && catchupWrites) {
    hold = new Promise<void>((resolve) => { release = () => { hold = undefined; resolve(); }; });
    for (let i = registrations + batchSize; i < registrations + batchSize + catchupWrites; i++) await register(i);
    const catchupStarted = performance.now();
    release();
    for (;;) {
      const result = await post(follower.url, '/access/v1/evaluation', { subject: { type: 'user', id: 'bob' }, action: { name: 'read' },
        resource: { type: 'case', id: `BENCH-${registrations + batchSize + catchupWrites - 1}` } }, { authorization: `Bearer ${credentials.pepApiKey}` });
      if (result.status === 200 && (result.json as { decision: unknown }).decision === true) break;
      if (performance.now() - catchupStarted > 60_000) throw new Error('Follower did not catch up within 60 s');
    }
    catchupMs = performance.now() - catchupStarted;
  }
  console.log(JSON.stringify({ command: commandLine(), resources: count, migrationMs, registrations, concurrency, registrationMs,
    registrationsPerSecond: registrations * 1000 / registrationMs, batchSize, batchMs,
    batchResourcesPerSecond: batchSize * 1000 / batchMs, catchupWrites, catchupMs }, null, 2));
} finally {
  release();
  await Promise.all([leader.close().catch(() => undefined), follower?.close().catch(() => undefined)]);
  rmSync(dir, { recursive: true, force: true });
}
