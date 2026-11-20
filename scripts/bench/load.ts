import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { createServer } from '../../packages/pdp-http/src/server.ts';
import {
  commandLine, evaluation, intOption, memory, options, percentile, post, random, readWorld,
  resetDatabase, textOption, databaseUrl, type BenchTuple, type BenchWorld, type HttpResult,
} from './common.ts';

type ScenarioName = 'evaluation' | 'batch' | 'search' | 'filter';
interface Scenario {
  name: ScenarioName;
  path: string;
  body(world: BenchWorld, rng: () => number): unknown;
  valid(value: unknown): boolean;
}

const object = (value: unknown): Record<string, unknown> | undefined =>
  value !== null && typeof value === 'object' ? value as Record<string, unknown> : undefined;
const pick = (world: BenchWorld, rng: () => number): BenchTuple => world.tuples[Math.floor(rng() * world.tuples.length)]!;
const columns = {
  'resource.id': 'id',
  'resource.level': { column: 'level', type: 'number' },
  'resource.compartments': { column: 'compartments', kind: 'text[]' },
  'resource.integrity': 'integrity',
  'resource.owner': 'owner',
  'resource.contentClasses': { column: 'content_classes', kind: 'text[]' },
  'resource.attrs.status': 'status',
};
const scenarios: Record<ScenarioName, Scenario> = {
  evaluation: {
    name: 'evaluation', path: '/access/v1/evaluation',
    body: (world, rng) => evaluation(pick(world, rng)),
    valid: (value) => typeof object(value)?.decision === 'boolean',
  },
  batch: {
    name: 'batch', path: '/access/v1/evaluations',
    body: (world, rng) => ({
      evaluations: Array.from({ length: 50 }, () => {
        const request = evaluation(pick(world, rng));
        return { subject: request.subject, action: request.action, resource: request.resource, context: request.context };
      }),
      options: { evaluations_semantic: 'execute_all' },
    }),
    valid: (value) => {
      const items = object(value)?.evaluations;
      return Array.isArray(items) && items.length === 50 && items.every((item) => typeof object(item)?.decision === 'boolean');
    },
  },
  search: {
    name: 'search', path: '/access/v1/search/resource',
    body: (world, rng) => {
      const tuple = pick(world, rng);
      return {
        subject: tuple.subject, action: { name: 'read' }, resource: { type: 'case' },
        context: { network: 'trusted' }, page: { limit: 50 },
      };
    },
    valid: (value) => Array.isArray(object(value)?.results) && object(object(value)?.page)?.next_token !== undefined,
  },
  filter: {
    name: 'filter', path: '/x/v1/filter',
    body: (world, rng) => {
      const tuple = pick(world, rng);
      return {
        subject: tuple.subject, action: { name: 'read' }, resource: { type: 'case' },
        context: { network: 'trusted' }, dialect: 'postgres', columns,
      };
    },
    valid: (value) => typeof object(object(value)?.sql)?.text === 'string' && Array.isArray(object(object(value)?.sql)?.params),
  },
};

/** `concurrency` workers per node; worker i always calls node i mod the node count. */
async function traffic(bases: readonly string[], key: string, scenario: Scenario, world: BenchWorld,
  seed: number, concurrency: number, durationSeconds: number, collect: boolean): Promise<Array<HttpResult & { node: number }>> {
  const results: Array<HttpResult & { node: number }> = [];
  const deadline = performance.now() + durationSeconds * 1000;
  await Promise.all(Array.from({ length: concurrency * bases.length }, async (_, worker) => {
    const rng = random((seed + Math.imul(worker + 1, 0x9e3779b9)) >>> 0);
    const node = worker % bases.length;
    while (performance.now() < deadline) {
      const result = await post(bases[node]!, key, scenario.path, scenario.body(world, rng), scenario.valid);
      if (collect) results.push({ ...result, node });
    }
  }));
  return results;
}

/** One cluster node per child process (scripts/bench/node.ts): node "a" seeds the database and leads. `replica`: a
 *  stateless replica of node "a" instead (no DATABASE_URL in its environment). */
async function startNode(id: string, dataDir: string, seal: string, extra: Record<string, string> = {}, replica = false): Promise<{ child: ChildProcess; url: string }> {
  const { DATABASE_URL: _db, TEST_DATABASE_URL: _test, ...inherited } = process.env;
  const child = spawn(process.execPath, [new URL('./node.ts', import.meta.url).pathname], {
    env: { ...(replica ? inherited : { ...process.env, DATABASE_URL: databaseUrl(), SIGNING_KEY_SEAL: seal }), GATE_NODE_ID: id, DATA_DIR: dataDir, WORLD_DIR: worldDir, ...extra },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const url = await new Promise<string>((accept, reject) => {
    child.once('exit', (code) => reject(new Error(`Node ${id} exited (${code}) before it served`)));
    createInterface({ input: child.stdout! }).on('line', (line) => { if (line.startsWith('READY ')) accept(line.slice(6)); });
  });
  child.removeAllListeners('exit');
  return { child, url };
}
async function stopNode(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null) return;
  await new Promise<void>((accept) => { child.once('exit', () => accept()); child.kill('SIGTERM'); });
}

function round(value: number): number { return Math.round(value * 1000) / 1000; }
function summarize(result: Array<HttpResult & { node: number }>, elapsedMs: number, before: ReturnType<typeof memory>, nodeCount: number): Record<string, unknown> {
  const latencies = result.map((r) => r.latencyMs).sort((a, b) => a - b);
  const errors: Record<string, number> = {};
  for (const item of result) if (item.error) errors[item.error] = (errors[item.error] ?? 0) + 1;
  const errorCount = result.filter((r) => r.error).length;
  return {
    requests: result.length,
    successes: result.length - errorCount,
    errors: { count: errorCount, byKind: errors },
    elapsedSeconds: round(elapsedMs / 1000),
    requestsPerSecond: round(result.length * 1000 / elapsedMs),
    ...(nodeCount > 0 ? { requestsPerSecondByNode: Array.from({ length: nodeCount }, (_, node) => round(result.filter((r) => r.node === node).length * 1000 / elapsedMs)) } : {}),
    latencyMs: {
      p50: round(percentile(latencies, 0.50)), p95: round(percentile(latencies, 0.95)),
      p99: round(percentile(latencies, 0.99)), max: round(latencies.at(-1) ?? 0),
    },
    memory: { before, after: memory() },
  };
}

const args = options();
const worldDir = resolve(textOption(args, 'world', 'tmp/bench-world'));
const mode = textOption(args, 'mode', 'file');
if (mode !== 'file' && mode !== 'postgres') throw new Error('--mode must be file or postgres');
const duration = intOption(args, 'duration', 20);
const warmup = intOption(args, 'warmup', 1, 0);
const concurrency = intOption(args, 'concurrency', 8);
const seed = intOption(args, 'seed', 20261108, 0);
const selected = textOption(args, 'scenario', 'all');
/** --nodes N: N cluster nodes, each in its own process, the load spread over them (PostgreSQL only). Absent: one server
 *  in this process, as in the earlier baselines. */
const nodeCount = args.has('nodes') ? intOption(args, 'nodes', 1) : 0;
if (nodeCount > 0 && mode !== 'postgres') throw new Error('--nodes needs --mode=postgres');
/** --replicas R (with --nodes=1): R stateless replicas of node "a" (GATE_REPLICA_OF), each in its own process; the load
 *  is spread over the leader and the replicas the same way. */
const replicaCount = args.has('replicas') ? intOption(args, 'replicas', 1, 0) : 0;
if (replicaCount > 0 && nodeCount !== 1) throw new Error('--replicas needs --nodes=1');
const replicaKeys = Array.from({ length: replicaCount }, () => randomBytes(32).toString('base64url'));
if (selected !== 'all' && !Object.hasOwn(scenarios, selected)) throw new Error('--scenario must be all, evaluation, batch, search or filter');
const world = readWorld(worldDir);
if (mode === 'postgres') await resetDatabase();
const dataDir = mkdtempSync(join(tmpdir(), 'gate-load-'));
const seal = randomBytes(32).toString('base64url');
const server = nodeCount > 0 ? undefined : createServer({
  port: 0, dataDir, worldDir, clock: 'fixed:2026-11-08T10:00:00Z', rateLimit: 1_000_000_000, pepRateLimit: 1_000_000_000,
  ...(mode === 'postgres' ? { databaseUrl: databaseUrl(), signingKeySeal: seal } : {}),
});
const children: ChildProcess[] = [];
const extraDirs: string[] = [];
try {
  const bases: string[] = [];
  if (server) { await server.listen(); bases.push(server.url); }
  for (let i = 0; i < nodeCount; i++) {
    const dir = i === 0 ? dataDir : mkdtempSync(join(tmpdir(), 'gate-load-'));
    if (i > 0) extraDirs.push(dir);
    const started = await startNode(String.fromCharCode(97 + i), dir, seal, replicaCount ? { GATE_REPLICA_KEYS: replicaKeys.map((k, n) => `r${n + 1}=${k}`).join(',') } : {});
    children.push(started.child); bases.push(started.url);
  }
  for (const [n, key] of replicaKeys.entries()) {
    const dir = mkdtempSync(join(tmpdir(), 'gate-load-')); extraDirs.push(dir);
    const started = await startNode(`r${n + 1}`, dir, seal, { GATE_REPLICA_OF: bases[0]!, GATE_REPLICA_KEY: key }, true);
    children.push(started.child); bases.push(started.url);
  }
  const credentials = JSON.parse(readFileSync(join(dataDir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string };
  const names = (selected === 'all' ? ['evaluation', 'batch', 'search', 'filter'] : [selected]) as ScenarioName[];
  const report: Record<string, unknown> = {
    command: commandLine(), seed, mode, worldDir, subjects: world.subjects.length,
    resources: world.resources.length, tuples: world.tuples.length, concurrency,
    ...(nodeCount > 0 ? { nodes: nodeCount, replicas: replicaCount, concurrencyPerNode: concurrency, nodeProcesses: true } : {}),
    durationSeconds: duration, warmupSeconds: warmup, node: process.version, scenarios: {},
  };
  const measurements: Record<string, unknown> = {};
  for (const [index, name] of names.entries()) {
    const scenario = scenarios[name];
    console.error(`Running ${name} for ${duration}s on ${bases.length} node(s)...`);
    if (warmup) await traffic(bases, credentials.pepApiKey, scenario, world, seed + index * 101, concurrency, warmup, false);
    const before = memory();
    const started = performance.now();
    const results = await traffic(bases, credentials.pepApiKey, scenario, world, seed + index * 101, concurrency, duration, true);
    measurements[name] = summarize(results, performance.now() - started, before, nodeCount + replicaCount);
  }
  report.scenarios = measurements;
  console.log(JSON.stringify(report, null, 2));
} finally {
  await server?.close();
  await Promise.all(children.map(stopNode));
  for (const dir of [dataDir, ...extraDirs]) rmSync(dir, { recursive: true, force: true });
}
