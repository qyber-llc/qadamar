import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createServer, type PdpServer } from '../../packages/pdp-http/src/server.ts';
import {
  commandLine, databaseUrl, evaluation, intOption, memory, options, post, random, readWorld,
  resetDatabase, textOption, type BenchTuple, type BenchWorld, type HttpResult,
} from './common.ts';

interface Recovery {
  repetition: number;
  recoveryMs: number;
  failedRequests: number;
  steadyFailedRequests: number;
}

const object = (value: unknown): Record<string, unknown> | undefined =>
  value !== null && typeof value === 'object' ? value as Record<string, unknown> : undefined;
const valid = (value: unknown): boolean => typeof object(value)?.decision === 'boolean';
const pick = (world: BenchWorld, rng: () => number): BenchTuple => world.tuples[Math.floor(rng() * world.tuples.length)]!;
const round = (value: number): number => Math.round(value * 1000) / 1000;

function summarize(values: number[]): { min: number; median: number; max: number } {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 ? sorted[middle]! : (sorted[middle - 1]! + sorted[middle]!) / 2;
  return { min: round(sorted[0]!), median: round(median), max: round(sorted.at(-1)!) };
}

const args = options();
const worldDir = resolve(textOption(args, 'world', 'tmp/bench-world'));
const concurrency = intOption(args, 'concurrency', 4);
const steadySeconds = intOption(args, 'steady', 2);
const repeats = intOption(args, 'repeats', 5);
const seed = intOption(args, 'seed', 20261108, 0);
const world = readWorld(worldDir);
const url = databaseUrl();
await resetDatabase();

const dataDir = mkdtempSync(join(tmpdir(), 'gate-failover-'));
const serverOptions = {
  port: 0,
  dataDir,
  worldDir,
  databaseUrl: url,
  signingKeySeal: randomBytes(32).toString('base64url'),
  clock: 'fixed:2026-11-08T10:00:00Z',
  rateLimit: 1_000_000_000, pepRateLimit: 1_000_000_000,
};
let active: PdpServer | undefined;
let standby: { server: PdpServer; listening: Promise<void> } | undefined;
let retiring: Promise<void> | undefined;
let stopTraffic: (() => Promise<void>) | undefined;
const before = memory();

try {
  active = createServer(serverOptions);
  await active.listen();
  const credentials = JSON.parse(readFileSync(join(dataDir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string };
  const recoveries: Recovery[] = [];

  for (let repetition = 1; repetition <= repeats; repetition++) {
    const oldActive = active;
    const next = createServer(serverOptions);
    const listening = next.listen();
    void listening.catch(() => undefined);
    standby = { server: next, listening };

    let phase: 'steady' | 'failover' | 'done' = 'steady';
    let steadyFailedRequests = 0;
    let failedRequests = 0;
    const workers = Array.from({ length: concurrency }, async (_, worker) => {
      const rng = random((seed + Math.imul((repetition - 1) * concurrency + worker + 1, 0x9e3779b9)) >>> 0);
      while (phase !== 'done') {
        const result: HttpResult = await post(oldActive.url, credentials.pepApiKey, '/access/v1/evaluation', evaluation(pick(world, rng)), valid, true);
        if (!result.error) continue;
        if (phase === 'steady') steadyFailedRequests++;
        else if (phase === 'failover') failedRequests++;
      }
    });
    stopTraffic = async (): Promise<void> => {
      phase = 'done';
      await Promise.all(workers);
    };

    await delay(steadySeconds * 1000);
    phase = 'failover';
    const stoppedAt = performance.now();
    retiring = oldActive.close();
    void retiring.catch(() => undefined);

    await listening;
    const readinessRng = random((seed + Math.imul(repetition, 0x85ebca6b)) >>> 0);
    let readiness: HttpResult;
    do {
      readiness = await post(next.url, credentials.pepApiKey, '/access/v1/evaluation', evaluation(pick(world, readinessRng)), valid);
      if (readiness.error) failedRequests++;
    } while (readiness.error);
    const recoveryMs = round(performance.now() - stoppedAt);

    phase = 'done';
    await Promise.all(workers);
    stopTraffic = undefined;
    await retiring;
    retiring = undefined;
    active = next;
    standby = undefined;
    recoveries.push({ repetition, recoveryMs, failedRequests, steadyFailedRequests });
  }

  console.log(JSON.stringify({
    command: commandLine(),
    seed,
    mode: 'postgres',
    worldDir,
    subjects: world.subjects.length,
    resources: world.resources.length,
    tuples: world.tuples.length,
    concurrency,
    steadySeconds,
    repeats,
    node: process.version,
    recoveries,
    recoveryMs: summarize(recoveries.map((item) => item.recoveryMs)),
    failedRequests: summarize(recoveries.map((item) => item.failedRequests)),
    memory: { before, after: memory() },
  }, null, 2));
} finally {
  try {
    await stopTraffic?.();
    if (retiring) await retiring;
    else if (active) await active.close();
    if (standby) {
      try { await standby.listening; }
      finally { await standby.server.close(); }
    }
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
}
