// Decision-token consumption on a two-node cluster (one PostgreSQL): every token is issued on one node and consumed on
// the other, all on the demo payment PAY-3, so every consumption contends for the same per-resource lock (the worst
// case of the separation-of-duty serialisation, docs/ARCHITECTURE.md). TEST_DATABASE_URL names a throwaway database.
//   node scripts/bench/consume.ts --tokens 2000 --concurrency 16
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type PdpServer } from '../../packages/pdp-http/src/server.ts';
import { databaseUrl, intOption, options, percentile, post, resetDatabase } from './common.ts';

const args = options();
const tokens = intOption(args, 'tokens', 2000);
const concurrency = intOption(args, 'concurrency', 16);
await resetDatabase();
const dirs: string[] = [];
const nodes: PdpServer[] = [];
try {
  for (const id of ['a', 'b']) {
    const dataDir = mkdtempSync(join(tmpdir(), 'gate-bench-consume-')); dirs.push(dataDir);
    const server = createServer({ port: 0, dataDir, clock: 'fixed:2026-11-08T10:00:00Z', rateLimit: 1_000_000_000, pepRateLimit: 1_000_000_000,
      databaseUrl: databaseUrl(), signingKeySeal: 'b'.repeat(64), cluster: true, nodeId: id });
    await server.listen(); nodes.push(server);
  }
  const key = (JSON.parse(readFileSync(join(dirs[0]!, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string }).pepApiKey;
  const issue = async (node: number): Promise<string> => {
    const response = await fetch(`${nodes[node]!.url}/access/v1/evaluation`, { method: 'POST', headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      body: JSON.stringify({ subject: { type: 'user', id: 'grace' }, action: { name: 'create' }, resource: { type: 'payment', id: 'PAY-3' }, context: { network: 'trusted' } }) });
    const token = ((await response.json()) as { context?: { decision_token?: string } }).context?.decision_token;
    if (!token) throw new Error(`no decision token (HTTP ${response.status})`);
    return token;
  };
  const issued = await Promise.all(Array.from({ length: tokens }, (_, i) => issue(i % 2)));
  const latencies: number[] = []; let failed = 0; let next = 0;
  const started = performance.now();
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (next < issued.length) {
      const i = next++;
      const r = await post(nodes[(i + 1) % 2]!.url, key, '/x/v1/tokens/consume', { token: issued[i], action: 'create', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 },
        (v) => (v as { ok?: boolean } | undefined)?.ok === true);
      if (r.error) failed++; else latencies.push(r.latencyMs);
    }
  }));
  const seconds = (performance.now() - started) / 1000;
  latencies.sort((x, y) => x - y);
  console.log(JSON.stringify({ tokens, concurrency, failed, perSecond: Math.round(latencies.length / seconds),
    p50Ms: +percentile(latencies, 0.5).toFixed(2), p95Ms: +percentile(latencies, 0.95).toFixed(2), p99Ms: +percentile(latencies, 0.99).toFixed(2) }));
} finally {
  for (const node of nodes) await node.close();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
}
