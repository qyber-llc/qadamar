import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { createServer } from '../src/server.ts';

type Body = Record<string, unknown>;
interface Vector { request: Body; expected: boolean | Array<{ decision: boolean }> }
type Endpoint = 'evaluation' | 'evaluations';

const directory = resolve('packages/pdp-http/test/authzen-official');
const suites = ['decisions.json', 'decisions-authorization-api-1_0-00.json',
  'decisions-authorization-api-1_0-01.json', 'decisions-authorization-api-1_0-02.json'];

function vectors(file: string): Array<{ vector: Vector; endpoint: Endpoint; index: number; group: string }> {
  const data = JSON.parse(readFileSync(resolve(directory, file), 'utf8')) as Record<string, Vector[] | undefined>;
  const groups: Array<[string, Endpoint]> = [['decisions', 'evaluation'], ['evaluation', 'evaluation'], ['evaluations', 'evaluations']];
  return groups.flatMap(([group, endpoint]) => (data[group] ?? []).map((vector, index) => ({ vector, endpoint, index, group })));
}

function actual(data: Body, endpoint: Endpoint): unknown {
  if (endpoint === 'evaluation') return data.decision || false;
  if (!Array.isArray(data.evaluations)) return [];
  // The vectors assert decisions; AuthZEN explicitly permits an additional response context on each item.
  return data.evaluations.map((item) => ({ decision: (item as Body).decision || false }));
}

test('official OpenID AuthZEN Todo vectors over HTTP', async (t) => {
  const dir = mkdtempSync('/tmp/authzen-official-');
  const server = createServer({ port: 0, dataDir: dir, worldDir: resolve('examples/authzen-todo'), rateLimit: 1000 });
  const counts = { passed: 0, skipped: 0, failed: 0 };
  t.after(async () => {
    await server.close();
    rmSync(dir, { recursive: true, force: true });
    console.log(`AUTHZEN_OFFICIAL total=${counts.passed + counts.skipped + counts.failed} passed=${counts.passed} skipped=${counts.skipped} failed=${counts.failed}`);
  });
  await server.listen();
  const credentials = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string };

  for (const file of suites) {
    for (const { vector, endpoint, index, group } of vectors(file)) {
      const name = `${file} ${group}[${index}] POST /access/v1/${endpoint}`;
      await t.test(name, async () => {
        let status = 0;
        let response = '';
        let result: unknown;
        try {
          const reply = await fetch(`${server.url}/access/v1/${endpoint}`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${credentials.pepApiKey}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(vector.request),
          });
          status = reply.status;
          response = await reply.text();
          result = actual(JSON.parse(response) as Body, endpoint);
          assert.equal(status, 200);
          assert.deepEqual(result, vector.expected);
          counts.passed++;
        } catch (error) {
          counts.failed++;
          console.error(`${name}\nrequest: ${JSON.stringify(vector.request)}\nexpected: ${JSON.stringify(vector.expected)}\nactual: ${JSON.stringify(result)}\nHTTP ${status}: ${response}`);
          throw error;
        }
      });
    }
  }
});
