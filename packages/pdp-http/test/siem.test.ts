import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createServer as createHttpServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { TestContext } from 'node:test';
import { Audit, GENESIS, type AuditList, type AuditLog, type AuditRecord } from '../src/audit.ts';
import { fileBacking } from '../src/store.ts';
import { HttpError } from '../src/http.ts';
import {
  AUDIT_NDJSON_CONTENT_TYPE,
  SIEM_SIGNATURE_HEADER,
  SIEM_TIMESTAMP_HEADER,
  SiemExporter,
  advance,
  fromText,
  pullAudit,
  readAuditBatch,
  siemFromEnv,
} from '../src/siem.ts';
import { createServer } from '../src/server.ts';
import { users } from './helpers.ts';

const NOW = 1_762_682_400_000;
const SECRET = 'test-only-hmac-secret';

function fileAudit(t: TestContext, count = 3): { audit: Audit; dir: string } {
  const dir = mkdtempSync('/tmp/pdp-siem-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const audit = new Audit(join(dir, 'audit.jsonl'), () => '2026-11-10T10:00:00.000Z');
  for (let i = 1; i <= count; i++) audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: `user-${i}`, effect: 'allow' });
  return { audit, dir };
}

const cursorAt = (dir: string) => fileBacking<{ seq: number }>(join(dir, 'siem-cursor.json'));
const forbidden = (error: unknown): boolean => error instanceof HttpError && error.status === 403;
const badRequest = (error: unknown): boolean => error instanceof HttpError && error.status === 400 && error.code === 'bad_request';

test('batch reads use an exclusive cursor, enforce the bound, and prefer PostgreSQL list over records', async (t) => {
  const { audit } = fileAudit(t);
  assert.deepEqual((await readAuditBatch(audit, 1, 2)).map((row) => row.seq), [2, 3]);
  assert.deepEqual(await readAuditBatch(audit, 3, 2), []);
  await assert.rejects(readAuditBatch(audit, -1, 1), RangeError);
  await assert.rejects(readAuditBatch(audit, 0, 0), RangeError);
  await assert.rejects(readAuditBatch(audit, 0, 1001), RangeError);

  let query: AuditList | undefined;
  let recordReads = 0;
  const listed = audit.records()[1]!;
  const postgres: AuditLog = {
    anchors: [],
    records: () => { recordReads++; return []; },
    tip: () => ({ seq: 3, hash: audit.records().at(-1)!.hash }),
    verify: () => ({ verified: true, length: 3 }),
    append: () => undefined,
    list: async (value) => {
      query = value;
      return { items: [listed], next: null };
    },
  };
  assert.deepEqual(await readAuditBatch(postgres, 1, 1), [listed]);
  assert.deepEqual(query, { cursor: 1, limit: 1 });
  assert.equal(recordReads, 0);
});

test('pull returns inclusive NDJSON pages and the next from cursor for both read roles', async (t) => {
  const { audit } = fileAudit(t);
  const page = await pullAudit(audit, users.sam, new URL('https://pdp.example/admin/v1/audit/export?from=2&limit=1'));
  assert.equal(page.contentType, AUDIT_NDJSON_CONTENT_TYPE);
  assert.equal(page.next, 3);
  assert.equal(page.body, JSON.stringify(audit.records()[1]) + '\n');
  assert.deepEqual(JSON.parse(page.body), audit.records()[1]);

  const officer = await pullAudit(audit, users.lina, new URL('https://pdp.example/admin/v1/audit/export?from=3'));
  assert.equal(officer.next, 4);
  assert.deepEqual(officer.body.trim().split('\n').map((line) => JSON.parse(line).seq), [3]);
  const empty = await pullAudit(audit, users.sam, new URL('https://pdp.example/admin/v1/audit/export?from=9'));
  assert.equal(empty.body, '');
  assert.equal(empty.next, 9);
});

test('pull rejects other roles and malformed, repeated, unknown, or unbounded parameters', async (t) => {
  const { audit } = fileAudit(t, 1);
  await assert.rejects(pullAudit(audit, users.amira, new URL('https://pdp.example/admin/v1/audit/export')), forbidden);
  await assert.rejects(pullAudit(audit, users.omar, new URL('https://pdp.example/admin/v1/audit/export')), forbidden);
  const queries = [
    'from=0', 'from=-1', 'from=1.0', 'from=01', 'from=1e1', 'from=', 'from=abc',
    'from=9007199254740992', 'from=1&from=2', 'limit=0', 'limit=1001', 'limit=1.0',
    'limit=01', 'limit=-1', 'limit=', 'limit=1&limit=2', 'cursor=1', 'from=1&extra=true',
  ];
  for (const query of queries) {
    await assert.rejects(pullAudit(audit, users.sam, new URL(`https://pdp.example/admin/v1/audit/export?${query}`)), badRequest, query);
  }
});

test('webhook sends exact NDJSON batches with timestamped HMAC and persists only delivered cursors', async (t) => {
  const { audit, dir } = fileAudit(t);
  const calls: Array<{ body: string; headers: Headers }> = [];
  const fetcher: typeof globalThis.fetch = async (_input, init) => {
    calls.push({ body: String(init?.body), headers: new Headers(init?.headers) });
    return new Response(null, { status: 204 });
  };
  const config = { url: 'https://siem.example/ingest', secret: SECRET, batchSize: 2 };
  const exporter = new SiemExporter(audit, cursorAt(dir), config, { fetch: fetcher, now: () => NOW });
  await exporter.flush();

  assert.equal(calls.length, 2);
  const records = audit.records();
  const expectedBodies = [records.slice(0, 2), records.slice(2)].map((rows) => rows.map((row) => JSON.stringify(row)).join('\n') + '\n');
  assert.deepEqual(calls.map((call) => call.body), expectedBodies);
  for (const call of calls) {
    const timestamp = String(Math.floor(NOW / 1000));
    const expected = createHmac('sha256', SECRET).update(`${timestamp}.${call.body}`, 'utf8').digest('hex');
    assert.equal(call.headers.get('content-type'), AUDIT_NDJSON_CONTENT_TYPE);
    assert.equal(call.headers.get(SIEM_TIMESTAMP_HEADER), timestamp);
    assert.equal(call.headers.get(SIEM_SIGNATURE_HEADER), `sha256=${expected}`);
    assert.ok(!call.body.includes(SECRET));
    assert.equal(call.headers.get('authorization'), null);
  }
  assert.equal(exporter.cursor, 3);
  const cursorFile = join(dir, 'siem-cursor.json');
  assert.deepEqual(JSON.parse(readFileSync(cursorFile, 'utf8')), { seq: 3 });
  assert.equal(statSync(cursorFile).mode & 0o777, 0o600);

  const restarted = new SiemExporter(audit, cursorAt(dir), config, { fetch: fetcher, now: () => NOW });
  assert.equal(restarted.cursor, 3);
  await restarted.flush();
  assert.equal(calls.length, 2, 'a restart does not resend the acknowledged rows');
});

test('webhook retries the identical batch with exponential backoff before advancing its cursor', async (t) => {
  const { audit, dir } = fileAudit(t, 1);
  const bodies: string[] = [];
  const delays: number[] = [];
  let attempts = 0;
  const fetcher: typeof globalThis.fetch = async (_input, init) => {
    attempts++;
    bodies.push(String(init?.body));
    if (attempts === 1) return new Response('refused', { status: 503 });
    if (attempts === 2) throw new Error(`network failure must not expose ${SECRET}`);
    return new Response(null, { status: 200 });
  };
  const exporter = new SiemExporter(audit, cursorAt(dir), {
    url: 'https://siem.example/ingest', secret: SECRET, maxAttempts: 3, backoffBaseMs: 5, backoffMaxMs: 40,
  }, { fetch: fetcher, now: () => NOW, sleep: async (milliseconds) => { delays.push(milliseconds); } });
  await exporter.flush();

  assert.equal(attempts, 3);
  assert.deepEqual(delays, [5, 10]);
  assert.equal(new Set(bodies).size, 1, 'every retry carries the same audit rows for at-least-once delivery');
  assert.equal(exporter.cursor, 1);
  assert.deepEqual(JSON.parse(readFileSync(join(dir, 'siem-cursor.json'), 'utf8')), { seq: 1 });
});

test('exhausted failures retain the cursor and reject without leaking secrets or payloads', async (t) => {
  const { audit, dir } = fileAudit(t, 1);
  let attempts = 0;
  const fetcher: typeof globalThis.fetch = async () => {
    attempts++;
    return new Response('receiver details must not be logged', { status: 500 });
  };
  const exporter = new SiemExporter(audit, cursorAt(dir), {
    url: 'https://siem.example/ingest', secret: SECRET, maxAttempts: 2, backoffBaseMs: 1,
  }, { fetch: fetcher, sleep: async () => undefined });
  const failure = await exporter.flush().then(() => null, (error: unknown) => error);
  assert.ok(failure instanceof Error);
  assert.equal(attempts, 2);
  assert.equal(exporter.cursor, 0);
  assert.equal(existsSync(join(dir, 'siem-cursor.json')), false);
  assert.ok(!failure.message.includes(SECRET));
  assert.ok(!failure.message.includes('user-1'));
  assert.ok(!failure.message.includes('receiver details'));
});

test('concurrent flushes are serialized and share one delivery pass', async (t) => {
  const { audit, dir } = fileAudit(t, 1);
  let calls = 0;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const fetcher: typeof globalThis.fetch = async () => {
    calls++;
    await gate;
    return new Response(null, { status: 204 });
  };
  const exporter = new SiemExporter(audit, cursorAt(dir), { url: 'https://siem.example/ingest', secret: SECRET }, { fetch: fetcher });
  const first = exporter.flush();
  const second = exporter.flush();
  assert.strictEqual(first, second);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(calls, 1);
  release();
  await Promise.all([first, second]);
  await exporter.flush();
  assert.equal(calls, 1);
});

test('request timeout aborts a stalled webhook and leaves its batch pending', async (t) => {
  const { audit, dir } = fileAudit(t, 1);
  let aborted = false;
  const fetcher: typeof globalThis.fetch = async (_input, init) => new Promise<Response>((_resolve, reject) => {
    const signal = init?.signal;
    assert.ok(signal);
    signal.addEventListener('abort', () => { aborted = true; reject(new Error('aborted')); }, { once: true });
  });
  const exporter = new SiemExporter(audit, cursorAt(dir), {
    url: 'https://siem.example/ingest', secret: SECRET, requestTimeoutMs: 5, maxAttempts: 1,
  }, { fetch: fetcher });
  await assert.rejects(exporter.flush(), /SIEM webhook delivery failed/);
  assert.equal(aborted, true);
  assert.equal(exporter.cursor, 0);
  assert.equal(existsSync(join(dir, 'siem-cursor.json')), false);
});

test('https is mandatory except for explicitly enabled loopback HTTP test hooks', async (t) => {
  const { audit, dir } = fileAudit(t, 0);
  for (const url of ['http://siem.example/ingest', 'ftp://siem.example/ingest', 'https://user:pass@siem.example/ingest']) {
    assert.throws(() => new SiemExporter(audit, cursorAt(dir), { url, secret: SECRET }), /https/);
  }
  assert.throws(() => new SiemExporter(audit, cursorAt(dir), { url: 'http://127.0.0.1/ingest', secret: SECRET }), /https/);
  assert.throws(() => new SiemExporter(audit, cursorAt(dir), { url: 'http://siem.example/ingest', secret: SECRET }, { allowLoopbackHttp: true }), /https/);
  const exporter = new SiemExporter(audit, cursorAt(dir), { url: 'http://127.0.0.1/ingest', secret: SECRET }, { allowLoopbackHttp: true });
  await exporter.flush();
  assert.equal(exporter.cursor, 0);
});

test('audit chain fixture remains intact after exports', async (t) => {
  const { audit, dir } = fileAudit(t, 2);
  const first = audit.records()[0]!;
  assert.equal(first.prevHash, GENESIS);
  await pullAudit(audit, users.sam, new URL('https://pdp.example/admin/v1/audit/export'));
  const exporter = new SiemExporter(audit, cursorAt(dir), { url: 'https://siem.example/ingest', secret: SECRET }, {
    fetch: async () => new Response(null, { status: 204 }),
  });
  await exporter.flush();
  assert.equal(audit.verify().verified, true);
});

test('the saved cursor is committed before it counts (PostgreSQL documents are durable only after commit)', async (t) => {
  const { audit } = fileAudit(t, 2);
  const steps: string[] = [];
  let saved: { seq: number } | undefined = { seq: 1 };
  const cursor = { load: () => saved, save: (value: { seq: number }) => { saved = value; steps.push(`save:${value.seq}`); } };
  const exporter = new SiemExporter(audit, cursor, { url: 'https://siem.example/ingest', secret: SECRET }, {
    fetch: async (_input, init) => { steps.push(`post:${String(init?.body).trim().split('\n').length}`); return new Response(null, { status: 202 }); },
    commit: async () => { steps.push('commit'); },
  });
  assert.equal(exporter.cursor, 1, 'the export resumes from the persisted cursor');
  await exporter.flush();
  assert.deepEqual(steps, ['post:1', 'save:2', 'commit']);
  assert.throws(() => new SiemExporter(audit, { load: () => ({ seq: -1 }), save: () => undefined }, { url: 'https://siem.example', secret: SECRET }), /cursor/);
});

test('environment configuration needs both URL and a strong secret', () => {
  assert.equal(siemFromEnv({}), undefined);
  assert.throws(() => siemFromEnv({ SIEM_WEBHOOK_URL: 'https://siem.example' }), /together/);
  assert.throws(() => siemFromEnv({ SIEM_WEBHOOK_URL: 'https://siem.example', SIEM_HMAC_SECRET: 'short' }), /32/);
  assert.throws(() => siemFromEnv({ SIEM_WEBHOOK_URL: 'https://siem.example', SIEM_HMAC_SECRET: SECRET.repeat(2), SIEM_INTERVAL_SECONDS: '0' }), /interval/);
  assert.deepEqual(siemFromEnv({ SIEM_WEBHOOK_URL: 'https://siem.example', SIEM_HMAC_SECRET: SECRET.repeat(2), SIEM_BATCH_SIZE: '50' }),
    { url: 'https://siem.example', secret: SECRET.repeat(2), batchSize: 50, intervalSeconds: 30 });
});

test('a running server pushes signed audit rows to a real receiver and serves the pull export over HTTP', async (t) => {
  const received: Array<{ body: string; timestamp: string; signature: string }> = [];
  const receiver = createHttpServer((req, res) => {
    let body = '';
    req.on('data', (chunk: Buffer) => { body += chunk.toString('utf8'); });
    req.on('end', () => {
      received.push({ body, timestamp: String(req.headers[SIEM_TIMESTAMP_HEADER]), signature: String(req.headers[SIEM_SIGNATURE_HEADER]) });
      res.statusCode = 204; res.end();
    });
  });
  try { await new Promise<void>((accept, reject) => { receiver.once('error', reject); receiver.listen(0, '127.0.0.1', accept); }); }
  catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'EPERM') { t.skip('Sandbox forbids listening on localhost'); return; }
    throw error;
  }
  t.after(() => new Promise<void>((accept) => receiver.close(() => accept())));
  const address = receiver.address() as AddressInfo;
  const dir = mkdtempSync('/tmp/pdp-siem-server-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const server = createServer({ port: 0, dataDir: dir, worldDir: resolve('examples/toy-domain'), clock: 'fixed:2026-11-08T10:00:00Z',
    siem: { url: `http://127.0.0.1:${address.port}/ingest`, secret: SECRET }, siemHooks: { allowLoopbackHttp: true } });
  t.after(() => server.close());
  await server.listen();
  const passwords = (JSON.parse(readFileSync(join(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<string, string> }).passwords;
  const login = await fetch(`${server.url}/admin/v1/session`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'sam', password: passwords.sam }) });
  const cookie = String(login.headers.get('set-cookie')).split(';')[0]!;

  await server.exportAudit();
  assert.equal(received.length, 1);
  const pushed = received[0]!;
  assert.equal(pushed.signature, `sha256=${createHmac('sha256', SECRET).update(`${pushed.timestamp}.${pushed.body}`).digest('hex')}`);
  assert.deepEqual(pushed.body.trim().split('\n').map((line) => JSON.parse(line).action), ['login']);
  assert.ok(!pushed.body.includes(passwords.sam!));
  assert.deepEqual(JSON.parse(readFileSync(join(dir, 'siem-cursor.json'), 'utf8')), { seq: 1 });

  const pulled = await fetch(`${server.url}/admin/v1/audit/export?from=1`, { headers: { cookie } });
  assert.equal(pulled.status, 200);
  assert.equal(pulled.headers.get('content-type'), AUDIT_NDJSON_CONTENT_TYPE);
  assert.equal(pulled.headers.get('x-audit-next-from'), '2');
  assert.equal(await pulled.text(), pushed.body);
  assert.equal((await fetch(`${server.url}/admin/v1/audit/export`)).status, 401);
  assert.equal((await fetch(`${server.url}/admin/v1/audit/export?cursor=1`, { headers: { cookie } })).status, 400);
});

test('a webhook URL with a query string is refused, so no token rides in the URL', (t) => {
  const { audit, dir } = fileAudit(t, 0);
  assert.throws(() => new SiemExporter(audit, cursorAt(dir), { url: 'https://siem.example/ingest?token=abc', secret: SECRET }), /query string/);
  assert.ok(new SiemExporter(audit, cursorAt(dir), { url: 'https://siem.example/ingest', secret: SECRET }));
});

test('export and push positions are per chain: a seq for chain "0" alone, "node:seq" lists otherwise', async () => {
  const rows = [{ node: 'a', seq: 3 }, { node: 'b', seq: 1 }, { seq: 7 }] as AuditRecord[];
  let asked: ReadonlyMap<string, number> | undefined; let bound: ReadonlyMap<string, number> | undefined;
  const audit = { anchors: [], records: () => [], tip: () => ({ seq: 0, hash: '' }), verify: () => ({ verified: true, length: 0 }), append: () => undefined,
    exportBatch: async (after: ReadonlyMap<string, number>, _limit: number, until?: ReadonlyMap<string, number>) => { asked = after; bound = until; return rows; } } as AuditLog;
  const page = await pullAudit(audit, users.sam, new URL('http://local/admin/v1/audit/export?from=a:3,b:1'));
  assert.deepEqual([...asked!], [['a', 2], ['b', 0]]);
  assert.equal(page.next, '0:8,a:4,b:2');
  assert.equal(fromText(advance(new Map([['0', 4]]), [])), 5, 'chain "0" alone keeps the numeric cursor');
  assert.equal(bound, undefined, 'no until: no bound');
  await pullAudit(audit, users.sam, new URL('http://local/admin/v1/audit/export?until=a:5,0:9'));
  assert.deepEqual([...bound!], [['a', 5], ['0', 9]], 'until is inclusive, as given');
  for (const bad of ['a:0', 'a:1,a:2', ':3', '-a:1', 'a:1,', '0']) {
    for (const name of ['from', 'until']) {
      await assert.rejects(pullAudit(audit, users.sam, new URL(`http://local/admin/v1/audit/export?${name}=${bad}`)), (e: unknown) => e instanceof Error && 'status' in e && e.status === 400, `${name}=${bad}`);
    }
  }
  // the file log: rows past the bound, and chains it does not name, are not exported
  const file = { anchors: [], records: () => [{ seq: 1 }, { seq: 2 }, { seq: 3 }] as AuditRecord[], tip: () => ({ seq: 3, hash: '' }), verify: () => ({ verified: true, length: 3 }), append: () => undefined } as AuditLog;
  assert.deepEqual((await readAuditBatch(file, 0, 10, new Map([['0', 2]]))).map((r) => r.seq), [1, 2]);
  assert.deepEqual(await readAuditBatch(file, 0, 10, new Map([['a', 2]])), []);
});
