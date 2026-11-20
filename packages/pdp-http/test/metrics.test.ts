import test from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage, ServerResponse } from 'node:http';
import { createHandler } from '../src/router.ts';
import { READINESS_CACHE_MS } from '../src/metrics.ts';
import { evaluation, fixture, type Fixture } from './helpers.ts';

type Handler = ReturnType<typeof createHandler>;
interface Response { status: number; headers: Record<string, unknown>; text: string; data: Record<string, unknown> }
async function send(handler: Handler, path: string, method = 'GET', data?: unknown, headers: Record<string, string> = {}): Promise<Response> {
  const socket = { remoteAddress: '127.0.0.1', readable: false } as ConstructorParameters<typeof IncomingMessage>[0];
  const req = new IncomingMessage(socket); req.url = path; req.method = method;
  req.headers = { ...(method === 'POST' ? { 'content-type': 'application/json' } : {}), ...headers };
  let text = '';
  const res = new ServerResponse(req);
  res.end = ((chunk?: unknown): ServerResponse => { text = chunk === undefined ? '' : String(chunk); return res; }) as typeof res.end;
  const pending = handler(req, res);
  req.push(data === undefined ? '' : JSON.stringify(data)); req.push(null);
  await pending;
  let parsed: Record<string, unknown> = {};
  try { parsed = JSON.parse(text) as Record<string, unknown>; } catch { /* Prometheus is text. */ }
  return { status: res.statusCode, headers: res.getHeaders(), text, data: parsed };
}
const handler = (f: Fixture): Handler => createHandler(f.rt, f.auth, {}, () => 'http://localhost:8787');

test('health, readiness and public Prometheus metrics expose operational state without identifiers', async (t) => {
  const previous = process.env.METRICS_TOKEN;
  delete process.env.METRICS_TOKEN;
  t.after(() => { if (previous === undefined) delete process.env.METRICS_TOKEN; else process.env.METRICS_TOKEN = previous; });
  const f = fixture(t); const route = handler(f);
  assert.deepEqual((await send(route, '/healthz')).data, { status: 'ok' });
  const ready = await send(route, '/readyz');
  assert.equal(ready.status, 200); assert.equal(ready.data.active, true);
  const auth = { authorization: `Bearer ${f.pepApiKey}` };
  assert.equal((await send(route, '/access/v1/evaluation', 'POST', evaluation(), auth)).data.decision, true);
  assert.equal((await send(route, '/access/v1/evaluation', 'POST', evaluation('bob', 'CASE-7'), auth)).data.decision, false);

  const scrape = await send(route, '/metrics');
  assert.equal(scrape.status, 200);
  assert.match(String(scrape.headers['content-type']), /^text\/plain; version=0\.0\.4/);
  assert.match(scrape.text, /gate_decisions_total\{effect="allow"\} 1\n/);
  assert.match(scrape.text, /gate_decisions_total\{effect="deny"\} 1\n/);
  assert.match(scrape.text, /gate_http_request_duration_seconds_bucket\{route="evaluation",le="\+Inf"\} 2\n/);
  assert.match(scrape.text, /gate_http_request_duration_seconds_count\{route="evaluation"\} 2\n/);
  assert.match(scrape.text, /gate_audit_length 2\n/);
  assert.match(scrape.text, /gate_audit_last_anchor_age_seconds -1\n/);
  assert.match(scrape.text, /gate_commit_duration_seconds_count 0\n/);
  assert.match(scrape.text, /gate_active_node 1\n/);
  for (const sensitive of ['bob', 'CASE-14', 'CASE-7', f.pepApiKey]) assert.ok(!scrape.text.includes(sensitive));
});

test('METRICS_TOKEN protects only the metrics scrape with a bearer token', async (t) => {
  const previous = process.env.METRICS_TOKEN;
  process.env.METRICS_TOKEN = 'metrics-test-secret';
  t.after(() => { if (previous === undefined) delete process.env.METRICS_TOKEN; else process.env.METRICS_TOKEN = previous; });
  const route = handler(fixture(t));
  assert.equal((await send(route, '/healthz')).status, 200);
  assert.equal((await send(route, '/readyz')).status, 200);
  const missing = await send(route, '/metrics');
  assert.equal(missing.status, 401); assert.equal(missing.headers['www-authenticate'], 'Bearer');
  assert.equal((await send(route, '/metrics', 'GET', undefined, { authorization: 'Bearer wrong' })).status, 401);
  const allowed = await send(route, '/metrics', 'GET', undefined, { authorization: 'Bearer metrics-test-secret' });
  assert.equal(allowed.status, 200); assert.ok(!allowed.text.includes('metrics-test-secret'));
});

test('readiness fails closed without leaking store or audit errors', async (t) => {
  const f = fixture(t);
  f.rt.commit = async () => { throw new Error('sensitive store detail'); };
  const route = handler(f);
  const storeDown = await send(route, '/readyz');
  assert.equal(storeDown.status, 503); assert.equal(storeDown.data.status, 'unavailable');
  assert.ok(!storeDown.text.includes('sensitive store detail'));
  assert.equal((await send(route, '/healthz')).status, 200);

  const other = fixture(t);
  other.rt.audit.recheck = async () => false;
  const broken = await send(handler(other), '/readyz');
  assert.deepEqual(broken.data, { status: 'unavailable' }); assert.equal(broken.status, 503);
});

test('commit and operational route latencies are observed', async (t) => {
  const f = fixture(t);
  f.rt.commit = async () => { await new Promise((resolve) => setTimeout(resolve, 2)); };
  const route = handler(f);
  await send(route, '/healthz');
  await send(route, '/readyz');
  const scrape = await send(route, '/metrics');
  assert.match(scrape.text, /gate_commit_duration_seconds_count 1\n/);
  assert.match(scrape.text, /gate_http_request_duration_seconds_count\{route="readiness"\} 1\n/);
  assert.match(scrape.text, /gate_http_request_duration_seconds_count\{route="health"\} 1\n/);
});

test('readiness is cached for a few seconds and does not report the audit length', async (t) => {
  const f = fixture(t); let ms = 1_000; let commits = 0;
  f.rt.commit = async () => { commits++; };
  const route = createHandler(f.rt, f.auth, { elapsed: () => ms }, () => 'http://localhost:8787');
  const first = await send(route, '/readyz');
  assert.deepEqual(first.data, { status: 'ready', active: true, audit: { verified: true } });
  await Promise.all([send(route, '/readyz'), send(route, '/readyz')]);
  ms += READINESS_CACHE_MS - 1;
  await send(route, '/readyz');
  assert.equal(commits, 1, 'one commit + verify per window, whatever the probe rate');
  ms += 1;
  f.rt.commit = async () => { commits++; throw new Error('down'); };
  assert.equal((await send(route, '/readyz')).status, 503, 'a new window checks again');
  assert.equal(commits, 2);
});
