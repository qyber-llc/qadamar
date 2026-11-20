import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer as createHttpServer, IncomingMessage, ServerResponse, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import type { TestContext } from 'node:test';
import { createServer } from '../src/server.ts';
import { createHandler } from '../src/router.ts';
import { MAX_CHILD_SPANS, Tracer, parseTraceparent, tracesUrl, tracingFromEnv } from '../src/tracing.ts';
import { evaluation, fixture } from './helpers.ts';

interface OtlpSpan { traceId: string; spanId: string; parentSpanId?: string; name: string; kind: number; startTimeUnixNano: string; endTimeUnixNano: string;
  attributes: { key: string; value: { stringValue?: string; intValue?: string; arrayValue?: { values: { stringValue: string }[] } } }[]; status: { code: number } }
interface Receiver { url: string; bodies: string[]; spans: OtlpSpan[]; paths: string[]; status: number[] }
/** A local OTLP/HTTP collector: answers each POST with the next scripted status (200 once the script is used up). */
async function receiver(t: TestContext, script: Array<number | 'hang'> = []): Promise<Receiver> {
  const got: Receiver = { url: '', bodies: [], spans: [], paths: [], status: [] };
  const server: Server = createHttpServer((req, res) => {
    let text = '';
    req.on('data', (chunk: Buffer) => { text += chunk.toString(); });
    req.on('end', () => {
      const next = script.shift() ?? 200;
      got.paths.push(`${req.method} ${req.url} ${req.headers['content-type']}`);
      got.status.push(next === 'hang' ? 0 : next);
      if (next === 'hang') return;
      if (next === 200) {
        got.bodies.push(text);
        const body = JSON.parse(text) as { resourceSpans: { scopeSpans: { spans: OtlpSpan[] }[] }[] };
        got.spans.push(...body.resourceSpans.flatMap((r) => r.scopeSpans.flatMap((s) => s.spans)));
      }
      res.statusCode = next; res.end('{}');
    });
  });
  await new Promise<void>((accept) => server.listen(0, '127.0.0.1', accept));
  t.after(() => { server.closeAllConnections(); server.close(); });
  got.url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return got;
}
const attribute = (span: OtlpSpan | undefined, key: string): unknown => {
  const v = span?.attributes.find((a) => a.key === key)?.value;
  return v?.stringValue ?? (v?.intValue === undefined ? undefined : Number(v.intValue)) ?? v?.arrayValue?.values.map((x) => x.stringValue);
};
const until = async (check: () => boolean, ms = 3000): Promise<void> => {
  const end = Date.now() + ms;
  while (!check()) { if (Date.now() > end) assert.fail('timed out'); await new Promise((r) => setTimeout(r, 10)); }
};

test('traceparent parsing follows W3C Trace Context and the OTLP endpoint is validated', () => {
  const id = '4bf92f3577b34da6a3ce929d0e0e4736'; const parent = '00f067aa0ba902b7';
  assert.deepEqual(parseTraceparent(`00-${id}-${parent}-01`), { traceId: id, parentSpanId: parent, sampled: true });
  assert.equal(parseTraceparent(`00-${id}-${parent}-00`)?.sampled, false);
  assert.equal(parseTraceparent(`01-${id}-${parent}-01-future`)?.traceId, id, 'a later version may append fields');
  for (const bad of [undefined, '', `00-${id}-${parent}-01-x`, `ff-${id}-${parent}-01`, `00-${'0'.repeat(32)}-${parent}-01`,
    `00-${id}-${'0'.repeat(16)}-01`, `00-${id.toUpperCase()}-${parent}-01`, `00-${id}-${parent}`]) assert.equal(parseTraceparent(bad), undefined, String(bad));
  assert.equal(tracesUrl('http://collector:4318'), 'http://collector:4318/v1/traces');
  assert.equal(tracesUrl('https://otel.example/otlp/'), 'https://otel.example/otlp/v1/traces');
  for (const bad of ['collector:4318', 'ftp://c/', 'https://user:pw@c/', 'https://c/?token=x']) assert.throws(() => tracesUrl(bad));
  assert.equal(tracingFromEnv({}), undefined);
  assert.deepEqual(tracingFromEnv({ OTEL_EXPORTER_OTLP_ENDPOINT: 'http://c:4318', OTEL_SERVICE_NAME: 'gate-eu' }), { endpoint: 'http://c:4318', serviceName: 'gate-eu' });
});

test('each request exports a SERVER span with decision child spans, continuing the incoming trace, with no identifiers', async (t) => {
  const otlp = await receiver(t);
  const dir = mkdtempSync('/tmp/pdp-trace-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const server = createServer({ dataDir: dir, worldDir: resolve('examples/toy-domain'), clock: 'fixed:2026-11-08T10:00:00Z', tracing: { endpoint: otlp.url, serviceName: 'gate-test' } });
  await server.listen(0); t.after(() => server.close());
  const key = (JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string }).pepApiKey;
  const traceId = '4bf92f3577b34da6a3ce929d0e0e4736'; const parent = '00f067aa0ba902b7';
  const answer = await fetch(`${server.url}/access/v1/evaluations`, { method: 'POST',
    headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json', traceparent: `00-${traceId}-${parent}-01` },
    body: JSON.stringify({ evaluations: [evaluation('bob', 'CASE-14', 'read', 'trusted'), evaluation('bob', 'CASE-7', 'read', 'trusted')] }) });
  assert.equal(answer.status, 200);
  assert.equal((await fetch(`${server.url}/healthz`, { headers: { traceparent: `00-${traceId}-${parent}-00` } })).status, 200, 'unsampled: not recorded');
  assert.equal((await fetch(`${server.url}/xacml/v3/authorize`, { method: 'POST', headers: { authorization: 'Bearer wrong', 'content-type': 'application/json' }, body: '{}' })).status, 401);
  await server.flushTraces();

  assert.deepEqual(otlp.paths, ['POST /v1/traces application/json']);
  const request = otlp.spans.find((s) => s.name === 'POST evaluations');
  assert.ok(request); assert.equal(request.kind, 2); assert.equal(request.traceId, traceId); assert.equal(request.parentSpanId, parent);
  assert.equal(attribute(request, 'gate.route_family'), 'evaluations'); assert.equal(attribute(request, 'http.response.status_code'), 200);
  assert.equal(attribute(request, 'client.address'), '127.0.0.1', 'the client address (TRUSTED_PROXIES unset: the peer)');
  assert.ok(BigInt(request.endTimeUnixNano) >= BigInt(request.startTimeUnixNano));
  assert.ok(Math.abs(Number(BigInt(request.startTimeUnixNano) / 1_000_000n) - Date.now()) < 60_000, 'real time, not the pinned business clock');
  const children = otlp.spans.filter((s) => s.parentSpanId === request.spanId);
  assert.deepEqual(children.map((s) => [s.name, s.kind, attribute(s, 'gate.decision.effect')]), [['gate.decision', 1, 'allow'], ['gate.decision', 1, 'deny']]);
  assert.ok((attribute(children[1], 'gate.decision.rules') as string[]).length > 0);
  const refused = otlp.spans.find((s) => s.name === 'POST xacml');
  assert.equal(attribute(refused, 'http.response.status_code'), 401); assert.notEqual(refused?.traceId, traceId, 'a request without traceparent starts a trace');
  assert.equal(otlp.spans.some((s) => s.name.includes('health')), false);
  assert.match(otlp.bodies[0]!, /"service\.name","value":\{"stringValue":"gate-test"\}/);
  for (const secret of ['bob', 'CASE-14', 'CASE-7', key, 'Bearer', 'trusted']) assert.equal(otlp.bodies.join('').includes(secret), false, secret);
});

test('database commits and their failures are child spans; a large batch records at most the child-span cap', async (t) => {
  const otlp = await receiver(t);
  const tracer = new Tracer({ endpoint: otlp.url }); t.after(() => tracer.close());
  const f = fixture(t); let fail = false;
  f.rt.commit = async () => { if (fail) throw new Error('database detail'); };
  const handler = createHandler(f.rt, f.auth, { tracer, rateLimit: 10_000 }, () => 'http://localhost');
  const call = async (path: string, body: unknown): Promise<number> => {
    const socket = { remoteAddress: '127.0.0.1', readable: false } as ConstructorParameters<typeof IncomingMessage>[0];
    const req = new IncomingMessage(socket); req.url = path; req.method = 'POST';
    req.headers = { 'content-type': 'application/json', authorization: `Bearer ${f.pepApiKey}` };
    const res = new ServerResponse(req); res.end = (() => res) as unknown as typeof res.end;
    const pending = handler(req, res); req.push(JSON.stringify(body)); req.push(null); await pending;
    return res.statusCode;
  };
  assert.equal(await call('/access/v1/evaluation', evaluation()), 200);
  fail = true;
  assert.equal(await call('/access/v1/evaluation', evaluation()), 500);
  fail = false;
  // 200 decisions in one request: the cap keeps the trace bounded
  assert.equal(await call('/access/v1/evaluations', { evaluations: Array.from({ length: 2 * MAX_CHILD_SPANS }, () => evaluation()) }), 200);
  await tracer.flush();
  const servers = otlp.spans.filter((s) => s.kind === 2);
  assert.deepEqual(servers.map((s) => [s.name, s.status.code]), [['POST evaluation', 0], ['POST evaluation', 2], ['POST evaluations', 0]]);
  const under = (i: number): OtlpSpan[] => otlp.spans.filter((s) => s.parentSpanId === servers[i]!.spanId);
  assert.deepEqual(under(0).map((s) => [s.name, s.status.code]), [['gate.decision', 0], ['gate.commit', 0]]);
  assert.deepEqual(under(1).map((s) => s.name), ['gate.decision', 'gate.commit', 'gate.commit'], 'the failed commit, then the refusal commit');
  assert.equal(under(1)[1]?.status.code, 2);
  assert.equal(under(2).length, MAX_CHILD_SPANS);
  assert.ok(Number(attribute(servers[2], 'gate.dropped_child_spans')) > 0);
  assert.equal(otlp.bodies.join('').includes('database detail'), false);
});

test('export is batched, bounded and retried with backoff, and a dead collector never delays a request', async (t) => {
  const otlp = await receiver(t, [503, 400]);
  const tracer = new Tracer({ endpoint: otlp.url, maxQueue: 5, maxBatch: 2, backoffBaseMs: 30, timeoutMs: 1000 }); t.after(() => tracer.close());
  const span = (name: string) => tracer.trace(undefined, async () => { const { endRequestSpan } = await import('../src/tracing.ts'); endRequestSpan('GET', name, 200); });
  for (let i = 0; i < 7; i++) await span(`s${i}`);
  assert.equal(tracer.queued, 5); assert.equal(tracer.dropped, 2, 'the queue is bounded: newest spans past it are dropped');
  await tracer.flush();
  assert.deepEqual(otlp.status, [503], 'a retryable refusal stops the drain and starts a backoff');
  assert.equal(tracer.queued, 5, 'the refused batch is kept');
  await tracer.flush();
  assert.equal(otlp.status.length, 1, 'no new attempt during the backoff');
  await new Promise((r) => setTimeout(r, 40));
  await tracer.flush();
  assert.deepEqual(otlp.status, [503, 400, 200, 200], 'a non-retryable refusal drops that batch, the rest is delivered in batches');
  assert.equal(tracer.queued, 0); assert.equal(tracer.dropped, 4);
  assert.deepEqual(otlp.spans.map((s) => s.name), ['GET s2', 'GET s3', 'GET s4']);

  // a collector that never answers: requests are answered at once; the export times out in the background
  const hung = await receiver(t, ['hang']);
  const slow = new Tracer({ endpoint: hung.url, timeoutMs: 200 }); t.after(() => slow.close());
  const f = fixture(t);
  const handler = createHandler(f.rt, f.auth, { tracer: slow }, () => 'http://localhost');
  const socket = { remoteAddress: '127.0.0.1', readable: false } as ConstructorParameters<typeof IncomingMessage>[0];
  const get = async (): Promise<number> => { const req = new IncomingMessage(socket); req.url = '/healthz'; req.method = 'GET'; req.headers = {};
    const res = new ServerResponse(req); res.end = (() => res) as unknown as typeof res.end; const p = handler(req, res); req.push(null); await p; return res.statusCode; };
  assert.equal(await get(), 200);
  const exporting = slow.flush();
  await until(() => hung.status.length === 1);
  const started = performance.now();
  assert.equal(await get(), 200);
  assert.ok(performance.now() - started < 100, 'the request does not wait for the export');
  await exporting;
  assert.equal(slow.queued, 2, 'the timed-out batch is kept for a retry, with the span of the request answered meanwhile');
});
