import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createServer as createHttpServer, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import type { TestContext } from 'node:test';
import { BreakGlassNotifier, breakGlassFromEnv, NOTICE_SIGNATURE_HEADER, NOTICE_TIMESTAMP_HEADER, type BreakGlassNotice, type NoticeOutcome } from '../src/notify.ts';
import { createServer } from '../src/server.ts';
import { WHY } from './helpers.ts';

const SECRET = 'break-glass-test-secret-of-32-chars!';
const NOTICE: BreakGlassNotice = { event: 'opened', emergencyId: 'e-1', subjectId: 'dan', resourceId: 'CASE-12', actorId: 'amira', at: '2026-11-10T10:00:00.000Z' };

function stubFetch(answers: Array<number | Error>, seen: Array<{ url: string; init: RequestInit }>): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    seen.push({ url: String(url), init: init! });
    const next = answers.shift() ?? 200;
    if (next instanceof Error) throw next;
    return new Response(null, { status: next });
  }) as typeof fetch;
}

test('configuration: both variables or neither, https only, no query or credentials, 32-character secret', () => {
  assert.equal(breakGlassFromEnv({}), undefined);
  assert.throws(() => breakGlassFromEnv({ BREAK_GLASS_WEBHOOK: 'https://hooks.example/bg' }), /set together/);
  assert.deepEqual(breakGlassFromEnv({ BREAK_GLASS_WEBHOOK: 'https://hooks.example/bg', BREAK_GLASS_WEBHOOK_SECRET: SECRET }), { url: 'https://hooks.example/bg', secret: SECRET });
  const make = (url: string, secret = SECRET, hooks = {}) => new BreakGlassNotifier({ url, secret }, () => undefined, hooks);
  assert.throws(() => make('http://hooks.example/bg'), /https/);
  assert.throws(() => make('http://127.0.0.1:9/bg'), /https/); // loopback http is a test hook, not a default
  assert.throws(() => make('https://user:pw@hooks.example/bg'), /https/);
  assert.throws(() => make('https://hooks.example/bg?token=x'), /query string/);
  assert.throws(() => make('not a url'), /Invalid/);
  assert.throws(() => make('https://hooks.example/bg', 'short'), /32 characters/);
  assert.throws(() => new BreakGlassNotifier({ url: 'https://hooks.example/bg', secret: SECRET, maxAttempts: 0 }, () => undefined), /retry settings/);
  assert.ok(make('http://127.0.0.1:9/bg', SECRET, { allowLoopbackHttp: true }));
});

test('signed JSON with ids only, no redirects, bounded retries with backoff, outcome reported once', async () => {
  const seen: Array<{ url: string; init: RequestInit }> = [];
  const sleeps: number[] = [];
  const outcomes: NoticeOutcome[] = [];
  const timeout = Object.assign(new Error('slow'), { name: 'TimeoutError' });
  const notifier = new BreakGlassNotifier({ url: 'https://hooks.example/bg', secret: SECRET, backoffBaseMs: 100, backoffMaxMs: 250 },
    (_notice, result) => { outcomes.push(result); },
    { fetch: stubFetch([500, new Error('reset'), timeout, 204], seen), now: () => 1_762_768_800_000, sleep: async (ms) => { sleeps.push(ms); } });
  notifier.send(NOTICE);
  await notifier.settled();
  assert.equal(seen.length, 4);
  assert.deepEqual(sleeps, [100, 200, 250]);
  assert.deepEqual(outcomes, [{ outcome: 'sent', attempts: 4 }]);
  const { init } = seen[0]!;
  assert.equal(init.redirect, 'error');
  const headers = init.headers as Record<string, string>;
  const body = String(init.body);
  assert.equal(headers[NOTICE_TIMESTAMP_HEADER], '1762768800');
  assert.equal(headers[NOTICE_SIGNATURE_HEADER], `sha256=${createHmac('sha256', SECRET).update(`1762768800.${body}`).digest('hex')}`);
  const parsed = JSON.parse(body) as Record<string, unknown>;
  assert.deepEqual(Object.keys(parsed).sort(), ['actorId', 'at', 'emergencyId', 'event', 'id', 'resourceId', 'subjectId', 'type']);
  assert.ok(seen.every((s) => JSON.parse(String(s.init.body)).id === parsed.id), 'retries carry the same notice id');

  const failed: NoticeOutcome[] = [];
  const giveUp = new BreakGlassNotifier({ url: 'https://hooks.example/bg', secret: SECRET, maxAttempts: 2, backoffBaseMs: 0 },
    () => { failed.push({ outcome: 'failed', attempts: -1, error: 'x' }); throw new Error('report failed'); }, { fetch: stubFetch([503, timeout], []), sleep: async () => undefined });
  giveUp.send(NOTICE); // a throwing reporter is logged, never surfaced
  await giveUp.settled();
  assert.equal(failed.length, 1);
  const reasons: NoticeOutcome[] = [];
  const reasonOf = new BreakGlassNotifier({ url: 'https://hooks.example/bg', secret: SECRET, maxAttempts: 1 }, (_n, r) => { reasons.push(r); },
    { fetch: stubFetch([timeout], []) });
  reasonOf.send(NOTICE); await reasonOf.settled();
  assert.deepEqual(reasons, [{ outcome: 'failed', attempts: 1, error: 'timeout' }]);
});

interface Received { headers: IncomingHttpHeaders; body: string }
async function receiver(t: TestContext, status: () => number): Promise<{ url: string; received: Received[] }> {
  const received: Received[] = [];
  const server = createHttpServer((req, res) => {
    let body = '';
    req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
    req.on('end', () => { received.push({ headers: req.headers, body }); res.statusCode = status(); res.end(); });
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  t.after(() => new Promise<void>((done) => server.close(() => done())));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/notices`, received };
}

test('server: open and revoke notify at once, expiry is audited and notified once, failures are audited and counted', async (t) => {
  const dir = mkdtempSync('/tmp/pdp-notify-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let answer = 200;
  const hook = await receiver(t, () => answer);
  let clock = '2026-11-08T10:00:00.000Z';
  const server = createServer({ port: 0, dataDir: dir, clock: () => clock, breakGlass: { url: hook.url, secret: SECRET, maxAttempts: 2, backoffBaseMs: 0 },
    breakGlassHooks: { allowLoopbackHttp: true } });
  t.after(() => server.close());
  await server.listen();
  const { passwords } = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<string, string> };
  const call = async (path: string, method: string, body?: unknown, headers: Record<string, string> = {}) => {
    const res = await fetch(server.url + path, { method, headers: { 'content-type': 'application/json', ...headers }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const text = await res.text();
    return { status: res.status, cookie: res.headers.get('set-cookie')?.split(';')[0] ?? '', data: (text && res.headers.get('content-type')?.includes('json') ? JSON.parse(text) : text) as Record<string, unknown> };
  };
  const session = async (id: string) => {
    const r = await call('/admin/v1/session', 'POST', { username: id, password: passwords[id] });
    return { cookie: r.cookie, 'x-csrf-token': String(r.data.csrfToken) };
  };
  const amira = await session('amira'), lina = await session('lina');
  const opened = await call('/admin/v1/break-glass', 'POST', { subjectId: 'dan', resourceId: 'CASE-11', reason: WHY, hours: 1 }, amira); // one emergency per pair: the seed holds dan/CASE-12
  assert.equal(opened.status, 201);
  const id = String(opened.data.id);
  const second = await call('/admin/v1/break-glass', 'POST', { subjectId: 'dan', resourceId: 'CASE-14', reason: WHY, hours: 2 }, amira);
  assert.equal((await call(`/admin/v1/break-glass/${id}/revoke`, 'POST', { reason: WHY }, lina)).status, 200);
  await server.notifyExpired(); // nothing expired yet; waits for the notices in flight
  const events = () => hook.received.map((r) => JSON.parse(r.body) as Record<string, string>);
  assert.deepEqual(events().map((e) => [e.event, e.emergencyId, e.actorId]).sort(), [['opened', id, 'amira'], ['opened', String(second.data.id), 'amira'], ['revoked', id, 'lina']].sort());
  for (const r of hook.received) {
    const ts = String(r.headers[NOTICE_TIMESTAMP_HEADER]);
    assert.equal(r.headers[NOTICE_SIGNATURE_HEADER], `sha256=${createHmac('sha256', SECRET).update(`${ts}.${r.body}`).digest('hex')}`);
    assert.ok(!r.body.includes(WHY), 'the reason never leaves the server');
  }
  // three hours later: the second emergency (and any seeded one) has expired; the revoked one is not re-notified
  clock = '2026-11-08T13:00:00.000Z';
  hook.received.length = 0;
  await server.notifyExpired();
  const expired = events();
  assert.ok(expired.some((e) => e.event === 'expired' && e.emergencyId === second.data.id && e.actorId === 'system'));
  assert.ok(expired.every((e) => e.event === 'expired' && e.emergencyId !== id));
  await server.notifyExpired();
  assert.equal(events().length, expired.length, 'an expiry is notified once');
  const auditor = await session('sam');
  const rows = (await call('/admin/v1/audit?type=break_glass', 'GET', undefined, auditor)).data.items as Array<Record<string, unknown>>;
  assert.ok(rows.some((r) => r.action === 'expire' && (r.details as Record<string, unknown>).id === second.data.id));
  // a receiver that keeps failing: the request still succeeds, the failure is audited and counted
  answer = 500;
  const third = await call('/admin/v1/break-glass', 'POST', { subjectId: 'dan', resourceId: 'CASE-15', reason: WHY, hours: 1 }, await session('amira')); // the first session idled out
  assert.equal(third.status, 201);
  await server.notifyExpired();
  const failedRows = (await call('/admin/v1/audit?type=break_glass', 'GET', undefined, auditor)).data.items as Array<Record<string, unknown>>;
  const failure = failedRows.find((r) => r.action === 'notify_failed');
  assert.deepEqual(failure?.details, { id: third.data.id, event: 'opened', attempts: 2, error: 'HTTP 500' });
  const metrics = String((await call('/metrics', 'GET')).data);
  assert.match(metrics, /gate_break_glass_notices_total\{outcome="failed"\} 1\n/);
  assert.match(metrics, /gate_break_glass_notices_total\{outcome="sent"\} [1-9]\d*\n/);
});
