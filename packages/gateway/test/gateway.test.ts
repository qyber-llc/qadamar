// End to end: a fake JSON API upstream, the real PDP server on the toy domain, and the gateway between them.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as httpServer, request, type IncomingHttpHeaders, type IncomingMessage, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { TestContext } from 'node:test';
import { createServer, type PdpServer } from '../../pdp-http/src/server.ts';
import { AssertionVerifier, MASKED_TEXT, PepClient, withGateAssertion, type AssertionClaims } from '../../sdk/src/index.ts';
import { createGateway, type Caller, type DecisionLog, type GatewayOptions, type NotifyEvent } from '../src/index.ts';

interface Seen { method: string; url: string; headers: IncomingHttpHeaders; body: string }
interface Reply { status: number; headers: IncomingHttpHeaders; body: string; json: () => any }

const CASES = ['CASE-7', 'CASE-11', 'CASE-12', 'CASE-14', 'CASE-15', 'CASE-18'];
const caseRecord = (id: string, bare = false) => ({
  id, title: `Title of ${id}`, informant_name: 'Confidential Informant',
  ...(bare ? {} : { content: [{ class: 'public.summary', text: 'Summary stays readable' }, { class: 'finance.amount', text: 'AED 900,000' }] }),
});
const USERS: Record<string, Caller> = {
  'user-bob': { subject: { type: 'user', id: 'bob' } },
  'user-dan': { subject: { type: 'user', id: 'dan' } },
  'user-henry': { subject: { type: 'user', id: 'henry' }, context: { makerId: 'grace' } },
};
const ROUTES: GatewayOptions['routes'] = [
  { method: 'GET', path: '/cases', resourceType: 'case', action: 'read', list: { items: 'items' } },
  { method: 'GET', path: '/cases/:id', resourceType: 'case', action: 'read', query: ['bare'] },
  { method: 'POST', path: '/cases/:id', resourceType: 'case', action: 'update' },
  { method: 'GET', path: '/slow/:id', resourceType: 'case', action: 'read' },
  { method: 'POST', path: '/payments/:id/approve', resourceType: 'payment', action: 'approve' },
  { method: 'GET', path: '/folders/:id', resourceType: 'folder', action: 'read' },
];

let pdp: PdpServer | undefined;
let upstream: Server | undefined;
let upstreamUrl = '';
let pepApiKey = '';
let dir = '';
const seen: Seen[] = [];

before(async () => {
  dir = mkdtempSync(join(tmpdir(), 'gateway-test-'));
  pdp = createServer({ port: 0, dataDir: resolve(dir, 'pdp'), worldDir: resolve('examples/toy-domain'), clock: 'fixed:2026-11-08T10:00:00Z', sodHistory: 'caller' });
  await pdp.listen();
  pepApiKey = (JSON.parse(readFileSync(resolve(dir, 'pdp/INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string }).pepApiKey;
  upstream = httpServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url ?? '/', 'http://upstream');
      seen.push({ method: req.method ?? '', url: req.url ?? '', headers: req.headers, body: Buffer.concat(chunks).toString() });
      res.setHeader('connection', 'x-upstream-hop');
      res.setHeader('x-upstream-hop', 'hop-secret');
      res.setHeader('proxy-authenticate', 'Basic realm="upstream"');
      res.setHeader('etag', '"original-body"');
      res.setHeader('x-request-id', 'r-1');
      const send = (status: number, value: unknown): void => { res.statusCode = status; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(value)); };
      const one = /^\/cases\/([^/]+)$/.exec(url.pathname);
      if (url.pathname.startsWith('/slow/')) {
        // headers at once, then a byte every 20 ms: never idle long enough for a socket timeout
        res.writeHead(200, { 'content-type': 'application/json' });
        const drip = setInterval(() => res.write(' '), 20);
        res.on('close', () => clearInterval(drip));
        setTimeout(() => { clearInterval(drip); res.end('{}'); }, 2000);
        return;
      }
      if (req.method === 'GET' && url.pathname === '/cases') send(200, { total: CASES.length, items: CASES.map((id) => caseRecord(id, id !== 'CASE-14')) });
      else if (req.method === 'GET' && one) send(200, caseRecord(decodeURIComponent(one[1] ?? ''), url.searchParams.has('bare')));
      else if (req.method === 'POST' && one) send(200, caseRecord(decodeURIComponent(one[1] ?? '')));
      else if (req.method === 'POST' && url.pathname === '/payments/PAY-3/approve') send(200, { ok: true, payment: 'PAY-3' });
      else if (url.pathname.startsWith('/rejected/')) send(422, { error: 'invalid payment' });
      else send(500, { error: 'upstream detail AED 900,000' });
    });
  });
  await new Promise<void>((accept) => upstream?.listen(0, '127.0.0.1', accept));
  const address = upstream.address();
  upstreamUrl = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
});
after(async () => {
  upstream?.closeAllConnections();
  await new Promise<void>((accept) => (upstream ? upstream.close(() => accept()) : accept()));
  await pdp?.close();
  rmSync(dir, { recursive: true, force: true });
});

async function gateway(t: TestContext, over: Partial<GatewayOptions> = {}): Promise<{ url: string; logs: DecisionLog[] }> {
  const logs: DecisionLog[] = [];
  const gw = createGateway({
    upstream: upstreamUrl, pdp: new PepClient({ baseUrl: pdp?.url ?? '', apiKey: pepApiKey }), routes: ROUTES,
    authenticate: (req: IncomingMessage) => USERS[String(req.headers.authorization ?? '').replace(/^Bearer /, '')],
    trustedNetworks: ['127.0.0.0/8', '::1/128'], log: (e) => logs.push(e), ...over,
  });
  await gw.listen();
  t.after(() => gw.close());
  return { url: gw.url, logs };
}
function call(base: string, path: string, options: { method?: string; headers?: Record<string, string>; body?: string } = {}): Promise<Reply> {
  return new Promise((accept, reject) => {
    const req = request(`${base}${path}`, { method: options.method ?? 'GET', headers: options.headers, agent: false }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString();
        accept({ status: res.statusCode ?? 0, headers: res.headers, body, json: () => JSON.parse(body) });
      });
    });
    req.on('error', reject);
    req.end(options.body);
  });
}
const as = (token: string, extra: Record<string, string> = {}): Record<string, string> => ({ authorization: `Bearer ${token}`, ...extra });
const upstreamCalls = (): number => seen.length;

test('a denied read is refused with 403 and never reaches the upstream', async (t) => {
  const { url, logs } = await gateway(t);
  const before = upstreamCalls();
  const r = await call(url, '/cases/CASE-7', { headers: as('user-bob') });
  assert.equal(r.status, 403);
  assert.deepEqual(r.json(), { error: 'forbidden' });
  assert.equal(upstreamCalls(), before);
  assert.equal(logs.length, 1);
  assert.equal(logs[0]?.outcome, 'deny');
  assert.equal(logs[0]?.resource, 'CASE-7');
  assert.ok(logs[0]?.rules?.length);
});

test('an allowed read is released with fields redacted and content classes masked', async (t) => {
  const { url, logs } = await gateway(t);
  const r = await call(url, '/cases/CASE-14', { headers: as('user-bob') });
  assert.equal(r.status, 200);
  const body = r.json();
  assert.equal(body.informant_name, null);
  assert.equal(body.content[0].text, 'Summary stays readable');
  assert.equal(body.content[1].text, MASKED_TEXT);
  assert.equal(body.title, 'Title of CASE-14');
  assert.equal(r.headers.etag, undefined, 'a validator of the unredacted body is not released');
  assert.equal(r.headers['x-request-id'], 'r-1');
  assert.equal(r.headers['cache-control'], 'no-store');
  assert.deepEqual(logs.map((l) => [l.outcome, l.resource, l.status]), [['allow', 'CASE-14', 200]]);
  const logged = JSON.stringify(logs);
  for (const secret of ['Confidential Informant', 'AED', pepApiKey, 'Bearer']) assert.ok(!logged.includes(secret), `log holds ${secret}`);
});

test('the attestation hook signs the fully resolved context sent to the PDP', async (t) => {
  let decisionContext: Record<string, unknown> | undefined;
  const recordingFetch: typeof fetch = async (input, init) => {
    if (String(input).endsWith('/x/v1/assertions/evaluation')) decisionContext = (JSON.parse(String(init?.body)) as { context: Record<string, unknown> }).context;
    return fetch(input, init);
  };
  const { url } = await gateway(t, {
    pdp: new PepClient({ baseUrl: pdp?.url ?? '', apiKey: pepApiKey, fetch: recordingFetch }),
    attestContext: (context) => {
      assert.equal(context.network, 'trusted');
      assert.equal(context.ip, '127.0.0.1');
      return { network: 'signed-network-attestation' };
    },
  });
  assert.equal((await call(url, '/cases/CASE-14', { headers: as('user-bob') })).status, 200);
  assert.equal(decisionContext?.network, 'trusted');
  assert.deepEqual(decisionContext?.attestations, { network: 'signed-network-attestation' });
});

test('the gateway passes a PDP session token and a second token cannot reset its mark', async (t) => {
  const client = new PepClient({ baseUrl: pdp?.url ?? '', apiKey: pepApiKey });
  const first = await client.openSession({ type: 'user', id: 'carol' });
  const reading = await gateway(t, { authenticate: () => ({ subject: { type: 'user', id: 'carol' }, context: { sessionToken: first.token } }) });
  assert.equal((await call(reading.url, '/cases/CASE-14')).status, 200);
  const second = await client.openSession({ type: 'user', id: 'carol' });
  const before = upstreamCalls();
  const writing = await gateway(t, { authenticate: () => ({ subject: { type: 'user', id: 'carol' }, context: { sessionToken: second.token, sessionLevel: 1 } }) });
  const denied = await call(writing.url, '/cases/CASE-11', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  assert.equal(denied.status, 403);
  assert.equal(upstreamCalls(), before, 'the write-down never reached the upstream');
  assert.ok(writing.logs.at(-1)?.rules?.includes('BLP.HIGH_WATER'));
  await client.closeSession(first.token);
  await client.closeSession(second.token);
});

test('a class the response does not carry cannot be masked: the record is refused', async (t) => {
  const { url } = await gateway(t);
  const r = await call(url, '/cases/CASE-14?bare=1', { headers: as('user-bob') });
  assert.equal(r.status, 502);
  assert.deepEqual(r.json(), { error: 'obligation_unenforceable' });
  assert.ok(!r.body.includes('Confidential'));
});

test('a list keeps only the allowed items, each with its own obligations, and drops sibling counts', async (t) => {
  const { url, logs } = await gateway(t);
  const client = new PepClient({ baseUrl: pdp?.url ?? '', apiKey: pepApiKey });
  const allowed: string[] = [];
  for (const id of CASES) {
    if ((await client.evaluate({ subject: { type: 'user', id: 'bob' }, action: { name: 'read' }, resource: { type: 'case', id }, context: { network: 'trusted' } })).decision) allowed.push(id);
  }
  assert.ok(allowed.includes('CASE-14') && !allowed.includes('CASE-7'));
  const r = await call(url, '/cases', { headers: as('user-bob') });
  assert.equal(r.status, 200);
  const body = r.json();
  assert.deepEqual(Object.keys(body), ['items']);
  assert.deepEqual(body.items.map((i: { id: string }) => i.id), allowed);
  for (const item of body.items) assert.equal(item.informant_name, null);
  assert.equal(body.items.find((i: { id: string }) => i.id === 'CASE-14').content[1].text, MASKED_TEXT);
  assert.equal(logs.length, CASES.length);
  assert.deepEqual(logs.filter((l) => l.outcome === 'deny').map((l) => l.resource), CASES.filter((id) => !allowed.includes(id)));
});

test('a notify obligation is refused without a hook, and carried out with ids only when one is configured', async (t) => {
  const plain = await gateway(t);
  const before = upstreamCalls();
  const refused = await call(plain.url, '/cases/CASE-12', { headers: as('user-dan') });
  assert.equal(refused.status, 502);
  assert.deepEqual(refused.json(), { error: 'obligation_unenforceable' });
  assert.equal(upstreamCalls(), before, 'nothing ran upstream');
  const events: NotifyEvent[] = [];
  const hooked = await gateway(t, { notify: async (e) => { events.push(e); } });
  const r = await call(hooked.url, '/cases/CASE-12', { headers: as('user-dan') });
  assert.equal(r.status, 200);
  assert.equal(events.length, 1);
  assert.deepEqual({ ...events[0], policyVersion: '' }, { recipients: ['security-officer'], subject: { type: 'user', id: 'dan' },
    resource: { type: 'case', id: 'CASE-12' }, action: 'read', policyVersion: '' });
  const failing = await gateway(t, { notify: async () => { throw new Error('mail relay down'); } });
  assert.equal((await call(failing.url, '/cases/CASE-12', { headers: as('user-dan') })).status, 502);
});

test('an obligation the gateway does not know is refused before anything is forwarded', async (t) => {
  const injecting: typeof fetch = async (input, init) => {
    const response = await fetch(input, init);
    const value = await response.json() as { context?: { obligations?: Record<string, unknown> } };
    if (value.context?.obligations) value.context.obligations.watermark = ['viewer-id'];
    return new Response(JSON.stringify(value), { status: response.status, headers: { 'content-type': 'application/json' } });
  };
  const { url } = await gateway(t, { pdp: new PepClient({ baseUrl: pdp?.url ?? '', apiKey: pepApiKey, fetch: injecting }) });
  const before = upstreamCalls();
  const r = await call(url, '/cases/CASE-14', { headers: as('user-bob') });
  assert.equal(r.status, 502);
  assert.deepEqual(r.json(), { error: 'unenforceable_decision' });
  assert.equal(upstreamCalls(), before);
});

test('hop-by-hop headers and credentials never cross the gateway, in either direction', async (t) => {
  const { url } = await gateway(t);
  const before = upstreamCalls();
  const r = await call(url, '/cases/CASE-11', { headers: as('user-bob', {
    connection: 'x-client-hop', 'x-client-hop': 'client-secret', 'proxy-authorization': 'Basic cHJveHk6c2VjcmV0', te: 'trailers',
    cookie: 'sid=session-secret', 'x-forwarded-for': '10.9.9.9', forwarded: 'for=10.9.9.9', 'x-trace': 'dropped',
    'x-user': 'admin', 'x-api-key': 'k', accept: 'application/json', 'if-none-match': '"v1"',
  }) });
  assert.equal(r.status, 200);
  const sent = seen[before];
  assert.ok(sent);
  for (const name of ['authorization', 'proxy-authorization', 'x-client-hop', 'te', 'cookie', 'x-forwarded-for', 'forwarded', 'x-trace', 'x-user', 'x-api-key']) {
    assert.equal(sent.headers[name], undefined, name);
  }
  assert.equal(sent.headers.accept, 'application/json');
  assert.equal(sent.headers['if-none-match'], undefined, 'a conditional GET would come back 304, which the gateway refuses (502)');
  assert.equal(sent.headers['accept-encoding'], 'identity');
  assert.ok(!JSON.stringify(sent.headers).includes(pepApiKey), 'the PEP credential is never forwarded');
  assert.ok(!JSON.stringify(sent.headers).includes('Bearer'), 'the caller credential is not forwarded');
  assert.equal(r.headers['x-upstream-hop'], undefined);
  assert.equal(r.headers['proxy-authenticate'], undefined);
});

test('requests outside the route table, without identity, oversized or with an ambiguous id are refused', async (t) => {
  const { url } = await gateway(t, { maxBodyBytes: 64 });
  const before = upstreamCalls();
  assert.equal((await call(url, '/admin', { headers: as('user-bob') })).status, 404);
  assert.equal((await call(url, '/cases/CASE-14', { method: 'DELETE', headers: as('user-bob') })).status, 404);
  assert.equal((await call(url, '/cases/CASE-14')).status, 401);
  assert.equal((await call(url, '/cases/CASE-14', { headers: as('user-nobody') })).status, 401);
  assert.equal((await call(url, '/cases/CASE-14%2F..%2FCASE-7', { headers: as('user-bob') })).status, 400);
  assert.equal((await call(url, '/cases/%E0%A4%A', { headers: as('user-bob') })).status, 400);
  const big = await call(url, '/payments/PAY-3/approve', { method: 'POST', headers: as('user-henry', { 'content-type': 'application/json' }), body: JSON.stringify({ note: 'x'.repeat(200) }) });
  assert.equal(big.status, 413);
  assert.equal(upstreamCalls(), before);
});

test('an unreachable PDP or upstream fails closed', async (t) => {
  const down = await gateway(t, { pdp: new PepClient({ baseUrl: 'http://127.0.0.1:9', apiKey: 'unused', timeoutMs: 2000 }) });
  assert.deepEqual((await call(down.url, '/cases/CASE-14', { headers: as('user-bob') })).json(), { error: 'pdp_unavailable' });
  const gone = await gateway(t, { upstream: 'http://127.0.0.1:9' });
  assert.equal((await call(gone.url, '/cases/CASE-14', { headers: as('user-bob') })).status, 502);
  // an upstream error page is not released: it could hold what the obligations hide
  const failing = await gateway(t);
  const r = await call(failing.url, '/folders/FOLDER-A', { headers: as('user-bob') });
  assert.equal(r.status, 500);
  assert.deepEqual(r.json(), { error: 'upstream_error' });
  assert.throws(() => createGateway({ upstream: 'http://127.0.0.1:1/api', pdp: new PepClient({ baseUrl: 'http://127.0.0.1:1', apiKey: 'k' }), routes: ROUTES, authenticate: () => undefined }), TypeError);
  assert.throws(() => createGateway({ upstream: upstreamUrl, pdp: new PepClient({ baseUrl: 'http://127.0.0.1:1', apiKey: 'k' }), routes: [{ method: 'POST', path: '/cases', resourceType: 'case', action: 'read', list: { items: 'items' } }], authenticate: () => undefined }), TypeError);
  assert.throws(() => createGateway({ upstream: upstreamUrl, pdp: new PepClient({ baseUrl: 'http://127.0.0.1:1', apiKey: 'k' }), routes: ROUTES, authenticate: () => undefined, trustedNetworks: ['10.0.0.0/33'] }), TypeError);
  // an earlier route that matches every path a later one does would decide the later one's requests with the wrong action
  const shadowed = [{ method: 'GET', path: '/cases/:id', resourceType: 'case', action: 'read' }, { method: 'GET', path: '/cases/export', resourceType: 'case', action: 'export', list: { items: 'items' } }];
  assert.throws(() => createGateway({ upstream: upstreamUrl, pdp: new PepClient({ baseUrl: 'http://127.0.0.1:1', apiKey: 'k' }), routes: shadowed, authenticate: () => undefined }), /shadowed/);
});

test('a certified command consumes its decision token before it is forwarded, so the PDP records who did it', async (t) => {
  const { url } = await gateway(t);
  const before = upstreamCalls();
  const r = await call(url, '/payments/PAY-3/approve', { method: 'POST', headers: as('user-henry', { 'content-type': 'application/json' }), body: '{}' });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json(), { ok: true, payment: 'PAY-3' });
  assert.equal(upstreamCalls(), before + 1);
  // the consumption made henry the recorded maker: the caller's contrary maker claim now denies (SOD.MAKER_MISMATCH)
  const again = await call(url, '/payments/PAY-3/approve', { method: 'POST', headers: as('user-henry', { 'content-type': 'application/json' }), body: '{}' });
  assert.equal(again.status, 403);
  assert.equal(upstreamCalls(), before + 1);
});

test('behind a PDP with SOD_HISTORY=server, a maker the caller asserts does not open a certified command', async (t) => {
  const strictDir = mkdtempSync(join(tmpdir(), 'gateway-sod-'));
  const strict = createServer({ port: 0, dataDir: strictDir, worldDir: resolve('examples/toy-domain'), clock: 'fixed:2026-11-08T10:00:00Z', sodHistory: 'server' });
  await strict.listen();
  t.after(async () => { await strict.close(); rmSync(strictDir, { recursive: true, force: true }); });
  const key = (JSON.parse(readFileSync(resolve(strictDir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string }).pepApiKey;
  const { url, logs } = await gateway(t, { pdp: new PepClient({ baseUrl: strict.url, apiKey: key }) });
  const before = upstreamCalls();
  const r = await call(url, '/payments/PAY-3/approve', { method: 'POST', headers: as('user-henry', { 'content-type': 'application/json' }), body: '{}' });
  assert.equal(r.status, 403, 'henry\'s makerId "grace" is ignored: no recorded maker, so the two-person rule fails closed');
  assert.equal(upstreamCalls(), before);
  assert.ok(logs.at(-1)?.rules?.includes('SOD.MAKER_UNKNOWN'), JSON.stringify(logs.at(-1)));
});

test('the gateway reports what became of a consumed certified command: 2xx completed, a 4xx refusal or no connection failed', async (t) => {
  const own = mkdtempSync(join(tmpdir(), 'gateway-outcome-'));
  const server = createServer({ port: 0, dataDir: own, worldDir: resolve('examples/toy-domain'), clock: 'fixed:2026-11-08T10:00:00Z', sodHistory: 'caller' });
  await server.listen();
  t.after(async () => { await server.close(); rmSync(own, { recursive: true, force: true }); });
  const key = (JSON.parse(readFileSync(resolve(own, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string }).pepApiKey;
  const client = new PepClient({ baseUrl: server.url, apiKey: key });
  const routes = [...ROUTES, { method: 'POST' as const, path: '/rejected/:id/approve', resourceType: 'payment', action: 'approve' }];
  const approve = (url: string, path: string) => call(url, path, { method: 'POST', headers: as('user-henry', { 'content-type': 'application/json' }), body: '{}' });
  // the upstream refuses with 422 on /rejected: the approval did not happen, so it does not count and can be retried
  const { url, logs } = await gateway(t, { pdp: client, routes });
  assert.equal((await approve(url, '/rejected/PAY-3/approve')).status, 422);
  assert.equal(logs.at(-1)?.reservation, 'failed');
  // the upstream cannot be reached at all: the request never left, so failed as well
  const gone = await gateway(t, { pdp: client, routes, upstream: 'http://127.0.0.1:9' });
  assert.equal((await approve(gone.url, '/payments/PAY-3/approve')).status, 502);
  assert.equal(gone.logs.at(-1)?.reservation, 'failed');
  const r = await approve(url, '/payments/PAY-3/approve');
  assert.equal(r.status, 200, 'the failed attempts left no history: henry still approves');
  assert.equal(logs.at(-1)?.reservation, 'completed');
  assert.equal((await approve(url, '/payments/PAY-3/approve')).status, 403, 'the completed approval counts: henry is the recorded maker now');
  const rows = readFileSync(resolve(own, 'audit.jsonl'), 'utf8').trim().split('\n').map((line) => JSON.parse(line) as { rules?: string[]; details?: { phase?: string } });
  const reported = rows.filter((row) => row.details?.phase === 'outcome').map((row) => row.rules);
  assert.deepEqual(reported, [['GATE.ACTION_FAILED'], ['GATE.ACTION_FAILED'], ['GATE.ACTION_COMPLETED']]);
});

test('a 5xx answer leaves the reservation pending: the command may have run, so it still counts for SoD', async (t) => {
  const own = mkdtempSync(join(tmpdir(), 'gateway-pending-'));
  const server = createServer({ port: 0, dataDir: own, worldDir: resolve('examples/toy-domain'), clock: 'fixed:2026-11-08T10:00:00Z', sodHistory: 'caller' });
  await server.listen();
  t.after(async () => { await server.close(); rmSync(own, { recursive: true, force: true }); });
  const key = (JSON.parse(readFileSync(resolve(own, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string }).pepApiKey;
  const routes = [...ROUTES, { method: 'POST' as const, path: '/broken/:id/approve', resourceType: 'payment', action: 'approve' }];
  const { url, logs } = await gateway(t, { pdp: new PepClient({ baseUrl: server.url, apiKey: key }), routes });
  const approve = (path: string) => call(url, path, { method: 'POST', headers: as('user-henry', { 'content-type': 'application/json' }), body: '{}' });
  assert.equal((await approve('/broken/PAY-3/approve')).status, 500);
  assert.equal(logs.at(-1)?.reservation, 'pending');
  assert.equal((await approve('/payments/PAY-3/approve')).status, 403, 'the pending reservation still makes henry the maker');
});

test('request headers are an allowlist: a route may add its own, never credentials or method overrides', async (t) => {
  const routes = ROUTES.map((r) => (r.path === '/cases/:id' ? { ...r, headers: ['x-trace'] } : r));
  const { url } = await gateway(t, { routes });
  const before = upstreamCalls();
  assert.equal((await call(url, '/cases/CASE-11', { headers: as('user-bob', { 'x-trace': 't-1', 'x-user': 'admin' }) })).status, 200);
  assert.equal(seen[before]?.headers['x-trace'], 't-1');
  assert.equal(seen[before]?.headers['x-user'], undefined);
  const make = (extra: Partial<GatewayOptions['routes'][number]>) => () => createGateway({ upstream: upstreamUrl, pdp: new PepClient({ baseUrl: 'http://127.0.0.1:1', apiKey: 'k' }),
    routes: [{ method: 'GET', path: '/cases/:id', resourceType: 'case', action: 'read', ...extra }], authenticate: () => undefined });
  for (const bad of [{ headers: ['authorization'] }, { headers: ['X-Trace'] }, { headers: ['x-http-method-override'] }, { headers: ['x-forwarded-host'] },
    { query: ['_method'] }, { query: [''] }, { postState: 'json' as never }]) assert.throws(make(bad), TypeError, JSON.stringify(bad));
});

test('a method override, in a header or as _method, is refused before anything runs; undeclared query parameters are dropped', async (t) => {
  const { url, logs } = await gateway(t);
  const before = upstreamCalls();
  for (const name of ['x-http-method-override', 'x-method-override', 'x-http-method']) {
    const r = await call(url, '/payments/PAY-3/approve', { method: 'POST', headers: as('user-henry', { 'content-type': 'application/json', [name]: 'DELETE' }), body: '{}' });
    assert.equal(r.status, 400, name);
  }
  assert.equal((await call(url, '/payments/PAY-3/approve?_method=DELETE', { method: 'POST', headers: as('user-henry', { 'content-type': 'application/json' }), body: '{}' })).status, 400);
  assert.equal((await call(url, '/cases/CASE-11?_method=DELETE', { headers: as('user-bob') })).status, 400);
  assert.equal(upstreamCalls(), before, 'nothing reached the upstream');
  assert.ok(logs.every((l) => l.outcome === 'refused' && l.code === 'bad_request'));
  assert.equal((await call(url, '/cases/CASE-11?bare=1&role=admin&bare=2', { headers: as('user-bob') })).status, 200);
  assert.equal(seen.at(-1)?.url, '/cases/CASE-11?bare=1&bare=2', 'only the declared parameter is forwarded');
  assert.equal((await call(url, '/cases/CASE-11?role=admin', { headers: as('user-bob') })).status, 200);
  assert.equal(seen.at(-1)?.url, '/cases/CASE-11');
});

test('the upstream timeout covers the whole exchange: a response dripping a byte at a time is cut', async (t) => {
  const { url } = await gateway(t, { upstreamTimeoutMs: 300 });
  const started = Date.now();
  const r = await call(url, '/slow/CASE-14', { headers: as('user-bob') });
  assert.equal(r.status, 504);
  assert.deepEqual(r.json(), { error: 'upstream_timeout' });
  assert.ok(Date.now() - started < 1500, `${Date.now() - started} ms`);
});

test('behind a PDP with IVPs, a certified command sends the request body as the post-state, or is refused', async (t) => {
  const world = mkdtempSync(join(tmpdir(), 'gateway-ivp-world-'));
  const dataDir = mkdtempSync(join(tmpdir(), 'gateway-ivp-'));
  t.after(() => { rmSync(world, { recursive: true, force: true }); rmSync(dataDir, { recursive: true, force: true }); });
  const bundle = JSON.parse(readFileSync(resolve('examples/toy-domain/bundle.json'), 'utf8')) as { clarkWilson: Record<string, unknown> };
  bundle.clarkWilson.ivps = [{ id: 'payment-status', description: 'A payment has a known status', resourceTypes: ['payment'],
    check: { op: 'in', left: { path: 'resource.attrs.status' }, right: { value: ['pending', 'approved', 'released'] } } }];
  mkdirSync(world, { recursive: true });
  writeFileSync(join(world, 'bundle.json'), JSON.stringify(bundle));
  writeFileSync(join(world, 'world.json'), readFileSync(resolve('examples/toy-domain/world.json')));
  const checked = createServer({ port: 0, dataDir, worldDir: world, clock: 'fixed:2026-11-08T10:00:00Z', sodHistory: 'caller' });
  await checked.listen();
  t.after(() => checked.close());
  const key = (JSON.parse(readFileSync(resolve(dataDir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string }).pepApiKey;
  const pep = new PepClient({ baseUrl: checked.url, apiKey: key });
  const approve = (url: string, body: string, type = 'application/json') =>
    call(url, '/payments/PAY-3/approve', { method: 'POST', headers: as('user-henry', { 'content-type': type }), body });
  const before = upstreamCalls();
  // a route that does not declare its post-state cannot be checked: refused before the token is spent
  const blind = await gateway(t, { pdp: pep });
  assert.deepEqual((await approve(blind.url, '{"status":"approved"}')).json(), { error: 'obligation_unenforceable' });
  const routes = ROUTES.map((r) => (r.path === '/payments/:id/approve' ? { ...r, postState: 'body' as const } : r));
  const { url } = await gateway(t, { pdp: pep, routes });
  assert.equal((await approve(url, 'not json')).status, 400);
  assert.equal((await approve(url, '[]')).status, 400);
  assert.equal((await approve(url, '{"status":"approved"}', 'text/plain')).status, 400);
  const invalid = await approve(url, '{"status":"lost"}');
  assert.equal(invalid.status, 409, 'the IVP refuses the state the upstream would commit');
  assert.equal(upstreamCalls(), before, 'nothing ran upstream');
  const ok = await approve(url, '{"status":"approved"}');
  assert.equal(ok.status, 200);
  assert.equal(upstreamCalls(), before + 1);
  assert.equal(seen.at(-1)?.body, '{"status":"approved"}');
});

test('behind a PDP with input validators, the body is the command input judged at decision (C5)', async (t) => {
  const world = mkdtempSync(join(tmpdir(), 'gateway-c5-world-'));
  const dataDir = mkdtempSync(join(tmpdir(), 'gateway-c5-'));
  t.after(() => { rmSync(world, { recursive: true, force: true }); rmSync(dataDir, { recursive: true, force: true }); });
  const bundle = JSON.parse(readFileSync(resolve('examples/toy-domain/bundle.json'), 'utf8')) as { clarkWilson: Record<string, unknown> };
  bundle.clarkWilson.inputValidators = [{ id: 'approve-body', description: 'status only', resourceTypes: ['payment'], actions: ['approve'],
    fields: { status: { type: 'string', required: true, enum: ['approved'] } } }];
  writeFileSync(join(world, 'bundle.json'), JSON.stringify(bundle));
  writeFileSync(join(world, 'world.json'), readFileSync(resolve('examples/toy-domain/world.json')));
  const checked = createServer({ port: 0, dataDir, worldDir: world, clock: 'fixed:2026-11-08T10:00:00Z', sodHistory: 'caller' });
  await checked.listen();
  t.after(() => checked.close());
  const key = (JSON.parse(readFileSync(resolve(dataDir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string }).pepApiKey;
  const pep = new PepClient({ baseUrl: checked.url, apiKey: key });
  const approve = (url: string, body: string) => call(url, '/payments/PAY-3/approve', { method: 'POST', headers: as('user-henry', { 'content-type': 'application/json' }), body });
  const before = upstreamCalls();
  const blind = await gateway(t, { pdp: pep });
  assert.equal((await approve(blind.url, '{"status":"approved"}')).status, 403, 'a route that does not hand its body over has no input to validate');
  const { url } = await gateway(t, { pdp: pep, routes: ROUTES.map((r) => (r.path === '/payments/:id/approve' ? { ...r, postState: 'body' as const } : r)) });
  assert.equal((await approve(url, '{"status":"approved","amount":1}')).status, 403, 'an undeclared field denies');
  assert.equal((await approve(url, '{"status":"rejected"}')).status, 403);
  assert.equal(upstreamCalls(), before);
  assert.equal((await approve(url, '{"status":"approved"}')).status, 200);
  assert.equal(upstreamCalls(), before + 1);
});

test('every forwarded request carries a PDP-signed assertion the backend verifies; a direct, replayed or re-targeted call is refused', async (t) => {
  const claims: AssertionClaims[] = []; const headers: string[] = [];
  let verifier: AssertionVerifier | undefined;
  const backend = httpServer(withGateAssertion({ verify: (r: Parameters<AssertionVerifier['verify']>[0]) => verifier!.verify(r) } as AssertionVerifier, (req, res, v) => {
    claims.push(v.claims); headers.push(String(req.headers['gate-assertion']));
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(v.claims.res.id ? caseRecord(v.claims.res.id) : { items: CASES.map((id) => caseRecord(id, id !== 'CASE-14')) }));
  }));
  await new Promise<void>((accept) => backend.listen(0, '127.0.0.1', accept));
  t.after(() => new Promise<void>((accept) => { backend.closeAllConnections(); backend.close(() => accept()); }));
  const address = backend.address();
  const origin = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
  // the PDP runs on a fixed demo clock; the backend's clock follows it
  verifier = new AssertionVerifier({ jwksUrl: `${pdp?.url}/.well-known/jwks.json`, audience: origin, now: () => Date.parse('2026-11-08T10:00:05Z') });
  const { url, logs } = await gateway(t, { upstream: origin, authenticate: (req: IncomingMessage) =>
    String(req.headers.authorization) === 'Bearer user-ghost' ? { subject: { type: 'user', id: 'ghost' } } : USERS[String(req.headers.authorization ?? '').replace(/^Bearer /, '')] });
  const one = await call(url, '/cases/CASE-14', { headers: as('user-bob', { 'gate-assertion': 'forged-by-the-client' }) });
  assert.equal(one.status, 200, one.body);
  const first = required(claims[0]);
  assert.deepEqual([first.sub, first.act, first.res, first.htm, first.htp, first.aud], [{ type: 'user', id: 'bob' }, 'read', { type: 'case', id: 'CASE-14' }, 'GET', '/cases/CASE-14', origin]);
  assert.equal(first.exp - first.iat, 30);
  assert.ok(pdp && JSON.stringify(readFileSync(resolve(dir, 'pdp/audit.jsonl'), 'utf8')).includes(first.did), 'the decision id is in the PDP audit');
  const list = await call(url, '/cases', { headers: as('user-bob') });
  assert.equal(list.status, 200);
  assert.deepEqual(required(claims[1]).res, { type: 'case' }, 'a list assertion names the type, not an item');
  // a subject the PDP knows nothing about: no assertion, no upstream call, an empty list
  const ghost = await call(url, '/cases', { headers: as('user-ghost') });
  assert.deepEqual([ghost.status, ghost.json()], [200, { items: [] }]);
  assert.equal(claims.length, 2);
  assert.equal(logs.at(-1)?.outcome, 'deny');
  const direct = (path: string, header?: string): Promise<Reply> => call(origin, path, { headers: header ? { 'gate-assertion': header } : {} });
  assert.equal((await direct('/cases/CASE-14')).status, 401, 'a call around the gateway');
  assert.equal((await direct('/cases/CASE-14', required(headers[0]))).json().error, 'assertion_replayed');
  assert.equal((await direct('/cases/CASE-7', required(headers[0]))).json().error, 'assertion_mismatch');
});

test('client headers cannot spoof the socket IP or the authenticated session MFA and authentication facts', async (t) => {
  let observed: Record<string, unknown> | undefined;
  const stub = { evaluateAsserted: async (request: Record<string, unknown>) => {
    observed = request;
    return { decision: false, context: { rules: ['CBAC.MFA_STALE'], reasons: [], obligations: { redact: [], maskClasses: [], notify: [] }, policy_version: 'pv.test', would_deny: [] } };
  } } as unknown as PepClient;
  const { url } = await gateway(t, { pdp: stub, authenticate: () => ({ subject: { type: 'user', id: 'bob' }, context: {
    ip: '192.0.2.99', authTime: '2026-11-08T09:00:00Z', mfaTime: '2026-11-08T09:30:00Z', authMethods: ['pwd', 'otp'],
  } }) });
  const response = await call(url, '/cases/CASE-14', { headers: as('user-bob', {
    'x-forwarded-for': '10.0.0.1', 'x-gate-ip': '10.0.0.1', 'x-gate-mfa-time': '2026-11-08T10:00:00Z',
    'x-gate-auth-methods': 'webauthn',
  }) });
  assert.equal(response.status, 403);
  const context = observed?.context as Record<string, unknown>;
  assert.equal(context.ip, '127.0.0.1');
  assert.equal(context.authTime, '2026-11-08T09:00:00Z');
  assert.equal(context.mfaTime, '2026-11-08T09:30:00Z');
  assert.deepEqual(context.authMethods, ['pwd', 'otp']);
  assert.ok(!JSON.stringify(context).includes('2026-11-08T10:00:00Z'));
});
test('behind trusted proxies the client is the rightmost untrusted X-Forwarded-For hop; otherwise the header is ignored', async (t) => {
  const seenContexts: Record<string, unknown>[] = [];
  const stub = { evaluateAsserted: async (request: Record<string, unknown>) => {
    seenContexts.push(request.context as Record<string, unknown>);
    return { decision: false, context: { rules: ['CBAC.IP_RANGE'], reasons: [], obligations: { redact: [], maskClasses: [], notify: [] }, policy_version: 'pv.test', would_deny: [] } };
  } } as unknown as PepClient;
  const ask = async (url: string, forwarded: string) => {
    await call(url, '/cases/CASE-14', { headers: as('user-bob', { 'x-forwarded-for': forwarded }) });
    return seenContexts.at(-1)!;
  };
  // the load balancer (here: loopback) is trusted as a proxy, not as the client network
  const behind = await gateway(t, { pdp: stub, trustedProxies: '127.0.0.0/8, ::1', trustedNetworks: ['10.0.0.0/8'] });
  assert.deepEqual([(await ask(behind.url, '10.0.0.1, 198.51.100.7')).ip], ['198.51.100.7'], 'a client-written left entry is not believed');
  const inside = await ask(behind.url, '10.1.2.3');
  assert.deepEqual([inside.ip, inside.network], ['10.1.2.3', 'trusted']);
  const outside = await ask(behind.url, '203.0.113.9');
  assert.deepEqual([outside.ip, outside.network], ['203.0.113.9', 'untrusted'], 'the balancer address no longer passes for every client');
  // without trustedProxies the header is never read
  const direct = await gateway(t, { pdp: stub });
  assert.equal((await ask(direct.url, '10.1.2.3')).ip, '127.0.0.1');
  assert.throws(() => createGateway({ upstream: upstreamUrl, pdp: stub, routes: ROUTES, authenticate: () => undefined, trustedProxies: '10.0.0.0/33' }));
});
function required<T>(value: T | undefined): T { assert.ok(value !== undefined); return value; }
