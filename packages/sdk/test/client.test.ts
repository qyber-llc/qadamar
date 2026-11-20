import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PdpHttpError, PdpNetworkError, PdpResponseError, PepClient, PepError, createPepClient,
} from '../src/index.ts';
import type { Evaluation } from '../src/index.ts';

const API_KEY = 'unit-test-api-key';
const evaluation: Evaluation = {
  decision: true,
  context: {
    rules: ['viewer'], reasons: ['allowed'], policy_version: 'pv.test', would_deny: [],
    obligations: { redact: ['informant_name'], maskClasses: ['finance.amount'], notify: [] },
  },
};
const request = {
  subject: { type: 'user', id: 'bob' }, action: { name: 'read' },
  resource: { type: 'case', id: 'CASE-14' }, context: { network: 'trusted', networkSensorId: 'sensor-1', attestations: { network: 'signed-network-jws' } },
} as const;
function json(value: unknown, status = 200, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json', ...headers } });
}

test('all seven PDP routes use POST, JSON, Bearer auth, and validated typed responses', async () => {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetcher: typeof globalThis.fetch = async (input, init) => {
    const url = String(input); calls.push({ url, ...(init ? { init } : {}) });
    if (url.endsWith('/access/v1/evaluation')) return json(evaluation);
    if (url.endsWith('/access/v1/evaluations')) return json({ evaluations: [evaluation] });
    if (url.endsWith('/access/v1/search/resource')) return json({ results: [{ type: 'case', id: 'CASE-14' }], page: { next_token: '' } });
    if (url.endsWith('/access/v1/search/subject')) return json({ results: [{ type: 'user', id: 'bob' }], page: { next_token: 'YzE=' } });
    if (url.endsWith('/access/v1/search/action')) return json({ results: [{ name: 'read' }] });
    if (url.endsWith('/x/v1/filter')) return json({ residual: { op: 'true' }, sql: { text: 'TRUE', params: [] } });
    if (url.endsWith('/x/v1/tokens/consume')) return json({ ok: true });
    return json({ error: 'not_found' }, 404);
  };
  const client = createPepClient({ baseUrl: 'http://pdp.test/', apiKey: API_KEY, fetch: fetcher });
  assert.deepEqual(await client.evaluate(request), evaluation);
  assert.deepEqual(await client.evaluateBatch({ ...request, evaluations: [{}] }), { evaluations: [evaluation] });
  assert.deepEqual(await client.searchResources({ ...request, resource: { type: 'case' }, page: { limit: 1 } }), {
    results: [{ type: 'case', id: 'CASE-14' }], page: { next_token: '' },
  });
  assert.deepEqual(await client.searchSubjects({ ...request, subject: { type: 'user' } }), {
    results: [{ type: 'user', id: 'bob' }], page: { next_token: 'YzE=' },
  });
  assert.deepEqual(await client.searchActions(request), { results: [{ name: 'read' }] });
  assert.deepEqual(await client.filter({
    ...request, resource: { type: 'case' }, dialect: 'postgres', columns: { 'resource.id': 'id' },
  }), { residual: { op: 'true' }, sql: { text: 'TRUE', params: [] } });
  assert.deepEqual(await client.consumeToken({
    token: 'decision-jws', action: 'close', resource: { type: 'case', id: 'CASE-14' }, resourceVersion: 8,
  }), { ok: true });

  assert.deepEqual(calls.map((call) => new URL(call.url).pathname), [
    '/access/v1/evaluation', '/access/v1/evaluations', '/access/v1/search/resource', '/access/v1/search/subject',
    '/access/v1/search/action', '/x/v1/filter', '/x/v1/tokens/consume',
  ]);
  for (const call of calls) {
    assert.equal(call.init?.method, 'POST');
    const headers = new Headers(call.init?.headers);
    assert.equal(headers.get('authorization'), `Bearer ${API_KEY}`);
    assert.equal(headers.get('content-type'), 'application/json');
    assert.equal(headers.get('accept'), 'application/json');
    assert.ok(call.init?.signal instanceof AbortSignal);
    assert.equal(typeof call.init?.body, 'string');
  }
  const consumed = JSON.parse(String(calls.at(-1)?.init?.body)) as Record<string, unknown>;
  assert.deepEqual(consumed, {
    token: 'decision-jws', action: 'close', resource: { type: 'case', id: 'CASE-14' }, resourceVersion: 8,
  });
});

test('openSession and closeSession use the session routes and validate their answers', async () => {
  const calls: Array<{ path: string; body: unknown }> = [];
  const opened = { token: 'session-jws', sessionId: 'pd-chosen-id', issuedAt: '2026-11-08T10:00:00.000Z', expiresAt: '2026-11-08T11:00:00.000Z', idleSeconds: 900 };
  const client = new PepClient({ baseUrl: 'http://pdp.test', apiKey: API_KEY, fetch: async (input, init) => {
    calls.push({ path: new URL(String(input)).pathname, body: JSON.parse(String(init?.body)) });
    return json(String(input).endsWith('/close') ? { ok: true } : opened, String(input).endsWith('/close') ? 200 : 201);
  } });
  assert.deepEqual(await client.openSession({ type: 'user', id: 'carol' }), opened);
  assert.deepEqual(await client.closeSession(opened.token), { ok: true });
  assert.deepEqual(calls, [{ path: '/x/v1/sessions', body: { subject: { type: 'user', id: 'carol' } } },
    { path: '/x/v1/sessions/close', body: { token: opened.token } }]);
  for (const bad of [{ ...opened, idleSeconds: 0 }, { ...opened, extra: true }]) {
    const invalid = new PepClient({ baseUrl: 'http://pdp.test', apiKey: API_KEY, fetch: async () => json(bad, 201) });
    await assert.rejects(invalid.openSession({ type: 'user', id: 'carol' }), PdpResponseError);
  }
  const invalidClose = new PepClient({ baseUrl: 'http://pdp.test', apiKey: API_KEY, fetch: async () => json({ ok: false }) });
  await assert.rejects(invalidClose.closeSession('token'), PdpResponseError);
});

test('client.enforce evaluates a real response shape before applying record obligations', async () => {
  const client = new PepClient({ baseUrl: 'http://pdp.test', apiKey: API_KEY, fetch: async () => json(evaluation) });
  const original = { informant_name: 'Name', content: [{ class: 'finance.amount', text: '100' }] };
  const result = await client.enforce(request, original);
  assert.equal(result.informant_name, null);
  assert.equal(result.content[0]?.text, '[MASKED]');
  assert.equal(original.informant_name, 'Name');
});

test('HTTP errors expose status, stable code, and Retry-After without response secrets', async () => {
  const client = new PepClient({
    baseUrl: 'http://pdp.test', apiKey: API_KEY,
    fetch: async () => json({ error: 'unauthenticated', message: `do not echo ${API_KEY}` }, 401, { 'retry-after': '12' }),
  });
  await assert.rejects(client.evaluate(request), (error: unknown) => {
    assert.ok(error instanceof PdpHttpError);
    assert.equal(error.status, 401);
    assert.equal(error.code, 'unauthenticated');
    assert.equal(error.retryAfter, '12');
    assert.doesNotMatch(`${error.name}: ${error.message} ${JSON.stringify(error)}`, new RegExp(API_KEY));
    assert.doesNotMatch(error.message, /do not echo/);
    return true;
  });
});

test('malformed success JSON and response shapes are rejected for each response family', async () => {
  const invalidJson = new PepClient({
    baseUrl: 'http://pdp.test', apiKey: API_KEY, fetch: async () => new Response('{', { status: 200 }),
  });
  await assert.rejects(invalidJson.evaluate(request), PdpResponseError);

  const invalidBodies: [string, unknown][] = [
    ['/access/v1/evaluation', { decision: true }],
    ['/access/v1/evaluations', { evaluations: [{ decision: true }] }],
    ['/access/v1/search/resource', { results: [{ type: 'case' }], page: { next_token: '' } }],
    ['/access/v1/search/subject', { results: [], page: {} }],
    ['/access/v1/search/action', { results: [{ id: 'read' }] }],
    ['/x/v1/filter', { residual: 'true', sql: { text: 'TRUE', params: [] } }],
    ['/x/v1/tokens/consume', { ok: false }],
    ['/x/v1/tokens/consume', { ok: true, reservation: 7 }],
    ['/x/v1/tokens/outcome', { ok: true, reservation: 'r', outcome: 'done' }],
  ];
  for (const [path, body] of invalidBodies) {
    const client = new PepClient({
      baseUrl: 'http://pdp.test', apiKey: API_KEY,
      fetch: async (input) => {
        assert.equal(new URL(String(input)).pathname, path);
        return json(body);
      },
    });
    const invocation = path.endsWith('/evaluations') ? client.evaluateBatch({ evaluations: [] })
      : path.endsWith('/search/resource') ? client.searchResources({ ...request, resource: { type: 'case' } })
        : path.endsWith('/search/subject') ? client.searchSubjects({ ...request, subject: { type: 'user' } })
          : path.endsWith('/search/action') ? client.searchActions(request)
            : path.endsWith('/filter') ? client.filter({ ...request, resource: { type: 'case' }, columns: {} })
              : path.endsWith('/consume') ? client.consumeToken({ token: 'x', action: 'read', resource: request.resource, resourceVersion: null })
                : path.endsWith('/outcome') ? client.reportOutcome({ reservation: 'r', outcome: 'completed' })
                : client.evaluate(request);
    await assert.rejects(invocation, PdpResponseError, path);
  }
});

test('network errors, timeouts, and caller aborts are sanitized and distinguishable', async () => {
  const secret = API_KEY;
  const failed = new PepClient({
    baseUrl: 'http://pdp.test', apiKey: secret,
    fetch: async () => { throw new Error(`transport leaked ${secret}`); },
  });
  await assert.rejects(failed.evaluate(request), (error: unknown) => {
    assert.ok(error instanceof PdpNetworkError);
    assert.equal(error.code, 'network_error');
    assert.doesNotMatch(error.message, new RegExp(secret));
    return true;
  });

  const pending = new PepClient({
    baseUrl: 'http://pdp.test', apiKey: secret, timeoutMs: 5,
    fetch: async (_input, init) => await new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
    }),
  });
  await assert.rejects(pending.evaluate(request), (error: unknown) => error instanceof PdpNetworkError && error.code === 'request_timeout');

  const controller = new AbortController(); controller.abort();
  await assert.rejects(pending.evaluate(request, { signal: controller.signal }), (error: unknown) => {
    return error instanceof PdpNetworkError && error.code === 'request_aborted';
  });
});

test('the client never follows a redirect and its timeout covers the response body', async () => {
  let redirect: unknown;
  const client = new PepClient({ baseUrl: 'http://pdp.test', apiKey: API_KEY, fetch: async (_input, init) => { redirect = init?.redirect; return json(evaluation); } });
  await client.evaluate(request);
  assert.equal(redirect, 'error', 'the bearer key must not follow a redirect to another host');

  const stalled = new PepClient({
    baseUrl: 'http://pdp.test', apiKey: API_KEY, timeoutMs: 5,
    fetch: async (_input, init) => new Response(new ReadableStream({
      start(controller) { init?.signal?.addEventListener('abort', () => controller.error(new Error('aborted')), { once: true }); },
    })),
  });
  await assert.rejects(stalled.evaluate(request), (error: unknown) => error instanceof PdpNetworkError && error.code === 'request_timeout');
});

test('invalid construction and unserializable requests fail without exposing credentials or record data', async () => {
  for (const baseUrl of ['file:///tmp/pdp', 'https://user:pass@pdp.test', 'https://pdp.test/?key=secret']) {
    assert.throws(() => new PepClient({ baseUrl, apiKey: API_KEY }), TypeError);
  }
  assert.throws(() => new PepClient({ baseUrl: 'https://pdp.test', apiKey: `bad\n${API_KEY}` }), TypeError);
  const client = new PepClient({ baseUrl: 'https://pdp.test', apiKey: API_KEY, fetch: async () => json(evaluation) });
  const circular: { request?: unknown; secret?: string } = { secret: 'do-not-log' }; circular.request = circular;
  await assert.rejects(client.evaluate(circular as unknown as typeof request), (error: unknown) => {
    assert.ok(error instanceof PepError);
    assert.equal(error.code, 'invalid_request');
    assert.doesNotMatch(error.message, /do-not-log/);
    return true;
  });
});

test('assertion routes: an allow must carry an assertion and a deny must not', async () => {
  const binding = { audience: 'http://backend:8080', method: 'GET', path: '/cases/CASE-14', bodySha256: '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU' };
  let reply: unknown = { ...evaluation, assertion: 'a.b.c' };
  const client = new PepClient({ baseUrl: 'http://pdp.test', apiKey: API_KEY, fetch: async () => json(reply) });
  assert.deepEqual(await client.evaluateAsserted({ ...request, request: binding }), { ...evaluation, assertion: 'a.b.c' });
  for (const bad of [evaluation, { ...evaluation, decision: false, assertion: 'a.b.c' }, { ...evaluation, assertion: '' }, { ...evaluation, assertion: 'x', extra: 1 }]) {
    reply = bad;
    await assert.rejects(client.evaluateAsserted({ ...request, request: binding }), PdpResponseError);
  }
  reply = { ...evaluation, decision: false };
  assert.equal((await client.evaluateAsserted({ ...request, request: binding })).decision, false);
  const list = { ...request, resource: { type: 'case' }, request: binding };
  reply = { decision: true, policy_version: 'pv', assertion: 'a.b.c' };
  assert.deepEqual(await client.assertList(list), reply);
  reply = { decision: false, policy_version: 'pv' };
  assert.deepEqual(await client.assertList(list), reply);
  for (const bad of [{ decision: true, policy_version: 'pv' }, { decision: false, policy_version: 'pv', assertion: 'a' }, { decision: 'yes', policy_version: 'pv' }, { decision: false, policy_version: 'pv', x: 1 }]) {
    reply = bad;
    await assert.rejects(client.assertList(list), PdpResponseError);
  }
});

test('resource registration: requests are checked before they leave, answers before they are returned', async () => {
  const sent: Array<{ path: string; body: unknown }> = [];
  let answer: unknown = { items: [{ type: 'case', id: 'CASE-100', status: 'created', version: 1 }], counts: { created: 1, updated: 0, unchanged: 0, retired: 0, proposed: 0 } };
  const fetcher: typeof globalThis.fetch = async (input, init) => {
    sent.push({ path: new URL(String(input)).pathname, body: JSON.parse(String(init?.body)) });
    return json(answer, String(input).endsWith('/list') ? 200 : 201);
  };
  const client = createPepClient({ baseUrl: 'http://pdp.test', apiKey: API_KEY, fetch: fetcher });
  const record = { type: 'case', id: 'CASE-100', level: 1, compartments: [], integrity: 'system', contentClasses: [] } as const;
  assert.equal((await client.registerResource(record)).items[0]?.status, 'created');
  await client.retireResource({ type: 'case', id: 'CASE-100' });
  await client.syncResources({ resources: [record], retire: [{ type: 'case', id: 'CASE-7' }] });
  assert.deepEqual(sent.map((s) => s.path), ['/x/v1/resources', '/x/v1/resources/retire', '/x/v1/resources/sync']);
  assert.deepEqual(sent[0]?.body, { resource: record });

  const rejected = async (p: Promise<unknown>): Promise<void> => { await assert.rejects(p, (e: unknown) => e instanceof PepError && e.code === 'invalid_request'); };
  await rejected(client.registerResource({ ...record, level: 4 as 1 }));
  await rejected(client.registerResource({ ...record, integrity: 'Verified' as 'verified' }));
  await rejected(client.registerResource({ ...record, contentClasses: undefined as unknown as [] }));
  await rejected(client.registerResource({ ...record, compartments: ['A', 'A'] }));
  await rejected(client.registerResource({ ...record, colour: 'red' } as typeof record));
  await rejected(client.retireResource({ type: 'case', id: '' }));
  await rejected(client.syncResources({}));
  await rejected(client.syncResources({ resources: Array.from({ length: 1001 }, (_, i) => ({ ...record, id: `C-${i}` })) }));
  await rejected(client.listResources({ type: 'case', limit: 0 }));
  assert.equal(sent.length, 3, 'nothing invalid was sent');

  answer = { items: [{ type: 'case', id: 'CASE-100', status: 'proposed', version: 2 }], counts: { created: 0, updated: 0, unchanged: 0, retired: 0, proposed: 1 } };
  await assert.rejects(client.registerResource(record), PdpResponseError, 'a proposal names its change');
  answer = { resources: [{ type: 'case', id: 'CASE-100', version: 2 }], next_cursor: '' };
  assert.deepEqual(await client.listResources({ type: 'case' }), answer);
  answer = { resources: [{ type: 'case', id: 'CASE-100' }], next_cursor: '' };
  await assert.rejects(client.listResources({ type: 'case' }), PdpResponseError);
});
