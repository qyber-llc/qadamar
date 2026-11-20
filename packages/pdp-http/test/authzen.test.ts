import test from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage, ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import { createHandler } from '../src/router.ts';
import { evaluation, fixture, required } from './helpers.ts';
import type { Fixture } from './helpers.ts';

type Handler = ReturnType<typeof createHandler>;
type Body = Record<string, unknown>;
interface Reply { status: number; headers: Record<string, unknown>; text: string; data: Body }
interface EvaluationResult { decision: boolean; context?: Body }
interface SearchResult { results: Body[]; page?: { next_token: string } }

function handler(f: Fixture): Handler {
  return createHandler(f.rt, f.auth, { staticDir: resolve(f.dir, 'static') }, () => 'https://pdp.example');
}

async function send(route: Handler, path: string, method = 'GET', data?: unknown, headers: Body = {}, raw?: string): Promise<Reply> {
  const socket = { remoteAddress: '127.0.0.1', readable: false } as ConstructorParameters<typeof IncomingMessage>[0];
  const req = new IncomingMessage(socket);
  req.url = path;
  req.method = method;
  req.headers = { ...(method === 'POST' ? { 'content-type': 'application/json' } : {}), ...headers } as IncomingMessage['headers'];
  let text = '';
  const res = new ServerResponse(req);
  res.end = ((chunk?: unknown): ServerResponse => { text = chunk === undefined ? '' : String(chunk); return res; }) as typeof res.end;
  const pending = route(req, res);
  req.push(raw ?? (data === undefined ? '' : JSON.stringify(data)));
  req.push(null);
  await pending;
  let parsed: Body = {};
  try { parsed = JSON.parse(text) as Body; } catch { /* The assertions below reject non-JSON API responses. */ }
  return { status: res.statusCode, headers: res.getHeaders(), text, data: parsed };
}

function post(route: Handler, f: Fixture, path: string, data: unknown, authenticated = true): Promise<Reply> {
  return send(route, path, 'POST', data, authenticated ? { authorization: `Bearer ${f.pepApiKey}` } : {});
}

function batch(reply: Reply): EvaluationResult[] {
  assert.equal(reply.status, 200, reply.text);
  assert.deepEqual(Object.keys(reply.data), ['evaluations']);
  assert.ok(Array.isArray(reply.data.evaluations));
  return reply.data.evaluations as EvaluationResult[];
}

function search(reply: Reply): SearchResult {
  assert.equal(reply.status, 200, reply.text);
  assert.ok(Array.isArray(reply.data.results));
  return reply.data as unknown as SearchResult;
}

test('AuthZEN discovery metadata is public and contains every endpoint URL', async (t) => {
  const f = fixture(t);
  const reply = await send(handler(f), '/.well-known/authzen-configuration');
  assert.equal(reply.status, 200);
  assert.match(String(reply.headers['content-type']), /^application\/json/);
  assert.deepEqual(reply.data, {
    policy_decision_point: 'https://pdp.example',
    access_evaluation_endpoint: 'https://pdp.example/access/v1/evaluation',
    access_evaluations_endpoint: 'https://pdp.example/access/v1/evaluations',
    search_subject_endpoint: 'https://pdp.example/access/v1/search/subject',
    search_resource_endpoint: 'https://pdp.example/access/v1/search/resource',
    search_action_endpoint: 'https://pdp.example/access/v1/search/action',
  });
});

test('AuthZEN evaluation returns a boolean decision and optional context object', async (t) => {
  const f = fixture(t);
  const route = handler(f);
  const allowed = await post(route, f, '/access/v1/evaluation', evaluation());
  assert.equal(allowed.status, 200);
  assert.deepEqual(Object.keys(allowed.data).sort(), ['context', 'decision']);
  assert.equal(allowed.data.decision, true);
  assert.equal(typeof allowed.data.decision, 'boolean');
  const context = allowed.data.context as Body;
  assert.equal(typeof context, 'object');
  assert.match(String(context.policy_version), /^pv\./);
  assert.ok(Array.isArray(context.rules));
  assert.ok(Array.isArray(context.reasons));

  const denied = await post(route, f, '/access/v1/evaluation', evaluation('unknown'));
  assert.equal(denied.status, 200);
  assert.equal(denied.data.decision, false);
});

test('AuthZEN batch entries override top-level subject, action, resource and context independently', async (t) => {
  const f = fixture(t);
  const route = handler(f);
  const base = evaluation();
  const reply = await post(route, f, '/access/v1/evaluations', {
    ...base,
    evaluations: [
      {},
      { subject: { type: 'user', id: 'alice' } },
      { action: { name: 'export' } },
      { resource: { type: 'case', id: 'CASE-7' } },
      { context: { sessionLevel: 0 } },
    ],
  });
  assert.deepEqual(batch(reply).map((item) => item.decision), [true, false, false, false, false]);
});

test('AuthZEN evaluations_semantic executes all or stops after the decisive result', async (t) => {
  const f = fixture(t);
  const route = handler(f);
  const entries = [{ resource: { type: 'case', id: 'CASE-7' } }, {}, { action: { name: 'export' } }];
  const cases = [
    { semantic: undefined, decisions: [false, true, false] },
    { semantic: 'execute_all', decisions: [false, true, false] },
    { semantic: 'deny_on_first_deny', decisions: [false] },
    { semantic: 'permit_on_first_permit', decisions: [false, true] },
  ];
  for (const { semantic, decisions } of cases) {
    const before = f.rt.decisions;
    const reply = await post(route, f, '/access/v1/evaluations', {
      ...evaluation(), evaluations: entries, ...(semantic ? { options: { evaluations_semantic: semantic } } : {}),
    });
    assert.deepEqual(batch(reply).map((item) => item.decision), decisions, semantic ?? 'default');
    assert.equal(f.rt.decisions - before, decisions.length, semantic ?? 'default');
  }
});

test('AuthZEN resource search returns resource references and follows next_token pagination', async (t) => {
  const f = fixture(t);
  const route = handler(f);
  const request = { ...evaluation(), resource: { type: 'case' } };
  const all = search(await post(route, f, '/access/v1/search/resource', request));
  assert.ok(all.results.length > 1);
  assert.equal(all.page?.next_token, '');
  const paged: Body[] = [];
  let token = '';
  do {
    const page = search(await post(route, f, '/access/v1/search/resource', { ...request, page: { limit: 1, ...(token ? { token } : {}) } }));
    assert.ok(page.results.length <= 1);
    paged.push(...page.results);
    token = required(page.page).next_token;
  } while (token);
  assert.deepEqual(paged, all.results);
  for (const resource of paged) {
    assert.deepEqual(Object.keys(resource).sort(), ['id', 'type']);
    assert.equal(resource.type, 'case');
    assert.equal(typeof resource.id, 'string');
    assert.notEqual(resource.id, 'CASE-7');
  }
});

test('AuthZEN subject and action searches return only permitted references and actions', async (t) => {
  const f = fixture(t);
  const route = handler(f);
  const subjectRequest = { ...evaluation(), subject: { type: 'user' } };
  const all = search(await post(route, f, '/access/v1/search/subject', subjectRequest));
  assert.ok(all.results.some((item) => item.id === 'bob'));
  assert.ok(!all.results.some((item) => item.id === 'frank'));
  const first = search(await post(route, f, '/access/v1/search/subject', { ...subjectRequest, page: { limit: 1 } }));
  assert.equal(first.results.length, 1);
  assert.ok(first.page?.next_token);
  const second = search(await post(route, f, '/access/v1/search/subject', { ...subjectRequest, page: { limit: 1, token: first.page?.next_token } }));
  assert.deepEqual([...first.results, ...second.results], all.results.slice(0, 2));
  for (const subject of all.results) assert.deepEqual(Object.keys(subject).sort(), ['id', 'type']);

  const actions = search(await post(route, f, '/access/v1/search/action', evaluation()));
  assert.ok(actions.results.some((item) => item.name === 'read'));
  assert.ok(!actions.results.some((item) => item.name === 'export'));
  assert.ok(!actions.results.some((item) => item.name === 'delete'));
  for (const action of actions.results) assert.deepEqual(Object.keys(action), ['name']);
});

test('AuthZEN malformed requests return sanitized 400 error envelopes', async (t) => {
  const f = fixture(t);
  const route = handler(f);
  const malformed: [string, unknown, string?][] = [
    ['/access/v1/evaluation', undefined, '{'],
    ['/access/v1/evaluation', null],
    ['/access/v1/evaluation', []],
    ['/access/v1/evaluation', {}],
    ['/access/v1/evaluation', { ...evaluation(), subject: null }],
    ['/access/v1/evaluation', { ...evaluation(), action: { name: '' } }],
    ['/access/v1/evaluation', { ...evaluation(), resource: { type: 'case' } }],
    ['/access/v1/evaluation', { ...evaluation(), context: { network: 'invalid' } }],
    ['/access/v1/evaluations', { evaluations: 'invalid' }],
    ['/access/v1/evaluations', { ...evaluation(), evaluations: [null] }],
    ['/access/v1/evaluations', { evaluations: [], options: { evaluations_semantic: 'invalid' } }],
    ['/access/v1/search/resource', { ...evaluation(), resource: { type: 'case' }, page: { limit: 0 } }],
    ['/access/v1/search/resource', { ...evaluation(), resource: { type: 'case' }, page: { token: 'not-base64!' } }],
    ['/access/v1/search/subject', { subject: { type: 'user' }, action: { name: 'read' } }],
    ['/access/v1/search/action', { resource: { type: 'case', id: 'CASE-14' } }],
  ];
  for (const [path, data, raw] of malformed) {
    const reply = await send(route, path, 'POST', data, { authorization: `Bearer ${f.pepApiKey}` }, raw);
    assert.equal(reply.status, 400, `${path}: ${JSON.stringify(data)}`);
    assert.equal(reply.data.error, 'bad_request');
    assert.deepEqual(Object.keys(reply.data).sort(), ['error', 'message']);
    assert.doesNotMatch(reply.text, /Error:|stack|\.ts:\d|\/src\/|pepApiKey/i);
  }
});

test('AuthZEN decision and search endpoints require PEP authentication', async (t) => {
  const f = fixture(t);
  const route = handler(f);
  const requests: [string, Body][] = [
    ['/access/v1/evaluation', evaluation()],
    ['/access/v1/evaluations', { ...evaluation(), evaluations: [{}] }],
    ['/access/v1/search/resource', { ...evaluation(), resource: { type: 'case' } }],
    ['/access/v1/search/subject', { ...evaluation(), subject: { type: 'user' } }],
    ['/access/v1/search/action', evaluation()],
  ];
  for (const [path, data] of requests) {
    const missing = await post(route, f, path, data, false);
    assert.equal(missing.status, 401, path);
    assert.equal(missing.data.error, 'unauthenticated');
    assert.deepEqual(Object.keys(missing.data).sort(), ['error', 'message']);
  }
  const invalid = await send(route, '/access/v1/evaluation', 'POST', evaluation(), { authorization: 'Bearer invalid' });
  assert.equal(invalid.status, 401);
  assert.equal(invalid.data.error, 'unauthenticated');
});
