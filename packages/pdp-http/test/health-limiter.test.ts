import test from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage, ServerResponse } from 'node:http';
import { createHandler } from '../src/router.ts';
import { fixture } from './helpers.ts';

type Handler = ReturnType<typeof createHandler>;
async function send(handler: Handler, path: string, headers: Record<string, string> = {}): Promise<number> {
  const socket = { remoteAddress: '127.0.0.1', readable: false } as ConstructorParameters<typeof IncomingMessage>[0];
  const req = new IncomingMessage(socket); req.url = path; req.method = 'GET'; req.headers = headers;
  const res = new ServerResponse(req);
  res.end = ((): ServerResponse => res) as typeof res.end;
  const pending = handler(req, res);
  req.push(''); req.push(null);
  await pending;
  return res.statusCode;
}

test('health and readiness probes answer while the address bucket is empty; /metrics stays limited and token-gated', async (t) => {
  const previous = process.env.METRICS_TOKEN;
  process.env.METRICS_TOKEN = 'metrics-limiter-secret';
  t.after(() => { if (previous === undefined) delete process.env.METRICS_TOKEN; else process.env.METRICS_TOKEN = previous; });
  const f = fixture(t);
  const route = createHandler(f.rt, f.auth, { rateLimit: 1 }, () => 'http://localhost:8787');
  assert.equal(await send(route, '/.well-known/authzen-configuration'), 200, 'the one token of the minute');
  assert.equal(await send(route, '/.well-known/authzen-configuration'), 429, 'the bucket is empty');
  for (let i = 0; i < 3; i++) {
    assert.equal(await send(route, '/healthz'), 200, 'a liveness probe is never refused by the limiter');
    assert.equal(await send(route, '/readyz'), 200, 'a readiness probe is never refused by the limiter');
    assert.equal(await send(route, '/leaderz'), 200, 'the leader probe a load balancer uses is never refused by the limiter');
  }
  assert.equal(await send(route, '/metrics', { authorization: 'Bearer metrics-limiter-secret' }), 429, '/metrics stays behind the limiter');
  const fresh = createHandler(f.rt, f.auth, { rateLimit: 5 }, () => 'http://localhost:8787');
  assert.equal(await send(fresh, '/metrics'), 401, '/metrics still needs its token');
  assert.equal(await send(fresh, '/metrics', { authorization: 'Bearer metrics-limiter-secret' }), 200);
});
