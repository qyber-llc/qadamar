// TRUSTED_PROXIES: X-Forwarded-For is believed only from a trusted proxy, and only up to the rightmost untrusted hop.
import test from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage, ServerResponse } from 'node:http';
import { resolve } from 'node:path';
import { createHandler } from '../src/router.ts';
import { createServer } from '../src/server.ts';
import { clientAddress, normalizeAddress, trustedProxies } from '../src/proxy.ts';
import { fixture } from './helpers.ts';

const request = (peer: string, forwarded?: string | string[]): IncomingMessage => {
  const req = new IncomingMessage({ remoteAddress: peer, readable: false } as never);
  req.headers = forwarded === undefined ? {} : { 'x-forwarded-for': forwarded as string };
  return req;
};
const INGRESS = trustedProxies('10.42.0.0/16, fd00::/8');

test('TRUSTED_PROXIES parses addresses and CIDR ranges, and refuses anything else at startup', () => {
  assert.equal(trustedProxies(undefined), undefined);
  assert.equal(trustedProxies(' , '), undefined);
  assert.ok(trustedProxies('127.0.0.1,::1,10.0.0.0/8,2001:db8::/32'));
  for (const bad of ['10.0.0.0/33', 'fd00::/129', 'nope', '10.0.0.0/8/1', '10.0.0.0/', '10.0.0.0/x', '*']) {
    assert.throws(() => trustedProxies(bad), /TRUSTED_PROXIES: invalid/, bad);
  }
  assert.throws(() => createServer({ trustedProxies: '10.0.0.0/99' }), /TRUSTED_PROXIES/);
});

test('without a trusted proxy the header is ignored: the connecting address is the client', () => {
  assert.equal(clientAddress(request('203.0.113.7', '198.51.100.1'), undefined), '203.0.113.7');
  // a direct client is not in the list: its own X-Forwarded-For is a spoofing attempt
  assert.equal(clientAddress(request('203.0.113.7', '10.42.0.5, 198.51.100.1'), INGRESS), '203.0.113.7');
  assert.equal(clientAddress(request('::ffff:203.0.113.7', '198.51.100.1'), INGRESS), '203.0.113.7');
});

test('behind a trusted proxy the client is the rightmost untrusted entry; spoofed entries on the left are ignored', () => {
  assert.equal(clientAddress(request('10.42.1.9', '198.51.100.1'), INGRESS), '198.51.100.1');
  // the client forged "1.1.1.1" and the ingress appended the real address
  assert.equal(clientAddress(request('10.42.1.9', '1.1.1.1, 198.51.100.1'), INGRESS), '198.51.100.1');
  // two trusted hops (load balancer, then ingress) are skipped
  assert.equal(clientAddress(request('10.42.1.9', '1.1.1.1, 198.51.100.1, 10.42.3.3'), INGRESS), '198.51.100.1');
  // repeated headers are one list, in order
  assert.equal(clientAddress(request('10.42.1.9', ['1.1.1.1', '198.51.100.2']), INGRESS), '198.51.100.2');
  assert.equal(clientAddress(request('::ffff:10.42.1.9', '[2001:db8::5]:443'), INGRESS), '2001:db8::5');
  assert.equal(clientAddress(request('fd00::1', '198.51.100.3:5555'), INGRESS), '198.51.100.3');
  // no header, or only trusted hops: the furthest trusted address
  assert.equal(clientAddress(request('10.42.1.9'), INGRESS), '10.42.1.9');
  assert.equal(clientAddress(request('10.42.1.9', '10.42.7.7'), INGRESS), '10.42.7.7');
  // garbage right of the client cannot be believed: the last address a trusted proxy vouched for
  assert.equal(clientAddress(request('10.42.1.9', '198.51.100.1, not-an-ip'), INGRESS), '10.42.1.9');
  assert.equal(clientAddress(request('10.42.1.9', '198.51.100.1, , 10.42.3.3'), INGRESS), '198.51.100.1');
  assert.equal(normalizeAddress('<script>'), undefined);
});

async function send(route: ReturnType<typeof createHandler>, peer: string, forwarded?: string): Promise<number> {
  const req = new IncomingMessage({ remoteAddress: peer, readable: false } as never);
  req.url = '/.well-known/authzen-configuration'; req.method = 'GET'; req.headers = forwarded ? { 'x-forwarded-for': forwarded } : {};
  const res = new ServerResponse(req); res.end = (() => res) as typeof res.end;
  const pending = route(req, res); req.push(null); await pending;
  return res.statusCode;
}

test('rate limiting behind an ingress: one bucket per client, and a spoofed header cannot pick another bucket', async (t) => {
  const f = fixture(t);
  const route = (proxies?: string): ReturnType<typeof createHandler> =>
    createHandler(f.rt, f.auth, { rateLimit: 1, staticDir: resolve(f.dir, 'static'), elapsed: () => 0, proxies: trustedProxies(proxies) }, () => 'http://localhost:8787');
  const behind = route('10.42.0.0/16');
  assert.equal(await send(behind, '10.42.0.10', '198.51.100.1'), 200);
  assert.equal(await send(behind, '10.42.0.10', '198.51.100.2'), 200, 'another client through the same ingress has its own bucket');
  assert.equal(await send(behind, '10.42.0.10', '198.51.100.1'), 429);
  assert.equal(await send(behind, '10.42.0.10', '9.9.9.9, 198.51.100.1'), 429, 'a forged left entry does not reset the limit');
  assert.equal(await send(behind, '203.0.113.9', '198.51.100.3'), 200);
  assert.equal(await send(behind, '203.0.113.9', '198.51.100.4'), 429, 'an untrusted peer cannot rotate buckets through the header');
  const untrusting = route(undefined);
  assert.equal(await send(untrusting, '10.42.0.10', '198.51.100.1'), 200);
  assert.equal(await send(untrusting, '10.42.0.10', '198.51.100.2'), 429, 'without TRUSTED_PROXIES the header is ignored');
});

test('the resolved client address is what the login audit records', async (t) => {
  const f = fixture(t);
  const route = createHandler(f.rt, f.auth, { staticDir: resolve(f.dir, 'static'), proxies: trustedProxies('10.42.0.0/16') }, () => 'http://localhost:8787');
  const req = new IncomingMessage({ remoteAddress: '10.42.0.10', readable: false } as never);
  req.url = '/admin/v1/session'; req.method = 'POST';
  req.headers = { 'content-type': 'application/json', 'x-forwarded-for': '1.1.1.1, 198.51.100.8' };
  const res = new ServerResponse(req); res.end = (() => res) as typeof res.end;
  const pending = route(req, res); req.push(JSON.stringify({ username: 'sam', password: 'wrong' })); req.push(null); await pending;
  assert.equal(res.statusCode, 401);
  assert.deepEqual(f.rt.audit.records().at(-1)?.details, { method: 'password', client: '198.51.100.8' });
});
