// Certified commands and notifications: what the PDP judged is what the upstream gets, and nobody is notified of a
// request the gateway then refuses. A stub PDP and a counting upstream; the end-to-end suite is gateway.test.ts.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createServer as httpServer, request, type Server } from 'node:http';
import type { TestContext } from 'node:test';
import { PdpHttpError, type PepClient } from '../../sdk/src/index.ts';
import { createGateway, type GatewayOptions, type NotifyEvent } from '../src/index.ts';

let upstream: Server | undefined;
let upstreamUrl = '';
const bodies: string[] = [];
before(async () => {
  upstream = httpServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      bodies.push(Buffer.concat(chunks).toString());
      res.setHeader('content-type', 'application/json');
      res.end(req.url === '/cases' ? '{"items":[{"id":"A"},{"id":"B"}]}' : '{"ok":true}');
    });
  });
  await new Promise<void>((accept) => upstream?.listen(0, '127.0.0.1', accept));
  const a = upstream.address();
  upstreamUrl = `http://127.0.0.1:${typeof a === 'object' && a ? a.port : 0}`;
});
after(async () => { upstream?.closeAllConnections(); await new Promise<void>((accept) => (upstream ? upstream.close(() => accept()) : accept())); });

const allow = (extra: Record<string, unknown> = {}, notify: string[] = []) => ({ decision: true, context: {
  rules: ['R'], reasons: [] as string[], obligations: { redact: [], maskClasses: [], notify, ...extra }, policy_version: 'pv.test', would_deny: [] as string[] } });
const certified = (notify: string[]) => {
  const d = allow({ decisionToken: { ttlSeconds: 30, resourceVersion: null } }, notify);
  return { ...d, assertion: 'a', context: { ...d.context, decision_token: 'dt' } };
};
const ROUTES: GatewayOptions['routes'] = [
  { method: 'POST', path: '/payments/:id/approve', resourceType: 'payment', action: 'approve', postState: 'body' },
  { method: 'GET', path: '/cases', resourceType: 'case', action: 'read', list: { items: 'items' } },
];
async function gateway(t: TestContext, pdp: unknown, notify?: GatewayOptions['notify']): Promise<string> {
  const gw = createGateway({ upstream: upstreamUrl, pdp: pdp as PepClient, routes: ROUTES, authenticate: () => ({ subject: { type: 'user', id: 'henry' } }),
    log: () => {}, ...(notify ? { notify } : {}) });
  await gw.listen();
  t.after(() => gw.close());
  return gw.url;
}
function call(base: string, path: string, method = 'GET', body?: string): Promise<{ status: number; body: string }> {
  return new Promise((accept, reject) => {
    const req = request(`${base}${path}`, { method, agent: false, headers: body === undefined ? {} : { 'content-type': 'application/json' } }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => accept({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end(body);
  });
}
const approve = (url: string, body: string) => call(url, '/payments/PAY-3/approve', 'POST', body);

test('a certified body with a duplicate key is refused: the PDP and the upstream could read two different commands', async (t) => {
  const inputs: unknown[] = [];
  const url = await gateway(t, { evaluateAsserted: async (r: { context: { input?: unknown } }) => { inputs.push(r.context.input); return { ...allow(), assertion: 'a' }; } });
  const before = bodies.length;
  for (const dup of ['{"amount":1,"amount":9999}', '{"amount":1,"\\u0061mount":9999}', '{"to":{"iban":"A","iban":"B"}}', '{"list":[{"x":1,"x":2}]}']) {
    assert.equal((await approve(url, dup)).status, 400, dup);
  }
  assert.equal(bodies.length, before, 'nothing ran upstream');
  assert.equal(inputs.length, 0, 'the PDP was not asked');
  // the same key in sibling objects, and a key equal to a value, are not duplicates; the bytes go through unchanged
  const fine = '{"a":{"k":1},"b":{"k":"a"},"k":[{"k":2},"k"],"s":"\\"k\\":"}';
  assert.equal((await approve(url, fine)).status, 200);
  assert.equal(bodies.at(-1), fine);
  assert.deepEqual(inputs, [JSON.parse(fine)]);
});

test('a decision token the PDP refuses to consume notifies nobody', async (t) => {
  const events: NotifyEvent[] = [];
  const pdp = { evaluateAsserted: async () => certified(['security-officer']), consumeToken: async () => { throw new PdpHttpError(409, 'conflict'); } };
  const url = await gateway(t, pdp, async (e) => { events.push(e); });
  const before = bodies.length;
  assert.equal((await approve(url, '{"status":"approved"}')).status, 409);
  assert.equal(bodies.length, before);
  assert.equal(events.length, 0, 'the command never ran: no notification');
});

test('a failed notification after the token is consumed refuses the command and settles its reservation as failed', async (t) => {
  const outcomes: unknown[] = [];
  const pdp = {
    evaluateAsserted: async () => certified(['security-officer']),
    consumeToken: async () => ({ consumed: true, reservation: 'res-1' }),
    reportOutcome: async (r: unknown) => { outcomes.push(r); return { ok: true }; },
  };
  const url = await gateway(t, pdp, async () => { throw new Error('mail relay down'); });
  const before = bodies.length;
  assert.equal((await approve(url, '{"status":"approved"}')).status, 502);
  assert.equal(bodies.length, before, 'nothing ran upstream');
  assert.deepEqual(outcomes, [{ reservation: 'res-1', outcome: 'failed' }]);
});

test('a list notifies only once every allowed item is released', async (t) => {
  const events: NotifyEvent[] = [];
  const pdp = {
    assertList: async () => ({ decision: true, policy_version: 'pv.test', assertion: 'a' }),
    // the second item must be masked but carries no content fragments: it cannot be released
    evaluateBatch: async () => ({ evaluations: [allow({}, ['security-officer']), allow({ maskClasses: ['finance.amount'] })] }),
  };
  const url = await gateway(t, pdp, async (e) => { events.push(e); });
  assert.equal((await call(url, '/cases')).status, 502, 'the second item cannot be released');
  assert.equal(events.length, 0, 'nothing was released: no notification');
});
