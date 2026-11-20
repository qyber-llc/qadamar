// PDP side of decision assertions: signed only on allow, bound to the request the PEP describes, verifiable with the
// published JWKS, audited with the decision id, and never accepted where a decision token is expected.
import test from 'node:test';
import assert from 'node:assert/strict';
import { pdp } from '../src/pdp.ts';
import { AssertionVerifier, bodySha256 } from '../../sdk/src/index.ts';
import { evaluation, fixture, FIXED, required } from './helpers.ts';
import type { Fixture } from './helpers.ts';

const request = { audience: 'http://backend.internal:8080', method: 'GET', path: '/cases/CASE-14?bare=1', bodySha256: bodySha256(Buffer.alloc(0)) };
const asserted = (f: Fixture, b: Record<string, unknown>, path = '/x/v1/assertions/evaluation') => pdp(f.rt, path, { ...b, request }) as
  { decision: boolean; assertion?: string; context?: { policy_version: string } };
const verifier = (f: Fixture): AssertionVerifier => new AssertionVerifier({ jwksUrl: 'https://pdp.test/jwks', audience: request.audience, now: () => Date.parse(FIXED),
  fetch: (async () => new Response(JSON.stringify(f.rt.tokens.jwks()))) as unknown as typeof fetch });

test('an allow carries an assertion bound to the request and the decision; a deny carries none', async (t) => {
  const f = fixture(t);
  const allowed = asserted(f, evaluation('bob', 'CASE-14', 'read', 'trusted'));
  assert.equal(allowed.decision, true);
  const claims = await verifier(f).verify({ method: 'GET', path: '/cases/CASE-14?bare=1', body: Buffer.alloc(0), header: required(allowed.assertion) });
  assert.deepEqual([claims.sub, claims.act, claims.res, claims.pv], [{ type: 'user', id: 'bob' }, 'read', { type: 'case', id: 'CASE-14' }, allowed.context?.policy_version]);
  assert.equal(claims.exp - claims.iat, 30);
  assert.deepEqual(f.rt.audit.records().at(-1)?.details, { decisionId: claims.did });
  const denied = asserted(f, evaluation('bob', 'CASE-7', 'read', 'trusted'));
  assert.equal(denied.decision, false);
  assert.equal(denied.assertion, undefined);
  // an assertion is not a decision token
  assert.throws(() => pdp(f.rt, '/x/v1/tokens/consume', { token: required(allowed.assertion), action: 'read', resource: { type: 'case', id: 'CASE-14' }, resourceVersion: null }),
    (e: unknown) => e instanceof Error && 'status' in e && e.status === 409);
});

test('a list assertion is signed only when the subject may act on some item of the type', async (t) => {
  const f = fixture(t);
  const list = (id: string) => asserted(f, { subject: { type: 'user', id }, action: { name: 'read' }, resource: { type: 'case' } }, '/x/v1/assertions/list');
  const bob = list('bob');
  assert.equal(bob.decision, true);
  const claims = await verifier(f).verify({ method: 'GET', path: request.path, body: Buffer.alloc(0), header: required(bob.assertion) });
  assert.deepEqual(claims.res, { type: 'case' });
  assert.deepEqual(f.rt.audit.records().at(-1)?.rules, ['GATE.LIST_ASSERTION']);
  const ghost = list('ghost');
  assert.deepEqual([ghost.decision, ghost.assertion], [false, undefined]);
  assert.deepEqual(f.rt.audit.records().at(-1)?.rules, ['GATE.LIST_NONE']);
});

test('the request binding is validated', (t) => {
  const f = fixture(t);
  for (const bad of [{ audience: 'http://backend.internal:8080/path' }, { audience: 'ftp://backend' }, { audience: 'not a url' }, { method: 'get' },
    { path: 'cases' }, { path: '/a b' }, { path: `/${'a'.repeat(2048)}` }, { bodySha256: 'short' }]) {
    assert.throws(() => pdp(f.rt, '/x/v1/assertions/evaluation', { ...evaluation(), request: { ...request, ...bad } }),
      (e: unknown) => e instanceof Error && 'status' in e && e.status === 400, JSON.stringify(bad));
  }
  assert.throws(() => pdp(f.rt, '/x/v1/assertions/evaluation', evaluation()), (e: unknown) => e instanceof Error && 'status' in e && e.status === 400);
});
