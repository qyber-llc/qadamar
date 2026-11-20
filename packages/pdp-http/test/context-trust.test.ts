import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { createServer } from '../src/server.ts';
import { Auth } from '../src/auth.ts';
import { Audit } from '../src/audit.ts';
import { authorizeContext, contextClaimScopes } from '../src/context-trust.ts';
import { HttpError } from '../src/http.ts';
import { ATTRIBUTE } from '../src/xacml.ts';
import { evaluation, FIXED, req } from './helpers.ts';

const point = (context: Record<string, unknown>): Record<string, unknown> => ({ ...evaluation('carol', 'CASE-14'), context });
const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
function attestation(key: KeyObject, alg: 'EdDSA' | 'ES256', kid: string, claims: Record<string, unknown>): string {
  const content = `${encode({ alg, kid, typ: 'gate-context-attestation+jwt' })}.${encode(claims)}`;
  const signature = alg === 'EdDSA' ? sign(null, Buffer.from(content), key) : sign('sha256', Buffer.from(content), { key, dsaEncoding: 'ieee-p1363' });
  return `${content}.${signature.toString('base64url')}`;
}

async function deployment(t: TestContext) {
  const dir = mkdtempSync('/tmp/pdp-context-trust-');
  const server = createServer({ port: 0, dataDir: dir, clock: `fixed:${FIXED}` });
  await server.listen(); t.after(() => server.close()); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const credentials = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string; passwords: Record<string, string> };
  const call = async (path: string, body: unknown, key = credentials.pepApiKey): Promise<{ status: number; data: Record<string, any>; headers: Headers }> => {
    const response = await fetch(`${server.url}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() as Record<string, any>, headers: response.headers };
  };
  const login = await call('/admin/v1/session', { username: 'lina', password: credentials.passwords.lina }, '');
  const admin = async (body: unknown): Promise<{ status: number; data: Record<string, any> }> => {
    const response = await fetch(`${server.url}/admin/v1/pep-credentials`, { method: 'POST', headers: {
      'content-type': 'application/json', cookie: String(login.headers.get('set-cookie')).split(';')[0]!, 'x-csrf-token': String(login.data.csrfToken),
    }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() as Record<string, any> };
  };
  return { server, dir, credentials, call, admin };
}

test('credential scopes constrain every asserted signal, warn for legacy credentials, and audit refusals', async (t) => {
  const d = await deployment(t);
  const created = await d.admin({ name: 'network-only', contextScopes: [{ signal: 'network', networks: ['trusted'] }, { signal: 'country', countries: ['AE'] }] });
  assert.equal(created.status, 201);
  const key = String(created.data.secret);
  const allowed = await d.call('/access/v1/evaluation', point({ network: 'trusted', country: 'AE' }), key);
  assert.equal(allowed.status, 200, JSON.stringify(allowed.data));
  for (const context of [{ network: 'untrusted' }, { country: 'FR' }, { ip: '10.0.0.1' }, { sessionLevel: 2 }, { riskScore: 1 }]) {
    const refused = await d.call('/access/v1/evaluation', point(context), key);
    assert.deepEqual([refused.status, refused.data.error], [403, 'context_claim_forbidden'], JSON.stringify(context));
    assert.match(String(refused.data.message), /context\./);
  }
  const batch = await d.call('/access/v1/evaluations', { context: { network: 'trusted' }, evaluations: [{ ...evaluation('carol', 'CASE-14'), context: { network: 'untrusted' } }] }, key);
  assert.deepEqual([batch.status, batch.data.error], [403, 'context_claim_forbidden'], 'an entry cannot escape the outer scope check');
  for (const [path, body] of [
    ['/access/v1/evaluation', { ...point({ network: 'untrusted' }), evaluations: [] }],
    ['/access/v1/evaluation', { ...point({ network: 'untrusted' }), evaluations: [{ context: {} }] }],
    ['/x/v1/explain', { ...point({ network: 'untrusted' }), evaluations: [] }],
    ['/access/v1/evaluations', { evaluations: [{ ...point({ network: 'untrusted' }), evaluations: [] }] }],
  ] as const) {
    const stray = await d.call(path, body, key);
    assert.deepEqual([stray.status, stray.data.error], [403, 'context_claim_forbidden'], `a stray evaluations key cannot skip the scope check on ${path}`);
  }
  const legacy = await d.call('/access/v1/evaluation', point({ network: 'trusted' }));
  assert.equal(legacy.status, 200);
  assert.equal(legacy.headers.get('deprecation'), 'true');
  assert.match(String(legacy.headers.get('warning')), /contextScopes/);
  const audit = readFileSync(resolve(d.dir, 'audit.jsonl'), 'utf8');
  assert.ok(audit.includes('"error":"context_claim_forbidden"'));
  assert.ok(audit.includes('"contextScopes"'));
  assert.ok(!audit.includes(key), 'the credential secret is never audited');
});

test('Ed25519 and ES256 attestations bind the exact claim, PEP, audience, key, and expiry', async (t) => {
  const d = await deployment(t);
  const ed = generateKeyPairSync('ed25519'); const es = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const keys = [
    { kid: 'mdm-ed', alg: 'EdDSA', jwk: ed.publicKey.export({ format: 'jwk' }) },
    { kid: 'mdm-es', alg: 'ES256', jwk: es.publicKey.export({ format: 'jwk' }) },
  ];
  const created = await d.admin({ name: 'mdm-gateway', contextScopes: [{ signal: 'device', attestation: { audience: 'gate/device', keys } }] });
  assert.equal(created.status, 201);
  const credential = created.data.credential as { id: string };
  const secret = String(created.data.secret);
  const device = { id: 'device-1', managed: true, compliant: true };
  const claims = { iss: 'mdm-ed', aud: 'gate/device', pep: credential.id, sub: ['user', 'carol'], src: 'device-1', signal: 'device', value: device, jti: randomUUID(), iat: Math.floor(Date.parse(FIXED) / 1000) - 1, exp: Math.floor(Date.parse(FIXED) / 1000) + 60 };
  const valid = attestation(ed.privateKey, 'EdDSA', 'mdm-ed', claims);
  assert.equal((await d.call('/access/v1/evaluation', point({ device, attestations: { device: valid } }), secret)).status, 200);
  assert.equal((await d.call('/access/v1/evaluation', point({ device }), secret)).data.error, 'invalid_context_attestation');
  for (const altered of [
    { ...claims, aud: 'other' }, { ...claims, pep: 'other' }, { ...claims, sub: ['user', 'alice'] }, { ...claims, src: 'device-2' },
    { ...claims, value: { managed: true, compliant: false } }, { ...claims, sid: randomUUID() },
    { ...claims, exp: Math.floor(Date.parse(FIXED) / 1000) }, { ...claims, iss: 'other' },
  ]) {
    const answer = await d.call('/access/v1/evaluation', point({ device, attestations: { device: attestation(ed.privateKey, 'EdDSA', 'mdm-ed', altered) } }), secret);
    assert.deepEqual([answer.status, answer.data.error], [403, 'invalid_context_attestation']);
  }
  const es256 = attestation(es.privateKey, 'ES256', 'mdm-es', { ...claims, iss: 'mdm-es', jti: randomUUID() });
  assert.equal((await d.call('/access/v1/evaluation', point({ device, attestations: { device: es256 } }), secret)).status, 200);

  const networkCredential = await d.admin({ name: 'sensor-gateway', contextScopes: [{ signal: 'network', attestation: { audience: 'gate/network', keys: [keys[0]] } }] });
  const networkId = (networkCredential.data.credential as { id: string }).id;
  const networkJws = attestation(ed.privateKey, 'EdDSA', 'mdm-ed', { ...claims, aud: 'gate/network', pep: networkId, src: 'sensor-1', signal: 'network', value: 'trusted', jti: randomUUID() });
  const xacml = await d.call('/xacml/v3/authorize', { Request: {
    AccessSubject: { Attribute: [{ AttributeId: ATTRIBUTE.subjectId, Value: 'carol' }] },
    Resource: { Attribute: [{ AttributeId: ATTRIBUTE.resourceId, Value: 'CASE-14' }, { AttributeId: ATTRIBUTE.resourceType, Value: 'case' }] },
    Action: { Attribute: { AttributeId: ATTRIBUTE.actionId, Value: 'read' } },
    Environment: { Attribute: [{ AttributeId: ATTRIBUTE.network, Value: 'trusted' }, { AttributeId: ATTRIBUTE.networkSensorId, Value: 'sensor-1' },
      { AttributeId: ATTRIBUTE.attestationNetwork, Value: networkJws }] },
  } }, String(networkCredential.data.secret));
  assert.equal(xacml.status, 200, JSON.stringify(xacml.data));
  assert.equal(xacml.data.Response[0].Decision, 'Permit');
  const audit = readFileSync(resolve(d.dir, 'audit.jsonl'), 'utf8');
  assert.ok(audit.includes('"error":"invalid_context_attestation"'));
  assert.ok(!audit.includes(valid), 'a signed attestation is never copied into the audit');
});

test('scope configuration is strict and production is fail closed for unscoped credentials', (t) => {
  for (const value of [[{ signal: 'unknown' }], [{ signal: 'ip', networks: ['trusted'] }], [{ signal: 'country', countries: ['ZZ'] }], [{ signal: 'network' }, { signal: 'network' }]]) {
    assert.throws(() => contextClaimScopes(value, false), (err) => err instanceof HttpError && err.status === 400);
  }
  assert.throws(() => contextClaimScopes(undefined, true), /contextScopes is required/);
  assert.throws(() => authorizeContext({ network: 'trusted' }, { credential: 'legacy', scopes: [] }, FIXED), (err) => err instanceof HttpError && err.code === 'context_claim_forbidden');
  const dir = mkdtempSync('/tmp/pdp-production-scopes-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const audit = new Audit(resolve(dir, 'audit.jsonl'), () => FIXED);
  const auth = new Auth(dir, audit, () => FIXED, undefined, { production: true });
  assert.throws(() => auth.createPepCredential('unscoped', 'lina'), /contextScopes is required/);
  const seeded = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string };
  const bootstrap = auth.pepCaller(req({ authorization: `Bearer ${seeded.pepApiKey}` }));
  assert.deepEqual(bootstrap.contextScopes, []);
});


test('an attestation cannot be replayed for another subject or PDP session', async (t) => {
  const d = await deployment(t);
  const ed = generateKeyPairSync('ed25519');
  const created = await d.admin({ name: 'replay-target', contextScopes: [{ signal: 'device', attestation: {
    audience: 'gate/device', keys: [{ kid: 'mdm-ed', alg: 'EdDSA', jwk: ed.publicKey.export({ format: 'jwk' }) }],
  } }] });
  const credential = created.data.credential as { id: string };
  const secret = String(created.data.secret);
  const opened = await d.call('/x/v1/sessions', { subject: { type: 'user', id: 'carol' } }, secret);
  assert.equal(opened.status, 201);
  const device = { managed: true, compliant: true };
  const now = Math.floor(Date.parse(FIXED) / 1000);
  const replayed = attestation(ed.privateKey, 'EdDSA', 'mdm-ed', {
    iss: 'mdm-ed', aud: 'gate/device', pep: credential.id, signal: 'device', value: device, jti: randomUUID(), iat: now - 1, exp: now + 60,
  });
  const first = await d.call('/access/v1/evaluation', { ...evaluation('carol', 'CASE-14'), context: {
    sessionToken: opened.data.token, device, attestations: { device: replayed },
  } }, secret);
  assert.equal(first.status, 403, 'an attestation without a subject and session binding must not authenticate this request');
  const second = await d.call('/access/v1/evaluation', { ...evaluation('alice', 'CASE-14'), context: {
    sessionToken: opened.data.token, device, attestations: { device: replayed },
  } }, secret);
  assert.equal(second.status, 403, 'the same attestation must not travel to another subject');

  const boundDevice = { ...device, id: 'device-1' };
  const boundClaims = { iss: 'mdm-ed', aud: 'gate/device', pep: credential.id, sub: ['user', 'carol'], sid: opened.data.sessionId,
    src: 'device-1', signal: 'device', value: boundDevice, jti: randomUUID(), iat: now - 1, exp: now + 60 };
  const bound = attestation(ed.privateKey, 'EdDSA', 'mdm-ed', boundClaims);
  assert.equal((await d.call('/access/v1/evaluation', { ...evaluation('carol', 'CASE-14'), context: {
    sessionToken: opened.data.token, device: boundDevice, attestations: { device: bound },
  } }, secret)).status, 200);
  const next = await d.call('/x/v1/sessions', { subject: { type: 'user', id: 'carol' } }, secret);
  assert.equal(next.status, 201);
  for (const [token, claims] of [
    [next.data.token, boundClaims],
    [opened.data.token, { ...boundClaims, sub: ['user', 'alice'] }],
    [opened.data.token, { ...boundClaims, src: 'device-2' }],
  ] as const) {
    const answer = await d.call('/access/v1/evaluation', { ...evaluation('carol', 'CASE-14'), context: {
      sessionToken: token, device: boundDevice, attestations: { device: attestation(ed.privateKey, 'EdDSA', 'mdm-ed', claims) },
    } }, secret);
    assert.deepEqual([answer.status, answer.data.error], [403, 'invalid_context_attestation']);
  }
  const batch = await d.call('/access/v1/evaluations', { ...evaluation('carol', 'CASE-14'), context: {
    sessionToken: opened.data.token, device: boundDevice, attestations: { device: bound },
  }, evaluations: [{ ...evaluation('alice', 'CASE-14') }] }, secret);
  assert.deepEqual([batch.status, batch.data.error], [403, 'invalid_context_attestation'], 'an inherited batch context binds to the entry subject');
});
