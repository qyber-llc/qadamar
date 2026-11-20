import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { authorizeContext, contextClaimScopes } from '../src/context-trust.ts';
import { HttpError } from '../src/http.ts';
import { FIXED } from './helpers.ts';

const encode = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');

// Characterizes the documented window (docs/API.md §2, THREAT-MODEL §4): `jti` is never remembered, so one attestation
// serves any number of decisions for the same credential, subject, session, source and value until `exp`.
test('a context attestation is reusable until it expires, then refused', () => {
  const ed = generateKeyPairSync('ed25519');
  const scopes = contextClaimScopes([{ signal: 'sessionLevel', attestation: {
    audience: 'gate/step-up', keys: [{ kid: 'idp', alg: 'EdDSA', jwk: ed.publicKey.export({ format: 'jwk' }) }],
  } }], true);
  const now = Math.floor(Date.parse(FIXED) / 1000);
  const claims = { iss: 'idp', aud: 'gate/step-up', pep: 'pep-1', sub: ['user', 'carol'], signal: 'sessionLevel', value: 2, jti: randomUUID(), iat: now, exp: now + 60 };
  const content = `${encode({ alg: 'EdDSA', kid: 'idp', typ: 'gate-context-attestation+jwt' })}.${encode(claims)}`;
  const jws = `${content}.${sign(null, Buffer.from(content), ed.privateKey).toString('base64url')}`;
  const trust = { credential: 'pep-1', scopes };
  const binding = { subject: { type: 'user', id: 'carol' } };
  const context = { sessionLevel: 2, attestations: { sessionLevel: jws } };
  for (let i = 0; i < 3; i++) authorizeContext(context, trust, FIXED, binding);
  authorizeContext(context, trust, new Date((now + 59) * 1000).toISOString(), binding);
  assert.throws(() => authorizeContext(context, trust, new Date((now + 60) * 1000).toISOString(), binding),
    (err) => err instanceof HttpError && err.code === 'invalid_context_attestation');
});
