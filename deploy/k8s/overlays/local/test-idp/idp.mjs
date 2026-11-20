// TEST ONLY (deploy/k8s/overlays/local). A minimal OpenID Connect provider for the production-profile smoke test,
// adapted from the fake IdP of packages/pdp-http/test/oidc.test.ts: discovery, JWKS, authorization code + PKCE (S256),
// RS256 ID tokens with MFA in `amr`. It signs in whoever names a test user in `login_hint`, WITHOUT A PASSWORD:
// never deploy it anywhere else. `test_mfa=0` leaves MFA out of `amr`, to check that Qadamar refuses the sign-in.
import { createServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { createHash, generateKeyPairSync, randomBytes, sign, timingSafeEqual } from 'node:crypto';

const env = (name) => { const v = process.env[name]; if (!v) throw new Error(`${name} is required`); return v; };
const issuer = env('TEST_IDP_ISSUER'), clientId = env('OIDC_CLIENT_ID'), clientSecret = env('OIDC_CLIENT_SECRET');
const redirectUri = env('TEST_IDP_REDIRECT_URI');
const USERS = {
  sam: { name: 'Sam (test auditor)', roles: ['auditor'] },
  amira: { name: 'Amira (test access admin)', roles: ['access_admin'] },
  omar: { name: 'Omar (test approver)', roles: ['approver'] },
  lina: { name: 'Lina (test security officer)', roles: ['security_officer'] },
  noor: { name: 'Noor (second test security officer: reviews what lina opened)', roles: ['security_officer'] },
};
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const kid = randomBytes(8).toString('hex');
const codes = new Map(); // code -> { challenge, claims, expires }
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
  res.end(body === undefined ? '' : JSON.stringify(body));
}
function authorize(url, res) {
  const q = url.searchParams, user = USERS[q.get('login_hint') ?? ''];
  if (q.get('response_type') !== 'code' || q.get('client_id') !== clientId || q.get('redirect_uri') !== redirectUri) return send(res, 400, { error: 'invalid_request' });
  if (q.get('code_challenge_method') !== 'S256' || !q.get('code_challenge') || !q.get('state') || !q.get('nonce')) return send(res, 400, { error: 'invalid_request', error_description: 'PKCE S256, state and nonce are required' });
  if (!user) return send(res, 400, { error: 'login_required', error_description: `login_hint must be one of ${Object.keys(USERS).join(', ')}` });
  const mfa = q.get('test_mfa') !== '0';
  const now = Math.floor(Date.now() / 1000), code = randomBytes(24).toString('base64url');
  for (const [c, grant] of codes) if (grant.expires < Date.now()) codes.delete(c);
  codes.set(code, { challenge: q.get('code_challenge'), expires: Date.now() + 60_000, claims: { iss: issuer, aud: clientId, sub: `test-${q.get('login_hint')}`,
    preferred_username: q.get('login_hint'), name: user.name, roles: user.roles, amr: mfa ? ['pwd', 'otp', 'mfa'] : ['pwd'],
    sid: randomBytes(12).toString('base64url'), nonce: q.get('nonce'), iat: now, exp: now + 300 } });
  console.log(`authorized ${q.get('login_hint')} (mfa ${mfa})`);
  const back = new URL(redirectUri); back.searchParams.set('code', code); back.searchParams.set('state', q.get('state'));
  send(res, 302, undefined, { location: back.toString() });
}
function token(raw, res) {
  const form = new URLSearchParams(raw), grant = codes.get(form.get('code') ?? '');
  codes.delete(form.get('code') ?? '');
  if (form.get('grant_type') !== 'authorization_code' || !grant || grant.expires < Date.now()) return send(res, 400, { error: 'invalid_grant' });
  if (form.get('client_id') !== clientId || !same(form.get('client_secret') ?? '', clientSecret) || form.get('redirect_uri') !== redirectUri) return send(res, 401, { error: 'invalid_client' });
  if (createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url') !== grant.challenge) return send(res, 400, { error: 'invalid_grant' });
  const signing = `${b64({ alg: 'RS256', kid, typ: 'JWT' })}.${b64(grant.claims)}`;
  const idToken = `${signing}.${sign('sha256', Buffer.from(signing), privateKey).toString('base64url')}`;
  send(res, 200, { access_token: randomBytes(24).toString('base64url'), token_type: 'Bearer', expires_in: 300, id_token: idToken });
}
const server = createServer({ cert: readFileSync('/etc/test-services/tls.crt'), key: readFileSync('/etc/test-services/tls.key') }, (req, res) => {
  const url = new URL(req.url ?? '/', issuer);
  if (req.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
    return send(res, 200, { issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/jwks`,
      response_types_supported: ['code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'], code_challenge_methods_supported: ['S256'] });
  }
  if (req.method === 'GET' && url.pathname === '/jwks') return send(res, 200, { keys: [{ ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' }] });
  if (req.method === 'GET' && url.pathname === '/authorize') return authorize(url, res);
  if (req.method === 'POST' && url.pathname === '/token') {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => { raw += chunk; if (raw.length > 16_384) req.destroy(); });
    req.on('end', () => token(raw, res));
    return;
  }
  send(res, 404, { error: 'not_found' });
});
server.listen(8443, () => console.log(`TEST-ONLY OIDC provider ${issuer} listening on 8443`));
process.once('SIGTERM', () => server.close(() => process.exit(0)));
