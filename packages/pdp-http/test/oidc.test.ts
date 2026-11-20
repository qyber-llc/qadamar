import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, IncomingMessage, ServerResponse, type Server } from 'node:http';
import { createHash, generateKeyPairSync, randomUUID, sign, type KeyObject } from 'node:crypto';
import { resolve } from 'node:path';
import { createHandler } from '../src/router.ts';
import { Oidc } from '../src/oidc.ts';
import { fixture } from './helpers.ts';

/** A local identity provider: discovery, JWKS and a token endpoint that checks PKCE and signs RS256 ID tokens. */
async function idp(t: { after: (fn: () => unknown) => void }) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const codes = new Map<string, { challenge: string; claims: Record<string, unknown> }>();
  let signer: KeyObject = privateKey;
  const server: Server = createServer((req, res) => {
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const send = (v: unknown, status = 200): void => { res.statusCode = status; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(v)); };
    if (req.url === '/.well-known/openid-configuration') return send({ issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, jwks_uri: `${base}/jwks` });
    if (req.url === '/jwks') return send({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' }] });
    if (req.url === '/token' && req.method === 'POST') {
      let raw = ''; req.on('data', (c) => { raw += c; }); req.on('end', () => {
        const form = new URLSearchParams(raw); const grant = codes.get(form.get('code') ?? '');
        if (!grant || createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url') !== grant.challenge) return send({ error: 'invalid_grant' }, 400);
        const head = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'k1' })).toString('base64url');
        const body = Buffer.from(JSON.stringify(grant.claims)).toString('base64url');
        send({ id_token: `${head}.${body}.${sign('sha256', Buffer.from(`${head}.${body}`), signer).toString('base64url')}` });
      }); return;
    }
    send({ error: 'not_found' }, 404);
  });
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  t.after(() => new Promise<void>((ok) => server.close(() => ok())));
  const issuer = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  return {
    issuer,
    /** The browser's round trip: the IdP authenticates the person and answers with a code bound to the PKCE challenge. */
    grant(location: string, extra: Record<string, unknown>): string {
      const q = new URL(location).searchParams; const code = `c${codes.size}`;
      const now = Math.floor(Date.now() / 1000);
      codes.set(code, { challenge: q.get('code_challenge')!, claims: { iss: issuer, aud: 'gate-console', sub: 'u-1', iat: now, exp: now + 300, nonce: q.get('nonce'), amr: ['pwd', 'mfa'], roles: ['approver'], preferred_username: 'omar', name: 'Omar H.', ...extra } });
      return code;
    },
    forge(): void { signer = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey; },
    /** A Back-Channel Logout 1.0 logout token signed by the IdP key. */
    logout(claims: Record<string, unknown>): string {
      const head = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'k1', typ: 'logout+jwt' })).toString('base64url');
      const body = Buffer.from(JSON.stringify({ iss: issuer, aud: 'gate-console', iat: Math.floor(Date.now() / 1000), jti: randomUUID(),
        events: { 'http://schemas.openid.net/event/backchannel-logout': {} }, ...claims })).toString('base64url');
      return `${head}.${body}.${sign('sha256', Buffer.from(`${head}.${body}`), signer).toString('base64url')}`;
    },
  };
}
interface Reply { status: number; headers: Record<string, unknown>; text: string }
async function get(handler: ReturnType<typeof createHandler>, path: string, cookie = ''): Promise<Reply> {
  const req = new IncomingMessage({ remoteAddress: '127.0.0.1', readable: false } as never); req.url = path; req.method = 'GET'; req.headers = cookie ? { cookie } : {};
  let text = ''; const res = new ServerResponse(req);
  res.end = ((chunk?: unknown): ServerResponse => { text = chunk === undefined ? '' : String(chunk); return res; }) as typeof res.end;
  const pending = handler(req, res); req.push(null); await pending;
  return { status: res.statusCode, headers: res.getHeaders(), text };
}
async function post(handler: ReturnType<typeof createHandler>, path: string, payload: string, contentType = 'application/x-www-form-urlencoded'): Promise<Reply> {
  const req = new IncomingMessage({ remoteAddress: '127.0.0.1', readable: false } as never); req.url = path; req.method = 'POST'; req.headers = { 'content-type': contentType };
  let text = ''; const res = new ServerResponse(req);
  res.end = ((chunk?: unknown): ServerResponse => { text = chunk === undefined ? '' : String(chunk); return res; }) as typeof res.end;
  const pending = handler(req, res); req.push(payload); req.push(null); await pending;
  return { status: res.statusCode, headers: res.getHeaders(), text };
}
const cookies = (r: Reply): string[] => [r.headers['set-cookie'] ?? []].flat().map(String);
const pick = (r: Reply, name: string): string => cookies(r).find((c) => c.startsWith(`${name}=`))!.split(';')[0]!;

async function setup(t: Parameters<typeof fixture>[0], extra: Partial<ConstructorParameters<typeof Oidc>[0]> = {}) {
  const f = fixture(t); const p = await idp(t);
  const oidc = new Oidc({ issuer: p.issuer, clientId: 'gate-console', idClaim: 'preferred_username', ...extra }, 'https://gate.example');
  const route = createHandler(f.rt, f.auth, { staticDir: resolve(f.dir, 'static'), security: { publicOrigin: 'https://gate.example', oidc, passwordLogin: false } }, () => 'https://gate.example');
  const start = async (): Promise<{ location: string; state: string; stateCookie: string }> => {
    const r = await get(route, '/admin/v1/oidc/login');
    assert.equal(r.status, 302);
    const location = String(r.headers.location);
    return { location, state: new URL(location).searchParams.get('state')!, stateCookie: pick(r, '__Host-gate_oidc') };
  };
  return { f, p, route, start };
}
const callback = async (s: { route: ReturnType<typeof createHandler>; p: Awaited<ReturnType<typeof idp>>; start: () => Promise<{ location: string; state: string; stateCookie: string }> }, claims: Record<string, unknown>): Promise<string> => {
  const st = await s.start();
  return String((await get(s.route, `/admin/v1/oidc/callback?code=${s.p.grant(st.location, claims)}&state=${st.state}`, st.stateCookie)).headers.location);
};

test('SSO sign-in: PKCE, signed ID token, MFA and roles open a Secure console session under the subject id', async (t) => {
  const { f, p, route, start } = await setup(t);
  const methods = await get(route, '/admin/v1/auth-methods');
  assert.deepEqual(JSON.parse(methods.text), { password: false, sso: true, saml: false });
  assert.equal(methods.headers['strict-transport-security'], 'max-age=31536000; includeSubDomains');
  const s = await start();
  const q = new URL(s.location).searchParams;
  assert.equal(q.get('redirect_uri'), 'https://gate.example/admin/v1/oidc/callback');
  assert.equal(q.get('code_challenge_method'), 'S256');
  assert.match(cookies(await get(route, '/admin/v1/oidc/login'))[0]!, /^__Host-gate_oidc=.*; HttpOnly; Secure; SameSite=Lax; Path=\/; Max-Age=600$/);
  const done = await get(route, `/admin/v1/oidc/callback?code=${p.grant(s.location, {})}&state=${s.state}`, s.stateCookie);
  assert.equal(done.status, 302); assert.equal(done.headers.location, '/');
  const sid = cookies(done).find((c) => c.startsWith('sid='))!;
  assert.match(sid, /HttpOnly; SameSite=Strict; Path=\/admin; Max-Age=28800; Secure$/);
  const me = await get(route, '/admin/v1/session', sid.split(';')[0]);
  assert.equal(me.status, 200);
  assert.deepEqual(JSON.parse(me.text).user, { id: 'omar', name: 'Omar H.', roles: ['approver'] });
  assert.ok(f.rt.audit.records().some((e) => e.action === 'login' && e.actor === 'omar' && e.effect === 'allow'));
  // the state is single use
  assert.equal((await get(route, `/admin/v1/oidc/callback?code=${p.grant(s.location, {})}&state=${s.state}`, s.stateCookie)).headers.location, '/?sso_error=sso_failed');
});

test('SSO refuses no MFA, no console role, a forged signature, a wrong audience, a foreign state and password sign-in', async (t) => {
  const { f, p, route, start } = await setup(t);
  const attempt = async (claims: Record<string, unknown>, tweak?: (s: Awaited<ReturnType<typeof start>>) => Awaited<ReturnType<typeof start>>): Promise<string> => {
    let s = await start(); const code = p.grant(s.location, claims); if (tweak) s = tweak(s);
    const r = await get(route, `/admin/v1/oidc/callback?code=${code}&state=${s.state}`, s.stateCookie);
    assert.ok(!cookies(r).some((c) => c.startsWith('sid=') && !c.startsWith('sid=;')), 'no session cookie on refusal');
    return String(r.headers.location);
  };
  assert.equal(await attempt({ amr: ['pwd'] }), '/?sso_error=mfa_required');
  assert.equal(await attempt({ roles: ['viewer'] }), '/?sso_error=no_role');
  assert.equal(await attempt({ aud: 'someone-else' }), '/?sso_error=sso_failed');
  assert.equal(await attempt({ exp: Math.floor(Date.now() / 1000) - 3600 }), '/?sso_error=sso_failed');
  assert.equal(await attempt({}, (s) => ({ ...s, stateCookie: '__Host-gate_oidc=attacker' })), '/?sso_error=sso_failed');
  p.forge();
  assert.equal(await attempt({}), '/?sso_error=sso_failed');
  assert.ok(f.rt.audit.records().some((e) => e.action === 'login' && e.effect === 'deny' && (e.details as { reason?: string })?.reason === 'mfa_required'));
  const pw = createHandler(f.rt, f.auth, { security: { publicOrigin: 'https://gate.example', passwordLogin: false } }, () => '');
  const req = new IncomingMessage({ remoteAddress: '127.0.0.1', readable: false } as never); req.url = '/admin/v1/session'; req.method = 'POST'; req.headers = { 'content-type': 'application/json' };
  let text = ''; const res = new ServerResponse(req); res.end = ((c?: unknown): ServerResponse => { text = String(c ?? ''); return res; }) as typeof res.end;
  const pending = pw(req, res); req.push(JSON.stringify({ username: 'amira', password: f.passwords.amira })); req.push(null); await pending;
  assert.equal(res.statusCode, 403); assert.equal(JSON.parse(text).error, 'password_login_disabled');
});

test('an acr requirement replaces the amr check and is sent to the IdP', async (t) => {
  const { p, route, start } = await setup(t, { acr: 'phr' });
  const s = await start();
  assert.equal(new URL(s.location).searchParams.get('acr_values'), 'phr');
  const r = await get(route, `/admin/v1/oidc/callback?code=${p.grant(s.location, { amr: ['pwd'], acr: '1' })}&state=${s.state}`, s.stateCookie);
  assert.equal(r.headers.location, '/?sso_error=mfa_required');
});

test('the id claim is required, compared as is, and an email id must be verified', async (t) => {
  assert.throws(() => new Oidc({ issuer: 'https://idp.example', clientId: 'c', idClaim: '' }, 'https://gate.example'), /OIDC_ID_CLAIM/);
  const s = await setup(t, { idClaim: 'email' });
  assert.equal(await callback(s, { email: 'omar@example.com', email_verified: false }), '/?sso_error=sso_failed');
  assert.equal(await callback(s, { email: ' omar@example.com' }), '/?sso_error=sso_failed');
  assert.equal(await callback(s, { email: 'omar@example.com', email_verified: true }), '/');
});

test('forged callbacks are refused without writing audit rows; refusals after a real start are audited', async (t) => {
  const s = await setup(t);
  const before = s.f.rt.audit.records().length;
  for (let i = 0; i < 5; i++) assert.equal(String((await get(s.route, '/admin/v1/oidc/callback?code=x&state=y', '__Host-gate_oidc=forged')).headers.location), '/?sso_error=sso_failed');
  assert.equal(s.f.rt.audit.records().length, before);
  assert.equal(await callback(s, { amr: ['pwd'] }), '/?sso_error=mfa_required');
  assert.equal(s.f.rt.audit.records().length, before + 1);
});

test('back-channel logout: a signed logout token ends the matching SSO session once, without CSRF, and is audited', async (t) => {
  const { f, p, route, start } = await setup(t);
  const st = await start();
  const signedIn = await get(route, `/admin/v1/oidc/callback?code=${p.grant(st.location, { sid: 'idp-session-1' })}&state=${st.state}`, st.stateCookie);
  const sid = pick(signedIn, 'sid');
  assert.equal((await get(route, '/admin/v1/session', sid)).status, 200);
  const path = '/admin/v1/oidc/backchannel-logout';
  const other = await post(route, path, `logout_token=${p.logout({ sid: 'another-session' })}`);
  assert.equal(other.status, 200);
  assert.equal((await get(route, '/admin/v1/session', sid)).status, 200, 'a token for another IdP session ends nothing');
  const forged = p.logout({ sid: 'idp-session-1' }).replace(/.$/, (c) => (c === 'A' ? 'B' : 'A'));
  assert.equal((await post(route, path, `logout_token=${forged}`)).status, 400);
  assert.equal((await post(route, path, JSON.stringify({ logout_token: 'x' }), 'application/json')).status, 415);
  const token = p.logout({ sub: 'u-1', sid: 'idp-session-1' });
  assert.equal((await post(route, path, `logout_token=${token}&logout_token=${token}`)).status, 400, 'a duplicated parameter is refused');
  const ended = await post(route, path, `logout_token=${token}`);
  assert.equal(ended.status, 200);
  assert.equal(ended.headers['cache-control'], 'no-store');
  assert.equal((await get(route, '/admin/v1/session', sid)).status, 401);
  assert.equal((await post(route, path, `logout_token=${token}`)).status, 400, 'a replayed jti is refused');
  const rows = f.rt.audit.records().filter((row) => row.action === 'oidc_backchannel_logout');
  assert.deepEqual(rows.map((row) => [row.effect, row.details?.sessionsEnded]), [['allow', 0], ['deny', undefined], ['allow', 1]]);
  assert.ok(!JSON.stringify(f.rt.audit.records()).includes(token));
});
