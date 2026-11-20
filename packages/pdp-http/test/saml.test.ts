import test from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage, ServerResponse } from 'node:http';
import { generateKeyPairSync, randomUUID, sign, X509Certificate, type KeyObject } from 'node:crypto';
import { createRequire } from 'node:module';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { signXml } from '@node-saml/node-saml/lib/xml.js';
import { createHandler } from '../src/router.ts';
import { Saml, samlFromEnv, type SamlConfig } from '../src/saml.ts';
import { evaluation, fixture } from './helpers.ts';
import { createTenantServer, tenantManifest } from '../src/tenants.ts';

const ORIGIN = 'https://gate.example';
const ACS = `${ORIGIN}/admin/v1/saml/acs`;
const SP = `${ORIGIN}/admin/v1/saml/metadata`;
const IDP = 'https://idp.example/saml';
const MFA = 'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract';

/** A throwaway IdP signing identity: an RSA key and a self-signed X.509 certificate, DER built by hand (node:crypto signs
 *  keys, not certificates). */
function identity(): { key: KeyObject; pem: string } {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const der = (tag: number, ...parts: Buffer[]): Buffer => {
    const body = Buffer.concat(parts); const len: number[] = [];
    for (let n = body.length; n > 0; n >>= 8) len.unshift(n & 255);
    return Buffer.concat([Buffer.from([tag]), Buffer.from(body.length < 128 ? [body.length] : [0x80 | len.length, ...len]), body]);
  };
  const seq = (...p: Buffer[]): Buffer => der(0x30, ...p);
  const oid = (hex: string): Buffer => der(0x06, Buffer.from(hex, 'hex'));
  const time = (ms: number): Buffer => der(0x17, Buffer.from(`${new Date(ms).toISOString().replace(/[-:T]/g, '').slice(2, 14)}Z`));
  const sha256Rsa = seq(oid('2a864886f70d01010b'), der(0x05));
  const name = seq(der(0x31, seq(oid('550403'), der(0x0c, Buffer.from('Test IdP')))));
  const tbs = seq(der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, Buffer.from([1])), sha256Rsa, name, seq(time(Date.now() - 3_600_000), time(Date.now() + 86_400_000)), name,
    publicKey.export({ type: 'spki', format: 'der' }));
  const cert = seq(tbs, sha256Rsa, der(0x03, Buffer.from([0]), sign('sha256', tbs, privateKey)));
  const pem = `-----BEGIN CERTIFICATE-----\n${cert.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END CERTIFICATE-----\n`;
  assert.ok(new X509Certificate(pem).verify(publicKey));
  return { key: privateKey, pem };
}

interface Claims { inResponseTo: string; issuer?: string; audience?: string; recipient?: string; destination?: string; classRef?: string;
  nameId?: string; uid?: string; roles?: string[]; issuedMs?: number; lifeMs?: number; sessionIndex?: string; authnMs?: number }
const iso = (ms: number): string => new Date(ms).toISOString();
function assertionXml(c: Claims, id = `_a${randomUUID()}`): string {
  const at = c.issuedMs ?? Date.now(), until = iso(at + (c.lifeMs ?? 300_000));
  return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${iso(at)}">`
    + `<saml:Issuer>${c.issuer ?? IDP}</saml:Issuer>`
    + `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${c.nameId ?? 'u-1'}</saml:NameID>`
    + `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${c.inResponseTo}" Recipient="${c.recipient ?? ACS}" NotOnOrAfter="${until}"/></saml:SubjectConfirmation></saml:Subject>`
    + `<saml:Conditions NotBefore="${iso(at - 1000)}" NotOnOrAfter="${until}"><saml:AudienceRestriction><saml:Audience>${c.audience ?? SP}</saml:Audience></saml:AudienceRestriction></saml:Conditions>`
    + `<saml:AuthnStatement AuthnInstant="${iso(c.authnMs ?? at)}" SessionIndex="${c.sessionIndex ?? 'idp-session-1'}"><saml:AuthnContext><saml:AuthnContextClassRef>${c.classRef ?? MFA}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`
    + `<saml:AttributeStatement><saml:Attribute Name="uid"><saml:AttributeValue>${c.uid ?? 'omar'}</saml:AttributeValue></saml:Attribute>`
    + `<saml:Attribute Name="roles">${(c.roles ?? ['approver']).map((r) => `<saml:AttributeValue>${r}</saml:AttributeValue>`).join('')}</saml:Attribute>`
    + `<saml:Attribute Name="displayName"><saml:AttributeValue>Omar H.</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`
    + '</saml:Assertion>';
}
const responseXml = (c: Claims, inner: string): string => `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r${randomUUID()}" Version="2.0" IssueInstant="${iso(Date.now())}" Destination="${c.destination ?? ACS}" InResponseTo="${c.inResponseTo}">`
  + `<saml:Issuer>${c.issuer ?? IDP}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${inner}</samlp:Response>`;
/** The library's own signer (xml-crypto underneath): enveloped signature placed after the element's Issuer. */
const signed = (xml: string, element: string, key: KeyObject, algorithm: 'sha256' | 'sha1' = 'sha256'): string => signXml(xml, `//*[local-name(.)='${element}']`,
  { reference: `//*[local-name(.)='${element}']/*[local-name(.)='Issuer']`, action: 'after' },
  { privateKey: key.export({ type: 'pkcs8', format: 'pem' }), signatureAlgorithm: algorithm, digestAlgorithm: algorithm });
const b64 = (xml: string): string => encodeURIComponent(Buffer.from(xml).toString('base64'));

interface Reply { status: number; headers: Record<string, unknown>; text: string }
async function call(handler: ReturnType<typeof createHandler>, method: string, path: string, cookie = '', payload?: string, headers: Record<string, string> = {}): Promise<Reply> {
  const req = new IncomingMessage({ remoteAddress: '127.0.0.1', readable: false } as never); req.url = path; req.method = method;
  req.headers = { ...(payload !== undefined ? { 'content-type': 'application/x-www-form-urlencoded' } : {}), ...headers, ...(cookie ? { cookie } : {}) };
  let text = ''; const res = new ServerResponse(req);
  res.end = ((chunk?: unknown): ServerResponse => { text = chunk === undefined ? '' : String(chunk); return res; }) as typeof res.end;
  const pending = handler(req, res); if (payload !== undefined) req.push(payload); req.push(null); await pending;
  return { status: res.statusCode, headers: res.getHeaders(), text };
}
const cookies = (r: Reply): string[] => [r.headers['set-cookie'] ?? []].flat().map(String);
const pick = (r: Reply, name: string): string => cookies(r).find((c) => c.startsWith(`${name}=`))!.split(';')[0]!;

function setup(t: Parameters<typeof fixture>[0], extra: Partial<SamlConfig> = {}) {
  const f = fixture(t); const idp = identity();
  const saml = new Saml({ idpEntityId: IDP, idpSsoUrl: 'https://idp.example/sso', idpCert: idp.pem, authnContext: [MFA], idAttribute: 'uid', ...extra }, ORIGIN);
  const route = createHandler(f.rt, f.auth, { staticDir: resolve(f.dir, 'static'), security: { publicOrigin: ORIGIN, saml, passwordLogin: false } }, () => ORIGIN);
  /** A sign-in start: the AuthnRequest id, and the cookie that binds it to this browser. */
  const start = async (): Promise<{ id: string; cookie: string; location: string }> => {
    const r = await call(route, 'GET', '/admin/v1/saml/login');
    assert.equal(r.status, 302);
    const cookie = pick(r, '__Host-gate_saml');
    return { id: cookie.split('=')[1]!, cookie, location: String(r.headers.location) };
  };
  const acs = (cookie: string, xml: string): Promise<Reply> => call(route, 'POST', '/admin/v1/saml/acs', cookie, `SAMLResponse=${b64(xml)}`);
  /** A full round trip with a signed assertion; `claims` and `build` vary what the IdP sends. */
  const attempt = async (claims: Partial<Claims> = {}, build?: (c: Claims) => string | Promise<string>): Promise<Reply> => {
    const s = await start(); const c = { inResponseTo: s.id, ...claims };
    return acs(s.cookie, build ? await build(c) : responseXml(c, signed(assertionXml(c), 'Assertion', idp.key)));
  };
  return { f, idp, route, start, acs, attempt };
}
const refusal = (r: Reply): string => { assert.ok(!cookies(r).some((c) => c.startsWith('sid=')), 'no session cookie on refusal'); return String(r.headers.location); };

test('SAML sign-in: a signed assertion answering this browser\'s AuthnRequest, with MFA and a role, opens a session', async (t) => {
  const { f, route, start, acs, idp } = setup(t);
  assert.deepEqual(JSON.parse((await call(route, 'GET', '/admin/v1/auth-methods')).text), { password: false, sso: false, saml: true });
  const s = await start();
  const request = inflateRawSync(Buffer.from(new URL(s.location).searchParams.get('SAMLRequest')!, 'base64')).toString('utf8');
  assert.ok(s.location.startsWith('https://idp.example/sso?SAMLRequest='));
  assert.match(request, new RegExp(`ID="${s.id}"`));
  assert.match(request, /AssertionConsumerServiceURL="https:\/\/gate\.example\/admin\/v1\/saml\/acs"/);
  assert.match(request, /Comparison="exact"[\s\S]*MobileTwoFactorContract/);
  assert.match(cookies(await call(route, 'GET', '/admin/v1/saml/login'))[0]!, /^__Host-gate_saml=_[0-9a-f]+; HttpOnly; Secure; SameSite=None; Path=\/; Max-Age=600$/);
  const c = { inResponseTo: s.id };
  const xml = responseXml(c, signed(assertionXml(c), 'Assertion', idp.key));
  const done = await acs(s.cookie, xml);
  assert.equal(done.status, 302); assert.equal(done.headers.location, '/');
  assert.ok(cookies(done).includes('__Host-gate_saml=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0'));
  const sid = pick(done, 'sid');
  const me = await call(route, 'GET', '/admin/v1/session', sid);
  assert.equal(me.status, 200);
  assert.deepEqual(JSON.parse(me.text).user, { id: 'omar', name: 'Omar H.', roles: ['approver'] });
  assert.ok(f.rt.audit.records().some((e) => e.action === 'login' && e.actor === 'omar' && e.effect === 'allow' && (e.details as { method?: string }).method === 'saml'));
  // replay: the same response again, and another signed assertion for the same (consumed) request id
  assert.equal(refusal(await acs(s.cookie, xml)), '/?sso_error=sso_failed');
  assert.equal(refusal(await acs(s.cookie, responseXml(c, signed(assertionXml(c), 'Assertion', idp.key)))), '/?sso_error=sso_failed');
  const metadata = await call(route, 'GET', '/admin/v1/saml/metadata');
  assert.match(String(metadata.headers['content-type']), /samlmetadata\+xml/);
  assert.match(metadata.text, /WantAssertionsSigned="true"/);
  assert.match(metadata.text, /entityID="https:\/\/gate\.example\/admin\/v1\/saml\/metadata"/);
});

test('SAML refuses unsigned, response-only signed, forged, SHA-1, wrong audience, recipient, destination, issuer, expired and DOCTYPE', async (t) => {
  const { idp, attempt } = setup(t);
  const other = identity();
  assert.equal(refusal(await attempt({}, (c) => responseXml(c, assertionXml(c)))), '/?sso_error=sso_failed', 'unsigned');
  assert.equal(refusal(await attempt({}, (c) => signed(responseXml(c, assertionXml(c)), 'Response', idp.key))), '/?sso_error=sso_failed', 'only the Response is signed');
  assert.equal(refusal(await attempt({}, (c) => responseXml(c, signed(assertionXml(c), 'Assertion', other.key)))), '/?sso_error=sso_failed', 'another key');
  assert.equal(refusal(await attempt({}, (c) => responseXml(c, signed(assertionXml(c), 'Assertion', idp.key, 'sha1')))), '/?sso_error=sso_failed', 'SHA-1');
  assert.equal(refusal(await attempt({ audience: 'https://other-sp.example' })), '/?sso_error=sso_failed', 'audience');
  assert.equal(refusal(await attempt({ recipient: 'https://evil.example/acs' })), '/?sso_error=sso_failed', 'recipient');
  assert.equal(refusal(await attempt({ destination: 'https://evil.example/acs' })), '/?sso_error=sso_failed', 'destination');
  assert.equal(refusal(await attempt({ issuer: 'https://other-idp.example' })), '/?sso_error=sso_failed', 'issuer');
  assert.equal(refusal(await attempt({ issuedMs: Date.now() - 600_000, lifeMs: 300_000 })), '/?sso_error=sso_failed', 'expired');
  assert.equal(refusal(await attempt({ issuedMs: Date.now() + 600_000 })), '/?sso_error=sso_failed', 'not yet valid');
  assert.equal(refusal(await attempt({}, (c) => `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>${responseXml(c, signed(assertionXml(c), 'Assertion', idp.key))}`)), '/?sso_error=sso_failed', 'DOCTYPE');
  // the control: the same IdP and setup accept a well-formed response
  assert.equal((await attempt()).headers.location, '/');
});

test('SAML signature wrapping: a signed assertion moved aside while an unsigned one takes its place is refused', async (t) => {
  const { attempt, idp } = setup(t);
  const wrap = (c: Claims): string => {
    const genuine = signed(assertionXml(c), 'Assertion', idp.key);
    const signature = /<Signature[\s\S]*<\/Signature>/.exec(genuine)![0];
    const evil = assertionXml({ ...c, uid: 'mallory', roles: ['access_admin'] }).replace(`<saml:Issuer>${IDP}</saml:Issuer>`, `<saml:Issuer>${IDP}</saml:Issuer>${signature}`);
    return responseXml(c, `<samlp:Extensions>${genuine}</samlp:Extensions>${evil}`);
  };
  assert.equal(refusal(await attempt({}, wrap)), '/?sso_error=sso_failed', 'evil assertion carrying the genuine signature');
  const sameId = (c: Claims): string => {
    const genuine = signed(assertionXml(c, '_same'), 'Assertion', idp.key);
    return responseXml(c, `<samlp:Extensions>${genuine}</samlp:Extensions>${assertionXml({ ...c, uid: 'mallory', roles: ['access_admin'] }, '_same')}`);
  };
  assert.equal(refusal(await attempt({}, sameId)), '/?sso_error=sso_failed', 'evil assertion with the genuine ID');
  assert.equal(refusal(await attempt({}, (c) => responseXml(c, signed(assertionXml(c), 'Assertion', idp.key) + signed(assertionXml({ ...c, uid: 'mallory' }), 'Assertion', idp.key)))),
    '/?sso_error=sso_failed', 'two assertions');
});

test('SAML requires an allowlisted AuthnContextClassRef (MFA), a console role and an id; a foreign request cookie writes no audit row', async (t) => {
  const { f, idp, start, acs, attempt } = setup(t);
  assert.equal(refusal(await attempt({ classRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' })), '/?sso_error=mfa_required');
  assert.equal(refusal(await attempt({ roles: ['viewer'] })), '/?sso_error=no_role');
  assert.equal(refusal(await attempt({ uid: ' omar' })), '/?sso_error=sso_failed');
  const reasons = f.rt.audit.records().filter((e) => e.action === 'login' && e.effect === 'deny').map((e) => (e.details as { reason?: string; method?: string }));
  assert.deepEqual(reasons.map((d) => [d.method, d.reason]), [['saml', 'mfa_required'], ['saml', 'no_role'], ['saml', 'sso_failed']]);
  // login CSRF: a response answering another browser's request, posted with this browser's cookie (or none), is refused quietly
  const before = f.rt.audit.records().length;
  const mine = await start(), theirs = await start();
  const c = { inResponseTo: theirs.id };
  const xml = responseXml(c, signed(assertionXml(c), 'Assertion', idp.key));
  assert.equal(refusal(await acs(mine.cookie, xml)), '/?sso_error=sso_failed');
  assert.equal(refusal(await acs('', xml)), '/?sso_error=sso_failed');
  assert.equal(f.rt.audit.records().length, before);
  assert.equal((await acs(theirs.cookie, xml)).headers.location, '/', 'the browser that started it still signs in');
  assert.throws(() => new Saml({ idpEntityId: IDP, idpSsoUrl: 'https://idp.example/sso', idpCert: idp.pem, authnContext: [], idAttribute: 'uid' }, ORIGIN), /SAML_AUTHN_CONTEXT/);
  assert.throws(() => new Saml({ idpEntityId: IDP, idpSsoUrl: 'http://idp.example/sso', idpCert: idp.pem, authnContext: [MFA], idAttribute: 'uid' }, ORIGIN), /SAML_IDP_SSO_URL/);
  assert.throws(() => new Saml({ idpEntityId: IDP, idpSsoUrl: 'https://idp.example/sso', idpCert: 'not a pem', authnContext: [MFA], idAttribute: 'uid' }, ORIGIN), /no PEM certificate/);
});

test('SAML single logout: a signed LogoutRequest ends the matching session once, without CSRF, and is audited', async (t) => {
  const { f, idp, route, attempt } = setup(t, { idAttribute: 'NameID' });
  const done = await attempt({ nameId: 'omar', sessionIndex: 'idp-session-1' });
  const sid = pick(done, 'sid');
  assert.equal((await call(route, 'GET', '/admin/v1/session', sid)).status, 200);
  const logout = (o: { sessionIndex?: string; nameId?: string; key?: KeyObject; algorithm?: 'sha256' | 'sha1'; issuedMs?: number } = {}): string => {
    const xml = `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_l${randomUUID()}" Version="2.0" IssueInstant="${iso(o.issuedMs ?? Date.now())}" Destination="${ORIGIN}/admin/v1/saml/logout">`
      + `<saml:Issuer>${IDP}</saml:Issuer><saml:NameID>${o.nameId ?? 'omar'}</saml:NameID><samlp:SessionIndex>${o.sessionIndex ?? 'idp-session-1'}</samlp:SessionIndex></samlp:LogoutRequest>`;
    return o.key === null ? xml : signed(xml, 'LogoutRequest', o.key ?? idp.key, o.algorithm);
  };
  const path = '/admin/v1/saml/logout';
  const send = (xml: string): Promise<Reply> => call(route, 'POST', path, '', `SAMLRequest=${b64(xml)}`);
  assert.equal((await send(logout({ sessionIndex: 'another-session' }))).status, 302);
  assert.equal((await call(route, 'GET', '/admin/v1/session', sid)).status, 200, 'another IdP session ends nothing');
  assert.equal((await send(logout({ key: identity().key }))).status, 400, 'forged');
  assert.equal((await send(logout({ algorithm: 'sha1' }))).status, 400, 'SHA-1');
  assert.equal((await send(logout({ issuedMs: Date.now() - 2 * 86_400_000 }))).status, 400, 'too old');
  assert.equal((await send(logout({ issuedMs: Date.now() - 10 * 60_000 }))).status, 400, 'older than the 5-minute replay window');
  assert.equal((await send(logout().replace(/<Signature[\s\S]*<\/Signature>/, ''))).status, 400, 'unsigned');
  const request = logout();
  const ended = await send(request);
  assert.equal(ended.status, 302);
  assert.equal((await call(route, 'GET', '/admin/v1/session', sid)).status, 401);
  assert.equal((await send(request)).status, 400, 'a replayed ID is refused');
  const rows = f.rt.audit.records().filter((row) => row.action === 'saml_logout');
  assert.deepEqual(rows.map((row) => [row.effect, row.details?.sessionsEnded]), [['allow', 0], ['deny', undefined], ['allow', 1]]);
});

test('SAML bounds how long ago the IdP authenticated the user (SAML_MAX_AUTH_AGE_SECONDS, 12 h by default)', async (t) => {
  const { attempt } = setup(t);
  assert.equal((await attempt({ authnMs: Date.now() - 11 * 3_600_000 })).status, 302);
  assert.equal(refusal(await attempt({ authnMs: Date.now() - 13 * 3_600_000 })), '/?sso_error=sso_failed', 'an IdP session older than 12 h');
  assert.equal(refusal(await attempt({ authnMs: Date.now() + 10 * 60_000 })), '/?sso_error=sso_failed', 'authenticated in the future');
  const strict = setup(t, { maxAuthAgeSeconds: 600 });
  assert.equal(refusal(await strict.attempt({ authnMs: Date.now() - 20 * 60_000 })), '/?sso_error=sso_failed');
  assert.ok(cookies(await strict.attempt({ authnMs: Date.now() - 5 * 60_000 })).some((c) => c.startsWith('sid=')));
  assert.throws(() => setup(t, { maxAuthAgeSeconds: 10 }), /SAML_MAX_AUTH_AGE_SECONDS/);
});

const pemKey = (id: ReturnType<typeof identity>): string => id.key.export({ type: 'pkcs8', format: 'pem' }) as string;
const require = createRequire(import.meta.url);
const encryption = createRequire(require.resolve('@node-saml/node-saml'))('xml-encryption') as {
  encrypt(xml: string, options: Record<string, unknown>, cb: (error: Error | null, xml: string) => void): void;
};
const encrypted = async (xml: string, sp: ReturnType<typeof identity>): Promise<string> => {
  const data = await new Promise<string>((accept, reject) => encryption.encrypt(xml, {
    rsa_pub: new X509Certificate(sp.pem).publicKey.export({ type: 'spki', format: 'pem' }), pem: sp.pem,
    encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm', keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
  }, (error, result) => error ? reject(error) : accept(result)));
  return `<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${data.replace(/<DigestMethod[^>]*\/>/, '')}</saml:EncryptedAssertion>`;
};

test('encrypted assertions retain signature, algorithm, audience, recipient, time, MFA and replay checks', async (t) => {
  const sp = identity();
  const { attempt, idp, start, acs } = setup(t, { decryptionKey: pemKey(sp), decryptionCert: sp.pem });
  const build = async (c: Claims, algorithm: 'sha256' | 'sha1' = 'sha256', key = idp.key) => responseXml(c, await encrypted(signed(assertionXml(c), 'Assertion', key, algorithm), sp));
  assert.equal((await attempt({}, build)).headers.location, '/');
  for (const claims of [{ audience: 'wrong' }, { recipient: 'https://wrong.example' }, { issuer: 'wrong' }, { issuedMs: Date.now() - 600_000 }, { issuedMs: Date.now() + 600_000 }]) {
    assert.equal(refusal(await attempt(claims, build)), '/?sso_error=sso_failed');
  }
  assert.equal(refusal(await attempt({}, (c) => build(c, 'sha1'))), '/?sso_error=sso_failed');
  assert.equal(refusal(await attempt({}, (c) => build(c, 'sha256', identity().key))), '/?sso_error=sso_failed');
  assert.equal(refusal(await attempt({}, async (c) => responseXml(c, await encrypted(assertionXml(c), sp)))), '/?sso_error=sso_failed');
  assert.equal(refusal(await attempt({}, async (c) => responseXml(c, await encrypted(signed(assertionXml(c), 'Assertion', idp.key), identity())))), '/?sso_error=sso_failed', 'wrong decryption key');
  assert.equal(refusal(await attempt({}, async (c) => responseXml(c, (await encrypted(signed(assertionXml(c), 'Assertion', idp.key), sp)).replace(/(<[^>]*CipherValue>)[A-Za-z0-9+/]/, '$1!')))), '/?sso_error=sso_failed', 'damaged ciphertext');
  assert.equal(refusal(await attempt({ classRef: 'password' }, build)), '/?sso_error=mfa_required');
  const other = setup(t);
  assert.equal(refusal(await other.attempt({}, async (c) => responseXml(c, await encrypted(signed(assertionXml(c), 'Assertion', other.idp.key), sp)))), '/?sso_error=sso_failed');
  assert.throws(() => setup(t, { decryptionKey: pemKey(identity()), decryptionCert: identity().pem }), /matching RSA/);
  const s = await start(), c = { inResponseTo: s.id }, xml = await build(c);
  assert.equal((await acs(s.cookie, xml)).headers.location, '/');
  assert.equal(refusal(await acs(s.cookie, xml)), '/?sso_error=sso_failed');
});

const LOGOUT = `${ORIGIN}/admin/v1/saml/logout`;
function redirectQuery(xml: string, key: KeyObject, parameter = 'SAMLRequest', relay = 'opaque', algorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'): string {
  const content = `${parameter}=${encodeURIComponent(deflateRawSync(xml).toString('base64'))}&RelayState=${encodeURIComponent(relay)}&SigAlg=${encodeURIComponent(algorithm)}`;
  return `${content}&Signature=${encodeURIComponent(sign(algorithm.endsWith('sha1') ? 'sha1' : 'sha256', Buffer.from(content), key).toString('base64'))}`;
}
const logoutXml = (kind: 'LogoutRequest' | 'LogoutResponse', extra = '', inner = '', issuer = IDP): string =>
  `<samlp:${kind} xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_l${randomUUID()}" Version="2.0" IssueInstant="${iso(Date.now())}" Destination="${LOGOUT}" ${extra}><saml:Issuer>${issuer}</saml:Issuer>${inner}</samlp:${kind}>`;
const logoutSubject = '<saml:NameID>u-1</saml:NameID><samlp:SessionIndex>idp-session-1</samlp:SessionIndex>';
const success = '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>';

test('Redirect logout requires the original signed query, ends the session and returns a signed correlated LogoutResponse', async (t) => {
  const sp = identity();
  const { route, attempt, idp } = setup(t, { idpSloUrl: 'https://idp.example/logout', signingKey: pemKey(sp), signingCert: sp.pem });
  const sid = pick(await attempt(), 'sid');
  const xml = logoutXml('LogoutRequest', '', logoutSubject);
  const query = redirectQuery(xml, idp.key);
  const send = (q: string) => call(route, 'GET', `/admin/v1/saml/logout?${q}`);
  for (const invalid of [query.replace('opaque', 'changed'), query + '&SAMLRequest=other', query + '&RelayState=other', query + '&SigAlg=other', query + '&Signature=other', query.split('&Signature=')[0]!,
    redirectQuery(xml, identity().key), redirectQuery(xml, idp.key, 'SAMLRequest', '', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'),
    redirectQuery(xml.replace(LOGOUT, 'https://evil.example/logout'), idp.key), redirectQuery(xml.replace(IDP, 'wrong'), idp.key),
    redirectQuery(xml.replace(/IssueInstant="[^"]+"/, `IssueInstant="${iso(Date.now() - 600_000)}"`), idp.key)]) {
    assert.equal((await send(invalid)).status, 400);
  }
  assert.equal((await call(route, 'GET', '/admin/v1/session', sid)).status, 200);
  const ended = await send(query);
  assert.equal(ended.status, 302);
  const url = new URL(String(ended.headers.location));
  assert.equal(url.origin + url.pathname, 'https://idp.example/logout');
  assert.equal(url.searchParams.get('RelayState'), 'opaque');
  const response = inflateRawSync(Buffer.from(url.searchParams.get('SAMLResponse')!, 'base64')).toString();
  assert.match(response, new RegExp(`InResponseTo="${/ID="([^"]+)"/.exec(xml)![1]}"`));
  const content = url.search.slice(1).split('&Signature=')[0]!;
  assert.ok((await import('node:crypto')).verify('sha256', Buffer.from(content), new X509Certificate(sp.pem).publicKey, Buffer.from(url.searchParams.get('Signature')!, 'base64')));
  assert.equal((await call(route, 'GET', '/admin/v1/session', sid)).status, 401);
  assert.equal((await send(query)).status, 400);
  const metadata = (await call(route, 'GET', '/admin/v1/saml/metadata')).text;
  assert.match(metadata, /bindings:HTTP-Redirect/);
  assert.ok(!metadata.includes('PRIVATE KEY'));
});

test('console sign out starts signed SLO, immediately revokes cookie and CSRF, and accepts a correlated response once over either binding', async (t) => {
  const sp = identity();
  const { route, attempt, idp } = setup(t, { idpSloUrl: 'https://idp.example/logout', signingKey: pemKey(sp), signingCert: sp.pem });
  for (const binding of ['POST', 'Redirect']) {
    const sid = pick(await attempt(), 'sid');
    const me = JSON.parse((await call(route, 'GET', '/admin/v1/session', sid)).text);
    assert.equal((await call(route, 'DELETE', '/admin/v1/session', sid)).status, 403);
    const ended = await call(route, 'DELETE', '/admin/v1/session', sid, undefined, { 'x-csrf-token': me.csrfToken });
    assert.equal(ended.status, 200);
    const location = new URL(JSON.parse(ended.text).logoutUrl);
    const request = inflateRawSync(Buffer.from(location.searchParams.get('SAMLRequest')!, 'base64')).toString();
    assert.match(request, /nameid-format:persistent/);
    const id = / ID="([^"]+)"/.exec(request)![1]!;
    assert.equal((await call(route, 'GET', '/admin/v1/session', sid)).status, 401);
    assert.equal((await call(route, 'DELETE', '/admin/v1/session', sid, undefined, { 'x-csrf-token': me.csrfToken })).status, 401);
    const response = logoutXml('LogoutResponse', `InResponseTo="${id}"`, success);
    const send = (xml: string) => binding === 'POST'
      ? call(route, 'POST', '/admin/v1/saml/logout', '', `SAMLResponse=${b64(signed(xml, 'LogoutResponse', idp.key))}`)
      : call(route, 'GET', `/admin/v1/saml/logout?${redirectQuery(xml, idp.key, 'SAMLResponse')}`);
    assert.equal((await send(response.replace(id, '_foreign'))).status, 400);
    assert.equal((await send(response)).status, 302);
    assert.equal((await send(response)).status, 400);
  }
  assert.equal((await call(route, 'POST', '/admin/v1/saml/logout/start')).status, 401);
});

test('SAML PEM configuration reads mounted secrets and refuses incomplete key pairs', (t) => {
  const dir = mkdtempSync('/tmp/gate-saml-env-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const sp = identity(); writeFileSync(`${dir}/key`, pemKey(sp)); writeFileSync(`${dir}/cert`, sp.pem);
  assert.equal(samlFromEnv({}), undefined);
  assert.throws(() => samlFromEnv({ SAML_IDP_ENTITY_ID: IDP }), /SAML_IDP_CERT_FILE/);
  const env = { SAML_IDP_ENTITY_ID: IDP, SAML_IDP_SSO_URL: 'https://idp.example/sso', SAML_IDP_CERT_FILE: `${dir}/cert`, SAML_ID_ATTRIBUTE: 'uid', SAML_AUTHN_CONTEXT: MFA,
    SAML_IDP_SLO_URL: 'https://idp.example/logout', SAML_DECRYPTION_KEY_FILE: `${dir}/key`, SAML_DECRYPTION_CERT_FILE: `${dir}/cert`, SAML_SIGNING_KEY_FILE: `${dir}/key`, SAML_SIGNING_CERT_FILE: `${dir}/cert` };
  assert.ok(new Saml(samlFromEnv(env)!, ORIGIN).logoutEnabled);
  assert.throws(() => setup(t, { signingKey: pemKey(sp) }), /must be set together/);
  assert.throws(() => setup(t, { decryptionCert: sp.pem }), /must be set together/);
  assert.throws(() => setup(t, { idpSloUrl: 'http://idp.example/logout' }), /SAML_IDP_SLO_URL/);
});

test('POST IdP logout replies to the pinned endpoint, bounds RelayState, and the SP start route requires CSRF and SAML', async (t) => {
  const sp = identity();
  const { route, attempt, idp, f } = setup(t, { idpSloUrl: 'https://idp.example/logout', signingKey: pemKey(sp), signingCert: sp.pem });
  const xml = () => signed(logoutXml('LogoutRequest', '', logoutSubject), 'LogoutRequest', idp.key);
  const send = (relay: string) => call(route, 'POST', '/admin/v1/saml/logout', '', `SAMLRequest=${b64(xml())}&${relay}`);
  assert.equal((await send('RelayState=a&RelayState=b')).status, 400);
  assert.equal((await send(`RelayState=${'x'.repeat(81)}`)).status, 400);
  const result = await send('RelayState=https%3A%2F%2Fevil.example');
  assert.equal(new URL(String(result.headers.location)).origin, 'https://idp.example');
  assert.equal(new URL(String(result.headers.location)).searchParams.get('RelayState'), 'https://evil.example');
  const sid = pick(await attempt(), 'sid');
  assert.equal((await call(route, 'POST', '/admin/v1/saml/logout/start', sid)).status, 403);
  const me = JSON.parse((await call(route, 'GET', '/admin/v1/session', sid)).text);
  assert.equal((await call(route, 'POST', '/admin/v1/saml/logout/start', sid, undefined, { 'x-csrf-token': me.csrfToken })).status, 302);
  assert.equal((await call(route, 'GET', '/admin/v1/session', sid)).status, 401);
  const password = f.auth.issue({ id: 'omar', name: 'Omar', roles: ['approver'] }, 'password');
  assert.equal((await call(route, 'POST', '/admin/v1/saml/logout/start', `sid=${password.sid}`, undefined, { 'x-csrf-token': password.csrfToken })).status, 400);
});

test('LogoutResponse rejects unsigned, forged, stale, wrong issuer/destination, failure and sign-in correlation', async (t) => {
  const sp = identity();
  const { route, attempt, idp, start } = setup(t, { idpSloUrl: 'https://idp.example/logout', signingKey: pemKey(sp), signingCert: sp.pem });
  const sid = pick(await attempt(), 'sid');
  const me = JSON.parse((await call(route, 'GET', '/admin/v1/session', sid)).text);
  const ended = await call(route, 'DELETE', '/admin/v1/session', sid, undefined, { 'x-csrf-token': me.csrfToken });
  const location = new URL(JSON.parse(ended.text).logoutUrl);
  const request = inflateRawSync(Buffer.from(location.searchParams.get('SAMLRequest')!, 'base64')).toString();
  const id = / ID="([^"]+)"/.exec(request)![1]!;
  const response = logoutXml('LogoutResponse', `InResponseTo="${id}"`, success);
  const send = (xml: string) => call(route, 'POST', '/admin/v1/saml/logout', '', `SAMLResponse=${b64(xml)}`);
  for (const invalid of [response, signed(response, 'LogoutResponse', identity().key), signed(response, 'LogoutResponse', idp.key, 'sha1'),
    signed(response.replace(LOGOUT, 'https://evil.example'), 'LogoutResponse', idp.key), signed(response.replace(IDP, 'wrong'), 'LogoutResponse', idp.key),
    signed(response.replace(/IssueInstant="[^"]+"/, `IssueInstant="${iso(Date.now() - 600_000)}"`), 'LogoutResponse', idp.key)]) {
    assert.equal((await send(invalid)).status, 400);
  }
  const login = await start();
  assert.equal((await send(signed(response.replace(id, login.id), 'LogoutResponse', idp.key))).status, 400);
  assert.equal((await send(signed(response.replace('status:Success', 'status:Responder'), 'LogoutResponse', idp.key))).status, 400);
  assert.equal((await send(signed(response, 'LogoutResponse', idp.key))).status, 400, 'a signed failed response retires the pending request');
});


test('PEP context scopes remain enforced beside SAML logout routes', async (t) => {
  const sp = identity();
  const { f, route, attempt } = setup(t, { idpSloUrl: 'https://idp.example/logout', signingKey: pemKey(sp), signingCert: sp.pem });
  const scoped = f.auth.createPepCredential('scoped', 'lina', undefined, undefined, undefined, [{ signal: 'network', networks: ['trusted'] }]);
  const decide = (network: string): Promise<Reply> => call(route, 'POST', '/access/v1/evaluation', '', JSON.stringify({ ...evaluation(), context: { network } }), {
    'content-type': 'application/json', authorization: `Bearer ${scoped.secret}`,
  });
  const refused = await decide('untrusted');
  assert.equal(refused.status, 403);
  assert.equal(JSON.parse(refused.text).error, 'context_claim_forbidden');
  const sid = pick(await attempt(), 'sid');
  const me = JSON.parse((await call(route, 'GET', '/admin/v1/session', sid)).text);
  const ended = await call(route, 'DELETE', '/admin/v1/session', sid, undefined, { 'x-csrf-token': me.csrfToken });
  assert.equal(ended.status, 200);
  assert.ok(JSON.parse(ended.text).logoutUrl);
  assert.equal((await call(route, 'GET', '/admin/v1/session', sid)).status, 401);
  assert.equal((await decide('trusted')).status, 200);
});

test('tenant partitions use their own SAML origins and keep IdP and SP logout tenant-local', async (t) => {
  const dir = mkdtempSync('/tmp/gate-saml-tenants-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const idp = identity(), sp = identity();
  const origins = { alpha: 'https://alpha.gate.example', beta: 'https://beta.gate.example' } as const;
  type Tenant = keyof typeof origins;
  const saml: SamlConfig = { idpEntityId: IDP, idpSsoUrl: 'https://idp.example/sso', idpCert: idp.pem, authnContext: [MFA], idAttribute: 'NameID',
    idpSloUrl: 'https://idp.example/logout', signingKey: pemKey(sp), signingCert: sp.pem };
  const tenants = tenantManifest(JSON.stringify(Object.fromEntries((['alpha', 'beta'] as const).map((tenant) => [tenant, {
    dataDir: resolve(dir, tenant), worldDir: 'examples/toy-domain', publicOrigin: origins[tenant],
  }]))));
  const server = createTenantServer({ port: 0, rateLimit: 100000, pepRateLimit: 100000, saml }, tenants, ['alpha', 'beta']);
  await server.listen(); t.after(() => server.close());
  const cookie = (response: Response, name: string): string => {
    const value = new RegExp(`${name}=([^;]+)`).exec(response.headers.get('set-cookie') ?? '')?.[0];
    assert.ok(value, `${name} cookie`); return value;
  };
  const session = (tenant: Tenant, sid: string): Promise<Response> => fetch(`${server.url}/admin/v1/session`, { headers: { 'x-gate-tenant': tenant, cookie: sid } });
  const start = async (tenant: Tenant): Promise<{ id: string; cookie: string }> => {
    const response = await fetch(`${server.url}/admin/v1/saml/login`, { headers: { 'x-gate-tenant': tenant }, redirect: 'manual' });
    assert.equal(response.status, 302);
    const location = new URL(String(response.headers.get('location')));
    const request = inflateRawSync(Buffer.from(location.searchParams.get('SAMLRequest')!, 'base64')).toString();
    assert.match(request, new RegExp(`AssertionConsumerServiceURL="${origins[tenant]}/admin/v1/saml/acs"`));
    const samlCookie = cookie(response, '__Host-gate_saml');
    return { id: samlCookie.split('=')[1]!, cookie: samlCookie };
  };
  const signIn = async (tenant: Tenant): Promise<{ sid: string; csrfToken: string }> => {
    const started = await start(tenant);
    const c = { inResponseTo: started.id, nameId: 'omar', recipient: `${origins[tenant]}/admin/v1/saml/acs`,
      audience: `${origins[tenant]}/admin/v1/saml/metadata`, destination: `${origins[tenant]}/admin/v1/saml/acs` };
    const xml = responseXml(c, signed(assertionXml(c), 'Assertion', idp.key));
    const response = await fetch(`${server.url}/admin/v1/saml/acs`, { method: 'POST', headers: {
      'content-type': 'application/x-www-form-urlencoded', 'x-gate-tenant': tenant, cookie: started.cookie,
    }, redirect: 'manual', body: `SAMLResponse=${b64(xml)}` });
    assert.equal(response.status, 302);
    const sid = cookie(response, 'sid');
    const me = await session(tenant, sid);
    assert.equal(me.status, 200);
    const current = await me.json() as { csrfToken: string };
    return { sid, csrfToken: current.csrfToken };
  };
  for (const tenant of ['alpha', 'beta'] as const) {
    const metadata = await fetch(`${server.url}/admin/v1/saml/metadata`, { headers: { 'x-gate-tenant': tenant } });
    assert.equal(metadata.status, 200);
    const xml = await metadata.text();
    assert.ok(xml.includes(`entityID="${origins[tenant]}/admin/v1/saml/metadata"`));
    assert.ok(xml.includes(`Location="${origins[tenant]}/admin/v1/saml/logout"`));
  }
  const alpha = await signIn('alpha'), beta = await signIn('beta');
  assert.notEqual(alpha.sid, beta.sid);
  assert.equal((await session('beta', alpha.sid)).status, 401, 'a cookie has no authority in another tenant');

  const logout = logoutXml('LogoutRequest', '', logoutSubject.replace('u-1', 'omar')).replace(LOGOUT, `${origins.alpha}/admin/v1/saml/logout`);
  const endedAlpha = await fetch(`${server.url}/admin/v1/saml/logout`, { method: 'POST', headers: {
    'content-type': 'application/x-www-form-urlencoded', 'x-gate-tenant': 'alpha',
  }, redirect: 'manual', body: `SAMLRequest=${b64(signed(logout, 'LogoutRequest', idp.key))}` });
  assert.equal(endedAlpha.status, 302);
  assert.equal((await session('alpha', alpha.sid)).status, 401);
  assert.equal((await session('beta', beta.sid)).status, 200, 'IdP logout ends only the named tenant session');

  const endedBeta = await fetch(`${server.url}/admin/v1/session`, { method: 'DELETE', headers: {
    'x-gate-tenant': 'beta', cookie: beta.sid, 'x-csrf-token': beta.csrfToken,
  } });
  assert.equal(endedBeta.status, 200);
  const result = await endedBeta.json() as { logoutUrl: string };
  assert.equal(new URL(result.logoutUrl).origin, 'https://idp.example');
  assert.equal((await session('beta', beta.sid)).status, 401);
});
