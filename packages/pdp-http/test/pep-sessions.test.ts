import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { createServer, type PdpServer, type ServerOptions } from '../src/server.ts';
import { ATTRIBUTE } from '../src/xacml.ts';
import { pdp } from '../src/pdp.ts';
import { SESSION_ABSOLUTE_MS, Sessions, scopeSession } from '../src/sessions.ts';
import { withSession } from '../src/runtime.ts';
import { PepSessions, SESSION_IDLE_SECONDS, sessionsPerCredentialFromEnv, sessionsPerSubjectFromEnv, subjectSessionScope } from '../src/pep-sessions.ts';
import { SESSION_TOKEN_TTL_SECONDS, SESSION_TOKEN_TYP } from '../src/tokens.ts';
import { HttpError } from '../src/http.ts';
import { fixture } from './helpers.ts';
import { skip, throwawayDatabase } from './pg-database.ts';

const SEAL = randomBytes(32).toString('base64url');
const PEP = 'bootstrap';
interface Answer { status: number; data: Record<string, any>; headers: Headers }
interface Opened { token: string; sessionId: string; issuedAt: string; expiresAt: string; idleSeconds: number }

async function deployment(t: TestContext, extra: Partial<ServerOptions> = {}) {
  const dir = mkdtempSync('/tmp/pdp-pep-sessions-');
  let at = Date.parse('2026-11-08T10:00:00Z');
  const server = createServer({ port: 0, dataDir: dir, clock: () => new Date(at).toISOString(), sodHistory: 'caller', ...extra });
  await server.listen(); t.after(() => server.close()); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const credentials = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string; passwords: Record<string, string> };
  const call = async (path: string, body: unknown, key = credentials.pepApiKey, method = 'POST'): Promise<Answer> => {
    const response = await fetch(`${server.url}${path}`, { method, headers: { 'content-type': 'application/json', authorization: `Bearer ${key}` }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() as Record<string, any>, headers: response.headers };
  };
  const open = async (subject = 'carol', key = credentials.pepApiKey): Promise<Opened> => {
    const answer = await call('/x/v1/sessions', { subject: { type: 'user', id: subject } }, key);
    assert.equal(answer.status, 201, JSON.stringify(answer.data));
    return answer.data as Opened;
  };
  const point = (subject: string, resource: string, action: string, token?: string): Record<string, unknown> => ({
    subject: { type: 'user', id: subject }, resource: { type: resource.startsWith('PAY') ? 'payment' : 'case', id: resource }, action: { name: action },
    context: { network: 'trusted', ...(action === 'read' ? {} : { sessionLevel: 1 }), ...(token ? { sessionToken: token } : {}) },
  });
  return { server, dir, credentials, call, open, point, advance: (ms: number) => { at += ms; } };
}

const adminLogins = new WeakMap<object, Map<string, Promise<Answer>>>();
async function admin(d: Awaited<ReturnType<typeof deployment>>, path: string, body: unknown, method = 'POST', user = 'lina'): Promise<Answer> {
  let logins = adminLogins.get(d);
  if (!logins) { logins = new Map(); adminLogins.set(d, logins); }
  let pending = logins.get(user);
  if (!pending) { pending = d.call('/admin/v1/session', { username: user, password: d.credentials.passwords[user] }); logins.set(user, pending); }
  const login = await pending;
  assert.equal(login.status, 200);
  const response = await fetch(`${d.server.url}${path}`, { method, headers: {
    'content-type': 'application/json', cookie: String(login.headers.get('set-cookie')).split(';')[0]!, 'x-csrf-token': String(login.data.csrfToken),
  }, ...(method === 'GET' ? {} : { body: JSON.stringify(body) }) });
  return { status: response.status, data: await response.json() as Record<string, any>, headers: response.headers };
}

test('open issues a PDP-bound Ed25519 session token, enforces the per-subject cap, audits, and closes', async (t) => {
  const d = await deployment(t, { blpSessionsPerSubject: 2 });
  const first = await d.open(); const second = await d.open();
  assert.notEqual(first.sessionId, second.sessionId);
  const [header, claims] = [0, 1].map((part) => JSON.parse(Buffer.from(first.token.split('.')[part]!, 'base64url').toString()) as Record<string, any>);
  assert.ok(header && claims);
  assert.deepEqual({ alg: header.alg, typ: header.typ }, { alg: 'EdDSA', typ: SESSION_TOKEN_TYP });
  assert.equal(claims.sid, first.sessionId);
  assert.deepEqual(claims.sub, JSON.stringify(['user', 'carol']));
  assert.equal(claims.pep, PEP);
  assert.equal(claims.exp - claims.iat, SESSION_TOKEN_TTL_SECONDS);
  assert.equal(claims.idle, SESSION_IDLE_SECONDS);
  assert.equal(first.idleSeconds, SESSION_IDLE_SECONDS);
  assert.equal((await d.call('/x/v1/sessions', { subject: { type: 'user', id: 'carol' } })).status, 409);
  assert.equal((await d.open('alice')).sessionId !== first.sessionId, true, 'the cap is per subject');
  assert.equal((await d.call('/x/v1/sessions/close', { token: first.token })).status, 200);
  const replacement = await d.open();
  assert.equal((await d.call('/access/v1/evaluation', d.point('carol', 'CASE-14', 'read', first.token))).status, 403);
  assert.equal((await d.call('/access/v1/evaluation', d.point('carol', 'CASE-14', 'read', replacement.token))).status, 200);
  await d.call('/x/v1/sessions/close', { token: second.token });
  const audit = readFileSync(resolve(d.dir, 'audit.jsonl'), 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line) as Record<string, any>);
  assert.ok(audit.some((row) => row.action === 'blp_session_open' && row.effect === 'allow'));
  assert.ok(audit.some((row) => row.action === 'blp_session_open' && row.effect === 'deny' && row.details.reason === 'subject_session_cap'));
  assert.ok(audit.some((row) => row.action === 'blp_session_close' && row.effect === 'allow'));
  assert.ok(!JSON.stringify(audit).includes(first.token), 'the bearer token is never audited');
});

test('forged, expired, foreign-subject, foreign-credential and closed tokens are refused', async (t) => {
  const d = await deployment(t);
  const opened = await d.open();
  const parts = opened.token.split('.');
  const forged = `${parts[0]}.${parts[1]}.${parts[2]!.slice(0, -1)}${parts[2]!.endsWith('A') ? 'B' : 'A'}`;
  for (const token of [forged, 'not-a-token']) {
    const answer = await d.call('/access/v1/evaluation', d.point('carol', 'CASE-14', 'read', token));
    assert.deepEqual([answer.status, answer.data.error], [403, 'invalid_session_token']);
  }
  const foreignSubject = await d.call('/access/v1/evaluation', d.point('alice', 'CASE-14', 'read', opened.token));
  assert.deepEqual([foreignSubject.status, foreignSubject.data.error], [403, 'invalid_session_token']);

  const login = await d.call('/admin/v1/session', { username: 'lina', password: d.credentials.passwords.lina });
  assert.equal(login.status, 200);
  const created = await fetch(`${d.server.url}/admin/v1/pep-credentials`, { method: 'POST', headers: {
    'content-type': 'application/json', cookie: String(login.headers.get('set-cookie')).split(';')[0]!, 'x-csrf-token': String(login.data.csrfToken),
  }, body: JSON.stringify({ name: 'foreign-pep' }) });
  assert.equal(created.status, 201);
  const credential = await created.json() as { secret: string };
  const foreignCredential = await d.call('/access/v1/evaluation', d.point('carol', 'CASE-14', 'read', opened.token), credential.secret);
  assert.deepEqual([foreignCredential.status, foreignCredential.data.error], [403, 'invalid_session_token']);

  d.advance((SESSION_TOKEN_TTL_SECONDS + 1) * 1000);
  const expired = await d.call('/access/v1/evaluation', d.point('carol', 'CASE-14', 'read', opened.token));
  assert.deepEqual([expired.status, expired.data.error], [403, 'invalid_session_token']);
});

test('one subject and credential share the mark across open tokens, and close/reopen cannot reset it', async (t) => {
  const d = await deployment(t);
  const first = await d.open();
  assert.equal((await d.call('/access/v1/evaluation', d.point('carol', 'CASE-14', 'read', first.token))).data.decision, true);
  const second = await d.open();
  const across = await d.call('/access/v1/evaluation', d.point('carol', 'CASE-11', 'update', second.token));
  assert.deepEqual([across.data.decision, across.data.context.rules], [false, ['BLP.HIGH_WATER']]);
  assert.equal((await d.call('/x/v1/sessions/close', { token: first.token })).status, 200);
  assert.equal((await d.call('/x/v1/sessions/close', { token: second.token })).status, 200);
  const third = await d.open();
  const reopened = await d.call('/access/v1/evaluation', d.point('carol', 'CASE-11', 'update', third.token));
  assert.deepEqual([reopened.data.decision, reopened.data.context.rules], [false, ['BLP.HIGH_WATER']]);
});

test('an expired token stays refused (no CBAC decision), leaves the shared mark, and a fresh token is not session-expired', async (t) => {
  const d = await deployment(t);
  const first = await d.open();
  assert.equal((await d.call('/access/v1/evaluation', d.point('carol', 'CASE-14', 'read', first.token))).data.decision, true);
  d.advance((SESSION_TOKEN_TTL_SECONDS + 1) * 1000);
  for (const action of ['update', 'read']) {
    const expired = await d.call('/access/v1/evaluation', d.point('carol', action === 'read' ? 'CASE-14' : 'CASE-11', action, first.token));
    assert.deepEqual([expired.status, expired.data.error], [403, 'invalid_session_token']);
  }
  const fresh = await d.open();
  const write = await d.call('/access/v1/evaluation', d.point('carol', 'CASE-11', 'update', fresh.token));
  assert.deepEqual([write.data.decision, write.data.context.rules], [false, ['BLP.HIGH_WATER']], 'the mark survived the expired token');
  assert.equal((await d.call('/access/v1/evaluation', d.point('carol', 'CASE-14', 'read', fresh.token))).data.decision, true, 'not CBAC.SESSION_EXPIRED');
});

test('a lapsed mark in the shared token scope is no expired session; a lapsed legacy session is', (t) => {
  const f = fixture(t); let elapsed = 0;
  const marks = new Sessions(false, () => elapsed); f.rt.sessions = marks;
  const carol = { type: 'user', id: 'carol' };
  const token = subjectSessionScope(PEP, carol), legacy = scopeSession(PEP, 's1');
  assert.ok(marks.raise(token, carol, 3, PEP) && marks.raise(legacy, carol, 3, PEP));
  elapsed += SESSION_ABSOLUTE_MS;
  const ctx = { network: 'trusted' as const, now: f.rt.now() };
  assert.equal(withSession(f.rt, carol, { ...ctx, sessionId: token }).sessionExpired, undefined, 'a verified token is a live session');
  assert.equal(withSession(f.rt, carol, { ...ctx, sessionId: legacy }).sessionExpired, true);
  assert.notEqual(token.startsWith('pdp:'), legacy.startsWith('pdp:'), 'no raw id can name a token scope');
});

test('batches, XACML and decision-token consumption use the verified subject mark scope', async (t) => {
  const d = await deployment(t);
  const carol = await d.open();
  const entries = [d.point('carol', 'CASE-14', 'read'), d.point('carol', 'CASE-11', 'update')].map(({ context: _context, ...entry }) => entry);
  const batch = await d.call('/access/v1/evaluations', {
    context: { network: 'trusted', sessionToken: carol.token }, evaluations: entries,
  });
  assert.equal(batch.status, 200, JSON.stringify(batch.data));
  assert.deepEqual(batch.data.evaluations.map((e: any) => e.decision), [true, false]);

  const request = (resource: string, action: string): Record<string, unknown> => ({ Request: {
    AccessSubject: { Attribute: [{ AttributeId: ATTRIBUTE.subjectId, Value: 'carol' }] },
    Resource: { Attribute: [{ AttributeId: ATTRIBUTE.resourceId, Value: resource }, { AttributeId: ATTRIBUTE.resourceType, Value: 'case' }] },
    Action: { Attribute: { AttributeId: ATTRIBUTE.actionId, Value: action } },
    Environment: { Attribute: [{ AttributeId: ATTRIBUTE.network, Value: 'trusted' }, { AttributeId: ATTRIBUTE.sessionToken, Value: carol.token },
      ...(action === 'read' ? [] : [{ AttributeId: ATTRIBUTE.sessionLevel, Value: 1, DataType: 'http://www.w3.org/2001/XMLSchema#integer' }])] },
  } });
  const xacml = await d.call('/xacml/v3/authorize', request('CASE-11', 'update'));
  assert.equal(xacml.status, 200);
  assert.equal(xacml.data.Response[0].Decision, 'Deny');
  assert.ok(xacml.data.Response[0].AssociatedAdvice[0].AttributeAssignment.some((a: any) => a.Value === 'BLP.HIGH_WATER'));

  const henry = await d.open('henry');
  const approve = await d.call('/access/v1/evaluation', { ...d.point('henry', 'PAY-3', 'approve', henry.token), context: {
    network: 'trusted', sessionToken: henry.token, makerId: 'grace',
  } });
  assert.equal(approve.data.decision, true, JSON.stringify(approve.data));
  const decisionToken = approve.data.context.decision_token as string;
  const sid = JSON.parse(Buffer.from(decisionToken.split('.')[1]!, 'base64url').toString()).sid;
  assert.equal(sid, subjectSessionScope(PEP, { type: 'user', id: 'henry' }));
  assert.equal((await d.call('/access/v1/evaluation', d.point('henry', 'PAY-3', 'read', henry.token))).data.decision, true);
  const consumed = await d.call('/x/v1/tokens/consume', { token: decisionToken, action: 'approve', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 });
  assert.deepEqual([consumed.status, consumed.data.ok], [200, true]);
});

test('a decision token minted in a BLP session dies with it: close or idle expiry refuses its consumption, audited', async (t) => {
  const d = await deployment(t);
  const approve = async (token: string): Promise<string> => {
    const answer = await d.call('/access/v1/evaluation', { ...d.point('henry', 'PAY-3', 'approve'), context: { network: 'trusted', sessionToken: token, makerId: 'grace' } });
    assert.equal(answer.data.decision, true, JSON.stringify(answer.data));
    return answer.data.context.decision_token as string;
  };
  const consume = (token: string) => d.call('/x/v1/tokens/consume', { token, action: 'approve', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 });
  const henry = await d.open('henry');
  const decisionToken = await approve(henry.token);
  assert.equal(JSON.parse(Buffer.from(decisionToken.split('.')[1]!, 'base64url').toString()).bsid, henry.sessionId, 'bound to the issuing BLP session');
  assert.equal((await d.call('/x/v1/sessions/close', { token: henry.token })).status, 200);
  const refused = await consume(decisionToken);
  assert.deepEqual([refused.status, refused.data.error], [409, 'conflict']);
  assert.match(String(refused.data.message), /BLP session .* closed or expired/);
  const audit = readFileSync(resolve(d.dir, 'audit.jsonl'), 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line) as Record<string, any>);
  assert.ok(audit.some((row) => row.type === 'decision' && row.effect === 'deny' && row.rules?.[0] === 'CBAC.SESSION_EXPIRED' && row.details?.phase === 'token_consume'));
  // a token from a session still open is consumed as before
  assert.deepEqual([(await consume(await approve((await d.open('henry')).token))).status], [200]);

  // idle expiry (real clock) and another credential, checked on the registry itself
  const f = fixture(t); let elapsed = Date.parse('2026-11-08T10:00:00Z');
  const sessions = new PepSessions(f.rt.tokens, new Sessions(false, () => elapsed), f.rt.audit, f.rt.now, () => elapsed);
  const opened = await sessions.open({ subject: { type: 'user', id: 'henry' } }, PEP, 'pep:test');
  const sub = JSON.stringify(['user', 'henry']);
  assert.equal(sessions.usable(opened.sessionId, sub, PEP), true);
  assert.equal(sessions.usable(opened.sessionId, sub, 'other-pep'), false, 'another credential');
  assert.equal(sessions.usable(opened.sessionId, JSON.stringify(['user', 'carol']), PEP), false, 'another subject');
  elapsed += SESSION_IDLE_SECONDS * 1000;
  assert.equal(sessions.usable(opened.sessionId, sub, PEP), false, 'idle expiry');
});

test('session creation takes the subject bounds of a decision, never mints an unusable token, and caps each credential', async (t) => {
  const d = await deployment(t, { blpSessionsPerCredential: 2 });
  for (const subject of [{ type: 'user', id: 'x'.repeat(10_000) }, { type: 'user', id: 'x'.repeat(257) }, { type: 't'.repeat(257), id: 'carol' }, { type: 'user', id: '' }]) {
    const refused = await d.call('/x/v1/sessions', { subject });
    assert.deepEqual([refused.status, refused.data.error], [400, 'bad_request'], `${subject.type.length}/${subject.id.length}`);
  }
  const longest = await d.call('/x/v1/sessions', { subject: { type: 'user', id: 'y'.repeat(256) } });
  assert.equal(longest.status, 201, JSON.stringify(longest.data));
  assert.ok((longest.data.token as string).length <= 4096, 'within the decision limit');
  const used = await d.call('/access/v1/evaluation', { subject: { type: 'user', id: 'y'.repeat(256) }, resource: { type: 'case', id: 'CASE-18' }, action: { name: 'read' },
    context: { network: 'trusted', sessionToken: longest.data.token } });
  assert.equal(used.status, 200, 'the longest subject still gets a token decisions accept');
  // distinct subject ids no longer evade the cap: it counts every open session of the credential
  await d.open('alice');
  const capped = await d.call('/x/v1/sessions', { subject: { type: 'user', id: 'carol' } });
  assert.deepEqual([capped.status, capped.data.error], [409, 'session_limit']);
  const audit = readFileSync(resolve(d.dir, 'audit.jsonl'), 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line) as Record<string, any>);
  assert.ok(audit.some((row) => row.action === 'blp_session_open' && row.effect === 'deny' && row.details.reason === 'credential_session_cap' && row.details.cap === 2));
  assert.equal((await d.call('/x/v1/sessions/close', { token: longest.data.token })).status, 200);
  await d.open('carol');
  assert.equal(sessionsPerCredentialFromEnv('5'), 5);
  for (const bad of ['0', '1.5', 'x', '100001']) assert.throws(() => sessionsPerCredentialFromEnv(bad), /BLP_SESSIONS_PER_CREDENTIAL/);
});

test('session creation has its own rate limit and rate-limited creation is audited', async (t) => {
  const d = await deployment(t, { blpSessionCreationRateLimit: 1 });
  await d.open();
  const limited = await d.call('/x/v1/sessions', { subject: { type: 'user', id: 'alice' } });
  assert.deepEqual([limited.status, limited.data.error], [429, 'rate_limited']);
  assert.ok(limited.headers.get('retry-after'));
  const audit = readFileSync(resolve(d.dir, 'audit.jsonl'), 'utf8');
  assert.ok(audit.includes('"action":"refused"'));
  assert.ok(audit.includes('"error":"rate_limited"'));
});

test('production mode refuses raw ids; demo compatibility still accepts them and the cap parser is strict', (t) => {
  const f = fixture(t);
  f.rt.sessions = new Sessions(true);
  f.rt.sessions.requireTokens = true;
  const body = { subject: { type: 'user', id: 'carol' }, resource: { type: 'case', id: 'CASE-11' }, action: { name: 'update' }, context: { sessionId: 'legacy', sessionLevel: 1 } };
  assert.throws(() => pdp(f.rt, '/access/v1/evaluation', body, [], true, PEP), (err: unknown) => err instanceof HttpError && err.status === 400 && err.code === 'session_token_required');
  f.rt.sessions.requireTokens = false;
  assert.equal((pdp(f.rt, '/access/v1/evaluation', body, [], true, PEP) as { decision: boolean }).decision, true);
  assert.equal(sessionsPerSubjectFromEnv('2'), 2);
  for (const bad of ['0', '1.5', 'x', '1001']) assert.throws(() => sessionsPerSubjectFromEnv(bad), /BLP_SESSIONS_PER_SUBJECT/);
});

test('an idle token expires on the real clock even when the business clock is pinned', async (t) => {
  const f = fixture(t); let elapsed = Date.parse('2026-11-08T10:00:00Z');
  const marks = new Sessions(false, () => elapsed); f.rt.sessions = marks;
  const sessions = new PepSessions(f.rt.tokens, marks, f.rt.audit, f.rt.now, () => elapsed);
  const opened = await sessions.open({ subject: { type: 'user', id: 'carol' } }, PEP, 'pep:test');
  await sessions.prepare([opened.token], PEP);
  elapsed += SESSION_IDLE_SECONDS * 1000;
  await assert.rejects(sessions.prepare([opened.token], PEP), (err: unknown) => err instanceof HttpError && err.code === 'invalid_session_token');
});

test('the shared mark outlives every open token that refers to it: no lapse while a token is still usable', async (t) => {
  const f = fixture(t); let elapsed = Date.parse('2026-11-08T10:00:00Z');
  const marks = new Sessions(false, () => elapsed); f.rt.sessions = marks;
  const sessions = new PepSessions(f.rt.tokens, marks, f.rt.audit, f.rt.now, () => elapsed);
  const carol = { type: 'user', id: 'carol' }; const scope = subjectSessionScope(PEP, carol);
  assert.ok(marks.raise(scope, carol, 3, PEP), 'an L3 read raised the shared mark');
  const opened = await sessions.open({ subject: carol }, PEP, 'pep:test');
  // the token is used (an L0 read, which never touches the mark) just before its idle bound, then again later
  elapsed += SESSION_IDLE_SECONDS * 1000 - 1000;
  await sessions.prepare([opened.token], PEP);
  elapsed += 2 * 60_000;
  await sessions.prepare([opened.token], PEP);
  assert.equal(marks.level(scope, carol), 3, 'the mark lapsing on its own schedule would reset the floor under a live token');
  elapsed += SESSION_IDLE_SECONDS * 1000 + 60_000 + 1;
  await assert.rejects(sessions.prepare([opened.token], PEP), (err: unknown) => err instanceof HttpError && err.code === 'invalid_session_token');
  assert.equal(marks.level(scope, carol), undefined, 'once no token can use it, the mark lapses as before');
});

test('PostgreSQL shares caps, marks and revocation across cluster nodes', { skip, timeout: 60_000 }, async (t) => {
  const { url } = await throwawayDatabase(t, 'pep_sessions');
  const dirs = [mkdtempSync('/tmp/pdp-session-a-'), mkdtempSync('/tmp/pdp-session-b-')];
  t.after(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });
  const options = (nodeId: string, dataDir: string): ServerOptions => ({ port: 0, dataDir, databaseUrl: url, signingKeySeal: SEAL, cluster: true, nodeId,
    blpSessionsPerSubject: 2, blpSessionsPerCredential: 5, rateLimit: 1_000_000, pepRateLimit: 1_000_000, sodHistory: 'caller' });
  const a = createServer(options('a', dirs[0]!)); await a.listen(); t.after(() => a.close());
  const b = createServer(options('b', dirs[1]!)); await b.listen(); t.after(() => b.close());
  const { pepApiKey } = JSON.parse(readFileSync(resolve(dirs[0]!, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string };
  const call = async (server: PdpServer, path: string, body: unknown): Promise<Answer> => {
    const response = await fetch(`${server.url}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${pepApiKey}` }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() as Record<string, any>, headers: response.headers };
  };
  const open = async (server: PdpServer): Promise<Opened> => {
    const answer = await call(server, '/x/v1/sessions', { subject: { type: 'user', id: 'carol' } });
    assert.equal(answer.status, 201, JSON.stringify(answer.data)); return answer.data as Opened;
  };
  const point = (resource: string, action: string, token: string): Record<string, unknown> => ({
    subject: { type: 'user', id: 'carol' }, resource: { type: 'case', id: resource }, action: { name: action },
    context: { network: 'trusted', sessionToken: token, ...(action === 'read' ? {} : { sessionLevel: 1 }) },
  });
  const first = await open(a); const second = await open(b);
  assert.equal((await call(a, '/x/v1/sessions', { subject: { type: 'user', id: 'carol' } })).status, 409, 'the cap is cluster-wide');
  assert.equal((await call(a, '/access/v1/evaluation', point('CASE-14', 'read', first.token))).data.decision, true);
  const across = await call(b, '/access/v1/evaluation', point('CASE-11', 'update', second.token));
  assert.deepEqual([across.data.decision, across.data.context.rules], [false, ['BLP.HIGH_WATER']]);
  assert.equal((await call(b, '/x/v1/sessions/close', { token: first.token })).status, 200);
  assert.equal((await call(a, '/access/v1/evaluation', point('CASE-14', 'read', first.token))).status, 403, 'close is cluster-wide');

  // a decision token minted in a session on node a is refused on node a once node b closed that session
  const henry = async (server: PdpServer): Promise<Opened> => (await call(server, '/x/v1/sessions', { subject: { type: 'user', id: 'henry' } })).data as Opened;
  const approve = async (server: PdpServer, token: string): Promise<string> => {
    const answer = await call(server, '/access/v1/evaluation', { subject: { type: 'user', id: 'henry' }, resource: { type: 'payment', id: 'PAY-3' }, action: { name: 'approve' },
      context: { network: 'trusted', sessionToken: token, makerId: 'grace' } });
    assert.equal(answer.data.decision, true, JSON.stringify(answer.data));
    return answer.data.context.decision_token as string;
  };
  const consume = (server: PdpServer, token: string) => call(server, '/x/v1/tokens/consume', { token, action: 'approve', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 });
  const closed = await henry(a); const minted = await approve(a, closed.token);
  assert.equal((await call(b, '/x/v1/sessions/close', { token: closed.token })).status, 200);
  const refused = await consume(a, minted);
  assert.equal(refused.status, 409, JSON.stringify(refused.data));
  assert.match(String(refused.data.message), /closed or expired/);
  const still = await henry(b);
  assert.equal((await consume(b, await approve(a, still.token))).status, 200, 'a token of an open session is consumed on another node');
  // one carol and one henry session open: three more subjects reach the credential's cap of 5 across both nodes
  for (const [server, id] of [[a, 'dave'], [b, 'erin'], [a, 'frank']] as const) assert.equal((await call(server, '/x/v1/sessions', { subject: { type: 'user', id } })).status, 201);
  const capped = await call(b, '/x/v1/sessions', { subject: { type: 'user', id: 'gina' } });
  assert.deepEqual([capped.status, capped.data.error], [409, 'session_limit'], 'the credential cap is cluster-wide');
});

test('PostgreSQL: a mark an open token still refers to does not lapse under it on any node', { skip, timeout: 60_000 }, async (t) => {
  const { url, sql } = await throwawayDatabase(t, 'pep_hold');
  const dirs = [mkdtempSync('/tmp/pdp-hold-a-'), mkdtempSync('/tmp/pdp-hold-b-')];
  t.after(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });
  const options = (nodeId: string, dataDir: string): ServerOptions => ({ port: 0, dataDir, databaseUrl: url, signingKeySeal: SEAL, cluster: true, nodeId,
    rateLimit: 1_000_000, pepRateLimit: 1_000_000 });
  const a = createServer(options('a', dirs[0]!)); await a.listen(); t.after(() => a.close());
  const b = createServer(options('b', dirs[1]!)); await b.listen(); t.after(() => b.close());
  const { pepApiKey } = JSON.parse(readFileSync(resolve(dirs[0]!, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string };
  const call = async (server: PdpServer, path: string, body: unknown): Promise<Answer> => {
    const response = await fetch(`${server.url}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${pepApiKey}` }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() as Record<string, any>, headers: response.headers };
  };
  const point = (resource: string, action: string, token: string): Record<string, unknown> => ({
    subject: { type: 'user', id: 'carol' }, resource: { type: 'case', id: resource }, action: { name: action },
    context: { network: 'trusted', sessionToken: token, ...(action === 'read' ? {} : { sessionLevel: 1 }) },
  });
  const opened = (await call(a, '/x/v1/sessions', { subject: { type: 'user', id: 'carol' } })).data as Opened;
  assert.equal((await call(a, '/access/v1/evaluation', point('CASE-14', 'read', opened.token))).data.decision, true, 'L3 read: the mark rises');
  // 14 minutes on: the mark is still live by its own clock; an L0 read (no mark touch) uses the token, recording its use
  await sql('UPDATE gate_blp_mark SET seen = seen - $1', [14 * 60_000]);
  await sql('UPDATE gate_blp_session SET seen = seen - $1', [2 * 60_000]);
  assert.equal((await call(a, '/access/v1/evaluation', point('CASE-18', 'read', opened.token))).data.decision, true);
  // 2 more minutes: the mark's own idle bound has passed, the token's has not
  await sql('UPDATE gate_blp_mark SET seen = seen - $1', [2 * 60_000]);
  const write = await call(b, '/access/v1/evaluation', point('CASE-11', 'update', opened.token));
  assert.equal(write.status, 200, JSON.stringify(write.data));
  assert.deepEqual([write.data.decision, write.data.context.rules], [false, ['BLP.HIGH_WATER']], 'no write down under the still-valid token');
});

test('resource search under a session token equals the point decisions under it; subject search refuses a token', async (t) => {
  const d = await deployment(t);
  const opened = await d.open();
  // a classified read raises the session's high-water mark, which the token carries into later writes
  assert.equal((await d.call('/access/v1/evaluation', d.point('carol', 'CASE-14', 'read', opened.token))).data.decision, true);
  const cases = ['CASE-7', 'CASE-11', 'CASE-12', 'CASE-14', 'CASE-15', 'CASE-18'];
  const seen: string[] = [];
  for (const token of [opened.token, undefined]) {
    for (const action of ['update', 'delete', 'close']) {
      const { context } = d.point('carol', 'CASE-7', action, token);
      const found = await d.call('/access/v1/search/resource', { subject: { type: 'user', id: 'carol' }, action: { name: action }, resource: { type: 'case' }, context });
      assert.equal(found.status, 200, JSON.stringify(found.data));
      const allowed: string[] = [];
      for (const id of cases) {
        const answer = await d.call('/access/v1/evaluation', d.point('carol', id, action, token));
        assert.equal(answer.status, 200, JSON.stringify(answer.data));
        if (answer.data.decision === true) allowed.push(id);
      }
      assert.deepEqual((found.data.results as { id: string }[]).map((r) => r.id).sort(), allowed.sort(), `${action} ${token ? 'with' : 'without'} the token`);
      seen.push(allowed.join(","));
    }
  }
  assert.notDeepEqual(seen.slice(0, 3), seen.slice(3), 'the session the token binds changes the answers (no write down after the read)');
  const subjects = await d.call('/access/v1/search/subject', { subject: { type: 'user' }, action: { name: 'read' }, resource: { type: 'case', id: 'CASE-14' },
    context: { network: 'trusted', sessionToken: opened.token } });
  assert.equal(subjects.status, 400, JSON.stringify(subjects.data));
});


test('admin revocation by session id, subject and credential immediately kills sessions and their decision tokens', async (t) => {
  const d = await deployment(t);
  const first = await d.open(); const second = await d.open(); const alice = await d.open('alice');
  const henry = await d.open('henry');
  const approve = await d.call('/access/v1/evaluation', { ...d.point('henry', 'PAY-3', 'approve', henry.token), context: {
    network: 'trusted', sessionToken: henry.token, makerId: 'grace',
  } });
  assert.equal(approve.data.decision, true);
  const decisionToken = String(approve.data.context.decision_token);

  assert.deepEqual((await admin(d, '/admin/v1/blp-sessions/revoke', { sessionId: first.sessionId }, 'POST', 'amira')).status, 403);
  const one = await admin(d, '/admin/v1/blp-sessions/revoke', { sessionId: first.sessionId });
  assert.deepEqual([one.status, one.data.revoked, one.data.sessionIds], [200, 1, [first.sessionId]]);
  assert.equal((await d.call('/access/v1/evaluation', d.point('carol', 'CASE-14', 'read', first.token))).status, 403);
  assert.equal((await d.call('/access/v1/evaluation', d.point('carol', 'CASE-14', 'read', second.token))).status, 200);
  assert.equal((await admin(d, '/admin/v1/blp-sessions/revoke', { sessionId: first.sessionId })).data.revoked, 0, 'idempotent');

  const subject = await admin(d, '/admin/v1/blp-sessions/revoke', { subject: { type: 'user', id: 'carol' }, credential: 'bootstrap' });
  assert.equal(subject.data.revoked, 1);
  assert.equal((await d.call('/access/v1/evaluation', d.point('carol', 'CASE-14', 'read', second.token))).status, 403);
  assert.equal((await d.call('/access/v1/evaluation', d.point('alice', 'CASE-14', 'read', alice.token))).status, 200);

  const byId = await admin(d, '/admin/v1/blp-sessions/revoke', { sessionId: henry.sessionId });
  assert.equal(byId.data.revoked, 1);
  const consumed = await d.call('/x/v1/tokens/consume', { token: decisionToken, action: 'approve', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 });
  assert.deepEqual([consumed.status, consumed.data.error], [409, 'conflict']);
  assert.match(String(consumed.data.message), /closed or expired/);

  const laterCarol = await d.open(); const laterAlice = await d.open('alice');
  const credential = await admin(d, '/admin/v1/blp-sessions/revoke', { credential: 'bootstrap' });
  assert.equal(credential.data.revoked, 3, 'alice, later carol and later alice');
  for (const [subjectId, opened] of [['carol', laterCarol], ['alice', laterAlice]] as const) {
    assert.equal((await d.call('/access/v1/evaluation', d.point(subjectId, 'CASE-14', 'read', opened.token))).status, 403);
  }
  assert.equal((await admin(d, '/admin/v1/blp-sessions/revoke', {})).status, 400);
  const listed = await admin(d, '/admin/v1/blp-sessions/revocations', undefined, 'GET');
  assert.equal(listed.status, 200);
  assert.ok((listed.data.items as Array<{ sid: string }>).some((row) => row.sid === henry.sessionId));
  const audit = readFileSync(resolve(d.dir, 'audit.jsonl'), 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line) as Record<string, any>);
  assert.ok(audit.some((row) => row.action === 'blp_session_revoke' && row.details?.sessionId === first.sessionId));
  assert.ok(!JSON.stringify(audit).includes(first.token));

  await d.server.close();
  const restarted = createServer({ port: 0, dataDir: d.dir, clock: 'fixed:2026-11-08T10:00:00Z', sodHistory: 'caller' });
  await restarted.listen(); t.after(() => restarted.close());
  const afterRestart = await fetch(`${restarted.url}/access/v1/evaluation`, { method: 'POST', headers: {
    'content-type': 'application/json', authorization: `Bearer ${d.credentials.pepApiKey}`,
  }, body: JSON.stringify(d.point('carol', 'CASE-14', 'read', first.token)) });
  assert.equal(afterRestart.status, 403, 'the revocation tombstone survives a single-node restart');
});


test('PostgreSQL revocation is immediate on another node and shared as a durable tombstone', { skip, timeout: 60_000 }, async (t) => {
  const { url, sql } = await throwawayDatabase(t, 'pep_admin_revocation');
  const dirs = [mkdtempSync('/tmp/pdp-revoke-a-'), mkdtempSync('/tmp/pdp-revoke-b-')];
  t.after(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });
  const options = (nodeId: string, dataDir: string): ServerOptions => ({ port: 0, dataDir, databaseUrl: url, signingKeySeal: SEAL, cluster: true, nodeId,
    rateLimit: 1_000_000, pepRateLimit: 1_000_000, sodHistory: 'caller' });
  const a = createServer(options('a', dirs[0]!)); await a.listen(); t.after(() => a.close());
  const b = createServer(options('b', dirs[1]!)); await b.listen(); t.after(() => b.close());
  const seeded = JSON.parse(readFileSync(resolve(dirs[0]!, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string; passwords: Record<string, string> };
  const call = async (server: PdpServer, path: string, body: unknown, headers: Record<string, string> = {}): Promise<Answer> => {
    const response = await fetch(`${server.url}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() as Record<string, any>, headers: response.headers };
  };
  const pep = { authorization: `Bearer ${seeded.pepApiKey}` };
  const open = async (server: PdpServer, subject: string): Promise<Opened> => {
    const answer = await call(server, '/x/v1/sessions', { subject: { type: 'user', id: subject } }, pep);
    assert.equal(answer.status, 201); return answer.data as Opened;
  };
  const carol = await open(a, 'carol'); const henry = await open(a, 'henry');
  const approved = await call(a, '/access/v1/evaluation', { subject: { type: 'user', id: 'henry' }, resource: { type: 'payment', id: 'PAY-3' }, action: { name: 'approve' },
    context: { network: 'trusted', sessionToken: henry.token, makerId: 'grace' } }, pep);
  assert.equal(approved.data.decision, true);
  const decisionToken = String(approved.data.context.decision_token);
  const login = await call(a, '/admin/v1/session', { username: 'lina', password: seeded.passwords.lina });
  const officer = { cookie: String(login.headers.get('set-cookie')).split(';')[0]!, 'x-csrf-token': String(login.data.csrfToken) };
  const revoked = await call(a, '/admin/v1/blp-sessions/revoke', { credential: 'bootstrap' }, officer);
  assert.deepEqual([revoked.status, revoked.data.revoked], [200, 2], JSON.stringify(revoked.data));
  const evaluation = await call(b, '/access/v1/evaluation', { subject: { type: 'user', id: 'carol' }, resource: { type: 'case', id: 'CASE-14' }, action: { name: 'read' },
    context: { network: 'trusted', sessionToken: carol.token } }, pep);
  assert.deepEqual([evaluation.status, evaluation.data.error], [403, 'invalid_session_token'], 'no document-reload wait on the other node');
  const consumed = await call(b, '/x/v1/tokens/consume', { token: decisionToken, action: 'approve', resource: { type: 'payment', id: 'PAY-3' }, resourceVersion: 4 }, pep);
  assert.deepEqual([consumed.status, consumed.data.error], [409, 'conflict']);
  const stored = await sql("SELECT body FROM gate_doc WHERE name = 'blp_revocations'");
  const tombstones = JSON.parse(String(stored.rows[0].body)) as Array<{ sid: string }>;
  assert.deepEqual(new Set(tombstones.map((row) => row.sid)), new Set([carol.sessionId, henry.sessionId]));
  assert.equal((await sql('SELECT count(*) AS n FROM gate_blp_session')).rows[0].n, '0');
});


test('PostgreSQL subject+credential revocation cannot deadlock a decision or latch either node', { skip, timeout: 60_000 }, async (t) => {
  const { url } = await throwawayDatabase(t, 'pep_revocation_deadlock');
  const dirs = [mkdtempSync('/tmp/pdp-deadlock-a-'), mkdtempSync('/tmp/pdp-deadlock-b-')];
  t.after(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });
  let entered!: () => void; let release!: () => void;
  const atScope = new Promise<void>((resolve) => { entered = resolve; });
  const unblock = new Promise<void>((resolve) => { release = resolve; });
  t.after(() => release());
  const options = (nodeId: string, dataDir: string): ServerOptions => ({ port: 0, dataDir, databaseUrl: url, signingKeySeal: SEAL, cluster: true, nodeId,
    rateLimit: 1_000_000, pepRateLimit: 1_000_000 });
  let injectDeadlock = false;
  const a = createServer({ ...options('a', dirs[0]!), databaseHooks: { onPepSessionLock: async () => {
    if (injectDeadlock) { injectDeadlock = false; throw Object.assign(new Error('injected deadlock'), { code: '40P01' }); }
  } } });
  await a.listen(); t.after(() => a.close());
  const b = createServer({ ...options('b', dirs[1]!), databaseHooks: { onDecisionLock: async (lock) => {
    if (lock.startsWith('pdp:')) { entered(); await unblock; }
  } } });
  await b.listen(); t.after(() => b.close());
  const seeded = JSON.parse(readFileSync(resolve(dirs[0]!, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string; passwords: Record<string, string> };
  const pep = { authorization: `Bearer ${seeded.pepApiKey}` };
  const call = async (server: PdpServer, path: string, body: unknown, headers: Record<string, string> = {}): Promise<Answer> => {
    const response = await fetch(`${server.url}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() as Record<string, any>, headers: response.headers };
  };
  const opened = await call(a, '/x/v1/sessions', { subject: { type: 'user', id: 'carol' } }, pep);
  assert.equal(opened.status, 201);
  const deciding = call(b, '/access/v1/evaluation', { subject: { type: 'user', id: 'carol' }, resource: { type: 'case', id: 'CASE-14' }, action: { name: 'read' },
    context: { network: 'trusted', sessionToken: opened.data.token } }, pep);
  await atScope;
  const login = await call(a, '/admin/v1/session', { username: 'lina', password: seeded.passwords.lina });
  const officer = { cookie: String(login.headers.get('set-cookie')).split(';')[0]!, 'x-csrf-token': String(login.data.csrfToken) };
  injectDeadlock = true;
  const revoking = call(a, '/admin/v1/blp-sessions/revoke', { subject: { type: 'user', id: 'carol' }, credential: 'bootstrap' }, officer);
  await new Promise((resolve) => setTimeout(resolve, 100));
  release();
  const [decision, revoked] = await Promise.all([deciding, revoking]);
  assert.equal(decision.status, 200, 'the decision commits without a lock inversion');
  assert.equal(revoked.status, 200, 'subject+credential revocation commits after the decision');
  const healthy = await call(b, '/access/v1/evaluation', { subject: { type: 'user', id: 'bob' }, resource: { type: 'case', id: 'CASE-18' }, action: { name: 'read' },
    context: { network: 'trusted' } }, pep);
  assert.equal(healthy.status, 200, 'a deadlock retry never latches the healthy node');
});
