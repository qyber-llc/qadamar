// /access/v1/search/subject lists who can access a resource: a per-credential capability (allowSubjectSearch), true by
// default for compatibility, false on demand, and false for every credential under GATE_PROFILE=production.
import test from 'node:test';
import assert from 'node:assert/strict';
import { IncomingMessage, ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { createServer, type PdpServer, type ServerOptions } from '../src/server.ts';
import { skip, throwawayDatabase } from './pg-database.ts';
import { Auth } from '../src/auth.ts';
import { HttpError } from '../src/http.ts';
import { createHandler } from '../src/router.ts';
import { fixture } from './helpers.ts';

const SEARCH = { subject: { type: 'user' }, action: { name: 'read' }, resource: { type: 'case', id: 'CASE-7' }, context: { network: 'trusted' } };

async function post(handler: ReturnType<typeof createHandler>, path: string, data: unknown, secret: string): Promise<{ status: number; data: Record<string, unknown> }> {
  const req = new IncomingMessage({ remoteAddress: '127.0.0.1', readable: false } as ConstructorParameters<typeof IncomingMessage>[0]);
  req.url = path; req.method = 'POST'; req.headers = { 'content-type': 'application/json', authorization: `Bearer ${secret}` };
  let text = '';
  const res = new ServerResponse(req);
  res.end = ((chunk?: unknown): ServerResponse => { text = chunk === undefined ? '' : String(chunk); return res; }) as typeof res.end;
  const pending = handler(req, res);
  req.push(JSON.stringify(data)); req.push(null);
  await pending;
  return { status: res.statusCode, data: JSON.parse(text) as Record<string, unknown> };
}

test('subject search follows the calling credential: allowed by default, refused when allowSubjectSearch is false', async (t) => {
  const f = fixture(t);
  const route = createHandler(f.rt, f.auth, { staticDir: resolve(f.dir, 'static') }, () => 'http://localhost:8787');
  const open = f.auth.createPepCredential('records-api', 'lina');
  const closed = f.auth.createPepCredential('gateway', 'lina', undefined, false);
  assert.equal(open.credential.allowSubjectSearch, true);
  assert.equal(closed.credential.allowSubjectSearch, false);
  for (const secret of [f.pepApiKey, open.secret]) {
    const r = await post(route, '/access/v1/search/subject', SEARCH, secret);
    assert.equal(r.status, 200); assert.ok((r.data.results as unknown[]).length > 0);
  }
  const refused = await post(route, '/access/v1/search/subject', SEARCH, closed.secret);
  assert.equal(refused.status, 403);
  // the other searches and decisions stay available to it
  const resources = await post(route, '/access/v1/search/resource', { subject: { type: 'user', id: 'alice' }, action: { name: 'read' }, resource: { type: 'case' } }, closed.secret);
  assert.equal(resources.status, 200);
  assert.ok(f.rt.audit.records().some((r) => r.action === 'pep_credential_create' && r.details?.allowSubjectSearch === false));
  assert.throws(() => f.auth.createPepCredential('bad', 'lina', undefined, 'yes'), (e: unknown) => e instanceof HttpError && e.status === 400);
});

test('the production profile refuses subject search to every credential and creates them without it', (t) => {
  const f = fixture(t);
  const auth = new Auth(f.dir, f.rt.audit, f.rt.now, undefined, { production: true });
  const created = auth.createPepCredential('gateway', 'lina', undefined, undefined, undefined, []);
  assert.equal(created.credential.allowSubjectSearch, false);
  assert.throws(() => auth.createPepCredential('wide', 'lina', undefined, true, undefined, []), (e: unknown) => e instanceof HttpError && e.status === 400 && /allowSubjectSearch/.test(e.message));
  const req = (secret: string) => ({ headers: { authorization: `Bearer ${secret}` } }) as unknown as IncomingMessage;
  assert.equal(auth.pepCaller(req(created.secret)).allowSubjectSearch, false);
  // a credential created earlier with the default (or the bootstrap one) cannot search subjects in production either
  const earlier = f.auth.createPepCredential('older', 'lina');
  const reloaded = new Auth(f.dir, f.rt.audit, f.rt.now, undefined, { production: true });
  assert.equal(reloaded.pepCaller(req(earlier.secret)).allowSubjectSearch, false);
  assert.equal(reloaded.pepCaller(req(f.pepApiKey)).allowSubjectSearch, false);
  assert.equal(f.auth.pepCaller(req(earlier.secret)).allowSubjectSearch, true, 'demo profile: unchanged');
});

test('PostgreSQL: a subject search on another node sees the session mark another node committed, as point decisions do', { skip, timeout: 60_000 }, async (t) => {
  const { url } = await throwawayDatabase(t, 'subject_search');
  const dirs = [mkdtempSync('/tmp/pdp-search-a-'), mkdtempSync('/tmp/pdp-search-b-')];
  t.after(() => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); });
  const seal = randomBytes(32).toString('base64url');
  const options = (nodeId: string, dataDir: string): ServerOptions => ({ port: 0, dataDir, databaseUrl: url, signingKeySeal: seal, cluster: true, nodeId,
    rateLimit: 1_000_000, pepRateLimit: 1_000_000 });
  const a = createServer(options('a', dirs[0]!)); await a.listen(); t.after(() => a.close());
  const b = createServer(options('b', dirs[1]!)); await b.listen(); t.after(() => b.close());
  const { pepApiKey } = JSON.parse(readFileSync(resolve(dirs[0]!, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string };
  const call = async (server: PdpServer, path: string, body: unknown): Promise<{ status: number; data: Record<string, any> }> => {
    const response = await fetch(`${server.url}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${pepApiKey}` }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() as Record<string, any> };
  };
  const context = { network: 'trusted', sessionId: 's1', sessionLevel: 1 };
  const write = { action: { name: 'update' }, resource: { type: 'case', id: 'CASE-11' }, context };
  const before = await call(b, '/access/v1/search/subject', { ...write, subject: { type: 'user' } });
  assert.equal(before.status, 200, JSON.stringify(before.data));
  assert.ok(before.data.results.some((s: { id: string }) => s.id === 'carol'), 'carol may update CASE-11 before any read');
  // node a commits carol's L3 mark in session s1
  const read = await call(a, '/access/v1/evaluation', { subject: { type: 'user', id: 'carol' }, resource: { type: 'case', id: 'CASE-14' }, action: { name: 'read' }, context: { network: 'trusted', sessionId: 's1' } });
  assert.equal(read.data.decision, true, JSON.stringify(read.data));
  const after = await call(b, '/access/v1/search/subject', { ...write, subject: { type: 'user' } });
  assert.equal(after.status, 200, JSON.stringify(after.data));
  assert.ok(!after.data.results.some((s: { id: string }) => s.id === 'carol'), 'no write down after the read on node a');
  const point = await call(b, '/access/v1/evaluation', { ...write, subject: { type: 'user', id: 'carol' } });
  assert.deepEqual([point.data.decision, point.data.context.rules], [false, ['BLP.HIGH_WATER']], 'the point decision agrees');
});
