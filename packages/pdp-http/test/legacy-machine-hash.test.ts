import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import crypto, { scryptSync } from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHandler } from '../src/router.ts';
import { needsRehash } from '../src/auth.ts';
import { Scim } from '../src/scim.ts';
import { fileBacking } from '../src/store.ts';
import { evaluation, fixture } from './helpers.ts';

type Handler = ReturnType<typeof createHandler>;
async function send(handler: Handler, path: string, method: string, authorization: string, data?: unknown): Promise<number> {
  const socket = { remoteAddress: '127.0.0.1', readable: false } as ConstructorParameters<typeof IncomingMessage>[0];
  const req = new IncomingMessage(socket); req.url = path; req.method = method;
  req.headers = { authorization, ...(data === undefined ? {} : { 'content-type': 'application/json' }) };
  const res = new ServerResponse(req);
  res.end = ((): ServerResponse => res) as typeof res.end;
  const pending = handler(req, res);
  req.push(data === undefined ? '' : JSON.stringify(data)); req.push(null);
  await pending;
  return res.statusCode;
}
/** The 0.8.3 form: `<salt>:<key>`, scrypt at the Node defaults. */
const legacyHash = (secret: string): string => `${'ab'.repeat(16)}:${scryptSync(secret, 'ab'.repeat(16), 32).toString('hex')}`;
/** Counts scryptSync calls made from now on (the real function still runs). */
function countSyncScrypt(t: TestContext): { calls: number } {
  const counter = { calls: 0 };
  const real = crypto.scryptSync;
  t.mock.method(crypto, 'scryptSync', (...args: Parameters<typeof scryptSync>) => { counter.calls++; return real(...args); });
  syncBuiltinESMExports();
  t.after(() => { t.mock.restoreAll(); syncBuiltinESMExports(); });
  return counter;
}

test('a 0.8.3 scrypt PEP key and SCIM token are verified off the event loop through the router, then upgraded', async (t) => {
  const f = fixture(t);
  const file = resolve(f.dir, 'credentials.json');
  const stored = JSON.parse(readFileSync(file, 'utf8')) as { pepCredentials: Array<{ hash: string }> };
  stored.pepCredentials[0]!.hash = legacyHash(f.pepApiKey);
  writeFileSync(file, JSON.stringify(stored));
  f.auth.reload();
  const token = 's'.repeat(48);
  const scimFile = resolve(f.dir, 'scim-credential.json');
  writeFileSync(scimFile, JSON.stringify({ hash: legacyHash(token), rotatedBy: 'amira' }));
  const route = createHandler(f.rt, f.auth, { scim: new Scim(f.rt, fileBacking(scimFile)) }, () => 'http://localhost:8787');
  const sync = countSyncScrypt(t);

  assert.equal(await send(route, '/access/v1/evaluation', 'POST', `Bearer ${f.pepApiKey}x`, evaluation()), 401);
  assert.equal(await send(route, '/scim/v2/Users', 'GET', `Bearer ${token}x`), 401);
  assert.equal(sync.calls, 0, 'a wrong secret against a legacy hash runs no synchronous scrypt');

  assert.equal(await send(route, '/access/v1/evaluation', 'POST', `Bearer ${f.pepApiKey}`, evaluation()), 200);
  assert.equal(await send(route, '/scim/v2/Users', 'GET', `Bearer ${token}`), 200);
  assert.equal(sync.calls, 0, 'the right secret is verified on the thread pool too');
  const pepHash = (JSON.parse(readFileSync(file, 'utf8')) as { pepCredentials: Array<{ hash: string }> }).pepCredentials[0]!.hash;
  const scimHash = (JSON.parse(readFileSync(scimFile, 'utf8')) as { hash: string }).hash;
  assert.equal(needsRehash(pepHash, true) || needsRehash(scimHash, true), false, 'both are rehashed to HMAC on first success');

  assert.equal(await send(route, '/access/v1/evaluation', 'POST', `Bearer ${f.pepApiKey}x`, evaluation()), 401);
  assert.equal(await send(route, '/scim/v2/Users', 'GET', `Bearer ${token}x`), 401);
  assert.equal(await send(route, '/access/v1/evaluation', 'POST', `Bearer ${f.pepApiKey}`, evaluation()), 200);
  assert.equal(sync.calls, 0);
});
