import test from 'node:test';
import assert from 'node:assert/strict';
import { scryptSync } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { User } from '../src/auth.ts';
import { Scim } from '../src/scim.ts';
import { fileBacking } from '../src/store.ts';
import { fixture } from './helpers.ts';

const legacyHash = (secret: string): string => `${'ab'.repeat(16)}:${scryptSync(secret, 'ab'.repeat(16), 32).toString('hex')}`;
const bearer = (token: string) => ({ headers: { authorization: `Bearer ${token}` } }) as unknown as IncomingMessage;

test('a SCIM rotation made while a legacy token is being verified is not overwritten by the old token', async (t) => {
  const f = fixture(t);
  const old = 'o'.repeat(48);
  const file = resolve(f.dir, 'scim-credential.json');
  writeFileSync(file, JSON.stringify({ hash: legacyHash(old), rotatedBy: 'amira' }));
  const scim = new Scim(f.rt, fileBacking(file));
  const inFlight = scim.authenticateAsync(bearer(old)); // suspended on the thread-pool scrypt
  const admin = { id: 'amira', roles: ['access_admin'] } as unknown as User;
  const fresh = (scim.rotateCredential(admin).body as { credential: string }).credential;
  const rotated = (JSON.parse(readFileSync(file, 'utf8')) as { hash: string }).hash;
  await assert.rejects(inFlight, (e: { status?: number }) => e.status === 401, 'the old token loses to the rotation');
  assert.equal((JSON.parse(readFileSync(file, 'utf8')) as { hash: string }).hash, rotated, 'the rotated hash is kept');
  assert.match(scim.authenticate(bearer(fresh)), /^scim:/, 'the new token works');
  assert.throws(() => scim.authenticate(bearer(old)), (e: { status?: number }) => e.status === 401);
});
