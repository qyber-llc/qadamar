import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { AssertionVerifier, bodySha256 } from '../../../packages/sdk/src/assertion.ts';
import { indexTuples, type PolicyBundle, type Subject } from '../../../packages/core/src/index.ts';
import { PostgresReplayStore, replaySchema } from '../postgres-replay.ts';
import { filteredCases } from '../filtered-backend.ts';

const require = createRequire(new URL('../../../packages/pdp-http/package.json', import.meta.url));
const { Client } = require('pg') as typeof import('../../../packages/pdp-http/node_modules/@types/pg/index.d.ts');
const skip = process.env.TEST_DATABASE_URL ? false : 'TEST_DATABASE_URL is not set';

test('PostgreSQL replay store atomically spends across backend replicas and fails closed on storage loss', { skip }, async (t) => {
  const a = new Client({ connectionString: process.env.TEST_DATABASE_URL });
  const b = new Client({ connectionString: process.env.TEST_DATABASE_URL });
  await a.connect(); await b.connect();
  const backend = randomUUID();
  t.after(async () => { await a.query('DELETE FROM example_assertion_replay WHERE backend = $1', [backend]); await a.end(); await b.end(); });
  await a.query(replaySchema);
  const stores = [new PostgresReplayStore(a, backend), new PostgresReplayStore(b, backend)];
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const audience = 'https://backend.example', now = Math.floor(Date.now() / 1000);
  const claims = { sub: { type: 'user', id: 'bob' }, act: 'read', res: { type: 'case', id: '1' }, did: 'd1', pv: 'p1',
    aud: audience, htm: 'GET', htp: '/cases/1', bsh: bodySha256(Buffer.alloc(0)), iat: now, exp: now + 30, nonce: randomUUID() };
  const enc = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const content = `${enc({ alg: 'EdDSA', typ: 'gate-assertion+jwt', kid: 'test' })}.${enc(claims)}`;
  const token = `${content}.${sign(null, Buffer.from(content), privateKey).toString('base64url')}`;
  const verifiers = stores.map((replayStore) => new AssertionVerifier({ jwksUrl: 'https://gate.example/.well-known/jwks.json', audience, replayStore,
    fetch: (async () => new Response(JSON.stringify({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'test' }] }))) as typeof fetch }));
  const request = { method: 'GET', path: '/cases/1', body: Buffer.alloc(0), header: token };
  const results = await Promise.allSettled(Array.from({ length: 2 }, (_, i) => verifiers[i % 2]!.verify(request)));
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  for (const result of results) if (result.status === 'rejected') assert.equal(result.reason.code, 'assertion_replayed');
  await stores[0]!.prune();
  assert.equal(await stores[1]!.spend(claims.nonce, now + 90), false, 'cleanup preserves unexpired nonces including skew');
  await a.query('UPDATE example_assertion_replay SET expires_at = 0 WHERE backend = $1', [backend]);
  assert.equal(await stores[0]!.spend(claims.nonce, now + 90), true, 'expired nonce may be reused atomically');
  await a.query('UPDATE example_assertion_replay SET expires_at = 0 WHERE backend = $1', [backend]);
  await stores[0]!.prune();
  assert.equal((await a.query('SELECT * FROM example_assertion_replay WHERE backend = $1', [backend])).rowCount, 0);
  await b.query('SELECT 1');
  const outage = new AssertionVerifier({ jwksUrl: 'https://gate.example/.well-known/jwks.json', audience, replayStore: new PostgresReplayStore({ query: async () => { throw new Error('offline'); } }, backend), fetch: (async () => new Response(JSON.stringify({ keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'test' }] }))) as typeof fetch });
  await assert.rejects(outage.verify(request), { code: 'replay_store_unavailable' });
  assert.throws(() => new PostgresReplayStore(a, ''), /backend/);
  await assert.rejects(stores[0]!.spend('', NaN), /Invalid replay/);
});

const bundle = JSON.parse(readFileSync(new URL('../bundle.json', import.meta.url), 'utf8')) as PolicyBundle;
const subject: Subject = { type: 'user', id: 'bob', active: true, roles: ['reviewer'], clearance: 1, compartments: [], integrity: 'verified' };

test('SQL candidates still receive per-row history checks and obligations before release', { skip }, async (t) => {
  const db = new Client({ connectionString: process.env.TEST_DATABASE_URL }); await db.connect(); t.after(() => db.end());
  await db.query(`CREATE TEMP TABLE example_cases (id TEXT, level INTEGER, compartments TEXT[], integrity TEXT, content_classes TEXT[], maker TEXT, prior_actions TEXT[], title TEXT, secret TEXT)`);
  for (const [id, level, maker, prior] of [['allowed', 0, 'alice', []], ['self', 0, 'bob', []], ['history', 0, 'alice', ['author']], ['unknown', 0, null, []], ['classified', 3, 'alice', []]] as const) {
    await db.query('INSERT INTO example_cases VALUES ($1, $2, ARRAY[]::text[], $3, ARRAY[]::text[], $4, $5, $6, $7)', [id, level, 'verified', maker, prior, 'A case', 'sensitive']);
  }
  await db.query('BEGIN');
  const result = await filteredCases(db, bundle, indexTuples([]), subject, 'review', { network: 'trusted', now: new Date().toISOString(), makerId: 'forged', priorActions: [] });
  assert.deepEqual(result, [{ id: 'allowed', title: 'A case', secret: null }]);
  await db.query('ROLLBACK');
  const notify: PolicyBundle = { ...bundle, abac: [{ ...bundle.abac[0]!, obligations: { notify: ['security'] } }] };
  await assert.rejects(filteredCases(db, notify, indexTuples([]), subject, 'review', { network: 'trusted', now: new Date().toISOString() }), /Notification obligations/);
});
