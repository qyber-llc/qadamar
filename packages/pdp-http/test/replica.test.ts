// Stateless decision replicas (docs/API.md §3.9.5) against a real PostgreSQL (TEST_DATABASE_URL; skipped otherwise):
// bootstrap from a signed snapshot, signed deltas, staleness, forwarding, the durable local chain and its ingestion.
import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer as httpServer, request as httpRequest, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { resolve } from 'node:path';
import { canonical } from '../../core/src/index.ts';
import { createServer, type PdpServer, type ServerOptions } from '../src/server.ts';
import { Audit, rowMac, sha256, type AuditRecord } from '../src/audit.ts';
import { Tokens } from '../src/tokens.ts';
import { signHop } from '../src/forward.ts';
import { derive, hopKeyOf, parseReplicaKeys, REPLICA_CHECKPOINT_LABEL, REPLICA_HOP_HEADER, REPLICA_SIGNATURE_HEADER, replicaId, replicaKeyEntry, replicaKeyFor, replicaKeyOf, signBody, TrustedKeys, type StateMessage } from '../src/replica-protocol.ts';
import { parsePins, replicaOrigin } from '../src/replica.ts';
import { replicaProductionFailures } from '../src/profile.ts';
import { evaluation, FIXED, WHY } from './helpers.ts';
import { skip, throwawayDatabase } from './pg-database.ts';

const SEAL = randomBytes(32).toString('base64url');
const K1 = randomBytes(32); const K2 = randomBytes(32);
/** r2 is served through the group `r*` (master K2): it holds only its own derived key. */
const R2 = Buffer.from(replicaKeyOf(K2, 'r2'));
const BOUND = 500;
const tmp = (t: TestContext): string => { const dir = mkdtempSync('/tmp/pdp-replica-'); t.after(() => rmSync(dir, { recursive: true, force: true })); return dir; };
interface Answer { status: number; data: Record<string, unknown>; headers: Headers }
async function call(base: string, path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}): Promise<Answer> {
  const res = await fetch(`${base}${path}`, { method, headers: { 'content-type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const text = await res.text();
  let data: Record<string, unknown> = {};
  try { data = text ? JSON.parse(text) as Record<string, unknown> : {}; } catch { /* not JSON */ }
  return { status: res.status, data, headers: res.headers };
}
async function within(limit: number, check: () => Promise<boolean>): Promise<number> {
  const started = performance.now();
  while (!await check()) {
    if (performance.now() - started > limit) assert.fail(`not within ${limit} ms`);
    await new Promise((done) => setTimeout(done, 5));
  }
  return performance.now() - started;
}
const localRows = (dir: string): AuditRecord[] => existsSync(resolve(dir, 'audit.jsonl'))
  ? readFileSync(resolve(dir, 'audit.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as AuditRecord) : [];
/** Servers close before the throwaway database is dropped (after hooks run in the order they were added). */
const closers = new WeakMap<TestContext, Array<() => Promise<void>>>();
function closeLater(t: TestContext, close: () => Promise<void>): void {
  let list = closers.get(t);
  if (!list) { const created: Array<() => Promise<void>> = []; list = created; closers.set(t, created); t.after(async () => { for (const c of created.reverse()) await c().catch(() => undefined); }); }
  list.push(close);
}

/** One database node serving replicas r1 and r2, plus the console and PEP credentials it seeded. */
async function deployment(t: TestContext, extra: Partial<ServerOptions> = {}) {
  closeLater(t, async () => undefined);
  const { url, sql } = await throwawayDatabase(t, 'replica');
  const dir = tmp(t);
  const leader = createServer({ port: 0, dataDir: dir, databaseUrl: url, signingKeySeal: SEAL, clock: `fixed:${FIXED}`, rateLimit: 1_000_000, pepRateLimit: 1_000_000,
    replicaKeys: new Map([['r1', K1], ['r*', K2]]), ...extra }); // r2 through a group key
  await leader.listen(); closeLater(t, () => leader.close());
  const seeded = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string; passwords: Record<string, string> };
  const pep = { authorization: `Bearer ${seeded.pepApiKey}` };
  const login = async (id: string): Promise<Record<string, string>> => {
    const r = await call(leader.url, '/admin/v1/session', 'POST', { username: id, password: seeded.passwords[id] });
    assert.equal(r.status, 200, JSON.stringify(r.data));
    return { cookie: String(r.headers.get('set-cookie')).split(';')[0]!, 'x-csrf-token': String(r.data.csrfToken) };
  };
  const rows = async (node: string): Promise<number> => Number((await sql('SELECT count(*) AS n FROM gate_audit WHERE node = $1', [node])).rows[0].n);
  return { leader, sql, pep, login, rows, dir };
}
async function replicaNode(t: TestContext, leaderUrl: string, id = 'r1', key = K1, extra: Partial<ServerOptions> = {}, dir = tmp(t)): Promise<{ server: PdpServer; dir: string }> {
  const server = createServer({ port: 0, dataDir: dir, replicaOf: leaderUrl, replicaKey: key.toString('base64url'), nodeId: id, clock: `fixed:${FIXED}`,
    rateLimit: 1_000_000, pepRateLimit: 1_000_000, maxStalenessMs: BOUND, ...extra });
  await server.listen(); closeLater(t, () => server.close());
  return { server, dir };
}
const decide = async (base: string, pep: Record<string, string>, body = evaluation()): Promise<Answer> => call(base, '/access/v1/evaluation', 'POST', body, pep);

test('a replica bootstraps from the signed snapshot, decides on its own durable chain, follows changes, and the database stores that chain', { skip, timeout: 60_000 }, async (t) => {
  const d = await deployment(t);
  const r = await replicaNode(t, d.leader.url);
  const ready = await call(r.server.url, '/readyz');
  assert.equal(ready.status, 200); assert.equal(ready.data.role, 'replica'); assert.equal(ready.data.node, 'r1');
  for (const body of [evaluation(), evaluation('alice', 'CASE-14'), evaluation('bob', 'PAY-1', 'read'), evaluation('bob', 'CASE-14', 'update', 'trusted')]) {
    const [at, replicated] = [await decide(d.leader.url, d.pep, body), await decide(r.server.url, d.pep, body)];
    assert.equal(replicated.status, 200); assert.deepEqual(replicated.data, at.data, JSON.stringify(body));
  }
  // the replica's own chain: every row names it, every subject is the database's pseudonym, nothing raw
  const local = localRows(r.dir);
  assert.ok(local.length >= 4 && local.every((row) => row.node === 'r1'));
  assert.ok(local.filter((row) => row.type === 'decision').every((row) => /^ps\.[0-9a-f]{32}$/.test(row.subject ?? '')));
  await within(5000, async () => await d.rows('r1') === local.length);
  const verified = await call(d.leader.url, '/admin/v1/audit/verify', 'GET', undefined, await d.login('sam'));
  assert.equal(verified.status, 200); assert.equal(verified.data.verified, true, JSON.stringify(verified.data));
  // a policy-plane change on the database reaches the replica: a subject disabled by two people
  const proposal = await call(d.leader.url, '/admin/v1/changes', 'POST', { kind: 'update_subject', payload: { id: 'bob', set: { active: false } }, reason: WHY }, await d.login('amira'));
  assert.equal(proposal.status, 201);
  assert.equal((await call(d.leader.url, `/admin/v1/changes/${String(proposal.data.id)}/approve`, 'POST', { reason: WHY }, await d.login('omar'))).status, 200);
  const subjectMs = await within(BOUND * 4, async () => (await decide(r.server.url, d.pep)).data.decision === false);
  // a revoked PEP credential stops working on the replica as well
  const lina = await d.login('lina');
  const created = await call(d.leader.url, '/admin/v1/pep-credentials', 'POST', { name: 'replica-test' }, lina);
  assert.equal(created.status, 201);
  const secret = { authorization: `Bearer ${String(created.data.secret)}` };
  await within(BOUND * 4, async () => (await decide(r.server.url, secret)).status === 200);
  const revoked = performance.now();
  const id = (created.data.credential as { id: string }).id;
  assert.equal((await call(d.leader.url, `/admin/v1/pep-credentials/${id}/revoke`, 'POST', {}, lina)).status, 200);
  await within(BOUND * 4, async () => (await decide(r.server.url, secret)).status === 401);
  console.info(`replica propagation: subject change ${subjectMs.toFixed(0)} ms after approval, revocation ${(performance.now() - revoked).toFixed(0)} ms after the revoke`);
  const metrics = await call(r.server.url, '/metrics');
  assert.equal(metrics.status, 200);
});

test('a replica passes on what its copy may not decide: session marks, separation of duty, certified actions, unknown subjects, the console', { skip, timeout: 60_000 }, async (t) => {
  const d = await deployment(t);
  const r = await replicaNode(t, d.leader.url);
  const leaderRows = async (): Promise<number> => d.rows('0');
  const forwarded = async (body: Record<string, unknown>, path = '/access/v1/evaluation'): Promise<Answer> => {
    const [before, local] = [await leaderRows(), localRows(r.dir).length];
    const answer = await call(r.server.url, path, 'POST', body, d.pep);
    assert.ok(await leaderRows() > before, `audited by the database: ${JSON.stringify(body)}`);
    assert.equal(localRows(r.dir).length, local, 'not on the replica chain');
    return answer;
  };
  assert.equal((await forwarded({ ...evaluation(), context: { sessionId: 's-1' } })).status, 200);
  const opened = await forwarded({ subject: { type: 'user', id: 'carol' } }, '/x/v1/sessions');
  assert.equal(opened.status, 201);
  const token = String(opened.data.token);
  const withToken = (resource: string, action: string, sessionToken = token): Record<string, unknown> => ({
    subject: { type: 'user', id: 'carol' }, resource: { type: 'case', id: resource }, action: { name: action },
    context: { network: 'trusted', sessionToken, ...(action === 'read' ? {} : { sessionLevel: 1 }) },
  });
  assert.equal((await forwarded(withToken('CASE-14', 'read'))).data.decision, true);
  const second = await forwarded({ subject: { type: 'user', id: 'carol' } }, '/x/v1/sessions');
  assert.equal((await forwarded(withToken('CASE-11', 'update', String(second.data.token)))).data.decision, false);
  assert.equal((await forwarded({ token }, '/x/v1/sessions/close')).status, 200);
  assert.equal((await forwarded(withToken('CASE-14', 'read'))).status, 403);
  const revoked = await call(d.leader.url, '/admin/v1/blp-sessions/revoke', 'POST', { sessionId: String(second.data.sessionId) }, await d.login('lina'));
  assert.equal(revoked.status, 200, JSON.stringify(revoked.data));
  const localBeforeRevoked = localRows(r.dir).length;
  const refusedRevoked = await call(r.server.url, '/access/v1/evaluation', 'POST', withToken('CASE-14', 'read', String(second.data.token)), d.pep);
  assert.equal(refusedRevoked.status, 403, JSON.stringify(refusedRevoked.data));
  assert.equal(localRows(r.dir).length, localBeforeRevoked, 'the token-bearing decision is forwarded, not decided locally');
  const nonce = randomBytes(18).toString('base64url');
  const feedPath = `/x/v1/replica/state?nonce=${nonce}`;
  const feed = await call(d.leader.url, feedPath, 'GET', undefined, { [REPLICA_HOP_HEADER]: signHop(hopKeyOf(K1), 'GET', feedPath, Buffer.alloc(0), 'test', 'r1') });
  assert.equal(feed.status, 200);
  const docs = (feed.data as unknown as StateMessage).docs;
  assert.ok(docs?.blp_revocations.some((row) => row.sid === second.data.sessionId), 'the signed replica feed carries the revocation tombstone');
  assert.equal((await forwarded(evaluation('bob', 'PAY-1', 'approve'))).status, 200);
  assert.equal((await forwarded(evaluation('bob', 'CASE-14', 'close'))).status, 200);
  assert.equal((await forwarded({ evaluations: [evaluation(), evaluation('bob', 'PAY-1', 'create')] }, '/access/v1/evaluations')).status, 200);
  // an id the database has no pseudonym for: decided there (which records one), then locally once the mapping arrives
  assert.equal((await forwarded(evaluation('zed'))).data.decision, false);
  await within(BOUND * 4, async () => { const before = localRows(r.dir).length; await decide(r.server.url, d.pep, evaluation('zed')); return localRows(r.dir).length > before; });
  assert.equal((await call(r.server.url, '/x/v1/tokens/consume', 'POST', { token: 'a.b.c', resource: { type: 'case', id: 'CASE-14' }, action: 'close' }, d.pep)).status, 409);
  assert.equal((await call(r.server.url, '/admin/v1/session')).status, 401, 'the console is the database\'s');
  assert.equal((await call(r.server.url, '/xacml/v3/authorize', 'POST', {}, d.pep)).status, 200);
  assert.equal((await call(r.server.url, '/access/v1/evaluation', 'POST', evaluation(), { authorization: 'Bearer nope' })).status, 401);
  // replica requests themselves need the replica's hop
  assert.equal((await call(d.leader.url, '/x/v1/replica/state?nonce=aaaaaaaaaaaaaaaaaaaa')).status, 401);
  const path = '/x/v1/replica/state?nonce=aaaaaaaaaaaaaaaaaaaa';
  assert.equal((await call(d.leader.url, path, 'GET', undefined, { [REPLICA_HOP_HEADER]: signHop(hopKeyOf(randomBytes(32)), 'GET', path, Buffer.alloc(0), 'x', 'r1') })).status, 401, 'wrong key');
  assert.equal((await call(d.leader.url, path, 'GET', undefined, { [REPLICA_HOP_HEADER]: signHop(hopKeyOf(K1), 'GET', path, Buffer.alloc(0), 'x', 'r9') })).status, 401, 'unknown replica');
});

/** A signer between the replica and the database: re-signs every answer with its own key (which the replica pins), after
 *  `edit`, or tampers, replays or holds answers. */
async function signer(t: TestContext, target: string) {
  const tokens = new Tokens(tmp(t), () => new Date().toISOString());
  const jwk = tokens.jwks().keys[0] as { x: string; kid: string };
  const pem = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' }).export({ type: 'spki', format: 'pem' }).toString();
  const control = { mode: 'resign' as 'resign' | 'tamper' | 'replay' | 'hold', edit: (m: StateMessage): StateMessage => m, last: undefined as { body: string; signature: string } | undefined };
  const server: Server = httpServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      if (control.mode === 'hold') { res.statusCode = 503; res.end('{}'); return; }
      const upstream = httpRequest(`${target}${req.url}`, { method: req.method, headers: { ...req.headers, host: new URL(target).host } }, (answer) => {
        const parts: Buffer[] = [];
        answer.on('data', (c: Buffer) => parts.push(c));
        answer.on('end', () => {
          let text = Buffer.concat(parts).toString('utf8');
          if (req.url?.startsWith('/x/v1/replica/state') && answer.statusCode === 200) {
            const m = control.edit(JSON.parse(text) as StateMessage);
            if (m.docs) m.docs.signing_keys.keys.push({ kid: jwk.kid, created: FIXED, publicKey: pem } as never);
            text = JSON.stringify(m);
          }
          let signature = signBody(tokens, text);
          if (control.mode === 'tamper') text = text.replace('"state"', '"state" ');
          if (control.mode === 'replay' && control.last) ({ body: text, signature } = control.last);
          else control.last = { body: text, signature };
          res.writeHead(answer.statusCode ?? 502, { 'content-type': 'application/json', [REPLICA_SIGNATURE_HEADER]: signature });
          res.end(text);
        });
      });
      upstream.on('error', () => { res.statusCode = 502; res.end('{}'); });
      upstream.end(Buffer.concat(chunks));
    });
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  t.after(() => { server.close(); server.closeAllConnections(); });
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, pin: jwk.x, control };
}

test('a replica refuses an untrusted, tampered, replayed or rolled-back state, and refuses decisions once beyond the staleness bound', { skip, timeout: 60_000 }, async (t) => {
  const d = await deployment(t);
  const s = await signer(t, d.leader.url);
  // not pinned: the signer's key is not one this replica trusts
  await assert.rejects(replicaNode(t, s.url, 'r1', K1, { replicaPins: [randomBytes(32).toString('base64url').slice(0, 43)] }), /not signed by a key this replica trusts/);
  s.control.mode = 'tamper';
  await assert.rejects(replicaNode(t, s.url, 'r1', K1, { replicaPins: [s.pin] }), /not signed by a key this replica trusts/);
  s.control.mode = 'resign';
  const dir = tmp(t);
  const r = await replicaNode(t, s.url, 'r1', K1, { replicaPins: [s.pin] }, dir);
  assert.equal((await decide(r.server.url, d.pep)).status, 200);
  // replayed: a genuine signed answer to an earlier request (another nonce)
  s.control.mode = 'replay';
  await within(BOUND * 4, async () => (await decide(r.server.url, d.pep)).status === 503);
  assert.equal((await call(r.server.url, '/readyz')).status, 503);
  s.control.mode = 'resign';
  await within(BOUND * 4, async () => (await decide(r.server.url, d.pep)).status === 200);
  // a signed state older than one already applied (here the signer once claimed a later generation): rollback refused
  s.control.edit = (m) => ({ ...m, at: { version: m.at.version + 1000, records: m.at.records + 1000 } });
  const proposal = await call(d.leader.url, '/admin/v1/changes', 'POST', { kind: 'update_subject', payload: { id: 'carol', set: { active: false } }, reason: WHY }, await d.login('amira'));
  assert.equal((await call(d.leader.url, `/admin/v1/changes/${String(proposal.data.id)}/approve`, 'POST', { reason: WHY }, await d.login('omar'))).status, 200);
  await within(BOUND * 4, async () => JSON.parse(readFileSync(resolve(dir, 'replica-trust.json'), 'utf8')).at.version > 1000);
  s.control.edit = (m) => m;
  await within(BOUND * 4, async () => (await decide(r.server.url, d.pep)).status === 503);
  // the floor outlives a restart: the same data directory still refuses the older state
  await r.server.close();
  await assert.rejects(replicaNode(t, s.url, 'r1', K1, { replicaPins: [s.pin] }, dir), /rollback refused/);
  // staleness: a replica cut off from the feed stops deciding within the bound, and resumes once it is back
  const s2 = await signer(t, d.leader.url);
  const cut = await replicaNode(t, s2.url, 'r2', R2, { replicaPins: [s2.pin] });
  assert.equal((await decide(cut.server.url, d.pep)).status, 200);
  s2.control.mode = 'hold';
  const stale = await within(BOUND * 4, async () => (await decide(cut.server.url, d.pep)).status === 503);
  assert.ok(stale >= BOUND / 2, `refused only once beyond the bound (${stale.toFixed(0)} ms)`);
  assert.equal((await call(cut.server.url, '/readyz')).status, 503);
  s2.control.mode = 'resign';
  const back = await within(BOUND * 8, async () => (await decide(cut.server.url, d.pep)).status === 200);
  console.info(`replica staleness: refused ${stale.toFixed(0)} ms after the feed was held (bound ${BOUND} ms), deciding again ${back.toFixed(0)} ms after it returned`);
});

test('the database refuses a replica chain with a gap, a fork or a tampered row, and alerts; a replica restart resumes its chain; a lost disk is refused', { skip, timeout: 60_000 }, async (t) => {
  const d = await deployment(t);
  const r = await replicaNode(t, d.leader.url, 'r2', R2);
  for (let i = 0; i < 3; i++) assert.equal((await decide(r.server.url, d.pep)).status, 200);
  await within(5000, async () => await d.rows('r2') === localRows(r.dir).length);
  const head = localRows(r.dir).at(-1)!;
  const post = (body: unknown): Promise<Answer> => {
    const path = `/x/v1/replica/audit?nonce=${randomBytes(18).toString('base64url')}`;
    const raw = Buffer.from(JSON.stringify(body));
    return call(d.leader.url, path, 'POST', body, { [REPLICA_HOP_HEADER]: signHop(hopKeyOf(R2), 'POST', path, raw, 'test', 'r2') });
  };
  const row = (seq: number, prevHash: string, key = derive(R2, REPLICA_CHECKPOINT_LABEL)): AuditRecord => {
    const unsigned = { type: 'security', actor: 'system', action: 'test', node: 'r2', seq, ts: FIXED, prevHash };
    const rest = { ...unsigned, mac: rowMac(key, unsigned) };
    return { ...rest, hash: sha256(prevHash + canonical(rest)) } as AuditRecord;
  };
  const refusals = async (): Promise<number> => Number((await d.sql(`SELECT count(*) AS n FROM gate_audit WHERE node = '0' AND record LIKE '%replica_audit_refused%'`)).rows[0].n);
  const next = row(head.seq + 1, head.hash);
  assert.equal((await post({ base: { seq: head.seq, hash: head.hash }, rows: [{ ...next, action: 'edited' }] })).data.refused, 'tampered');
  assert.equal((await post({ base: { seq: head.seq, hash: head.hash }, rows: [row(head.seq + 1, head.hash, randomBytes(32))] })).data.refused, 'tampered', 'linked and hashed, but not the replica\'s MAC');
  assert.equal((await post({ base: { seq: head.seq, hash: '1'.repeat(64) }, rows: [row(head.seq + 1, '1'.repeat(64))] })).data.refused, 'fork');
  assert.equal((await post({ base: { seq: head.seq + 5, hash: '2'.repeat(64) }, rows: [row(head.seq + 6, '2'.repeat(64))] })).data.refused, 'gap');
  assert.equal((await post({ base: { seq: 1, hash: localRows(r.dir)[0]!.hash }, rows: [] })).data.refused, 'behind');
  const resent = await post({ base: { seq: head.seq - 1, hash: localRows(r.dir).at(-2)!.hash }, rows: [head] });
  assert.equal(resent.status, 200, 'a resend of a stored row is accepted as is'); assert.equal((resent.data.head as { seq: number }).seq, head.seq);
  assert.equal(await refusals(), 4, 'the second tampered batch within a minute is counted, not chained again');
  assert.match(await (await fetch(`${d.leader.url}/metrics`)).text(), /gate_replica_audit_refused_total 4/);
  // restart: the local chain continues where it was, and so does the stored one
  await r.server.close();
  const again = await replicaNode(t, d.leader.url, 'r2', R2, {}, r.dir);
  assert.equal((await decide(again.server.url, d.pep)).status, 200);
  const continued = localRows(again.dir);
  assert.equal(continued.at(-1)!.seq, head.seq + 1);
  await within(5000, async () => await d.rows('r2') === continued.length);
  await again.server.close();
  // a replica whose disk is gone (empty data directory, same id) is refused: the database holds rows it no longer has
  await assert.rejects(replicaNode(t, d.leader.url, 'r2', R2), /refused this replica's audit chain \(behind/);
  assert.equal(await refusals(), 4, 'behind was alerted less than a minute ago');
  const verified = await call(d.leader.url, '/admin/v1/audit/verify', 'GET', undefined, await d.login('sam'));
  assert.equal(verified.data.verified, true);
});

test('a key rotation on the database is followed through the introduction the old key signed', { skip, timeout: 60_000 }, async (t) => {
  const d = await deployment(t);
  const jwks = await call(d.leader.url, '/.well-known/jwks.json');
  const first = (jwks.data.keys as Array<{ x: string }>)[0]!.x;
  const r = await replicaNode(t, d.leader.url, 'r1', K1, { replicaPins: [first] });
  assert.equal((await call(d.leader.url, '/admin/v1/signing-keys/rotate', 'POST', {}, await d.login('lina'))).status, 201);
  // the database now signs with the new key only; the replica keeps deciding because the old key introduced it
  await new Promise((done) => setTimeout(done, BOUND * 2));
  // a slow runner may still be re-reading the trust file: poll rather than assert once
  await within(10_000, async () => (await decide(r.server.url, d.pep)).status === 200);
  const trusted = JSON.parse(readFileSync(resolve(r.dir, 'replica-trust.json'), 'utf8')) as { trusted: string[] };
  assert.equal(trusted.trusted.length, 2, 'the pinned key and the key it introduced');
});

test('durable audit: an answer waits for fdatasync; every row carries its MAC; a torn last row is dropped; truncation below the checkpoint is caught', (t) => {
  const dir = tmp(t);
  const key = randomBytes(32);
  const file = resolve(dir, 'audit.jsonl');
  const shipped: number[] = [];
  const open = (): Audit => new Audit(file, () => FIXED, { checkpointKey: key, node: 'r1', durable: true, onDurable: (rows) => shipped.push(...rows.map((row) => row.seq)) });
  assert.throws(() => new Audit(resolve(dir, 'x.jsonl'), () => FIXED, { durable: true }), /checkpoint key/);
  const audit = open();
  audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'allow' });
  assert.equal(audit.durable().seq, 0, 'not durable before the flush');
  return (async () => {
    await audit.flush();
    assert.deepEqual(shipped, [1]); assert.equal(audit.durable().seq, 1);
    audit.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'deny' });
    await audit.flush();
    const [first, second] = audit.records();
    assert.equal(first!.node, 'r1'); assert.equal((first as AuditRecord & { mac: string }).mac, rowMac(key, first!));
    // a crash in the middle of an append: the partial row was never answered, and is dropped (audited) at the next start
    appendFileSync(file, '{"seq":3,"type":"decis');
    const reopened = open();
    assert.deepEqual(reopened.records().map((row) => [row.seq, row.action]), [[1, 'read'], [2, 'read'], [3, 'torn_row_dropped']]);
    await reopened.flush();
    // rows past the checkpoint (written at most once a second) stand on their MACs: a forged one does not
    const forged = { ...second!, action: 'export' };
    const lines = readFileSync(file, 'utf8').split('\n').filter(Boolean);
    const tampered = resolve(tmp(t), 'audit.jsonl');
    for (const name of ['audit.jsonl', 'audit-checkpoint.slots']) appendFileSync(resolve(tampered, '..', name), readFileSync(resolve(dir, name)));
    rmSync(tampered); appendFileSync(tampered, [lines[0], JSON.stringify({ ...forged, hash: sha256(forged.prevHash + canonical((({ hash: _h, ...rest }) => rest)(forged))) })].join('\n') + '\n');
    assert.equal(new Audit(tampered, () => FIXED, { checkpointKey: key, node: 'r1', durable: true }).verify().verified, false);
    // a chain cut below its checkpoint is refused
    const cut = resolve(tmp(t), 'audit.jsonl');
    appendFileSync(resolve(cut, '..', 'audit-checkpoint.slots'), readFileSync(resolve(dir, 'audit-checkpoint.slots')));
    appendFileSync(cut, `${lines[0]}\n`);
    assert.throws(() => new Audit(cut, () => FIXED, { checkpointKey: key, node: 'r1', durable: true }).append({ type: 'security', actor: 'system', action: 'x' }), /integrity/);
    // retention of the shipped prefix keeps the chain verifiable
    const clean = resolve(tmp(t), 'audit.jsonl');
    const kept = new Audit(clean, () => FIXED, { checkpointKey: key, node: 'r1', durable: true });
    for (let i = 0; i < 4; i++) kept.append({ type: 'decision', actor: 'pep', action: 'read', effect: 'allow' });
    await kept.flush();
    assert.equal(kept.retain({ seq: 3 }), true);
    await kept.flush();
    assert.ok(kept.verify().verified);
    assert.ok(new Audit(clean, () => FIXED, { checkpointKey: key, node: 'r1', durable: true }).verify().verified);
  })();
});

test('replica configuration is validated at start', () => {
  assert.throws(() => replicaOrigin('http://leader.example'), /https/);
  assert.throws(() => replicaOrigin('https://leader.example/path'), /origin/);
  assert.equal(replicaOrigin('http://127.0.0.1:9').port, '9');
  assert.throws(() => replicaId('0'), /not "0"/);
  assert.throws(() => parseReplicaKeys('r1=short'), /32 bytes/);
  assert.throws(() => parseReplicaKeys(`r1=${K1.toString('base64url')},r1=${K2.toString('base64url')}`), /twice/);
  assert.equal(parseReplicaKeys(`r1=${K1.toString('hex')}, r2=${K2.toString('base64url')}`)?.size, 2);
  assert.equal(parseReplicaKeys(''), undefined);
  const group = parseReplicaKeys(`gate-replica-*=${K1.toString('base64url')},r2=${K2.toString('base64url')}`)!;
  assert.equal(replicaKeyEntry(group, 'gate-replica-0'), 'gate-replica-*'); assert.equal(replicaKeyEntry(group, 'r2'), 'r2');
  assert.equal(replicaKeyEntry(group, 'gate-0'), undefined); assert.equal(replicaKeyEntry(group, '0'), undefined);
  assert.throws(() => parseReplicaKeys(`-x*=${K1.toString('base64url')}`), /GATE_REPLICA_KEYS ids/);
  assert.throws(() => parsePins('not-a-key'), /JWK x/);
  assert.throws(() => createServer({ replicaOf: 'https://x.example', nodeId: 'r1' }), /GATE_REPLICA_KEY/);
  assert.throws(() => createServer({ replicaOf: 'https://x.example', nodeId: 'r1', replicaKey: K1.toString('base64url'), databaseUrl: 'postgres://x' }), /exclude/);
  assert.throws(() => createServer({ replicaKeys: new Map([['r1', K1]]) }), /needs DATABASE_URL/);
  assert.throws(() => createServer({ databaseUrl: 'postgres://x', signingKeySeal: SEAL, nodeId: 'gate-1', replicaKeys: new Map([['gate-*', K1]]) }), /own GATE_NODE_ID/);
  const failures = replicaProductionFailures({ replicaOf: 'http://127.0.0.1:1', clock: 'fixed:x' }, '');
  assert.equal(failures.length, 4);
  assert.deepEqual(replicaProductionFailures({ replicaOf: 'https://x', publicOrigin: 'https://r' }, 'm'.repeat(32)), []);
});

test('a replica audit shipment stays under the database nodes\' 1 MB body cap, whatever the row size', async () => {
  const { Replica } = await import('../src/replica.ts');
  const batch = (Replica.prototype as unknown as { batch(this: { queue: Array<{ row: unknown }> }): unknown[] }).batch;
  const rows = (n: number, size: number): Array<{ row: unknown }> => Array.from({ length: n }, (_, seq) => ({ row: { seq, pad: 'x'.repeat(size) } }));
  assert.equal(batch.call({ queue: rows(3000, 10) }).length, 1000, 'at most 1,000 rows');
  const large = batch.call({ queue: rows(1000, 4000) });
  assert.ok(large.length < 1000 && Buffer.byteLength(JSON.stringify({ base: { seq: 0, hash: '0'.repeat(64) }, rows: large })) < 1_048_576);
  assert.equal(batch.call({ queue: rows(2, 900_000) }).length, 1, 'one row always ships');
});

test('a group master gives each replica its own key: the ops script derives it, and a sibling\'s id is never accepted', async () => {
  const keys = parseReplicaKeys(`gate-replica-*=${K1.toString('base64url')},solo=${K2.toString('base64url')}`)!;
  const a = replicaKeyFor(keys, 'gate-replica-0')!, b = replicaKeyFor(keys, 'gate-replica-1')!;
  assert.ok(!a.equals(b) && !a.equals(K1), 'each id has its own key, none the master');
  assert.ok(replicaKeyFor(keys, 'solo')!.equals(K2), 'a listed id keeps its key');
  assert.equal(replicaKeyFor(keys, 'other'), undefined);
  const { execFileSync } = await import('node:child_process');
  const out = execFileSync(process.execPath, ['scripts/ops/replica-key.ts', 'gate-replica-0', 'gate-replica-1'], { input: K1.toString('hex'), encoding: 'utf8' });
  assert.deepEqual(out.trim().split('\n'), [`gate-replica-0=${a.toString('base64url')}`, `gate-replica-1=${b.toString('base64url')}`]);
});

test('an introduction counts only while the introducing key is inside its verification window', () => {
  const dir = mkdtempSync('/tmp/pdp-replica-keys-');
  try {
    let disk: unknown;
    const tokens = new Tokens(dir, () => FIXED, undefined, { keyring: { load: () => disk as never, save: (value) => { disk = value; } } });
    const parent = tokens.activePublic();
    tokens.rotate();
    const keyring = JSON.parse(JSON.stringify(disk)) as { keys: Array<{ kid: string; publicKey: string; verifyUntil?: string }> };
    const until = Date.parse(keyring.keys.find((k) => k.kid === parent.kid)!.verifyUntil!);
    const x = createPublicKey(parent.publicKey).export({ format: 'jwk' }).x!;
    assert.equal(new TrustedKeys([x]).learn(keyring as never, until - 1000).size, 2, 'introduced while the old key verifies');
    assert.deepEqual([...new TrustedKeys([x]).learn(keyring as never, until + 1000).keys()], [parent.kid], 'an expired key introduces nothing');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('replica hops: a key holder cannot pass as a sibling, its budget is its id\'s whatever client it names, full snapshots are limited', { skip, timeout: 60_000 }, async (t) => {
  const d = await deployment(t, { pepRateLimit: 1000 });
  const hop = (key: Buffer, node: string, path: string, client = 'pep', method = 'GET', raw = Buffer.alloc(0)): Record<string, string> =>
    ({ [REPLICA_HOP_HEADER]: signHop(hopKeyOf(key), method, path, raw, client, node) });
  const state = (key: Buffer, node: string): Promise<Answer> => {
    const path = `/x/v1/replica/state?wait=0&nonce=${randomBytes(18).toString('base64url')}`;
    return call(d.leader.url, path, 'GET', undefined, hop(key, node, path));
  };
  const R3 = replicaKeyOf(K2, 'r3');
  assert.equal((await state(R2, 'r2')).status, 200);
  assert.equal((await state(R2, 'r3')).status, 401, 'r2\'s key does not sign for r3');
  assert.equal((await state(K2, 'r2')).status, 401, 'the master is not a replica key');
  const path = `/x/v1/replica/audit?nonce=${randomBytes(18).toString('base64url')}`;
  const raw = Buffer.from(JSON.stringify({ base: { seq: 0, hash: '0'.repeat(64) }, rows: [] }));
  assert.equal((await call(d.leader.url, path, 'POST', JSON.parse(raw.toString()), hop(R2, 'r3', path, 'pep', 'POST', raw))).status, 401, 'nor reads r3\'s head');
  for (let i = 0; i < 6; i++) assert.equal((await state(R3, 'r3')).status, 200);
  assert.equal((await state(R3, 'r3')).status, 429, 'full snapshots: a burst, then a few a minute');
  // the hop's client is the replica's choice: the replica's own bucket still empties (1000 a minute here)
  let limited = 0;
  for (let batch = 0; batch < 21 && !limited; batch++) {
    const answers = await Promise.all(Array.from({ length: 50 }, (_, i) => call(d.leader.url, '/healthz', 'GET', undefined, hop(K1, 'r1', '/healthz', `client-${batch}-${i}`))));
    limited = answers.filter((a) => a.status === 429).length;
  }
  assert.ok(limited > 0, 'a replica cannot spread past its budget by naming new clients');
  assert.equal((await state(K1, 'r1')).status, 200, 'its own feed has a separate budget: forwarded traffic cannot leave it stale');
});

test('feed reads take one snapshot at a time on the shared connection, and a long poll that times out leaves no waiter', { skip, timeout: 60_000 }, async (t) => {
  closeLater(t, async () => undefined); // the ledger closes before the database is dropped
  const { url } = await throwawayDatabase(t, 'replica_feed');
  const { PgLedger } = await import('../src/postgres.ts');
  const ledger = await PgLedger.open(url, () => undefined, { checkpointKey: randomBytes(32) });
  closeLater(t, () => ledger.close());
  await ledger.replicaFeed();
  const feed = (ledger as unknown as { side: Map<string, { query: (...args: unknown[]) => Promise<unknown> }> }).side.get('feed')!;
  const original = feed.query.bind(feed);
  const statements: string[] = [];
  feed.query = async (...args: unknown[]) => {
    const text = typeof args[0] === 'string' ? args[0] : (args[0] as { text: string }).text;
    statements.push(text.startsWith('BEGIN') ? 'BEGIN' : text === 'COMMIT' || text === 'ROLLBACK' ? 'END' : 'Q');
    await new Promise((done) => setImmediate(done)); // give a concurrent poll every chance to interleave
    return original(...args);
  };
  const generation = ledger.generation;
  const answers = await Promise.all(Array.from({ length: 8 }, (_, i) => ledger.replicaFeed(i % 2 ? generation : undefined)));
  assert.ok(answers.every((a) => a.version === generation.version && a.records === generation.records));
  const opened = statements.reduce((depth, s) => { if (s === 'BEGIN') { assert.equal(depth, 0, statements.join(' ')); return 1; } if (s === 'END') return 0; assert.equal(depth, 1, 'every read inside its own transaction'); return depth; }, 0);
  assert.equal(opened, 0);
  assert.equal(statements.filter((s) => s === 'BEGIN').length, 8);
  await Promise.all([ledger.changed(20), ledger.changed(30)]);
  assert.equal(ledger.waiting, 0, 'timed-out polls removed their waiters');
});
