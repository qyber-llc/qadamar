// SIGNING_KEY_SEAL rotation: SIGNING_KEY_SEAL_PREVIOUS opens what the old key sealed, the start re-seals it under the new
// key with one audit row, after which the old key alone is refused and the new one alone suffices. A key that opens
// nothing stops the start without changing a byte.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { resealAtRest, sealedUnderPrevious } from '../src/seal-rotation.ts';
import { checkpointBody, parseCheckpoint } from '../src/postgres-chains.ts';
import { CHECKPOINT_KEY_LABEL, derivedKey } from '../src/tokens.ts';
import { seal, unseal, type SigningKeyDisk } from '../src/tokens.ts';
import type { Credentials } from '../src/auth.ts';
import type { Backing } from '../src/store.ts';
import { createServer, type PdpServer, type ServerOptions } from '../src/server.ts';
import { fromBase32, hotp } from '../src/totp.ts';
import { evaluation } from './helpers.ts';
import { skip, throwawayDatabase } from './pg-database.ts';

const key = (): Buffer => randomBytes(32);
const text = (k: Buffer): string => k.toString('base64url');
function memory<T>(value: T): Backing<T> & { saves: number; value: T } {
  const m = { saves: 0, value, load: (): T => structuredClone(m.value), save: (v: T): void => { m.saves++; m.value = structuredClone(v); } };
  return m;
}
const atRest = (k: Buffer): { keyring: ReturnType<typeof memory<SigningKeyDisk>>; credentials: ReturnType<typeof memory<Credentials>> } => ({
  keyring: memory<SigningKeyDisk>({ keys: [{ kid: 'k1', created: 'x', publicKey: 'pub', privateKey: seal('PRIVATE-1', k, 'k1') }, { kid: 'k0', created: 'x', publicKey: 'pub', verifyUntil: 'x' }] }),
  credentials: memory<Credentials>({ pepCredentials: [], users: [
    { id: 'amira', name: 'amira', roles: [], hash: 'h', totp: { secret: seal('TOTPSECRET', k, 'totp:amira'), active: true } },
    { id: 'omar', name: 'omar', roles: [], hash: 'h' }] }),
});

test('resealAtRest re-seals under the new key what only the previous one opens, and refuses without saving when neither does', () => {
  const [old, next, stranger] = [key(), key(), key()];
  const store = atRest(old);
  const before = JSON.stringify([store.keyring.value, store.credentials.value]);
  assert.throws(() => resealAtRest(store.keyring, store.credentials, next), /2 sealed value\(s\) at rest do not open under SIGNING_KEY_SEAL \(signing key k1, TOTP secret of amira\)\. Nothing was changed/);
  assert.throws(() => resealAtRest(store.keyring, store.credentials, next, stranger), /do not open under SIGNING_KEY_SEAL or SIGNING_KEY_SEAL_PREVIOUS/);
  assert.equal(JSON.stringify([store.keyring.value, store.credentials.value]), before);
  assert.equal(store.keyring.saves + store.credentials.saves, 0, 'a refusal saves nothing');

  assert.deepEqual(resealAtRest(store.keyring, store.credentials, next, old), { signingKeys: 1, totpSecrets: 1 });
  const privateKey = store.keyring.value.keys[0]!.privateKey!;
  const secret = store.credentials.value.users[0]!.totp!.secret;
  assert.equal(unseal(privateKey, next, 'k1'), 'PRIVATE-1');
  assert.equal(unseal(secret, next, 'totp:amira'), 'TOTPSECRET');
  assert.throws(() => unseal(privateKey, old, 'k1'), 'the old key no longer opens anything');
  assert.deepEqual(store.keyring.value.keys[1], { kid: 'k0', created: 'x', publicKey: 'pub', verifyUntil: 'x' }, 'public-only keys are kept as they are');

  assert.deepEqual(resealAtRest(store.keyring, store.credentials, next), { signingKeys: 0, totpSecrets: 0 }, 'the new key alone suffices');
  assert.equal(store.keyring.saves + store.credentials.saves, 2, 'nothing more to write');
});

test('SIGNING_KEY_SEAL_PREVIOUS must come with a different SIGNING_KEY_SEAL', () => {
  const k = text(key());
  assert.throws(() => createServer({ signingKeySealPrevious: k }), /SIGNING_KEY_SEAL_PREVIOUS needs a different SIGNING_KEY_SEAL/);
  assert.throws(() => createServer({ signingKeySeal: k, signingKeySealPrevious: k }), /needs a different SIGNING_KEY_SEAL/);
  assert.throws(() => createServer({ signingKeySeal: k, signingKeySealPrevious: 'short' }), /SIGNING_KEY_SEAL_PREVIOUS must be 32 bytes/);
});

interface Snapshot { (): Promise<string> }
/** Starts the node, enrols TOTP for amira, decides once; then rotates, checks refusals, and signs in with TOTP under the
 *  new key alone. `snapshot` reads what is at rest (files or rows), to prove a refusal changed nothing. */
type Started = { k1: string; k2: string; start: (seals: Pick<ServerOptions, 'signingKeySeal' | 'signingKeySealPrevious'>) => Promise<PdpServer> };
async function rotation(t: test.TestContext, base: ServerOptions, dir: string, snapshot: Snapshot, audited: () => Promise<Array<Record<string, unknown>>>): Promise<Started> {
  const [k1, k2, wrong, wrong2] = [key(), key(), key(), key()].map(text) as [string, string, string, string];
  const start = async (seals: Pick<ServerOptions, 'signingKeySeal' | 'signingKeySealPrevious'>): Promise<PdpServer> => {
    const server = createServer({ ...base, ...seals }); t.after(() => server.close());
    await server.listen();
    return server;
  };
  const call = async (server: PdpServer, path: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}): Promise<{ status: number; data: Record<string, unknown>; cookie: string }> => {
    const res = await fetch(`${server.url}${path}`, { method, headers: { 'content-type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const raw = await res.text();
    return { status: res.status, data: raw ? JSON.parse(raw) as Record<string, unknown> : {}, cookie: String(res.headers.get('set-cookie')).split(';')[0]! };
  };
  const a = await start({ signingKeySeal: k1 });
  const { passwords, pepApiKey } = JSON.parse(readFileSync(resolve(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { passwords: Record<'amira' | 'sam', string>; pepApiKey: string };
  const signIn = await call(a, '/admin/v1/session', 'POST', { username: 'amira', password: passwords.amira });
  const amira = { cookie: signIn.cookie, 'x-csrf-token': String(signIn.data.csrfToken) };
  const enrol = await call(a, '/admin/v1/session/totp/enrol', 'POST', { password: passwords.amira }, amira);
  const totp = fromBase32(new URL(String(enrol.data.otpauthUri)).searchParams.get('secret')!);
  const step = Math.floor(Date.now() / 30_000);
  assert.equal((await call(a, '/admin/v1/session/totp/activate', 'POST', { code: hotp(totp, step - 1) }, amira)).status, 200);
  const decide = async (server: PdpServer): Promise<number> => (await call(server, '/access/v1/evaluation', 'POST', evaluation(), { authorization: `Bearer ${pepApiKey}` })).status;
  assert.equal(await decide(a), 200);
  const kids = (await call(a, '/.well-known/jwks.json')).data.keys;
  if (base.databaseUrl) {
    // an authenticated audit checkpoint under the old key: the rotation must re-authenticate it, not call it tampering
    const sam = await call(a, '/admin/v1/session', 'POST', { username: 'sam', password: passwords.sam });
    assert.equal((await call(a, '/admin/v1/audit/verify', 'GET', undefined, { cookie: sam.cookie })).data.verified, true);
  }
  await a.close();

  const sealed = await snapshot();
  await assert.rejects(start({ signingKeySeal: wrong }), /do not open under SIGNING_KEY_SEAL \(.*signing key .*TOTP secret of amira\)\. Nothing was changed/);
  await assert.rejects(start({ signingKeySeal: wrong, signingKeySealPrevious: wrong2 }), /do not open under SIGNING_KEY_SEAL or SIGNING_KEY_SEAL_PREVIOUS/);
  assert.equal(await snapshot(), sealed, 'a refused start changes nothing at rest');

  const b = await start({ signingKeySeal: k2, signingKeySealPrevious: k1 });
  assert.equal(await decide(b), 200);
  assert.deepEqual((await call(b, '/.well-known/jwks.json')).data.keys, kids, 'the same signing keys, re-sealed');
  await b.close();
  const rotated = (await audited()).filter((r) => r.action === 'seal_key_rotated');
  assert.equal(rotated.length, 1, 'one audit row for the rotation');
  assert.deepEqual(rotated[0]!.details, { signingKeys: 1, totpSecrets: 1, checkpointRekeyed: Boolean(base.databaseUrl) });
  assert.notEqual(await snapshot(), sealed);

  const c = await start({ signingKeySeal: k2 });
  assert.equal(await decide(c), 200);
  const withTotp = await call(c, '/admin/v1/session', 'POST', { username: 'amira', password: passwords.amira, code: hotp(totp, Math.floor(Date.now() / 30_000) + 1) });
  assert.equal(withTotp.status, 200, 'the re-sealed TOTP secret opens under the new key alone');
  if (base.databaseUrl) {
    // started from the re-authenticated checkpoint: verified at once, the whole chain in the background (fullChain)
    const ready = (await call(c, '/readyz')).data.audit as { verified: boolean; fullChain: boolean };
    assert.equal(ready.verified, true, 'the re-authenticated checkpoint verifies');
    assert.equal(typeof ready.fullChain, 'boolean');
  }
  await c.close();
  const resealed = await snapshot();
  await assert.rejects(start({ signingKeySeal: k1 }), /do not open under SIGNING_KEY_SEAL/, 'the old key alone is no longer enough');
  assert.equal(await snapshot(), resealed);
  return { k1, k2, start };
}

/** Starts with SIGNING_KEY_SEAL_PREVIOUS still set after the rotation: returns what the start warned. */
async function warned(t: test.TestContext, run: () => Promise<PdpServer>): Promise<{ server: PdpServer; warnings: string[] }> {
  const warnings: string[] = [];
  const spy = t.mock.method(console, 'warn', (...args: unknown[]) => { warnings.push(args.map(String).join(' ')); });
  try { return { server: await run(), warnings }; } finally { spy.mock.restore(); }
}

test('files: rotation re-seals the keyring and TOTP secrets, audited; wrong keys are refused without changing a byte', async (t) => {
  const dir = mkdtempSync('/tmp/pdp-seal-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const read = (file: string): string => existsSync(resolve(dir, file)) ? readFileSync(resolve(dir, file), 'utf8') : '';
  const { k1, k2, start } = await rotation(t, { port: 0, dataDir: dir }, dir, async () => read('signing-keys.json') + read('credentials.json'),
    async () => read('audit.jsonl').trim().split('\n').map((line) => JSON.parse(line) as Record<string, unknown>));
  // the previous key left configured after the rotation: every start warns
  const { server, warnings } = await warned(t, () => start({ signingKeySeal: k2, signingKeySealPrevious: k1 }));
  await server.close();
  assert.ok(warnings.some((w) => /SIGNING_KEY_SEAL_PREVIOUS is set but nothing at rest is sealed under it/.test(w)), warnings.join('\n'));
});

test('PostgreSQL: rotation re-seals the shared documents and re-authenticates the audit checkpoint in one transaction', { skip, timeout: 120_000 }, async (t) => {
  const { url, sql } = await throwawayDatabase(t, 'gate_seal');
  const dir = mkdtempSync('/tmp/pdp-seal-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { k1, k2, start } = await rotation(t, { port: 0, dataDir: dir, databaseUrl: url }, dir,
    async () => JSON.stringify((await sql(`SELECT name, body FROM gate_doc WHERE name IN ('signing_keys', 'credentials', 'audit_checkpoint') ORDER BY name`)).rows),
    async () => (await sql('SELECT record FROM gate_audit ORDER BY node, seq')).rows.map((r: { record: string }) => JSON.parse(r.record) as Record<string, unknown>));
  // after the rotation, a checkpoint MAC'd under the previous key (say, by whoever holds the old key) is not trusted
  const stored = JSON.parse((await sql(`SELECT body FROM gate_doc WHERE name = 'audit_checkpoint'`)).rows[0].body) as unknown;
  const current = parseCheckpoint(stored, derivedKey(k2, CHECKPOINT_KEY_LABEL)!);
  assert.ok(current, 'the checkpoint is under the new key');
  await sql(`UPDATE gate_doc SET body = $1 WHERE name = 'audit_checkpoint'`, [JSON.stringify(checkpointBody(derivedKey(k1, CHECKPOINT_KEY_LABEL)!, current))]);
  const { server, warnings } = await warned(t, () => start({ signingKeySeal: k2, signingKeySealPrevious: k1 }));
  const ready = await (await fetch(`${server.url}/readyz`)).json() as { audit: { verified: boolean; fullChain: boolean } };
  assert.deepEqual(ready.audit, { verified: true, fullChain: true }, 'the whole chain was verified before serving');
  await server.close();
  assert.ok(warnings.some((w) => /authenticated only by SIGNING_KEY_SEAL_PREVIOUS .* not trusted; verifying every chain/.test(w)), warnings.join('\n'));
  assert.ok(warnings.some((w) => /SIGNING_KEY_SEAL_PREVIOUS is set but nothing at rest is sealed under it/.test(w)));
  const rotatedRows = (await sql('SELECT record FROM gate_audit ORDER BY node, seq')).rows.filter((r: { record: string }) => r.record.includes('seal_key_rotated'));
  assert.equal(rotatedRows.length, 1, 'no second rotation row');
});

test('sealedUnderPrevious: true only while some sealed value opens under the previous key alone', () => {
  const [old, next] = [key(), key()];
  const store = atRest(old);
  assert.equal(sealedUnderPrevious(store.keyring.value, store.credentials.value, next, old), true);
  assert.equal(store.keyring.saves + store.credentials.saves, 0, 'nothing saved');
  resealAtRest(store.keyring, store.credentials, next, old);
  assert.equal(sealedUnderPrevious(store.keyring.value, store.credentials.value, next, old), false, 'rotation complete');
  assert.equal(sealedUnderPrevious(store.keyring.value, store.credentials.value, key(), old), false, 'opens under neither: the start refuses elsewhere');
  assert.equal(sealedUnderPrevious(undefined, undefined, next, old), false);
});
