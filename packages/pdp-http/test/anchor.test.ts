import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { canonical } from '../../core/src/index.ts';
import { createServer } from '../src/server.ts';
import { GENESIS, sha256, verifyChain, type AuditRecord } from '../src/audit.ts';
import { loadAnchorFile, readTimestampReply, timestampQuery, verifyToken } from '../src/anchor.ts';
import { evaluation, FIXED } from './helpers.ts';
import { hasOpensslTs, startTsa } from './tsa.ts';

const skip = hasOpensslTs ? false : 'openssl with the ts command is not available';

async function node(t: { after: (fn: () => unknown) => void }, dataDir: string, tsa: string, caFile?: string) {
  const server = createServer({ port: 0, dataDir, clock: `fixed:${FIXED}`, tsa: { url: tsa, caFile } });
  await server.listen();
  t.after(() => server.close());
  const credentials = JSON.parse(readFileSync(resolve(dataDir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string; passwords: Record<string, string> };
  const decide = async (): Promise<void> => {
    const res = await fetch(`${server.url}/access/v1/evaluation`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${credentials.pepApiKey}` }, body: JSON.stringify(evaluation()) });
    assert.equal(res.status, 200);
  };
  const login = await fetch(`${server.url}/admin/v1/session`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'sam', password: credentials.passwords.sam }) });
  const cookie = String(login.headers.get('set-cookie')).split(';')[0]!;
  const get = async (path: string): Promise<Record<string, unknown>> => (await (await fetch(`${server.url}${path}`, { headers: { cookie } })).json()) as Record<string, unknown>;
  return { server, decide, get };
}
/** A full rewrite: every hash recomputed, so the chain alone still verifies. */
function rewrite(rows: AuditRecord[]): string {
  let prev = GENESIS;
  return rows.map((row) => {
    // sam's login row: its actor is stored as a pseudonym, so the forgery replaces whatever is there
    const { hash: dropped, ...rest } = { ...row, actor: row.action === 'login' ? 'mallory' : row.actor, prevHash: prev };
    void dropped;
    prev = sha256(prev + canonical(rest));
    return JSON.stringify({ ...rest, hash: prev });
  }).join('\n') + '\n';
}

test('the audit head is timestamped by the authority, verifiable offline with openssl, and only when it moved', { skip }, async (t) => {
  const tsa = await startTsa(t);
  const dir = mkdtempSync('/tmp/pdp-anchor-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const n = await node(t, dir, tsa.url);
  await n.decide();
  await n.server.anchor();
  await n.server.anchor(); // head unchanged: nothing sent
  assert.equal(tsa.requests, 1);
  const anchors = await n.get('/admin/v1/audit/anchors');
  const items = anchors.items as Array<{ seq: number; hash: string; token: string; tsa: string }>;
  assert.equal(items.length, 1); assert.equal(anchors.lastError, null); assert.equal(items[0]!.tsa, tsa.url);
  const verified = await n.get('/admin/v1/audit/verify');
  assert.equal(verified.verified, true);
  const rows = readFileSync(resolve(dir, 'audit.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l) as AuditRecord);
  assert.equal(items[0]!.hash, rows[items[0]!.seq - 1]!.hash);
  assert.match(tsa.verify(items[0]!.token, items[0]!.hash), /Verification: OK/);
  await n.decide();
  await Promise.all([n.server.anchor(), n.server.anchor()]);
  assert.equal(tsa.requests, 2, 'concurrent runs anchor a head once');
});

test('with TSA_CA_FILE, a token not signed under that CA is not kept', { skip }, async (t) => {
  const tsa = await startTsa(t); const other = await startTsa(t);
  const dir = mkdtempSync('/tmp/pdp-anchor-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const n = await node(t, dir, tsa.url, resolve(other.dir, 'ca.crt'));
  await n.decide();
  await n.server.anchor();
  const anchors = await n.get('/admin/v1/audit/anchors');
  assert.equal((anchors.items as unknown[]).length, 0);
  assert.match(String(anchors.lastError), /does not verify/);
  const good = await node(t, mkdtempSync('/tmp/pdp-anchor-'), tsa.url, resolve(tsa.dir, 'ca.crt'));
  await good.decide(); await good.server.anchor();
  assert.equal(((await good.get('/admin/v1/audit/anchors')).items as unknown[]).length, 1);
});

test('a rewritten or truncated audit log no longer starts once it has been anchored', { skip }, async (t) => {
  const tsa = await startTsa(t);
  const dir = mkdtempSync('/tmp/pdp-anchor-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const n = await node(t, dir, tsa.url);
  await n.decide(); await n.decide();
  await n.server.anchor();
  await n.server.close();
  const file = resolve(dir, 'audit.jsonl');
  const original = readFileSync(file, 'utf8');
  const rows = original.trim().split('\n').map((l) => JSON.parse(l) as AuditRecord);
  const forged = rewrite(rows);
  assert.equal(verifyChain(forged.trim().split('\n').map((l) => JSON.parse(l))).verified, true, 'the forgery is a valid chain on its own');
  assert.equal(verifyChain(forged.trim().split('\n').map((l) => JSON.parse(l)), loadAnchorFile(resolve(dir, 'anchors.jsonl'))).verified, false);
  writeFileSync(file, forged);
  assert.throws(() => createServer({ port: 0, dataDir: dir, clock: `fixed:${FIXED}` }), /Audit integrity failure/);
  writeFileSync(file, original.split('\n').slice(0, rows.length - 1).join('\n') + '\n');
  assert.throws(() => createServer({ port: 0, dataDir: dir, clock: `fixed:${FIXED}` }), /Audit integrity failure/);
  writeFileSync(file, original);
  const back = createServer({ port: 0, dataDir: dir, clock: `fixed:${FIXED}` });
  await back.close();
});

test('a timestamp reply is accepted only for this hash and nonce, and only when granted', { skip }, async (t) => {
  const tsa = await startTsa(t);
  const hash = sha256('head'); const nonce = Buffer.from('0102030405060708', 'hex');
  const reply = tsa.reply(timestampQuery(hash, nonce));
  assert.match(readTimestampReply(reply, hash, nonce).genTime, /^\d{4}-\d{2}-\d{2}T/);
  assert.throws(() => readTimestampReply(reply, sha256('other'), nonce), /another hash/);
  assert.throws(() => readTimestampReply(reply, hash, Buffer.from('0102030405060709', 'hex')), /nonce/);
  assert.throws(() => readTimestampReply(Buffer.from('3005300302010 2'.replace(' ', ''), 'hex'), hash, nonce), /refused/);
  assert.throws(() => readTimestampReply(reply.subarray(0, 40), hash, nonce));
});

test('the token reaches openssl as a regular file: /dev/stdin is a socket for a Node child on Linux and fopen fails', (t) => {
  const dir = mkdtempSync('/tmp/pdp-fake-openssl-');
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const fake = resolve(dir, 'openssl');
  // prints OK only when the argument after -in is a regular file holding the token
  writeFileSync(fake, '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = -in ]; then f=$2; fi; shift; done\n[ -f "$f" ] && [ "$(cat "$f")" = token ] && echo "Verification: OK"\n', { mode: 0o700 });
  assert.doesNotThrow(() => verifyToken(Buffer.from('token'), 'ab'.repeat(32), '/ca.pem', fake));
  assert.throws(() => verifyToken(Buffer.from('other'), 'ab'.repeat(32), '/ca.pem', fake), /does not verify/);
});
