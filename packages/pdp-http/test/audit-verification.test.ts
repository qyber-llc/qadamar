// The customer's offline audit check: the signed verification manifest (GET /admin/v1/audit/verification) and the
// verifier a tenant's auditor runs on its own machine (scripts/audit/verify-export.ts).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { canonical } from '../../core/src/index.ts';
import { admin } from '../src/admin/index.ts';
import { pdp } from '../src/pdp.ts';
import { requestAnchor } from '../src/anchor.ts';
import { GENESIS, sha256, type AuditRecord, type Head } from '../src/audit.ts';
import { pullAudit } from '../src/siem.ts';
import { HttpError } from '../src/http.ts';
import { Tokens, type SigningKeyDisk } from '../src/tokens.ts';
import { verdict, verifyEvidence, type Evidence, type Manifest } from '../../../scripts/audit/verify-export.ts';
import { hasOpensslTs, startTsa } from './tsa.ts';
import { evaluation, fixture, users, type Fixture } from './helpers.ts';

const status = (code: number) => (e: unknown): boolean => e instanceof HttpError && e.status === code;
type Signed = { manifest: Manifest & Record<string, unknown>; signature: string };
const exportManifest = (f: Fixture, user = users.sam, query = ''): Promise<Signed> =>
  admin(f.rt, user, 'GET', new URL(`http://local/admin/v1/audit/verification${query}`), {}).value as Promise<Signed>;
/** `heads`: the manifest's, passed as `until` so the export stops at them (rows after a head are not signed). */
async function rows(f: Fixture, heads?: Record<string, Head>): Promise<AuditRecord[]> {
  const until = heads ? `&until=${Object.entries(heads).map(([node, head]) => `${node}:${head.seq}`).join(',')}` : '';
  const page = await pullAudit(f.rt.audit, users.sam, new URL(`http://local/admin/v1/audit/export?limit=1000${until}`));
  return page.body.trim().split('\n').map((line) => JSON.parse(line) as AuditRecord);
}
function decide(f: Fixture, n: number): void { for (let i = 0; i < n; i++) pdp(f.rt, '/access/v1/evaluation', evaluation()); }

test('the verification manifest is signed, audited, and lets an auditor check the exported rows offline', async (t) => {
  const f = fixture(t); decide(f, 5);
  const anchored = f.rt.audit.records().at(-1)!;
  f.rt.audit.anchors.push({ seq: anchored.seq, hash: anchored.hash, tsa: 'https://tsa.example', genTime: anchored.ts, token: 'dG9rZW4' });
  const { manifest, signature } = await exportManifest(f);
  assert.equal(manifest.format, 'gate-audit-verification/1');
  assert.equal(f.rt.tokens.verifyDetached(manifest, signature), true);
  assert.deepEqual(manifest.heads, { 0: { seq: anchored.seq, hash: anchored.hash } }, 'the head before the export row');
  assert.deepEqual(manifest.anchors, [{ seq: anchored.seq, hash: anchored.hash, tsa: 'https://tsa.example', genTime: anchored.ts, tokenSha256: sha256('dG9rZW4') }]);
  const audited = f.rt.audit.records().at(-1)!;
  assert.deepEqual([audited.type, audited.actor, audited.action, audited.details?.manifestSha256], ['security', 'sam', 'audit_verification_export', sha256(canonical(manifest))]);

  const evidence: Evidence = { rows: await rows(f, manifest.heads), manifest, signature, jwks: f.rt.tokens.jwks() as Evidence['jwks'],
    anchors: { items: f.rt.audit.anchors } };
  assert.equal(evidence.rows.at(-1)!.seq, anchored.seq, 'until stops the export at the signed head');
  const report = verifyEvidence(evidence);
  assert.deepEqual([report.ok, report.problems, report.chains, report.anchorsChecked, report.tokens.length], [true, [], { 0: anchored.seq }, 1, 1]);

  // what an auditor must catch
  const edited = evidence.rows.map((r) => r.seq === 2 ? { ...r, effect: r.effect === 'allow' ? 'deny' as const : 'allow' as const } : r);
  assert.deepEqual(verifyEvidence({ ...evidence, rows: edited }).problems, ['chain 0 breaks at seq 2']);
  assert.ok(verifyEvidence({ ...evidence, rows: evidence.rows.slice(0, 3) }).problems.includes(`head 0:${anchored.seq} is not in the exported rows`), 'a truncated export');
  assert.ok(verifyEvidence({ ...evidence, manifest: { ...manifest, heads: { 0: { seq: 1, hash: GENESIS } } } }).problems.includes('manifest signature does not verify against the JWKS'));
  assert.ok(verifyEvidence({ ...evidence, anchors: { items: [{ ...f.rt.audit.anchors[0]!, token: 'b3RoZXI' }] } }).problems.includes(`anchor ${anchored.seq}: token missing or not the one the manifest signed`));
  assert.ok(verifyEvidence({ ...evidence, rows: evidence.rows.map((r) => ({ ...r, pseudonymised: true })) }).problems[0]!.startsWith('pseudonymised rows'));
  assert.ok(verifyEvidence({ ...evidence, jwks: { keys: [] } }).problems.includes('manifest signature does not verify against the JWKS'));
  // rows after the signed head prove nothing: the export row the manifest call wrote, or events invented after it
  const tail = `chain 0: 1 row(s) after the signed head ${anchored.seq} (unauthenticated tail: export with until=<the manifest's heads>)`;
  assert.deepEqual(verifyEvidence({ ...evidence, rows: await rows(f) }).problems, [tail]);
  const last = evidence.rows.at(-1)!;
  const body = { seq: last.seq + 1, ts: last.ts, type: 'decision' as const, actor: 'pep', action: 'evaluate', effect: 'allow' as const, prevHash: last.hash };
  const invented = { ...body, hash: sha256(last.hash + canonical(body)) };
  const appended = verifyEvidence({ ...evidence, rows: [...evidence.rows, invented], pins: f.rt.tokens.jwks() as Evidence['jwks'] });
  assert.deepEqual([appended.ok, appended.problems, appended.chains], [false, [tail], { 0: anchored.seq }]);
  assert.equal(verdict(appended, 1).result, 'failed', 'a genuine pinned manifest does not certify rows past its heads');
});

test('only security officers and auditors export it, without parameters', async (t) => {
  const f = fixture(t);
  for (const user of [users.amira, users.omar, users.ruth]) await assert.rejects(exportManifest(f, user), status(403));
  await assert.rejects(exportManifest(f, users.lina, '?x=1'), status(400));
  assert.equal((await exportManifest(f, users.lina)).manifest.generatedBy, 'lina');
});

/** A chain of `n` rows of `node`, continuing `from` (a sealed head, or the genesis). */
function chain(node: string, n: number, from: Head = { seq: 0, hash: GENESIS }): AuditRecord[] {
  const out: AuditRecord[] = []; let prev = from.hash;
  for (let seq = from.seq + 1; seq <= from.seq + n; seq++) {
    const body = { node, seq, ts: '2026-11-08T10:00:00Z', type: 'decision' as const, actor: 'pep:a', action: 'evaluate', prevHash: prev };
    prev = sha256(prev + canonical(body)); out.push({ ...body, hash: prev });
  }
  return out;
}

test('several chains, a multi-head anchor and a sealed retention prefix', async (t) => {
  const f = fixture(t);
  const sealedHead = { seq: 2, hash: sha256('removed prefix head') };
  const a = chain('a', 3, sealedHead); const b = chain('b', 2);
  const head = (r: AuditRecord): Head => ({ seq: r.seq, hash: r.hash });
  const heads = { a: head(a.at(-1)!), b: head(b.at(-1)!) };
  const segment = { version: 1 as const, node: 'a', firstSeq: 1, lastSeq: 2, removed: 2, prefixHash: sha256('x'), head: sealedHead, sealedAt: '2026-11-08T09:00:00Z' };
  const anchor = (seq: number, at: Record<string, Head>) => ({ seq, heads: at, hash: sha256(canonical(at)), genTime: '2026-11-08T10:01:00Z', tokenSha256: sha256('t') });
  const multi = anchor(7, heads);
  // the sealed head itself, and an older head of the removed prefix (covered by the seal: nothing left to compare)
  const manifest = { format: 'gate-audit-verification/1', heads, segments: [segment],
    anchors: [multi, anchor(2, { a: sealedHead }), anchor(1, { a: { seq: 1, hash: sha256('removed row') } })] } as Manifest;
  const evidence: Evidence = { rows: [...a, ...b], manifest, signature: f.rt.tokens.detached(manifest), jwks: f.rt.tokens.jwks() as Evidence['jwks'] };
  assert.deepEqual(verifyEvidence(evidence).problems, [], 'a node, the sealed head, an anchor inside the sealed prefix');
  // a forged chain, self-consistent from the genesis, for a node the signed manifest does not list
  assert.deepEqual(verifyEvidence({ ...evidence, rows: [...a, ...b, ...chain('c', 2)] }).problems, ["chain c is not among the manifest's heads"]);
  const forged = { ...manifest, anchors: [{ ...multi, heads: { ...heads, b: { seq: 1, hash: b[0]!.hash } } }] };
  assert.deepEqual(verifyEvidence({ ...evidence, manifest: forged, signature: f.rt.tokens.detached(forged) }).problems, ['anchor 7: heads do not hash to the timestamped value']);
  const unsealed = { ...manifest, segments: [] };
  assert.deepEqual(verifyEvidence({ ...evidence, manifest: unsealed, signature: f.rt.tokens.detached(unsealed) }).problems, ['chain a breaks at seq 1', 'anchor 2: head a:2 differs from the rows', 'anchor 1: head a:1 differs from the rows'],
    'without its seal the chain cannot start at seq 3');
});

test('consistent evidence is only self-consistent unless a TSA token or a signing key held out of band anchors it', async (t) => {
  const f = fixture(t); decide(f, 2);
  const pinnedEarlier = f.rt.tokens.jwks() as Evidence['jwks']; // kept by the auditor at onboarding
  const before = f.rt.tokens.activePublic();
  const evidence = async (): Promise<Evidence> => {
    const { manifest, signature } = await exportManifest(f);
    return { rows: await rows(f, manifest.heads), manifest, signature, jwks: f.rt.tokens.jwks() as Evidence['jwks'] };
  };
  const served = await evidence();
  const plain = verifyEvidence(served);
  assert.deepEqual([plain.problems, plain.pinned], [[], false]);
  assert.deepEqual(verdict(plain, 0), { ok: false, result: 'self-consistent only (not anchored)', anchoredBy: [] });
  assert.deepEqual(verdict(plain, 1), { ok: true, result: 'ok', anchoredBy: ['tsa'] });
  const pinned = verifyEvidence({ ...served, pins: pinnedEarlier });
  assert.deepEqual(verdict(pinned, 0), { ok: true, result: 'ok', anchoredBy: ['pinned signing key'] });
  // a server that serves its own JWKS proves nothing against a pin it does not hold
  assert.equal(verifyEvidence({ ...served, pins: { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'A'.repeat(43) }] } }).pinned, false);
  // after a rotation the pinned key no longer signs: its introduction of the new key, in the public keyring, links them
  f.rt.tokens.rotate();
  const rotated = await evidence();
  assert.equal(verifyEvidence({ ...rotated, pins: pinnedEarlier }).pinned, false);
  const keyring = { keys: [before, f.rt.tokens.activePublic()] };
  assert.equal(verifyEvidence({ ...rotated, pins: pinnedEarlier, keyring }).pinned, true);
  const { introducedBy: _dropped, ...unintroduced } = f.rt.tokens.activePublic();
  assert.equal(verifyEvidence({ ...rotated, pins: pinnedEarlier, keyring: { keys: [before, unintroduced] } }).pinned, false);
  assert.deepEqual(verdict({ ...pinned, problems: ['x'] }, 1).result, 'failed');

  const dir = mkdtempSync('/tmp/pdp-verify-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'audit.ndjson'), rotated.rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
  writeFileSync(join(dir, 'verification.json'), JSON.stringify({ manifest: rotated.manifest, signature: rotated.signature }));
  writeFileSync(join(dir, 'jwks.json'), JSON.stringify(rotated.jwks));
  writeFileSync(join(dir, 'pin.json'), JSON.stringify(pinnedEarlier));
  writeFileSync(join(dir, 'keyring.json'), JSON.stringify(keyring));
  const run = (...extra: string[]) => spawnSync(process.execPath, [resolve(import.meta.dirname, '../../../scripts/audit/verify-export.ts'), '--rows', join(dir, 'audit.ndjson'),
    '--manifest', join(dir, 'verification.json'), '--jwks', join(dir, 'jwks.json'), ...extra], { encoding: 'utf8' });
  const alone = run();
  assert.equal(alone.status, 3, alone.stdout + alone.stderr);
  assert.deepEqual([JSON.parse(alone.stdout).ok, JSON.parse(alone.stdout).result], [false, 'self-consistent only (not anchored)']);
  const anchored = run('--pin', join(dir, 'pin.json'), '--keyring', join(dir, 'keyring.json'));
  assert.equal(anchored.status, 0, anchored.stdout + anchored.stderr);
  assert.deepEqual(JSON.parse(anchored.stdout).anchoredBy, ['pinned signing key']);
  assert.equal(run('--keyring', join(dir, 'keyring.json')).status, 2, 'a keyring without a pin anchors nothing');
});

test('a manifest signed before a rotation verifies through the keyring after its key has left the JWKS', (t) => {
  const dir = mkdtempSync('/tmp/pdp-verify-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  let now = '2026-11-08T10:00:00.000Z';
  const tokens = new Tokens(dir, () => now);
  const rows = chain('a', 2);
  const manifest = { format: 'gate-audit-verification/1', heads: { a: { seq: 2, hash: rows[1]!.hash } }, segments: [], anchors: [] } as Manifest;
  const signature = tokens.detached(manifest); // by the key the auditor pinned at onboarding
  const pin = tokens.jwks() as Evidence['jwks'];
  const signer = tokens.activePublic().kid;
  tokens.rotate();
  now = '2026-11-09T10:00:00.000Z'; // past both of the old key's windows (decision tokens 300 s, session tokens 1 h)
  const jwks = tokens.jwks() as Evidence['jwks'];
  assert.ok(!jwks.keys.some((k) => (k as { kid?: string }).kid === signer), 'the retired key has left the JWKS of the day');
  const served: Evidence = { rows, manifest, signature, jwks };
  assert.deepEqual(verifyEvidence({ ...served, pins: pin }).problems, ['manifest signature does not verify against the JWKS'], 'the JWKS alone no longer names the signer');
  // the stored keyring keeps the retired public key: its public half, as replicas and auditors receive it
  const stored = JSON.parse(readFileSync(join(dir, 'signing-keys.json'), 'utf8')) as SigningKeyDisk;
  const keyring: SigningKeyDisk = { keys: stored.keys.map(({ privateKey: _private, ...key }) => key) };
  assert.ok(keyring.keys.some((k) => k.kid === signer));
  const report = verifyEvidence({ ...served, pins: pin, keyring });
  assert.deepEqual([report.problems, report.pinned], [[], true]);
  assert.deepEqual(verdict(report, 0).anchoredBy, ['pinned signing key']);
  // without the pin the keyring only restores consistency, never the anchor
  assert.deepEqual(verdict(verifyEvidence({ ...served, keyring }), 0).result, 'self-consistent only (not anchored)');
  // a keyring entry under the signer's kid with another key does not verify the signature
  const other = { ...keyring.keys.find((k) => k.kid === signer)!, publicKey: generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString() };
  assert.deepEqual(verifyEvidence({ ...served, pins: pin, keyring: { keys: [other, ...keyring.keys.filter((k) => k.kid !== signer)] } }).problems, ['manifest signature does not verify against the JWKS']);
  writeFileSync(join(dir, 'audit.ndjson'), rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
  writeFileSync(join(dir, 'verification.json'), JSON.stringify({ manifest, signature }));
  writeFileSync(join(dir, 'jwks.json'), JSON.stringify(jwks));
  writeFileSync(join(dir, 'pin.json'), JSON.stringify(pin));
  writeFileSync(join(dir, 'keyring.json'), JSON.stringify(keyring));
  const cli = spawnSync(process.execPath, [resolve(import.meta.dirname, '../../../scripts/audit/verify-export.ts'), '--rows', join(dir, 'audit.ndjson'),
    '--manifest', join(dir, 'verification.json'), '--jwks', join(dir, 'jwks.json'), '--pin', join(dir, 'pin.json'), '--keyring', join(dir, 'keyring.json')], { encoding: 'utf8' });
  assert.equal(cli.status, 0, cli.stdout + cli.stderr);
  assert.deepEqual(JSON.parse(cli.stdout).anchoredBy, ['pinned signing key']);
});

test('the command line verifies real RFC 3161 tokens with openssl', { skip: hasOpensslTs ? false : 'openssl ts unavailable' }, async (t) => {
  const f = fixture(t); decide(f, 3);
  const tsa = await startTsa(t);
  f.rt.audit.anchors.push(await requestAnchor(tsa.url, f.rt.audit.tip(), join(tsa.dir, 'ca.crt')));
  const signed = await exportManifest(f);
  const dir = mkdtempSync('/tmp/pdp-verify-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'audit.ndjson'), (await rows(f, signed.manifest.heads)).map((r) => JSON.stringify(r)).join('\n') + '\n');
  writeFileSync(join(dir, 'verification.json'), JSON.stringify(signed));
  writeFileSync(join(dir, 'jwks.json'), JSON.stringify(f.rt.tokens.jwks()));
  writeFileSync(join(dir, 'anchors.json'), JSON.stringify({ items: f.rt.audit.anchors }));
  const run = (...extra: string[]) => spawnSync(process.execPath, [resolve(import.meta.dirname, '../../../scripts/audit/verify-export.ts'), '--rows', join(dir, 'audit.ndjson'),
    '--manifest', join(dir, 'verification.json'), '--jwks', join(dir, 'jwks.json'), '--anchors', join(dir, 'anchors.json'), ...extra], { encoding: 'utf8' });
  const ok = run('--tsa-ca', join(tsa.dir, 'ca.crt'));
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.deepEqual(JSON.parse(ok.stdout), { ok: true, result: 'ok', anchoredBy: ['tsa'], problems: [], chains: { 0: signed.manifest.heads[0]!.seq }, anchorsChecked: 1, tokensChecked: 1 });
  const other = await startTsa(t); // a CA that did not sign the token
  const refused = run('--tsa-ca', join(other.dir, 'ca.crt'));
  assert.equal(refused.status, 1);
  assert.deepEqual(JSON.parse(refused.stdout).problems, [`anchor ${f.rt.audit.anchors[0]!.seq}: openssl ts -verify refused the token`]);
  assert.equal(spawnSync(process.execPath, [resolve(import.meta.dirname, '../../../scripts/audit/verify-export.ts')], { encoding: 'utf8' }).status, 2, 'usage');
});
