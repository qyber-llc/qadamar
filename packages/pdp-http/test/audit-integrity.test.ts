import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { canonical } from '../../core/src/index.ts';
import { Audit, GENESIS, sha256, verifyChain, type AuditRecord } from '../src/audit.ts';
import { FileSubjectIdentities } from '../src/audit-subjects.ts';
import { CHECKPOINT_KEY_LABEL, derivedKey } from '../src/tokens.ts';
import { createServer } from '../src/server.ts';
import { evaluation } from './helpers.ts';

const SEAL = 'a'.repeat(64);
const KEY = derivedKey(SEAL, CHECKPOINT_KEY_LABEL)!;
const NOW = '2026-11-08T10:00:00.000Z';

function rewrite(rows: AuditRecord[]): string {
  let prev = GENESIS;
  return rows.map((row) => {
    const { hash: ignored, ...rest } = { ...row, actor: 'mallory', prevHash: prev };
    void ignored;
    prev = sha256(prev + canonical(rest));
    return JSON.stringify({ ...rest, hash: prev });
  }).join('\n') + '\n';
}

test('file audit migrates to a keyed checkpoint and refuses a valid full-chain forgery or a forged checkpoint', (t) => {
  const dir = mkdtempSync('/tmp/pdp-file-checkpoint-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'audit.jsonl'); const checkpoint = join(dir, 'audit-checkpoint.json');
  let audit = new Audit(file, () => NOW, { checkpointKey: KEY });
  assert.equal(JSON.parse(readFileSync(checkpoint, 'utf8')).seq, 0, 'the first start checkpoints the empty chain');
  audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'alice', effect: 'allow' });
  audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'bob', effect: 'deny' });
  const original = readFileSync(file, 'utf8');
  const forged = rewrite(audit.records());
  assert.equal(verifyChain(forged.trim().split('\n').map((line) => JSON.parse(line))).verified, true);
  writeFileSync(file, forged);
  audit = new Audit(file, () => NOW, { checkpointKey: KEY });
  assert.equal(audit.verify().verified, false);
  assert.throws(() => audit.append({ type: 'session', actor: 'sam', action: 'login' }), /Audit integrity failure/);

  writeFileSync(file, original);
  const body = JSON.parse(readFileSync(checkpoint, 'utf8')) as Record<string, unknown>;
  writeFileSync(checkpoint, JSON.stringify({ ...body, hash: 'f'.repeat(64) }));
  assert.equal(new Audit(file, () => NOW, { checkpointKey: KEY }).verify().verified, false);
  writeFileSync(checkpoint, JSON.stringify(body));
  assert.equal(new Audit(file, () => NOW, { checkpointKey: KEY }).verify().verified, true);
});

test('file retention seals the removed prefix, keeps the remaining chain verifiable across restart, and continues its sequence', (t) => {
  const dir = mkdtempSync('/tmp/pdp-file-retention-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'audit.jsonl'); let clock = Date.parse(NOW);
  const now = () => new Date(clock).toISOString();
  const audit = new Audit(file, now, { checkpointKey: KEY });
  for (const subject of ['alice', 'bob', 'carol']) {
    audit.append({ type: 'decision', actor: 'pep', action: 'read', subject, effect: 'allow' });
    clock += 86_400_000;
  }
  const originalHead = audit.tip();
  const removedHash = sha256(canonical(audit.records().slice(0, 2)));
  const sealedHead = audit.records()[1]!;
  audit.retain(new Date(clock - 86_400_000).toISOString(), { seq: sealedHead.seq, hash: sealedHead.hash, tsa: 'test', genTime: now(), token: 'token' });
  assert.deepEqual(audit.records().map((row) => row.seq), [3, 4], 'the third decision and the retention marker remain');
  assert.equal(audit.records()[0]?.prevHash, audit.segments[0]?.head.hash);
  assert.equal(audit.segments[0]?.removed, 2);
  assert.equal(audit.segments[0]?.prefixHash, removedHash);
  assert.equal(audit.segments[0]?.head.seq, 2);
  assert.equal(audit.segments[0]?.anchor?.hash, sealedHead.hash);
  assert.equal(audit.verify().verified, true);
  assert.equal(audit.tip().seq, originalHead.seq + 1);

  const restarted = new Audit(file, now, { checkpointKey: KEY });
  assert.equal(restarted.verify().verified, true);
  restarted.append({ type: 'session', actor: 'sam', action: 'login' });
  assert.equal(restarted.tip().seq, 5);
  assert.equal(restarted.verify().verified, true);
  assert.equal(restarted.segments.length, 1);
  assert.equal(restarted.records().some((row) => row.subject === 'alice'), false);
  clock += 86_400_000;
  assert.equal(restarted.retain(now()), true, 'a second seal covers every remaining older row');
  assert.equal(restarted.segments.length, 2);
  assert.deepEqual(restarted.records().map((row) => row.seq), [6], 'only the second retention marker remains');
  assert.equal(restarted.verify().verified, true);
  const next = derivedKey(randomBytes(32).toString('base64url'), CHECKPOINT_KEY_LABEL)!;
  const rotating = new Audit(file, now, { checkpointKey: next, previousCheckpointKey: KEY, checkpointRotationInProgress: true });
  assert.equal(rotating.verify().verified, true);
  assert.equal(new Audit(file, now, { checkpointKey: next }).verify().verified, true);
});

test('file retention completes a crash between the segment and audit file replacements', (t) => {
  const dir = mkdtempSync('/tmp/pdp-retention-crash-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'audit.jsonl'); const checkpoint = join(dir, 'audit-checkpoint.json');
  const audit = new Audit(file, () => NOW, { checkpointKey: KEY });
  for (let i = 0; i < 5; i++) audit.append({ type: 'security', actor: 'system', action: `row${i}` });
  copyFileSync(file, `${file}.before`); copyFileSync(checkpoint, `${checkpoint}.before`);
  assert.equal(audit.retain({ seq: 3 }), true);
  copyFileSync(`${file}.before`, file); copyFileSync(`${checkpoint}.before`, checkpoint);
  const restarted = new Audit(file, () => NOW, { checkpointKey: KEY });
  assert.equal(restarted.verify().verified, true);
  assert.deepEqual(restarted.records().map((row) => row.seq), [4, 5]);
  restarted.append({ type: 'security', actor: 'system', action: 'after' });
  assert.equal(restarted.tip().seq, 6);
  assert.equal(restarted.verify().verified, true);
});

test('subject erasure deletes the only id-to-key mapping, leaves a keyed audit event, and does not change the chain', async (t) => {
  const dir = mkdtempSync('/tmp/pdp-file-erasure-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'audit.jsonl'); const mapping = join(dir, 'audit-subjects.json');
  const audit = new Audit(file, () => NOW, { checkpointKey: KEY, subjects: new FileSubjectIdentities(mapping) });
  audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'alice@example.test', effect: 'allow' });
  const row = audit.records()[0]!;
  assert.match(row.subject!, /^ps\.[0-9a-f]{32}$/);
  assert.ok(!readFileSync(file, 'utf8').includes('alice@example.test'));
  const stored = JSON.parse(readFileSync(mapping, 'utf8')) as Array<{ id: string; key: string }>;
  assert.equal(stored[0]?.id, 'alice@example.test');
  assert.equal(audit.subjectPseudonym('alice@example.test'), row.subject);

  const append = audit.append.bind(audit);
  audit.append = () => { throw new Error('Audit storage failed'); };
  await assert.rejects(audit.eraseSubject('alice@example.test', 'lina'), /Audit storage failed/);
  assert.equal(audit.subjectPseudonym('alice@example.test'), row.subject, 'an erasure the audit refuses erases nothing');
  audit.append = append;
  const erased = await audit.eraseSubject('alice@example.test', 'lina');
  assert.deepEqual(erased, { pseudonym: row.subject!, erased: true });
  assert.ok(!(JSON.parse(readFileSync(mapping, 'utf8')) as Array<{ id: string }>).some((entry) => entry.id === 'alice@example.test'));
  assert.equal(audit.subjectPseudonym('alice@example.test'), undefined);
  assert.equal(audit.verify().verified, true);
  assert.equal(audit.records()[0]?.hash, row.hash);
  assert.deepEqual(audit.records()[1]?.details, { pseudonym: row.subject });
  assert.equal((await audit.eraseSubject('alice@example.test', 'lina')).erased, false);
  assert.equal(existsSync(mapping), true, 'the separate mapping remains a mode-600 file without the erased id');
});


test('the privacy erasure route needs two officers and preserves the live server audit chain', async (t) => {
  const dir = mkdtempSync('/tmp/pdp-erasure-http-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  let server = createServer({ port: 0, dataDir: dir, signingKeySeal: SEAL, clock: `fixed:${NOW}` });
  await server.listen(); t.after(() => server.close());
  const credentials = JSON.parse(readFileSync(join(dir, 'INITIAL-CREDENTIALS.txt'), 'utf8')) as { pepApiKey: string; passwords: Record<string, string> };
  const decision = await fetch(`${server.url}/access/v1/evaluation`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${credentials.pepApiKey}` }, body: JSON.stringify(evaluation()) });
  assert.equal(decision.status, 200);
  const signIn = async (id: string): Promise<Record<string, string>> => {
    const login = await fetch(`${server.url}/admin/v1/session`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: id, password: credentials.passwords[id] }) });
    assert.equal(login.status, 200);
    const session = await login.json() as { csrfToken: string };
    return { cookie: String(login.headers.get('set-cookie')).split(';')[0]!, 'x-csrf-token': session.csrfToken, 'content-type': 'application/json' };
  };
  const headers = await signIn('lina');
  const before = await fetch(`${server.url}/admin/v1/audit?subject=bob&type=decision`, { headers });
  const beforeRows = (await before.json() as { items: AuditRecord[] }).items;
  assert.equal(beforeRows.length, 1); assert.equal(beforeRows[0]!.subject, 'bob', 'admin display uses the live mapping');
  const storedPseudonym = (JSON.parse(readFileSync(join(dir, 'audit.jsonl'), 'utf8').split('\n')[0]!) as AuditRecord).subject!;

  const proposed = await fetch(`${server.url}/admin/v1/privacy/subjects/bob/erasure`, { method: 'POST', headers, body: '{}' });
  assert.equal(proposed.status, 201);
  const change = await proposed.json() as { id: string; status: string };
  assert.equal(change.status, 'pending');
  await server.close();
  const accountsFile = join(dir, 'credentials.json');
  const accounts = JSON.parse(readFileSync(accountsFile, 'utf8')) as { users: Array<{ id: string; roles: string[] }> };
  accounts.users.find((account) => account.id === 'omar')!.roles.push('security_officer');
  writeFileSync(accountsFile, JSON.stringify(accounts));
  server = createServer({ port: 0, dataDir: dir, signingKeySeal: SEAL, clock: `fixed:${NOW}` });
  await server.listen();
  const approver = await signIn('omar');
  const approved = await fetch(`${server.url}/admin/v1/changes/${change.id}/approve`, { method: 'POST', headers: approver, body: JSON.stringify({ reason: 'independent privacy review' }) });
  assert.equal(approved.status, 200);
  const result = await approved.json() as { status: string; erasure: { pseudonym: string; erased: boolean; changeId: string } };
  assert.equal(result.status, 'applied');
  assert.deepEqual(result.erasure, { pseudonym: storedPseudonym, erased: true, changeId: change.id });
  assert.ok(!(JSON.parse(readFileSync(join(dir, 'audit-subjects.json'), 'utf8')) as Array<{ id: string }>).some((mapping) => mapping.id === 'bob'));
  const after = await fetch(`${server.url}/admin/v1/audit?subject=bob&type=decision`, { headers: approver });
  assert.equal((await after.json() as { items: AuditRecord[] }).items.length, 0);
  const verified = await fetch(`${server.url}/admin/v1/audit/verify`, { headers: approver });
  assert.equal((await verified.json() as { verified: boolean }).verified, true);
  const siem = await fetch(`${server.url}/admin/v1/audit/export`, { headers: approver });
  assert.ok(!(await siem.text()).includes('bob'));

  const auditor = await signIn('sam');
  const forbidden = await fetch(`${server.url}/admin/v1/privacy/subjects/bob/erasure`, { method: 'POST', headers: auditor, body: '{}' });
  assert.equal(forbidden.status, 403);
  assert.ok(!readFileSync(join(dir, 'audit.jsonl'), 'utf8').includes('bob'), 'the refused route is audited without the id');
});


test('a deleted checkpoint never launders a rewritten non-empty chain; migration requires the explicit flag and is audited', (t) => {
  const dir = mkdtempSync('/tmp/pdp-checkpoint-downgrade-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'audit.jsonl'); const checkpoint = join(dir, 'audit-checkpoint.json');
  const legacy = new Audit(file, () => NOW);
  legacy.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'alice', effect: 'allow' });
  assert.equal(new Audit(file, () => NOW, { checkpointKey: KEY }).verify().verified, false, 'a non-empty legacy chain does not self-migrate');
  assert.equal(existsSync(checkpoint), false);
  const reviewed = legacy.records().at(-1)!.hash;
  assert.equal(new Audit(file, () => NOW, { checkpointKey: KEY, checkpointMigration: 'f'.repeat(64) }).verify().verified, false, 'only the reviewed head migrates');
  const migrated = new Audit(file, () => NOW, { checkpointKey: KEY, checkpointMigration: reviewed });
  assert.equal(migrated.verify().verified, true);
  assert.equal(migrated.records().at(-1)?.action, 'checkpoint_migrated');
  assert.equal(migrated.records().at(-1)?.actor, 'system');
  assert.deepEqual(migrated.records().at(-1)?.details, { seq: 1, hash: reviewed });

  const forged = rewrite(migrated.records().filter((row) => row.action !== 'checkpoint_migrated'));
  writeFileSync(file, forged);
  rmSync(checkpoint);
  assert.equal(new Audit(file, () => NOW, { checkpointKey: KEY }).verify().verified, false, 'the reviewed downgrade attack is refused');
  assert.equal(new Audit(file, () => NOW, { checkpointKey: KEY, checkpointMigration: reviewed }).verify().verified, false, 'a migration value left set is spent');
  assert.equal(existsSync(checkpoint), false, 'nothing re-mints the deleted checkpoint');
  assert.throws(() => createServer({ dataDir: dir, signingKeySeal: SEAL }), /Audit integrity failure/);
  assert.throws(() => createServer({ dataDir: dir, signingKeySeal: SEAL, auditCheckpointMigration: reviewed }), /Audit integrity failure/);
});

test('a valid checkpoint one row behind completes only the append crash window', (t) => {
  const dir = mkdtempSync('/tmp/pdp-checkpoint-crash-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'audit.jsonl'); const checkpoint = join(dir, 'audit-checkpoint.json');
  const audit = new Audit(file, () => NOW, { checkpointKey: KEY });
  const genesis = readFileSync(checkpoint, 'utf8');
  audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'alice', effect: 'allow' });
  const beforeSecond = readFileSync(checkpoint, 'utf8');
  audit.append({ type: 'decision', actor: 'pep', action: 'read', subject: 'bob', effect: 'deny' });
  writeFileSync(checkpoint, genesis);
  assert.equal(new Audit(file, () => NOW, { checkpointKey: KEY }).verify().verified, false, 'two rows beyond the checkpoint are refused');
  writeFileSync(checkpoint, beforeSecond);
  const recovered = new Audit(file, () => NOW, { checkpointKey: KEY });
  assert.equal(recovered.verify().verified, true);
  assert.equal(recovered.records().at(-1)?.action, 'checkpoint_completed', 'the completed crash window is audited');
  assert.equal(recovered.records().at(-1)?.details?.seq, 2);
  assert.equal(JSON.parse(readFileSync(checkpoint, 'utf8')).seq, 3);
  const current = readFileSync(checkpoint, 'utf8');
  writeFileSync(checkpoint, '{not json');
  assert.equal(new Audit(file, () => NOW, { checkpointKey: KEY }).verify().verified, false);
  writeFileSync(checkpoint, current);
});
