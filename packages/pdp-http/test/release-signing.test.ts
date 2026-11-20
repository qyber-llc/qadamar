import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../../..');
const hook = join(root, 'scripts/release/sign-ssh.sh');

test('the release signing hook signs SHA256SUMS, and a changed checksum file no longer verifies', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'gate-sign-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const key = join(dir, 'key');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'test', '-f', key]);
  const signers = join(dir, 'allowed_signers');
  writeFileSync(signers, `release@qadamar namespaces="file" ${readFileSync(`${key}.pub`, 'utf8').split(' ').slice(0, 2).join(' ')}\n`);
  const sums = join(dir, 'SHA256SUMS');
  writeFileSync(sums, `${'0'.repeat(64)}  qadamar-0.0.0.tar.gz\n`);
  const env = { ...process.env, RELEASE_SSH_KEY: key, RELEASE_ALLOWED_SIGNERS: signers };
  const signed = spawnSync('bash', [hook, sums], { env, encoding: 'utf8' });
  assert.equal(signed.status, 0, signed.stderr);
  const verify = () => spawnSync('ssh-keygen', ['-Y', 'verify', '-f', signers, '-I', 'release@qadamar', '-n', 'file', '-s', `${sums}.sig`],
    { input: readFileSync(sums), encoding: 'utf8' }).status;
  assert.equal(verify(), 0);
  writeFileSync(sums, `${'1'.repeat(64)}  qadamar-0.0.0.tar.gz\n`);
  assert.notEqual(verify(), 0, 'a tampered checksum file fails verification');
});

test('the hook refuses a missing key and a key that is not in allowed_signers', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'gate-sign-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const sums = join(dir, 'SHA256SUMS');
  writeFileSync(sums, 'x\n');
  assert.notEqual(spawnSync('bash', [hook, sums], { env: { ...process.env, RELEASE_SSH_KEY: join(dir, 'none') } }).status, 0);
  const key = join(dir, 'key');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'other', '-f', key]);
  // the committed allowed_signers names the real release key only
  assert.notEqual(spawnSync('bash', [hook, sums], { env: { ...process.env, RELEASE_SSH_KEY: key } }).status, 0);
});

test('the committed allowed_signers holds exactly one ed25519 release key for the file namespace', () => {
  const lines = readFileSync(join(root, 'scripts/release/allowed_signers'), 'utf8').trim().split('\n');
  assert.equal(lines.length, 1);
  assert.match(lines[0]!, /^release@qadamar namespaces="file" ssh-ed25519 [A-Za-z0-9+/=]+$/);
});

test('an encrypted key signs with its passphrase from RELEASE_SSH_KEY_PASSPHRASE, and a wrong passphrase fails', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'gate-sign-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const key = join(dir, 'key');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', 'correct horse battery', '-C', 'test', '-f', key]);
  const signers = join(dir, 'allowed_signers');
  writeFileSync(signers, `release@qadamar namespaces="file" ${readFileSync(`${key}.pub`, 'utf8').split(' ').slice(0, 2).join(' ')}\n`);
  const sums = join(dir, 'SHA256SUMS');
  writeFileSync(sums, 'x\n');
  const run = (passphrase: string) => spawnSync('bash', [hook, sums],
    { env: { ...process.env, RELEASE_SSH_KEY: key, RELEASE_ALLOWED_SIGNERS: signers, RELEASE_SSH_KEY_PASSPHRASE: passphrase }, encoding: 'utf8' });
  assert.notEqual(run('wrong').status, 0);
  const ok = run('correct horse battery');
  assert.equal(ok.status, 0, ok.stderr);
  assert.ok(!ok.stdout.includes('correct horse') && !ok.stderr.includes('correct horse'), 'the passphrase is never printed');
});
