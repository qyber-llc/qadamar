// scripts/ops/archive-crypt.ts, the AES-256-GCM layer of backup.sh and restore.sh: no database needed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, type SpawnSyncReturns } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const crypt = fileURLToPath(new URL('../../../scripts/ops/archive-crypt.ts', import.meta.url));
const HEADER = 19, TAG = 16;
const hexKey = randomBytes(32).toString('hex');
const urlKey = randomBytes(32).toString('base64url');

function setup(t: test.TestContext): (name: string) => string {
  const dir = mkdtempSync(resolve(tmpdir(), 'gate-crypt-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return (name) => resolve(dir, name);
}

function run(args: string[], key: string | undefined): SpawnSyncReturns<string> {
  const env = { ...process.env };
  delete env.BACKUP_ENCRYPTION_KEY;
  if (key !== undefined) env.BACKUP_ENCRYPTION_KEY = key;
  const result = spawnSync(process.execPath, [crypt, ...args], { env, encoding: 'utf8', timeout: 30_000 });
  for (const secret of [hexKey, urlKey, key]) {
    if (secret) assert.ok(!`${result.stdout}${result.stderr}`.includes(secret), 'the key is never printed');
  }
  return result;
}

function ok(args: string[], key: string): void {
  const result = run(args, key);
  assert.equal(result.status, 0, result.stderr);
}

function refused(args: string[], key: string | undefined, message: RegExp): void {
  const result = run(args, key);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, message);
}

test('encrypts and decrypts round trip with a hex or base64url key, files mode 600, header in clear', (t) => {
  const path = setup(t);
  const plain = Buffer.from('PGDMP gate_audit gate_doc '.repeat(50));
  writeFileSync(path('plain'), plain);
  for (const key of [hexKey, urlKey]) {
    ok(['encrypt', path('plain'), path(`sealed-${key.length}`)], key);
    const sealed = readFileSync(path(`sealed-${key.length}`));
    assert.deepEqual([...sealed.subarray(0, 7)], [...Buffer.from('GATEBK'), 1]);
    assert.equal(sealed.length, HEADER + plain.length + TAG);
    assert.ok(!sealed.includes('gate_audit'), 'no plaintext in the archive');
    ok(['decrypt', path(`sealed-${key.length}`), path(`opened-${key.length}`)], key);
    assert.deepEqual(readFileSync(path(`opened-${key.length}`)), plain);
    for (const file of [`sealed-${key.length}`, `opened-${key.length}`]) assert.equal(statSync(path(file)).mode & 0o777, 0o600);
  }
  const nonce = (file: string): Buffer => readFileSync(path(file)).subarray(7, HEADER);
  assert.ok(!nonce('sealed-64').equals(nonce('sealed-43')), 'a fresh nonce per archive');
  writeFileSync(path('empty'), '');
  ok(['encrypt', path('empty'), path('empty.sealed')], hexKey);
  ok(['decrypt', path('empty.sealed'), path('empty.opened')], hexKey);
  assert.equal(readFileSync(path('empty.opened')).length, 0);
});

test('streams a multi-megabyte archive', (t) => {
  const path = setup(t);
  const plain = randomBytes(6 * 1024 * 1024 + 3);
  writeFileSync(path('plain'), plain);
  ok(['encrypt', path('plain'), path('sealed')], hexKey);
  ok(['decrypt', path('sealed'), path('opened')], hexKey);
  assert.ok(readFileSync(path('opened')).equals(plain));
});

test('refuses to overwrite an existing output, bad usage and a missing input', (t) => {
  const path = setup(t);
  writeFileSync(path('plain'), 'archive');
  writeFileSync(path('taken'), 'keep me');
  refused(['encrypt', path('plain'), path('taken')], hexKey, /already exists/);
  ok(['encrypt', path('plain'), path('sealed')], hexKey);
  refused(['decrypt', path('sealed'), path('taken')], hexKey, /already exists/);
  assert.equal(readFileSync(path('taken'), 'utf8'), 'keep me');
  refused(['seal', path('plain'), path('out')], hexKey, /usage/);
  refused(['encrypt', path('plain')], hexKey, /usage/);
  refused(['encrypt', path('missing'), path('out')], hexKey, /ENOENT/);
  refused(['decrypt', path('missing'), path('out')], hexKey, /ENOENT/);
  assert.ok(!existsSync(path('out')));
});

test('rejects keys that are not exactly 32 bytes in hex or canonical unpadded base64url', (t) => {
  const path = setup(t);
  writeFileSync(path('plain'), 'archive');
  const bad = [undefined, '', hexKey.slice(1), `${hexKey}0`, 'g'.repeat(64), randomBytes(31).toString('base64url'),
    `${urlKey}=`, randomBytes(32).toString('base64').replace(/=+$/, '').replace(/[^+/]/, '+'), `${urlKey.slice(0, 42)}B`];
  for (const key of bad) {
    refused(['encrypt', path('plain'), path('out')], key, /BACKUP_ENCRYPTION_KEY must be 32 bytes/);
    assert.ok(!existsSync(path('out')));
  }
});

test('refuses a wrong key, any flipped byte, a truncated or empty file, and leaves no output', (t) => {
  const path = setup(t);
  writeFileSync(path('plain'), randomBytes(4096));
  ok(['encrypt', path('plain'), path('sealed')], hexKey);
  const sealed = readFileSync(path('sealed'));
  const flip = (at: number): Buffer => { const copy = Buffer.from(sealed); copy[at] = copy[at]! ^ 1; return copy; };
  const cases: Array<[string, Buffer, RegExp]> = [
    ['magic', flip(0), /not a Qadamar backup archive/],
    ['version', flip(6), /not a Qadamar backup archive/],
    ['nonce', flip(10), /authentication failed/],
    ['body', flip(HEADER + 2000), /authentication failed/],
    ['tag', flip(sealed.length - 1), /authentication failed/],
    ['truncated tag', sealed.subarray(0, sealed.length - 1), /authentication failed/],
    ['truncated to the header', sealed.subarray(0, HEADER + TAG - 1), /truncated/],
    ['empty', Buffer.alloc(0), /truncated/],
  ];
  for (const [name, bytes, message] of cases) {
    writeFileSync(path(name), bytes);
    refused(['decrypt', path(name), path('out')], hexKey, message);
    assert.ok(!existsSync(path('out')), `${name}: no output left`);
  }
  refused(['decrypt', path('sealed'), path('out')], randomBytes(32).toString('hex'), /authentication failed/);
  assert.ok(!existsSync(path('out')), 'wrong key: no output left');
  refused(['decrypt', path('sealed'), path('out')], urlKey, /authentication failed/);
  assert.ok(!existsSync(path('out')));
});
