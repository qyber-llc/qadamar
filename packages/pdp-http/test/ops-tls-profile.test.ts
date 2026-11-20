// The operations tools (backup.sh, restore.sh through database-tls.ts, audit-retention.ts, migrate-records.ts) run by
// hand, outside the Kubernetes Jobs that set GATE_PROFILE: they verify the database certificate unless demo is explicit.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { opsProfile } from '../src/postgres-tls.ts';

const root = resolve(import.meta.dirname, '../../..');
const libpq = (env: Record<string, string>): string[] => execFileSync(process.execPath, [resolve(root, 'scripts/ops/database-tls.ts')],
  { env: { PATH: process.env.PATH ?? '', DATABASE_URL: 'postgresql://backup@db.internal.example/gate', ...env }, encoding: 'utf8' }).split('\0');

test('outside Kubernetes the operations tools take the production profile unless GATE_PROFILE=demo', () => {
  assert.equal(opsProfile(undefined), 'production');
  assert.equal(opsProfile('production'), 'production');
  assert.equal(opsProfile('demo'), 'demo');
  assert.equal(opsProfile('Demo'), 'production', 'only the exact word opts out');
  assert.equal(libpq({})[0], 'verify-full', 'backup.sh and restore.sh verify the server certificate by default');
  assert.equal(libpq({ GATE_PROFILE: 'demo' })[0], 'require');
  assert.equal(libpq({ DATABASE_TLS: 'disable', DATABASE_URL: 'postgresql://u@127.0.0.1:5432/gate' })[0], 'disable', 'a local drill database without TLS still works');
});
