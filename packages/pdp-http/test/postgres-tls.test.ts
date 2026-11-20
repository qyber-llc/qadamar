import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import pg from 'pg';
import { GENESIS } from '../src/audit.ts';
import { PgLedger } from '../src/postgres.ts';
import { databaseTlsFailures, databaseTlsFromEnv, libpqTlsEnvironment, postgresClientConfig, type DatabaseTls } from '../src/postgres-tls.ts';

const admin = process.env.TEST_DATABASE_URL;
const skip = admin ? false : 'TEST_DATABASE_URL is not set';
const verify = (caFile?: string): DatabaseTls => ({ mode: 'verify-full', ...(caFile ? { caFile } : {}) });

test('DATABASE_TLS parses an explicit policy, with verify-full the production default', (t) => {
  assert.deepEqual(databaseTlsFromEnv({}, 'production'), { mode: 'verify-full' });
  assert.deepEqual(databaseTlsFromEnv({}, 'demo'), { mode: 'require' });
  assert.deepEqual(databaseTlsFromEnv({ DATABASE_TLS: 'disable' }, 'demo'), { mode: 'disable' });
  assert.throws(() => databaseTlsFromEnv({ DATABASE_TLS: 'prefer' }), /DATABASE_TLS must be verify-full, require or disable/);
  assert.throws(() => databaseTlsFromEnv({ DATABASE_TLS: 'require', DATABASE_TLS_CA_FILE: '/ca.pem' }), /CA_FILE requires DATABASE_TLS=verify-full/);
  assert.throws(() => databaseTlsFromEnv({ DATABASE_TLS_CERT_FILE: '/client.crt' }), /CERT_FILE and DATABASE_TLS_KEY_FILE must be set together/);
  assert.throws(() => databaseTlsFromEnv({ DATABASE_TLS: 'disable', DATABASE_TLS_CERT_FILE: '/client.crt', DATABASE_TLS_KEY_FILE: '/client.key' }), /require TLS/);

  const dir = mkdtempSync('/tmp/gate-db-tls-config-'); t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const name of ['ca.pem', 'client.crt', 'client.key']) writeFileSync(resolve(dir, name), `${name}\n`);
  const tls = databaseTlsFromEnv({ DATABASE_TLS: 'verify-full', DATABASE_TLS_CA_FILE: resolve(dir, 'ca.pem'),
    DATABASE_TLS_CERT_FILE: resolve(dir, 'client.crt'), DATABASE_TLS_KEY_FILE: resolve(dir, 'client.key') }, 'production');
  const config = postgresClientConfig('postgresql://gate@db.example/gate', tls, 'production', { application_name: 'tls_test' });
  assert.equal(config.application_name, 'tls_test');
  assert.deepEqual(config.ssl, { rejectUnauthorized: true, ca: Buffer.from('ca.pem\n'), cert: Buffer.from('client.crt\n'), key: Buffer.from('client.key\n') });
  assert.deepEqual(postgresClientConfig('postgresql://gate@db.example/gate', { mode: 'require' }).ssl, { rejectUnauthorized: false });
  assert.deepEqual(postgresClientConfig('postgresql://gate@db.example/gate', { mode: 'require', certFile: tls.certFile, keyFile: tls.keyFile }).ssl,
    { rejectUnauthorized: false, cert: Buffer.from('client.crt\n'), key: Buffer.from('client.key\n') });
  assert.equal(postgresClientConfig('postgresql://gate@127.0.0.1/gate', { mode: 'disable' }, 'production').ssl, false);
  assert.deepEqual(libpqTlsEnvironment('postgresql://gate@db.example/gate', tls, 'production'), {
    PGSSLMODE: 'verify-full', PGSSLROOTCERT: resolve(dir, 'ca.pem'), PGSSLCERT: resolve(dir, 'client.crt'), PGSSLKEY: resolve(dir, 'client.key') });
  assert.equal(libpqTlsEnvironment('postgresql://gate@db.example/gate', verify()).PGSSLROOTCERT, 'system');
});

test('DATABASE_TLS refuses remote plaintext in production and ambiguous URL TLS parameters', () => {
  const remote = 'postgresql://gate@db.example/gate';
  assert.match(databaseTlsFailures(remote, { mode: 'disable' }, 'production')[0]!, /verify-full is required/);
  assert.match(databaseTlsFailures(remote, { mode: 'require' }, 'production')[0]!, /verify-full is required/);
  assert.deepEqual(databaseTlsFailures(remote, verify(), 'production'), []);
  assert.deepEqual(databaseTlsFailures(remote, { mode: 'disable' }, 'demo'), []);
  for (const local of ['postgresql://gate@localhost/gate', 'postgresql://gate@127.0.0.2/gate', 'postgresql://gate@[::1]/gate', 'postgresql:///gate?host=%2Fvar%2Frun%2Fpostgresql']) {
    assert.deepEqual(databaseTlsFailures(local, { mode: 'disable' }, 'production'), [], local);
  }
  assert.match(databaseTlsFailures('postgresql:///gate?host=%2Fvar%2Frun%2Fpostgresql', verify(), 'production')[0]!, /unix-socket/);
  assert.throws(() => postgresClientConfig('postgresql://gate@db.example/gate?sslmode=disable', verify(), 'production'), /must not set sslmode; use DATABASE_TLS/);
  for (const url of ['postgresql://gate@db.example/gate?host=localhost&host=evil.example', 'postgresql://gate@db.example/gate?host=evil.example&host=localhost']) {
    assert.match(databaseTlsFailures(url, { mode: 'disable' }, 'production')[0]!, /repeated host parameter/, url);
  }
  assert.match(databaseTlsFailures('not a url', verify(), 'production')[0]!, /valid PostgreSQL URL/);
});

function openssl(...args: string[]): void { execFileSync('openssl', args, { stdio: 'ignore' }); }
function docker(env: NodeJS.ProcessEnv, ...args: string[]): string {
  return execFileSync('docker', args, { encoding: 'utf8', env, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
}

async function connect(url: string, tls: DatabaseTls): Promise<void> {
  const client = new pg.Client(postgresClientConfig(url, tls, 'production'));
  await client.connect();
  try { assert.equal((await client.query<{ ssl: string }>('SHOW ssl')).rows[0]?.ssl, 'on'); } finally { await client.end(); }
}

test('PostgreSQL verify-full checks chain and hostname for every ledger connection', { skip, timeout: 120_000 }, async (t) => {
  const dir = mkdtempSync('/tmp/gate-db-tls-live-');
  const name = `gate-tls-${process.pid}-${randomBytes(6).toString('hex')}`;
  const password = randomBytes(24).toString('hex');
  const env = { ...process.env, POSTGRES_PASSWORD: password };
  let ledger: PgLedger | undefined;
  t.after(async () => {
    await ledger?.close().catch(() => undefined);
    try {
      if (docker(env, 'container', 'inspect', name, '--format', '{{ index .Config.Labels "qadamar.ci" }}') === 'local/qadamar/postgres-tls-test') docker(env, 'rm', '-fv', name);
    } catch { /* the container was never created or is already gone */ }
    rmSync(dir, { recursive: true, force: true });
  });
  openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', resolve(dir, 'ca.key'));
  openssl('req', '-x509', '-new', '-key', resolve(dir, 'ca.key'), '-days', '1', '-sha256', '-subj', '/CN=Qadamar PostgreSQL test CA', '-out', resolve(dir, 'ca.crt'));
  openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', resolve(dir, 'server.key'));
  openssl('req', '-new', '-key', resolve(dir, 'server.key'), '-subj', '/CN=localhost', '-out', resolve(dir, 'server.csr'));
  writeFileSync(resolve(dir, 'server.ext'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n');
  openssl('x509', '-req', '-in', resolve(dir, 'server.csr'), '-CA', resolve(dir, 'ca.crt'), '-CAkey', resolve(dir, 'ca.key'), '-CAcreateserial', '-days', '1', '-sha256', '-extfile', resolve(dir, 'server.ext'), '-out', resolve(dir, 'server.crt'));
  chmodSync(resolve(dir, 'server.key'), 0o600);
  docker(env, 'run', '-d', '--rm', '--name', name, '--label', 'qadamar.ci=local/qadamar/postgres-tls-test',
    '--cpus=1', '--memory=512m', '-p', '127.0.0.1::5432', '-e', 'POSTGRES_USER=gate', '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB=gate',
    '-v', `${dir}:/certs:ro`, 'postgres:17-alpine', 'sh', '-c',
    'cp /certs/server.crt /certs/server.key /tmp/ && chown postgres:postgres /tmp/server.crt /tmp/server.key && chmod 600 /tmp/server.key && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key');
  for (let i = 0; i < 60; i++) {
    try { docker(env, 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'gate', '-d', 'gate'); break; } catch { await new Promise((resolve) => setTimeout(resolve, 500)); }
  }
  docker(env, 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'gate', '-d', 'gate');
  const port = docker(env, 'port', name, '5432/tcp').split(':').at(-1)!;
  assert.match(port, /^\d+$/);
  const url = (hostname: string): string => `postgresql://gate:${encodeURIComponent(password)}@${hostname}:${port}/gate`;
  const caFile = resolve(dir, 'ca.crt');

  await connect(url('localhost'), verify(caFile));
  await assert.rejects(connect(url('localhost'), verify()), /self.signed|unable to verify|certificate/i);
  await assert.rejects(connect(url('127.0.0.1'), verify(caFile)), /altnames|hostname|certificate/i);
  await connect(url('127.0.0.1'), { mode: 'require' });

  ledger = await PgLedger.open(url('localhost'), () => undefined, { databaseTls: verify(caFile), cluster: true, node: 'tls-test' });
  assert.equal((await ledger.leaseRateLimit('tls-test', 10, 60, 1)).granted, 1);
  assert.equal((await ledger.replicaFeed()).version, 0);
  assert.deepEqual(await ledger.ingestReplica('tls-replica', { seq: 0, hash: GENESIS }, []), { head: { seq: 0, hash: GENESIS } });
});
