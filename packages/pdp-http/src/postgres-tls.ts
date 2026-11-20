import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import type { ClientConfig } from 'pg';

// Resolve pg's own nested parser without making it a second direct dependency.
const require = createRequire(import.meta.url);
const { parse } = createRequire(require.resolve('pg'))('pg-connection-string') as { parse(connectionString: string): { host: string | null } };

export type DatabaseTlsMode = 'verify-full' | 'require' | 'disable';
export type DatabaseProfile = 'demo' | 'production';
export interface DatabaseTls {
  mode: DatabaseTlsMode;
  caFile?: string;
  certFile?: string;
  keyFile?: string;
}

const MODES = new Set<DatabaseTlsMode>(['verify-full', 'require', 'disable']);
/** The operations tools' profile: production (verify-full by default) unless GATE_PROFILE=demo is explicit, since run by
 *  hand outside the Jobs that set it they would otherwise skip certificate verification against a production database. */
export const opsProfile = (gateProfile: string | undefined): DatabaseProfile => (gateProfile === 'demo' ? 'demo' : 'production');
const URL_TLS_PARAMETERS = ['ssl', 'sslmode', 'sslcert', 'sslkey', 'sslrootcert', 'sslpassword'];

export function databaseTlsFromEnv(env: NodeJS.ProcessEnv = process.env, profile: DatabaseProfile = 'demo'): DatabaseTls {
  const value = env.DATABASE_TLS ?? (profile === 'production' ? 'verify-full' : 'require');
  if (!MODES.has(value as DatabaseTlsMode)) throw new Error('DATABASE_TLS must be verify-full, require or disable');
  const mode = value as DatabaseTlsMode;
  const caFile = env.DATABASE_TLS_CA_FILE || undefined;
  const certFile = env.DATABASE_TLS_CERT_FILE || undefined;
  const keyFile = env.DATABASE_TLS_KEY_FILE || undefined;
  if (caFile && mode !== 'verify-full') throw new Error('DATABASE_TLS_CA_FILE requires DATABASE_TLS=verify-full');
  if (Boolean(certFile) !== Boolean(keyFile)) throw new Error('DATABASE_TLS_CERT_FILE and DATABASE_TLS_KEY_FILE must be set together');
  if (mode === 'disable' && certFile) throw new Error('DATABASE_TLS_CERT_FILE and DATABASE_TLS_KEY_FILE require TLS');
  return { mode, ...(caFile ? { caFile } : {}), ...(certFile ? { certFile, keyFile } : {}) };
}

function target(databaseUrl: string): { host: string; local: boolean } {
  let url: URL;
  try { url = new URL(databaseUrl); } catch { throw new Error('DATABASE_URL must be a valid PostgreSQL URL'); }
  if (url.protocol !== 'postgresql:' && url.protocol !== 'postgres:') throw new Error('DATABASE_URL must be a PostgreSQL URL');
  for (const name of URL_TLS_PARAMETERS) if (url.searchParams.has(name)) throw new Error(`DATABASE_URL must not set ${name}; use DATABASE_TLS and its file settings`);
  if (url.searchParams.getAll('host').length > 1) throw new Error('DATABASE_URL must not contain a repeated host parameter');
  let host: string;
  try { host = parse(databaseUrl).host ?? ''; } catch { throw new Error('DATABASE_URL must be a valid PostgreSQL URL'); }
  const local = host === '' || host.startsWith('/') || host === 'localhost' || host === '::1' || host === '[::1]' || /^127(?:\.\d{1,3}){3}$/.test(host);
  return { host, local };
}

export function databaseTlsFailures(databaseUrl: string, tls: DatabaseTls, profile: DatabaseProfile): string[] {
  try {
    const { host, local } = target(databaseUrl);
    if (profile === 'production' && !local && tls.mode !== 'verify-full') return ['DATABASE_TLS=verify-full is required for a non-local DATABASE_URL host in production'];
    if (tls.mode === 'verify-full' && (host === '' || host.startsWith('/'))) return ['DATABASE_TLS=verify-full cannot verify a unix-socket DATABASE_URL host; use require or disable for a local socket'];
    return [];
  } catch (err) { return [err instanceof Error ? err.message : String(err)]; }
}

export function assertDatabaseTls(databaseUrl: string, tls: DatabaseTls, profile: DatabaseProfile = 'demo'): void {
  const failures = databaseTlsFailures(databaseUrl, tls, profile);
  if (failures.length) throw new Error(failures[0]);
}

/** Explicit ssl wins over pg's connection-string defaults; URL ssl parameters are refused above, never merged. */
export function postgresClientConfig(databaseUrl: string, tls: DatabaseTls, profile: DatabaseProfile = 'demo', extra: ClientConfig = {}): ClientConfig {
  assertDatabaseTls(databaseUrl, tls, profile);
  const files = tls.caFile || tls.certFile ? {
    ...(tls.caFile ? { ca: readFileSync(tls.caFile) } : {}),
    ...(tls.certFile ? { cert: readFileSync(tls.certFile), key: readFileSync(tls.keyFile!) } : {}),
  } : {};
  const ssl = tls.mode === 'disable' ? false : tls.mode === 'require' ? { rejectUnauthorized: false, ...files } : { rejectUnauthorized: true, ...files };
  return { connectionString: databaseUrl, ...extra, ssl };
}

/** libpq's names for the same policy, used by pg_dump/pg_restore/createdb/dropdb/psql. */
export function libpqTlsEnvironment(databaseUrl: string, tls: DatabaseTls, profile: DatabaseProfile = 'demo'): Record<'PGSSLMODE' | 'PGSSLROOTCERT' | 'PGSSLCERT' | 'PGSSLKEY', string> {
  assertDatabaseTls(databaseUrl, tls, profile);
  return {
    PGSSLMODE: tls.mode,
    PGSSLROOTCERT: tls.mode === 'verify-full' ? tls.caFile ?? 'system' : '',
    PGSSLCERT: tls.mode === 'disable' ? '' : tls.certFile ?? '',
    PGSSLKEY: tls.mode === 'disable' ? '' : tls.keyFile ?? '',
  };
}
