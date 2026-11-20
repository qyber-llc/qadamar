// Maps the one Qadamar database TLS policy to libpq for the shell-based backup and restore tools. Values are NUL-separated
// so paths need no shell evaluation; no URL, credential or key material is printed.
import { databaseTlsFromEnv, libpqTlsEnvironment, opsProfile } from '../../packages/pdp-http/src/postgres-tls.ts';

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('DATABASE_URL is required');
const profile = opsProfile(process.env.GATE_PROFILE);
const tls = databaseTlsFromEnv({
  DATABASE_TLS: process.env.DATABASE_TLS,
  DATABASE_TLS_CA_FILE: process.env.DATABASE_TLS_CA_FILE,
  DATABASE_TLS_CERT_FILE: process.env.DATABASE_TLS_CERT_FILE,
  DATABASE_TLS_KEY_FILE: process.env.DATABASE_TLS_KEY_FILE,
}, profile);
const values = libpqTlsEnvironment(databaseUrl, tls, profile);
if (process.env.MAINTENANCE_DATABASE_URL) libpqTlsEnvironment(process.env.MAINTENANCE_DATABASE_URL, tls, profile);
process.stdout.write(`${values.PGSSLMODE}\0${values.PGSSLROOTCERT}\0${values.PGSSLCERT}\0${values.PGSSLKEY}\0`);
