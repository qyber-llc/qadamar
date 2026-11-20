import { migrateRecordStore } from '../../packages/pdp-http/src/postgres-records.ts';
import { databaseTlsFromEnv, opsProfile } from '../../packages/pdp-http/src/postgres-tls.ts';

const url = process.env.DATABASE_URL;
if (!url) throw new Error('DATABASE_URL is required');
const migrated = await migrateRecordStore(url, databaseTlsFromEnv(process.env, opsProfile(process.env.GATE_PROFILE)));
console.log(migrated
  ? 'Legacy state document migrated into per-record tables.'
  : 'Per-record state migration already complete.');
