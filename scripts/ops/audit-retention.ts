// Owner-run PostgreSQL audit retention. Stop every Qadamar writer first; DATABASE_URL must be the table owner's URL.
import { retainPostgres } from '../../packages/pdp-http/src/audit-maintenance.ts';
import { CHECKPOINT_KEY_LABEL, derivedKey } from '../../packages/pdp-http/src/tokens.ts';
import { databaseTlsFromEnv, opsProfile } from '../../packages/pdp-http/src/postgres-tls.ts';

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('DATABASE_URL must name the owner/maintenance role, not the Qadamar service role');
const checkpointKey = derivedKey(process.env.SIGNING_KEY_SEAL, CHECKPOINT_KEY_LABEL);
if (!checkpointKey) throw new Error('SIGNING_KEY_SEAL is required to authenticate retention seals');
const retentionDays = Number(process.env.AUDIT_RETENTION_DAYS);
const previousCheckpointKey = derivedKey(process.env.SIGNING_KEY_SEAL_PREVIOUS, CHECKPOINT_KEY_LABEL);
const databaseTls = databaseTlsFromEnv(process.env, opsProfile(process.env.GATE_PROFILE));
const sealed = await retainPostgres({ databaseUrl, databaseTls, checkpointKey, retentionDays, ...(previousCheckpointKey ? { previousCheckpointKey } : {}),
  ...(process.env.TSA_URL ? { tsa: { url: process.env.TSA_URL, caFile: process.env.TSA_CA_FILE } } : {}) });
console.log(`Audit retention complete: ${sealed.length} chain segment(s) sealed; ${sealed.reduce((sum, segment) => sum + segment.removed, 0)} row(s) removed.`);
