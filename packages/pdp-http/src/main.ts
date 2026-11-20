import { readFileSync } from 'node:fs';
import { createServer, type ServerOptions } from './server.ts';
import { createTenantServer, tenantConfigFromEnv } from './tenants.ts';
import { scimFromEnv } from './scim.ts';
import { samlFromEnv } from './saml.ts';
import { siemFromEnv } from './siem.ts';
import { parseResourceOwners, parseSodHistory } from './runtime.ts';
import { breakGlassFromEnv } from './notify.ts';
import { profileOf } from './profile.ts';
import { tracingFromEnv } from './tracing.ts';
import { rateLimitsFromEnv } from './ratelimit.ts';
import { sessionsPerPepFromEnv } from './sessions.ts';
import { sessionsPerCredentialFromEnv, sessionsPerSubjectFromEnv } from './pep-sessions.ts';
import { parseReplicaKeys } from './replica-protocol.ts';
import { parsePins } from './replica.ts';
import { databaseTlsFromEnv } from './postgres-tls.ts';

const port = Number(process.env.PORT ?? 8787);
if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('PORT must be 0..65535');
const env = process.env;
const flag = (v: string | undefined): boolean | undefined => (v === undefined ? undefined : /^(1|on|true|yes)$/i.test(v));
const serverOptions: ServerOptions = { profile: profileOf(env.GATE_PROFILE), host: env.HOST, port, dataDir: env.DATA_DIR, worldDir: env.WORLD_DIR, clock: env.CLOCK,
  publicOrigin: env.PUBLIC_ORIGIN, trustedProxies: env.TRUSTED_PROXIES, ...rateLimitsFromEnv(env),
  tls: env.TLS_CERT_FILE && env.TLS_KEY_FILE ? { cert: readFileSync(env.TLS_CERT_FILE), key: readFileSync(env.TLS_KEY_FILE) } : undefined,
  oidc: env.OIDC_ISSUER ? { issuer: env.OIDC_ISSUER, clientId: env.OIDC_CLIENT_ID ?? '', clientSecret: env.OIDC_CLIENT_SECRET,
    roleClaim: env.OIDC_ROLE_CLAIM, idClaim: env.OIDC_ID_CLAIM ?? '', acr: env.OIDC_ACR } : undefined,
  saml: samlFromEnv(env),
  passwordLogin: flag(env.PASSWORD_LOGIN),
  pepRotationGraceSeconds: env.PEP_ROTATION_GRACE_SECONDS ? Number(env.PEP_ROTATION_GRACE_SECONDS) : undefined,
  initialCredentialsTtlSeconds: env.INITIAL_CREDENTIALS_TTL_SECONDS ? Number(env.INITIAL_CREDENTIALS_TTL_SECONDS) : undefined,
  signingKeySeal: env.SIGNING_KEY_SEAL, signingKeySealPrevious: env.SIGNING_KEY_SEAL_PREVIOUS,
  auditCheckpointMigration: env.AUDIT_CHECKPOINT_MIGRATE || undefined,
  allowClearSigningKeys: flag(env.ALLOW_CLEAR_SIGNING_KEYS),
  allowRemoteDemo: flag(env.DEMO_ALLOW_REMOTE), allowDemoWorld: flag(env.ALLOW_DEMO_WORLD),
  scim: scimFromEnv(env), siem: siemFromEnv(env), breakGlass: breakGlassFromEnv(env), tracing: tracingFromEnv(env),
  databaseUrl: env.DATABASE_URL, databaseTls: databaseTlsFromEnv(env, profileOf(env.GATE_PROFILE)),
  nodeId: env.GATE_NODE_ID, cluster: flag(env.GATE_CLUSTER), advertiseUrl: env.GATE_ADVERTISE_URL,
  maxStalenessMs: env.GATE_MAX_STALENESS_MS ? Number(env.GATE_MAX_STALENESS_MS) : undefined,
  replicaKeys: parseReplicaKeys(env.GATE_REPLICA_KEYS), replicaOf: env.GATE_REPLICA_OF || undefined, replicaKey: env.GATE_REPLICA_KEY ?? (env.GATE_REPLICA_KEY_FILE ? readFileSync(env.GATE_REPLICA_KEY_FILE, 'utf8').trim() : undefined),
  replicaPins: parsePins(env.GATE_REPLICA_PIN), replicaCaFile: env.GATE_REPLICA_CA_FILE || undefined,
  replicaAuditLagMs: env.GATE_REPLICA_AUDIT_LAG_MS ? Number(env.GATE_REPLICA_AUDIT_LAG_MS) : undefined,
  retentionDays: env.AUDIT_RETENTION_DAYS ? Number(env.AUDIT_RETENTION_DAYS) : undefined,
  resourceOwners: parseResourceOwners(env.RESOURCE_OWNERS), sodHistory: parseSodHistory(env.SOD_HISTORY),
  blpSessionRequired: flag(env.BLP_SESSION_REQUIRED), blpSessionsPerPep: sessionsPerPepFromEnv(env.BLP_SESSIONS_PER_PEP),
  blpSessionsPerSubject: sessionsPerSubjectFromEnv(env.BLP_SESSIONS_PER_SUBJECT),
  blpSessionsPerCredential: sessionsPerCredentialFromEnv(env.BLP_SESSIONS_PER_CREDENTIAL),
  policySignatureAdopt: flag(env.POLICY_SIGNATURE_ADOPT),
  tsa: env.TSA_URL ? { url: env.TSA_URL, intervalSeconds: env.ANCHOR_INTERVAL ? Number(env.ANCHOR_INTERVAL) : undefined, caFile: env.TSA_CA_FILE } : undefined,
  // fail-stop: a node whose store failed must not answer again; the supervisor restarts it as a standby
  onFatal: (err) => { console.error(`Storage failure, stopping: ${err.message}`); process.exit(1); } };
const partition = tenantConfigFromEnv(env);
const server = partition ? createTenantServer(serverOptions, partition.tenants, partition.selected) : createServer(serverOptions);
// production refuses an explicit caller history (profile.ts); a demo warns only about that explicit opt-in
if (profileOf(env.GATE_PROFILE) === 'demo' && parseSodHistory(env.SOD_HISTORY) === 'caller') console.warn('SOD_HISTORY=caller: separation of duty believes the makerId and priorActions a PEP sends when the PDP recorded no history. Use this opt-in only for demos and compatibility tests');
if (env.ANCHOR_INTERVAL && !(Number(env.ANCHOR_INTERVAL) >= 60)) throw new Error('ANCHOR_INTERVAL must be at least 60 seconds');
// Registered before listen(): a standby waiting for the lock has no port and nothing to drain, and as PID 1 in a
// container it would otherwise ignore SIGTERM, take the lock while terminating and hold it until it is killed.
let serving = false;
const stop = (): void => { if (serving) void server.close(); else process.exit(0); };
process.once('SIGINT', stop);
process.once('SIGTERM', stop);
await server.listen();
serving = true;
console.log(`PDP listening at ${server.url}`);
