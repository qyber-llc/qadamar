// Generates docs/CONFIGURATION.md from the environment variables the server code (packages/*/src) and the operations
// scripts (scripts/ops) read, and with --check fails when a variable is read but not documented here, documented here
// but not read, or the file is stale.
//   node scripts/docs/env-table.ts          write docs/CONFIGURATION.md
//   node scripts/docs/env-table.ts --check  exit 1 on any difference (tools/ci/checks.sh)
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '../..');
const OUT = join(ROOT, 'docs/CONFIGURATION.md');

interface Doc { default: string; meaning: string }
/** The documentation of every variable. Defaults and limits are those of the code (file named in the table). */
const DOCS: Record<string, Doc> = {
  GATE_TENANTS_FILE: { default: 'unset (single tenant)', meaning: 'JSON tenant map for isolated runtimes: each entry needs dataDir and worldDir; database tenants need separate databaseUrl and signingKeySeal. Optional signingKeySealPrevious, auditCheckpointMigration, replicaOf, replicaKey, replicaPins, replicaKeys, replicaCaFile, advertiseUrl, publicOrigin. Secret file, mode 600. Requests require X-Qadamar-Tenant (docs/DEPLOY.md). Only selected runtimes are opened.' },
  GATE_SERVE_TENANTS: { default: 'all manifest tenants', meaning: 'Comma-separated distinct tenant ids in GATE_TENANTS_FILE. Lowercase letter followed by up to 62 lowercase letters, digits or hyphens. Empty, duplicate and unknown ids refuse startup. Other tenants receive HTTP 421 tenant_not_served.' },
  ALLOW_DEMO_WORLD: { default: 'off', meaning: 'Production profile: allows the first start to seed from a world whose `world.json` is marked `"demo": true` (the image\'s toy world). Local test deployments only; otherwise production refuses to seed fictional people.' },
  ALLOW_CLEAR_SIGNING_KEYS: { default: 'off', meaning: 'With `DATABASE_URL` and no `SIGNING_KEY_SEAL`, allows the signing keyring to be stored in clear in `gate_doc`; otherwise the start is refused. Refused by the production profile.' },
  ANCHOR_INTERVAL: { default: '3600', meaning: 'Seconds between RFC 3161 anchors of the audit head (with `TSA_URL`); at least 60.' },
  AUDIT_CHECKPOINT_MIGRATE: { default: 'unset', meaning: 'File mode, one-time: the reviewed head hash of an older audit chain that has no keyed checkpoint yet. Its first start with `SIGNING_KEY_SEAL` authenticates exactly that head and audits `checkpoint_migrated`; any other head (a rewritten chain, or the same chain once it grew) is refused, so a deleted checkpoint is never re-minted. Remove it afterwards (docs/DEPLOY.md).' },
  AUDIT_RETENTION_DAYS: { default: 'unset (keep all rows)', meaning: 'Audit rows older than this many days (1..36500) are sealed as an authenticated segment before their prefix is removed. Requires `SIGNING_KEY_SEAL`. File mode runs at start and daily; PostgreSQL runs only through `scripts/ops/audit-retention.ts` as the owner with every writer stopped.' },
  BLP_SESSIONS_PER_PEP: { default: '10000', meaning: 'Session high-water marks one PEP credential may hold at once (1..100000). A credential at its share gets `BLP.SESSION_LIMIT` on a read that would open a new mark (without a database; with one, its own oldest cached mark makes room), while other credentials keep theirs; 100,000 marks over all credentials stay the overall bound (docs/API.md §2).' },
  BLP_SESSIONS_PER_SUBJECT: { default: '4', meaning: 'Concurrently open PDP-issued session tokens per (PEP credential, subject), 1..1000. Opening above the cap gets 409 `session_limit`; every open token of the pair shares one high-water mark, and close does not clear it (docs/API.md §2).' },
  BLP_SESSIONS_PER_CREDENTIAL: { default: '10000', meaning: 'Concurrently open PDP-issued session tokens per PEP credential over all its subjects, 1..100000. Opening above the cap gets 409 `session_limit` (audited `credential_session_cap`), so distinct subject ids cannot each take a `BLP_SESSIONS_PER_SUBJECT` share; cluster-wide with PostgreSQL (docs/API.md §2).' },
  BLP_SESSION_CREATION_PER_MINUTE: { default: '60', meaning: 'Session-creation requests a minute per PEP credential, a separate token bucket with 429 and Retry-After (open and cap refusals are audited). Cluster mode leases from PostgreSQL; a replica also charges its local budget before forwarding (docs/API.md §2).' },
  BLP_SESSION_REQUIRED: { default: 'off', meaning: 'Every read above L0, and every write by a subject cleared above L0, needs a session (else `BLP.SESSION_REQUIRED`). Production requires this and accepts only `context.sessionToken` from `POST /x/v1/sessions`; raw `sessionId` is refused. Demo keeps raw ids as a warned compatibility mode (docs/API.md §2).' },
  BREAK_GLASS_WEBHOOK: { default: 'unset (no notices)', meaning: 'https URL that receives signed break-glass notices; set together with `BREAK_GLASS_WEBHOOK_SECRET`. No query string, no credentials.' },
  BREAK_GLASS_WEBHOOK_SECRET: { default: 'unset', meaning: 'HMAC secret for break-glass notices, at least 32 characters.' },
  CLOCK: { default: 'unset (system clock)', meaning: '`fixed:<ISO timestamp>` pins the time for demos. Refused by the production profile.' },
  DATABASE_URL: { default: 'unset (local files, one node)', meaning: 'PostgreSQL connection string: state, audit and shared security material; one active node and standbys, or several deciding nodes with `GATE_CLUSTER`. Do not put `ssl`/`sslmode` or TLS file parameters in it: `DATABASE_TLS` is the only TLS policy.' },
  DATABASE_TLS: { default: '`verify-full` in production, `require` otherwise', meaning: 'PostgreSQL transport policy. `verify-full` checks the server certificate chain and hostname and is required for a non-local host in production. `require` encrypts without authenticating the server. `disable` is allowed only outside production or for loopback/unix-socket hosts. `verify-full` cannot be used with a unix socket.' },
  DATABASE_TLS_CA_FILE: { default: 'unset (system CA store)', meaning: 'PEM CA bundle for `DATABASE_TLS=verify-full`, for a private PostgreSQL CA. The server certificate must also name the `DATABASE_URL` host.' },
  DATABASE_TLS_CERT_FILE: { default: 'unset', meaning: 'Optional PEM PostgreSQL client certificate; set together with `DATABASE_TLS_KEY_FILE`. Not valid with `DATABASE_TLS=disable`.' },
  DATABASE_TLS_KEY_FILE: { default: 'unset', meaning: 'PEM private key for `DATABASE_TLS_CERT_FILE`; set together. Not valid with `DATABASE_TLS=disable`.' },
  DATA_DIR: { default: '`data/runtime`', meaning: 'Directory for local state, audit, keys and `INITIAL-CREDENTIALS.txt`.' },
  DEMO_ALLOW_REMOTE: { default: 'off', meaning: 'Demo profile only: lets it listen on a non-loopback `HOST` (it refuses to start otherwise) and prints a warning at start. The demo has seeded accounts, a toy world and the production checks off; `/metrics` still needs `METRICS_TOKEN` there. Ignored by the production profile.' },
  GATE_ADVERTISE_URL: { default: 'unset', meaning: 'Cluster mode: this node\'s internal address, an http(s) origin (no credentials, path, query or fragment; anything else stops the process at start), published in PostgreSQL while it leads. Followers forward `/admin/`, `/scim/` and `/x/v1/resources` requests to it with a signed hop (needs `SIGNING_KEY_SEAL`; docs/API.md §3.9.1), and name it in their `409 not_leader` answers when they cannot forward.' },
  GATE_CLUSTER: { default: 'off', meaning: 'With `DATABASE_URL`: every node decides against the shared PostgreSQL, the admin plane, SCIM and resource registration stay on the leader (followers forward them to `GATE_ADVERTISE_URL`, or answer `409 not_leader`; `GET /leaderz` is 200 only on the leader), followers follow changes by LISTEN/NOTIFY (docs/API.md §3.9.1). Each node needs its own `GATE_NODE_ID`. Ignored without `DATABASE_URL`.' },
  GATE_MAX_STALENESS_MS: { default: '2000', meaning: 'Cluster mode and replicas: a node that last confirmed the shared state longer ago refuses decisions (503) and fails `/readyz`; integer in 100..60000. A replica polls its feed every quarter of it.' },
  GATE_NODE_ID: { default: '`0`', meaning: 'With PostgreSQL, the audit chain this node writes: 1..64 characters from `[A-Za-z0-9_.-]`, starting with a letter or digit. Unique per node in cluster mode (a second process with the same id waits). `0` is the chain of earlier versions. A replica (`GATE_REPLICA_OF`) must set it (not `0`): it names its own chain on the database; one whose disk was lost starts with a new id.' },
  GATE_REPLICA_AUDIT_LAG_MS: { default: '10000', meaning: 'Replica: it refuses decisions (503, `/readyz` 503) while a durable local audit row has waited longer than this to be stored by the database; the bound on what a lost replica disk can lose. Integer in 100..3600000.' },
  GATE_REPLICA_CA_FILE: { default: 'unset (system CA store)', meaning: 'Replica: PEM CA that verifies the database nodes\' TLS certificate (`GATE_REPLICA_OF`), for the feed, the JWKS bootstrap, audit shipping and forwarded requests.' },
  GATE_REPLICA_KEY: { default: 'none (required with `GATE_REPLICA_OF`)', meaning: 'Replica: its secret, 32 bytes as base64url or hex, as listed for its id in the database nodes\' `GATE_REPLICA_KEYS`. HKDF derives the hop key (every request), the audit key (row MACs and the checkpoint) and the key of `replica-trust.json`.' },
  GATE_REPLICA_KEY_FILE: { default: 'unset', meaning: 'Replica: a file holding `GATE_REPLICA_KEY` (used when that is unset); the k8s component writes the pod\'s own key there.' },
  GATE_REPLICA_KEYS: { default: 'unset (no replicas served)', meaning: 'Database node: the replicas it serves the signed state feed and audit ingestion, `id=key,id=key` (keys as in `GATE_REPLICA_KEY`); `prefix*=master` is a group: each id holds only HKDF(master, its id), from `scripts/ops/replica-key.ts`. Needs `DATABASE_URL` (docs/API.md §3.9.5).' },
  GATE_REPLICA_OF: { default: 'unset (not a replica)', meaning: 'This node is a stateless decision replica of the database nodes at this origin (https; plain http only on loopback): no `DATABASE_URL`, its own durable audit chain in `DATA_DIR`, everything it may not decide forwarded (docs/API.md §3.9.5).' },
  GATE_REPLICA_PIN: { default: 'unset (trust the JWKS over verified TLS)', meaning: 'Replica, first start only: comma-separated Ed25519 public keys (the `x` of `/.well-known/jwks.json` entries) the first snapshot must be signed by. Later rotations are followed through the introduction the old key signs; the trusted set and the rollback floor persist in `DATA_DIR/replica-trust.json` (MAC under `GATE_REPLICA_KEY`).' },
  GATE_PROFILE: { default: '`demo`', meaning: '`demo` or `production`; production refuses to start unless every check of docs/DEPLOY.md §5 holds. Any other value stops the process.' },
  HOST: { default: '`127.0.0.1`', meaning: 'Listen address. The demo profile refuses a non-loopback address (anything but `localhost`, `127.0.0.0/8`, `::1`) unless `DEMO_ALLOW_REMOTE` is on. On a non-loopback address `/metrics` needs `METRICS_TOKEN` in every profile.' },
  IMPACT_MAX_EVALUATIONS: { default: '100000', meaning: 'Upper bound on affected-cell evaluations in an impact preview or proposal, after network and maker/history variants; positive integer. Read at the first proposal, not at start.' },
  INITIAL_CREDENTIALS_TTL_SECONDS: { default: '3600', meaning: 'Lifetime of the first-start bootstrap credentials; integer in 1..86400.' },
  METRICS_TOKEN: { default: 'unset (`/metrics` open on a loopback address, 403 on any other)', meaning: 'Bearer token required on `GET /metrics`; the production profile requires at least 32 characters.' },
  OIDC_ACR: { default: 'unset', meaning: 'When set, sent as `acr_values` and the ID token\'s `acr` must equal it; otherwise `amr` must show MFA.' },
  OIDC_CLIENT_ID: { default: 'none (required with `OIDC_ISSUER`)', meaning: 'OIDC client id of the console.' },
  OIDC_CLIENT_SECRET: { default: 'unset', meaning: 'OIDC client secret, for a confidential client.' },
  OIDC_ID_CLAIM: { default: 'none (required with `OIDC_ISSUER`)', meaning: 'ID token claim that carries the subject id your applications use (`email` also needs `email_verified`).' },
  OIDC_ISSUER: { default: 'unset (local password accounts)', meaning: 'OIDC issuer for console sign-in (https, or http on loopback); needs `PUBLIC_ORIGIN`.' },
  OIDC_ROLE_CLAIM: { default: '`roles`', meaning: 'ID token claim that carries the console roles.' },
  OPENSSL: { default: '`openssl`', meaning: 'OpenSSL binary used to verify timestamp tokens against `TSA_CA_FILE`.' },
  OTEL_EXPORTER_OTLP_ENDPOINT: { default: 'unset (no tracing)', meaning: 'OTLP/HTTP JSON trace collector; `/v1/traces` is appended. http(s), no credentials, query or fragment; the production profile accepts plain http only on loopback.' },
  OTEL_SERVICE_NAME: { default: '`gate-pdp`', meaning: 'Service name on exported spans.' },
  PASSWORD_LOGIN: { default: 'on without an IdP, off with OIDC or SAML', meaning: 'Local password sign-in (`1`, `on`, `true`, `yes` turn it on).' },
  PEP_ROTATION_GRACE_SECONDS: { default: '300', meaning: 'Seconds a rotated PEP API key keeps working; integer in 0..86400.' },
  POLICY_SIGNATURE_ADOPT: { default: 'off', meaning: 'Adopts (signs) a stored policy bundle whose signature does not verify, once, after a restore. Refused by the production profile.' },
  PORT: { default: '8787', meaning: 'Listen port, 0..65535.' },
  PUBLIC_ORIGIN: { default: 'unset', meaning: 'External origin (https, or http on loopback) for cookies, HSTS, the OIDC redirect and the SAML endpoints; required with OIDC or SAML.' },
  RESOURCE_OWNERS: { default: 'unset', meaning: 'JSON object: console user id -> array of resource owner ids it answers for (demo: `{"ruth":["carol"]}`).' },
  RESOURCE_PENDING_PROPOSALS_PER_PEP: { default: '100', meaning: 'Resource registration: `register_resources` changes one PEP credential may have awaiting review at once; a call that would queue another is refused with `409 proposal_limit` (docs/API.md §2.2). Positive integer.' },
  SAML_ACS_URL: { default: '`PUBLIC_ORIGIN` + `/admin/v1/saml/acs`', meaning: 'Assertion consumer service URL the IdP posts to and the bearer `Recipient` must name (https, path `/admin/v1/saml/acs`).' },
  SAML_AUTHN_CONTEXT: { default: 'none (required with `SAML_IDP_ENTITY_ID`)', meaning: 'Comma-separated `AuthnContextClassRef` values that prove multi-factor authentication at the IdP: requested (exact), and every `AuthnStatement` must carry one, else `mfa_required`.' },
  SAML_DECRYPTION_KEY_FILE: { default: 'unset', meaning: 'Mounted PEM RSA 2048+ private key for encrypted assertions; requires matching SAML_DECRYPTION_CERT_FILE. Never published or logged.' },
  SAML_DECRYPTION_CERT_FILE: { default: 'unset', meaning: 'Matching PEM certificate for the assertion decryption key; published as the encryption certificate in SP metadata.' },
  SAML_SIGNING_KEY_FILE: { default: 'unset', meaning: 'Mounted PEM RSA 2048+ private key for outgoing SAML Redirect signatures (SHA-256); requires matching SAML_SIGNING_CERT_FILE.' },
  SAML_SIGNING_CERT_FILE: { default: 'unset', meaning: 'Matching PEM certificate for the SP signing key; published in SP metadata.' },
  SAML_IDP_SLO_URL: { default: 'unset (local sign-out only)', meaning: 'Pinned IdP SingleLogoutService HTTP-Redirect URL (https or loopback); requires SP signing key and certificate. Enables SP-initiated logout and LogoutResponse replies.' },
  SAML_ID_ATTRIBUTE: { default: 'none (required with `SAML_IDP_ENTITY_ID`)', meaning: 'Assertion attribute that carries the subject id your applications use, compared as is; `NameID` uses the subject NameID.' },
  SAML_IDP_CERT_FILE: { default: 'none (required with `SAML_IDP_ENTITY_ID`)', meaning: 'PEM file with the IdP signing certificate(s), pinned (RSA 2048+ or EC); IdP metadata is never fetched.' },
  SAML_IDP_ENTITY_ID: { default: 'unset (no SAML sign-in)', meaning: 'SAML 2.0 IdP entity id for console sign-in: the `Issuer` every assertion and logout request must carry; needs `PUBLIC_ORIGIN`.' },
  SAML_IDP_SSO_URL: { default: 'none (required with `SAML_IDP_ENTITY_ID`)', meaning: 'IdP SingleSignOnService URL, HTTP-Redirect binding (https, or http on loopback).' },
  SAML_MAX_AUTH_AGE_SECONDS: { default: '43200 (12 h)', meaning: 'Longest time since the IdP authenticated the user (`AuthnInstant` of every `AuthnStatement`), 60..604800 seconds.' },
  SAML_ROLE_ATTRIBUTE: { default: '`roles`', meaning: 'Assertion attribute that carries the console roles.' },
  SAML_SP_ENTITY_ID: { default: '`PUBLIC_ORIGIN` + `/admin/v1/saml/metadata`', meaning: 'Entity id of the console as a SAML service provider: the audience assertions must name.' },
  SCIM_BEARER_TOKEN: { default: 'unset', meaning: 'Bearer credential for `/scim/v2` (32..256 characters), set from the environment instead of minted in the console.' },
  SCIM_DIRECT: { default: 'off', meaning: 'Applies SCIM changes directly instead of as two-person changes; requires `SCIM_BEARER_TOKEN`.' },
  SCIM_GROUP_ROLES: { default: 'unset', meaning: 'JSON object: SCIM group name -> PDP role, one group per role.' },
  SIEM_BATCH_SIZE: { default: '100', meaning: 'Audit rows per SIEM push; 1..1000.' },
  SIEM_HMAC_SECRET: { default: 'unset', meaning: 'HMAC secret for SIEM pushes, at least 32 characters; set together with `SIEM_WEBHOOK_URL`.' },
  SIEM_INTERVAL_SECONDS: { default: '30', meaning: 'Seconds between SIEM pushes; 1..86400.' },
  SIEM_WEBHOOK_URL: { default: 'unset (no push export)', meaning: 'https receiver of the audit push export.' },
  SIGNING_KEY_SEAL: { default: 'unset', meaning: '32 bytes as base64url or 64 hex characters: seals the signing keyring and TOTP secrets, keys the audit checkpoint HMAC. Required with PostgreSQL (unless `ALLOW_CLEAR_SIGNING_KEYS`), for TOTP, and by the production profile.' },
  SIGNING_KEY_SEAL_PREVIOUS: { default: 'unset', meaning: 'Seal key rotation only: the old `SIGNING_KEY_SEAL`, set together with the new one. The start re-seals under the new key everything only the old one opens (signing keyring, TOTP secrets, audit checkpoint) and audits `seal_key_rotated`; remove it afterwards. A start where a sealed value opens under neither key is refused and changes nothing (docs/handbook/operations/rotate-credentials.md).' },
  SOD_HISTORY: { default: '`server`', meaning: '`server` ignores caller-supplied maker and history for SoD-constrained actions in every profile. `caller` is an explicit compatibility opt-in for demos/tests and logs a warning; production refuses it.' },
  TLS_CERT_FILE: { default: 'unset', meaning: 'PEM certificate; with `TLS_KEY_FILE` the node serves https itself.' },
  TLS_KEY_FILE: { default: 'unset', meaning: 'PEM private key for `TLS_CERT_FILE`.' },
  RATE_LIMIT_PER_MINUTE: { default: '120', meaning: 'Requests a minute per client address and per signed-in principal on the console, SCIM and public routes (token bucket, 429 with Retry-After). Cluster mode leases capacity from the shared PostgreSQL bucket; other modes use one local bucket per node. A replica (`GATE_REPLICA_OF`) keeps local buckets: set its share (docs/API.md §3.9.5).' },
  PEP_RATE_LIMIT_PER_MINUTE: { default: '60000', meaning: 'Decisions a minute per PEP credential and per client address on the decision plane (`/access/*`, `/x/*`, `/xacml/v3/authorize`); a batch costs one per item. At least 1000, the largest batch. Cluster mode leases capacity from the shared PostgreSQL bucket; a replica keeps local buckets at its share.' },
  TRUSTED_PROXIES: { default: 'unset (no proxy trusted)', meaning: 'Comma-separated addresses or CIDR ranges of the reverse proxies in front of the node. Only from such a peer is the client address read from `X-Forwarded-For` (its rightmost untrusted entry), for the per-IP rate limit, login lockout, sign-in audit rows and request spans.' },
  TSA_CA_FILE: { default: 'unset', meaning: 'CA file the timestamp tokens are verified against (OpenSSL). Required by the production profile.' },
  TSA_URL: { default: 'unset (no anchoring)', meaning: 'RFC 3161 timestamp authority for the audit head. The production profile requires https.' },
  WORLD_DIR: { default: '`examples/toy-domain`', meaning: 'Seed `bundle.json` and `world.json`, read only when no stored state exists yet (first start). The production profile refuses a world marked `"demo": true` (the shipped examples) unless `ALLOW_DEMO_WORLD` is on.' },
};

/** Variables the operations scripts read (scripts/ops: backup, restore, archive encryption), docs/DEPLOY.md §4. */
const OPS_DOCS: Record<string, Doc> = {
  AUDIT_RETENTION_DAYS: { default: 'none (required by audit-retention.ts)', meaning: '`audit-retention.ts`: expired-prefix age in days, 1..36500. Stop every Qadamar writer and use the owner role; the service role is never granted audit DELETE.' },
  BACKUP_ENCRYPTION_KEY: { default: 'none (required)', meaning: 'AES-256-GCM key of the backup archives, 32 bytes as 64 hex characters or unpadded base64url. `backup.sh` encrypts and `restore.sh` refuses an archive that does not authenticate under it. Keep it apart from the archives and from the database.' },
  BACKUP_FILE: { default: 'none (required)', meaning: 'Archive path: written by `backup.sh` (never overwritten), read by `restore.sh`.' },
  DATABASE_URL: { default: 'none (required)', meaning: '`backup.sh`: the database to dump (a role that bypasses RLS); `restore.sh`: the NEW database to create and restore into (the owner role). TLS URL parameters are refused; use `DATABASE_TLS`.' },
  DATABASE_TLS: { default: '`verify-full`, `require` with `GATE_PROFILE=demo`', meaning: 'PostgreSQL TLS policy of `database-tls.ts`, `migrate-records.ts` and `audit-retention.ts`, exported as libpq settings by `backup.sh` and `restore.sh`. Production requires `verify-full` for every non-local target or maintenance host.' },
  DATABASE_TLS_CA_FILE: { default: 'unset (system CA store)', meaning: 'PEM CA bundle for `DATABASE_TLS=verify-full`; maps to `PGSSLROOTCERT` (`system` when unset, which needs libpq 16 or later; the ops image has 17).' },
  DATABASE_TLS_CERT_FILE: { default: 'unset', meaning: 'Optional PEM PostgreSQL client certificate for the operations tools; set with `DATABASE_TLS_KEY_FILE`.' },
  DATABASE_TLS_KEY_FILE: { default: 'unset', meaning: 'PEM private key for `DATABASE_TLS_CERT_FILE`; set together.' },
  GATE_PROFILE: { default: '`production`', meaning: 'Operations database tools default to `production` (`verify-full`, and any weaker policy refused for a non-local database) unless `GATE_PROFILE=demo` is set explicitly.' },
  MAINTENANCE_DATABASE_URL: { default: 'the target URL with database `postgres`', meaning: '`restore.sh`: the database to connect to while creating (or removing after a failure) the target.' },
  SIGNING_KEY_SEAL: { default: 'none (required by audit-retention.ts)', meaning: '`audit-retention.ts`: the deployment seal, used only through the HKDF-derived audit checkpoint key to authenticate new segment seals.' },
  SIGNING_KEY_SEAL_PREVIOUS: { default: 'unset', meaning: '`audit-retention.ts`: previous deployment seal during rotation; old segment HMACs are verified and re-keyed by the owner before nodes restart with only the new seal.' },
  TSA_CA_FILE: { default: 'unset', meaning: '`audit-retention.ts`: CA bundle used to verify the RFC 3161 anchor of the sealed heads when `TSA_URL` is set.' },
  TSA_URL: { default: 'unset (HMAC only)', meaning: '`audit-retention.ts`: RFC 3161 authority that timestamps the sealed heads before any audit prefix is deleted.' },
};

const READ = /\bprocess\.env\.([A-Z][A-Z0-9_]*)|\benv\.([A-Z][A-Z0-9_]*)|\benv\[\s*['"]([A-Z][A-Z0-9_]*)['"]\s*\]/g;
// a read by computed name cannot be checked: refused, so every variable stays greppable
const DYNAMIC = /\b(?:process\.env|env)\[\s*(?!['"])/;

export interface Scan { reads: Map<string, Set<string>>; dynamic: string[] }
export function scan(files: ReadonlyArray<{ path: string; text: string }>): Scan {
  const reads = new Map<string, Set<string>>(); const dynamic: string[] = [];
  for (const { path, text } of files) {
    for (const m of text.matchAll(READ)) {
      const name = m[1] ?? m[2] ?? m[3] ?? '';
      reads.set(name, (reads.get(name) ?? new Set()).add(path));
    }
    text.split('\n').forEach((line, i) => { if (DYNAMIC.test(line)) dynamic.push(`${path}:${i + 1}`); });
  }
  return { reads, dynamic };
}

// self-check of the scanner
{
  const s = scan([{ path: 'a.ts', text: "process.env.PORT; env.HOST ?? x; env['TLS_KEY_FILE']; env.subject; const e = env[name];" }]);
  assert.deepEqual([...s.reads.keys()].sort(), ['HOST', 'PORT', 'TLS_KEY_FILE']);
  assert.deepEqual(s.dynamic, ['a.ts:1']);
  assert.deepEqual([...'x="${BACKUP_FILE:?set it}" ${MAINTENANCE_DATABASE_URL:-} ${TABLES[@]} ${BACKUP_FILE%/*} $HOME'.matchAll(/\$\{([A-Z][A-Z0-9_]*):[?-]/g)].map((m) => m[1]),
    ['BACKUP_FILE', 'MAINTENANCE_DATABASE_URL']);
}

function sources(): Array<{ path: string; text: string }> {
  const out: Array<{ path: string; text: string }> = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.ts')) out.push({ path: relative(ROOT, full), text: readFileSync(full, 'utf8') });
    }
  };
  for (const pkg of readdirSync(join(ROOT, 'packages')).sort()) {
    try { walk(join(ROOT, 'packages', pkg, 'src')); } catch (err) { if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err; }
  }
  return out;
}

/** scripts/ops: `${NAME:?...}` / `${NAME:-...}` inputs of the shell scripts, environment reads of the TypeScript. */
const SHELL_INPUT = /\$\{([A-Z][A-Z0-9_]*):[?-]/g;
function opsReads(): Map<string, Set<string>> {
  const reads = new Map<string, Set<string>>();
  const dir = join(ROOT, 'scripts/ops');
  for (const name of readdirSync(dir).sort()) {
    const path = `scripts/ops/${name}`; const text = readFileSync(join(dir, name), 'utf8');
    const found = name.endsWith('.ts') ? scan([{ path, text }]).reads.keys() : [...text.matchAll(SHELL_INPUT)].map((m) => m[1]!);
    for (const variable of found) reads.set(variable, (reads.get(variable) ?? new Set()).add(path));
  }
  return reads;
}

function rows(reads: Map<string, Set<string>>, docs: Record<string, Doc>, prefix: RegExp): string[] {
  return [...reads.keys()].sort().map((name) => {
    const doc = docs[name]!;
    const where = [...reads.get(name)!].sort().map((p) => `\`${p.replace(prefix, '')}\``).join(', ');
    return `| \`${name}\` | ${doc.default} | ${doc.meaning} | ${where} |`;
  });
}

function render(reads: Map<string, Set<string>>, ops: Map<string, Set<string>>): string {
  const server = rows(reads, DOCS, /^packages\//);
  const scripts = rows(ops, OPS_DOCS, /^scripts\/ops\//);
  return [
    '# Configuration',
    '',
    '<!-- Generated by scripts/docs/env-table.ts from the variables read in packages/*/src. Do not edit by hand:',
    '     change the DOCS table in the script and run `node scripts/docs/env-table.ts`. CI runs it with --check. -->',
    '',
    `Every environment variable the server reads (${server.length}). Unset means the feature is off unless the default says`,
    'otherwise. Flags accept `1`, `on`, `true` or `yes`. The production profile\'s requirements are in',
    '[DEPLOY.md](DEPLOY.md) §5; the release process\'s own variables are in [RELEASE.md](RELEASE.md).',
    '',
    '| Variable | Default | Meaning | Read in (`packages/`) |',
    '|---|---|---|---|',
    ...server,
    '',
    '## Operations scripts',
    '',
    `Backup and restore (\`scripts/ops\`, docs/DEPLOY.md §4; the managed offer passes them from Secrets, docs/MANAGED-OFFER.md) (${scripts.length}).`,
    '',
    '| Variable | Default | Meaning | Read in (`scripts/ops/`) |',
    '|---|---|---|---|',
    ...scripts,
    '',
    'Not read by the server or the operations scripts, used by tests and tools only: `TEST_DATABASE_URL` and',
    '`PG_TOOLS_CONTAINER` (live PostgreSQL tests, docs/QUALITY.md), `BACKUP_TESTS_REQUIRED=1` (fail rather than skip',
    'backup drills without client tools; set by CI when `PG_TOOLS_CONTAINER` is present), `FUZZ_SEED` and `FUZZ_RUNS`',
    '(`packages/core/test/fuzz.test.ts`), `IMPACT_FUZZ_RUNS` (`packages/pdp-http/test/impact.test.ts`),',
    '`E2E_REQUIRED` (missing Chromium is fatal), `PLAYWRIGHT_CORE_PATH` / `PLAYWRIGHT_CORE` (local browser driver),',
    '`PLAYWRIGHT_BROWSERS_PATH` (browser cache) and `CI_CHROMIUM_SHA256` (CI browser archive pin, docs/CI.md),',
    '`PDP_URL` (console dev server proxy, `apps/admin/vite.config.ts`),',
    '`GATE_K8S_TEST` and `GATE_K8S_CONTEXT` (`packages/pdp-http/test/k8s.test.ts`).',
    '',
  ].join('\n');
}

const { reads, dynamic } = scan(sources());
const ops = opsReads();
const mismatches = (found: Map<string, Set<string>>, docs: Record<string, Doc>): string[] => [
  ...[...found.keys()].filter((n) => !Object.hasOwn(docs, n)).map((n) => `read but not documented: ${n} (${[...found.get(n)!].join(', ')})`),
  ...Object.keys(docs).filter((n) => !found.has(n)).map((n) => `documented but not read: ${n}`),
];
const problems = [
  ...dynamic.map((at) => `computed environment read (name the variable): ${at}`),
  ...mismatches(reads, DOCS),
  ...mismatches(ops, OPS_DOCS),
];
if (problems.length) { console.error(`scripts/docs/env-table.ts:\n- ${problems.join('\n- ')}`); process.exit(1); }
const text = render(reads, ops);
if (process.argv.includes('--check')) {
  let current = '';
  try { current = readFileSync(OUT, 'utf8'); } catch { /* missing: reported below */ }
  if (current !== text) { console.error('docs/CONFIGURATION.md is stale: run node scripts/docs/env-table.ts'); process.exit(1); }
  console.log(`docs/CONFIGURATION.md: ${reads.size} server and ${ops.size} operations variables, in step with packages/*/src and scripts/ops`);
} else {
  writeFileSync(OUT, text);
  console.log(`wrote docs/CONFIGURATION.md (${reads.size} server and ${ops.size} operations variables)`);
}
