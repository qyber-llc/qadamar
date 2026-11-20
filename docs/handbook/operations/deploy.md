# Deploy Qadamar

This runbook was written against commit b09bc44 (after 0.3.0) and last revised, before this sentence was added, in commit 1869f97 (2026-11-11, first released in 0.10.0); later releases are not reviewed here (see CHANGELOG.md). It deploys Qadamar as a file-backed demonstration, a PostgreSQL active/standby pair, a cluster of deciding nodes, or one tenant of the managed offer on Kubernetes. Production requires an owner role that creates the schema and a separate least-privilege service role; the supplied Compose file does not pass the production preflight as shipped.

## On this page

- [Choose the deployment](#choose-the-deployment)
- [Verify the release you deploy](#verify-the-release-you-deploy)
- [Prepare prerequisites](#prepare-prerequisites)
- [Run a file-backed demonstration](#run-a-file-backed-demonstration)
- [Prepare PostgreSQL for production](#prepare-postgresql-for-production)
- [Configure and start production](#configure-and-start-production)
- [Deploy in cluster mode](#deploy-in-cluster-mode)
- [Deploy the managed offer on Kubernetes](#deploy-the-managed-offer-on-kubernetes)
- [Verify the deployment](#verify-the-deployment)
- [Troubleshoot startup refusal](#troubleshoot-startup-refusal)

## Choose the deployment

| Deployment | Use | Storage and availability |
| --- | --- | --- |
| File-backed demo | Local evaluation, policy testing, console walkthrough | One process and `DATA_DIR`. No standby, no cross-file transaction. |
| PostgreSQL active/standby | One serving node with automatic takeover | One active node holds the PostgreSQL advisory lock and serves. Standbys wait without an open port. |
| PostgreSQL cluster mode (`GATE_CLUSTER=true`) | Several nodes deciding at once | Every node serves the PDP API. One leader serves the admin plane (`/admin/`, `/scim/`). |
| `GATE_PROFILE=production` | Customer-facing or sensitive deployment | Applies to either PostgreSQL topology. Mandatory security preflight and full audit verification at every start. |
| Managed offer on Kubernetes | One dedicated instance per customer | Active/standby in `GATE_PROFILE=production`, with migration Job, backup CronJob, NetworkPolicies, and alert rules (`deploy/k8s`). |

## Verify the release you deploy

A release is three files built by `scripts/release/pack.sh` from a tagged commit: `qadamar-X.Y.Z.tar.gz`, the SBOM `qadamar-X.Y.Z.cdx.json` (CycloneDX 1.5, from `scripts/release/sbom.ts`), and `SHA256SUMS` ([docs/RELEASE.md](../../RELEASE.md)).

1. Check the checksums and read the build record:

   ```bash
   shasum -a 256 -c SHA256SUMS
   tar -xzf qadamar-X.Y.Z.tar.gz
   cat qadamar-X.Y.Z/BUILD-INFO
   ```

2. Confirm that `BUILD-INFO` names the expected commit and `dirty=false`.
3. Optional: rebuild the tarball from the commit with `SOURCE_DATE_EPOCH` from `BUILD-INFO` and compare SHA-256 values. Reproducibility was verified only with the same tar implementation (two bsdtar runs on one macOS machine); GNU tar produces different bytes ([Verifying a release](../../RELEASE.md#verifying-a-release-buyer)).
4. Feed the SBOM to your dependency scanner.

**Partial:** release signing. `pack.sh` runs the executable named by `RELEASE_SIGNING_HOOK` on `SHA256SUMS` when it is set. No signing tool or key is chosen, so releases are unsigned and checksums prove only that the files match the release page ([Signing](../../RELEASE.md#signing-owner-decision)). No container image is built or published; build it from the unpacked tarball.

## Prepare prerequisites

- Node.js 22.18 or later (`package.json` `engines`) and pnpm.
- PostgreSQL 17 for PostgreSQL mode, reached directly on the primary. Compose and the managed offer use PostgreSQL 17.
- PostgreSQL client tools of major version 17 or later for backup and restore.
- OpenSSL. The server runs `openssl ts -verify` on every anchor when `TSA_CA_FILE` is set; the runtime image includes it.
- A TLS-terminating proxy or load balancer, or PEM files for direct TLS.
- For production: an OIDC IdP that supplies MFA evidence and a console role claim, an RFC 3161 TSA and its CA bundle, a break-glass webhook receiver, and a metrics bearer token.
- A secret store for `SIGNING_KEY_SEAL`, `BACKUP_ENCRYPTION_KEY`, database credentials, the OIDC secret, HMAC secrets, and the metrics token.

To build and test from source:

```bash
pnpm install --frozen-lockfile
pnpm typecheck
pnpm --filter @product/admin build
pnpm test
pnpm --filter @product/admin test
```

The full CI gate also needs a throwaway PostgreSQL database. `bash tools/ci/local.sh` starts one in Docker, runs `tools/ci/checks.sh` against it, and removes its own labelled container.

## Run a file-backed demonstration

```bash
CLOCK=fixed:2026-11-08T10:00:00Z \
RESOURCE_OWNERS='{"ruth":["carol"]}' \
node packages/pdp-http/src/main.ts
```

Open `http://127.0.0.1:8787`. On first start, Qadamar writes generated local passwords and the bootstrap PEP key to `DATA_DIR/INITIAL-CREDENTIALS.txt` with mode 0600. The file is removed on the first successful sign-in or after `INITIAL_CREDENTIALS_TTL_SECONDS`, one hour by default (`packages/pdp-http/src/auth.ts`).

Do not expose this demonstration to an untrusted network. Its fixed clock, local accounts, unauthenticated metrics endpoint, and file persistence are not production controls. The demo profile listens on loopback only: another `HOST` is refused unless `DEMO_ALLOW_REMOTE=true` (it warns at start, and `/metrics` then needs `METRICS_TOKEN`).

The supplied Compose file starts PostgreSQL 17 and two Qadamar nodes, `gate-active` on `127.0.0.1:8787` and `gate-standby` on `127.0.0.1:8788`:

```bash
export POSTGRES_PASSWORD='<strong URL-safe password>'
export SIGNING_KEY_SEAL="$(openssl rand -hex 32)"
export METRICS_TOKEN="$(openssl rand -hex 32)"
docker compose up -d --build
```

Use it to evaluate takeover, not as a production deployment. Its database role owns the tables and is rejected by the production profile (`docker-compose.yml`, `packages/pdp-http/src/profile.ts`).

## Prepare PostgreSQL for production

### 1. Create separate roles

Create three roles through your database's secure administration process. Do not put passwords in command arguments or shell history.

| Role | Purpose | Requirement |
| --- | --- | --- |
| Owner | Creates and migrates the schema | Owns the `gate_*` tables. Never configured on a Qadamar node. |
| Service | `DATABASE_URL` of every Qadamar node | Not a superuser; no `BYPASSRLS` or `CREATEROLE`; does not own, or belong to the owner of, any Qadamar table; directly or through membership. |
| Backup | `DATABASE_URL` of `scripts/ops/backup.sh` | `SELECT` on every Qadamar table and `BYPASSRLS`, because `pg_dump` refuses tables with forced row-level security otherwise. Keep it separate from the service role, which must not have `BYPASSRLS`. |

### 2. Run the schema and grants as the owner

`SCHEMA` is idempotent. It creates eighteen tables: `gate_doc`, `gate_audit`, `gate_audit_meta`, `gate_anchor`, `gate_audit_segment`, `gate_subject_identity`, `gate_sync`, `gate_token`, `gate_performed`, `gate_session`, `gate_blp_mark`, `gate_blp_session`, `gate_retired`, `gate_subject`, `gate_resource`, `gate_tuple`, `gate_state_change`, and `gate_rate_limit`, with keys, indexes, forced row-level security, and policies. `serviceGrants` and `backupGrants` produce the role grants. All three are exported by `packages/pdp-http/src/postgres.ts` from `postgres-schema.ts`, and are what the managed offer's `gate-migrate` Job runs (`deploy/k8s/base/jobs.yaml`). A 0.6.0 database's records are imported by the first target start after this owner step; older archives are migrated by `restore.sh`.

```bash
export OWNER_DATABASE_URL='postgresql://owner@db.internal/gate'
node --input-type=module -e '
  import pg from "pg";
  import { SCHEMA, serviceGrants, backupGrants } from "./packages/pdp-http/src/postgres.ts";
  const client = new pg.Client({ connectionString: process.env.OWNER_DATABASE_URL });
  await client.connect();
  try {
    await client.query("BEGIN");
    await client.query(SCHEMA);
    await client.query(serviceGrants(client.escapeIdentifier("gate_service")));
    await client.query(backupGrants(client.escapeIdentifier("gate_backup")));
    await client.query("COMMIT");
  } finally { await client.end(); }
'
```

Replace `gate_service` and `gate_backup` with your role names. The service role receives:

| Tables | Privileges |
| --- | --- |
| `gate_doc`, `gate_audit_meta` | `SELECT, INSERT, UPDATE` |
| `gate_audit`, `gate_anchor`, `gate_performed`, `gate_retired`, `gate_state_change` | `SELECT, INSERT` |
| `gate_audit_segment` | `SELECT` |
| `gate_sync` | `SELECT, UPDATE` |
| `gate_subject_identity`, `gate_token`, `gate_session`, `gate_blp_mark`, `gate_blp_session`, `gate_subject`, `gate_resource`, `gate_tuple`, `gate_rate_limit` | `SELECT, INSERT, UPDATE, DELETE` |

Do not grant `UPDATE`, `DELETE`, or `TRUNCATE` on `gate_audit`, `gate_anchor`, `gate_audit_segment`, or `gate_performed`; the production preflight refuses them. `SCHEMA` revokes those privileges from the owner that runs it, but an owner can grant them back, so keep the owner role out of runtime configuration. The service role can still update documents and derived metadata, so its compromise can cause an integrity denial of service.

### 3. Configure database availability and protection

Qadamar does not provide database replication or failover, encryption at rest, WAL archiving, or off-site backup. Configure these in the hosting environment ([docs/DEPLOY.md §4](../../DEPLOY.md#point-in-time-recovery-the-hostings)). Point `DATABASE_URL` at the primary, not a replica or a transaction-mode pooler: Qadamar holds session advisory locks.

Set `DATABASE_TLS=verify-full` (the production default) and make the database certificate name that host. Use `DATABASE_TLS_CA_FILE` for a private CA, or the system CA store otherwise. Optional `DATABASE_TLS_CERT_FILE` and `DATABASE_TLS_KEY_FILE` enable mutual TLS and must be set together. URL `ssl*` parameters are refused. `require` encrypts without authenticating the server; `disable` is only for non-production or loopback/unix-socket targets. Migration, retention, backup and restore use the same settings.

## Configure and start production

### 1. Register OIDC

Register these URLs at the IdP:

```text
Redirect URI: https://gate.example/admin/v1/oidc/callback
Back-channel logout: https://gate.example/admin/v1/oidc/backchannel-logout
```

Choose `OIDC_ID_CLAIM` so its value matches application subject IDs exactly. Require MFA through `OIDC_ACR`, or make the IdP put `mfa` or `mca` in `amr`. Map only recognised console roles through `OIDC_ROLE_CLAIM` (`packages/pdp-http/src/oidc.ts`).

If local recovery accounts stay enabled, every one needs active TOTP before production. Enrol them in a controlled demo-profile start against the same database with `SIGNING_KEY_SEAL` set. The production refusal lists every account without active TOTP (`packages/pdp-http/src/profile.ts`).

### 2. Set the environment

This is a checklist, not a secret-management template. Inject values from your secret store and never log them. Every variable is described in [docs/CONFIGURATION.md](../../CONFIGURATION.md); the profile checks are in [Configuration reference](configuration.md#production-profile-requirements).

```bash
export GATE_PROFILE=production
export HOST=0.0.0.0
export PORT=8787
export PUBLIC_ORIGIN=https://gate.example
export TRUSTED_PROXIES='10.0.0.0/24'   # your proxy or ingress addresses
export DATABASE_URL='postgresql://gate_service@db.internal/gate'
export DATABASE_TLS=verify-full
export DATABASE_TLS_CA_FILE=/run/secrets/postgres-ca.pem  # omit when the system CA store issues the database certificate
export SIGNING_KEY_SEAL='<32 bytes as base64url or 64 hex>'
export SOD_HISTORY=server
export METRICS_TOKEN='<at least 32 characters>'

export OIDC_ISSUER=https://idp.example/tenant
export OIDC_CLIENT_ID=gate-console
export OIDC_ID_CLAIM=sub
export OIDC_ROLE_CLAIM=roles
# Set OIDC_ACR, or rely on amr=mfa/mca. Set OIDC_CLIENT_SECRET only for a confidential client.

export TSA_URL=https://tsa.example/rfc3161
export TSA_CA_FILE=/run/secrets/tsa-ca.pem
export BREAK_GLASS_WEBHOOK=https://hooks.example/break-glass
export BREAK_GLASS_WEBHOOK_SECRET='<at least 32 characters>'
```

Set `TLS_CERT_FILE` and `TLS_KEY_FILE` together only when Qadamar terminates TLS itself. Otherwise terminate TLS at the proxy and keep the Qadamar listener on a private network. `PUBLIC_ORIGIN` drives Secure cookies, HSTS, the OIDC redirect, and discovery.

### 3. Set `TRUSTED_PROXIES` behind a proxy

Set `TRUSTED_PROXIES` to the addresses or CIDR ranges your reverse proxy, load balancer, or ingress controller connects from. Without it, Qadamar takes the proxy's address as every client's address. In 0.3.0, which had no such setting, all clients behind a proxy therefore shared one per-IP rate-limit bucket of 120 requests per minute, and the audit recorded the proxy's address.

With `TRUSTED_PROXIES`, Qadamar reads `X-Forwarded-For` only from a listed peer and takes the rightmost untrusted entry as the client address (`packages/pdp-http/src/proxy.ts`). List only addresses from which nothing but your proxies can connect. The production profile does not check this setting. See [Reverse proxy settings](configuration.md#reverse-proxy-settings).

### 4. Start the active and standby processes

Build the image, or use the same source tree and built console, on every node. The `Dockerfile` runs as uid 1000, exposes 8787, keeps the root filesystem read-only-compatible except `DATA_DIR=/var/lib/gate`, stops on SIGTERM, and health-checks `GET /healthz`.

Start every node with the same shared configuration and the same `SIGNING_KEY_SEAL`. In production each node runs the preflight, then waits for the advisory lock. The first to take it loads and verifies state and audit, then opens its port. The others stay blocked before listening; this is normal (`packages/pdp-http/src/server.ts`, `postgres.ts`). A waiting standby exits at once on SIGTERM (`packages/pdp-http/src/main.ts`).

When the service role does not own the tables, a node never migrates the schema: run `SCHEMA` as the owner before every upgrade ([Upgrade Qadamar](upgrade.md)).

Do not set `ALLOW_CLEAR_SIGNING_KEYS`, `POLICY_SIGNATURE_ADOPT`, `CLOCK`, or `SCIM_DIRECT` as a routine production override. The first three cause production refusal; `SCIM_DIRECT` removes two-person review of provisioning.

## Deploy in cluster mode

Cluster mode runs several deciding nodes against one PostgreSQL database. Set it up on top of the production steps above.

1. On every node, set `GATE_CLUSTER=true` and a unique `GATE_NODE_ID`. Each node writes its own audit chain. A second process started with an id already in use waits, like a standby, until the first stops.
2. Set `GATE_ADVERTISE_URL` on every node to the address the admin plane is reachable at when that node leads. Followers return it in their `409 not_leader` answers.
3. Optionally set `GATE_MAX_STALENESS_MS` (default 2000, range 100 to 60000).
4. Start the nodes. Every node opens its port. One takes the leader lock and serves the admin plane.
5. Configure the load balancer:

   | Requests | Pool | Health check |
   | --- | --- | --- |
   | `/access/`, `/x/`, `/xacml/` | Every node | `GET /readyz` (503 while the node is past its staleness bound) |
   | `/admin/`, `/scim/`, including `/admin/v1/oidc/` | The node whose `GET /leaderz` returns 200 | `GET /leaderz` (503 on followers) |

A follower answers every `/admin/` and `/scim/` request with `409` and `{"error":"not_leader","message":"...","leader":<GATE_ADVERTISE_URL of the leader, or null>}` (`packages/pdp-http/src/router.ts`). When the leader stops, followers keep deciding and one of them takes the leader lock ([Fail over the active node](failover.md#leader-change-in-cluster-mode)).

Set the same `RATE_LIMIT_PER_MINUTE` and `PEP_RATE_LIMIT_PER_MINUTE` on every node. Cluster nodes lease small batches from shared `gate_rate_limit` buckets and make no database call per request while a lease lasts. Leases cannot overspend; at most N(B−1) unused tokens per key can temporarily under-admit. On an existing database, run `SCHEMA` and `serviceGrants` as the owner before starting the cluster to add this disposable table.

Anchoring, SIEM export, and break-glass expiry notices run only on the leader (`packages/pdp-http/src/server.ts`). Without `GATE_CLUSTER`, PostgreSQL mode keeps the active/standby behaviour. Scaling figures and their conditions are in [Capacity and performance](capacity.md#multi-node-scaling-in-cluster-mode).

## Deploy the managed offer on Kubernetes

The managed offer runs one dedicated Qadamar per customer in its own namespace `gate-<tenant>`, in `GATE_PROFILE=production`, as an active/standby pair (two pods; the base manifests do not set `GATE_CLUSTER`). The full runbook is [docs/MANAGED-OFFER.md](../../MANAGED-OFFER.md); this section summarises it.

| Path | Content |
| --- | --- |
| `deploy/k8s/base` | Namespace (Pod Security `restricted`), Deployment of 2 pods, Service, TLS Ingress, PodDisruptionBudget, NetworkPolicies, `gate-migrate` Job, `gate-backup` CronJob and its volume |
| `deploy/k8s/overlays/local` | Local test only: in-cluster PostgreSQL 17 and test stand-ins for the IdP, TSA, and break-glass receiver |
| `deploy/k8s/monitoring/alerts.yaml` | Prometheus Operator alert rules ([Monitoring and alerts](monitoring.md#alert-rules-shipped-for-kubernetes)) |
| `scripts/managed/new-tenant.sh <tenant>` | Creates or completes a tenant: namespace, Secrets (generated by the local overlay; created by you otherwise), migration, server, one ready pod, bootstrap PEP key into Secret `gate-initial-credentials`. Idempotent: existing Secrets are kept. `KUBE_CONTEXT` and `OVERLAY` select the cluster and overlay. |
| `scripts/managed/smoke.sh <tenant>` | End-to-end check of a local-overlay tenant: production profile, probes, PEP decision, OIDC with MFA, break-glass notice, anchoring, two failovers, cold start, backup, and a restore drill |
| `scripts/managed/delete-tenant.sh <tenant> --yes` | Removes the tenant's namespace and everything in it, irreversibly. Managed databases and off-site backups are not touched. |
| `scripts/managed/build-local-image.sh` | Offline build of `gate:local` and `gate-ops:local` |

The `ops` target of the `Dockerfile` builds the backup tools image (`gate-ops`): PostgreSQL client tools, Node.js, `backup.sh`, `restore.sh`, and `archive-crypt.ts`. The `gate-backup` CronJob runs it ([Back up and restore](backup-restore.md#managed-backups-on-kubernetes)).

**Partial:** the managed offer was proven end to end only on a local single-node Kubernetes cluster, against test stand-ins for the IdP, TSA, CA, and break-glass receiver. The provider-agnostic UAE sovereign overlay is rendered and tested but was never applied to a cloud, and `TRUSTED_PROXIES` was not exercised through a real ingress controller ([docs/MANAGED-OFFER.md §14](../../MANAGED-OFFER.md#14-not-covered-yet)).

## Verify the deployment

1. **Readiness:** `GET /readyz` returns 200 with `"status":"ready"` and `"audit":{"verified":true}`. With PostgreSQL the body also carries `role` and `node`. A waiting standby has no listening port.
2. **Leader:** in cluster mode, exactly one node returns 200 on `GET /leaderz`.
3. **Metrics:** `GET /metrics` without the token returns 401; with `Authorization: Bearer $METRICS_TOKEN` it returns Prometheus text including `gate_active_node 1`.
4. **Client address:** behind a proxy, sign in and confirm the sign-in audit row records the client's address in `details.client`, not the proxy's.
5. **OIDC:** sign in through the IdP and confirm that a login without MFA evidence or without a recognised role is refused.
6. **PEP decision:** use a named PEP credential for a known allow and a known deny. Stop using `bootstrap` once named credentials are deployed.
7. **Audit:** as an auditor or security officer, call `GET /admin/v1/audit/verify` and confirm `verified` is `true`.
8. **Anchoring:** after `ANCHOR_INTERVAL` and a changed head, check `GET /admin/v1/audit/anchors` and `gate_audit_last_anchor_age_seconds`.
9. **Break-glass webhook:** open a controlled test emergency and verify the receiver's HMAC, timestamp, and event ID handling.
10. **Failover:** complete [Fail over the active node](failover.md) before admitting production traffic.
11. **Recovery:** complete [Back up and restore](backup-restore.md) on a separate target.
12. **Bypass check:** confirm that the protected application cannot be reached around its PEP and that the gateway upstream is private.

## Troubleshoot startup refusal

| Symptom | Action |
| --- | --- |
| `GATE_PROFILE=production refused to start` | Read every listed item. Correct the settings and database-role findings, then restart. Do not weaken the preflight. |
| `tables missing from schema public` | Run `SCHEMA` as the owner role before starting nodes with the service role. |
| `The database schema is from an earlier version` | The tables predate cluster mode and belong to another role. Run `SCHEMA` and `serviceGrants` as the owner ([Upgrade Qadamar](upgrade.md)). |
| Role owns or belongs to the owner of a table | Use a service role with no owner membership and only the grants above. |
| `TRUSTED_PROXIES: invalid address or CIDR range` | Correct the list. Each entry is one IPv4 or IPv6 address or CIDR range. |
| `GATE_NODE_ID must be ...` or `GATE_MAX_STALENESS_MS must be an integer in 100..60000` | Correct the cluster setting. |
| Bundle signature does not verify | Check that the intended database and keyring are in use. Do not adopt until the bundle's provenance is checked; see [Upgrade Qadamar](upgrade.md#adopt-an-unsigned-or-orphaned-policy-signature). |
| Sealed keys cannot be read | Restore the exact `SIGNING_KEY_SEAL`. Root-key recovery is **Not available**. |
| Local account lacks TOTP | Enrol and activate TOTP in a controlled demo-profile window, or turn password sign-in off. |
| Standby appears unhealthy | Expected while it waits for the advisory lock: it has no port. Check its logs rather than restarting it repeatedly. |
| Readiness fails after startup | Treat as a storage, staleness, or audit-integrity problem. Keep the node out of traffic. If verification fails, follow [Respond to an audit tamper alert](audit-tamper-response.md). |

## Related pages

- [Configuration reference](configuration.md)
- [Upgrade Qadamar](upgrade.md)
- [Fail over the active node](failover.md)
- [Back up and restore](backup-restore.md)
- [Monitoring and alerts](monitoring.md)
- [Architecture overview](../architecture/overview.md)
- [Security architecture](../architecture/security-architecture.md)

## Deploying a tenant partition

Follow [docs/DEPLOY.md, Tenant partitions](../../DEPLOY.md#tenant-partitions). Mount the secret manifest, select ids
with `GATE_SERVE_TENANTS`, and provision independent PostgreSQL databases and service roles for those tenants.
Use distinct keys and data directories. Existing single-tenant stores can be assigned intact; do not divide their
relation graphs. Cluster leadership and audit chains remain local to each database, so probe `/leaderz` per tenant.
Replica source entries need the matching tenant-specific replica keys; replicas poll and ship audit only for selected
entries. Keep replica rate shares within the existing per-tenant budget.

Route `X-Qadamar-Tenant` to the assigned nodes and include it in every health/readiness/metrics probe. Override the
image’s headerless HEALTHCHECK. For browser sign-in use separate hostnames/public origins and inject the header
from the hostname at the trusted edge, including SSO callbacks. A 421 is a routing error; do not turn it into an
allow/deny decision or retry it against another tenant. Restart and drain nodes when changing assignment. Test
revocations, failover and audit ingestion for each assigned tenant before putting its partition into service.

### SAML alternative

For SAML with MFA, encrypted assertions and signed POST/Redirect single logout, follow the
[configuration runbook](configuration.md#saml-encryption-and-single-logout). Mount SP private keys from the secret
store and re-register metadata when certificates change. Test console Sign out and IdP-initiated logout through
the production ingress, including local session refusal afterwards. Keep callbacks routed to the admin leader.
