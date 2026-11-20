# Managed offer: one dedicated Qadamar per customer, on Kubernetes

Status (2026-11-10, main at b09bc44: cluster mode, encrypted backups, signed decision assertions): **proven end to end
in `GATE_PROFILE=production` on a local OrbStack Kubernetes cluster only** (`deploy/k8s/overlays/local`, tenant `demo`,
upgraded in place from the v0.3.0 image, §6; cluster mode in `overlays/local-cluster`, §6a). The local overlay replaces what a customer's
environment provides (IdP, time-stamp authority, break-glass receiver, certificates, managed database) with
**test-only stand-ins**, clearly marked. No cloud account, domain, price or customer is involved. Owner decisions
(cloud provider, domain names, prices, TSA vendor) are left as named **PARAMETERS** in the manifests and in §4. Every
figure below was measured on one laptop and is indicative; the objectives in §10 are a proposal (TO DECIDE), not
promises.

| Path | What |
|---|---|
| `deploy/k8s/base` | one tenant in `GATE_PROFILE=production`: Namespace (Pod Security `restricted`), Deployment of 2 Qadamar pods, Service, TLS Ingress, PodDisruptionBudget, NetworkPolicies, schema migration Job, backup CronJob and its volume |
| `deploy/k8s/overlays/local` | **local test only**: in-cluster PostgreSQL 17, Qadamar serving TLS itself, test OIDC provider (`test-idp/`), test RFC 3161 authority (`test-tsa/`), break-glass receiver (`test-webhook/`), local images, no Ingress (port-forward) |
| `deploy/k8s/components/cluster` | optional kustomize Component: cluster mode (`GATE_CLUSTER=true`), every pod deciding, a StatefulSet with stable node ids, admin plane forwarded to the leader (§6a) |
| `deploy/k8s/overlays/local-cluster` | **local test only**: the local overlay plus the cluster Component |
| `deploy/k8s/overlays/sovereign-uae` | provider-agnostic production overlay for a UAE sovereign cloud (§12): cluster mode, decision replicas with HPA, TLS everywhere, in-country placement, strict egress, images by digest; rendered and tested, never applied (no provider chosen) |
| `deploy/k8s/monitoring` | Prometheus Operator alert rules (`alerts.yaml`), one set for all tenants |
| `scripts/managed/new-tenant.sh`, `smoke.sh`, `delete-tenant.sh` | onboarding, end-to-end check (active/standby or cluster), removal |
| `scripts/managed/upgrade-tenant.sh` | upgrade to this checkout: stop the nodes, migrate as owner, start (§6) |
| `scripts/managed/local-test-pki.sh` | **local test only**: throwaway CA and certificates of one tenant |
| `scripts/managed/build-local-image.sh` | offline build of `gate:local` and `gate-ops:local` from the Dockerfile |
| `packages/pdp-http/test/k8s.test.ts` | renders base and overlays and asserts the security settings (`GATE_K8S_TEST=1`) |
| `scripts/audit/verify-export.ts` | the customer's offline check of an audit export: chain, heads, anchors, signature (§13) |

## 1. Architecture of one tenant

```
customer PEPs / admins ──https──▶ ingress controller (TLS, host = PARAMETER)
                                        │ X-Forwarded-For, believed only from TRUSTED_PROXIES (PARAMETER)
                                        │ (NetworkPolicy: only from the ingress namespace and the metrics scraper)
                                        ▼
                         Service gate:8787 ──▶ the Ready pod only
                         ┌──────────────────────────────┐
     namespace gate-<t>  │ gate pod A  (holds the lock)  │──┐
                         │ gate pod B  (standby, no port)│──┤ advisory lock + one transaction per request
                         └──────────────────────────────┘  ▼
                         backup CronJob ──pg_dump──▶  PostgreSQL 17 (managed, HA, PITR; in-cluster locally)
                              │                         ▲   state, audit, anchors AND the security material:
                              ▼                         │   signing keys (sealed), PEP credentials, lockouts,
                         backup volume                  │   SCIM credential, SIEM cursor (gate_doc)
                                       egress only to PostgreSQL, the IdP, the TSA, the break-glass receiver, DNS
```

- **Active/standby, as the code does it.** Both pods run the same image. The one that obtains the PostgreSQL session
  advisory lock loads state and audit and opens port 8787; the other blocks in `listen()` **without opening its port**.
  Readiness is `GET /readyz` (pending writes committed, audit chain verified), so only the active pod is Ready and the
  Service routes only to it. Checked in `smoke.sh`: one ready endpoint, and it is the active pod.
- **Cluster mode, optional** (`deploy/k8s/components/cluster`, §6a). With `GATE_CLUSTER=true` every pod decides
  against the shared PostgreSQL and is Ready; the lock holder is the leader and alone serves `/admin/` and `/scim/`,
  which followers forward to it, so the plain Service works for the console too.
- **Shared security material in PostgreSQL** (v0.3.0). Signing keyring (sealed with `SIGNING_KEY_SEAL`, required),
  PEP credentials, accounts, lockouts, the SCIM credential and the SIEM cursor are `gate_doc` rows: a failover keeps
  them, rotations and revocations hold on both pods, nothing is copied between pods. The kit's earlier `gate-data-dir`
  Secret and init container are gone. `DATA_DIR` (an emptyDir) holds only the one-time `INITIAL-CREDENTIALS.txt` of
  the first start, which `new-tenant.sh` copies into the Secret `gate-initial-credentials`.
- **Production profile.** `GATE_PROFILE=production`, `DATABASE_TLS=verify-full` and `SOD_HISTORY=server` are in the base
  ConfigMap: every start runs the checks of docs/DEPLOY.md §5 (https origin, OIDC with MFA, verified non-local database
  TLS, least-privilege database role, sealed keys, metrics token, TSA with its CA, break-glass webhook, no pinned clock)
  and refuses to start otherwise. Server, migration and backup pods can mount optional `gate-postgres-tls` files
  `ca.crt`, `tls.crt` and `tls.key`; path-valued keys `DATABASE_TLS_CA_FILE=/etc/gate/postgres/ca.crt`,
  `DATABASE_TLS_CERT_FILE=/etc/gate/postgres/tls.crt` and `DATABASE_TLS_KEY_FILE=/etc/gate/postgres/tls.key` select them.
  A public server certificate needs no mounted CA. The local PostgreSQL serves TLS with a throwaway certificate naming
  `postgres`, so the production transport check runs for real.
- **Client address behind the ingress.** `TRUSTED_PROXIES` (base ConfigMap, PARAMETER: the ingress controller's
  address range) makes the node take the client address from the rightmost untrusted `X-Forwarded-For` entry, for the
  per-IP rate limit, the login lockout, the audit and traces; from any other peer the header is ignored
  (docs/API.md §3.1.1). The NetworkPolicy lets only the ingress and scraper namespaces connect, so trusting the
  cluster's pod range is acceptable when the controller's own range is not fixed.
- **Probes.** Readiness `/readyz` every second (HTTPS when the node serves TLS). Liveness and startup are exec probes
  that accept a 200 from `/healthz` or a refused connection (standby waiting), over https when `TLS_CERT_FILE` is set,
  and fail on a timeout or an error status. A standby is never Ready: `kubectl get deploy` shows 1/2 and a rollout
  never reports "complete". Watch `GateNoActiveNode`, not the rollout status.
- **Pod hardening.** UID 1000, `runAsNonRoot`, read-only root filesystem, all capabilities dropped, no privilege
  escalation, seccomp `RuntimeDefault`, no service-account token, requests and limits on every container. Writable
  paths: `/var/lib/gate` (emptyDir) and `/tmp` (memory emptyDir; `openssl ts -verify` writes the token there).
- **Database roles** (docs/API.md §3.9.1): `gate_owner` owns the schema and runs it (Job `gate-migrate`);
  `gate_app`, the service role of the pods, is not a superuser, owns nothing, and has only the privileges of
  `serviceGrants` (`packages/pdp-http/src/postgres-schema.ts`): `SELECT, INSERT, UPDATE` on `gate_doc`,
  `gate_audit_meta`, `SELECT, INSERT` on `gate_audit`, `gate_anchor`, `gate_performed`, `SELECT` on
  `gate_audit_segment`, `SELECT, UPDATE` on `gate_sync`, and `DELETE` only on `gate_token`, `gate_session`,
  `gate_blp_mark` and the erasable `gate_subject_identity`; never on the audit or seals. `gate_backup` reads every gate table (`backupGrants`; `BYPASSRLS`: `pg_dump` refuses
  forced RLS otherwise).

## 2. Per-tenant isolation

| Layer | How |
|---|---|
| Kubernetes | one namespace `gate-<tenant>` with Pod Security `restricted` enforced; no RBAC granted to the tenant's service account, no API token mounted |
| Network | default deny in and out; in: port 8787 from the ingress controller's and the scraper's namespaces only; out: DNS, PostgreSQL (all Qadamar pods), IdP, TSA and break-glass receiver on 443 (server only) |
| Data | one PostgreSQL database (cloud: one instance or cluster) per tenant, own roles and passwords; own sealed signing keyring and seal key; own backup volume |
| Secrets | generated per tenant (`openssl rand`) and stored only in that namespace's Secrets; never printed by the scripts |
| Compute | requests/limits per pod; spread across zones and nodes (`topologySpreadConstraints`, `ScheduleAnyway`) |

Not isolated: the cluster's nodes and control plane are shared between tenants (dedicated node pools or clusters per
customer are a pricing decision, PARAMETER).

## 3. Images

The release image is built by the unchanged default of the Dockerfile (`node:22.20.0-alpine` plus the `openssl`
package, pnpm via corepack, network). The server needs the `openssl` command: it runs `openssl ts -verify` on every
anchor against `TSA_CA_FILE`, which production requires, and the node images do not ship it. Offline,
`scripts/managed/build-local-image.sh` builds the same Dockerfile with `RUNTIME_BASE=runtime-base-postgres`
(`postgres:17`, Debian, which ships openssl, plus the node binary of `node:22-bookworm-slim`; 846 MB, test only) and
passes the console bundle and the server's production dependencies, prepared from the local pnpm store, as named build
contexts. The `ops` target adds the backup tools image (PostgreSQL client 17 + `node` + `scripts/ops/backup.sh`, `restore.sh`
and `archive-crypt.ts`, UID 1000).

Found while building and running them: the runtime stage lacked `packages/sql` (the image could not start); the
runtime had no `openssl`; and anchor verification could never succeed on Linux, because the token was handed to
openssl as `/dev/stdin`, which OpenSSL cannot open when Node gives the child a socket (it worked on macOS, where the
tests run). All three are fixed (Dockerfile, `packages/pdp-http/src/anchor.ts`, test in `anchor.test.ts`).

## 4. Parameters (owner and cloud decisions)

| Parameter | Where | Default placeholder |
|---|---|---|
| Image registry and digest | `base/kustomization.yaml` `images` | `registry.example.invalid/gate:<version>`, `gate-ops:<version>` (base: the release tag; a non-local overlay must name a digest, `new-tenant.sh` refuses a tag) |
| Public host, TLS certificate Secret, ingress class | `base/gate.yaml` Ingress | `tenant.gate.example.invalid`, `gate-tls`, `nginx` |
| `PUBLIC_ORIGIN` | `base/kustomization.yaml` `gate-config` | `https://tenant.gate.example.invalid` |
| `TRUSTED_PROXIES` | `base/kustomization.yaml` `gate-config` | `192.0.2.64/26` (the ingress controller's range) |
| Ingress controller and scraper namespaces | `base/network-policies.yaml` | `ingress-nginx`, `monitoring` |
| PostgreSQL, IdP, TSA, break-glass receiver address ranges | `base/network-policies.yaml` | RFC 5737 documentation ranges (`new-tenant.sh` refuses to apply them) |
| PostgreSQL private CA and optional mutual-TLS client certificate | Secret `gate-postgres-tls`, mounted by server/migration/backup | `ca.crt`, `tls.crt`, `tls.key`; optional with a publicly trusted server certificate. `DATABASE_TLS=verify-full` always checks the hostname |
| IdP, TSA, break-glass receiver | Secrets `gate-oidc`, `gate-tsa`, `gate-break-glass` (§5) | none: required by the production profile |
| Backup schedule, retention, volume (bucket) | `base/jobs.yaml` | daily 02:17 UTC, 14 days, 1 Gi PVC |
| Tenant's first-start world (`world.json`, `bundle.json`) | `new-tenant.sh` `WORLD=<dir>` (ConfigMap `gate-world` at `WORLD_DIR=/etc/gate/world`), or the overlay's own `WORLD_DIR` | none: production refuses the image's demo world |
| Role names | `base/jobs.yaml` (`gate-migrate` env) | `gate_app`, `gate_backup` |
| Resources | `base/gate.yaml` | server 100m/192Mi, limit 1 CPU/512Mi |
| Alert thresholds | `monitoring/alerts.yaml` | see §8 |

A cloud overlay patches these, the way the local overlay patches the database and IdP/TSA egress rules.
`deploy/k8s/overlays/sovereign-uae` (§12) is the first one: provider-agnostic, every provider value still a PARAMETER.

## 5. Onboarding runbook

1. **Database (cloud).** Create the tenant's PostgreSQL 17 (§9) and the three roles of §1. In namespace
   `gate-<tenant>`, create the Secrets `gate-env` (`DATABASE_URL` = service role, `SIGNING_KEY_SEAL` = 32 random bytes
   from the KMS-backed store, `METRICS_TOKEN`, 32+ characters), `gate-db-admin` (`OWNER_DATABASE_URL`,
   `BACKUP_DATABASE_URL`) and `gate-backup` (`BACKUP_ENCRYPTION_KEY`, 32 random bytes as 64 hex characters: the
   archives are AES-256-GCM encrypted with it; escrow a copy outside the cluster, or no archive can be restored).
   The database certificate must name the `DATABASE_URL` host. If a public CA does not issue it, also create
   `gate-postgres-tls` with `ca.crt` and `DATABASE_TLS_CA_FILE=/etc/gate/postgres/ca.crt`; add `tls.crt`, `tls.key`,
   `DATABASE_TLS_CERT_FILE=/etc/gate/postgres/tls.crt` and `DATABASE_TLS_KEY_FILE=/etc/gate/postgres/tls.key` together
   when the database requires a client certificate. Server, migration and backup mount this optional Secret at
   `/etc/gate/postgres` and verify the chain and hostname. Locally `new-tenant.sh` creates it and starts PostgreSQL with `ssl=on`.
2. **Customer integrations (required by the production profile).** `gate-oidc` (`OIDC_ISSUER`, `OIDC_CLIENT_ID`,
   `OIDC_CLIENT_SECRET`, `OIDC_ROLE_CLAIM`, `OIDC_ID_CLAIM`, optional `OIDC_ACR`; the redirect URI to register at the
   IdP is `PUBLIC_ORIGIN/admin/v1/oidc/callback`), `gate-tsa` (`TSA_URL`, `TSA_CA_FILE=/etc/gate/tsa/ca.pem`, `ca.pem`,
   optional `ANCHOR_INTERVAL`), `gate-break-glass` (`BREAK_GLASS_WEBHOOK`, `BREAK_GLASS_WEBHOOK_SECRET`). Locally,
   `new-tenant.sh` creates all of these, pointing at the test services.
3. **Create.** `OVERLAY=deploy/k8s/overlays/<cloud> KUBE_CONTEXT=<ctx> WORLD=<dir> scripts/managed/new-tenant.sh <tenant>`,
   where `<dir>` holds the tenant's own `world.json` and `bundle.json` (a production first start refuses a world marked
   `"demo": true`, as the image's default is; the script refuses a new tenant without one unless the overlay sets
   `WORLD_DIR`; the local overlays seed the toy world with `ALLOW_DEMO_WORLD=true`, which `smoke.sh` relies on):
   namespace, Secrets (generated locally, required otherwise; existing ones kept), everything but the server,
   migration (waits for the Job), the server, exactly one ready pod, then the bootstrap PEP key into
   `gate-initial-credentials`. Prints names and the elapsed time only; a rerun is idempotent. **Measured: 29.3 s** for
   tenant `trial` from nothing to a ready production-profile node (images present; includes the test PKI, PostgreSQL
   start, migration and first start); removed again with `delete-tenant.sh` in 48 s (namespace finalisation).
4. **Check.** `scripts/managed/smoke.sh <tenant>` (local overlay; on a cloud, the same steps through the Ingress).
5. **Hand over.** The bootstrap PEP key is in Secret `gate-initial-credentials`. Hand it over through the customer's
   secure channel, have the customer create one PEP credential per application and revoke `bootstrap` (docs/API.md
   §3.10), then delete the Secret. Console access is through the customer's IdP only (password sign-in is off).
6. **Remove.** `scripts/managed/delete-tenant.sh <tenant> --yes` deletes the namespace (pods, Secrets, local database
   and backups). Managed databases and off-site backups are retired separately, under the contract's retention terms.

## 6. Upgrade (rolling) and day-2 procedures

**Upgrade** (`scripts/managed/upgrade-tenant.sh <tenant>`). A release that changes the schema needs, per
docs/DEPLOY.md, every node stopped while the **owner** role runs the schema and the grants. The script does:

1. `kubectl scale deploy/gate --replicas=0` and waits until no Qadamar pod is left;
2. `kubectl delete job gate-migrate` (a Job is immutable, and an old *completed* Job would satisfy the wait below
   without migrating anything);
3. `new-tenant.sh <tenant>`: creates the Secrets a newer release added and keeps every existing one, applies everything
   but the server, waits for `gate-migrate` (new image, owner role: `SCHEMA` + `serviceGrants` + `backupGrants`), applies
   the server (back to 2 replicas) and waits for the ready pod(s).

Stopping the pods also recreates them when the image tag did not change (`gate:local`), which a plain `kubectl apply`
would not: the pod template is identical, so nothing rolls. In a cloud, set the new digest in the overlay first.

**Performed on tenant `demo` (2026-11-10), v0.3.0 image (f882687) to b09bc44.** Before: 4 tables (`gate_doc`,
`gate_audit`, `gate_audit_meta`, `gate_anchor`), 105 audit rows, 13 anchors, no Secret `gate-backup`.

1. `scripts/managed/build-local-image.sh` (now `docker build --pull=false`: base images local only, no download;
   5.5 s with a warm cache). The old image was kept as `gate:pre-upgrade-f882687` for a rollback.
2. `scripts/managed/upgrade-tenant.sh demo`: **12.3 s without a serving node** (stop, migration, start; the
   `new-tenant.sh` part 11.1 s). It created `gate-backup` (`BACKUP_ENCRYPTION_KEY`, 64 hex characters).
3. Checked: 7 tables (`gate_sync`, `gate_token`, `gate_performed` added); the 105 rows kept untouched as chain `"0"`,
   which the nodes (default `GATE_NODE_ID`) continue; `gate_app` holds exactly `serviceGrants`, `gate_backup` SELECT on
   all 7 tables; both pods on the new image digest; then three smoke runs (§7).

What the upgrade needed besides the documented steps: the Secret `gate-backup` (new-tenant.sh creates it), deleting the
old migration Job, recreating the pods (same tag), and two `smoke.sh` fixes found on the first run: it still parsed
`backup.sh`'s old "Backup created and validated" line (now "created, validated and encrypted"), and it put its
port-forwards in the background through a shell function, so `$!` was the subshell and the killed forward's `kubectl`
stayed on the port. The next forward then failed to bind while its readiness probe was answered by the old one: the
restore-drill node's `/readyz` and audit length were read **from the tenant's active pod**. The earlier "Qadamar on the
restored database" figures are therefore not evidence; §7 below is from the fixed script, which also refuses to start
when 18787 or 18443 is already taken.

**Rollback.** Keep the previous image. The schema change is additive (a `node` column with default `"0"`, three new
tables), but the previous release does not know per-node chains: roll back only by restoring the pre-upgrade backup.

Cold start of both pods (`kubectl rollout restart`, smoke §6, every production check rerun including the database
role check and the full audit-chain scan): **3.6–4.6 s** without a ready endpoint. A node that is not yet serving exits
at once on SIGTERM. PEPs should retry decisions for about 10 s during a planned upgrade (active/standby; cluster mode
has no gap, §6a).

**Node drain.** The standby is never Ready, so the PodDisruptionBudget (`minAvailable: 1`,
`unhealthyPodEvictionPolicy: AlwaysAllow`) blocks the eviction of the active pod and lets the standby go. Move the
active role on purpose first (`kubectl -n gate-<t> delete pod <active>`, a graceful failover), then drain.

**Rotations.** Signing-key rotation, PEP credential creation, rotation and revocation, and lockouts are stored in
PostgreSQL by the active node: nothing to copy, a failover keeps them (v0.3.0 tests in `postgres.test.ts`).

## 6a. Cluster mode (several deciding pods)

`deploy/k8s/components/cluster` is a kustomize Component any overlay can add (`components: [../../components/cluster]`);
`overlays/local-cluster` is the local overlay with it. It sets `GATE_CLUSTER=true` and replaces the Deployment by a
**StatefulSet** running the same pod template (copied by a kustomize replacement), with a headless Service `gate-nodes`:
`GATE_NODE_ID` is the pod name (`gate-0`, `gate-1`), the same after every restart, so a restarted node **continues its
own audit chain**; `GATE_ADVERTISE_URL=<scheme>://<pod>.gate-nodes.<namespace>.svc:8787` (scheme `http` behind a
TLS-terminating ingress, `https` when the node serves TLS itself, as locally, whose certificate must then name
`*.gate-nodes.<namespace>.svc`: PARAMETER); NetworkPolicies let the pods reach each other's port 8787. A rolling update
replaces one pod at a time; the other keeps deciding. `new-tenant.sh` removes the other workload kind when a tenant
switches mode; `upgrade-tenant.sh` scales whichever exists.

**Admin plane through the plain Service.** A follower forwards `/admin/` and `/scim/` to the leader's advertised
address (API.md §3.9.1: streamed, cookies and CSRF kept, an HMAC hop header with a key derived from
`SIGNING_KEY_SEAL`, 30 s window, single use, never forwarded twice, 10 s / 30 s timeouts); `409 not_leader` remains the
answer only when the leader is unknown. No leader-aware load balancer is needed.

**Retired node ids.** Scaling down (say from 3 to 2) retires `gate-2`: its chain stays in PostgreSQL, verified at every
start and recheck and covered by anchors and the checkpoint, with no new rows; scaling up again continues it. Nothing
to clean up; deleting rows would break verification by design.

```
OVERLAY=deploy/k8s/overlays/local-cluster scripts/managed/new-tenant.sh <tenant>   # waits for 2 ready pods
scripts/managed/smoke.sh <tenant>                                                 # detects GATE_CLUSTER=true
```

**Measured 2026-11-10, tenant `cluster`, production profile:** created in 29.9 s (2 ready pods); smoke, 6 PASS:
2 pods running and Ready, 2 ready Service endpoints; a PEP evaluation answered 200 by **each** pod, `/readyz` naming the
pod as node; exactly one `/leaderz` 200; the follower answers `/admin/v1/session` with `409 not_leader` naming the
leader's advertised URL; OIDC sign-in with MFA and audit verify on the leader; a decision token issued by the follower
consumed on the leader and refused (409) on reuse on the follower; leader pod deleted: the follower kept deciding
(4 decisions, 0 failed) and **took the lead after 0.8 s**, sign-in and audit verify on it; `kubectl rollout restart`
**completed** (it never does in active/standby) in 6.2 s with 2 new ready pods. Deleted with `delete-tenant.sh` in
47.8 s. Anchoring, backup and restore were not rerun on it (same Jobs and scripts as §7).

The measurement above predates the StatefulSet and the forwarding (see CHANGELOG, Unreleased); `smoke.sh` now also
checks: stable pod names as node ids, `/admin/` answered by the leader through **either** pod (OIDC sign-in with MFA,
session, audit verify and a CSRF-checked sign-out through the follower), the loop guard (a request already carrying a
hop header gets `409 not_leader` naming `https://<leader>.gate-nodes.<namespace>.svc:8787`), a forged hop refused by
the leader (401), the deleted leader coming back under its name and continuing its audit chain, and a rolling restart
that brings the same node ids back.

## 7. What `smoke.sh` checks and measured

`smoke.sh` runs through `kubectl port-forward` to `https://localhost:18787`, verifying Qadamar's certificate against the
tenant's test CA, and prints PASS lines and timings, never a secret. Three consecutive runs on 2026-11-10 against
tenant `demo` after its upgrade to b09bc44 (OrbStack, Kubernetes 1.36, one arm64 node, images `gate:local` /
`gate-ops:local`, real clock), 15 PASS lines each, no port-forward retry needed. Timings come from polling `kubectl`
every 0.1–0.3 s.

**2026-11-17, v0.12.1 (`d46319c` plus the smoke and network-policy fixes):** tenant `demo` upgraded in place after a
disk-pressure eviction had removed its local images (38.3 s without a serving node), then three consecutive runs, 15
PASS lines each. A run now opens PDP sessions and closes them at exit, creates a PEP credential scoped to `network` and
revokes it, and has break-glass reviewed by a second security officer. Last run: graceful failover 0.6 / 0.9 / 1.0 s,
forced 2.7 / 3.0 / 3.1 s, cold start 5.7 s, anchor after 25.4 s, backup 7.5 s (97.0 KB, audit length 409), restore
drill 10.0 s with all 18 gate tables. The runs below are those of 2026-11-10.

| Step | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| Production profile at start, https, probes, `/metrics` 401 without the token | PASS | PASS | PASS |
| PEP evaluation (401 without key), maker-checker deny with `SOD_HISTORY=server` | PASS | PASS | PASS |
| OIDC sign-in through the test IdP: without MFA refused (`mfa_required`), with MFA accepted; password sign-in 403; client address in the audit row | PASS | PASS | PASS |
| Break-glass opened by an access admin; signed notice received and HMAC-verified by the in-cluster receiver | PASS | PASS | PASS |
| Anchor of the audit head by the test TSA (`ANCHOR_INTERVAL` 60 s): wait; token verified **offline** with `openssl ts -verify` against the test CA, refused for another hash, hash equal to the audit row | 25.1 s | 39.6 s | 39.8 s |
| Graceful failover (`kubectl delete pod <active>`): endpoint ready / answering / token issued before it consumed | 1.2 / 1.5 / 1.7 s | 0.9 / 1.1 / 1.5 s | 0.6 / 0.7 / 0.9 s |
| Forced failover (`--grace-period=0`, process killed): endpoint ready / answering / token consumed | 2.7 / 2.8 / 3.0 s | 2.5 / 2.6 / 2.8 s | 1.5 / 1.7 / 1.8 s |
| Consumed token reused after the failovers (tokens are `gate_token` rows: they survive a failover) | 409 | 409 | 409 |
| Audit chain verified after every failover and the restart | yes | yes | yes |
| Cold start of both pods (`rollout restart`), production-profile startup to a ready endpoint | 3.6 s | 4.6 s | 4.5 s |
| Backup (CronJob run once as a Job): time, encrypted archive size, audit length | 6.1 s, 38.5 KB, 178 | 6.1 s, 39.9 KB, 192 | 6.1 s, 41.3 KB, 206 |
| Archive starts with `GATEBK` (AES-256-GCM); `restore.sh` under a random key refused before any database is created | PASS | PASS | PASS |
| Restore drill: `restore.sh` decrypting into a fresh database + service/backup grants | 5.1 s | 5.0 s | 5.0 s |
| Production-profile Qadamar as the **service role** on the restored database: ready / restore start to ready; chain verified, length = backup's | +1.3 s / 6.6 s | +1.5 s / 6.7 s | +1.6 s / 6.7 s |

Decision tokens live 15 s by policy and the clock is real: tokens issued just before a failover were consumed
0.9–3.0 s after the delete. A failover longer than the TTL expires in-flight tokens; PEPs ask again.

**Failover procedure.** Nothing to do: the Deployment recreates the lost pod, which becomes the standby. A crash
releases the lock when PostgreSQL sees the connection close. **A node loss** (no FIN/RST) releases it only when the
server's TCP keepalive gives up: the local PostgreSQL runs `tcp_keepalives_idle=10, interval=5, count=3` (about 25 s);
the cloud database must be configured likewise (§9). Not measured here.

**Backup procedure.** Daily CronJob `gate-backup` (`scripts/ops/backup.sh`: one consistent snapshot, validated with
`pg_restore --list`, then encrypted with `BACKUP_ENCRYPTION_KEY` into `gate-<UTC time>.dump.gcm`, mode 600, never
overwritten), retention by age. Run one now:
`kubectl -n gate-<t> create job --from=cronjob/gate-backup gate-backup-manual-$(date +%s)`. The logical backup is a
second line of defence: the RPO of the offer must come from the cloud's point-in-time recovery (§9).

**Restore procedure** (what `smoke.sh` §8 automates): run `restore.sh` from the ops image with
`DATABASE_URL=<owner URL>/<new database>`, the archive and its `BACKUP_ENCRYPTION_KEY` (refused if the database
exists, or if the archive does not authenticate under the key); grant the service and
backup roles as `gate-migrate` does; start a Qadamar node on it as the service role, in the production profile (the drill
clones the Deployment's pod template with another database and labels the Service does not select); check `/readyz`
(audit chain verified) and `gate_audit_length`; then point `gate-env` `DATABASE_URL` at the new database and restart
the pods. The signing keys are in the archive (sealed): the tenant's `SIGNING_KEY_SEAL` must be the one in use when
the backup was taken.

## 8. On-call alerts (`deploy/k8s/monitoring/alerts.yaml`)

| Alert | Severity | Meaning and first action |
|---|---|---|
| `GateNoActiveNode` | critical | No pod Ready or answering its scrape for 1 min: every decision fails, PEPs deny. Pods, PostgreSQL reachability, logs (`Storage failure`, `Audit integrity failure`, `GATE_PROFILE=production refused to start`). |
| `GateActiveNodeNotReady` | critical | The lock holder answers but `/readyz` fails for 2 min: audit chain unverified or commits failing. Inferred; `gate_audit_full_chain_verified` (0.5.0) covers the background verification after a start. Verify as auditor; treat a broken chain as a security incident, preserve the database before any restore. |
| `GateAuditFullChainUnverified` | warning | `gate_audit_full_chain_verified` 0 for 15 min: the background verification of the whole chain after a start is still running (very large log: raise `for`) or found a rewritten row (`AUDIT INTEGRITY FAILURE` in the log; then also `GateActiveNodeNotReady`). |
| `GateAnchoringStale` | warning | No RFC 3161 anchor for 2 × `ANCHOR_INTERVAL`: TSA unreachable, its CA wrong, or a chain problem (`/admin/v1/audit/anchors` `lastError`). |
| `GateCommitLatencyHigh` | warning | p99 commit above 250 ms for 10 min: every decision waits for its commit; look at the database. |
| `GateHigh5xxRate` | critical | Above 2 % 5xx at the ingress for 5 min (Qadamar's own metrics have no status code). |
| `GateFailover` | warning | The active role moved within 15 min: expected during upgrades and drains, otherwise read the previous pod's log. |
| `GateBackupMissing` | warning | No successful backup for 26 h, or a backup Job failed. |
| `GateDecisionLatencyHigh` | warning | Decision p99 above 250 ms for 10 min (§10 proposal): compare with `GateCommitLatencyHigh` and CPU throttling. |
| `GateAvailabilityBudgetBurn` | critical | 5xx ratio above 14.4 × the 0.1 % budget over both 1 h and 5 min (§10 proposal): the month's budget goes in about two days. |
| `GateReplicaStale` | warning | A replica has not confirmed the shared state for over 2 s (`GATE_MAX_STALENESS_MS`): it answers 503 instead of deciding. |
| `GateBreakGlassNoticeFailed` | warning | A signed break-glass notice was given up after its retries: tell the customer's security officer directly. |

`GateNoActiveNode` and `GateActiveNodeNotReady` also cover cluster mode (StatefulSet pods `gate-<n>`) and never count a
decision replica (`gate-replica-<n>`) as a Qadamar node.

The scrape job must send `Authorization: Bearer <METRICS_TOKEN>` and keep `namespace` and `pod` labels; the standby's
scrape always fails (no port) and is not an alert. Counters restart at every failover. A failed break-glass notice is
audited (`notify_failed`), counted in `gate_break_glass_notices_total{outcome="failed"}` and alerted
(`GateBreakGlassNoticeFailed`).

## 9. What each cloud must provide

- **Managed PostgreSQL 17** per tenant with synchronous HA (automatic primary failover), **point-in-time recovery**,
  encryption at rest, a private endpoint, server-side TCP keepalives of about 10 s, roles as in §1 including one with
  `BYPASSRLS` for `pg_dump`, and a direct connection to the primary (no transaction pooler; docs/API.md §3.9.1).
  TLS must be enabled with a certificate naming the connection host and chaining to the system store or the supplied
  `gate-postgres-tls/ca.crt`; supply a client certificate/key as well when required. Qadamar refuses weaker non-local TLS.
- **KMS-backed secret store** delivering `SIGNING_KEY_SEAL`, the database URLs, the OIDC client secret, the webhook
  secret and `METRICS_TOKEN` into the tenant's Kubernetes Secrets (CSI secret store driver or an external-secrets
  controller), with Kubernetes Secret encryption at rest enabled.
- **The customer's IdP** (OIDC, MFA asserted in `amr` or a required `acr`) with the console roles in a claim.
- **A TSA** (RFC 3161) reachable over https, with its CA for `TSA_CA_FILE`; an eIDAS-qualified one if the customer's
  regulator asks for it (owner decision). **A break-glass receiver** over https (the customer's SOC or paging bridge).
- **Object storage** for backups: a bucket per tenant mounted as the backup volume through the cloud's CSI driver, or a
  copy job off the PVC; versioning, retention lock and encryption on the bucket.
- **Ingress with TLS**: an ingress controller, certificates per tenant host, the controller's namespace in the
  NetworkPolicy and its address range in `TRUSTED_PROXIES`. HSTS follows from `PUBLIC_ORIGIN`.
- **A CNI that enforces NetworkPolicy**, several zones, Prometheus with the Operator and kube-state-metrics.

## 10. SLO proposal (TO DECIDE: owner)

**Nothing in this section is a commitment.** Availability percentages, latency objectives, RPO and RTO are commercial
terms: each objective below is a **recommendation** with its rationale, marked **TO DECIDE**, until the owner approves
it and the provider (§12) is chosen. The indicators exist today; the alert rules in `deploy/k8s/monitoring/alerts.yaml`
fire on the proposed values and change with them.

| SLI (what is measured) | Where the product exposes it | Proposed objective (TO DECIDE) | Rationale |
|---|---|---|---|
| **Decision availability**: share of decision-plane requests (`/access/*`, `/x/*`, `/xacml/*`) not answered 5xx, per tenant, per calendar month | ingress `nginx_ingress_controller_requests` by status (Qadamar's own metrics carry no status code); `GateNoActiveNode` for a full outage | **99.9 %** (about 43 min a month). Alerts: `GateAvailabilityBudgetBurn` (budget burning 14.4× over 1 h and 5 min), `GateHigh5xxRate`, `GateNoActiveNode` | Measured gaps are seconds: failover 0.6–2.8 s, cold start 3.6–4.6 s, schema upgrade 12.3 s (active/standby), none in cluster mode (§6a, §7). The unknown is the provider's managed PostgreSQL and zones: every decision commits its audit row there, so the tenant cannot be more available than its database. Do not offer more than the chosen database's own published objective allows. |
| **Readiness**: at least one Ready Qadamar node per tenant | `/readyz` (pending writes committed, audit chain verified); `kube_statefulset_status_replicas_ready` / `kube_deployment_status_replicas_ready`; `gate_active_node` | Counted inside availability; page after **1 min** without a Ready node (`GateNoActiveNode`) | `/readyz` already folds storage and audit integrity into one signal; no separate objective needed. |
| **Decision latency**: p99 of `route="evaluation"` (and `evaluations`, `search`, `xacml`, `tokens`), node side, audit commit included | `gate_http_request_duration_seconds` histogram (buckets 1 ms … 30 s, `metrics.ts`) | **p99 < 250 ms over 5 min**, in 99 % of the 5 min windows of a month. Alert: `GateDecisionLatencyHigh` (10 min) | 250 ms is a bucket boundary (exact quantile) and the existing commit alert. Laptop measurements (PERFORMANCE.md, one machine, not production): large world on PostgreSQL p99 9–32 ms at 8–64 clients after the decision-write change; cluster mode p99 118–188 ms on a loaded laptop. Leaves room for a database in another zone; tighten after measuring on the provider. A batch of up to 1,000 evaluations is one request and is excluded from a per-decision promise. |
| **Error rate** | as availability (5xx); 4xx are caller errors, 429 is the published quota (§11) | the budget is 1 − availability | One budget, not two. |
| **Audit integrity**: every chain verified from its genesis (or sealed head) since start | `gate_audit_full_chain_verified`, `/readyz` `audit.verified` and `fullChain`, `GET /admin/v1/audit/verify` | **No budget**: any confirmed break is a security incident (`GateActiveNodeNotReady`, `GateAuditFullChainUnverified` after 15 min) | Background verification costs about 9 s per million rows on the laptop (PERFORMANCE.md): 15 min covers about 100 million rows there. A tenant with a larger log needs a longer `for`, measured on the provider. |
| **Anchoring freshness**: age of the last RFC 3161 anchor | `gate_audit_last_anchor_age_seconds` | **< 2 × `ANCHOR_INTERVAL`** (2 h at the default 3600 s). Alert: `GateAnchoringStale` | Depends on the TSA's availability, which is an owner choice (§12); an objective cannot exceed what the chosen TSA offers. |
| **Replica staleness** (only with decision replicas) | `gate_replica_state_age_seconds`, `gate_replica_audit_lag_seconds`, `gate_replica_audit_refused` | state age **≤ `GATE_MAX_STALENESS_MS`** (2 s default; a replica refuses beyond it); audit lag **< 5 s** (it refuses at `GATE_REPLICA_AUDIT_LAG_MS`, 10 s). Alerts: `GateReplicaStale`, `GateReplicaAuditLagging`, `GateReplicaAuditRefused` | These are the code's own safety bounds: a stale replica answers 503 rather than deciding, so staleness shows up as availability, not as wrong decisions. |
| **Backup freshness** | `kube_cronjob_status_last_successful_time{cronjob="gate-backup"}` | a validated encrypted archive **< 26 h** old. Alert: `GateBackupMissing` | Daily logical backup (§7); the RPO itself comes from the database's point-in-time recovery. |
| **RPO / RTO** | restore drill (§7); provider PITR | **TO DECIDE**: recommendation RPO 5 min with the provider's PITR (24 h with logical backups alone), RTO 4 h | Restore of a 41 KB archive measured 6.7 s to a serving node, which says nothing about real sizes: confirm with a drill on the provider at the tenant's size before quoting. |
| **Break-glass notice delivery** | `gate_break_glass_notices_total{outcome="failed"}` | every failure acted on. Alert: `GateBreakGlassNoticeFailed` | The customer's SOC must hear of an emergency access; a failure is audited (`notify_failed`) but nobody else would see it. |

**Error-budget policy (recommendation).** While a tenant's monthly budget is spent, upgrades of that tenant wait except
security fixes; the burn alert pages the on-call; a post-incident review is written for any month that misses.

## 11. Quotas and limits

### 11.1 What the code enforces (defaults)

Every figure below is the code's own value, cited to the variable or constant that sets it; an environment variable
can change it per tenant (docs/CONFIGURATION.md), a constant only with a release. Rate limits are token buckets per
minute, answered `429 rate_limited` with `Retry-After`; in cluster mode the bucket is shared by every node through
leased PostgreSQL capacity, on a replica it is local to the replica.

| Limit | Default (bounds) | Set by |
|---|---|---|
| Decision plane (`/access/*`, `/x/*`, `/xacml/v3/authorize`), per PEP credential **and** per client address | 60,000 requests/min (at least 1,000) | `PEP_RATE_LIMIT_PER_MINUTE`; `DEFAULT_PEP_RATE_LIMIT`, `MIN_PEP_RATE_LIMIT` (`ratelimit.ts`) |
| Cost of a batch (`/access/v1/evaluations`) and of an XACML multiple request | one token per evaluation | `router.ts` (`cost`), `xacmlCost` (`xacml.ts`) |
| Console, SCIM and public routes, per client address **and** per signed-in principal | 120 requests/min | `RATE_LIMIT_PER_MINUTE`; `DEFAULT_RATE_LIMIT` (`ratelimit.ts`) |
| Password sign-in attempts, per username + client address | 5/min; then progressive lockout 1, 2, 4 … min, at most 1 h | `auth.ts` (`login:` bucket), docs/API.md §0 |
| Replica feed and audit shipping, per replica | 1,200 requests/min; 6 full snapshots/min | `REPLICA_FEED_RATE_LIMIT` (`router.ts`), `FULL_SNAPSHOTS_PER_MINUTE` (`replica-source.ts`) |
| Request body | 1 MiB (1,048,576 bytes; 413 and `Connection: close` above) | `http.ts` (`body`) |
| SAML message | 262,144 bytes | `SAML_MESSAGE_MAX` (`router.ts`) |
| Evaluations in one batch; requests in one XACML multiple request | 1,000 | `pdp.ts` (`evaluations`), `XACML_MAX_REQUESTS` (`xacml.ts`) |
| Search page (`/access/v1/search/*`) | 100 results, at most 1,000 | `searchPage` (`pdp.ts`) |
| Audit listing / pull export / SIEM batch | 50 (≤ 1,000) / 100 (≤ 1,000) / 100 (1..1,000) rows; SIEM every 30 s (1..86,400) | `admin/audit.ts`; `AUDIT_EXPORT_MAX_LIMIT` (`siem.ts`); `SIEM_BATCH_SIZE`, `SIEM_INTERVAL_SECONDS` |
| Subject access report | 1,000 rows | `MAX_REPORT_ROWS` (`admin/privacy.ts`) |
| Resource registration: rate cost | a listing 1; a write 10 + 1 per resource named, capped at 1,000 | `REGISTRATION_WRITE_COST`, `registrationCost` (`resources.ts`) |
| Resource registration: size | 1,000 resources per call; `attrs` at most 64 attributes and 8,192 bytes | `MAX_BATCH`, `MAX_ATTRS` (`resource-registry.ts`) |
| Registrations awaiting two-person review, per PEP credential | 100 (`409 proposal_limit` above) | `RESOURCE_PENDING_PROPOSALS_PER_PEP` (`resources.ts`) |
| BLP open session tokens | 4 per (PEP credential, subject) (1..1,000); 10,000 per PEP credential (1..100,000); subject type and id 1..256 characters | `BLP_SESSIONS_PER_SUBJECT`, `BLP_SESSIONS_PER_CREDENTIAL` (`pep-sessions.ts`) |
| BLP session high-water marks | 10,000 per PEP credential (1..100,000); 100,000 in all; idle 15 min, absolute 8 h; id 1..128 printable characters | `BLP_SESSIONS_PER_PEP`; `MAX_SESSIONS`, `SESSION_IDLE_MS`, `SESSION_ABSOLUTE_MS`, `SESSION_ID` (`sessions.ts`) |
| Impact preview budget | 100,000 affected-cell evaluations (422 above) | `IMPACT_MAX_EVALUATIONS`; `DEFAULT_IMPACT_EVALUATION_LIMIT` (`admin/changes.ts`), docs/DEPLOY.md §6 |
| Audit retention | unset: every row kept; 1..36,500 days seals and removes the expired prefix (owner operation on PostgreSQL) | `AUDIT_RETENTION_DAYS` (docs/API.md §3.9.4) |
| Audit row size | strings over 512 characters truncated with their SHA-256; a row over 16,384 bytes keeps its identity fields only | `AUDIT_MAX_STRING`, `AUDIT_MAX_ROW` (`audit.ts`) |
| Audit anchoring | every 3,600 s (at least 60) | `ANCHOR_INTERVAL` (`main.ts`) |
| Decision token / backend assertion lifetime | at most 300 s / 30 s | `MAX_DECISION_TOKEN_TTL_SECONDS`, `ASSERTION_TTL_SECONDS` (`tokens.ts`) |
| Console session | idle 15 min, absolute 8 h | `IDLE_MS`, `ABSOLUTE_MS` (`auth.ts`) |
| Cluster / replica freshness | a node or replica refuses decisions on a state confirmed more than 2,000 ms ago (100..60,000); a replica also when an audit row waits more than 10,000 ms | `GATE_MAX_STALENESS_MS`, `GATE_REPLICA_AUDIT_LAG_MS` (`replica.ts`, `postgres.ts`) |
| Delegation depth; relation hops | 4; 32 | `MAX_DELEGATION_DEPTH` (`core/src/request.ts`), `MAX_HOPS` (`core/src/relations.ts`) |
| Backup schedule and retention | daily 02:17 UTC; 14 days | `base/jobs.yaml` (`schedule`, `BACKUP_RETENTION_DAYS`) |

**World size: what was measured, on one laptop** (docs/PERFORMANCE.md: Apple M5 Pro, 18 cores, 48 GiB, PostgreSQL 17 in
Docker on the same machine, other work running; **not production hardware, not capacity targets**):

- Decisions were measured on worlds up to **5,000 subjects, 50,000 resources, 5,000 tuples**: on PostgreSQL 2,678 to
  8,263 single evaluations/s at 8 to 64 clients (p99 9 to 32 ms) after the decision-write change; resource search about
  27 pages/s at one client (p99 53 ms).
- Per-record storage was measured to **1,000,000 resources** for registration (about 1,960 single registrations/s,
  batches of 1,000 at about 14,400 resources/s) and a one-time migration of 17.4 s; decisions on that size were not.
- Cluster mode scaled 1.48× with 2 nodes and 1.79× with 3 (small world); the shared database's WAL flush is the limit.
- Start-up from the checkpoint is about 0.1 s at one million audit rows; the background full verification about 9 s
  per million rows.
- Every node holds the whole world and its indexes in memory; start-up memory at large sizes was not measured.

### 11.2 Per-tenant defaults we recommend (recommendations, not commitments)

| Setting | Recommendation | Why |
|---|---|---|
| Decision-plane rate (`PEP_RATE_LIMIT_PER_MINUTE`) | keep the code default, 60,000/min per PEP credential and per address | It protects the tenant from one runaway PEP; the laptop sustained more than that per node. A lower tier figure is a pricing decision (TO DECIDE). |
| Console rate (`RATE_LIMIT_PER_MINUTE`) | keep 120/min | Ample for people and SCIM; it is also the brute-force brake. |
| Published world size of a standard tenant | up to **50,000 resources, 5,000 subjects, 5,000 tuples**; above that, measure on the provider before quoting | Largest world measured end to end on decisions. |
| `BLP_SESSIONS_PER_PEP`, `RESOURCE_PENDING_PROPOSALS_PER_PEP`, `IMPACT_MAX_EVALUATIONS` | keep 10,000, 100, 100,000 | Code defaults, chosen as fairness and safety bounds; raise only for a measured need (docs/DEPLOY.md §6). |
| Qadamar nodes / decision replicas | 2 cluster nodes (one per zone); replicas HPA 2..4 at 70 % CPU (`overlays/sovereign-uae/pdb-hpa.yaml`) | One node per zone survives a zone loss; the replica bounds are a cost decision (TO DECIDE) and need one key per ordinal provisioned. |
| `ANCHOR_INTERVAL` | 3,600 s | One TSA request an hour per tenant; the staleness alert at 2 h. |
| `AUDIT_RETENTION_DAYS` | unset by default; set per contract | Retention is a customer and regulatory decision (TO DECIDE per tenant); deletion is an owner operation with every writer stopped. |
| Backup retention | 14 days logical + the provider's PITR window | TO DECIDE with the contract; the archives are encrypted before they leave the pod. |
| SIEM push | `SIEM_BATCH_SIZE` 100, `SIEM_INTERVAL_SECONDS` 30 | Code defaults; at-least-once with dedup on `(node, seq)` (docs/API.md §3.9.3). |

## 12. UAE sovereign cloud (provider not chosen)

A production overlay for an in-country (sovereign) cloud. No provider is assumed: what a provider must offer is
written as questions (§12.3); every commercial term is the operator's decision (§12.5).

### 12.1 Architecture

`deploy/k8s/overlays/sovereign-uae` is a provider-agnostic production overlay on `base` plus the `replicas` and `cluster`
components. Every value marked PARAMETER is a placeholder; `new-tenant.sh` refuses to apply it while one remains.

```
customer PEPs / admins ──https──▶ ingress (TLS, tenant host) ──https (re-encrypted)──▶ Service gate:8787
                                                                                      │
      namespace gate-<t>, nodes only in in-country zones (required node affinity)    ▼
      ┌──────────────────────────────────────────────────────────────────────────────────────┐
      │ gate-0 (zone 1)  gate-1 (zone 2)   cluster mode: both decide, one leads the admin plane │
      │ gate-replica-0..n (HPA 2..4, zone spread, in-country encrypted volumes): decide without │
      │   a database, fed by the signed state feed over https, ship their audit chains back     │
      └──────────────────────────────────────────────────────────────────────────────────────┘
          │ TLS verify-full (DATABASE_TLS, CA gate-postgres-tls)   │ egress allow-list, :443 only
          ▼                                                        ▼
   managed PostgreSQL 17, in-country, private endpoint      customer IdP · TSA · break-glass receiver · SIEM
   (state, audit, anchors, sealed keys)                     (each a PARAMETER CIDR; nothing else is reachable)
          │
   backup CronJob ──AES-256-GCM archive──▶ in-country backup storage (StorageClass gate-in-country-backup)
```

| Concern | What the overlay does | Checked by |
|---|---|---|
| Profile | `GATE_PROFILE=production` (base): the node refuses to start without OIDC/SAML with MFA, TSA with its CA, break-glass receiver, sealed keys, metrics token, least-privilege database role | `profile.ts`; k8s test |
| TLS | ingress TLS; Qadamar pods serve TLS (`TLS_CERT_FILE`, Secret `gate-pod-tls`), readiness over HTTPS, ingress re-encrypts (`backend-protocol: HTTPS`, ingress-nginx; PARAMETER); replicas reach the nodes over https and serve TLS themselves (same Secret, which also names `gate-replica` and `gate-replica.<ns>.svc`; probes over HTTPS); every PostgreSQL client (server, migration, `backup.sh`, `restore.sh`) with `DATABASE_TLS=verify-full` and `DATABASE_TLS_CA_FILE=/etc/gate/postgres/ca.crt`, the CA from Secret `gate-postgres-tls` (required by this overlay) | k8s test (`sovereign-uae overlay`); `new-tenant.sh` refuses a missing CA and database URLs with TLS parameters (`sslmode`, `sslrootcert`, ...), which Qadamar and the ops scripts refuse too |
| Placement | required node affinity to `topology.kubernetes.io/region` and `/zone` (placeholder values) on every pod, Jobs included; zone spread `DoNotSchedule` for nodes and replicas; PDBs for both | k8s test |
| Residency labels | `qadamar.example/data-residency: AE` on every object and pod template | k8s test |
| Storage | replica volumes on `gate-in-country-encrypted`, backups on `gate-in-country-backup` (PARAMETER StorageClasses: in-country zones only, encrypted with an in-country KMS key) | k8s test (named class) |
| Egress | default deny; DNS to the cluster DNS only (the replicas' open port-53 rule is narrowed); PostgreSQL :5432; IdP, TSA, break-glass receiver and SIEM on :443, each its own CIDR | k8s test: every egress rule names destinations and ports, none is `0.0.0.0/0` |
| Secrets | referenced only; filled by an external, KMS/HSM-backed in-country store (`external-secrets.example.yaml`: ExternalSecret or Secrets Store CSI pattern, not rendered, no CRD needed to render) | k8s test: no Secret object, no credentials in any URL, secret variables from `secretKeyRef` |
| Images | in-country registry, **by digest** (all-zero placeholder digests refused at apply) | k8s test; `new-tenant.sh` |

### 12.2 Data residency design

| Data | Where it stays | Notes |
|---|---|---|
| Policy state, subjects, resources, tuples, sealed signing keys, PEP credentials, sessions | tenant's managed PostgreSQL, in-country | private endpoint, TLS verify-full |
| Audit chains, anchors, sealed retention segments | same database; replica chains first on their in-country volumes | shipped to the database within `GATE_REPLICA_AUDIT_LAG_MS` |
| Backups | in-country backup storage | encrypted (AES-256-GCM, `BACKUP_ENCRYPTION_KEY`) before they leave the pod; key escrowed in-country (owner process) |
| Secrets and keys | in-country secret store backed by KMS/HSM | Kubernetes Secret encryption at rest required |
| **What leaves the namespace** | to the TSA: only the SHA-256 of the audit head (docs/API.md §3.9.2); to the customer's IdP: the sign-in exchange; to the customer's break-glass receiver and SIEM: signed notices and audit rows (ids, rule ids, no secrets; docs/API.md §3.9.3) | the customer chooses where its IdP, SIEM and receiver live; the TSA choice is an owner decision (§12.5) |
| Metrics and logs | the provider's monitoring stack | ask where they are stored (§12.3); they hold ids, never secrets |

### 12.3 Provider selection checklist (questions to ask every candidate)

Ask each candidate in writing and keep the answers with the decision; none of these is assumed for any provider.

1. **Zones**: How many availability zones are in the UAE, with what separation? Which Kubernetes labels name region and zone?
2. **Kubernetes**: Which managed Kubernetes versions? Is NetworkPolicy enforced by the CNI (default deny, `ipBlock`)? Pod Security admission `restricted`? Can node pools be dedicated per customer?
3. **Managed PostgreSQL 17**: synchronous HA across zones with automatic failover? Point-in-time recovery: window and granularity? TLS with a CA we can pin (`verify-full`)? Private endpoint only? Server TCP keepalives configurable (about 10 s)? Can we create roles with `BYPASSRLS` for `pg_dump`? A direct (non-pooled) connection to the primary?
4. **Keys**: KMS and/or HSM in-country? Customer-managed keys for disks, buckets, database and Kubernetes Secrets? Key residency and who at the provider can use them?
5. **Secret store**: which store, and which integration (an external-secrets provider or a Secrets Store CSI provider)?
6. **Storage**: StorageClasses restricted to in-country zones, encrypted with our KMS keys? Object storage with versioning and retention lock, mountable through a CSI driver?
7. **Networking**: private networking between cluster and database; egress control; which addresses does the ingress controller use (`TRUSTED_PROXIES`)? DDoS protection on the ingress?
8. **Registry**: an in-country container registry with digest pinning, image scanning and signature verification?
9. **Monitoring**: Prometheus-compatible metrics with the Operator's `PrometheusRule`, kube-state-metrics; where are metrics and logs stored?
10. **Compliance attestations**: which certifications and attestations does the provider hold for these services, with the scope statements and report dates? (Ask for the documents; do not quote them before reading their scope.)
11. **Data residency commitments**: what does the contract say about data, backups, logs, support access and sub-processors staying in the UAE?
12. **Operations**: maintenance windows and notice; the provider's own published objectives for Kubernetes, PostgreSQL and storage (they bound ours, §10); support channels and hours.
13. **Time stamping**: does the provider, or another in-country party, run an RFC 3161 TSA? Its CA, availability and policy?
14. **Exit**: how do we export the database and backups if we leave?

### 12.4 Onboarding runbook (sovereign overlay)

1. **Fill the PARAMETERS** in a copy of `deploy/k8s/overlays/sovereign-uae` for the chosen provider: registry and
   release digest, tenant host and `PUBLIC_ORIGIN`, `TRUSTED_PROXIES`, region and zone values, StorageClass names, the
   five egress CIDRs, ingress class and its https-backend annotation, HPA bounds.
2. **Render without a cluster** and review: `OVERLAY=sovereign-uae scripts/managed/new-tenant.sh <tenant> > <tenant>.yaml`
   (no `KUBE_CONTEXT`: nothing is contacted or applied). `GATE_K8S_TEST=1 node --test packages/pdp-http/test/k8s.test.ts`
   checks the overlay's invariants.
3. **Database**: create the tenant's PostgreSQL 17 in-country and the three roles of §1; take its server CA as `ca.crt`.
4. **Secrets** in the external store, synced into namespace `gate-<tenant>` (the list in `external-secrets.example.yaml`):
   database URLs without TLS parameters, `gate-postgres-tls` (`ca.crt` and `DATABASE_TLS_CA_FILE=/etc/gate/postgres/ca.crt`;
   `DATABASE_TLS=verify-full` is in the base config), `gate-pod-tls`, `gate-tls`,
   OIDC/SAML, TSA and its CA, break-glass receiver, optional SIEM, backup key (escrowed), replica keys for every ordinal
   up to the HPA maximum.
5. **Create**: `OVERLAY=sovereign-uae KUBE_CONTEXT=<ctx> WORLD=<dir> scripts/managed/new-tenant.sh <tenant>`. It refuses
   placeholders, a missing Secret or CA, or a database URL with its own TLS parameters, migrates as owner, then waits
   for the ready pods.
6. **Check**: the smoke steps of §7 through the Ingress (sign-in with MFA, a decision, break-glass notice received,
   an anchor verified offline, a backup and a restore drill); then the customer audit export of §13 once.
7. **Hand over** as §5 (bootstrap PEP key, then revoke it). Alerts of §8 and §10 routed to the on-call.

### 12.5 Owner decisions still open

| Decision | Recommendation (not a commitment) | Rationale |
|---|---|---|
| **Provider** | TO DECIDE after the §12.3 answers | Choose on database HA/PITR, in-country KMS/HSM and written residency terms first; price second. |
| **Price** (per tenant, tiers, what is included) | TO DECIDE | Cost drivers: managed PostgreSQL per tenant, nodes per zone, replicas, backup storage, TSA, support. |
| **Availability objective and SLA %** | TO DECIDE; propose 99.9 % monthly as an objective (§10), contractual only after the provider's own database objective is known | The tenant cannot exceed its database. |
| **Latency, RPO, RTO** | TO DECIDE; §10 proposals: p99 < 250 ms, RPO 5 min with PITR, RTO 4 h | To be confirmed by measurements on the provider. |
| **Support hours, languages, response times** | TO DECIDE (docs/SUPPORT.md) | No support commitment exists yet. |
| **TSA provider** | TO DECIDE; prefer an in-country RFC 3161 authority acceptable to the customer's regulator | Only a hash leaves; the token's trust is what the auditor relies on. |
| **Data-residency attestation wording** | TO DECIDE with counsel, after the provider's contract | No residency statement may be given to a customer before then. |
| **Sizing**: nodes, HPA bounds, dedicated node pools per customer | 2 nodes, replicas 2..4, shared pool for a standard tenant (§11.2) | Cost against isolation. |
| **Audit and backup retention defaults** | keep every audit row unless the contract sets a period; backups 14 days + PITR | Customer and regulatory decision. |
| **Domain names and certificate authority** | TO DECIDE | Tenant hosts in the Ingress and `PUBLIC_ORIGIN`. |
| **Support access from outside the UAE** | TO DECIDE; recommend none to customer data without the customer's approval | Part of the residency promise. |

## 13. Customer audit export and offline verification

A tenant's **security officer** or **auditor** (console roles; nobody else, docs/API.md §1) takes its audit evidence
away and checks it without trusting the service. Everything below exists in the product; each call is a console `GET`
(signed-in session cookie, no CSRF header needed for a GET) and counts against the console rate limit (120/min per
principal and per address, §11).

| Endpoint | Gives | Audited as |
|---|---|---|
| `GET /admin/v1/audit/verification` | **signed verification manifest**: the verified head of every chain, the sealed retention segments (without their HMAC, which needs the deployment's seal key), every anchor with the SHA-256 of its token, the server's own verification result; detached EdDSA JWS | `security audit_verification_export {manifestSha256, chains, anchors}` |
| `GET /admin/v1/audit/export?from=&limit=1000` | the hash-chained rows themselves (NDJSON), page by page (`X-Audit-Next-From`) | not per page (read-only pull) |
| `GET /admin/v1/audit/anchors` | the RFC 3161 tokens (DER, base64) | not audited |
| `GET /.well-known/jwks.json` | the public keys of the signature (public) | not audited |
| `GET /admin/v1/compliance/evidence?framework=<id>` | a signed evidence pack per framework (§3.8 of docs/API.md) | `security evidence_export` |
| SIEM push (`SIEM_WEBHOOK_URL`) | the same rows, continuously, HMAC-signed, to the customer's SIEM | the cursor |

**Export** (in this order: the rows must reach the manifest's heads and stop there, `until=` the heads; take the JWKS the
same day, a rotated key leaves it after 300 s):

```sh
O=https://<tenant host>; C="sid=<session cookie of a signed-in auditor>"
curl -fsS -b "$C" "$O/admin/v1/audit/verification" > verification.json
curl -fsS "$O/.well-known/jwks.json" > jwks.json
until=$(jq -r '.manifest.heads | to_entries | map(select(.value.seq > 0) | "\(.key):\(.value.seq)") | join(",")' verification.json)
from=1; : > audit.ndjson
while :; do
  curl -fsS -b "$C" -D headers.txt "$O/admin/v1/audit/export?from=$from&until=$until&limit=1000" >> audit.ndjson
  next=$(tr -d '\r' < headers.txt | awk 'tolower($1) == "x-audit-next-from:" { print $2 }')
  [ "$next" = "$from" ] && break; from=$next
done
curl -fsS -b "$C" "$O/admin/v1/audit/anchors" > anchors.json
```

**Verify offline**, on the auditor's machine, with this repository's verifier (Node 22, the TSA's CA certificate):

```sh
node scripts/audit/verify-export.ts --rows audit.ndjson --manifest verification.json --jwks jwks.json \
  --anchors anchors.json --tsa-ca tsa-ca.pem
```

It prints a JSON report and exits 1 on any problem. It checks: (1) the manifest's signature against the JWKS; (2) every
chain recomputed row by row, `hash = sha256(prevHash + canonical(row without hash))`, from the genesis (64 zeros) or
from the head of its sealed retention segment, up to the manifest's head of that chain, and only chains the manifest's
heads name (rows of any other node are a problem); no row after a head: the manifest's signature does not cover it, and
anyone can append rows with recomputed hashes, so such an unauthenticated tail fails the check (exit 1) even under a
pinned key; (3) the manifest's heads present in the rows; (4) each anchor
consistent with the rows: its head (or, over several chains, `sha256(canonical(heads))` and each head) equals the row
there; heads inside a sealed prefix are covered by the seal; (5) each token is the one the manifest hashed, and
`openssl ts -verify -digest <hash> -in <token> -token_in -CAfile tsa-ca.pem` accepts it. One token can also be checked
by hand: `jq -r '.items[0].token' anchors.json | base64 -d > t.der` then the `openssl` line above with that anchor's
`hash`.

`ok: true` (exit 0) needs more than consistency: the rows, the manifest and the JWKS all come from the tenant's server,
which could serve a consistent forgery. The report says `"result": "ok"` only when something it cannot forge vouches for
the evidence (`anchoredBy`): `tsa`, a token accepted by `--tsa-ca`, or `pinned signing key`, `--pin <jwks.json>`, a
JWKS the auditor kept out of band (at onboarding, or from an export already anchored). After a key rotation add
`--keyring <json>`, the keyring's public half (`{ keys: [{ kid, publicKey, introducedBy }] }`, as replicas receive it):
the pinned key's signed introduction of its successor carries the trust, a retired key introduces nothing. The keyring also
keeps retired public keys after they leave the JWKS, so a manifest signed before a rotation still verifies (against the
pinned key) with `--keyring`. Otherwise
`"result": "self-consistent only (not anchored)"`, `ok: false`, exit 3.

**What this proves, and what it does not.** An anchored head proves the chain up to it existed, unchanged, at the TSA's
time: rewriting it afterwards needs the TSA's key. Rows after the last anchor rest on the manifest signature (the
tenant's signing key) until the next anchor; keep each export, so a later rewrite is caught by comparing exports. The
server's checkpoint HMAC and segment seals use the deployment's seal key, which the customer does not hold: the
customer verifies the heads they commit to, not the HMAC. Pseudonymised exports (`pseudonymise=1`) do not hash and are
refused by the verifier. Rows removed by sealed retention cannot be recomputed by anyone (docs/API.md §3.9.4).

## 14. Not covered yet

- **Only test stand-ins for the customer side.** The production profile ran for real, but against a test IdP that
  signs in any listed user without a password, a test TSA with a throwaway signer, a throwaway CA and a local
  receiver; no real IdP, TSA, certificate authority or SOC integration was exercised. The sovereign overlay (§12) is
  rendered and checked by the k8s test, never applied to a real cluster; no managed PostgreSQL, no Ingress (so
  `TRUSTED_PROXIES` is proven by unit tests and not through a real ingress controller).
- **Node loss, multi-zone spread and PodDisruptionBudget behaviour during a real drain** not exercised (one node).
- **The standby is never Ready** in the default active/standby mode: Deployment status looks degraded by design.
  Cluster mode (§6a) removes that and the upgrade gap; its followers forward the admin plane to the leader, so a plain
  Service is enough. A schema migration still stops every node (12.3 s here).
- **No `gate_audit_verified` metric**: the integrity alert is inferred from readiness.
- **Backups**: archives are AES-256-GCM encrypted (`BACKUP_ENCRYPTION_KEY`, Secret `gate-backup`); its escrow outside
  the cluster is the operator's job and not automated. No off-site copy; the backup role needs `BYPASSRLS`; no WAL
  archiving: logical backups only.
- **Release image** (alpine plus the openssl package) not built here (offline); the local image is the larger
  PostgreSQL-based variant. The release workflow builds and Trivy-scans it, but that has not run here. No image
  signing or admission policy; no `ResourceQuota`/`LimitRange`.
- **Initial credentials**: the first start still creates the demo password accounts (unused: password sign-in is off)
  and a `bootstrap` PEP key; a tenant-specific first-administrator flow is not designed.
- **Rate limits** are per tenant through `RATE_LIMIT_PER_MINUTE` and `PEP_RATE_LIMIT_PER_MINUTE` (§11); there is no
  per-tenant aggregate quota across credentials, and no alert rule watches 429 rates.
