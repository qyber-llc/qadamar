# Deploying Qadamar

What ships: a `Dockerfile`, a `docker-compose.yml` (PostgreSQL 17, an active and a standby Qadamar node), health,
readiness and metrics endpoints, and `scripts/ops/backup.sh` / `restore.sh`. The compose file was checked with
`docker compose config`. The Dockerfile was built on 2026-11-10, offline, with `RUNTIME_BASE=runtime-base-postgres`
(`scripts/managed/build-local-image.sh`); the pinned alpine default has still not been built here. Kubernetes, one
instance per customer: [MANAGED-OFFER.md](MANAGED-OFFER.md).

The built console includes English, French and Arabic without a language service or outbound fetch. Language choice
persists per browser/user; Arabic sets `dir="rtl"`. A native Arabic review is required before customer use.
The browser CI tooling is separate from the runtime image: its read-only job verifies pinned Playwright and Chromium
artifacts, then requires the workflow tests ([CI.md](CI.md)). Local `checks.sh` stays offline and reports a skip when
Chromium is absent or cannot launch. Reflow and forced-colors test limits: [ACCESSIBILITY.md](ACCESSIBILITY.md).

## 1. Image

- Multi-stage: the console is built with Vite in one stage, the server's production dependencies (`pg` only) are
  installed in another, and the runtime stage holds the server sources, the toy-domain seed and the built console.
- Base images pinned **by digest** (`node:22.20.0-alpine@sha256:…`, `postgres:17-alpine@sha256:…`, the compose file's
  `postgres:17@sha256:…`); CI refuses a `Dockerfile` default without one. To move a base, read the new digest with
  `docker buildx imagetools inspect <image:tag>` and change tag and digest together. pnpm is pinned to the version used
  to write the lockfile (`PNPM_VERSION`) and to its tarball hash (`PNPM_SHA512`), which corepack checks; the corepack
  package itself (`COREPACK_VERSION`) is pinned by version only. The OS packages are upgraded at build time (`apk
  upgrade`) so the image scan passes: two builds of one commit can differ in OS package versions.
- The runtime contains the `openssl` command: the server runs `openssl ts -verify` on every RFC 3161 anchor against
  `TSA_CA_FILE` (required in production), and the node images do not ship it. The default `RUNTIME_BASE`
  (`runtime-base-node`) installs it with the package manager (network); `runtime-base-postgres` takes
  `POSTGRES_IMAGE`, which ships it, plus the node binary (offline builds; a larger image).
- The `ops` target (backup, restore) is slim by default (`OPS_BASE=ops-base-slim`): the digest-pinned Alpine
  `NODE_IMAGE` plus `bash` and `postgresql17-client` only (`pg_dump`, `pg_restore`, `psql`), with no PostgreSQL server,
  LLVM or `gosu`, and the OS packages upgraded to their fixed versions (network). The offline local build uses
  `OPS_BASE=runtime-base-postgres` (`POSTGRES_IMAGE` plus the node binary, `gosu` removed). Either way the image runs
  as uid 1000 and never switches user.
- Runs as uid 1000 (the node images' `node` user). The only writable path is `DATA_DIR=/var/lib/gate` (a volume), so the
  root filesystem can be read-only (`read_only: true` in compose, `--read-only` with `docker run`); `/tmp` is a tmpfs.
- `HEALTHCHECK` calls `GET /healthz` (process liveness only).

## 2. Compose: PostgreSQL 17 and two nodes

```sh
export POSTGRES_PASSWORD='<strong URL-safe password>'   # required; compose refuses to start without it
export SIGNING_KEY_SEAL="$(openssl rand -hex 32)"       # required; seals the signing keys stored in PostgreSQL. Keep it
                                                        # in your secret store: without it the nodes cannot sign again
export METRICS_TOKEN="$(openssl rand -hex 32)"         # optional; unset: /metrics answers 403 here (non-loopback bind; production: 32+ chars)
export RESOURCE_OWNERS='{"ruth":["carol"]}'             # optional; console user -> resource owner ids (docs/API.md 1)
docker compose up -d --build
```

- The compose file runs the **demo** profile inside containers, so it sets `DEMO_ALLOW_REMOTE=true` (the node must
  listen on the container address; it prints a warning at start) and publishes the ports on the host's loopback only.
  Without that flag the demo profile refuses any `HOST` other than loopback (`docker run` of the image included, whose
  `HOST` is `0.0.0.0`). For anything reachable from other machines use `GATE_PROFILE=production` (section 5).
- `SOD_HISTORY=server` is the default in every profile; the compose file makes it explicit. Caller-supplied maker and
  history are ignored for SoD-constrained actions (docs/API.md 2). Set `SOD_HISTORY=caller` only as a warned compatibility
  opt-in for demos/tests with PEPs you fully trust.
- The node refuses to start when the stored policy bundle's signature does not verify against the keyring in
  `DATA_DIR` (docs/API.md 3.10). Restoring the database without that volume therefore needs one start with
  `POLICY_SIGNATURE_ADOPT=1` after checking the bundle (in the demo profile: production refuses the flag). A new
  state document under an existing audit trail is treated the same way: it is not signed silently.

- `gate-active` publishes `127.0.0.1:8787`, `gate-standby` `127.0.0.1:8788`. Nothing else is in front of them: put
  your TLS proxy or load balancer there (`PUBLIC_ORIGIN`, `TLS_CERT_FILE`/`TLS_KEY_FILE`, see docs/API.md), and set
  `TRUSTED_PROXIES` to its address: otherwise every client shares the proxy's per-IP rate-limit bucket (120/min) and
  the audit records the proxy's address. Only list addresses that nothing else can connect from.
- PostgreSQL publishes no port. It sits on an `internal` network with the nodes; the nodes also join `edge`, because
  Docker publishes no port from a container that is only on an internal network. The demo-only compose file sets
  `DATABASE_TLS=disable` on that isolated network; this is not a production database transport configuration.
- **Database TLS is one explicit policy.** `DATABASE_TLS=verify-full` (the production default) checks both the server
  certificate chain and the hostname in `DATABASE_URL`; every non-local production host requires it. Set
  `DATABASE_TLS_CA_FILE` for a private CA (the system store is used otherwise), or `DATABASE_TLS_CERT_FILE` and
  `DATABASE_TLS_KEY_FILE` together for mutual TLS. `require` encrypts without authenticating the server. `disable` is
  accepted only outside production or for loopback/unix-socket hosts. Do not put `ssl`, `sslmode` or TLS file
  parameters in `DATABASE_URL`: they are refused so they cannot contradict the policy. The same settings cover all
  node connections and the migration, retention, backup and restore tools.
- **Active and standby are roles, not fixed names.** Whichever node takes the PostgreSQL advisory lock first serves;
  the other blocks before opening its port. `depends_on` makes `gate-active` start first, which usually wins, but not
  always. When the active node stops (crash, fail-stop on a storage error, `docker stop`), the standby takes the lock,
  reloads state and audit from the database and opens its port. A load balancer pointed at both ports with a check on
  `/readyz` (or `/healthz`) follows it.
- The standby's Docker health shows `unhealthy` while it waits: it has no open port yet. That is expected; it does not
  restart it (plain Docker does not restart unhealthy containers).
- The signing keyring (sealed with `SIGNING_KEY_SEAL`), console accounts, PEP credentials, lockouts, SCIM credential
  and SIEM cursor live in PostgreSQL (docs/API.md 3.9.1): a rotation or revocation on the active node holds on the
  standby after takeover, with nothing to copy. Console sessions are rows of `gate_session` (hashed ids): users signed
  in on the active node stay signed in after takeover. Both nodes still mount the `gate-runtime` volume, for
  `INITIAL-CREDENTIALS.txt` and for the one-time import of a file-based deployment's `DATA_DIR`.
- **Decision commit latency.** Concurrent decision-only requests share one prepared PostgreSQL statement for audit,
  metadata and any tokens or BLP marks. The statement's implicit transaction is durable before any of those requests
  answers; other writes use explicit transactions. Keep `synchronous_commit` enabled and size the primary for WAL
  flush latency: this optimization removes round trips, not the durability wait. Large-world laptop measurements at
  concurrency 8, 32 and 64, including p50/p99, are in docs/PERFORMANCE.md.
- **Search memory and latency.** AuthZEN resource search keeps attribute/value position indexes for each stored resource array and
  rebuilds them after an in-place record patch; subject search shares relation reachability before point decisions. Each served tenant’s world and these indexes remain in memory; tenant partitions can exclude other tenants
  (see [Tenant partitions](#tenant-partitions)), so include the attribute paths your policy reads in capacity measurements. The
  5,000-subject / 50,000-resource before/after p50 and p99 figures are in docs/PERFORMANCE.md.
- **Upgrading a deployment that kept these in `DATA_DIR`:** set `SIGNING_KEY_SEAL`, start one node on the volume that
  holds the current files; it imports them once (logged) and seals the keys before they reach the database. Then
  remove `credentials.json`, `signing-keys.json`, `signing-private.pem`, `lockouts.json`, `scim-credential.json`,
  `siem-cursor.json` and `approval-prefs.json` from the volume (they are no longer read or written). Starting without a seal is refused unless
  `ALLOW_CLEAR_SIGNING_KEYS=true`, which stores the private keys in clear in `gate_doc`.
- **Takeover time.** The active node records a verified audit checkpoint after each full recheck (every 5 minutes),
  authenticated with an HMAC keyed from `SIGNING_KEY_SEAL` (HKDF, its own label); a forged one stops the start. In
  every profile, production included (since 0.5.0), a standby that takes over verifies only from it (plus the
  anchored rows) before opening its port, then verifies the whole chain in the background: takeover follows the rows
  written since the last recheck, not the log size (about 0.1 s at a million rows on a laptop, against 9 s before;
  docs/PERFORMANCE.md). A row rewritten before the checkpoint is caught by that background verification
  rather than before the port opens (docs/API.md 3.9.1, detection window and failure path). Watch
  `gate_audit_full_chain_verified` (0 until it ends) or `audit.fullChain` in `/readyz`; on a detected rewrite the node
  stops deciding and fails `/readyz`, and the next start refuses the log.
- **Several deciding nodes (cluster mode).** Set `GATE_CLUSTER=true` and a distinct `GATE_NODE_ID` on every node
  (`GATE_ADVERTISE_URL` to its reachable address, optionally `GATE_MAX_STALENESS_MS`, default 2000) and start as many
  as needed against the same database; every node opens its port at once. Put all of them in the load balancer's
  pool for `/access/`, `/x/` and `/xacml/`, health-checked on `/readyz` (503 while a node is behind its staleness
  bound). Route `/admin/` and `/scim/` (and the OIDC callback under `/admin/v1/oidc/`, the SAML ACS and logout under `/admin/v1/saml/`) to the node whose `/leaderz` is
  200; a follower answers them `409 not_leader` with the leader's advertised URL. When the leader stops, the followers
  keep deciding and one of them takes the lead within about half a second (the poll interval); console users sign in
  again on it. A node id must not run twice: a second process with the same id waits, like a standby, until the first
  stops. Leaving `GATE_CLUSTER` unset keeps the active/standby behaviour above. `RATE_LIMIT_PER_MINUTE` and
  `PEP_RATE_LIMIT_PER_MINUTE` are cluster-wide: each node leases at most 1,000 tokens (a tenth of a smaller bucket, or a
  larger single-request cost) from `gate_rate_limit`, then spends locally without a query per request. Leases never
  overspend; with N nodes and lease size B, up to N(B−1) unused tokens per key can temporarily reduce admission. Use the
  same limits on every node. Rows idle for an hour are swept on later leases. Before starting an existing cluster on this
  version, run `SCHEMA` and `serviceGrants` as the owner to add the disposable table.
- **Upgrading to per-node chains.** Stop every node, run `SCHEMA` (packages/pdp-http/src/postgres.ts) as the owner role,
  grant the service role the three new tables (`serviceGrants` in the same file), then start. Existing audit rows
  are kept byte for byte as chain `"0"`, which a node with the default `GATE_NODE_ID` continues; when the service role
  owns the tables (the compose setup) the first start migrates by itself.
- **Upgrading to session high-water marks (`gate_blp_mark`).** The same steps: run `SCHEMA` as the owner role and grant
  the service role the new table (`serviceGrants`), then start; a service role that owns the tables migrates by itself.
  An archive taken before this version has no `gate_blp_mark`: `restore.sh` restores it and creates that table empty
  (it says so); any other missing table still refuses the archive. Marks are disposable, but not free to lose: a
  restore without them (an older archive, or marks newer than the backup) lowers protection for the sessions that were
  in flight at backup time, whose next writes are decided as if they had read nothing. Those sessions end within
  8 hours (15 minutes idle); to close the gap at once, have the PEPs start new sessions after a restore.
- **Upgrading to PDP-issued sessions (`gate_blp_session`).** Run `SCHEMA` and `serviceGrants` as the owner before
  starting the new nodes; owner-managed tables migrate at start. Every PEP must move to `openSession` and
  `context.sessionToken` before production starts refusing raw `sessionId`. An older archive has no session registry,
  which `restore.sh` creates empty: previously issued tokens are closed (fail closed) and PEPs open new ones. Existing
  raw-id marks are not migrated into the new subject scopes, so open fresh sessions after the upgrade as well.
- **Upgrading to resource registration (`gate_retired`).** The same steps: run `SCHEMA` as the owner role and grant
  the service role the new append-only table (`serviceGrants`), then start. An archive taken before it has no
  `gate_retired`: `restore.sh` creates it empty (nothing could be retired before it existed).
- **Upgrading from 0.6.0 to per-record state.** Stop every node, run `SCHEMA`, `serviceGrants` and `backupGrants` as
  the owner, then start one target node. Under the migration advisory lock it moves subjects, resources and tuples from
  the old `state` document to `gate_subject`, `gate_resource` and `gate_tuple`, preserving their order and state digest,
  and leaves only policy/workflow metadata in `gate_doc`. The transaction is automatic, idempotent and all-or-nothing;
  `gate_state_change` starts empty for that baseline. Start the remaining nodes only after the first succeeds. An older
  archive restored by `restore.sh` goes through the same migration before the script validates the tables. A 0.6.0 binary
  must not be restarted against the migrated schema: restore the pre-upgrade archive to roll back.
- First start writes `INITIAL-CREDENTIALS.txt` (mode 600) into that volume. Read it once with
  `docker compose exec gate-active cat /var/lib/gate/INITIAL-CREDENTIALS.txt`, store the secrets, then delete it.
- **Not least privilege as shipped:** the nodes connect as the role compose creates for the database, which owns the
  tables and is a superuser of that cluster. For production, use the role layout in docs/API.md 3.9.1 (an owner role
  migrates, the service role gets only `SELECT, INSERT, UPDATE` on `gate_doc`, `gate_audit_meta`, `SELECT, INSERT` on
  `gate_audit`, `gate_anchor`, `gate_performed`, `gate_retired`, `gate_state_change`, `SELECT` on `gate_audit_segment`,
  `SELECT, UPDATE` on `gate_sync`, and `SELECT, INSERT, UPDATE, DELETE` on `gate_subject_identity`, `gate_token`,
  `gate_session`, `gate_blp_mark`, `gate_subject`, `gate_resource`, `gate_tuple` and `gate_rate_limit`) and give the nodes the service
  role's URL. `GATE_PROFILE=production`
  (section 5) refuses to start with the compose role as shipped.

## 3. Probes and metrics

| Endpoint | Auth | Meaning |
|---|---|---|
| `GET /healthz` | none | The process answers HTTP. Nothing else. |
| `GET /readyz` | none | Pending writes committed and audit chain verified; `503 {"status":"unavailable"}` otherwise. The result is cached for 5 s. With PostgreSQL the chain and store result is the shared recheck, up to 60 s old, and `audit.fullChain` is false while the background verification after a start from the checkpoint runs. Active/standby: only the active node has an open port. Cluster: also 503 while the node's shared state is older than `GATE_MAX_STALENESS_MS`; the body adds `role` (`leader`/`follower`) and `node`. |
| `GET /leaderz` | none | Cluster: `200 {"leader":true,"node"}` on the leader (route `/admin/` and `/scim/` there), `503` on followers. Without PostgreSQL, or active/standby: always 200. |
| `GET /metrics` | `Authorization: Bearer $METRICS_TOKEN` when set; without it, open on a loopback listen address and `403` on any other | Prometheus text format. |

Metrics: `gate_decisions_total{effect}`, `gate_http_request_duration_seconds{route}` (fixed route families),
`gate_audit_length`, `gate_audit_last_anchor_age_seconds` (`-1` without anchor), `gate_commit_duration_seconds`,
`gate_active_node`, `gate_break_glass_notices_total{outcome}`. No label carries a subject, resource, principal, IP, path or secret. Counters and histograms are
per process and restart from zero after a restart or failover. Every request, probes included, counts against the
per-IP rate limit (120/min by default), so scrape and probe intervals must stay well below it per source address.
Behind a proxy the "IP" is the client address resolved through `TRUSTED_PROXIES` (docs/API.md 3.1.1).

## 4. Backup and restore

Both scripts read `DATABASE_URL`, `BACKUP_FILE` and `BACKUP_ENCRYPTION_KEY` from the environment, print no connection
string and no key, and need PostgreSQL client tools of major version 17 or later and `node` 22.18 or later (it runs
`scripts/ops/archive-crypt.ts` directly). The password (in the URL's user info or a `password=`
parameter, `MAINTENANCE_DATABASE_URL` included) is removed from the URL and handed to `pg_dump`, `pg_restore`,
`createdb`, `dropdb` and `psql` in `PGPASSWORD`; the URL reaches `node` through the environment. No password appears in
a process argument list, and neither does the key. A URL without a password falls back to `PGPASSWORD`, `~/.pgpass`
or `PGPASSFILE` as usual. `DATABASE_TLS` and its CA/client certificate file settings also apply: the scripts map them to
`PGSSLMODE`, `PGSSLROOTCERT`, `PGSSLCERT` and `PGSSLKEY`, and validate both the target and maintenance hosts. These
tools (and `audit-retention.ts`, `migrate-records.ts`) use the production profile unless `GATE_PROFILE=demo` is set:
`DATABASE_TLS` defaults to `verify-full` and a non-local host requires it; URL `ssl*` parameters are refused. Without
`DATABASE_TLS_CA_FILE`, `verify-full` gives libpq `PGSSLROOTCERT=system`, which libpq 16 or later understands (the ops
image ships PostgreSQL 17): with older client tools, set `DATABASE_TLS_CA_FILE`.

```sh
# BACKUP_ENCRYPTION_KEY comes from the secret store (see below), exported without shell tracing
# backup: custom format, all 17 gate_* tables, including per-record state and its change log
# (schema, data, keys, indexes, forced RLS policies)
DATABASE_URL=postgresql://owner@db/gate BACKUP_FILE=/backups/gate-$(date -u +%Y%m%dT%H%M%SZ).dump.gcm scripts/ops/backup.sh

# restore into a NEW database (refused if it exists; removed again if the restore fails)
DATABASE_URL=postgresql://owner@db/gate_restored BACKUP_FILE=/backups/gate-....dump.gcm \
  MAINTENANCE_DATABASE_URL=postgresql://admin@db/postgres scripts/ops/restore.sh
```

- `backup.sh` dumps one consistent snapshot (`pg_dump` runs in a single repeatable-read transaction) into a private
  `mktemp -d` directory (under `TMPDIR`: point it at local, non-synced disk with room for one dump), checks with
  `pg_restore --list` that every table's schema and data are present, encrypts it (mode 600) into a temporary directory
  next to `BACKUP_FILE`, then links it to `BACKUP_FILE`, refusing to overwrite an existing file. The plaintext never
  touches the `BACKUP_FILE` directory (which may be synced off-site) and is removed on success and failure alike.
- `restore.sh` decrypts `BACKUP_FILE` into a private `mktemp -d` directory and checks its tag first: a wrong key or a
  damaged or tampered file prints `Restore refused: ...` and stops before any database is created. It then validates
  the archive, creates the target database (with `MAINTENANCE_DATABASE_URL`, default: the same
  server's `postgres` database), restores the whole archive in one transaction and runs `migrate-records.ts`. A current
  archive is a no-op there; a 0.6.0-or-older archive has its whole-document records imported into the new tables in one
  transaction before the script checks every gate table exists. An archive from before `gate_session` (0.4.x) is also
  accepted: that table is created empty (console sessions are disposable; users sign in again), and so is one without
  `gate_blp_mark`, `gate_blp_session`, `gate_retired` or `gate_rate_limit` (shared rate buckets are disposable); any other missing table is refused. Restore without owners and grants: the objects
  belong to the role in `DATABASE_URL`, so restore as the owner role, then grant the service role as in section 2.
- **In the backup:** the signing keyring (sealed), console accounts, PEP credentials, lockouts, SCIM credential, SIEM
  cursor and audit checkpoint are `gate_doc` rows; console sessions are `gate_session` rows (hashes of their ids; a
  restore later than 15 minutes after the backup finds them all expired). **Not in the backup:** `SIGNING_KEY_SEAL`;
  keep it in the secret store, because a restored keyring cannot sign or be read without it. After a seal rotation,
  keep the old key as long as archives taken before it are retained (docs/handbook/operations/rotate-credentials.md). The archives are encrypted (below); copying
  them off-site is yours.
- After a restore, start a node on the restored database and check `/readyz` and `GET /admin/v1/audit/verify`
  (auditor) before admitting traffic.

### Archive encryption (`BACKUP_ENCRYPTION_KEY`)

- Mandatory for both scripts. 32 bytes, as 64 hexadecimal characters or unpadded base64url (the same rule as
  `SIGNING_KEY_SEAL`); anything else is refused. Generate it with `openssl rand -hex 32`.
- Keep it in the secret store, **separately from the archives and from `SIGNING_KEY_SEAL`**: whoever holds an archive
  and its key reads every `gate_*` row; losing the key loses every archive made with it.
- Rotation: a new key applies to new backups only; nothing re-encrypts old archives. Keep each old key as long as the
  archives it encrypted are retained, and record which key goes with which archive (by date).
- Format (`scripts/ops/archive-crypt.ts`, Node `crypto` only, streaming): `GATEBK` (6 bytes), version byte `1`, a
  random 12-byte nonce, then the AES-256-GCM ciphertext of the custom-format dump, then the 16-byte tag. The 19-byte
  header is authenticated as GCM additional data. Output files are created exclusively (`wx`) with mode 600.
- Decryption is refused (exit non-zero, output file deleted) on a wrong key, a changed header, nonce, body or tag, a
  truncated or empty file. Only a file whose tag verified survives, so `restore.sh` never restores unauthenticated
  data. Standalone: `BACKUP_ENCRYPTION_KEY=... node scripts/ops/archive-crypt.ts decrypt <in> <out>`.

### Point-in-time recovery: the hosting's

`backup.sh` is a logical snapshot: it cannot replay what was committed after it ran. Bounding the loss below the backup
interval needs WAL archiving on the PostgreSQL server, which these scripts do **not** provide or check. A managed
PostgreSQL must give, and you must confirm in writing or in its console:

- `wal_level=replica` (or `logical`), `archive_mode=on`, and an `archive_command` / `archive_library`, or the
  provider's continuous backup (which sets these for you).
- `archive_timeout` set to bound the RPO on a quiet database (e.g. `60s`): a WAL segment is archived at least that
  often.
- Base backups on a schedule (e.g. daily), and a retention window covering how far back you must recover (WAL kept
  from the oldest retained base backup onward).
- Encryption at rest of the WAL archive and the base backups, and a copy in a second region.
- Restore with `restore_command` and `recovery_target_time` (or the provider's "restore to a point in time") into a
  new instance, never over the live one.
- A PITR drill on a schedule: restore to a chosen time, start a Qadamar node on it, check `/readyz` and
  `GET /admin/v1/audit/verify`. None has been run for this product.

What the scripts here do not do: WAL archiving, base backups, PITR, retention or expiry of archives, off-site copy,
key custody, or scheduling (run `backup.sh` from your scheduler).

### What the drill measured (not promises)

`packages/pdp-http/test/backup-restore.test.ts` runs when `TEST_DATABASE_URL` points at a throwaway PostgreSQL
(`PG_TOOLS_CONTAINER=<postgres container>` runs the client tools through `docker exec` when they are not installed
locally). Without local tools or that container the two live drills skip with an explicit message; setting
`BACKUP_TESTS_REQUIRED=1` makes their absence fail instead. `tools/ci/checks.sh` sets it whenever `PG_TOOLS_CONTAINER`
is present, so CI cannot silently skip the drills. The test starts a node on a fresh database, records a decision and a pending change, stops the node, runs
`backup.sh`, **drops the source database**, runs `restore.sh` into a new one, checks every row of the eighteen tables and
every key, index and RLS policy against the source, then starts a node on the restored database, finds the change,
verifies the audit chain through the admin API and records one more decision on it. With encryption it also checks
that the archive starts with the `GATEBK` header and shows no table name in clear, and that `restore.sh` refuses an
archive with one flipped ciphertext byte and a wrong key, without creating the target database.
`packages/pdp-http/test/backup-crypt.test.ts` (no database) covers the format, mode 600, refusals and a 6 MB stream.

Two runs on 2026-11-10, a laptop (Apple M5 Pro), PostgreSQL 17 in Docker, tools through `docker exec` (included in
the times), a tiny dataset (3 audit rows, 13 KB archive), encryption included: backup 226 / 199 ms, restore script
583 / 531 ms, restore through a verified node that accepted a new decision 824 / 732 ms. The encryption step alone,
same laptop, file in the page cache: 13 KB 0.04 s each way (mostly `node` start-up); 256 MiB encrypt 0.18 / 0.23 s,
decrypt 0.19 / 0.19 s.

| | What the drill measured (laptop, Docker, 3 audit rows) | What the hosting must provide (targets you set) |
|---|---|---|
| **RPO** | Zero committed changes lost between the snapshot and the restore, with no writes during the backup. | With PITR: bounded by `archive_timeout` (e.g. 60 s). Without it: the interval between `backup.sh` runs; anything committed after the last backup is lost. |
| **RTO** | Under a second: restore script 583 / 531 ms, through a verified node 824 / 732 ms. | Measured on a copy of real data: restore and the startup chain scan grow with the audit; add fetching the archive off-site, the key from the secret store, and the people involved. |
| **Tamper / wrong key** | Refused before `createdb`, no database created. | Key custody separate from the archives and from `SIGNING_KEY_SEAL`. |

Neither column is a commitment: measure your own drill, PITR included, before stating an RPO or RTO.

### Audit retention and erasure

Leave `AUDIT_RETENTION_DAYS` unset to retain all rows. Setting 1..36500 requires `SIGNING_KEY_SEAL`. File mode seals
and removes an expired prefix at startup and daily. PostgreSQL retention is deliberately **not** performed by the
service: stop every Qadamar writer, take a backup, then run `node scripts/ops/audit-retention.ts` with the table owner's
`DATABASE_URL`, `DATABASE_TLS` (and any CA/client-key files), `SIGNING_KEY_SEAL`, `AUDIT_RETENTION_DAYS`, and the production `TSA_URL`/`TSA_CA_FILE`. The script
authenticates the removed prefix and last head, anchors the sealed heads, appends retention markers, and only then
deletes in the same transaction. It refuses, changing nothing, unless the stored authenticated checkpoint is extended
by the live chains, so start Qadamar once (until `/readyz` shows `fullChain: true`) after a restore or a previous run.
The owner's temporary `DELETE`/`UPDATE` grants are revoked at the end of every run. Do not grant `DELETE` on
`gate_audit` or `gate_audit_segment` to the service role.
See docs/API.md §3.9.4 for the seal format and what remains provable.

New person ids (subjects, human actors, makers, checkers, approvers, break-glass openers, SCIM batch ids) enter audit
rows only as per-person HMAC pseudonyms; technical actors (`pep`, `pep:<credential>`, `system`, `scim`, `bootstrap`,
`unknown`) and policy-level notification targets stay readable. Erasure is a two-person change: one security officer
calls `POST /admin/v1/privacy/subjects/<id>/erasure`, a different one approves the resulting change; neither may be
the subject, and open break-glass access or pending access reviews of the subject block it. Qadamar then deletes the
separate raw-id/key mapping and audits the erasure with the change id. Coordinate a pause in new activity for that
subject across all nodes before erasing; later activity creates a fresh mapping. This does not erase backups, SIEM
copies taken earlier, or raw ids already written by an earlier version. Include mapping tables/files and external
copies in the organisation's erasure procedure.

**Upgrading a file-mode chain without a keyed checkpoint.** The first start with `SIGNING_KEY_SEAL` refuses a
non-empty chain that has no `audit-checkpoint.json` and logs its head hash. Review the chain (verify it against your
anchors or an independent copy), then start once with `AUDIT_CHECKPOINT_MIGRATE=<that hash>` and remove the variable;
the migration is audited as `checkpoint_migrated`. A checkpoint that disappears later is an integrity incident
(docs/handbook/operations/audit-tamper-response.md), never a reason to migrate again.

**Demo residual risk.** `SIGNING_KEY_SEAL` and TSA anchoring remain optional only in demo. Without a seal, file mode
has no keyed checkpoint and an attacker with write access to `audit.jsonl` can recompute the entire plain chain;
without an external TSA anchor or independent export there is no trusted head to reveal it. Demo is loopback-only by
default and not an evidence-production configuration. Production requires the seal, PostgreSQL, and HTTPS TSA with a
pinned CA; anchoring runs automatically every `ANCHOR_INTERVAL` (default 3600 seconds).

## 5. Production profile (`GATE_PROFILE=production`)

`GATE_PROFILE` is `demo` (default: today's behaviour, every setting optional) or `production`; any other value stops
the process. In production the node **refuses to start** unless every line below holds, and names all that fail in
one error (`GATE_PROFILE=production refused to start:` followed by one `- ` line per failure). The checks run before
the node takes the PostgreSQL lock or migrates anything (`packages/pdp-http/src/profile.ts`).

- [ ] **TLS**: `PUBLIC_ORIGIN` is `https://…` (also when the node serves TLS itself with `TLS_CERT_FILE` and
      `TLS_KEY_FILE`: cookies, HSTS, the OIDC redirect and the SAML endpoints are derived from it).
- [ ] **SSO with MFA**: `OIDC_ISSUER` (with `OIDC_CLIENT_ID`, `OIDC_ID_CLAIM`) or `SAML_IDP_ENTITY_ID` (with
      `SAML_IDP_SSO_URL`, `SAML_IDP_CERT_FILE`, `SAML_AUTHN_CONTEXT`, `SAML_ID_ATTRIBUTE`) is set. OIDC sign-in always
      requires MFA from the IdP (`amr` `mfa`/`mca`, or `OIDC_ACR`); SAML sign-in requires an `AuthnContextClassRef` from
      `SAML_AUTHN_CONTEXT`, which must list only classes your IdP issues after a second factor. There is no setting that
      turns either off. For SAML, give the IdP the metadata at `${PUBLIC_ORIGIN}/admin/v1/saml/metadata`, configure it to
      sign assertions with RSA-SHA256 or stronger (SHA-1 is refused), and copy its signing certificate into
      `SAML_IDP_CERT_FILE` (both certificates during a rotation) (docs/API.md 3.1.1).
- [ ] **Password sign-in off**, or every local account has TOTP active (docs/API.md 3.1.2). With `OIDC_ISSUER` set,
      password sign-in is off unless `PASSWORD_LOGIN=on` (the same with `SAML_IDP_ENTITY_ID`). To keep local recovery accounts: start once in the demo
      profile against the same database with `SIGNING_KEY_SEAL` set, sign in as each local account, enrol and activate
      TOTP, store the recovery codes, then restart in production. The accounts are read from the `credentials` row of
      `gate_doc` (before the first PostgreSQL start has imported it, from `DATA_DIR/credentials.json`); the refusal
      lists the accounts still without TOTP.
- [ ] **`DATABASE_URL`** is set, and its role (checked in the database): is not, directly or through membership, a
      superuser, and holds no `BYPASSRLS` or `CREATEROLE` (itself or through a role it is a member of); neither owns nor
      is a member of the role that owns any of the 17 Qadamar tables (`GATE_TABLES` in `profile.ts`: `gate_doc`,
      `gate_audit`, `gate_audit_meta`, `gate_anchor`, `gate_audit_segment`, `gate_subject_identity`, `gate_sync`,
      `gate_token`, `gate_performed`, `gate_session`, `gate_blp_mark`, `gate_blp_session`, `gate_retired`, `gate_subject`, `gate_resource`,
      `gate_tuple`, `gate_state_change`, `gate_rate_limit`); holds no privilege that rewrites or empties append-only evidence (`gate_audit`,
      `gate_anchor`, `gate_audit_segment`, `gate_performed`, `gate_retired`, `gate_state_change`, checked with
      `has_table_privilege`); and finds all 18 tables already created in schema `public` (by an owner role, docs/API.md 3.9.1), since otherwise it would create,
      and own, them. Table names are qualified with the schema, not resolved through `search_path`.
- [ ] **`DATABASE_TLS=verify-full`** for a non-local `DATABASE_URL` host (the production default). The server
      certificate's chain and hostname are both checked; set `DATABASE_TLS_CA_FILE` for a private CA, and optionally
      `DATABASE_TLS_CERT_FILE` with `DATABASE_TLS_KEY_FILE` for mutual TLS. `require` and `disable` are refused for a
      non-local host. The evidence baseline reports the mode and whether a private CA/client certificate is configured.
- [ ] **`SIGNING_KEY_SEAL`** is set (decision-token keys and TOTP secrets sealed at rest in `gate_doc`, audit
      checkpoint authenticated), and neither `ALLOW_CLEAR_SIGNING_KEYS` nor `POLICY_SIGNATURE_ADOPT` is. The key is
      backed up outside the secret store (offline escrow under dual control): without it the signing keys and TOTP
      secrets cannot be recovered, and Qadamar refuses to start rather than replace them. Rotate it with
      `SIGNING_KEY_SEAL_PREVIOUS` (docs/handbook/operations/rotate-credentials.md), which every start accepts, in
      production too; remove it once the start audited `seal_key_rotated`.
- [ ] **`SOD_HISTORY=server`** (the default; do not opt into `caller`): SoD-constrained actions trust only server-recorded
      history, never a caller-supplied `makerId` or `priorActions` (docs/API.md §2); this holds for `/access`, XACML and the gateway.
- [ ] **Context claim scopes on every PEP credential**: create each credential with `contextScopes` listing only the
      signals it must assert, optional `networks`/`countries` constraints and, for independently proven posture, trusted
      Ed25519/ES256 attester public keys and audience (docs/API.md §2 and §3.10). Production requires the field at
      creation. Older unscoped credentials, `bootstrap` included, receive the empty scope and cannot assert protected
      signals. Demo alone keeps their old behaviour for one version, with response and log deprecation warnings. Rotate
      to named scoped credentials before production; scope changes require a new credential, not secret rotation.
- [ ] **`BLP_SESSION_REQUIRED=true` and PDP session tokens at every PEP**: every classified read and cleared write
      carries `context.sessionToken` from `POST /x/v1/sessions` (the SDKs' `openSession`). Production refuses raw
      `sessionId`. Tokens expire after one hour or 15 minutes idle and can be closed or revoked immediately by an
      administrator by token id, subject or credential; revocation also kills their unconsumed decision tokens across
      PostgreSQL nodes and carries tombstones to replicas. Open replacements rather than sharing tokens across subjects
      or credentials. `BLP_SESSIONS_PER_SUBJECT` (default 4) and `BLP_SESSIONS_PER_CREDENTIAL` (default 10,000) cap concurrent tokens, and
      `BLP_SESSION_CREATION_PER_MINUTE` (default 60) rate-limits creation. The mark is shared per (credential, subject),
      so a fresh token cannot reset it. Related decisions and open/close are serialized locally and through PostgreSQL
      advisory locks; a lock wait beyond 15 s returns 503. Unrelated subjects, no-session traffic and L0 reads bypass it.
- [ ] **CBAC (context) rules have trustworthy, current PEP signals on every request.** When the bundle uses `context`, each PEP
      supplies the required `ip`, `country`, device posture, `authTime`, `mfaTime`, `authMethods` and `riskScore` from
      its authenticated session/MDM/IdP integration; an absent required signal denies. Qadamar validates shape, bounds and
      credential scope. Where independent proof is required, configure an attester and send its short-lived signed JWS;
      without that hook Qadamar cannot prove device compliance or MFA itself. The gateway takes `ip`
      from its socket and authentication facts from its own session, never client headers. **Behind a load balancer,
      give the gateway `trustedProxies`** (the balancer addresses): otherwise every client has the balancer's IP and
      passes an `ipRanges` rule (or `trustedNetworks`) that covers it. The gateway cannot see the policy bundle, so it
      cannot refuse to start over this: it warns at creation when `trustedProxies` is unset; check the warning is
      absent wherever a balancer sits in front. Use the gateway's `attestContext(context, req)` hook to obtain fresh
      attester signatures over the fully resolved context. Do not cache and replay a decision for another request context.
- [ ] **`METRICS_TOKEN`** is set, at least 32 characters (`/metrics` is not public).
- [ ] **`TSA_URL`** (https) and **`TSA_CA_FILE`** are set (audit head anchored and the token checked against the CA).
- [ ] **`CLOCK`** is not set (a fixed clock is for demos).
- [ ] **`BREAK_GLASS_WEBHOOK`** (https) and **`BREAK_GLASS_WEBHOOK_SECRET`** (32+ characters) are set (docs/API.md
      3.6.1).
- [ ] **`OTEL_EXPORTER_OTLP_ENDPOINT`**, when set, is https (plain http only to a loopback collector).
- [ ] **Not the demo world**: on its first start (no stored state yet) a production node refuses to seed from a
      `WORLD_DIR` whose `world.json` is marked `"demo": true`, which the image's default (`examples/toy-domain`, fictional
      people) is. Point `WORLD_DIR` at the tenant's own `world.json` and `bundle.json`. `ALLOW_DEMO_WORLD=true` lifts
      this for local test deployments only (the `deploy/k8s/overlays/local` overlay sets it for `smoke.sh`). Checked
      when the state is seeded (`store.ts`), after the database checks; a node with stored state never reads `WORLD_DIR`.
- [ ] Alert on `gate_audit_full_chain_verified` staying 0 for longer than a full recheck takes on your log (shipped as
      `GateAuditFullChainUnverified`, 15 min, in `deploy/k8s/monitoring/alerts.yaml`; every
      start from the checkpoint verifies the whole chain in the background; see Takeover time).

Not checked, yours to do: the IdP's own MFA policy,
encryption of `DATA_DIR`, custody of `BACKUP_ENCRYPTION_KEY` and the off-site copy of the (encrypted) backups, WAL
archiving and point-in-time recovery (section 4), a SIEM receiver (`SIEM_WEBHOOK_URL`, optional), the hosting network.

## 6. Impact-preview budget

`IMPACT_MAX_EVALUATIONS` (default 100,000) bounds the **affected** subject × resource × action cells after network,
context-class and maker/history variants, not the whole world grid. The preview reports the unique affected-cell count
and its selection reasons in `impact.analysis`. A no-op evaluates zero cells; a tuple edit follows only its relation
dependencies, and a policy edit follows the changed rule or definition. CBAC previews evaluate at most 32 representative
context classes per network, with one-signal boundary variants before their cross-product. `contextAnalysis.truncated`
means the cap omitted combinations: split the change instead of treating an empty aggregate diff as proof of safety.
`contextAnalysis.incomplete` also covers unsupported ABAC comparisons and always requires security-officer approval.
CIDR classes come from interval boundaries rather than a fixed address list; ABAC equality, in-list, numeric and instant
literals contribute representatives. Mandatory-model, broad-rule and relation-rewrite edits can still select a world-wide
set and be refused with 422. Split
such proposals rather than raising the budget without measuring on the production-shaped world; `scripts/bench/impact.ts`
and docs/PERFORMANCE.md provide the local measurement path.

## 7. Stateless decision replicas (optional)

Replicas (docs/API.md §3.9.5) decide without a database, from the signed state the Qadamar pods stream to them, and keep
their own durable audit chain that they ship back. Use them to add deciding capacity close to PEPs without adding
PostgreSQL connections; they forward what they may not decide (session-marked reads, separation of duty, certified
actions, the console, SCIM, registration) to the Qadamar pods.

- **Kubernetes.** `deploy/k8s/components/replicas`: a StatefulSet `gate-replica` (pod name = `GATE_NODE_ID` = audit
  chain; a 1 Gi volume per pod holds that chain), a Service `gate-replica` for PEPs, a NetworkPolicy that lets the
  replicas reach only the Qadamar pods and kube-dns (admitting only the ingress controller and Prometheus pods on 8787; and the namespaces labelled `qadamar/pep=true`, the opt-in for in-cluster PEPs), and a patch giving the Qadamar pods `GATE_REPLICA_KEYS`. Add it before the
  cluster component: `components: [../../components/replicas, ../../components/cluster]`. Create a group master
  (`openssl rand -base64 32 | tr '+/' '-_' | tr -d '='`) and the Secret `gate-replica` with
  `GATE_REPLICA_KEYS=gate-replica-*=<master>` (only the Qadamar pods mount it), plus `ca.pem` when the Qadamar pods' TLS
  certificate is not publicly trusted. Derive each pod's own key and create Secret `gate-replica-keys` from them:
  `node scripts/ops/replica-key.ts gate-replica-0 gate-replica-1 < master > keys.env`, then
  `kubectl create secret generic gate-replica-keys --from-env-file=keys.env` (add an entry before scaling up). An init
  container copies the entry named after the pod into a memory volume; the gate container reads it through
  `GATE_REPLICA_KEY_FILE` and never mounts the Secret, so a compromised replica cannot sign as a sibling or write its
  chain. PARAMETERS: `GATE_REPLICA_OF` (the Qadamar pods over TLS: they must serve TLS themselves with a certificate naming
  that host), `PUBLIC_ORIGIN` or `TLS_CERT_FILE` for the PEPs, the volume size and storage class.
- **Elsewhere.** Run the image with `GATE_REPLICA_OF`, `GATE_NODE_ID`, `GATE_REPLICA_KEY` or `GATE_REPLICA_KEY_FILE`
  (its own key, or under a group its key from `scripts/ops/replica-key.ts`; and optionally
  `GATE_REPLICA_PIN`, `GATE_REPLICA_CA_FILE`), no `DATABASE_URL`, and a persistent `DATA_DIR`; add the id and key to
  every database node's `GATE_REPLICA_KEYS` and restart them. `GATE_PROFILE=production` on a replica checks
  `GATE_REPLICA_OF` is https, TLS towards the PEPs (`TLS_CERT_FILE` or an https `PUBLIC_ORIGIN`), `METRICS_TOKEN` and no
  `CLOCK`; separation of duty, session marks and `BLP_SESSION_REQUIRED` come from the database nodes.
- **Trust on first start.** Prefer `GATE_REPLICA_PIN` (the `x` of the database nodes' active key in
  `/.well-known/jwks.json`, read over a channel you trust). Without it the replica trusts the JWKS served over TLS
  verified against `GATE_REPLICA_CA_FILE`. Rotations later need no change on the replica.
- **Probes and alerts.** `/readyz` is 503 on a replica beyond `GATE_MAX_STALENESS_MS` without a verified state, with
  audit rows waiting longer than `GATE_REPLICA_AUDIT_LAG_MS`, or after its chain was refused; the load balancer then
  drops it. `deploy/k8s/monitoring/alerts.yaml` ships `GateReplicaAuditRefused` and `GateReplicaAuditLagging`.
- **Operations.** A replica restarted with its volume resumes its chain. A replica whose volume is lost is refused at
  start (`behind`): it lost at most `GATE_REPLICA_AUDIT_LAG_MS` of unshipped decisions; start it under a new id (scale
  the StatefulSet up, then retire the old ordinal: its chain stays, verified and anchored, with no new rows).
  Deleting `DATA_DIR/replica-trust.json` re-bootstraps trust and drops the rollback floor: only after a deliberate
  restore of the database to an older state. Backups need nothing for replicas: their chains are in `gate_audit`.

## Tenant partitions

Set `GATE_TENANTS_FILE` to a local secret JSON file (mode 600) and `GATE_SERVE_TENANTS=alpha,beta` to the tenant
ids this node serves. Omitting the selection loads all manifest tenants; an empty selection, duplicate or unknown id
refuses startup. Configuration is read at startup; change assignment by restarting and draining the old node.
Only selected runtimes are opened. A first file-backed example:

```json
{
  "alpha": { "dataDir": "/var/lib/gate/alpha", "worldDir": "/etc/gate/worlds/alpha" },
  "beta": { "dataDir": "/var/lib/gate/beta", "worldDir": "/etc/gate/worlds/beta" }
}
```

Each entry requires `dataDir` and `worldDir`. For PostgreSQL, add `databaseUrl` and a distinct `signingKeySeal` to
each tenant. Provision a **separate database** with its own service role using the existing migrations and production
checks; this does not add tenant columns or shared-table RLS. Do not name the same physical database through aliases
or different socket URLs. Directory overlap (including existing symlinks), duplicate database host/port/name and
reused security keys are rejected. Existing single-tenant data can be assigned unchanged as one entry; do not split
its subjects or relations into different tenant stores. Never run concurrent file-mode writers for one tenant.

Optional entry fields are `signingKeySealPrevious`, `auditCheckpointMigration`, `advertiseUrl`, `publicOrigin`,
`replicaOf`, `replicaKey`, `replicaPins`, `replicaKeys`, `replicaCaFile`. All fields are nonempty strings;
`replicaKeys` and `replicaPins` use the existing comma-separated environment formats. Unknown fields refuse startup.
All other server settings come from the existing environment. Global `DATABASE_URL`, signing seal, previous seal,
checkpoint migration and replica key/pins/source/list are not inherited: specify those in each entry.
The manifest contains secrets: mount it read-only from the secret store and never log it.

For cluster nodes, use `GATE_CLUSTER=true` and a unique `GATE_NODE_ID` per node within each tenant database.
Locks, leader election, audit chains, session state, decision tokens and shared rate leases stay per database; different
tenants can have different leaders. `advertiseUrl` must reach the leader’s partition ingress, which receives the
forwarded tenant header. Use cluster mode for simultaneously serving nodes: in active/standby mode, startup waits
for each selected tenant’s lock. A blocked tenant delays readiness for this entire process. A storage fatal error
retains the existing process fail-stop behavior.

For a replica, configure each selected entry’s `replicaOf`, `replicaKey` and, when needed, `replicaPins` and
`replicaCaFile`. Put its matching `replicaKeys` in the corresponding source tenant entry. The replica’s source must
serve that tenant. Each runtime follows its own signed generations, rollback floor and trust file and ships its own
durable audit chain; no feed or audit shipment is opened for excluded tenants. Size replica rate shares per tenant
as before. Keep distinct DATA_DIRs and keys across tenants on both source and replica nodes.

Route by tenant at the load balancer and preserve `X-Qadamar-Tenant` on internal hops. For browser/SSO traffic, use
separate tenant hostnames and tenant `publicOrigin` values; the trusted edge must replace the header from the
hostname on every request, including IdP callbacks. Qadamar does not add a tenant picker to the console. PEP clients can
send the header directly. Keep proxy trust configuration unchanged: ingress dispatch keeps the original socket, so
IP budgets, secure cookies and trusted-proxy checks use the real connection. Probe each assigned tenant with its
header (`GET /readyz`, `/leaderz`, `/metrics`); headerless probes return 400. The existing image HEALTHCHECK is
headerless, so override it in a partition deployment. HTTP 421 `tenant_not_served` means route elsewhere, never
retry against a random tenant or treat the response as a policy decision. Ingress refusals have no audit chain and
should be counted by the edge. Per-tenant metrics are fetched using the header; add the tenant label at scrape time.

Capacity remains proportional to the combined worlds of served tenants, plus one runtime and database connection
set per tenant. A single large tenant still needs its whole graph and indexes in memory. Measure your own attribute
cardinality and graph shape with [PERFORMANCE.md](PERFORMANCE.md#tenant-partition-memory-2026-11-11).

### SAML encryption and logout keys

For encrypted assertions mount `SAML_DECRYPTION_KEY_FILE` and `SAML_DECRYPTION_CERT_FILE` (matching RSA 2048+ PEM).
For full SLO mount a separate `SAML_SIGNING_KEY_FILE` / `SAML_SIGNING_CERT_FILE` pair and set `SAML_IDP_SLO_URL` to the
IdP's HTTPS HTTP-Redirect logout endpoint. Distribute Qadamar's metadata again after changing public certificates;
register both POST and Redirect logout bindings. Keep private files readable only by the service account, outside
images and source control; never put PEM values in logs. Rotate with the IdP in a coordinated restart: Qadamar accepts
one decryption and one signing key at a time. IdP verification certificates retain their existing multi-cert overlap.
Route logout callbacks to the admin leader. Restart/failover cancels in-flight request IDs; already-ended sessions
stay ended in PostgreSQL. Check encrypted MFA login, IdP logout and console Sign out during deployment.

Backend replicas must share an atomic assertion replay store. The
[PostgreSQL example](../examples/integration-safety/postgres-replay.ts) uses the existing `pg` driver: run its schema
as owner, grant the backend only SELECT/INSERT/UPDATE/DELETE on that table, and schedule expiry pruning. Keep backend
and database clocks synchronised. The [integration safety guide](handbook/guides/integration-safety.md) covers this
and locking authoritative history while enforcing each SQL-filtered row.
