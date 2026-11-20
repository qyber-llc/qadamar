# Upgrade Qadamar

This runbook upgrades a PostgreSQL deployment of Qadamar while keeping one writer per audit chain, and verifies the result before restoring redundancy. It covers schema upgrades and two one-time procedures: importing file-based security material and adopting a policy signature.

The console now includes Arabic and RTL layout. Include a native Arabic review before customer rollout; do not
interpret automated accessibility assertions as a human screen-reader audit. Review [ACCESSIBILITY.md](../../ACCESSIBILITY.md).
The CI gate includes browser workflows with `E2E_REQUIRED=1`, and checks the README test summary against the run.
Provision the pinned CI browser separately from the runtime ([CI.md](../../CI.md)); local missing-browser skips
must not be accepted as evidence that the browser workflow passed.

## On this page

- [Plan the upgrade](#plan-the-upgrade)
- [Upgrade from 0.6.0 to per-record storage](#upgrade-from-060-to-per-record-storage)
- [Upgrade from 0.3.0](#upgrade-from-030)
- [Prepare a recoverable starting point](#prepare-a-recoverable-starting-point)
- [Perform active/standby upgrade](#perform-activestandby-upgrade)
- [Upgrade a cluster](#upgrade-a-cluster)
- [Migrate file-based security material](#migrate-file-based-security-material)
- [Adopt an unsigned or orphaned policy signature](#adopt-an-unsigned-or-orphaned-policy-signature)
- [Roll back](#roll-back)
- [Post-upgrade checks](#post-upgrade-checks)

## Plan the upgrade

There is no zero-downtime or downgrade guarantee. Production verifies every audit chain at startup, so plan for startup time that grows with the audit. With PostgreSQL, console sessions survive the restart; in file mode users sign in again. Upgrading from 0.4.2 or earlier adds the table `gate_session`: when an owner role holds the schema, run `SCHEMA` as that role and grant the service role (`serviceGrants`) before starting the nodes.

Before changing a node:

1. Record the source version and artifact digest running now, and the target commit. Verify the target release as in [Deploy Qadamar](deploy.md#verify-the-release-you-deploy).
2. Read `CHANGELOG.md` for every intervening change, including `[Unreleased]`.
3. Confirm Node.js 22.18 or later and rebuild the console from the target source.
4. Run `pnpm typecheck`, `pnpm --filter @product/admin build`, the package and console tests, and the full CI database gate in a non-production environment.
5. Test the target against a restored copy of production-shaped state, including policy-signature and audit verification.
6. Confirm that the owner and service roles are separate, and that no upgrade step creates tables with the service role.
7. Schedule administrators' reauthentication and a window for full-chain verification.

`SCHEMA` is idempotent, but that does not make arbitrary downgrades compatible. Treat the tested backup as the rollback boundary.

### Release by release, 0.8.0 to 0.11.0

From `CHANGELOG.md` only: breaking changes and operator steps, nothing else. Read the full entries before upgrading.

- **0.8.0:** new table `gate_rate_limit` (cluster-wide rate limits): the owner runs `SCHEMA` and the grants; older archives restore it empty. Unset `SOD_HISTORY` now means `server` in every profile; `caller` is an explicit opt-in that production refuses.
- **0.8.1:** no operator step (AES-GCM tag length fixed at 16 bytes; manifest version fix).
- **0.8.2:** string ordering in conditions is Unicode code-point order and the SQL filter uses `COLLATE "C"`: policies comparing strings with characters from U+10000 and U+E000..U+FFFF may decide differently.
- **0.8.3:** no product code change.
- **0.9.0 (breaking):** CBAC now means context-based; content rules are ABAC (reason codes `CBAC.<id>` become `ABAC.CONTENT_*`, `CTX.*` become `CBAC.*`, trace stages renamed): update PEPs, SIEM rules and dashboards. New tuples use `notBefore`/`notAfter`; readers of `GET /admin/v1/tuples` must accept both names. Bundle field `cbac` is deprecated for `abacContent`. `DATABASE_TLS=verify-full` is the production default and required for non-local hosts; URL `ssl*` parameters are refused. New table `gate_blp_session` and new schema marker `gate_tuple_not_after`: the owner runs `SCHEMA` on upgrade. Production requires BLP session tokens and refuses a raw `sessionId`; a new cap `BLP_SESSIONS_PER_CREDENTIAL` (default 10,000) applies; `gate_blp_mark.held_until` is added in place at start. `upgrade-tenant.sh` requires `KUBE_CONTEXT` for a cloud overlay. 0.9.0 was tagged but never published.
- **0.9.1:** image build fix (pinned corepack); no operator step. Tagged but never published.
- **0.9.2:** the server image drops the bundled package managers and upgrades Alpine packages; no operator step.
- **0.10.0:** PEP credentials bind context claims to explicit scopes: production requires scopes for new credentials and gives older unscoped credentials no permitted signals (demo keeps them for one version, with warnings). Tagged but never published.
- **0.10.1:** CI fix only; no operator step.
- **0.11.0:** policy bundle validation is closed: a bundle with stray keys, non-boolean flags, a missing `needToKnow.protect` or SoD/Biba lists naming undeclared actions must be cleaned before it is accepted. The OIDC state cookie is renamed `__Host-gate_oidc`.
- **0.12.1** (0.12.0 tagged but never published): new column `gate_subject_identity.used_at` and new schema marker `gate_subject_identity_used`: stop every node and the owner runs `SCHEMA` (no new grant: the service role already has `UPDATE, DELETE` on that table). Existing mappings get `NULL` and are never purged; new mappings of ids that are not world subjects are deleted after 90 days without use, with a `subject_mappings_purged { count }` audit row. File mode needs no step (`audit-subjects.json` rows without `usedAt` are kept). Do not make the existing mappings purgeable with a bulk `UPDATE … SET used_at = now() WHERE used_at IS NULL`: `NULL` also marks the actors, person-id details, console accounts and world subjects that must never be purged, and after that statement nothing tells them apart (no rollback short of a restore).

## Upgrade from 0.6.0 to per-record storage

The target adds `gate_subject`, `gate_resource`, `gate_tuple`, and `gate_state_change`, plus record generations and ordering fields in `gate_sync`. The old `state` document becomes policy/workflow metadata; subjects, resources, and tuples move to individual rows.

1. **Rehearse on a restored 0.6.0 database.** Run the target's test suite, including `a 0.6.0 state document migrates automatically, losslessly and idempotently into ordered record rows` and the legacy archive drill. Compare subjects, resources, tuples, pending changes, certifications, and state digests after migration.
2. **Stop every Qadamar node.** Mixed 0.6.0 and target writers are not supported. Create and validate the pre-upgrade encrypted backup with the scripts of the running version.
3. **Run `SCHEMA`, `serviceGrants`, and `backupGrants` as the owner.** This creates keys, indexes, and forced RLS policies and grants the service role record read/upsert/delete plus change-log read/append. Do not let the production service role create or own the tables.
4. **Start one target node.** Under `MIGRATE_LOCK`, `migrateLegacyRecords` reads the old document and inserts ordered rows in batches, strips the three record arrays from `gate_doc`, and sets `records_migrated`. All of this is one transaction: a failure rolls back, and retrying is safe. The baseline has no change-log entries because every target node loads its initial snapshot.
5. **Verify before restoring redundancy.** Check readiness and audit verification, known allow/deny decisions, pending proposals and their state digests, resource registration and retirement, SCIM, break-glass, certified post-states, and row counts against the old document. Confirm a second start is a no-op. Then start the other target nodes and verify incremental follower registration within the staleness bound.
6. **Verify backup and restore.** The target `backup.sh` includes all eighteen tables. `restore.sh` accepts the older archive and runs the same migration before validating it. Restore into a new database and verify there before any cutover.

For the version after 0.7.0, the same owner step also adds `gate_rate_limit` for cluster-wide leased budgets. Older archives restore it empty; no rate state needs migration.

**Rollback:** stop the target and restore the pre-upgrade archive into a new database for the 0.6.0 artifact. Do not point a 0.6.0 binary at migrated tables. Registration validates only changed resources and their direct children, and updates arrays and decision indexes in place; every node still retains the full decision world in memory. See docs/PERFORMANCE.md for the measured 100k and 1M limits.

## Upgrade from 0.3.0

### What changes in the database

`SCHEMA` (`packages/pdp-http/src/postgres-schema.ts`) upgrades a 0.3.0 database in place:

| Change | Effect |
| --- | --- |
| `gate_audit` and `gate_audit_meta` gain a `node` column, default `'0'`; their primary keys become `(node, seq)` | Existing audit rows are not rewritten. They become chain `"0"`. |
| `gate_anchor` gains a `heads` column | An anchor can cover the heads of several chains. |
| New table `gate_sync` | One row: shared-state version, performed-action counter, and advertised leader URL. |
| New table `gate_token` | Decision tokens, single use across nodes. |
| New table `gate_performed` | Performed certified actions. Append-only, like `gate_audit` and `gate_anchor`. |
| Row-level security and policies on the new tables | Same pattern as the existing tables. |

A node that keeps the default `GATE_NODE_ID=0` continues chain `"0"` with rows of the same shape. The test `an earlier version's single chain becomes chain "0" without rewriting a row, and continues there` in `packages/pdp-http/test/postgres.test.ts` checks this: it creates the four 0.3.0 tables, writes a chain, runs `SCHEMA` as the owner and `serviceGrants`, confirms that no stored record changed, appends on chain `"0"`, adds chain `"b"`, and verifies both together.

Two data moves happen at the first start on the new code:

- **Decision tokens.** The leader imports unexpired tokens from the 0.3.0 `tokens` document into `gate_token`, so they stay consumable (`packages/pdp-http/src/postgres.ts`). Unproven: no test covers this import. Tokens live at most 300 seconds, so draining certified traffic before the upgrade avoids depending on it.
- **Performed actions.** History that 0.3.0 kept in the state document stays there unchanged; new actions go to `gate_performed` (`packages/pdp-http/src/store.ts`).

### Who runs the migration

- **Service role owns the tables** (the Compose setup): the first node to start migrates by itself, in one transaction under an advisory lock.
- **Tables owned by an owner role** (production): a node never migrates. Without the new tables it stops with `The database schema is from an earlier version: run SCHEMA (packages/pdp-http/src/postgres.ts) as the owner role first`; in the production profile the preflight first refuses with `tables missing from schema public` and names `gate_sync`, `gate_token`, and `gate_performed`.

Stop every node, then run as the owner, in one transaction: `SCHEMA`, `serviceGrants(<service role>)`, and `backupGrants(<backup role>)`. The script in [Deploy Qadamar](deploy.md#2-run-the-schema-and-grants-as-the-owner) does exactly this. The service role needs grants on the three new tables, and the backup role needs `SELECT` on all seven tables; without them nodes cannot decide and backups cannot run. In the managed offer, the `gate-migrate` Job runs the same three statements from the code; recreate it for each upgrade (`deploy/k8s/base/jobs.yaml`, [docs/MANAGED-OFFER.md §6](../../MANAGED-OFFER.md#6-upgrade-rolling-and-day-2-procedures)).

### Other changes to plan for

- **Backups are now encrypted.** The new `backup.sh` and `restore.sh` require `BACKUP_ENCRYPTION_KEY` and back up seven tables. Create the key before the first post-upgrade backup ([Back up and restore](backup-restore.md#manage-the-backup-encryption-key)). Take the pre-upgrade backup with the 0.3.0 scripts: the new `backup.sh` expects the new tables and fails on an un-migrated database.
- **SIEM records.** Records of chains other than `"0"` carry a `node` field and a per-node `seq`. A receiver that deduplicates by `seq` alone must deduplicate by `node` and `seq` once more than one chain exists.
- **`TRUSTED_PROXIES`.** Behind a proxy, set it during the upgrade ([Deploy Qadamar](deploy.md#3-set-trusted_proxies-behind-a-proxy)).
- **Production preflight.** It now checks all seven tables, and refuses rewrite privileges on `gate_performed` as well as `gate_audit` and `gate_anchor`.

## Prepare a recoverable starting point

1. Put the change under your approval process and freeze unrelated policy and credential changes.
2. Create and validate a backup. From 0.3.0, use the 0.3.0 `backup.sh`, which writes an unencrypted archive of the four 0.3.0 tables; encrypt and store it under your own controls.
3. Copy the backup, current configuration, artifact digest, current JWKS, latest policy publication, TSA anchors, and relevant logs to independent evidence storage.
4. Confirm the exact `SIGNING_KEY_SEAL` is in the secret store. It is not in the backup.
5. Restore the backup into a separate database, run the target's `SCHEMA` and grants on it, and start the target there in isolation. Confirm readiness and `GET /admin/v1/audit/verify`.
6. Confirm one healthy active node and one waiting standby. Do not begin if the standby cannot reload the current store cleanly in rehearsal.

Keep the `DATA_DIR` files until the post-upgrade checks are complete.

## Perform active/standby upgrade

The standby has no listener until takeover, so upgrading it means replacing its artifact and restarting its waiting process.

1. **Drain administration work.** Stop batch jobs, SCIM writes, and certified commands. Keep the PEP path available until cutover.
2. **Stop every node** if the schema changes, as from 0.3.0, and run `SCHEMA` and the grants as the owner. A node of the old version must not write while the schema migrates.
3. **Start the target on one node.** It takes the lock, loads all shared documents, imports legacy tokens, verifies the policy signature and the audit, then opens its port. Production always scans the full chain.
4. **Verify before traffic.** Check readiness, metrics authentication, a known allow and deny, the current policy signature, audit verification, and administrative sign-in.
5. **Restore service** through the load balancer. Clients with in-flight requests and console users retry or sign in again.
6. **Start the second node** on the same target artifact as the waiting standby. Do not leave mixed versions running.
7. **Rehearse a second takeover** if your change policy requires it.

For an upgrade without schema change, you can instead replace the waiting standby first, then stop the active node gracefully with SIGTERM so the standby takes over. A standby that is still waiting exits at once on SIGTERM (`packages/pdp-http/src/main.ts`).

If the new node fails verification, keep it out of service. Do not start the old binary against a database whose compatibility you have not tested; use the rollback path.

## Upgrade a cluster

Upgrading 0.3.0 to cluster mode and upgrading an existing cluster follow the same rules:

1. Stop every node, run `SCHEMA` and the grants as the owner, then start the target nodes.
2. Keep `GATE_NODE_ID` unchanged on each node. A node with the default `0` continues the old chain; every other node needs its own id.
3. Confirm exactly one node returns 200 on `GET /leaderz`, every node returns 200 on `/readyz`, and `GET /admin/v1/audit/verify` through the leader reports `verified: true` over every chain.

**Not available:** a documented rolling upgrade of a cluster with mixed versions. Followers reload documents written by the leader, so run one version at a time.

## Migrate file-based security material

In PostgreSQL mode, credentials, lockouts, the signing keyring, the SCIM credential, and the SIEM cursor are shared documents. The first start against a database without them imports the local files once and logs `Imported into PostgreSQL from DATA_DIR (committed at start; the files are no longer used):` followed by the file names (`packages/pdp-http/src/server.ts`).

1. Set `SIGNING_KEY_SEAL` before the first database start. Without it, startup refuses unless `ALLOW_CLEAR_SIGNING_KEYS` is on, which production forbids.
2. Start **one** node on the `DATA_DIR` that holds the current files and the intended database.
3. Confirm the import log line and a successful first commit. Recognised files: `credentials.json`, `signing-keys.json` or `signing-private.pem`, `lockouts.json`, `scim-credential.json`, `siem-cursor.json`, and `approval-prefs.json`.
4. Verify local accounts, PEP credentials, signing keys, SCIM source, and SIEM cursor through the admin API.
5. Stop that node and start the normal topology with the same seal. Verify a decision and a token consumption.
6. After successful verification, move the obsolete files to controlled offline storage. PostgreSQL mode no longer reads or writes them, including `signing-public.pem`; use the JWKS instead.

`INITIAL-CREDENTIALS.txt` stays a local first-start file on the node that seeds a fresh database. It is not imported.

## Adopt an unsigned or orphaned policy signature

At startup Qadamar checks that the stored bundle matches the latest publication and carries a valid Ed25519 signature from the stored keyring. An unsigned store, or one whose signer is no longer in the keyring, stops startup (`packages/pdp-http/src/policy-signature.ts`).

**This is a recovery procedure, not a routine upgrade flag.**

1. Confirm the database, `state` document, latest publication, and keyring are the intended ones. Recompute and independently review the canonical bundle and policy version.
2. Preserve the bundle and audit evidence before changing anything.
3. Start once in the **demo** profile with the correct `SIGNING_KEY_SEAL`:

   ```bash
   POLICY_SIGNATURE_ADOPT=1 GATE_PROFILE=demo node packages/pdp-http/src/main.ts
   ```

4. Confirm the audited `policy_signature_adopt` security event, then verify the current policy and readiness.
5. Stop the node, remove `POLICY_SIGNATURE_ADOPT` everywhere, and restart with the intended profile. Production refuses to start while the flag is on.

A new state document under an existing audit trail is not signed silently. Adoption tells Qadamar to trust a bundle after your review; it does not repair a broken audit chain or prove that a replaced state document is legitimate.

## Roll back

### Before cutover

Stop the replacement process and restore the old artifact. If the old active node never released the lock, it remains authoritative.

### After cutover

1. Remove the new nodes from the load balancer and stop every Qadamar writer.
2. Preserve logs and every audit row committed since the upgrade.
3. **Unproven:** running a 0.3.0 binary against a database migrated by the new `SCHEMA`. No test covers it. Do not do it.
4. Restore the pre-upgrade backup into a **new** database with the scripts of the version that made it (0.3.0 archives are unencrypted, and the new `restore.sh` accepts only encrypted archives). Reapply the 0.3.0 service grants and use the same `SIGNING_KEY_SEAL`.
5. Start the old, previously verified artifact against the restored database, and verify policy, audit, credentials, and a new decision before switching traffic.
6. Reconcile decisions made after the backup from SIEM and TSA evidence. A snapshot rollback loses later writes unless the hosting provides point-in-time recovery.

Do not use `POLICY_SIGNATURE_ADOPT` to make an unreviewed rollback store start.

## Post-upgrade checks

- Every node runs the intended artifact. Active/standby: one listens, one waits. Cluster: one leader.
- `/readyz` and `/admin/v1/audit/verify` pass.
- The current policy publication verifies against the keyring; historical JWKS for older evidence are preserved.
- OIDC sign-in, MFA, role mapping, and back-channel logout work.
- Named PEP credentials, SCIM authentication, and revocation survive takeover.
- A certified action consumes its token once and records the performed action.
- The SIEM cursor continues without unexpected duplication or gaps.
- Anchoring resumes and `gate_audit_last_anchor_age_seconds` returns to its usual cadence.
- Break-glass notices reach the receiver.
- An encrypted backup and a test restore with the new scripts succeed.

## Related pages

- [Deploy Qadamar](deploy.md)
- [Back up and restore](backup-restore.md)
- [Fail over the active node](failover.md)
- [Rotate keys and credentials](rotate-credentials.md)
- [ADR: Production profile](../architecture/decisions/0010-production-profile.md)
