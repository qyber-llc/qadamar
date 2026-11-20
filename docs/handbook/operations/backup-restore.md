# Back up and restore

`scripts/ops/backup.sh` takes a consistent, encrypted snapshot of Qadamar's seventeen PostgreSQL tables, and `scripts/ops/restore.sh` restores one into a new database. Neither script exposes a database password or the backup key in process arguments. This runbook covers routine and managed backups, a non-destructive recovery drill, and the verification required before any cutover.

## On this page

- [Understand recovery scope](#understand-recovery-scope)
- [Manage the backup encryption key](#manage-the-backup-encryption-key)
- [Create a validated backup](#create-a-validated-backup)
- [Restore into a new database](#restore-into-a-new-database)
- [Verify recovered service](#verify-recovered-service)
- [Managed backups on Kubernetes](#managed-backups-on-kubernetes)
- [Run the full recovery drill](#run-the-full-recovery-drill)
- [RPO, RTO, and retention](#rpo-rto-and-retention)
- [File-mode note](#file-mode-note)

## Understand recovery scope

The backup contains, with their definitions, primary keys, indexes, and row-level security policies (`scripts/ops/backup.sh`):

| Table | Content |
| --- | --- |
| `gate_doc` | Policy/workflow metadata, credentials, lockouts, sealed signing keyring, SCIM credential, SIEM cursor, and audit checkpoint |
| `gate_subject`, `gate_resource`, `gate_tuple` | Ordered per-record decision world |
| `gate_state_change` | Append-only incremental record changes |
| `gate_audit` | Every node's audit chain |
| `gate_audit_meta` | Derived filter metadata |
| `gate_anchor` | RFC 3161 tokens and the anchored heads |
| `gate_audit_segment` | HMAC-sealed removed-prefix digests and heads, with any retention anchors |
| `gate_subject_identity` | Erasable raw-subject/per-subject-HMAC-key mappings (ids JSON-encoded) |
| `gate_sync` | Document version, record generation/positions, migration flag, performed counter, and advertised leader |
| `gate_token` | Issued decision tokens and whether they were used |
| `gate_performed` | Performed certified actions |
| `gate_session`, `gate_blp_mark`, `gate_blp_session`, `gate_retired` | Console sessions, BLP marks, open PDP session registry, and retired-id log |
| `gate_rate_limit` | Disposable shared rate-bucket leases (hashed keys; older archives restore this table empty) |

The backup does **not** contain:

- `SIGNING_KEY_SEAL` or `BACKUP_ENCRYPTION_KEY`; keep both in the secret store, separately;
- pending OIDC logins or the process-local buckets used outside cluster mode (console sessions are `gate_session` rows: in the backup, and expired after 15 minutes);
- the protected application's database;
- TSA CA files, OIDC configuration, webhook secrets, or other environment secrets;
- writes committed after the snapshot.

The scripts do not provide WAL archiving, point-in-time recovery, off-site copies, or scheduling. The managed offer's CronJob adds scheduling and age-based pruning ([Managed backups on Kubernetes](#managed-backups-on-kubernetes)).

## Manage the backup encryption key

Both scripts require `BACKUP_ENCRYPTION_KEY` and refuse to run without it (`scripts/ops/backup.sh`, `restore.sh`).

- **Format:** 32 bytes as 64 hexadecimal characters or canonical unpadded base64url. Any other value is refused. Generate one with `openssl rand -hex 32`.
- **Algorithm:** AES-256-GCM, streaming, through `scripts/ops/archive-crypt.ts` (Node.js `crypto` only). The archive is `GATEBK` (6 bytes), version byte `1`, a random 12-byte nonce, the ciphertext of the custom-format dump, and a 16-byte tag. The 19-byte header is authenticated as GCM additional data. Output files are created exclusively with mode 600.
- **Refusal:** decryption fails, and leaves no output file, for a wrong key, any changed byte, a shortened or empty file, or a file that is not a version 1 Qadamar archive. `restore.sh` decrypts and checks the tag first, so a tampered archive or wrong key is refused before any database is created.
- **Custody:** keep the key apart from the archives, from the database, and from `SIGNING_KEY_SEAL`. Whoever holds an archive and its key can read every `gate_*` row. Losing the key makes every archive encrypted with it unrecoverable.
- **Rotation:** **Partial.** A new key applies to new backups only. Re-encryption of existing archives is **Not available**. Keep each old key while archives encrypted with it are retained, and record which key belongs to which archive.

The archive name convention is `gate-<UTC time>.dump.gcm`, used by docs/DEPLOY.md and the managed CronJob. The scripts do not enforce a suffix.

## Create a validated backup

### Prerequisites

- PostgreSQL client tools of major version 17 or later: `pg_dump` and `pg_restore` for backup; `pg_restore`, `createdb`, `dropdb`, and `psql` for restore.
- Node.js 22.18 or later. The scripts run `archive-crypt.ts` from their own directory.
- For backup, a `DATABASE_URL` role with `SELECT` on every Qadamar table and `BYPASSRLS`; `pg_dump` refuses tables with forced row-level security otherwise. `backupGrants` produces the grants ([Deploy Qadamar](deploy.md#prepare-postgresql-for-production)).
- `BACKUP_ENCRYPTION_KEY` exported from the secret store, with shell tracing off.
- `TMPDIR` on local, non-synced disk with room for one plaintext dump.

The scripts move the password out of the URL into `PGPASSWORD` for the client tools. A URL without a password falls back to `PGPASSWORD`, `~/.pgpass`, or `PGPASSFILE`. They map `DATABASE_TLS` to `PGSSLMODE`, with `DATABASE_TLS_CA_FILE`, `DATABASE_TLS_CERT_FILE` and `DATABASE_TLS_KEY_FILE` mapped to the corresponding libpq settings. Production defaults to `verify-full`; target and maintenance hosts must both pass that policy. URL `ssl*` parameters are refused. Without `DATABASE_TLS_CA_FILE`, `verify-full` uses `PGSSLROOTCERT=system`, which needs libpq 16 or later (the ops image ships 17).

### Backup procedure

1. Record the active policy version, audit head, latest anchor, and current time in the change log.
2. Choose a new absolute archive path in an existing directory. The script refuses to overwrite an existing file or follow a symbolic link.

   ```bash
   export DATABASE_URL='postgresql://gate_backup@db.internal/gate'
   export BACKUP_FILE="/backups/gate-$(date -u +%Y%m%dT%H%M%SZ).dump.gcm"
   scripts/ops/backup.sh
   ```

3. What the script does: `pg_dump` writes one consistent snapshot, in custom format, without owners or privileges, into a private `mktemp -d` directory. The script checks with `pg_restore --list` that every table's schema and data are present, encrypts the dump into a temporary directory next to `BACKUP_FILE`, and links it into place. The plaintext never reaches the `BACKUP_FILE` directory and is removed on success and on failure.
4. Confirm the output reads `Backup created, validated and encrypted:` followed by the archive path, and that no credential appears.
5. Copy the archive to independent storage according to your policy.
6. Record the archive digest, storage location, source database, software version, completion time, and which `BACKUP_ENCRYPTION_KEY` was used in your backup catalogue.

To inspect an archive later, decrypt it into a private directory, list it, and remove the plaintext:

```bash
node scripts/ops/archive-crypt.ts decrypt "$BACKUP_FILE" /private/dir/gate.dump
pg_restore --list /private/dir/gate.dump
```

## Restore into a new database

1. Choose a **new** database name of letters, digits, and underscores, starting with a letter or underscore, at most 63 characters. `createdb` fails if it exists (`scripts/ops/restore.sh`).
2. Use a readable, non-empty regular file, not a symbolic link.
3. Set the target URL with the owner role, the maintenance URL, the archive, and its key:

   ```bash
   export DATABASE_URL='postgresql://owner@db.internal/gate_restored'
   export MAINTENANCE_DATABASE_URL='postgresql://admin@db.internal/postgres'
   export BACKUP_FILE='/backups/gate-YYYYMMDDTHHMMSSZ.dump.gcm'
   scripts/ops/restore.sh
   ```

   Without `MAINTENANCE_DATABASE_URL`, the script connects to the `postgres` database of the target server with the target's credentials.

4. What the script does, in order: decrypts and authenticates the archive (`Restore refused: the archive did not decrypt and authenticate` otherwise, before any database exists); checks every table's schema and data with `pg_restore --list`; creates the target; confirms the URL resolves to it; restores the whole archive with `--single-transaction --exit-on-error --no-owner --no-privileges`; runs `migrate-records.ts`; and checks that all eighteen tables exist. A current archive needs no data move. A 0.6.0-or-older archive receives the record schema and has the old state document imported, transactionally and idempotently, before validation. Missing disposable tables are created empty with their RLS and policies, with a notice: `gate_session` and `gate_blp_mark` (0.4.x archives), `gate_blp_session` (archives before PDP-issued sessions), `gate_retired`, `gate_audit_segment`, `gate_subject_identity` and `gate_rate_limit`. Console users sign in again; an absent PDP session registry closes old tokens (fail closed), so PEPs open new sessions. Lost BLP marks lower protection for sessions in flight at backup time until they end (docs/DEPLOY.md). Any other missing table, or an optional table with schema but no data, is refused. After a failure the script tries to remove only the target it created.
5. Grant the runtime and backup roles as the owner, as the `gate-migrate` Job does. The SQL is produced by `serviceGrants` and `backupGrants` in `packages/pdp-http/src/postgres-schema.ts`:

   ```sql
   GRANT SELECT, INSERT, UPDATE ON gate_doc, gate_audit_meta TO gate_service;
   GRANT SELECT, INSERT ON gate_audit, gate_anchor, gate_performed, gate_retired, gate_state_change TO gate_service;
   GRANT SELECT ON gate_audit_segment TO gate_service;
   GRANT SELECT, UPDATE ON gate_sync TO gate_service;
   GRANT SELECT, INSERT, UPDATE, DELETE ON gate_subject_identity, gate_token, gate_session, gate_blp_mark, gate_blp_session, gate_subject, gate_resource, gate_tuple, gate_rate_limit TO gate_service;
   GRANT SELECT ON gate_doc, gate_audit, gate_audit_meta, gate_anchor, gate_audit_segment, gate_subject_identity, gate_sync, gate_token, gate_performed, gate_session, gate_blp_mark, gate_blp_session, gate_retired, gate_subject, gate_resource, gate_tuple, gate_state_change, gate_rate_limit TO gate_backup;
   ```

6. Do not send production traffic to the restored database yet. First verify it with an isolated Qadamar node.

## Verify recovered service

1. Configure an isolated node with the restored `DATABASE_URL` (service role), the exact original `SIGNING_KEY_SEAL`, and the intended profile. Keep its listener private.
2. Start it and let the policy-signature and full audit checks finish. Production always scans the full chain.
3. Check that `/readyz` returns 200.
4. As an auditor or security officer, call `GET /admin/v1/audit/verify` and require `verified: true` with the expected length.
5. Compare the latest publication and policy version with the backup catalogue. Confirm the signature verifies against the restored keyring.
6. Inspect pending changes, emergencies, named PEP credentials, signing keys, SCIM credential source, and SIEM cursor.
7. Make one known decision and confirm it commits, extends the audit, and still verifies.
8. If certified commands are used, run a controlled token issue and consume cycle and inspect performed-action history.
9. Verify anchor tokens with OpenSSL and compare the restored heads with SIEM and TSA evidence:

   ```bash
   openssl ts -verify -digest <anchored-record-hash> \
     -in token.der -token_in -CAfile tsa-ca.pem
   ```

10. Only after every check passes, plan a separate cutover. Keep the original database and post-snapshot audit evidence until reconciliation is complete.

If the keyring or bundle is not the intended one, stop. Do not use `POLICY_SIGNATURE_ADOPT` to make an unreviewed restore start; follow the reviewed procedure in [Upgrade Qadamar](upgrade.md#adopt-an-unsigned-or-orphaned-policy-signature).

## Managed backups on Kubernetes

The managed offer schedules `backup.sh` as the CronJob `gate-backup` (`deploy/k8s/base/jobs.yaml`):

| Setting | Value in the base manifests |
| --- | --- |
| Schedule | `17 2 * * *`, time zone `Etc/UTC` (daily), `concurrencyPolicy: Forbid` |
| Image | `gate-ops`, built from the `ops` target of the `Dockerfile` |
| Database URL | `BACKUP_DATABASE_URL` from the Secret `gate-db-admin` (the backup role) |
| Encryption key | `BACKUP_ENCRYPTION_KEY` from the Secret `gate-backup` |
| Archive | `/backups/gate-<UTC time>.dump.gcm` on the PersistentVolumeClaim `gate-backups` (1 Gi) |
| Retention | Archives older than `BACKUP_RETENTION_DAYS` (14) are pruned after each successful backup |

Schedule, retention, and volume are parameters to set per cloud; in a cloud, mount object storage with versioning and a retention lock as the volume ([docs/MANAGED-OFFER.md §4](../../MANAGED-OFFER.md#4-parameters-owner-and-cloud-decisions)).

- `scripts/managed/new-tenant.sh` creates the Secret `gate-backup` on the local overlay; on other overlays you create it. Keep a copy of the key outside the cluster: without it no archive can be restored.
- Run a backup now: `kubectl -n gate-<tenant> create job --from=cronjob/gate-backup gate-backup-manual-$(date +%s)`.
- The alert `GateBackupMissing` fires when no backup has succeeded for 26 hours or a backup Job failed ([Monitoring and alerts](monitoring.md#alert-rules-shipped-for-kubernetes)).
- To restore, run `restore.sh` from the `gate-ops` image with the owner URL of a new database, the archive, and its key, as described under Restore procedure in [docs/MANAGED-OFFER.md §7](../../MANAGED-OFFER.md#7-what-smokesh-checks-and-measured). Then grant the roles and verify as above.

## Run the full recovery drill

`packages/pdp-http/test/backup-restore.test.ts` automates an end-to-end drill against a throwaway PostgreSQL. It starts a node on a fresh database, records a decision and a pending change, runs `backup.sh`, removes the source database, runs `restore.sh` into a new one, compares the restored rows and schema objects with the source, starts a node on the restored database, verifies the audit chain, and records another decision. It also checks that the archive starts with the `GATEBK` header and shows no table name in clear, and that `restore.sh` refuses an archive with one flipped byte and a wrong key without creating the target. A second drill backs up a database without `gate_session` with the 0.4.x `backup.sh`, restores it with the current `restore.sh`, and checks that `gate_session` is created empty, matches a server-created schema, and takes new sessions.

```bash
export TEST_DATABASE_URL='postgresql://admin@db.internal/postgres'
node --test packages/pdp-http/test/backup-restore.test.ts packages/pdp-http/test/backup-crypt.test.ts
```

If local client tools are missing, set `PG_TOOLS_CONTAINER` to a running throwaway PostgreSQL container whose tools the test calls through `docker exec`. Without either, the two live drills skip with an explicit message; `BACKUP_TESTS_REQUIRED=1` makes that condition fail, and CI sets it whenever `PG_TOOLS_CONTAINER` is present. `backup-crypt.test.ts` needs no database: it covers the archive format, mode 600, key rules, and refusals.

For a production-scale drill:

1. Restore a copy into an isolated environment as above.
2. Compare row counts, contents, indexes, and row-level security policies with the source snapshot.
3. Record backup, restore, full-startup verification, and first-decision durations with dataset size and load.
4. Perform the drill without the original runtime secret files, to prove independent custody of `SIGNING_KEY_SEAL` and `BACKUP_ENCRYPTION_KEY`.
5. Reconcile writes after the snapshot from SIEM and TSA records.
6. Repeat after significant version, data-volume, or hosting changes.

## RPO, RTO, and retention

Point-in-time recovery is the hosting's responsibility. `backup.sh` is a logical snapshot and cannot replay commits made after it ran. To bound data loss below the backup interval, the database must have WAL archiving and point-in-time recovery, which these scripts neither provide nor check. The settings to require from your provider are listed in [docs/DEPLOY.md, Point-in-time recovery](../../DEPLOY.md#point-in-time-recovery-the-hostings).

- **RPO with logical backups alone:** the interval between successful backups. Anything committed after the last usable backup is lost.
- **RPO with PITR:** bounded by the hosting's WAL archiving, for example its `archive_timeout`. You set and verify this target.
- **RTO:** archive transfer, key retrieval, restore, role grants, full startup verification, and application checks. Measure each phase on production-shaped data.

The drill measurements and the RPO/RTO table, with their conditions (one laptop, PostgreSQL in Docker, three audit rows), are in [docs/DEPLOY.md, What the drill measured](../../DEPLOY.md#what-the-drill-measured-not-promises). They are not targets. No PITR drill has been run for this product.

Define archive and audit retention together. `AUDIT_RETENTION_DAYS` enables sealed-prefix retention: file mode runs at start and daily; PostgreSQL uses `audit-retention.ts` as the table owner with every writer stopped. Back up first: after pruning, Qadamar proves seals and retained rows, not the deleted row contents. Keep archives, TSA tokens, SIEM rows, and the root seal in separate failure domains.

## File-mode note

The scripts do not back up `DATA_DIR`. File mode is for demonstrations and has no cross-file transaction. For a demo copy, stop the process and copy the whole `DATA_DIR`, including state, audit, anchors, the keyed checkpoint, retention seals, subject mappings, tokens, credentials, and signing keys. This is not a production recovery procedure.

## Related pages

- [Data and storage](../architecture/data-and-storage.md)
- [Audit and evidence](../architecture/audit-and-evidence.md)
- [Deploy Qadamar](deploy.md)
- [Upgrade Qadamar](upgrade.md)
- [Fail over the active node](failover.md)
- [Rotate keys and credentials](rotate-credentials.md)
