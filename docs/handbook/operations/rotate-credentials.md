# Rotate keys and credentials

This runbook covers the credentials that the code at commit b09bc44 (after 0.3.0) can rotate, and names those with no built-in rotation. Test each new credential before you retire the old one, and keep old verification material as evidence.

## On this page

- [Prepare every rotation](#prepare-every-rotation)
- [Rotate a PEP credential](#rotate-a-pep-credential)
- [Rotate the decision-token signing key](#rotate-the-decision-token-signing-key)
- [Rotate the SCIM credential](#rotate-the-scim-credential)
- [Rotate webhook, IdP, and metrics secrets](#rotate-webhook-idp-and-metrics-secrets)
- [Rotate the backup encryption key](#rotate-the-backup-encryption-key)
- [Rotate database credentials](#rotate-database-credentials)
- [Rotate the root seal (`SIGNING_KEY_SEAL`)](#rotate-the-root-seal-signing_key_seal)
- [Local-account limits](#local-account-limits)
- [Emergency revocation](#emergency-revocation)

## Prepare every rotation

1. Identify the credential by name, owner, consumers, and dependent runbooks.
2. Record credential metadata, never the secret, in the change record.
3. When signing keys are involved, preserve the current JWKS, policy publication, evidence packs, and audit anchors.
4. Confirm the serving node is ready. In cluster mode, run admin-plane rotations against the leader: followers answer `/admin/` with `409 not_leader`.
5. Stage the new secret in your secret store without printing it to logs or shell history.
6. Define a verification call and a rollback owner.
7. Use an authenticated admin session with a valid CSRF token. Roles are enforced by the server (`packages/pdp-http/src/admin/security.ts`).

Secrets returned by a create or rotate call are shown once. Qadamar keeps only hashes.

Rotations and revocations are stored in PostgreSQL. They survive a takeover, and cluster followers apply them at their next sync of the shared state (`packages/pdp-http/src/auth.ts`, `tokens.ts`).

## Rotate a PEP credential

Security officers create, rotate, and revoke PEP credentials. Access administrators and security officers can list them (`packages/pdp-http/src/admin/security.ts`). The console screen is **Credentials and keys**.

| Call | Body | Result |
| --- | --- | --- |
| `POST /admin/v1/pep-credentials` | `{"name": "...", "subjectTypes": [...], "contextScopes": [...]}`; both optional outside production | `201 {credential, secret}` |
| `POST /admin/v1/pep-credentials/:id/rotate` | `{}` | `200 {credential, secret}`; `404` unknown; `409` revoked |
| `POST /admin/v1/pep-credentials/:id/revoke` | `{}` | `200`; `409` already revoked |
| `GET /admin/v1/pep-credentials` | none | `200 {items}` |

### Bind a credential to subject populations

`subjectTypes` binds a credential to the subject types its PEP may present for Clark-Wilson procedures (E3). When a bundle lists a resource type in `clarkWilson.requirePepBinding`, a certified procedure on that type is denied with `CW.SUBJECT_NOT_AUTHENTICATED` unless the calling credential is bound to the subject's type (`packages/core/src/procedures.ts`).

- `subjectTypes` holds 1 to 16 entries, each 1 to 64 characters from `[A-Za-z0-9_.-]`. Duplicates are removed. Anything else returns `400 bad_request`.
- It is set only at creation. Rotation keeps it. To change it, create a new credential with the new binding, move the PEP, and revoke the old one.
- **Partial:** the console creates credentials by name only. Use the API to set `subjectTypes` and `contextScopes`.

### Bind context claims and attesters

`contextScopes` lists the context signals this PEP may assert, with optional `networks`/`countries` constraints and
optional trusted-attester public keys per signal. Rotation preserves it; create a replacement credential to change it.
Production requires the field and maps older unscoped credentials to no permitted signals; demo retains their previous
behaviour for one version with deprecation warnings. Use `[]` for a PEP that asserts no protected signals. See
[Manage PEP credentials](../guides/security-officer.md#manage-pep-credentials) and the JWS contract in
[API](../../API.md#2-pdp-api-authzen-authorization-api-10--extensions).

### Routine rotation with overlap

1. In **Credentials and keys**, select the credential and choose **Rotate**, or call the rotate endpoint.
2. Store the returned `secret`, of the form `pep.<id>.<random>`.
3. Update one canary PEP and make a known allow and deny call.
4. Update the remaining PEPs before `previousValidUntil`.
5. The previous secret stays valid for `PEP_ROTATION_GRACE_SECONDS`, 300 seconds by default, measured in real time (`packages/pdp-http/src/auth.ts`).
6. After the grace period, confirm the old secret fails and the new one works.

`lastUsed` is updated at most once per minute; it is not a precise inventory.

### Move away from the bootstrap credential

1. Create one named credential per PEP. Names are 1 to 80 printable characters and unique among active credentials (`409 conflict` otherwise).
2. Deploy and verify every named secret.
3. Revoke `bootstrap`. A bearer value without the `pep.<id>.` prefix is checked only against `bootstrap` (`packages/pdp-http/src/auth.ts`).

### Rollback

Before the grace period ends, put the previous secret back on a failing PEP. After it ends, rotate again and deploy the newest secret: Qadamar cannot recover a secret from its hash.

## Rotate the decision-token signing key

Only security officers can rotate the signing key; access administrators and security officers can list keys. One Ed25519 key signs decision tokens, decision assertions (`gate-assertion`), policy publication signatures, and the detached signatures of compliance and evidence packs (`packages/pdp-http/src/tokens.ts`, `admin/evidence.ts`, `admin/compliance.ts`).

1. Export and archive the current JWKS and the current policy publication.
2. Confirm `SIGNING_KEY_SEAL` is present and identical on every node.
3. Call `POST /admin/v1/signing-keys/rotate` with `{}`, or use the console confirmation. The call returns `201` with `current` and `previous`.
4. Record `current.kid`, `previous.kid`, `previous.verifyUntil`, and `previous.sessionVerifyUntil`. The rotation is audited as `signing_key_rotate`.
5. Fetch `/.well-known/jwks.json` and confirm it holds both keys.
6. Issue and consume a certified decision, and confirm its `kid` is the new key. Backends that verify `gate-assertion` refresh their JWKS cache when they see the new `kid`.
7. Confirm the current policy publication was re-signed with the new key; the rotate call re-signs it.
8. After 300 seconds, confirm the old key cannot verify a decision token, policy signature, or key introduction. BLP session tokens alone may verify until `sessionVerifyUntil`. After that instant, confirm the old key has left the live JWKS.

The previous private key is discarded at rotation. `verifyUntil` is 300 seconds for decision tokens, backend assertions,
policy signatures, replica answers, and key-introduction links; `sessionVerifyUntil` is one hour and applies only to
`gate-blp-session+jwt`. Existing tokens still pass every expiry, single-use, version, and re-decision check: rotation
does not extend them. A key's presence in the live JWKS never widens those per-type checks.

Keep historical keyrings with long-term evidence. Public keys remain in the stored keyring after leaving the live JWKS,
with each `introducedBy` link preserving the rotation chain. Evidence manifests (`gate-evidence-manifest/1`) verify
offline against that history even after both acceptance windows end; the manifest and section hashes still bind the
exact exported content. Online policy signatures and introductions do not inherit this indefinite evidence rule. A
signature proves which key signed an old pack, not that the data was trustworthy during a key-compromise investigation.
Do not set `POLICY_SIGNATURE_ADOPT` for a rotation.

## Rotate the SCIM credential

The environment token and the console-minted credential are mutually exclusive.

### Console-minted credential

1. An access administrator calls `POST /admin/v1/scim/credential`, or uses the console. The call returns `201 {credential}`, or `409 conflict` when `SCIM_BEARER_TOKEN` is set.
2. Store the credential and update the SCIM provisioner.
3. Verify provisioning reads and one controlled proposal.
4. Have an independent approver review the proposal. The person who minted the credential cannot approve the changes it proposes (`packages/pdp-http/src/scim.ts`).

The new credential replaces the old one at once, without overlap; plan a short provisioning pause. `GET /admin/v1/scim/credential` (access administrators and security officers) reports the source (`env`, `console`, or `none`) and who rotated it when, never the secret.

### Environment token

1. Set a new `SCIM_BEARER_TOKEN` of 32 to 256 characters in the secret store.
2. Restart the nodes with the new value, then update the provisioner.
3. Verify SCIM authentication, then remove the old token from the secret store.

`SCIM_DIRECT=true` requires the environment token and bypasses two-person proposals. Review that setting during rotation.

## Rotate webhook, IdP, and metrics secrets

These secrets have no dual-secret overlap. Coordinate a short pause and restart every node with the new value.

| Secret | Procedure | Verification |
| --- | --- | --- |
| `SIEM_HMAC_SECRET` | Update the receiver and Qadamar together, restart, and wait for a batch. Keep the cursor. | The receiver accepts the HMAC and sequences continue without a gap. |
| `BREAK_GLASS_WEBHOOK_SECRET` | Update the receiver and Qadamar together, restart, and open a controlled emergency. | The receiver accepts one signed notice and `gate_break_glass_notices_total{outcome="sent"}` increases on the node that sent it. |
| SAML SP decryption/signing PEM pairs | Coordinate the IdP certificate update and Qadamar restart; mount matching key/certificate files. One key per purpose is active at a time. | Encrypted MFA sign-in and both directions of single logout succeed; metadata contains only public certificates. |
| `OIDC_CLIENT_SECRET` | Update the IdP and Qadamar, then restart. | A fresh OIDC login with MFA and a recognised role succeeds. |
| `METRICS_TOKEN` | Update the scraper and Qadamar together and restart. In the managed offer it is in the Secret `gate-env`. Production requires at least 32 characters. | The old token returns 401 and the new token returns Prometheus text. |
| `TSA_CA_FILE` trust material | Validate the new CA bundle offline and stage it before the TSA chain changes. Restart with the new file. | A new anchor verifies and is stored. |

With PostgreSQL, console sessions are rows of `gate_session` and survive the restart; in file mode a restart ends them. A sign-in in progress at the IdP (the sealed OIDC state cookie) does not survive a restart: plan for those users to start it again. SIEM batches resume from their stored cursor.

## Rotate the backup encryption key

`BACKUP_ENCRYPTION_KEY` encrypts archives written by `scripts/ops/backup.sh`; it is not read by the server ([Back up and restore](backup-restore.md#manage-the-backup-encryption-key)).

1. Generate a new key: `openssl rand -hex 32`, or 32 bytes as unpadded base64url.
2. Store it in the secret store next to, not in place of, the old key. In the managed offer, update the Secret `gate-backup`; keep a copy outside the cluster.
3. Run a backup and a test restore with the new key.
4. Record which key encrypts which archives.

**Partial:** a new key applies to new backups only. No script re-encrypts existing archives. Keep every old key as long as the archives it encrypted are retained. `scripts/ops/archive-crypt.ts` can decrypt an archive with one key and encrypt the result with another in two separate runs, but that writes the plaintext dump to disk in between; treat it as a manual, controlled procedure.

## Rotate database credentials

1. Create or update the service-role secret through the database's secure administration process. Keep the role's privileges exactly as required by the production preflight.
2. Stage the new `DATABASE_URL` for every node without logging it.
3. Active/standby: restart the waiting standby with the new URL first, then stop the active node gracefully so the updated node takes over. Cluster mode: restart followers one at a time, then the leader.
4. Verify readiness, a committed decision, an audit recheck, and the production role check.
5. Restart the remaining node with the new URL and confirm it waits or follows normally.
6. Revoke the old database secret only after every node works with the new one.

Rotate the backup role's secret in `BACKUP_DATABASE_URL` (managed offer: Secret `gate-db-admin`) the same way, and run one backup to confirm. A credential rotation must not switch the nodes to the owner role, a replica, or a transaction-mode pooler.

## Rotate the root seal (`SIGNING_KEY_SEAL`)

The 32-byte root seals the private signing keys and TOTP secrets (AES-256-GCM), and keys, through HKDF, the audit-checkpoint and retention-segment HMACs, export pseudonymisation and cluster hop signatures. Rotation is operator-driven, at start (`packages/pdp-http/src/seal-rotation.ts`). File checkpoints and retention seals are re-keyed there; PostgreSQL segment seals require the owner step below because the service role cannot update them.

1. **Back up first.** Take a database backup (or copy `DATA_DIR`) and confirm the current `SIGNING_KEY_SEAL` is in the secret store. Keep the old key until step 6.
2. Generate the new key (`openssl rand -hex 32`) and store it next to, not in place of, the old one.
3. Set on **every** node: `SIGNING_KEY_SEAL=<new>` and `SIGNING_KEY_SEAL_PREVIOUS=<old>`. Restart all nodes together: active/standby, stop both and start them; cluster, restart every node in the same window (followers forward console requests with a hop signed by a key derived from the seal, so a mixed cluster refuses console forwarding until all nodes run the new key; decisions are unaffected).
4. The node that writes (the active node, or the cluster leader) checks every sealed value at start, re-seals under the new key what only the old key opens, re-authenticates the audit checkpoint (trusted under the old key only while some sealed value is still under it, that is during this start), and commits it all in one transaction with one audit row `security / seal_key_rotated` (`details`: `signingKeys`, `totpSecrets`, `checkpointRekeyed`). The log line says `Re-sealed under SIGNING_KEY_SEAL: ...`. Followers open old values with the previous key until they sync the re-sealed documents.
5. Verify: the audit row is present, `/readyz` reports the audit verified, a decision verifies against `/.well-known/jwks.json` (the signing keys are the same, only re-sealed), and a TOTP account signs in.
6. **Right after the first successful start, remove `SIGNING_KEY_SEAL_PREVIOUS` from every node and restart.** Until then every start warns `SIGNING_KEY_SEAL_PREVIOUS is set but nothing at rest is sealed under it any more`. Once the rotation is done the previous key vouches for nothing: an audit checkpoint authenticated only by it is not trusted (the start logs `... authenticated only by SIGNING_KEY_SEAL_PREVIOUS ... not trusted` and verifies every chain from its genesis before serving), since the old key may be the one you rotated away from because it leaked. Without the previous key the start logs nothing about it, and a start with the old key alone is refused.

If `gate_audit_segment` is non-empty, stop every writer before step 3 and run `scripts/ops/audit-retention.ts` as the table owner with the new `SIGNING_KEY_SEAL`, old `SIGNING_KEY_SEAL_PREVIOUS`, and the configured `AUDIT_RETENTION_DAYS`/TSA. It verifies and re-keys old segment HMACs (and applies only retention already due), deleting nothing merely because it is a rotation. Never grant the runtime role `UPDATE` on that table. File mode re-keys its checkpoint and segment file at startup; the checkpoint's old key is trusted only while rotation is in progress, then the whole retained chain is checked and re-authenticated.

While `SIGNING_KEY_SEAL_PREVIOUS` is set, the configuration baseline in evidence packs reports `storage.sealRotationInProgress: true`.

### Refusal, never loss

Every start, rotation or not, checks that each sealed value opens under `SIGNING_KEY_SEAL` (or `SIGNING_KEY_SEAL_PREVIOUS`). If one opens under neither, the start stops with `... sealed value(s) at rest do not open under SIGNING_KEY_SEAL ... Nothing was changed`, naming the signing key ids and account ids (never a value). Nothing is re-sealed, discarded or written: start again with the key that sealed them, as `SIGNING_KEY_SEAL`, or as `SIGNING_KEY_SEAL_PREVIOUS` to rotate. With PostgreSQL the re-seal and its audit row commit in one transaction; in file mode, should the node stop between the two files, start again with both keys set: the step is idempotent.

### Consequences to plan for

- **Pseudonyms:** pseudonymised audit exports use a key derived from the seal; after rotation the same person gets a new pseudonym. Record the rotation date with exported datasets.
- **Backups:** an archive holds material sealed under the key in force when it was taken. Keep every old `SIGNING_KEY_SEAL` as long as archives it sealed are retained, labelled with the archive dates; to restore an old archive, start with that key as `SIGNING_KEY_SEAL_PREVIOUS` and the current one as `SIGNING_KEY_SEAL`, which re-seals it.
- **Lost key:** without the seal key, the signing keys and TOTP secrets cannot be recovered. Qadamar refuses to start rather than replace them; the recovery is the secret-store copy. Store the key in two independent places (secret store and an offline escrow under dual control) and test the copy at each disaster-recovery exercise.

## Local-account limits

There is no route to change a local account's password or roles, so no session needs ending for them. Console sessions end at logout, at 15 minutes idle or 8 hours, and, for OIDC sign-ins, by back-channel logout from the IdP, or for SAML sign-ins by signed single logout; with PostgreSQL each of these holds on every node and after a takeover.

### Local passwords and TOTP reset

**Not available:** a local password-change route and a self-service TOTP reset. TOTP enrolment, in the console's **Two-step sign-in** screen or through the API, requires a password session, the current password, and a CSRF token (`packages/pdp-http/src/auth.ts`).

If a user loses both the device and the recovery codes, use the organisation's controlled identity-recovery process. The only implementation-level recovery is removing that account's `totp` entry from the `credentials` document by an authorised operator: a sensitive manual edit, not a product procedure. Back up first, prove identity out of band, apply the change in a controlled maintenance window, and require immediate re-enrolment. Prefer OIDC accounts in production.

## Emergency revocation

- **PEP compromise:** revoke the credential at once. Its current and previous secrets stop, and their cached digests are cleared (`packages/pdp-http/src/auth.ts`). Cluster followers apply the revocation at their next sync; a node that has not synced within `GATE_MAX_STALENESS_MS` refuses decisions.
- **BLP session-token theft or subject/session compromise:** call `POST /admin/v1/blp-sessions/revoke` by `sessionId`,
  `subject` (optionally narrowed by `credential`), or `credential`. This removes live rows under the decision locks and
  commits audited tombstones shared across PostgreSQL and the replica feed; outstanding decision tokens with that `bsid`
  also die. Revoke the PEP credential too when it must not open replacements (`packages/pdp-http/src/pep-sessions.ts`).
- **Signing-key compromise:** preserve evidence, rotate the signing key, confirm the current policy was re-signed, and investigate every token and assertion issued during the exposure. Existing tokens remain bounded by their TTL and current-state checks.
- **SCIM compromise:** replace the console credential or environment token and pause SCIM writes. Review pending and applied `scim_subjects` proposals by credential fingerprint and reverse unauthorised changes through new reviewed proposals.
- **Webhook-secret compromise:** disable the integration, rotate at both ends, and review events and batches accepted during the exposure.
- **Database-credential compromise:** revoke and rotate the secret, inspect database and Qadamar logs, and verify every audit chain against independent evidence.
- **Backup-key compromise:** generate a new key for future backups, and treat every archive encrypted with the old key as readable by the holder. Archives cannot be re-keyed by a script.
- **Seal compromise:** treat all sealed private keys, TOTP secrets, and checkpoints as exposed. Isolate the deployment, preserve evidence, [rotate the seal](#rotate-the-root-seal-signing_key_seal), then rotate the signing key (the old private key was readable) and treat the TOTP secrets as known: reset them as described under [Local passwords and TOTP reset](#local-passwords-and-totp-reset). Re-sealing protects the material from now on; it does not make exposed copies unusable.

## Related pages

- [Security architecture](../architecture/security-architecture.md)
- [Deploy Qadamar](deploy.md)
- [Upgrade Qadamar](upgrade.md)
- [Fail over the active node](failover.md)
- [Back up and restore](backup-restore.md)
- [Configuration reference](configuration.md)
- [Audit and evidence](../architecture/audit-and-evidence.md)
