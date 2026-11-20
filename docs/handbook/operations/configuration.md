# Configuration reference

Qadamar is configured through environment variables. The authoritative list is [docs/CONFIGURATION.md](../../CONFIGURATION.md): it is generated from the variables the code reads, and CI fails when it drifts. This page tells you which variables to set for each task, what the production profile requires, and how to configure cluster mode and a reverse proxy. It does not repeat the per-variable table.

## On this page

- [About docs/CONFIGURATION.md](#about-docsconfigurationmd)
- [Settings by task](#settings-by-task)
- [Production profile requirements](#production-profile-requirements)
- [Cluster mode settings](#cluster-mode-settings)
- [Reverse proxy settings](#reverse-proxy-settings)
- [Values you cannot configure](#values-you-cannot-configure)
- [Secret handling](#secret-handling)

## About docs/CONFIGURATION.md

[docs/CONFIGURATION.md](../../CONFIGURATION.md) is written by `scripts/docs/env-table.ts` from the variables read under `packages/*/src` and `scripts/ops`. CI runs `node scripts/docs/env-table.ts --check` and fails when a variable is read but not documented, or documented but not read. For the code at commit b09bc44 (after 0.3.0) it lists:

- 46 server variables, each with its default, meaning, and the file that reads it;
- 4 operations-script variables for `scripts/ops/backup.sh` and `restore.sh`: `BACKUP_ENCRYPTION_KEY`, `BACKUP_FILE`, `DATABASE_URL`, and `MAINTENANCE_DATABASE_URL` ([Operations scripts](../../CONFIGURATION.md#operations-scripts));
- the test and tool variables that neither the server nor the scripts read.

Release variables (`RELEASE_SIGNING_HOOK`, `SOURCE_DATE_EPOCH`, `ALLOW_DIRTY`, `OUT_DIR`) are in [docs/RELEASE.md](../../RELEASE.md).

Two parsing rules apply to the server variables (`packages/pdp-http/src/main.ts`):

- Flags are on for `1`, `on`, `true`, or `yes`, case-insensitive. Any other set value is off.
- An invalid value for a validated setting stops startup with an error that names the variable.

## Settings by task

Look up each variable in [docs/CONFIGURATION.md](../../CONFIGURATION.md).

| Task | Variables |
| --- | --- |
| Listen and serve TLS | `HOST`, `PORT`, `PUBLIC_ORIGIN`, `TLS_CERT_FILE`, `TLS_KEY_FILE` |
| Choose storage | `DATA_DIR`, `WORLD_DIR`, `DATABASE_URL` (unset: file mode, one node) |
| Authenticate PostgreSQL transport | `DATABASE_TLS`, optional `DATABASE_TLS_CA_FILE`, `DATABASE_TLS_CERT_FILE` and `DATABASE_TLS_KEY_FILE` |
| Run several deciding PostgreSQL nodes | `GATE_CLUSTER`, `GATE_NODE_ID`, `GATE_MAX_STALENESS_MS`, `GATE_ADVERTISE_URL` ([Cluster mode settings](#cluster-mode-settings)) |
| Run behind a proxy or ingress | `TRUSTED_PROXIES` ([Reverse proxy settings](#reverse-proxy-settings)) |
| Select the security baseline | `GATE_PROFILE` ([Production profile requirements](#production-profile-requirements)) |
| Console sign-in | `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ID_CLAIM`, `OIDC_ROLE_CLAIM`, `OIDC_ACR`, `PASSWORD_LOGIN`, `RESOURCE_OWNERS` |
| Seal keys at rest | `SIGNING_KEY_SEAL`, `ALLOW_CLEAR_SIGNING_KEYS` |
| Separation of duty and administration | `SOD_HISTORY`, `IMPACT_MAX_EVALUATIONS`, `POLICY_SIGNATURE_ADOPT` |
| PEP credentials and first start | `PEP_ROTATION_GRACE_SECONDS`, `INITIAL_CREDENTIALS_TTL_SECONDS` |
| Anchor the audit | `TSA_URL`, `TSA_CA_FILE`, `ANCHOR_INTERVAL`, `OPENSSL` |
| Protect metrics | `METRICS_TOKEN` |
| Provision through SCIM | `SCIM_BEARER_TOKEN`, `SCIM_GROUP_ROLES`, `SCIM_DIRECT` |
| Export the audit to a SIEM | `SIEM_WEBHOOK_URL`, `SIEM_HMAC_SECRET`, `SIEM_INTERVAL_SECONDS`, `SIEM_BATCH_SIZE` |
| Send break-glass notices | `BREAK_GLASS_WEBHOOK`, `BREAK_GLASS_WEBHOOK_SECRET` |
| Export traces | `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME` |
| Fix the business clock for a demo | `CLOCK` |
| Back up and restore | `BACKUP_ENCRYPTION_KEY`, `BACKUP_FILE`, `DATABASE_URL`, `MAINTENANCE_DATABASE_URL` ([Back up and restore](backup-restore.md)) |

For a production deployment, also read [docs/DEPLOY.md §5](../../DEPLOY.md#5-production-profile-gate_profileproduction), the checklist the production check follows.

## Production profile requirements

With `GATE_PROFILE=production`, the node refuses to start unless every item below holds. The error starts with `GATE_PROFILE=production refused to start:` and lists every failing item. The checks run before the node takes the PostgreSQL lock or migrates anything (`packages/pdp-http/src/profile.ts`, `server.ts`).

- `PUBLIC_ORIGIN` starts with `https://`.
- `OIDC_ISSUER` or `SAML_IDP_ENTITY_ID` is set. SAML requires an MFA class from `SAML_AUTHN_CONTEXT`; OIDC sign-in always requires MFA evidence from the IdP: `amr` contains `mfa` or `mca`, or `acr` equals `OIDC_ACR`.
- Password sign-in is off, or every local account in the `credentials` document has active TOTP. Password sign-in is off by default when OIDC or SAML is configured.
- `DATABASE_URL` is set, and its role, checked in the database:
  - is not a superuser, directly or through membership;
  - has no `BYPASSRLS` or `CREATEROLE`, directly or through membership;
  - finds all eighteen tables in schema `public`: `gate_doc`, `gate_audit`, `gate_audit_meta`, `gate_anchor`, `gate_audit_segment`, `gate_subject_identity`, `gate_sync`, `gate_token`, `gate_performed`, `gate_session`, `gate_blp_mark`, `gate_blp_session`, `gate_retired`, `gate_subject`, `gate_resource`, `gate_tuple`, `gate_state_change`, `gate_rate_limit`;
  - neither owns, nor is a member of the owner of, any of those tables;
  - holds no `UPDATE`, `DELETE`, or `TRUNCATE` on `gate_audit`, `gate_anchor`, `gate_audit_segment`, or `gate_performed`.
- `DATABASE_TLS=verify-full` for every non-local database host. The certificate chain and hostname are verified against the system store or `DATABASE_TLS_CA_FILE`; an optional client certificate and key must be configured together.
- `SIGNING_KEY_SEAL` is set.
- `ALLOW_CLEAR_SIGNING_KEYS` and `POLICY_SIGNATURE_ADOPT` are off.
- `SOD_HISTORY=server`.
- `BLP_SESSION_REQUIRED=true`. Every PEP opens PDP sessions and sends `context.sessionToken`; production refuses raw `sessionId`. Tune `BLP_SESSIONS_PER_SUBJECT` and `BLP_SESSION_CREATION_PER_MINUTE` if the defaults (4 and 60) do not fit.
- `METRICS_TOKEN` has at least 32 characters.
- `TSA_URL` starts with `https://` and `TSA_CA_FILE` is set.
- `CLOCK` is not set.
- `BREAK_GLASS_WEBHOOK` and `BREAK_GLASS_WEBHOOK_SECRET` are set, and the webhook URL starts with `https://`.
- `OTEL_EXPORTER_OTLP_ENDPOINT`, when set, uses HTTPS. Plain HTTP is accepted only on a loopback address.

Since 0.5.0 the profile no longer forces a full audit-chain scan before serving: like every profile, a start (a takeover included) verifies from the authenticated checkpoint, then the whole chain in the background (docs/API.md §3.9.1). Watch `gate_audit_full_chain_verified`.

The profile does not check `TRUSTED_PROXIES`, the cluster settings, `SIEM_WEBHOOK_URL`, custody of `BACKUP_ENCRYPTION_KEY`, WAL archiving, the IdP's own MFA policy, encryption of `DATA_DIR`, or network segmentation. Check those in your own deployment checklist.

## Cluster mode settings

Cluster mode applies only with `DATABASE_URL`. Without `GATE_CLUSTER`, PostgreSQL mode runs one active node and waiting standbys ([Fail over the active node](failover.md)).

| Variable | Default | Rule |
| --- | --- | --- |
| `GATE_CLUSTER` | off | On: every node decides against the shared database, and only the leader serves `/admin/` and `/scim/`. |
| `GATE_NODE_ID` | `0` | The audit chain this node writes. 1 to 64 characters from `[A-Za-z0-9_.-]`, starting with a letter or digit. Give every node its own id: a second process with an id already in use waits until the first stops. `0` continues the single chain of earlier versions. |
| `GATE_MAX_STALENESS_MS` | `2000` | Integer from 100 to 60000. A node that has not confirmed the shared state within this bound answers PDP requests with `503 unavailable` and fails `/readyz`. |
| `GATE_ADVERTISE_URL` | unset | The address this node publishes while it leads. Followers return it in the `leader` field of their `409 not_leader` answers; unset, the field is `null`. |

A node polls the shared state every `GATE_MAX_STALENESS_MS / 4` milliseconds, at least 20 and at most 500, and also wakes on PostgreSQL `LISTEN/NOTIFY` (`packages/pdp-http/src/postgres.ts`). With the default bound the poll interval is 500 ms. For load-balancer routing, see [Deploy in cluster mode](deploy.md#deploy-in-cluster-mode).

Set the same `RATE_LIMIT_PER_MINUTE` and `PEP_RATE_LIMIT_PER_MINUTE` on every node. Cluster nodes lease capacity from shared `gate_rate_limit` buckets (at most 1,000 tokens, a tenth of a smaller bucket, or a larger single-request cost), so N nodes cannot admit N times the configured rate. There is no database call per request while a lease lasts. Unused leases can under-admit by at most N(B−1) tokens per key, never overspend. Rows idle for an hour are swept. File and active/standby modes retain local buckets.

## Reverse proxy settings

Set `TRUSTED_PROXIES` whenever a reverse proxy, load balancer, or ingress controller connects to Qadamar. Without it, Qadamar takes the proxy's address as the client address: every client shares one per-IP rate-limit bucket of 120 requests per minute, and the audit records the proxy's address. 0.3.0 behaved this way behind any proxy.

- Value: a comma-separated list of IPv4 or IPv6 addresses or CIDR ranges. An invalid entry stops startup.
- Qadamar reads `X-Forwarded-For` only when the connecting peer is in the list. The client address is then the rightmost entry that is not itself a trusted proxy; entries further left are ignored (`packages/pdp-http/src/proxy.ts`).
- The resolved address keys the per-IP rate limit and the login lockout, and is recorded in sign-in audit rows (`details.client`) and on request spans (`client.address`).
- List only addresses from which nothing but your proxies can connect.

## Values you cannot configure

These are code constants. Do not invent environment variables for them.

| Value | Constant | Source |
| --- | --- | --- |
| Cluster rate-lease size | At most 1,000 tokens, or a tenth of a smaller bucket; a larger single-request cost is leased instead | `packages/pdp-http/src/ratelimit.ts` |
| Console session | 8 hours absolute, 15 minutes idle | `packages/pdp-http/src/auth.ts` |
| Readiness cache | 5 seconds | `packages/pdp-http/src/metrics.ts` |
| Periodic full audit recheck | Every 5 minutes; 3 consecutive failures stop the node | `packages/pdp-http/src/server.ts`, `postgres.ts` |
| PostgreSQL statement timeout | 15 seconds, set after the locks are taken | `packages/pdp-http/src/postgres.ts` |
| Maximum decision-token TTL | 300 seconds | `packages/pdp-http/src/tokens.ts` |
| Decision-assertion TTL | 30 seconds | `packages/pdp-http/src/tokens.ts` |

## Secret handling

- Inject secrets from your secret store. Do not put them in manifests, images, shell history, or documentation.
- Do not log `process.env`, connection URLs, bearer headers, `INITIAL-CREDENTIALS.txt`, or key material.
- Use separate secrets for each PEP credential and for SCIM, SIEM, break-glass, metrics, the database, and backups.
- Keep `SIGNING_KEY_SEAL` and `BACKUP_ENCRYPTION_KEY` apart from each other and from the backup archives. Every node needs the same `SIGNING_KEY_SEAL`.
- Rotate credentials with [Rotate keys and credentials](rotate-credentials.md).

## Related pages

- [Deploy Qadamar](deploy.md)
- [Monitoring and alerts](monitoring.md)
- [Rotate keys and credentials](rotate-credentials.md)
- [Back up and restore](backup-restore.md)
- [Security architecture](../architecture/security-architecture.md)
- [ADR: Production profile](../architecture/decisions/0010-production-profile.md)

## Tenant assignment

`GATE_TENANTS_FILE` names a mode-600 JSON secret file mapping tenant ids to separate `dataDir`, `worldDir` and,
for database tenants, `databaseUrl` and `signingKeySeal`. `GATE_SERVE_TENANTS` lists distinct ids to open; omitted
means all manifest entries. Bad ids, unknown fields, overlapping stores and reused keys refuse startup. No worlds,
feeds or indexes are opened for excluded tenants. Tenant source/replica keys and rotation settings belong in each
entry. Existing non-tenant settings still apply to every served runtime; production checks remain unchanged.

Every route requires one `X-Qadamar-Tenant` header in this mode. Unknown/unassigned ids return 421 `tenant_not_served`;
missing or invalid headers return 400 `tenant_required`. Without the manifest the single-tenant behavior remains.
See [Tenant partitions](../../DEPLOY.md#tenant-partitions) for the full manifest fields, cluster/replica configuration,
separate-database requirement, browser hostname routing and health-check override.

## SAML encryption and single logout

SAML is an alternative to OIDC with the same required MFA and console role restrictions. Set `SAML_IDP_ENTITY_ID`,
`SAML_IDP_SSO_URL`, `SAML_IDP_CERT_FILE`, `SAML_ID_ATTRIBUTE` and `SAML_AUTHN_CONTEXT`; see [API §3.1.1](../../API.md#311-console-sign-in-through-the-organisation-oidc-or-saml-and-tls).
Mount matching RSA 2048+ PEM key/certificate pairs as `SAML_DECRYPTION_KEY_FILE` / `SAML_DECRYPTION_CERT_FILE` for
encrypted signed assertions, and `SAML_SIGNING_KEY_FILE` / `SAML_SIGNING_CERT_FILE` for outgoing signatures.
Set `SAML_IDP_SLO_URL` to the pinned IdP Redirect logout endpoint for full SLO. Register Qadamar's metadata and both
logout bindings at the IdP. Metadata includes public certificates only. Protect private files in the secret store;
Qadamar never logs them. Local sessions and their CSRF authority end before SP logout leaves Qadamar, even if the IdP
never replies. Pending SAML logins, logout requests and replay IDs are process-local on the admin leader.
