# ADR 0010: Production profile with fail-closed preflight

This ADR records the decision to make production startup refuse an incomplete security baseline rather than rely on documentation or warn and continue. The profile consolidates controls that otherwise depend on an operator remembering several independent environment variables.

## On this page

- [Status](#status)
- [Context](#context)
- [Decision](#decision)
- [Consequences](#consequences)
- [Alternatives](#alternatives)
- [Evidence](#evidence)

## Status

Accepted in v0.3.0 commit `6cd36fb`. Demo remains the default for compatibility; `GATE_PROFILE=production` activates the preflight.

At commit `b09bc44` (after 0.3.0) the database checks cover seven tables (`gate_doc`, `gate_audit`, `gate_audit_meta`, `gate_anchor`, `gate_sync`, `gate_token`, `gate_performed`), and `gate_performed` joins the append-only set. The profile does not check `TRUSTED_PROXIES` or the cluster settings (`GATE_CLUSTER`, `GATE_NODE_ID`, `GATE_MAX_STALENESS_MS`); it records them in the configuration baseline of evidence packs (`configurationBaseline`).

## Context

The system has demo-friendly defaults: file storage, generated local accounts, optional metrics authentication on loopback, optional TSA, and (after the safer-defaults change) server-recorded SoD history. These are useful for evaluation but unsafe as an unnoticed production configuration.

Some requirements can be checked locally, while database role ownership and privileges require a database query. The preflight must run before migration or leader-lock acquisition so an invalid node cannot become active or change the schema.

## Decision

- Accept only `demo` or `production` for `GATE_PROFILE`; default to `demo`.
- In production, require HTTPS public origin, OIDC with MFA evidence, PostgreSQL, sealed signing keys, server-derived SoD, authenticated metrics, CA-verified HTTPS TSA anchoring, real clock, and break-glass notices.
- If local passwords remain enabled, require active TOTP for every local account in the shared credentials document.
- Refuse clear signing keys and policy-signature adoption mode.
- Check the database service role before migration: no superuser, BYPASSRLS, CREATEROLE, table ownership, owner membership, or append-only-table rewrite privileges; all Qadamar tables must already exist in `public` (four in 0.3.0, seven at b09bc44).
- Require `DATABASE_TLS=verify-full` for a non-local production database. The same explicit policy covers runtime, migration, retention and backup/restore connections; local sockets and non-production testing retain bounded exceptions.
- Report all discovered failures together and refuse startup before taking the leader lock.
- ~~Always perform a full audit-chain scan before production serving, ignoring checkpoints.~~ Superseded in 0.5.0: production starts from the authenticated checkpoint like every profile and verifies the whole chain in the background, with a readiness field and a metric, because takeover time grew with the audit (docs/API.md §3.9.1).
- Require HTTPS for remote break-glass and OTLP endpoints; allow loopback HTTP only for those outbound development cases where supported.

## Consequences

### Positive

- An operator cannot accidentally launch the defined production profile with several known unsafe defaults.
- Database checks include indirect role membership and append-only privileges, not just “connected successfully.”
- Startup refusal happens before schema mutation or active service.
- (Until 0.4.2) full startup verification avoided the checkpoint’s early-row detection window; since 0.5.0 that window, the background verification, applies to production too.
- Local recovery accounts remain possible, but only with TOTP.

### Negative and operational

- First production deployment requires an owner-role migration and careful sequencing of TOTP enrolment in demo mode against the same database.
- Existing large logs increase production startup and takeover time.
- Preflight does not prove ongoing external security: IdP MFA policy, database availability and encryption at rest, host encryption, backups, SIEM, TSA availability, and network controls still need verification. Database TLS verifies the configured endpoint at connection time, not the hosting service's ongoing custody.
- The supplied Compose role fails the production role checks by design, so Compose is not a turnkey production deployment.
- Recovery flags such as `POLICY_SIGNATURE_ADOPT` require a deliberate non-production recovery step rather than being left enabled.

## Alternatives

- **Warn but serve:** rejected because a warning is easy to miss and leaves a misleading “production” deployment.
- **Secure defaults with no profile switch:** not chosen because it would break the demonstration startup path.
- **Only static environment checks:** insufficient for database role membership and actual table privileges.

## Evidence

- Local and database preflight checks: `packages/pdp-http/src/profile.ts`.
- Preflight ordering and full-scan option: `packages/pdp-http/src/server.ts`.
- Environment parsing: `packages/pdp-http/src/main.ts`.
- Compose’s demonstration role layout: `docker-compose.yml`.
- Introduction: git commit `6cd36fb`.

## Related pages

- [Security architecture](../security-architecture.md)
- [Deploy Qadamar](../../operations/deploy.md)
- [Configuration reference](../../operations/configuration.md)
- [ADR 0003: PostgreSQL single active node](0003-postgresql-single-active-node.md)
