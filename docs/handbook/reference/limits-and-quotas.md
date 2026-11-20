# Limits and quotas

Qadamar bounds request bodies, batches, searches, audit pages, policy evaluation, credentials, tokens, and gateway exchanges to make failures explicit and resource use predictable. These are implementation limits rather than service-level quotas or capacity promises; configurable defaults can differ when code-level server options or environment variables change them.

## On this page

- [HTTP and authentication limits](#http-and-authentication-limits)
- [Evaluation and search limits](#evaluation-and-search-limits)
- [Policy and governance limits](#policy-and-governance-limits)
- [Credential and token limits](#credential-and-token-limits)
- [Audit, provisioning, and export limits](#audit-provisioning-and-export-limits)
- [SDK and gateway limits](#sdk-and-gateway-limits)

## HTTP and authentication limits

| Limit | Value and behavior |
|---|---|
| JSON or form request body | 1,048,576 bytes. Larger bodies return 413 `payload_too_large` with the normal JSON envelope and `Connection: close`; incomplete or aborted bodies return 400 `bad_request`. |
| Form fields | At most 8 key-value entries and 16,384 characters per value. |
| PDP and admin server timeouts | 30-second request timeout and 10-second headers timeout. |
| Default general rate limit | 120 tokens per minute per source IP and per authenticated principal. PEP batch evaluations cost one token per evaluation. |
| Rate-bucket memory | At most 10,000 token-bucket entries per limiter; oldest entries are evicted. |
| Login throttle | 5 attempts per minute per normalized username and source IP. |
| Login lockout | From the fifth failure, progressive locks of 1, 2, 4, 8, 16, 32, then at most 60 minutes. Account and IP-related locks apply. |
| TOTP enrolment throttle | 5 attempts per account per limiter window before 429. |
| Console session | 15-minute idle timeout and 8-hour absolute timeout. |
| OIDC state | 10-minute lifetime; callback code at most 4,096 characters and state at most 256. |
| OIDC logout replay memory | Used `jti` values retained for 24 hours, at most 10,000 in memory. |
| OIDC clock skew | 60 seconds. |
| Initial credential file | Default lifetime 3,600 seconds, configurable 1–86,400; deleted at first successful sign-in or expiry, whichever comes first. |
| Metrics token | Required on every non-loopback bind in every profile; without it `/metrics` answers 403. Production additionally requires at least 32 characters. |

`RATE_LIMIT_PER_MINUTE` defaults to 120 and `PEP_RATE_LIMIT_PER_MINUTE` to 60,000. In cluster mode each node leases at most 1,000 tokens (a tenth of a smaller bucket, or a larger single-request cost) from shared PostgreSQL buckets. There is no query per request while a lease lasts and no cluster overspend; up to N(B−1) unused leased tokens per key can temporarily under-admit. File and active/standby modes keep process-local buckets. Behind a reverse proxy, the per-IP bucket uses the client address only when the proxy is listed in `TRUSTED_PROXIES`; see `docs/CONFIGURATION.md`. Health, readiness, and metrics calls count against the per-IP bucket. Sources: `packages/pdp-http/src/http.ts`, `packages/pdp-http/src/ratelimit.ts`, `packages/pdp-http/src/router.ts`, `packages/pdp-http/src/auth.ts`, `packages/pdp-http/src/oidc.ts`, `packages/pdp-http/src/server.ts`.

## Evaluation and search limits

| Limit | Value and behavior |
|---|---|
| Batch evaluation | At most 1,000 entries. An empty array is accepted and returns no evaluations. |
| Resource or subject search page | Default 100; allowed 1–1,000. `next_token` is an opaque candidate position. |
| Action search | Declared actions for the resource type are filtered by point decision; no page parameter. |
| XACML MultiRequests | At most 1,000 request references. |
| Impact analysis | Default maximum 100,000 affected-cell evaluations after network, context-class and maker/history variants. `IMPACT_MAX_EVALUATIONS` must be a positive safe integer. |
| Impact context classes | At most 32 representative classes per network. One-signal variants derived from old and new CBAC rules precede their cross-product; `contextAnalysis.truncated` reports omitted combinations. |
| Impact work | Each reported cell can be decided in both before and after worlds, so engine work is up to twice the reported count. Larger proposals return 422 before evaluation. |
| Delegation | At most four delegation links, or five principals including the initial subject. |
| Relation walk | At most 32 general hops; reporting-line `maxDepth` is 1–50 and cycles are not followed. |
| Condition nesting | Bundle validation rejects nesting deeper than 32. SQL compilation rejects nesting deeper than 64. |
| Rule identifier | 1–64 characters: letters, digits, underscore, dot, or hyphen. |
| Subject/resource/action identifier | Non-empty string, at most 256 characters. |

Sources: `packages/pdp-http/src/pdp.ts`, `packages/pdp-http/src/admin/changes.ts`, `packages/pdp-http/src/xacml.ts`, `packages/core/src/request.ts`, `packages/core/src/relations.ts`, `packages/core/src/validate.ts`, `packages/sql/src/index.ts`.

## Policy and governance limits

| Limit | Value and behavior |
|---|---|
| Proposal and emergency reason | At least 20 trimmed characters for change proposals, break-glass opening and revocation, and access-review decisions. |
| Approval or emergency review note | At least one non-empty character; use a substantive note. |
| `granted` / `allocated` validity | Expiry required within 90 days of the server time. Future-start grants cannot be proposed before their effective time. |
| Access-review horizon | Expiring within 30 days, plus `granted` tuples at least 90 days old. |
| Break-glass bundle cap | Greater than 0 and at most 24 hours. |
| Break-glass admin grant | Greater than 0 and at most the smaller of 4 hours and the bundle cap. The console presents whole hours 1–4. |
| Decision-token TTL | Greater than 0 and at most 300 seconds, set by the bundle. |
| Retired signing-key verification | 300 seconds after rotation, then the old public key leaves the JWKS. |

Sources: `packages/pdp-http/src/http.ts`, `packages/pdp-http/src/admin/changes.ts`, `packages/pdp-http/src/admin/reviews.ts`, `packages/pdp-http/src/admin/break-glass.ts`, `packages/core/src/validate.ts`, `packages/pdp-http/src/tokens.ts`.

## Credential and token limits

| Limit | Value and behavior |
|---|---|
| PEP credential name | Trimmed 1–80 printable characters, unique among active credentials. |
| PEP bearer header | `Authorization` length above 263 characters is refused as unauthenticated. |
| Secret verification | Secrets longer than 256 characters are not accepted for password or PEP verification. |
| PEP rotation grace | Default 300 seconds, configurable 0–86,400 seconds using real wall time. |
| Signing-key seal | Exactly 32 bytes as base64url or 64 hexadecimal characters. |
| SCIM environment token | 32–256 characters. |
| PEP credential binding | 1–16 subject types, each 1–64 characters from letters, digits, `_`, `.`, and `-`. |
| Decision assertion | 30-second lifetime; the SDK verifier refuses a longer one. |
| TOTP code | Six digits; other forms are interpreted as recovery codes, with a maximum input length of 64. |
| TOTP recovery codes | Ten one-time codes returned at activation; only hashes are stored. |

Sources: `packages/pdp-http/src/auth.ts`, `packages/pdp-http/src/tokens.ts`, `packages/pdp-http/src/scim.ts`, `packages/pdp-http/src/totp.ts`, `packages/sdk/src/assertion.ts`.

## Audit, provisioning, and export limits

| Limit | Value and behavior |
|---|---|
| Audit list page | Default 50; allowed 1–1,000. Cursor must be a non-negative safe integer. |
| Audit NDJSON export | Default 100; allowed 1–1,000 rows. `from` starts at 1 and is inclusive; it is a sequence number on chain `0` or a comma-separated list of `node:seq` positions. Only `from`, `limit`, and `pseudonymise=1` are accepted, once each. |
| Subject access report | At most the newest 1,000 audit rows; `complete: false` when older rows were left out. |
| Evidence pack anchors | The newest 20 anchors are listed, with the total count. |
| SCIM subject-set proposal | 1–1,000 subjects with unique ids. |
| SCIM list count | At most 200. |
| SCIM PATCH | At most 100 operations. |
| SIEM batch | Default 100 rows, configurable 1–1,000. |
| SIEM interval | Default 30 seconds, configurable 1–86,400. |
| SIEM and break-glass webhook attempts | Up to 5 attempts, each with a 10-second timeout and exponential backoff. |
| Readiness cache | 5 seconds of real time. PostgreSQL readiness can reuse a recheck up to 60 seconds old. In cluster mode, freshness is read on every probe. |
| Cluster staleness bound | `GATE_MAX_STALENESS_MS`, default 2,000 ms, allowed 100–60,000. Past it the node answers decisions with 503 and fails `/readyz`. |
| Node id | `GATE_NODE_ID`, 1–64 characters from letters, digits, `_`, `.`, and `-`, starting with a letter or digit. Default `0`. |
| PostgreSQL audit recheck | Periodic default every 300 seconds; `/audit/verify` shares a recheck at most once per 60 seconds. |
| Trace children | At most 100 child spans per request; the remainder is counted as dropped. |
| Trace export queue and batch | 2,048 queued spans; export batches up to 512 every 5 seconds or when full, with a 10-second request timeout. |

Sources: `packages/pdp-http/src/admin/audit.ts`, `packages/pdp-http/src/siem.ts`, `packages/pdp-http/src/admin/changes.ts`, `packages/pdp-http/src/admin/privacy.ts`, `packages/pdp-http/src/admin/evidence.ts`, `packages/pdp-http/src/scim.ts`, `packages/pdp-http/src/notify.ts`, `packages/pdp-http/src/metrics.ts`, `packages/pdp-http/src/tracing.ts`, `packages/pdp-http/src/postgres.ts`, `packages/pdp-http/src/postgres-chains.ts`.

## SDK and gateway limits

| Limit | Value and behavior |
|---|---|
| SDK request timeout | Default 10,000 ms; must be positive and finite. |
| SDK record depth | JSON cloning and validation reject nesting beyond 100, cycles, sparse arrays, non-finite numbers, symbols, and non-plain objects. |
| Gateway request body | Default 1,048,576 bytes; configurable positive `maxBodyBytes`. Excess returns 413 and closes the connection. |
| Gateway response body | Default 8,388,608 bytes; configurable positive `maxResponseBytes`. Excess returns 502 `upstream_too_large`. |
| Gateway upstream deadline | Default 10,000 ms for the complete exchange, configurable positive `upstreamTimeoutMs`. |
| Gateway list | At most 1,000 items, each with a non-empty string id. One batch evaluation covers the list. |
| Gateway route id | Decoded id at most 256 characters; separators, controls, `.` and `..` are refused. |
| Gateway server timeouts | 30-second request timeout and 10-second headers timeout. |
| Assertion middleware body | `withGateAssertion` reads at most 1,048,576 bytes by default; configurable `maxBodyBytes`. |

Sources: `packages/sdk/src/client.ts`, `packages/sdk/src/enforce.ts`, `packages/sdk/src/validation.ts`, `packages/sdk/src/assertion.ts`, `packages/gateway/src/gateway.ts`, `packages/gateway/src/routes.ts`.

## Related pages

- [Resolve rate and validation errors](error-codes.md)
- [Integrate batches, filters, and the gateway](../guides/integrator.md)
- [Operate readiness and export jobs](../guides/operator.md)
- [Understand bounded impact](../concepts/governance-and-audit.md)
