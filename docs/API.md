# API contract (MVP)

Status: **contract for the MVP build (2026-11-08).** Details the API table of [ARCHITECTURE.md](ARCHITECTURE.md) §4.
The PDP server (`packages/pdp-http`) implements it; the admin console (`apps/admin`) consumes it. Engine semantics:
`packages/core` (`evaluate`, `buildFilter`, `simulate`). Default listen address `127.0.0.1:8787`. JSON everywhere,
UTF-8, request bodies ≤ 1 MB. XACML-speaking PEPs use the JSON Profile of XACML 3.0 (§2.1).

The console localises stable error codes and UI text in English, French and Arabic; API field names, rule codes,
identifiers and signed payloads keep their canonical wire form. Language choice is local to the browser, not an API
translation parameter. Arabic uses RTL layout with isolated LTR codes and numbers; native Arabic review is required
before customer use. Automated browser coverage and its verification limits are in [ACCESSIBILITY.md](ACCESSIBILITY.md).

## 0. Common rules

With `GATE_TENANTS_FILE`, every route (including health, readiness, metrics, console, SCIM and the replica feed)
requires exactly one `X-Qadamar-Tenant: <id>` header. Ids match `[a-z][a-z0-9-]{0,62}`. Missing, malformed or repeated
headers return 400 `tenant_required`. A valid id outside `GATE_SERVE_TENANTS` returns 421 `tenant_not_served`,
with a message asking the load balancer to route to its partition. It is a routing refusal, never an authorization
result or fallback to another tenant. These ingress refusals have no tenant audit chain; observe them at the edge.
A selected runtime starting up returns 503. Health and readiness otherwise describe the named tenant.

The header selects an isolated credential namespace; it does not authenticate a caller. PEP credentials, sessions,
policy keys and decision tokens remain tenant-specific. The replica feed carries the header on its own requests;
existing forwarding preserves it. Cluster buckets and audit ingestion use the named tenant’s database. Replica rate
limits retain their existing local-share semantics, separately per served tenant. Without a manifest, the existing
single-tenant API is unchanged. Browser deployments need a trusted edge to inject the tenant from distinct tenant
hostnames; configure each tenant’s `publicOrigin` for cookies and SSO ([DEPLOY.md](DEPLOY.md#tenant-partitions)).

- **Errors**: `{ "error": "<code>", "message": "<human text>", "details"?: [...] }` with codes
  `bad_request` 400, `unauthenticated` 401, `forbidden` 403, `not_found` 404, `conflict` 409, `payload_too_large` 413,
  `unsupported_media_type` 415, `unprocessable` 422, `rate_limited` 429 (with `Retry-After`), `internal` 500 (no stack,
  no internals), `unavailable` 503. A body over 1 MB returns 413 with this envelope and `Connection: close`: the server
  stops buffering, drains without retaining the excess, and closes cleanly after the response. Decision-plane, registration
  and applicable admin/session refusals use the same audit paths as other refusals.
- **Identity is resolved by the PDP.** A caller names a subject and a resource by `type` + `id`; clearance,
  compartments, roles, integrity and relations always come from the PDP's own store. Client-supplied attributes are
  ignored (an unknown id is denied, never trusted).
- **Delegation**: a subject whose `attrs.delegatedBy` names a person is evaluated with that person as `delegator`.
- **Hidden means absent**: on the end-user PDP API, a resource the subject may not read (any denied read, whatever
  action is explained) is reported by `/x/v1/explain` as the same 404 as a missing record.
- **Rate limits**: per IP and per principal, token bucket, shared cluster-wide in `GATE_CLUSTER` mode through leased
  PostgreSQL capacity (§3.9.1); login 5 per minute per username + IP. Sign-in throttle,
  on real elapsed time (never a pinned `CLOCK`): 5 failures from one client address on one account lock that pair
  progressively (1, 2, 4 … minutes, max 1 hour). Failures from every address also count per account, with the same
  progressive delay, but that delay holds back only a client that has itself failed on the account: a client that
  never failed still signs in with the right password (and second factor). Trade-off: nobody can lock an owner out by
  spraying failures from elsewhere (CWE-307), at the price of one guess per fresh address while the account delay
  runs; the production profile's MFA (OIDC with MFA, or TOTP) is what makes such guesses useless. Wrong second factors
  after a correct password are the exception: five of them, from any addresses, lock that account's sign-in for every
  client with the same progressive delay (a correct sign-in clears that counter). The failure that
  starts or extends a lock is audited with `details.lockedSeconds`; a `429` itself writes no row.
- **Audit**: every decision, login, change, approval and break-glass event appends one record to the hash chain
  (§3.9). Metadata only: ids, rule ids, policy version. Never passwords, tokens, session ids or resource content.
  Every string in a row is bounded: one over 512 characters keeps its first 128, then
  `…[truncated <n> chars, sha256:<hex of the full value>]`; a row still over 16 KiB keeps its identity fields and
  replaces `rules` and `details` by `{ truncated: true, bytes, sha256 }`. Callers (an unknown sign-in name, a refused
  route, an XACML attribute id) cannot grow the log without bound.
- **Condition language** (ABAC `when`, content-attribute `unless`, IVP `check`): three-valued like SQL. A comparison is UNKNOWN
  when an operand is missing or JSON `null`, **or when the operands have the wrong type**: `lt`/`le`/`gt`/`ge` need two
  numbers or two strings; `in` needs an array on the right; `contains` needs an array on the left, or two strings;
  `subset` needs two arrays. So `resource.attrs.amount ge 10000` is UNKNOWN for `"50000"`, `[50000]` or `{}`, not
  FALSE. `eq` and `ne` are defined across types (structural JSON equality: `"1"` is not `1`), and so are the element
  tests inside an array (`1 in ["1"]` is FALSE). A `permit` or an exemption needs TRUE; a `forbid` or an obligation
  fires on TRUE or UNKNOWN; a list filter keeps a row only on TRUE. A mistyped attribute therefore never grants and
  never escapes a forbid.
- **Server time**: the `Date` response header follows the server clock (including a pinned demo clock), so clients
  compute countdowns on server time.
- **Security headers** on every response: `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on API routes.
  No CORS: the console is served from the same origin (or through the dev proxy).

## 1. Principals

| Principal | How it authenticates | Uses |
|---|---|---|
| **PEP service** (an application) | `Authorization: Bearer <api key>` from a named PEP credential (§3.10); keys stored as a salted HMAC-SHA256 (random secrets, §3.10) | §2 PDP API, §2.1 XACML |
| **Administrator** (console) | `POST /admin/v1/session` with username + password (scrypt N=2^16, r=8, p=2, ≥ 12 chars), then an `HttpOnly; SameSite=Strict` cookie `sid` plus header `X-CSRF-Token` on every mutating call. Idle timeout 15 min, absolute 8 h. | §3 Admin API |

Demo administrators (fictitious) and their console roles. Passwords and the PEP key are generated at first start,
stored hashed under `data/runtime/` (git-ignored) and the clear values written once to
`data/runtime/INITIAL-CREDENTIALS.txt` (mode 600). That file is deleted at the first successful sign-in of any account
(password or SSO) or `INITIAL_CREDENTIALS_TTL_SECONDS` (default 3600, at most 86400) after it was written, whichever
comes first; a restart does not extend it. The startup log says when it will go and when it went, never its content.

**Resource-owner scope.** A console user whose only role is `resource_owner` sees and acts only on resources whose
`owner` equals its authenticated id (the password account name, or with OIDC the `OIDC_ID_CLAIM` value), plus the
owner ids mapped to that id in `RESOURCE_OWNERS`, a JSON object set by configuration (not by an IdP claim), e.g.
`RESOURCE_OWNERS='{"ruth":["carol"],"j.doe@corp":["finance-desk"]}'`. Values are arrays of owner ids; anything else
stops the server at start. The scope applies to every admin route: resource, tuple and subject lists, explain, the
simulator (what-can, who-can, matrix, impact), change proposals and the change list with its impact rows, access
reviews, and the overview counts (pending changes, break-glass, expiring grants, audit rows, decisions). Out-of-scope
ids answer `404`, as if absent; the unscoped audit, break-glass and compliance lists stay closed to owners (`403`).
Copy the values before then:

| Username | Console roles |
|---|---|
| `amira` | `access_admin`, `policy_author` |
| `omar` | `approver` |
| `lina` | `security_officer` |
| `ruth` | `resource_owner` (owner scope: resources whose `owner` is `ruth`, or an id `RESOURCE_OWNERS` maps to her; the demo maps her to `carol`) |
| `sam` | `auditor` |

Console role permissions:

| Capability | access_admin | policy_author | approver | security_officer | resource_owner | auditor |
|---|---|---|---|---|---|---|
| read overview, schema, policy, subjects, resources, tuples, resource inventory | yes | yes | yes | yes | own scope | yes |
| read retired resource ids | yes | yes | yes | yes | no | yes |
| simulator (what-can, who-can, explain) | yes | yes | yes | yes | own scope | no |
| propose a change | yes | policy only | no | yes | revoke in own scope | no |
| approve / reject a change (never one's own) | no | no | yes | yes | no | no |
| open break-glass | yes | no | no | yes | no | no |
| revoke / review break-glass (never one's own, nor one granting oneself access) | only when no other security officer exists (§3.6) | no | no | yes | no | no |
| access reviews: certify / revoke | no | no | no | yes | own scope | no |
| audit explorer, chain verify, compliance export, evidence packs, audit verification manifest | no | no | no | yes | no | yes |
| subject access report (personal data of one subject id) | no | no | no | yes | no | no |

## 2. PDP API (AuthZEN Authorization API 1.0 + extensions)

### 2.0 Health, readiness and metrics

- `GET /healthz` (no auth) → `200 { "status": "ok" }` whenever the HTTP process can answer. It does not check the store or audit.
- `GET /readyz` (no auth) → `200 { "status": "ready", "active": true, "audit": { "verified": true } }` (with PostgreSQL `audit` adds `fullChain`, false while the background verification after a start from the checkpoint runs, §3.9.1) only after pending state is committed and the audit chain verifies; otherwise `503 { "status": "unavailable" }` (the cause is logged, never returned). The result (ready or not) is cached for 5 s of real time, so a probe flood runs at most one commit and verification per 5 s. With files the whole chain is reread at each check. With PostgreSQL the check reuses the shared database recheck, so the store and chain results may be up to 60 s old (at most one full scan per minute, whatever the probe rate); a lost writer connection stops the node at its next write or keepalive failure. A standby waits for the advisory lock before opening its port, so a responding node is the active one. Health and readiness are public and reveal no identifiers.
- `GET /metrics` → Prometheus text format (`text/plain; version=0.0.4; charset=utf-8`). Without `METRICS_TOKEN` it is open only while the node listens on a loopback address; on any other address it answers 403 (`DEMO_ALLOW_REMOTE` demos included). Set `METRICS_TOKEN` to a non-empty secret (an empty value counts as unset) to require `Authorization: Bearer <secret>`; a missing or wrong token returns 401. Health and readiness remain public. Do not put the token in URLs or labels.

Metrics are `gate_decisions_total{effect="allow|deny"}`, `gate_http_request_duration_seconds` (histogram with a fixed `route` family label), `gate_audit_length` (head sequence, not a fresh verification), `gate_audit_last_anchor_age_seconds` (`-1` when there is no anchor), `gate_commit_duration_seconds` (histogram), `gate_active_node` (`1` on the only node with a listening port), and `gate_break_glass_notices_total{outcome="sent|failed"}` (§3.6.1). No metric label contains a subject, resource, principal, IP address, secret or raw request path. File storage has no asynchronous commit, so its commit count stays zero. Request observations are process-local and reset on restart or failover.

#### 2.0.1 Traces (OpenTelemetry, OTLP/HTTP JSON)

Built in, no SDK or dependency (`packages/pdp-http/src/tracing.ts`). Off unless configured:

| Variable | Effect |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector base URL, e.g. `http://127.0.0.1:4318`. Spans are posted to `<endpoint>/v1/traces` as OTLP/HTTP JSON (`Content-Type: application/json`). http or https (`GATE_PROFILE=production`: https, or plain http on loopback only); a URL with credentials, a query string or a fragment is refused at start. Unset: no tracing. |
| `OTEL_SERVICE_NAME` | The `service.name` resource attribute (default `gate-pdp`). |

- **Spans.** One `SERVER` span per HTTP request, named `<METHOD> <route family>` (the families of `gate_http_request_duration_seconds`), with `http.request.method` (`_OTHER` for a non-standard method), `http.response.status_code`, `gate.route_family`, and status `ERROR` on a 5xx. Child `INTERNAL` spans: `gate.decision` for every decision evaluated in the request, with `gate.decision.effect` (`allow`/`deny`) and `gate.decision.rules` (the rule ids of its audit row); `gate.commit` for every database commit (PostgreSQL only; status `ERROR` when it fails). At most 100 child spans per request (a batch or search can decide thousands); the rest are counted in `gate.dropped_child_spans` on the request span.
- **Nothing else is recorded**: no subject, resource or action, no id, path, IP address, header, PEP key, token, session id or error message. Times are real wall-clock time, never a pinned `CLOCK`.
- **Propagation.** A valid W3C `traceparent` header (Trace Context level 1: lowercase hex, version not `ff`, non-zero ids, nothing appended to version `00`) makes the request span a child of the caller's span in the same trace. Its sampled flag is honoured: `-00` records nothing for that request (parent-based sampling). An absent or invalid header starts a new trace, always sampled. `tracestate` is ignored, and nothing is propagated outbound (the request path calls no other service).
- **Export never blocks or fails a request.** Spans enter an in-memory queue of 2048; a full queue drops new spans. Batches of up to 512 leave every 5 s, or as soon as a batch is full, one request at a time, with a 10 s timeout and redirects refused. A 2xx delivers the batch; `429`, `502`, `503`, `504`, a network error or a timeout keeps it at the head of the queue and starts a backoff (1 s, doubling to 60 s) during which nothing is sent; any other status drops that batch (OTLP/HTTP: not retryable). Shutdown makes one last attempt.
- **Not supported**: `OTEL_EXPORTER_OTLP_HEADERS` (no authentication header towards the collector: run a local collector or sidecar that forwards with its own credentials), `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`, protobuf and gRPC transports, sampler configuration, OTLP metrics and logs (metrics stay on `/metrics`), span events and links. The dropped-span count is not exported as a metric.

#### 2.0.2 Decision assertions for the backend

The enforcing gateway (§5) forwards each request with a `gate-assertion` header: a compact JWS signed by the **PDP**,
so the gateway (or any PEP) never holds a private key and gets no assertion for a deny. A backend checks it with the
SDK's `AssertionVerifier` / `withGateAssertion` (`packages/sdk/src/assertion.ts`, example `example-backend.ts`).

- `POST /x/v1/assertions/evaluation` (PEP credential) — an evaluation request plus
  `request: { audience, method, path, bodySha256 }` (the backend origin, `A-Z` method, path with the forwarded query,
  base64url SHA-256 of the forwarded body) → the `/access/v1/evaluation` answer, plus `assertion` on allow only. Same
  engine, decision token, rate limit and audit row; the row carries `details: { decisionId }`.
- `POST /x/v1/assertions/list` — `{ subject, action, resource: { type }, context?, request }` →
  `{ decision, policy_version, assertion? }`. `decision` is true when the list residual (`/x/v1/filter`) is not FALSE:
  the subject may act on some item of the type; the PEP still decides every item. Audited as a `decision` with rule
  `GATE.LIST_ASSERTION` or `GATE.LIST_NONE` and `details: { decisionId, listOf }`.
- A malformed `request` → 400. Header `{ alg: "EdDSA", typ: "gate-assertion+jwt", kid }` (the decision-token keyring,
  §3.10; the `typ` keeps it from passing as a decision token, and a decision token from passing as an assertion).
  Claims: `sub {type,id}`, `act`, `res {type, id?}`, `did` (decision id), `pv`, `aud`, `htm`, `htp`, `bsh`, `iat`,
  `exp = iat + 30`, `nonce` (128 random bits).
- **Verifier** (backend): the key by `kid` from `GET /.well-known/jwks.json` (cached `jwksCacheSeconds`, 300 s by
  default; an unknown `kid` refetches at most every 10 s, so a rotation is picked up and a flood of bogus kids costs
  one fetch per 10 s; a key dropped from the JWKS stops verifying at the next refresh; a JWKS that cannot be fetched
  when needed → 503, never the stale keys); exact header and claim sets; signature; `iat` not later than now + skew,
  `exp` later than now − skew (`clockSkewSeconds`, 5 by default, at most 60); `aud`, `htm`, `htp` (the raw request
  target) and `bsh` equal to this request; the nonce unseen, then remembered until `exp` + skew (in the `replayStore`).
  Failures answer 401 `{ error }` with `assertion_missing`, `assertion_invalid`, `assertion_expired`,
  `assertion_mismatch`, `assertion_replayed` or `assertion_key_unknown`, or 503 `replay_store_unavailable` when the
  replay store throws; the handler never runs.
- **Replay store (several replicas).** By default spent nonces are remembered in the process (`MemoryReplayStore`):
  a backend that runs several processes or replicas accepts the same assertion once **per process** within its 30 s
  life. Such a backend must pass one shared `replayStore` to every verifier: an object with
  `spend(nonce, expiresAt)` that performs an atomic check-and-set and returns `true` the first time, `false` when the
  nonce was already spent (`expiresAt` is in seconds since the epoch: when it may be forgotten). The SDK ships no
  client for it (no dependency); two short implementations:

  ```ts
  // Redis (any client with SET NX PX): the key exists only for the assertion's remaining life
  const replayStore: ReplayStore = { spend: async (nonce, expiresAt) =>
    (await redis.set(`gate:nonce:${nonce}`, '1', { NX: true, PX: Math.max(1000, expiresAt * 1000 - Date.now()) })) === 'OK' };
  // PostgreSQL (node-postgres): CREATE TABLE gate_nonce (nonce text PRIMARY KEY, expires_at timestamptz NOT NULL);
  // remove rows whose expires_at has passed from time to time
  const replayStore: ReplayStore = { spend: async (nonce, expiresAt) =>
    (await pool.query('INSERT INTO gate_nonce VALUES ($1, to_timestamp($2)) ON CONFLICT DO NOTHING', [nonce, expiresAt])).rowCount === 1 };
  new AssertionVerifier({ jwksUrl, audience, replayStore });
  ```

  A store that throws fails the request closed (503), never open. The runnable
  [PostgreSQL reference](../examples/integration-safety/postgres-replay.ts) namespaces nonces by backend audience,
  reclaims expired entries atomically, and is tested with two database connections and independent verifiers.
  See [integration safety](handbook/guides/integration-safety.md) for setup and SQL filtering followed by per-row enforcement.
- **Limits.** The PDP signs the method, path and body digest the PEP reports: the
  assertion proves the decision and that the request came through a credentialed PEP, not that a compromised PEP
  forwarded the body it described.

`GET /.well-known/authzen-configuration` (no auth) →
`{ "policy_decision_point": "<base url>", "access_evaluation_endpoint": ".../access/v1/evaluation", "access_evaluations_endpoint": "...", "search_subject_endpoint": "...", "search_resource_endpoint": "...", "search_action_endpoint": "..." }`

`POST /access/v1/evaluation`
```json
{ "subject": { "type": "user", "id": "bob" }, "action": { "name": "read" },
  "resource": { "type": "case", "id": "CASE-14" },
  "context": { "network": "trusted", "sessionLevel": 2, "makerId": "grace", "priorActions": [] } }
```
→ `{ "decision": true, "context": { "rules": [...], "reasons": [...], "obligations": {...}, "policy_version": "pv.…", "would_deny": [...], "decision_token"?: "<JWS>" } }`
`context.network` defaults to `untrusted` when absent (fail closed). `decision_token` is present when the engine
returns a `decisionToken` obligation (Clark-Wilson certified command): an Ed25519 JWS (`alg: EdDSA`, `kid` naming its key in `/.well-known/jwks.json`, §3.10) with claims
`{ sub, act, res, ver, pv, jti, iat, exp, sid?, bsid? }`, single use (`sid`: the mark scope; `bsid`: the issuing PDP session, below).
`context.input` (optional, a JSON object): the input of a certified command, checked by the `clarkWilson.inputValidators`
of §3.12 (C5); the gateway sends the request body on `postState: 'body'` routes.

**CBAC signals (context-based, Zero Trust).** Optional `context.ip` (IPv4/IPv6 literal, no `%` zone id), `country` (assigned ISO
3166-1 alpha-2, upper case), `device` (`{ managed: boolean, compliant: boolean }`, no other keys), `authTime` and
`mfaTime` (ISO-8601 instants), `authMethods` (at most 16 names matching `[A-Za-z0-9_.-]{1,32}`), and integer
`riskScore` 0..100 are validated at the HTTP boundary; malformed values return 400 `bad_request`. Existing `network`,
`now` and session fields are unchanged. The bundle's optional `context` rule list and all requirement/reason codes are
specified in [spec/POLICY-LANGUAGE.md](spec/POLICY-LANGUAGE.md) §3.7: network, country, CIDR, local time window, device,
MFA/authentication freshness, method and risk. Every matched requirement is checked on every request; a missing signal
is UNKNOWN and denies (`CBAC.SIGNAL_MISSING`). Other denials include `CBAC.NETWORK`, `CBAC.COUNTRY`, `CBAC.IP_RANGE`,
`CBAC.TIME_WINDOW`, `CBAC.DEVICE_UNMANAGED`, `CBAC.DEVICE_NONCOMPLIANT`, `CBAC.MFA_STALE`, `CBAC.AUTH_STALE`,
`CBAC.AUTH_METHOD`, `CBAC.RISK` and `CBAC.SESSION_EXPIRED`. Explain trace entries (stage `cbac`) name the policy rule,
requirement and observed value.

**CBAC grant duration and session expiry.** A role assignment (`roleAssignments: [{ role, notBefore?, notAfter? }]` on
the subject, adding to its unconditional `roles`) and a relation tuple (`notBefore` / `notAfter`; legacy
`validFrom` / `validTo` are read as the same window, `notBefore` / `notAfter` win when both are present) exist only
within their window, both bounds inclusive, evaluated against `context.now`. Outside it the grant does not exist for that
request: the explain trace shows a `cbac` step with outcome `skip` and rule `CBAC.GRANT_EXPIRED` or `CBAC.GRANT_NOT_YET`
(`policyRule` the role, or `NTK.<relation>` for a direct relation grant; `requirement` `roleAssignment` or
`relationTuple`); it is informational, and the decision is whatever the remaining grants give. With a
legacy `context.sessionId`, the PDP sets `context.sessionExpired: true` when that session's mark has passed its idle
(15 min) or absolute (8 h) expiry (below). A `context.sessionToken` is checked itself instead: an expired, idle or closed
token is refused with 403 `invalid_session_token` before any decision and never touches the shared mark, and a lapsed
shared mark is not an expired session (every token of the subject shares it). An authenticated PEP may also assert
`context.sessionExpired: true` itself (a `false` from the caller changes nothing). An expired session denies with `CBAC.SESSION_EXPIRED` (stage `cbac`), and its filter/SQL
residual is FALSE. The expiry sticks: the expired mark stays as a tombstone until 8 h 15 min after the session's first
mark (absolute expiry plus a 15-minute grace), every node loads it before deciding (PostgreSQL), and no node writes a
fresh mark under that id meanwhile; after it, the id starts clean.

**Content attributes are ABAC.** Content rules (bundle field `abacContent`) mask, redact or deny by the resource's
content classes; they run inside the `abac` trace stage, their steps carry `kind: "content"` and `policyRule: <rule id>`,
and their codes are `ABAC.CONTENT_DENY`, `ABAC.CONTENT_MASK` and `ABAC.CONTENT_REDACT` (the rule id is in the step's
`policyRule`, not in the code). Obligations (`maskClasses`, `redact`) are unchanged.

These signals are **asserted by the authenticated PEP**, within its credential scope. Without the optional attestation
hook the PDP validates shape and bounds but cannot verify actual device compliance, MFA, location or the IdP's risk
computation. Decisions are not cached across contexts; resource and
subject/action search, list assertions and SQL filters apply the same request-level requirements as point decisions.
See [spec/POLICY-LANGUAGE.md](spec/POLICY-LANGUAGE.md) §7 for signal limits and §6 for pipeline order.

**PEP credential claim scopes and attestations.** The protected signal names are `network`, `ip`, `country`, `device`,
`authTime`, `mfaTime`, `authMethods`, `riskScore` and `sessionLevel`. A credential's `contextScopes` (§3.10) lists exactly
which of them it may assert. An assertion outside that list, a `network` outside the scope's optional `networks` list, or a
`country` outside its optional `countries` list returns 403 `context_claim_forbidden` with the signal and reason, audited
as a decision-plane refusal. It is never silently removed. This check covers point and batch evaluations, searches,
filters, decision/list assertions and XACML's mapped environment attributes. An absent signal is still absent and a CBAC
rule that requires it denies as before.

For one compatibility version, a credential created before `contextScopes` (including `bootstrap`) keeps its old behaviour
in the **demo** profile. The first such assertion per credential logs a warning and the response carries `Deprecation:
true` and a `Warning` header. Production is fail closed: creation requires `contextScopes` (use `[]` for no assertions),
and an older unscoped credential gets the empty scope, so every protected assertion is refused. Rotation preserves scopes;
changing them requires a new credential. `sessionToken`, `sessionExpired`, `makerId`, `priorActions` and `input` are not
context-claim scopes: their separate binding, narrowing and server-history rules continue to apply.

A scope may additionally require a signed attestation for its signal. Configure `attestation: { audience, keys }` on that
scope, with 1..8 public keys `{ kid, alg: "EdDSA" | "ES256", jwk }` (Ed25519 or P-256 respectively; private JWK fields are
refused). Send the compact JWS as `context.attestations.<signal>`. A missing, malformed, wrongly signed, expired, unknown-
key or mismatched attestation returns 403 `invalid_context_attestation`, audited without copying the JWS. Supplying an
attestation without its signal, for an unscoped signal, or where no attester is configured is also refused.

The JWS has exactly header `{ alg, kid, typ: "gate-context-attestation+jwt" }` and claims:

```json
{ "iss": "<attester kid>", "aud": "<configured audience>", "pep": "<PEP credential id>",
  "sub": ["user", "carol"], "sid": "<PDP session UUID when context.sessionToken is used>",
  "src": "device-1", "signal": "device", "value": { "id": "device-1", "managed": true, "compliant": true },
  "jti": "<unique id>", "iat": 1794131999, "exp": 1794132059 }
```

`iss` and `kid` agree; signature verification uses only the configured key with that id and algorithm. `pep`, `aud`,
`signal` and `value` must equal this credential, audience and exact asserted value (Qadamar canonical JSON for `value`).
`sub` is required and must equal the request subject's `[type, id]`. `sid` is required exactly when the request carries
`context.sessionToken`, and must equal that token's verified session UUID; it is absent otherwise. Device and network
attestations also require `src`, respectively equal to `context.device.id` and `context.networkSensorId` (1..128 printable
ASCII characters); those request fields are source metadata only and are not passed to the decision core. Other signals
must not carry `src`. All comparisons use constant-time byte equality. `jti` is 1..128 printable id characters. `iat` may
be at most 30 seconds in the future, `exp` must be in the future, and `exp - iat` must be 1..300 seconds. An attestation
can be reused only for the same subject, session and source until expiry, never across users, PDP sessions, devices or
sensors. MFA evidence is bound to that same session rather than accepted as a fresh authentication for an arbitrary one.
**Accepted limit: attestations are not single use.** `jti` is format-checked and never remembered, by any node, so one
attestation authorizes any number of decisions (a batch, a search, several requests) for the same credential, subject,
session, source and value until `exp`, at most 300 seconds. A step-up meant for one action therefore holds for its
whole lifetime: an attester that needs near one-shot evidence issues a short `exp`.
The TypeScript and Python SDK context types expose `attestations`, `device.id` and `networkSensorId`; the gateway's
`attestContext(context, req)` hook receives the resolved socket IP/network and returns the map to send.

**PDP-issued sessions and the high-water mark (Bell-LaPadula \*-property across requests).** Open a working session
with the authenticated PEP credential; the PDP, never the PEP, chooses its id:

`POST /x/v1/sessions`
```json
{ "subject": { "type": "user", "id": "carol" } }
```
→ 201
```json
{ "token": "<JWS>", "sessionId": "<PDP-chosen UUID>", "issuedAt": "2026-11-08T10:00:00.000Z",
  "expiresAt": "2026-11-08T11:00:00.000Z", "idleSeconds": 900 }
```

The compact JWS uses `alg: EdDSA`, `typ: gate-blp-session+jwt` and the existing keyring (`kid` in
`/.well-known/jwks.json`). Claims are `{ sid, sub, pep, iat, exp, idle }`: the PDP-chosen session id, JSON
`[subject.type, subject.id]`, PEP credential id, issue/expiry seconds (one hour apart), and a 15-minute idle bound in
seconds. The registry keeps last use on the real clock, so a pinned `CLOCK` cannot keep an idle token alive. Signing-key
rotation gives the old key separate acceptance windows: 300 seconds for decision tokens, backend assertions, policy and
introduction signatures, and `sessionVerifyUntil` (one hour) only for this token type. Public keys then leave the live
JWKS but remain in the stored keyring with their `introducedBy` chain, so archived `gate-evidence-manifest/1` packs
still verify offline; that indefinite evidence rule never applies to online policy or token acceptance.
`POST /x/v1/sessions/close` with
`{ "token": "<JWS>" }` closes it and returns `{ "ok": true }`; later decisions with it fail, and so does the
consumption of any decision token issued in it (below). Creation and close are
audited without the token. Creation has a per-credential token bucket (`BLP_SESSION_CREATION_PER_MINUTE`, default 60,
429 with `Retry-After`), a concurrent-open cap per (credential, subject) (`BLP_SESSIONS_PER_SUBJECT`, default 4,
409 `session_limit`) and one per credential over all its subjects (`BLP_SESSIONS_PER_CREDENTIAL`, default 10,000,
409 `session_limit`, audited `credential_session_cap`), both cluster-wide with PostgreSQL. `subject.type` and
`subject.id` take the bounds of a decision request (1..256 characters each, else 400), so every token issued fits the
4,096-character `context.sessionToken` limit; a token that would not is refused, never issued. File mode stores the registry in `DATA_DIR/blp-sessions.json`; PostgreSQL uses `gate_blp_session`.
A stateless replica forwards open, close and token-bearing decisions to a database node.

**Immediate administrative revocation.** A security officer calls `POST /admin/v1/blp-sessions/revoke` with exactly one
selector: `{ sessionId }`, `{ credential }`, or `{ subject: { type, id } }` (optionally with `credential` to narrow the
subject). It returns 200 `{ revoked, sessionIds }` (the first 100 ids), is idempotent (`revoked: 0` when nothing live
matches), and appends an audited `blp_session_revoke` event without a bearer token. Invalid or combined selectors return
400. `GET /admin/v1/blp-sessions/revocations` (access admin or security officer) lists the tombstones
`{ sid, sub, pep, revokedAt }`.

Revocation deletes the live `gate_blp_session` rows and writes their tombstones in the same PostgreSQL transaction as the
audit row and shared `blp_revocations` document; file mode uses `DATA_DIR/blp-revocations.json`. It takes the same token
locks as decisions, so a decision already in flight finishes before revocation and a later one sees no live row on any
cluster node without waiting for document reload. Candidate session UUIDs and selector scopes are acquired in one sorted
order and candidates are revalidated after locking; a changed candidate set or SQLSTATE `40P01` retries the transaction
up to three times before any audit/document batch is drained, rather than latching a healthy node. Session tokens then
fail with 403 `invalid_session_token`, and every
unconsumed decision token carrying their `bsid` fails consumption with 409. The signed replica feed carries the same
tombstones. They are retained for two hours after revocation (longer than the one-hour token life and five-minute maximum
decision-token life), bounded at 100,000 entries; the independent audit event is the longer-term evidence. Revoking a
selector does not prevent a PEP from opening a genuinely new session afterwards; revoke the PEP credential itself when it
is compromised.

Send the token as `context.sessionToken` on decisions. The PDP verifies its signature and type, exact subject and
credential bindings, issue/expiry, idle last use, and that its session is still open; a forged, expired, closed,
foreign-subject or foreign-credential token gets 403 `invalid_session_token`, also audited. `context.sessionId` is a
deprecated compatibility mode outside production and logs a warning once per node. Production requires
`BLP_SESSION_REQUIRED=true`, refuses a raw id with 400 `session_token_required`, and accepts only these tokens. Sending
both forms is a 400 everywhere. The token itself is never logged or stored; its claims are.

The mark is per (PEP credential, subject), shared by every open token of that pair. This is deliberate: a cap of one
would only limit concurrency, while the shared mark also stops a PEP from laundering a read through a new token.
Closing a token does **not** clear the mark, since close/reopen would be the same bypass. A genuinely new working
session starts clean only after the old mark lapses.

- **Raised by permitted point reads only.** A `read`-kind action on a resource above L0 that is permitted by
  `/access/v1/evaluation`, `/access/v1/evaluations`, `/x/v1/assertions/evaluation` or XACML raises the mark before the
  permit is answered (with PostgreSQL, committed with it). A denied read, search, filter, explanation or list assertion
  never raises it. Batch entries are decided in order.
- **Never lowered.** The working level is `min(max(sessionLevel ?? clearance, mark), clearance)`. A write below
  `sessionLevel` stays `BLP.NO_WRITE_DOWN`; a write at or above it but below the mark is `BLP.HIGH_WATER`. Trusted roles
  remain exempt. Point decisions, batches, write searches and filters, explanations, XACML and decision-token
  consumption all apply the mark. A decision token's `sid` is this subject-and-credential mark scope.
- **Expires.** A mark lapses after 15 minutes without a decision in its scope, or 8 hours after its first mark, on the
  real clock. A session token itself expires after one hour or 15 minutes idle; close it when the working session ends.
  Last use is written at most once a minute, so idle expiry may come up to a minute early. A mark never lapses while an
  open token of its scope can still be used: opening a token and each recorded use hold the mark (`held_until` in
  `gate_blp_mark`, shared by every node) until that token's idle or absolute expiry, whichever is first, plus one
  minute; neither the sweep nor a reload drops a held mark, so a valid token never sees its floor reset.
- **Bounded.** At most 100,000 marks in memory and `BLP_SESSIONS_PER_PEP` (default 10,000) per credential, in addition
  to the open-token cap above. Without a database, exhausting a share returns `BLP.SESSION_LIMIT`; with PostgreSQL,
  memory is a cache. Raised marks reach `DATA_DIR/sessions.json` within one second (and at shutdown), or commit with
  the decision in `gate_blp_mark`.
- **Opt-in outside production, required in production.** Without a session nothing is tracked. With
  `BLP_SESSION_REQUIRED=true`, every read above L0 and every write by a subject cleared above L0 needs one
  (`BLP.SESSION_REQUIRED`). The requirement applies to PEP decisions, not console views. Production refuses to start
  without it. Deploy tokens at every PEP before enabling it.
- **Linearizable within one subject scope.** Mark-relevant decisions use local queues for the token sid and shared
  subject scope. PostgreSQL holds `pg_advisory_xact_lock(BLP_LOCK, hashtext(scope))` from token verification and mark
  reload through the mark and audit commit. Open/cap checks and close use the same locks, so revocation and cap checks
  cannot race a decision. Batches acquire all locks in sorted order; decision-token consumption takes its `sid` lock.
  Unrelated sessions proceed independently; no-session requests and L0 reads bypass this machinery. A lock wait beyond
  the 15 s statement timeout fails with 503.

**Server-derived separation of duty.** Successfully consuming a certified-action token reserves the action: its
subject, resource, action and time go into the PDP's persisted performed-action history at once. A reservation counts
while its outcome is pending (otherwise two makers racing each other would both pass the check) and once reported
`completed`; one reported `failed` stops counting (the command did not run). History recorded before reservations
(0.4.0) counts as completed. Every decision adds to `context.priorActions` all
recorded actions on that resource by the subject or anyone in its delegation chain; caller-supplied history can add
entries but cannot remove recorded ones. The subject of the first recorded certified action is the resource's maker.
That maker overrides an omitted `context.makerId`, and a contradictory caller-supplied `makerId` denies with
`SOD.MAKER_MISMATCH`. Without recorded history, what happens depends on `SOD_HISTORY`:

- `server` (default in every profile): for every action the bundle constrains (`requiresSecondPerson`, or listed in an
  `sod` rule) the caller's `makerId` and `priorActions` are ignored. Only the server-recorded history counts: with none
  for that resource, conflict rules see an empty history and the two-person rule denies with `SOD.MAKER_UNKNOWN`, so
  the first certified action on a resource must be one that does not require a second person (e.g. `create`). Other
  actions still receive the caller context. Impact analysis keeps evaluating the caller-maker variants, so in this mode
  it can over-report, never under-report.
- `caller` (explicit, warned compatibility opt-in for demos/tests): the caller-supplied `makerId` and `priorActions` are
  taken as given. A PEP that lies about the maker or omits history defeats the two-person and conflict rules for that resource.

Performed actions are indexed by resource for the lifetime of each immutable history array; a decision scans only that resource's actions, not the whole history, and preserves recorded order and delegation semantics.

`POST /access/v1/evaluations` → `{ "evaluations": [ {...same as one response...} ] }`; body
`{ subject?, action?, resource?, context?, evaluations: [ partial requests ], options?: { evaluations_semantic: "execute_all" | "deny_on_first_deny" | "permit_on_first_permit" } }`.

`POST /access/v1/search/resource` `{ subject, action, resource: { type }, context?, page?: { token?, limit? } }` →
`{ "results": [ { "type", "id" } ], "page": { "next_token": "" } }`

`POST /access/v1/search/subject` `{ subject: { type }, action, resource, context?, page?: { token?, limit? } }` → same shape with subjects.
It discloses who can access a resource, so it is a per-credential capability: a PEP credential created with
`allowSubjectSearch: false` gets `403 forbidden` here (§3.10, PEP credentials). Credentials default to `true` for
compatibility; `false` is recommended for every PEP that only enforces decisions, and the production profile
(`GATE_PROFILE=production`) refuses subject search to every credential. A session token is refused here (400); with a
legacy `context.sessionId` the search locks that session and loads every subject's mark and expiry tombstone in it
(PostgreSQL: as committed by any node) before deciding, so it lists exactly the subjects point decisions would allow.
`POST /access/v1/search/action` `{ subject, resource, context? }` → `{ "results": [ { "name": "read" } ] }`

Resource and subject searches visit surviving candidates in their stable stored order and stop once the requested page and one
allowed lookahead result are known. `next_token` is an opaque, validated position in the original stored array, not a count of
matches or a position in the survivor set; a malformed token is a 400. The lookahead is decided again when its page is requested.
Resource search evaluates the residual through cached type, label, known-relation and attribute-value indexes, including for
two-person and separation-of-duty actions. Subject search shares one relation-reachability traversal, then applies the candidate's
own eligibility and mandatory checks. These steps only prune: every survivor still gets the full point decision, including every
delegation link, history, certification and obligation stage. Action search decides each declared action of the type. Only decisions
actually made are audited: denied survivors decided on the way are included, pruned candidates and candidates beyond the stopping
point are not, and the allowed lookahead is decided without an audit row until its page is requested.

**External interop evidence.** `examples/authzen-todo` models the OpenID AuthZEN Todo users, roles and ownership rules.
`node --test packages/pdp-http/test/authzen-official.test.ts` starts this server and replays all 163 official decision
vectors over authenticated HTTP. The current run passes 163, skips 0 and fails 0; provenance, scope and rerun details are
in [AUTHZEN-CONFORMANCE.md](AUTHZEN-CONFORMANCE.md). This is vector replay evidence, not OpenID certification.

Extensions:

- `POST /x/v1/explain` (same body as evaluation) → the engine `Decision` (`decision, rules, reasons, obligations,
  trace[], wouldDeny, policyVersion`), or 404 under the hidden-means-absent rule.
- `POST /x/v1/filter` `{ subject, action, resource: { type }, context?, dialect?: "postgres", columns: { "resource.level": { "column": "level", "type": "number" }, ... } }`
  → `{ "residual": <Expr>, "sql": { "text": "…", "params": [...] } }` (`packages/sql`). Each answered call is
  audited as a `decision` with rule `GATE.FILTER` (effect allow) or `GATE.FILTER_NONE` (residual FALSE, effect deny) and
  `details: { listOf, residual: "true" | "false" | "conditional" }`; a refused request writes no row. A built-in field mapped with
  the wrong type (`resource.level` not `number`, `resource.compartments` or `resource.contentClasses` not `text[]`,
  the other built-ins not `text`) → 400: a mistyped column would compile to a constant. Tenant attributes must be
  declared with the type their data really has, or as `"type": "jsonb"` (a JSONB column whose JSON type may vary per
  row): each operator then tests `jsonb_typeof` and is SQL NULL when the type does not fit, exactly as the point
  decision (§0, condition language), so a forbid drops a mistyped row and a permit does not keep it. A JSONB value
  `null` counts as missing. A `jsonb` path compares with literals only (another column → 400). With typed columns, an
  ordering, `contains` or `subset` whose literal cannot match the declared type compiles to NULL (not FALSE), and
  `eq`/`ne` to FALSE/TRUE. Every text comparison (ordering, equality, `= ANY`, array containment, `strpos`, and the
  text of a JSONB string) carries `COLLATE "C"`, the condition language's code-point semantics: a linguistic or
  nondeterministic (case- or accent-insensitive) database or column collation does not change which rows are kept.
  A residual literal holding an unpaired surrogate → 400.
- `POST /x/v1/tokens/consume` `{ token, action, resource: { type, id }, resourceVersion, attrs? }` → `{ "ok": true, "reservation": "<id>" }` once;
  a reused, expired, mismatched or tampered token → 409 `conflict`. A decision token issued under a session token
  carries that BLP session's id (`bsid`): its consumption locks and reads the session row (on every node, PostgreSQL
  included) and is refused with 409 `conflict` ("the BLP session it was issued in is closed or expired") once the
  session is closed, past its absolute or idle expiry, or held by another subject or PEP credential; audited as a
  `decision` deny with rule `CBAC.SESSION_EXPIRED` and `details: { phase: "token_consume", session: "closed_or_expired" }`.
  The PDP re-decides on its current state, which
  includes the integrity verification procedures (IVP, §3.12) of a constrained item. `attrs` (optional, a JSON object)
  is the item's attributes as the certified command will commit them: merged over the stored attributes and checked
  by the same IVPs. A failing check → 409 `conflict`, audited as a `decision` deny with the `CW.IVP.<id>` rule ids and
  `details: { phase: "token_consume", state: "proposed" }`; the token is **not** consumed, so the PEP can retry with a
  valid state while it lives, and no reservation is recorded. When the item's type has IVPs, `attrs` is
  **required** (the decision token obligation then carries `postState: true`): without it → 409 `conflict`, audited
  with rule `CW.POST_STATE_REQUIRED` and `details: { phase: "token_consume", state: "missing" }`, token kept. A certified
  command can no longer commit a state nobody checked. The re-decision runs for the **consuming** PEP's credential
  binding (§3.12, E3) and takes `attrs` as the command's input (C5): with input validators declared, `attrs` is
  required too, and a failing validator → 409, audited with `CW.INPUT.<id>`, token kept.
  A consumption **reserves** the certified action: the PDP cannot know yet whether the command will run.
- `POST /x/v1/tokens/outcome` `{ reservation, outcome: "completed" | "failed" }` → `{ "ok": true, reservation, outcome }`:
  the PEP reports what became of a reserved action once its command ran. `completed`: the upstream did it (the gateway
  sends this for a 2xx answer); `failed`: it did not (any other answer, or a connection that was never made). Only the
  PEP credential that consumed the token may report (any other credential, or an unknown reservation → 404). Once per
  reservation, on any node: the same report again → the same 200 answer and nothing recorded; a different outcome →
  409 `conflict`, audited with rule `GATE.OUTCOME_CONFLICT`. A report is audited as a `decision` row on the reserved
  action's subject and resource with rule `GATE.ACTION_COMPLETED` or `GATE.ACTION_FAILED` and
  `details: { phase: "outcome", reservation, outcome, reservedAt }`. A PEP **unsure** whether the command ran (a timeout
  after the request left, a lost connection) must not report: the reservation stays pending.

  **A post-state is accepted only where a certified procedure may write it**, checked before the token is touched (the
  PEP may retry within the token's life): only for a `constrained` type (`400` otherwise), at most 64 attributes and
  8 KiB (`400`), and only keys the procedure's input validators declare or the type's IVPs read (`400` for another
  key). An attribute the policy reads (§2.2, attributes the policy reads) is accepted only when the procedure's input
  validators declare it (`403` otherwise): then the certified procedure, validated field by field, changes it; an IVP
  merely reading it does not make the procedure its author, and a compromised PEP could otherwise change a policy-read
  attribute alone through its post-state.

  **The PDP's copy follows the command (post-state).** A consumption that carried `attrs` (the post-state, required
  with `postState: true`) keeps them with the reservation, with the item version the token was bound to. Reported
  `completed`, the post-state is merged into the PDP's copy of the item's `attrs` and its version becomes **the bound
  version + 1** (one rule, whatever the PEP's own counter: the next token is bound to that), in the same transaction as
  the outcome row with PostgreSQL, audited in the outcome row as `details.postState: { applied: true, version }`.
  Reported `failed`, or still pending: nothing is applied. When the item is no longer at the bound version (it changed
  or was retired since), nothing is applied either: `details.postState: { applied: false, reason }`, and the post-state
  is listed for reconciliation by `GET /admin/v1/integrity/reservations` (`unappliedPostStates`, at most 1000, oldest
  dropped first) until a later command's post-state is applied to the same item. Since registration never changes an
  existing constrained item (§2.2), this is how its copy stays current. In a cluster such a completion writes the state
  document, so only the leader settles it: a follower forwards it over the signed hop, or answers `409 not_leader`;
  `failed` reports, and completions without a post-state, are still settled on any node.

**Clark-Wilson integrity at decision time.** A certified action on a constrained type is denied with
`CW.IVP.<id>` when an IVP of that type is not TRUE on the stored item (a missing value fails), so no decision token is
issued. `/x/v1/filter` adds the same predicate to the residual for such actions (map the attributes it reads in
`columns`). With no IVP declared, decisions are unchanged.

### 2.1 XACML 3.0 JSON Profile (`POST /xacml/v3/authorize`)

For enforcement points that speak XACML: requests and responses follow the OASIS *JSON Profile of XACML 3.0
Version 1.1*, and each individual request is translated to the AuthZEN evaluation of §2 and decided by it
(`packages/pdp-http/src/xacml.ts`). Same engine, same decision tokens, same audit row.

**Transport.** `POST` only (other methods 404). `Authorization: Bearer <PEP key>` exactly as for `/access` routes (§3.10;
401 otherwise, before the body is read). `Content-Type: application/xacml+json` or `application/json` (else 415), body
≤ 1 MB. Answer: `200`, `Content-Type: application/xacml+json; charset=utf-8`, body `{ "Response": [ Result, … ] }`.
A body that is not a JSON object is still a `200` with one `Indeterminate` (syntax-error) result. The per-IP and
per-PEP rate limits apply; a request costs one token per individual request, as `/access/v1/evaluations` does
(429 with `Retry-After`). If the store or the audit fails, the answer is a `500`, never a decision.

**Request mapping.** Categories may be given by shorthand (`AccessSubject`, `Resource`, `Action`, `Environment`) or in the
`Category` array with the full category URN or its shorthand (`access-subject`, `resource`, `action`, `environment`).
`DataType` may be omitted (inferred from the JSON value), a shorthand (`string`, `integer`, `anyURI`…) or the full URI.

| XACML category and attribute | Data type | Qadamar (AuthZEN) | |
|---|---|---|---|
| AccessSubject `urn:oasis:names:tc:xacml:1.0:subject:subject-id` | string or anyURI, one value | `subject.id` | required |
| AccessSubject `urn:qadamar:1.0:subject:subject-type` | string, one value | `subject.type` | default `user` |
| Resource `urn:oasis:names:tc:xacml:1.0:resource:resource-id` | string or anyURI, one value | `resource.id` | required |
| Resource `urn:qadamar:1.0:resource:resource-type` | string, one value | `resource.type` | required (XACML has no standard resource-type attribute) |
| Action `urn:oasis:names:tc:xacml:1.0:action:action-id` | string, one value | `action.name` | required |
| Environment `urn:qadamar:1.0:environment:network` | string `trusted` / `untrusted` | `context.network` | default `untrusted` |
| Environment `urn:qadamar:1.0:environment:network-sensor-id` | string, one value | `context.networkSensorId` | source identity required by a network attestation (§2) |
| Environment `urn:qadamar:1.0:environment:session-level` | integer 0..3 | `context.sessionLevel` | |
| Environment `urn:qadamar:1.0:environment:attestation:network` | string compact JWS, one value | `context.attestations.network` | required when the network scope configures an attester (§2) |
| Environment `urn:qadamar:1.0:environment:attestation:session-level` | string compact JWS, one value | `context.attestations.sessionLevel` | same for session level |
| Environment `urn:qadamar:1.0:environment:session-token` | string, one value | `context.sessionToken` | PDP-issued session and high-water mark (§2) |
| Environment `urn:qadamar:1.0:environment:session-id` | string, one value | `context.sessionId` | deprecated outside production; refused in production (§2) |
| Environment `urn:qadamar:1.0:environment:maker-id` | string or anyURI | `context.makerId` | ignored for SoD-constrained actions with `SOD_HISTORY=server` (§2) |
| Environment `urn:qadamar:1.0:environment:prior-action` | string, a bag | `context.priorActions` | same as `maker-id` |
| Any other attribute, category or `Issuer` (roles, clearance, `current-dateTime`, `RecipientSubject`, `Codebase`, custom categories…) | | ignored | |

Other attributes are ignored for the reason of §0: identity, clearance, roles and relations come from the PDP's own
store, and time from the server clock. A recognised attribute with another data type, several values where one is
expected, or an invalid value is a syntax error, never a guess. The same attribute id given twice in a category forms
one bag.

**Decisions.**

| Qadamar outcome | `Decision` | `Status.StatusCode.Value` |
|---|---|---|
| allow | `Permit` | `urn:oasis:names:tc:xacml:1.0:status:ok` |
| deny, including every fail-closed deny (`CORE.UNKNOWN_ID`, `ENGINE.*`, `SOD.MAKER_UNKNOWN`…) | `Deny` | `…:status:ok` |
| deny whose only rule is `SCHEMA.UNKNOWN_ACTION` (the action is not declared for that resource type, so no policy applies) | `NotApplicable` | `…:status:ok` |
| a required attribute absent | `Indeterminate` | `…:status:missing-attribute`, with `StatusDetail.MissingAttributeDetail[]` (`AttributeId`, `Category`, `DataType`) |
| malformed request (structure, data type, arity, value, repeated category, unknown `ReferenceId`) | `Indeterminate` | `…:status:syntax-error`, with a `StatusMessage` |
| `CombinedDecision: true` | `Indeterminate` | `…:status:processing-error` |

XACML lets a *permit-biased* PEP (XACML 3.0 §7.2) permit on `NotApplicable` and `Indeterminate`. Qadamar's fail-closed
guarantees hold for the base and *deny-biased* PEPs only; configure XACML PEPs as deny-biased.

**Obligations and advice.** Obligations are sent with `Permit` only (a deny releases nothing); a PEP that does not
understand one must not release the resource (XACML 3.0 §7.18). Ids are stable; each value is an `AttributeAssignment`
whose `Value` is a string.

| Qadamar | XACML obligation `Id` | `AttributeAssignment.AttributeId` (one per value) |
|---|---|---|
| `obligations.redact` (fields) | `urn:qadamar:1.0:obligation:redact` | `urn:qadamar:1.0:obligation:redact:field` |
| `obligations.maskClasses` (content classes) | `urn:qadamar:1.0:obligation:mask` | `urn:qadamar:1.0:obligation:mask:content-class` |
| `obligations.notify` (recipients) | `urn:qadamar:1.0:obligation:notify` | `urn:qadamar:1.0:obligation:notify:recipient` |
| `obligations.fieldAllowlist` (sent even when empty: no field may be shown) | `urn:qadamar:1.0:obligation:field-allowlist` | `urn:qadamar:1.0:obligation:field-allowlist:field` |
| `decision_token` (Clark-Wilson certified command, §2) | `urn:qadamar:1.0:obligation:decision-token` | `urn:qadamar:1.0:obligation:decision-token:jws` |

A permitted decision carrying an obligation this mapping cannot express is answered `Indeterminate` (processing-error)
rather than released without it: no decision token is issued, and the decision is recorded as a deny with rule
`XACML.OBLIGATION_UNEXPRESSIBLE` (fail closed). `AssociatedAdvice` (informational) is on every decided result:
`urn:qadamar:1.0:advice:decision-basis` with one `…:decision-basis:rule-id` per rule and
`…:decision-basis:policy-version`, and, when need-to-know runs as a dry run, `urn:qadamar:1.0:advice:would-deny`
with `…:would-deny:rule-id`. `ReturnPolicyIdList: true` adds `PolicyIdentifierList.PolicyIdReference[]` with the rule
ids as `Id` (no `Version`: Qadamar's `pv.…` policy version is not an XACML version number; it is in the advice).

**MultiRequests** (Multiple Decision Profile, `RequestReference` form). Category objects carry an `Id`;
`MultiRequests.RequestReference[].ReferenceId[]` names the objects of each individual request, and one `Result` is
returned per reference, in order. Category objects without an `Id` cannot be referenced and are shared by every
individual request (Qadamar's reading; for instance one `Environment` for all). Limits as for `/access/v1/evaluations`:
at most 1000 references (more: one `Indeterminate` result for the whole request), body ≤ 1 MB. `Id` values must be
unique. An individual request that is malformed or names an unknown `Id` gets its own `Indeterminate` result; the
others are still decided.

**Audit.** Every evaluated individual request appends exactly the record of an AuthZEN evaluation (`type: decision`,
`actor: pep`, subject, resource, action, effect, rule ids, policy version); `NotApplicable` is recorded as the deny it
is. An `Indeterminate` result (malformed input) is recorded too, as a deny: `type: decision`, `actor: pep`,
`action: xacml`, rule `XACML.INDETERMINATE`, `details: { status, reason, missing? }` (`status`: `syntax`, `missing` or
`processing`; `missing`: the absent attribute ids). No subject or resource is recorded, since none was read reliably.

**Not supported.** `CombinedDecision: true`; repeated categories without `MultiRequests` (the Multiple Decision
Profile's "repeated attribute categories" form: syntax-error, use `MultiRequests`); `Content`, `XPathVersion`,
the XPath (content-selector) form of the Multiple Decision Profile and every XPath data type (ignored); `IncludeInResult` (attributes are not echoed in the
result `Category`); `Issuer` matching; obligations or advice on `Deny`; the extended `Indeterminate{D,P,DP}` values
(results say `Indeterminate`); the XML request/response syntax (`application/xacml+xml`); the REST Profile of XACML's
discovery document; policy administration (PAP) in XACML.

**Conformance note.** Implemented from the OASIS JSON Profile of XACML 3.0 v1.1, XACML 3.0 core and the Multiple
Decision Profile v1.0, and tested by this repository (`packages/pdp-http/test/xacml.test.ts`: each category mapping,
each decision value, obligations, MultiRequests, malformed input, authentication, rate cost and audit equality with
AuthZEN). It has not been run against the OASIS conformance tests or a third-party XACML PEP, and it is not certified.

### 2.2 Resource registration (`/x/v1/resources`)

Resources come from `world.json` at the first start; after that, the application that owns the records registers them
at run time, as SCIM does for subjects (§3.11). Without it, a decision on a record created after deployment is
`CORE.UNKNOWN_ID`. All routes are `POST`, authenticated by a PEP credential **bound to resource types**
(`resourceTypes`, §3.10): a credential writes only the types it lists, and one created without `resourceTypes` (the
`bootstrap` credential included) writes none (`403`). They share the decision-plane rate budget: a listing costs one
token, a write costs 10 plus one per resource it names (at most 1000, so the largest sync still fits the smallest
budget), because every write checks level inheritance for its changed resources and their direct children, then updates their changed records. In
a cluster they are answered by the leader: a follower forwards them over the signed hop, or answers
`409 not_leader` (§3.9.1); followers see the result at their next synchronisation, within `GATE_MAX_STALENESS_MS`.

A **resource** is `{ type, id, level, compartments, integrity, contentClasses, owner?, parent?, version?, attrs? }`,
checked against the published bundle and refused with `400` on anything else: `type` a resource type of the policy,
`id` 1..256 characters without control characters, `level` an integer 0..3, `compartments` distinct compartments of the
policy, `integrity` `derived|extracted|system|verified`, `contentClasses` the content scan result (required: empty when
scanned and clean, as the engine requires), `parent` a `{ type, id }` that must be registered (`422` otherwise, or when
the resource would sit below its parent's level) and of a type the credential is bound to as well (`403`: placing a
record under a parent links it to the parent's need-to-know), `attrs` an object of at most 8 KiB. When the type declares a relation
named `parent`, the PDP keeps the `parent` tuple in step with `parent`, so need-to-know inheritance and `/x/v1/filter`
see a registered child like a seeded one.

**Constrained data items (Clark-Wilson).** A resource of a `constrained` type can be **created** by registration, and
its IVPs must hold (§3.12; `422` naming `CW.IVP.<id>` otherwise). An **existing** one is never changed by
registration: any difference from what is stored (labels, `attrs`, `version`) is refused with
`409 certified_command_required`, for the whole call; change it with its certified command (decision token consumed with
`postState`, §2): the reported completion then updates the PDP's copy. Sending it again as stored is `unchanged`. **Retiring** one is proposed (`202`), not applied: deleting
a constrained item is a transformation the PDP cannot see certified, and it would also reset the item (a later
registration would create it afresh); a second person decides.

| Route | Body | Answer |
|---|---|---|
| `POST /x/v1/resources` | `{ resource }` | `201` created, `200` updated or unchanged, `202` proposed |
| `POST /x/v1/resources/retire` | `{ resource: { type, id } }` | `200`; unknown and never registered → `404` |
| `POST /x/v1/resources/sync` | `{ resources?: Resource[], retire?: { type, id }[] }`, 1..1000 together | `200`, or `202` when anything is proposed |
| `POST /x/v1/resources/list` | `{ type, cursor?, limit? }` (limit 1..1000, default 100) | `{ resources: [{ type, id, version }], next_cursor }` in id order; `""` ends |

Writes answer `{ items: [{ type, id, status, version?, changeId? }], counts: { created, updated, unchanged, retired, proposed } }`.
A call is **atomic**: every item is validated first, and one refused item (`400`, `403`, `404`, `409`, `422`) refuses the
call with nothing kept. It is **idempotent**: a resource sent again as stored is `unchanged`, a retired one retired again
is `unchanged`, and a proposal already pending for the same content is not proposed twice (its `changeId` is returned).
**Versions**: without `version`, the PDP stores the next one (1 for a new resource); a given `version` must be above
the stored one (`409` otherwise). Every change bumps it, so decision tokens issued on the earlier version can no longer
be consumed.

**Sync: upsert batches plus a cursor listing, not a full-set replacement.** The application is the system of record:
it sends what changed and retires what it deleted, and reconciles by paging `/x/v1/resources/list` against its own
table. A "this is the whole set of type X" mode was not built: at 1000 items per call it cannot be one request for a
real table, and a truncated or buggy full set would silently retire everything it missed; the server also keeps no sync
session to lose on a leader change.

**What a PEP may do alone, and what waits for a second person.** Registration is data, not policy, but some fields
decide who sees what. Compared with the stored resource; **an id that was ever retired is never registered again by
the PEP alone**, whatever it sends (below):

| Applied at once | Proposed as a `register_resources` change (§3.5) |
|---|---|
| a new resource, at any level, compartments and content classes (nobody could reach it before: decisions were `CORE.UNKNOWN_ID`) | the level lowered (declassification) |
| the level raised, compartments or content classes added | a compartment removed (declassification) |
| `attrs` no rule reads, `version` | a content class removed (lifts a content-attribute deny or mask) |
| retirement (decisions then fail closed with `CORE.UNKNOWN_ID`), except of a constrained item | `integrity` changed, either way (moves the Biba bounds: who may write it, what may rely on it) |
| | `owner` changed (ABAC owner rules, `RESOURCE_OWNERS` console scope) |
| | `parent` changed (need-to-know inheritance and the level floor) |
| | an **attribute the policy reads** added, removed or changed (below) |
| | a constrained item retired (above) |
| | **any registration of an id that was retired** (reason `retired id registered again`) |

A proposed resource keeps its stored labels until a checker (approver or security officer) approves; the change carries
the usual impact preview (`broadens`, who gains), bounded by `IMPACT_MAX_EVALUATIONS` like any change (a call whose
proposal would exceed it is refused with `422` and keeps nothing). Whoever created or last rotated the proposing credential, and so knows
its secret, cannot approve or reject it (`403 self_approval`). Approval is refused as stale (`409`) when one of the
proposed resources changed since (its version moved) or the impact differs; registrations of other resources meanwhile
do not make it stale.

**Attributes the policy reads.** For each resource type, the PDP collects, once per published bundle, every
`resource.attrs.<name>` read by an ABAC rule applying to the type (`forbid`, `obligation` and `permit`: a new value can
lift a forbid or an obligation, or meet a permit) or by any content-attribute rule's `unless`, plus the type's optional
`schema.resourceTypes.<type>.governedAttributes` (attribute names; validated by `validateBundle`). A rule reading
`resource.attrs` as a whole governs every attribute. On an existing resource, any change to one of them (a new value,
added or removed) is proposed, whatever its direction: proving that a new value keeps every rule at least as strict is
not attempted, so `status: open → closed` waits for a second person as `closed → open` does. Every other attribute is
applied at once. Keep classification in the labels above, not in `attrs`.

Retiring a resource that is still another resource's `parent` is refused (`422`: retire the children first, or in the
same sync). Retirement keeps the resource's tuples and its performed-action history; registering the id again restores
them.

**Retired ids: append-only, outside the state document, no cap.** A retirement records `(type, id, version,
retiredAt)` in an append-only log of its own, committed with the retirement: the `gate_retired` table with PostgreSQL
(the service role may only read and append; forced row-level security), `retired.jsonl` in `DATA_DIR` in file mode.
Neither the PostgreSQL metadata document nor file mode's state document holds them, and nothing caps them, so
create/retire cycles do not block later retirements. File mode still rewrites its document on every write; PostgreSQL
writes only the retired row and the changed resource row. Registering a retired id again is **always** a
`register_resources` proposal, whatever its labels: no stored copy of the old labels or attributes is needed to judge
it (a later bundle reading a new attribute cannot let a reused id skip review), the reviewer sees the id is reused, and
the version continues above the retired one. Only the leader registers, so only the leader reads the log: it loads it
when it starts or takes the lead (a follower that becomes leader sees every id retired before). Retiring an id already
retired is `unchanged`. An archive taken before `gate_retired` existed is restored with the table created empty
(nothing could be retired then).

**Pending proposals are bounded per credential.** A call that would queue a new `register_resources` change while its
credential already has `RESOURCE_PENDING_PROPOSALS_PER_PEP` (default 100) awaiting review is refused, whole call, with
`409 proposal_limit`; sending again what is already pending is not a new proposal.

**Audit and metrics.** One `change` row per call, actor the PEP, action `resource_register`, `resource_retire` or
`resource_sync`, with `details: { credential, counts, resources: ["type:id", …] (first 32), omitted?, changeIds? }`; a
proposal adds the usual `propose` row. A refused call writes a `change / refused` row with the route and error code
(at most one a minute per source address and error). `/metrics` counts `gate_resource_registrations_total{operation}`
(`register`, `retire`, `sync`, `refused`) and `gate_registered_resources_total{outcome}` (`created`, `updated`,
`unchanged`, `retired`, `proposed`). The SDK has `registerResource`, `retireResource`, `syncResources` and
`listResources` ([integrator guide](handbook/guides/integrator.md#register-the-records-your-application-owns)).

### 2.3 PEP SDKs

Two SDKs with one contract, neither with a runtime dependency. Both send `Authorization: Bearer <PEP key>` with JSON,
bound every call by a timeout, check every answer against its exact shape (an unexpected answer is an error, never a
partial result), apply obligations to a copy of the record and refuse what they cannot enforce, and verify the
decision assertions of §2.0.2 (JWKS cached and refreshed on an unknown `kid`, clock skew, binding, replay store).

| | TypeScript (`packages/sdk`) | Python (`sdks/python`, package `qadamar`) |
|---|---|---|
| Runtime | Node.js ≥ 22.18, standard library | Python ≥ 3.9, standard library (`urllib`, TLS verified by default, optional `ca_file`) |
| Client | `PepClient`: `evaluate`, `evaluateBatch`, `searchResources`, `searchSubjects`, `searchActions`, `filter`, `consumeToken`, `reportOutcome`, `evaluateAsserted`, `assertList`, `registerResource`, `retireResource`, `syncResources`, `listResources`, `enforce` | `PepClient`: the same in snake_case (`evaluate_batch`, `consume_token`, ...), plus `explain` |
| Obligations | `enforce(decision, record)`, `MASKED_TEXT` | `enforce(decision, record)`, `MASKED_TEXT` |
| Assertions | `AssertionVerifier`, `withGateAssertion` (node:http), `MemoryReplayStore`, `ReplayStore` | `AssertionVerifier.verify(method, path, body, header)`, `status_for`, `MemoryReplayStore`, `ReplayStore`; Ed25519 in pure Python (RFC 8032 §6, verification only, not constant-time: public data only) |
| Errors | `PepError`, `PdpHttpError`, `PdpResponseError`, `PdpNetworkError`, `AccessDeniedError`, `ObligationError`, `AssertionError` | the same, with `GateAssertionError` for `AssertionError` |

The Python client follows no redirect and ignores proxy environment variables, so the key only goes to its base URL;
it has no abort signal. Usage: [sdks/python/README.md](../sdks/python/README.md).

## 3. Admin API (console)

All routes require a session except `POST /admin/v1/session`. Every list response is `{ "items": [...] }`.
Scoping follows §1: a resource owner never sees ids outside their scope, and counts never include them.

### 3.1 Session
- `POST /admin/v1/session` `{ username, password, code? }` → `{ user: { id, name, roles }, csrfToken }` + cookie.
  `code` is required once the account has TOTP (§3.1.2): the current 6-digit code or an unused recovery code.
  When 32 password checks already wait for the two scrypt slots → `503 unavailable` with `Retry-After: 3` at once
  (audited as a denied `login`, reason `busy`), never an unbounded wait.
- `GET /admin/v1/session` → same, or 401. `DELETE /admin/v1/session` → 204.
- Sessions end at logout, after 15 min without a request or 8 h after sign-in, both on real time. The `csrfToken` is
  derived from the session id (HMAC-SHA256 keyed by it), so it is the same for the life of the session and on every
  node. **Storage:** with PostgreSQL a session is a row of `gate_session` keyed by the SHA-256 of its id; neither the id
  nor the CSRF token is stored. Every node reads it (one primary-key lookup per console request), so a session survives
  a standby takeover or a leader change, and a logout, expiry or back-channel logout holds on every node. Its last use
  is written at most once a minute (a session may end up to a minute before 15 idle minutes, never after), and each
  sign-in deletes the expired rows. Without a database, sessions live in the node's memory and end with the process.

### 3.1.1 Console sign-in through the organisation (OIDC or SAML) and TLS

Configuration by environment variables (`packages/pdp-http/src/main.ts`):

| Variable | Effect |
|---|---|
| `PUBLIC_ORIGIN` | The console's external origin, e.g. `https://gate.example`. If https: cookies are always `Secure` and HSTS (`max-age=31536000; includeSubDomains`) is sent, even behind a TLS-terminating proxy. `X-Forwarded-Proto` is never trusted. Must be https unless loopback. Also the AuthZEN discovery base. |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | Serve HTTPS directly (TLS 1.2 minimum). |
| `TRUSTED_PROXIES` | Comma-separated addresses or CIDR ranges (IPv4 or IPv6) of the reverse proxies in front of the node, e.g. the ingress controller's pod range. Empty or unset (default): `X-Forwarded-For` is ignored and the client address is the connecting address. When the connecting address is in the list, the client address is the **rightmost** `X-Forwarded-For` entry that is not itself a trusted proxy (entries a client wrote on the left are never believed; a malformed entry stops the walk at the last trusted hop). That address keys the per-IP rate limit and the login lockout, is recorded as `details.client` in sign-in audit rows and as `client.address` on request spans. An invalid entry stops the process at start. `X-Forwarded-Proto` and `Forwarded` are never read. |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | Turn on SSO. Issuer must be https (loopback allowed for tests). Secret optional (public client with PKCE). Redirect URI to register at the IdP: `${PUBLIC_ORIGIN}/admin/v1/oidc/callback`. |
| `OIDC_ROLE_CLAIM` | Claim holding console roles (default `roles`; Entra app roles use `roles`, Okta/Keycloak often `groups`). Only `access_admin`, `policy_author`, `approver`, `security_officer`, `resource_owner`, `auditor` count. |
| `OIDC_ID_CLAIM` | **Required.** Claim used as the console user id, compared as is (no case folding). It must be the id your applications send as subject, so self-grant and maker-checker rules see the same person. `email` is accepted only with `email_verified: true`. |
| `OIDC_ACR` | If set, sent as `acr_values` and the ID token's `acr` must equal it. Otherwise `amr` must contain `mfa` or `mca` (RFC 8176). |
| `SAML_IDP_ENTITY_ID`, `SAML_IDP_SSO_URL`, `SAML_IDP_CERT_FILE`, `SAML_AUTHN_CONTEXT`, `SAML_ID_ATTRIBUTE`, `SAML_ROLE_ATTRIBUTE`, `SAML_SP_ENTITY_ID`, `SAML_ACS_URL`, `SAML_MAX_AUTH_AGE_SECONDS` | Turn on SAML 2.0 sign-in, beside or instead of OIDC: see *SAML 2.0 Web SSO* below. |
| `PASSWORD_LOGIN` | `on` keeps local password sign-in alongside SSO (e.g. a recovery account). Default: off when OIDC or SAML is configured, on otherwise. |
| `RESOURCE_OWNERS` | JSON object: console user id → array of further resource owner ids that user answers for (resource-owner scope, §1). A user's own id always counts. Unset: own id only. Not read from any IdP claim. |

Routes:

- `GET /admin/v1/auth-methods` → `{ "password": bool, "sso": bool, "saml": bool }` (no session needed; `sso` is OIDC).
  The console shows one sign-in button per IdP configured.
- `GET /admin/v1/oidc/login` → `302` to the IdP with `state`, `nonce` and an S256 PKCE challenge; sets `__Host-gate_oidc`,
  which carries state, nonce and verifier sealed with AES-256-GCM under a per-process key (no server-side table to
  fill; a restart cancels sign-ins in progress)
  (`HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`). Lax because the IdP returns by a cross-site top-level GET;
  the `__Host-` prefix prevents a sibling domain from planting the cookie.
- `GET /admin/v1/oidc/callback?code&state` → exchanges the code with the verifier; verifies the ID token signature
  (RS256, PS256 or ES256 from the IdP's JWKS, RSA ≥ 2048 bits, refetched at most once a minute for an unknown `kid`),
  `iss` (exact match), `aud`, `azp`, `exp`, `iat`, `nbf` (60 s skew, wall clock) and `nonce`; the IdP endpoints must
  be https; state is single use, bound to the cookie, 10 minutes.
  Success: session cookie as in 3.1, `302 /`, audit `login allow {method: oidc}`. Refusal: `302 /?sso_error=` with
  `mfa_required`, `no_role` or `sso_failed`, audit `login deny` with the reason. A
  callback that never matched a sign-in started here (forged or replayed) is refused without an audit row.
- `POST /admin/v1/session` with a password → `403 password_login_disabled` when password sign-in is off.
- `POST /admin/v1/oidc/backchannel-logout` (OpenID Connect Back-Channel Logout 1.0; register
  `${PUBLIC_ORIGIN}/admin/v1/oidc/backchannel-logout` at the IdP) with `application/x-www-form-urlencoded` body
  `logout_token=<JWT>` (exactly one). No session or CSRF token: the IdP calls it server to server; the per-IP rate limit
  applies. The logout token is checked like an ID token (signature from the same IdP JWKS, `iss` exact, `aud`, 60 s
  skew) plus: `iat` required and at most 24 h old, `exp`/`nbf` checked when present, `jti` required and single use (kept
  24 h, at most 10,000 in memory: when full, new tokens are refused until entries expire), `events` must contain
  `http://schemas.openid.net/event/backchannel-logout` with an object value, `sid` or `sub` required, `nonce` forbidden,
  `typ` absent, `JWT` or `logout+jwt`. Valid → `200 {}`: the console sessions opened by SSO with that IdP `sid` (and
  `sub` when given) end; a session whose ID token carried no `sid` ends on a matching `sub`. Audit
  `oidc_backchannel_logout allow {sessionsEnded}` (actor: the IdP `sub`). Invalid → `400 invalid_request`, audit
  `oidc_backchannel_logout deny`. With PostgreSQL the matching sessions are deleted from `gate_session`, so they end on
  every node; without it, in the memory of the node that receives the logout.
  The `jti` replay memory is in memory too and is not persisted: after a restart (or on another node) a logout token
  already used, still under 24 h old, is accepted once more. Its only effect is to end the matching SSO sessions again,
  which is the fail-closed direction; it cannot open or extend a session.

#### SAML 2.0 Web SSO

Web Browser SSO profile, SP-initiated: HTTP-Redirect `AuthnRequest`, HTTP-POST `Response`. XML signatures are checked by
`@node-saml/node-saml` (xml-crypto underneath, `packages/pdp-http/src/saml.ts`); Qadamar adds the checks the library only
warns about or leaves out. The IdP signing certificate is pinned from `SAML_IDP_CERT_FILE` (PEM, one or more
certificates, RSA ≥ 2048 bits or EC); no metadata is fetched. Register at the IdP: entity id `SAML_SP_ENTITY_ID`
(default `${PUBLIC_ORIGIN}/admin/v1/saml/metadata`), ACS `${PUBLIC_ORIGIN}/admin/v1/saml/acs` (HTTP-POST), single logout
`${PUBLIC_ORIGIN}/admin/v1/saml/logout` (HTTP-POST and HTTP-Redirect), assertions signed.

| Variable | Effect |
|---|---|
| `SAML_IDP_ENTITY_ID` | Turns SAML on. The `Issuer` every assertion and logout request must carry (exact, one Issuer). Needs `PUBLIC_ORIGIN`. |
| `SAML_IDP_SSO_URL` | **Required.** The IdP SingleSignOnService URL (HTTP-Redirect); https, loopback http allowed for tests. |
| `SAML_IDP_CERT_FILE` | **Required.** PEM file of the IdP signing certificate(s). Rotation: put the old and the new certificate in the file, restart. |
| `SAML_AUTHN_CONTEXT` | **Required.** Comma-separated `AuthnContextClassRef` values that prove MFA at your IdP (for example `http://schemas.microsoft.com/claims/multipleauthn` for Entra, or a `urn:oasis:names:tc:SAML:2.0:ac:classes:…` class your IdP issues only after a second factor). Sent as `RequestedAuthnContext Comparison="exact"`; every `AuthnStatement` of the assertion must carry one of them, else `mfa_required`. SAML cannot be configured without it. |
| `SAML_ID_ATTRIBUTE` | **Required.** Attribute used as the console user id, compared as is, single value; `NameID` takes the subject NameID. As `OIDC_ID_CLAIM`: it must be the id your applications send as subject. |
| `SAML_ROLE_ATTRIBUTE` | Attribute holding console roles (default `roles`), one role per `AttributeValue`; the same six roles as OIDC count. |
| `SAML_MAX_AUTH_AGE_SECONDS` | Longest time since the IdP authenticated the user (`AuthnInstant`), default 43200 (12 h), 60..604800: an older IdP session signs nobody in. |
| `SAML_DECRYPTION_KEY_FILE`, `SAML_DECRYPTION_CERT_FILE` | Matching RSA 2048+ PEM private key and certificate for encrypted assertions. Mount the private key from your secret store; only the certificate is published in metadata. |
| `SAML_SIGNING_KEY_FILE`, `SAML_SIGNING_CERT_FILE` | Matching RSA 2048+ PEM signing identity. Outgoing Redirect messages use RSA-SHA256. |
| `SAML_IDP_SLO_URL` | Pinned IdP HTTP-Redirect SingleLogoutService URL (https, or loopback http). Requires the signing pair; enables outgoing LogoutRequest and LogoutResponse. |
| `SAML_SP_ENTITY_ID`, `SAML_ACS_URL` | Override the entity id (the audience assertions must name) and the ACS URL (https, path `/admin/v1/saml/acs`). |

Routes:

- `GET /admin/v1/saml/login` → `302` to the IdP with a deflated `AuthnRequest` (signed when the SP signing key is configured) (random `ID`, the ACS URL,
  the requested MFA classes). The request id is kept in memory for 10 minutes (single use) and bound to this browser in
  `__Host-gate_saml` (`HttpOnly; Secure; SameSite=None; Path=/; Max-Age=600`): the IdP posts the Response cross-site,
  which a `Lax` cookie does not survive, and the `__Host-` prefix keeps a sibling domain from planting one (login CSRF).
- `POST /admin/v1/saml/acs` with `SAMLResponse` (exactly one, at most 256 KiB). Refused unless all hold:
  the Response's `InResponseTo` is the request id of this browser's cookie, still pending (single use: consumed by the
  first response, signed or not, that answers it); no `DOCTYPE` or entity declaration (XXE); every `SignatureMethod`
  is RSA-SHA256, RSA-SHA512 or RSA-PSS-SHA256 and every `DigestMethod` SHA-256 or SHA-512 (one SHA-1 algorithm anywhere
  refuses the message); the `Destination`, when present, is the ACS; exactly one assertion, **itself signed** by a
  pinned certificate (a signature on the Response alone is not enough; signature-wrapping defences of node-saml: one
  signature, one same-document reference to the signature's parent, a unique `ID`, only the signed bytes read); `Issuer`
  the IdP entity id; `Audience` the SP entity id; `NotBefore` / `NotOnOrAfter` of the conditions and of a bearer
  `SubjectConfirmationData` within 60 s of skew, the assertion at most 5 minutes old; a bearer confirmation whose
  `Recipient` is the ACS; the assertion `ID` not seen before; an `AuthnContextClassRef` from `SAML_AUTHN_CONTEXT`; every
  `AuthnInstant` at most `SAML_MAX_AUTH_AGE_SECONDS` old (default 43200, 12 h; 60..604800) and not in the future; the id
  attribute; a console role. Encrypted assertions are decrypted with the configured key and pass the same checks, including the algorithm allowlist inside the ciphertext; encryption never substitutes for an assertion signature. Success: session cookie as in
  3.1, `302 /`, audit `login allow {method: saml}`. Refusal: `302 /?sso_error=` with `mfa_required`, `no_role` or
  `sso_failed`, audit `login deny {method: saml}` with the reason; a response that never answered this browser's request
  (forged, foreign or replayed cookie) is refused without an audit row.
- `POST /admin/v1/saml/logout` accepts one `SAMLRequest` or `SAMLResponse` with a root XML signature;
  `GET` accepts the HTTP-Redirect binding with a signed, deflated message. Redirect verification uses the original
  query bytes, including RelayState; missing signatures, duplicate signed fields and SHA-1 are refused. Both bindings
  pin the issuer and signature key, check Destination when present, require IssueInstant within five minutes (60 s
  future skew), and accept each message ID once. LogoutRequest NotOnOrAfter is checked when present.
  A valid request ends matching SAML console sessions by NameID and optional SessionIndex, including across nodes in
  PostgreSQL mode. Their cookie and derived CSRF token no longer authorise requests. With `SAML_IDP_SLO_URL`, Qadamar
  redirects to that pinned URL with a signed Success LogoutResponse, InResponseTo the request ID, and echoed RelayState
  (opaque, at most 80 bytes). Without it, legacy incoming logout still ends sessions and redirects locally.
  Invalid messages answer `400 invalid_request`; audit action `saml_logout` records allow/deny and sessionsEnded.
- `DELETE /admin/v1/session` from a SAML session with SLO configured requires the normal CSRF header, ends the matching
  local sessions immediately and returns `200 {logoutUrl}`. The console navigates there: a signed HTTP-Redirect
  LogoutRequest containing the stored NameID format/qualifiers and SessionIndex. Other sessions keep the existing 204
  response. `POST /admin/v1/saml/logout/start` is also available with the session cookie and CSRF header (302).
  A signed LogoutResponse on either binding must answer a pending logout request (single use, 10 minutes), carry
  Success and pass the issuer, destination, signature, age and replay checks; then Qadamar redirects to `/`.
  Local logout holds even if the IdP fails or never responds. Logout correlation uses a separate cache from sign-in.
- `GET /admin/v1/saml/metadata` → the SP metadata (`application/samlmetadata+xml`): entity id, ACS, single logout
  services for both logout bindings, configured public certificates, `WantAssertionsSigned="true"`.

The pending request ids and the assertion and logout ids already seen live in the memory of the leader, like OIDC's
consumed states (the admin plane runs on the leader; followers forward `/admin/`): a restart or a failover cancels
sign-ins in progress, and each memory keeps at most 10,000 entries (the oldest goes first). SAML sessions are stored in
`gate_session` like OIDC ones (`method = saml`, NameID and SessionIndex in the IdP columns).

### 3.1.2 TOTP for local password accounts

RFC 6238: HMAC-SHA-1, 6 digits, 30 s steps, one step of drift either way, on the server's wall clock (never `CLOCK`).
No dependency: `packages/pdp-http/src/totp.ts`.

- `GET /admin/v1/session/totp` (a session opened by password; an SSO session gets 403) → `{ active, pending, available }`:
  TOTP is active, an enrolment awaits its first code, and `available` is false when `SIGNING_KEY_SEAL` is not set.
- `POST /admin/v1/session/totp/enrol` `{ password }` (session + CSRF token, a session opened **by password**; an SSO
  session gets 403). Re-authentication: `password` is the account's current password, else 403 (audited `totp_enrol`
  deny, five attempts per account per window, then 429), so a stolen session cannot bind its own second factor
  → `200 { otpauthUri }`. The URI carries a new 160-bit secret and is returned this once; calling again replaces
  a pending (not yet active) secret. `409` when TOTP is already active, or when `SIGNING_KEY_SEAL` is not set: the
  secret is stored in `credentials.json` (in PostgreSQL mode, the `credentials` row of `gate_doc`, shared by every node;
  §3.9.1) only sealed with that key (AES-256-GCM as for signing keys, the account id
  bound as additional data), never in clear.
- `POST /admin/v1/session/totp/activate` `{ code }` → `200 { recoveryCodes: [10 × "xxxx-xxxx-xxxx-xxxx"] }`, shown
  this once; only their SHA-256 is stored (80 random bits each), each works once. `422` for a wrong code, `409` without
  a pending enrolment.
- Sign-in with TOTP active: the password and `code` are checked together and every failure is the same `401`
  (missing, wrong, replayed or used code, or wrong password), so a correct password is never confirmed on its own. A
  code is accepted once: its time step, or an earlier one, is refused after a sign-in (or the activation) used it.
  Each failure counts towards the sign-in throttle (as for passwords) and is audited
  `login deny {method: password, reason: second_factor}`.
- Audit, without secrets or codes: `totp_enrol`, `totp_activate {recoveryCodes: 10}`, `totp_recovery_code_used
  {remaining}` (type `security`), `login allow {method: password, mfa: totp|recovery}`.
- An enrolled account whose `SIGNING_KEY_SEAL` is gone cannot sign in (the same `401`, so the password is not
  confirmed): fail closed. There is no reset route
  yet: an account that lost its device and its recovery codes needs its `totp` entry removed from `credentials.json`
  (the `credentials` row of `gate_doc` in PostgreSQL mode) by an operator.
- PostgreSQL mode: the last accepted step is in that shared row too, so a code used on one node is a replay on the
  node that takes over.
- The console's sign-in form has an optional one-time code field. The console's **Two-step sign-in** screen
  (`#/two-step`, every role, local accounts) shows this status, enrols (current password), draws the otpauth URI as a
  QR code and as text, activates with a first code and shows the recovery codes once with a copy button.

### 3.2 Overview
`GET /admin/v1/overview` →
```json
{ "policy": { "name": "...", "version": "pv.…", "publishedAt": "ISO", "publishedBy": "amira", "approvedBy": "omar" },
  "needToKnowMode": "enforce",
  "counts": { "pendingChanges": 2, "activeBreakGlass": 1, "breakGlassToReview": 1, "expiringGrants30d": 3 },
  "audit": { "verified": true, "length": 123, "head": "<sha256 hex>" },
  "pdp": { "status": "ok", "uptimeSeconds": 42, "decisions": 1000 } }
```

### 3.3 Model and data (read)
- `GET /admin/v1/schema` → `{ resourceTypes, subjectRelations, compartments, mandatory, needToKnow }` (from the bundle).
- `GET /admin/v1/policy` → `{ current: { version, bundle, signature: { alg: "EdDSA", kid, jws } | null }, history: [ { version, publishedAt, publishedBy, approvedBy, reason, signature? } ] }`.
  `version` is `pv.` followed by the SHA-256 (hex) of the canonical bundle (JSON, keys sorted, no whitespace). Ids
  written before this version (`pv.` + 16 hex, FNV-1a 64) remain as they were in history and audit rows; they are
  fingerprints, not security hashes. `signature` is null only if the stored signature no longer verifies (the node
  would not have started). See "Policy bundle signature" in §3.10.
- `GET /admin/v1/subjects` → items `{ type, id, name, unit, active, roles, roleAssignments?, clearance, compartments, integrity, delegatedBy? }`
- `GET /admin/v1/resources` → items `{ type, id, title, status, level, compartments, integrity, owner, contentClasses }`
  (metadata only: no body, no amounts, no document text)
- `GET /admin/v1/resources/inventory?type=&cursor=&limit=` → `{ type, total, items, next }`: the resources of one
  type (registered through §2.2 or seeded), in id order, `limit` 1..500 (default 50); `next` is the last id of the page
  (pass it as `cursor`), `null` on the last page. Items `{ id, title, level, compartments, integrity, owner, contentClasses,
  version, parent? }`. A resource owner sees only its own scope, and `total` counts that scope. `400` on a type the policy
  does not declare, a bad `limit` or a cursor over 256 characters. Not audited, like the other model reads.
- `GET /admin/v1/resources/retired?type=&cursor=&limit=` → the same page shape over the retired-id log (§2.2), items
  `{ id, version, retiredAt, registeredAgain }` (`registeredAgain`: the id is live again, after review). The log keeps no
  owner, so a console user whose only role is `resource_owner` gets `403`. Pending `register_resources` proposals are
  the `GET /admin/v1/changes?status=pending` items of that kind.
- `GET /admin/v1/tuples` → items `{ id, object, relation, subject, subjectRelation?, notBefore?, notAfter?, validFrom?, validTo?, breakGlass?, grantedBy?, reason? }`
  (new tuples are stored with `notBefore` / `notAfter`; older ones may still carry `validFrom` / `validTo`)

### 3.4 Simulator
- `POST /admin/v1/simulate/what-can` `{ subjectId, action, network }` → items
  `{ resource: { type, id, title, level }, decision, rules, reasons, path?, obligations }` for every resource in scope.
- `POST /admin/v1/simulate/who-can` `{ resourceId, action, network }` → items `{ subject: { type, id, name }, decision, rules, reasons, path? }`.
- `POST /admin/v1/simulate/matrix` `{ action, network }` → `{ action, network, layers, actions, subjects, resources, cells }`: every subject × resource in the caller's scope (a subject also lists its `roleAssignments` with their `notBefore` / `notAfter` windows), each cell `{ subject, resource, applicable, decision?, layers?, path?, obligations? }` where `layers` gives, for `rights` (RBAC or an ABAC permit), `clearance` (BLP, compartments, network, Biba, and the delegator's), `needToKnow`, `conditions` (ABAC forbid and obligations), `content` (ABAC on content attributes), `context` (CBAC: context-based, Zero Trust) and `controls` (inactive, Clark-Wilson, SoD), the outcome `pass | deny | would_deny | obligation | none`, its rules and reason. Not audited, like the other simulator routes.
- `POST /admin/v1/explain` `{ subjectId, resourceId, action, network, sessionLevel?, makerId?, priorActions? }` → `Decision`.
- `POST /admin/v1/simulate/impact` `{ kind, payload }` (same as a change, not stored) → `Impact`
  (`{ evaluated, analysis: { affectedCells, reasons }, gained: [ { subjectType, subject, resourceType, resource, action, rules } ], lost: [...], obligationsLost: [ ObligationChange ], obligationsGained: [...], policyVersionBefore, policyVersionAfter, contextAnalysis? }`).
  `affectedCells` is the unique subject × resource × action set selected before network, context and maker/history variants;
  `reasons` names the changed inputs that selected it. `evaluated` counts those cells across the variants. Impacts stored
  before affected-set analysis have no `analysis` field. When context signals are partitioned, `contextAnalysis` is
  `{ cap, evaluatedClasses, truncated, incomplete, unsupported, classes }`. Each changed class carries its representative
  `context`, `evaluated` count and its own gained/lost/obligation rows; maker/history variants are merged within that
  class. The global rows remain the union over all evaluated classes. `incomplete` is true when the cap or an unsupported
  ABAC expression leaves context space unanalysed; `unsupported` lists the paths or comparison shapes responsible.
  `obligationsLost` / `obligationsGained` list the cells allowed in both worlds whose obligations changed:
  `ObligationChange` is the cell plus `rules` (the obligation rules present on one side only) and
  `obligations: { redact, maskClasses, notify, fieldAllowlist?: { before, after }, decisionToken? }`, what the before
  side imposes and the after side does not (lost) or the reverse (gained). `fieldAllowlist` appears when the visible
  fields widened (lost) or narrowed (gained), `null` meaning every field; `decisionToken: true` when the single-use
  token is no longer required, lives longer or lost its post-state binding (lost), or the reverse (gained).

### 3.5 Changes (two-person approval, Clark-Wilson)
Change kinds and payloads:

| kind | payload |
|---|---|
| `add_tuple` | a tuple without `id`, with optional `notBefore` / `notAfter` (legacy `validFrom` / `validTo` still accepted; both names for one bound → 422). An expiry is required for `granted` and `allocated`, at most 90 days ahead; a `notBefore` in the future is refused (the impact of a grant is reviewed when it takes effect) |
| `remove_tuple` | `{ tupleId }` |
| `update_subject` | `{ id, set: { clearance?, compartments?, roles?, roleAssignments?, active? } }`; `roleAssignments` is `[{ role, notBefore?, notAfter? }]`, at most 256, each role must exist |
| `update_resource` | `{ id, set: { level?, compartments?, integrity? } }`; a resource below its parent's level (or a parent raised above a child) → 422 |
| `publish_policy` | `{ bundle }` (validated by `validateBundle`; errors → 422 with `details`). Compatibility for one version: a bundle still carrying the legacy content-rule field `cbac` is read as `abacContent`, with the warning `DEPRECATED_CBAC_FIELD` in the validation result (`warnings`), in the publish audit row and in the console; `cbac` and `abacContent` together → 422 ("cbac and abacContent cannot both be present"). Stored bundles keep loading; the legacy field will be removed in a later version |
| `certify_tp` | `{ resourceType, action }`: records the certification of a transformation procedure (a `certified` action of a `constrained` type, else 422). Proposed by a security officer only (403 otherwise), approved by an approver or another security officer. E4: the maker and the checker must each be a PDP subject with the same id (no such subject → 403: fail closed), and none of those subjects may be able to execute the action (403): a role granting it, or a permit by the engine itself on any item of the type (trusted network, an independent maker; roles through delegation, ABAC permits and relations count; a deny caused only by the item's IVPs, a missing certification or SoD history does not clear the certifier). On approval, appends `{ resourceType, action, certifiedBy, approvedBy, certifiedAt, policyVersion, changeId, reason, fingerprint }` to the certification records (the fingerprint binds the record to the procedure's current definition, §3.12). Decisions change only for types listed in `clarkWilson.requireCertification` (§3.12). |
| `register_resources` | `{ resources: Resource[], basis: string[], retire?: { type, id }[], retireBasis?: string[] }`, proposed only by a PEP credential bound to the resource types (§2.2); a person proposing it gets 403. Each resource as it will be stored, with what it replaces (`live:<version>`, `retired:<version>`, or `new`); `retire` lists constrained items whose retirement waits for review. Approval by an approver or a security officer other than whoever issued (created or last rotated) the credential (`403 self_approval`); stale (`409`) once one of the resources changed (a new version, or retired since) or the impact differs, not because other resources were registered meanwhile. |
| `scim_subjects` | `{ subjects: Subject[] }`, proposed only by the SCIM service (section 3.11); a person proposing it gets 403. Clearance, compartments, integrity, type and non-SCIM attributes of an existing subject cannot change; new subjects start at clearance 0 without compartments. A checker who is one of the subjects, or who minted the SCIM credential that proposed it (`403 self_approval`), cannot approve it. |

Impact analysis is bounded by `IMPACT_MAX_EVALUATIONS`, a positive integer with default `100000`. The analyzer selects
only subject × resource × action cells whose decision or obligations can change, following changed entities, rule scopes
and relation dependencies. The `evaluated` count covers that affected set over both networks, representative contexts
and the required maker/history variants; `analysis.affectedCells` is the unique set before variants and
`analysis.reasons` explains the selection. Old and new CBAC and ABAC rules contribute every listed country, equality and
in-list literals, numeric thresholds and adjacent values, instant and age boundaries, each local time-window edge, every
device posture combination, authentication methods, missing signals and live/expired sessions. Old and new CIDRs are
partitioned by their interval boundaries into membership classes (IPv4 and IPv6), with one representative per class and
one outside all ranges. One-signal variants run before their cross-product, capped at 32 classes per network;
`contextAnalysis.truncated: true` explicitly means combinations were omitted, so the change must be split for a complete
review. Unsupported expression shapes set `contextAnalysis.incomplete: true` even when `truncated` is false; any
incomplete analysis requires security-officer approval. A proposal whose affected analysis would exceed the evaluation
limit is refused with 422 `unprocessable` before those evaluations run. The engine decides
each reported cell in both the current and proposed world, so the work is up to twice that.

- `POST /admin/v1/changes` `{ kind, payload, reason }` (`reason` ≥ 20 characters) → 201 `Change`:
  `{ id, kind, payload, reason, makerId, createdAt, status: "pending", impact: Impact, broadens: boolean, stateDigest, weakensMandatory? }`.
  `stateDigest` is `v2.<record generation>.<SHA-256 of the State metadata>` for new proposals, so it changes only when
  the decision world changes, not when the proposal itself is stored. Pre-v2 proposals carried the bare SHA-256 of the
  whole canonical world; approval still verifies those with that exact legacy computation. Registration proposals use
  their per-resource bases as before. `weakensMandatory` (publish_policy only) lists every loosening of the mandatory models found by core
  `mandatoryWeakenings` (including any redefined relation, since relations are the reasons to know); such a change can only be approved by a security officer who is not the maker. A candidate
  that removes a compartment, role, relation or resource type still in use is refused (422). Biba no-read-down accepts
  optional `mandatory.bibaNoReadDownScope: "actions" | "reads" | "all"` (absent means `actions`, the old list behavior);
  the weakening check compares effective coverage on every declared action, so any narrowing requires security-officer approval.
  Protective rules count too: every ABAC `forbid` or `obligation` rule and every content-attribute (`abacContent`) `deny`, `mask` or `redact` rule
  of the published bundle must still be covered by a rule of the candidate that provably fires in every case it fired
  (same effect, same or wider `resourceTypes` / `actions`, a `when` the old one implies, an `unless` that implies the
  old one, the same content class) and imposes at least its obligations (redacted fields, masked classes,
  notifications, a field allowlist no wider). Anything else (removed, effect changed, scope narrowed, a condition or
  exemption changed in a way not provably stronger) is listed as `ABAC rule <id> removed or weakened` or
  `content rule <id> removed or weakened`; an action reclassified to another kind is listed as well. Every removal or
  non-identical edit of an existing CBAC (context) rule is conservatively listed as `context rule <id> removed or weakened`
  (selectors and conjoined requirements do not admit a general safe strengthening proof), so loosening or removing one
  requires the same independent security-officer approval. Adding a CBAC rule is security-relevant in impact preview
  but is not, by itself, a weakening. Impact variants partition the signals referenced by the old and new rules rather
  than relying on one country, address, device or freshness value; a change confined to one listed country or CIDR is
  therefore visible in its own class. `broadens`, the stored preview and the approval-time staleness comparison all use
  this same analysis.
  `broadens` is true when the impact gains access (`impact.gained`) or loses an obligation on a cell that stays
  allowed (`impact.obligationsLost`). A change that only narrows access (`broadens: false`) is still queued: every
  change is reviewed by a second person in this MVP.
- `GET /admin/v1/changes?status=pending|applied|rejected` → items `Change` (with `checkerId`, `decidedAt`, `decisionReason` once decided).
- `POST /admin/v1/changes/:id/approve` `{ reason }` → 200 `Change` with `status: "applied"`.
  403 `forbidden` with `error: "self_approval"` when the caller is the maker; 409 `conflict` with
  `error: "stale"` when the state changed since the change was simulated (the maker re-submits).
- `POST /admin/v1/changes/:id/reject` `{ reason }` → 200 `Change` with `status: "rejected"`.

### 3.5.1 Approvals inbox: approval modes, bulk decisions, snoozes

Each approver has an approval mode, `individual` (the default: one change at a time) or `list` (may also decide several
changes with one note). It is kept per console user id (the password account name or the OIDC/SAML id claim) in the
`approval_prefs` document (PostgreSQL `gate_doc` row, or `DATA_DIR/approval-prefs.json`, mode 0600, in file mode),
with each user's snoozes. Erasing a person (§3.9) drops their mode and snoozes, and a mode they set then names their
pseudonym. Like every admin call these routes need the session cookie, `X-CSRF-Token` on writes and
the per-principal rate limit; in cluster mode a follower forwards them to the leader, and a replica forwards them too.

- `GET /admin/v1/inbox` (any console role) → `{ approvalMode, snoozes: [{ item, until }] }`: the caller's own mode
  and the snoozes still in force. The console reads its mode here.
- `GET /admin/v1/approval-modes` (access_admin, security_officer) → `{ items: [{ id, mode, setBy?, at? }] }`: every
  local holder of `approver` or `security_officer`, plus every id with a stored mode (with SSO, an approver known only
  to the identity provider appears once a mode was set for them).
- `PUT /admin/v1/approval-modes/:userId` `{ mode: "individual" | "list" }` (access_admin, security_officer, for any
  id including their own) → 200 `{ id, mode, setBy, at }`. Takes effect at once (not a two-person change) and is
  audited as `security` / `approval_mode_set`, the target as the row's `subject` (pseudonymised like every person id) and `{ from, to }` in `details`. An id of more than 256 characters, with
  surrounding space, control characters, or one of `__proto__`, `constructor`, `prototype` → 422; another mode → 422.
- `POST /admin/v1/changes/decide` `{ ids, approve: boolean, reason }` (approver, security_officer, in `list` mode
  only, else 403 `individual_mode`) → 200 `{ approve, results: [{ id, ok, status?, error?, message? }] }`. `ids`: 1 to
  50 distinct change ids, else 422; `reason` follows the rule of a single decision note. The ids are decided one after
  the other through the same path as `POST /admin/v1/changes/:id/approve|reject` (the `erase_subject` approval
  included), so every check of a single decision holds per item (maker, beneficiary, credential holder, officer-only,
  stale state, break-glass) and each decided change gets its own `approve` / `reject` audit row. A refused item does
  not stop the others: it is reported with its error code and message, and the batch's refused items are audited in one
  `change` / `refused` row, `{ route, approve, refused: [{ changeId, error }] }`. Because an approval changes the state, a second ordinary approval in the same batch is refused `stale`
  exactly as it would be alone; rejections, and registrations whose resources do not overlap, are unaffected. Only
  changes: a break-glass id is `not_found`.
- `POST /admin/v1/inbox/snoozes` `{ item, until }` → 201 `{ item, until }`. `item` is `change:<id>` or
  `emergency:<id>` of an item the caller can see (emergencies: access_admin and security_officer), else 404; `until`
  is a `YYYY-MM-DD` day strictly after today and at most 30 days ahead (server clock, UTC), else 422. The item is
  hidden for this user only, until that day or until it changes (a change decided, an emergency reviewed or revoked):
  the server stores the item's version and treats any other version as un-snoozed. At most 500 per user. Audited as
  `change` / `snooze`.
- `DELETE /admin/v1/inbox/snoozes/:item` → 200 `{ item }`, audited as `change` / `unsnooze`; 404 when it is not
  snoozed.

### 3.6 Break-glass
- `POST /admin/v1/break-glass` `{ subjectId, resourceId, reason, hours, network? }` (`network` defaults to `trusted` for
  admission only: the network condition is enforced again on every access; the opener cannot be the subject) (`reason` ≥ 20 chars, `0 < hours ≤ 4` and not above the bundle's `needToKnow.breakGlassMaxHours`) →
  201 `{ id, subjectId, resourceId, reason, openedBy, openedAt, expiresAt, status: "active" }`. Applied at once (an
  emergency), notified, queued for review. An id matching more than one subject or resource is refused with 422.
  One emergency per (subject, resource type, resource id) at a time: `409 break_glass_pending` while an earlier one
  for the same pair is still active (not revoked and not expired) or has not been reviewed (by a security officer, or the access_admin fallback below), so a
  revoked or expired emergency must be reviewed before the pair can be opened again (a re-open never extends the time
  box nor undoes a revoke).
  422 `unprocessable` with `details` = the mandatory rule ids when the
  subject would still be denied by BLP, compartments, Biba or the network condition: break-glass gives a reason to
  know, nothing else (any other remaining deny: 422 with its rule ids).
- `GET /admin/v1/break-glass` → `{ active: [...], toReview: [...], reviewed: [...], fallbackReview: [ids] }`;
  `fallbackReview` lists the emergencies the caller may revoke or review only as the access_admin fallback below.
- `POST /admin/v1/break-glass/:id/revoke` `{ reason }`; `POST /admin/v1/break-glass/:id/review`
  `{ outcome: "justified" | "escalated", note }`. Never by the person who opened it nor by its subject
  (`403 self_approval`). Done by a security officer; when no security officer other than the opener and the subject
  exists (the local console accounts holding `security_officer`), an access_admin who is neither may do it, so the pair
  is never locked. Otherwise an access_admin gets `403 forbidden`. When OIDC or SAML sign-in is configured, officers
  may exist only at the identity provider, so the fallback is never offered (fail closed): keep a second security
  officer able to review, or the pair stays locked until one is. The audit row (`break_glass` `review` / `revoke`) records
  `reviewerRole` (`security_officer` or `access_admin`) and `fallback` (true for the access_admin fallback).

### 3.6.1 Break-glass notices (outbound webhook)

| Variable | Effect |
|---|---|
| `BREAK_GLASS_WEBHOOK` | Receiver, https only (credentials or a query string in the URL are refused at start). Unset with the secret: no notice. |
| `BREAK_GLASS_WEBHOOK_SECRET` | HMAC-SHA256 key shared with the receiver, at least 32 characters. Never sent, never logged. |

- Sent when an emergency access is **opened**, **revoked**, or **expires**. Expiry is found by a check every minute
  (`expiresAt` passed, not revoked): it is audited as `break_glass expire` (actor `system`), marked on the emergency
  (`expiryNotified: true`, so a restart does not notify it again), committed, then notified.
- `POST`, `Content-Type: application/json`, body
  `{ "type": "break_glass", "id": "<notice uuid>", "event": "opened|revoked|expired", "emergencyId", "subjectId",
  "resourceId", "actorId", "at" }`: ids and the event time only, never the reason. Headers
  `X-Qadamar-Timestamp: <unix seconds>` and `X-Qadamar-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>`;
  the receiver checks it in constant time and refuses old timestamps (five minutes is usual).
- Never on the request path: the request answers first, the notice is sent in the background. Redirects are refused;
  each attempt times out after 10 s; up to 5 attempts, backoff 1 s doubling (30 s cap). Every attempt carries the same
  notice `id`, for deduplication. After the last failed attempt: audit `break_glass notify_failed deny
  {id, event, attempts, error}` (`error` is `HTTP <status>`, `timeout` or `transport error`) and
  `gate_break_glass_notices_total{outcome="failed"}`; a delivered notice counts as `outcome="sent"`. A notice in flight
  when the process stops is lost (its event is in the audit).

### 3.7 Access reviews
- `GET /admin/v1/reviews` → `{ items: [ { tupleId, subject, resource, relation, validTo, daysLeft, grantedBy, reason } ] }`
  (grants and allocations ending within 30 days, plus all grants older than 90 days); and, for a security officer,
  `roleAssignments: [ { subject, role, notBefore?, notAfter, daysLeft } ]`: the time-bound role assignments not yet expired that end within 30 days (read-only; change them with `update_subject`).
- `POST /admin/v1/reviews/:tupleId` `{ decision: "certify" | "revoke", reason, newValidTo? }` → 201 `Change`
  (certify = an `add_tuple` extension written with `notBefore` / `notAfter`, revoke = `remove_tuple`; both go through §3.5).

### 3.8 Compliance
- `GET /admin/v1/compliance` → `{ frameworks: [ { id, name, controls: [ { id, title, enforcedBy: [rule ids], evidence: { decisions, denies, lastSeen } } ] } ] }`
  Frameworks in the MVP: NIST SP 800-53 Rev. 5 (AC-3, AC-4, AC-5, AC-6, AC-16, AC-24, AU-2, AU-9, AU-10) and ISO/IEC
  27001:2022 Annex A (5.15, 5.18, 8.3, 8.15). UAE IA control ids are left empty, to be mapped from the TDRA text.
- `GET /admin/v1/compliance/export` → `{ pack: {...}, signature: "<detached JWS>" }` (Ed25519), metadata only.
  `GET /admin/v1/compliance` also lists `evidenceFrameworks: [ { id, name } ]`, the frameworks below.
- `GET /admin/v1/compliance/evidence?framework=<id>[&pseudonymise=1]` (security officer, auditor) →
  `{ pack, manifest, signature }`: an evidence pack for one of `iso27001`, `iso27017`, `iso27018`, `iso27701`,
  `iso42001`, `iec62443-4-1`, `iec62443-4-2`, `soc2`, built from live data (`packages/pdp-http/src/admin/evidence.ts`).
  `pack.sections`: `configuration` (the node's secure-configuration baseline: which controls are on, origins only,
  never a secret, plus `productionDeviations`, what `GATE_PROFILE=production` would refuse), `time` (server time,
  whether the clock is pinned, and for the last 20 anchors the TSA time minus the anchored row's time; over several
  chains, the newest anchored head's row), `policy` (version, state digest, signed publications, Clark-Wilson
  certifications), `audit` (verification of every chain, this node's head and, in cluster mode, `heads` per chain,
  anchors with the SHA-256 of each token and their `heads`), `accessReviews` (grants due and review decisions), `approvals` (every
  change: maker, checker, status, broadening), `breakGlass` (emergencies and their audit rows), `keys` (signing keys
  and PEP credentials, no secret), `securityEvents` (`security` audit rows: rotations, IVP runs, TOTP, exports) and
  `ci` (references to the gate, not results). Audit-derived lists keep the newest 1,000 rows with `complete: false`
  when older ones were left out (newest by time across every chain in cluster mode). `pack.framework.controls` names, per control, the sections that hold its live
  evidence; every other control is in the mapping document `pack.framework.mapping` (`docs/compliance/`).
  `manifest = { format, framework, generatedAt, packSha256, sections: { <name>: sha256(canonical(section)) }, verify }`;
  `signature` is a detached EdDSA JWS over `canonical(manifest)` by the decision-token keyring (current JWKS at
  `/.well-known/jwks.json`). Archive the keyring with the pack: its public verification history and `introducedBy`
  links keep old manifests verifiable after a rotation, even after those keys leave the live JWKS (`Tokens.verifyManifest`). This offline
  evidence exception does not extend the 300 s acceptance window for online policy or key-introduction signatures.
  `pseudonymise=1` replaces person ids (subjects, actors, makers, checkers, owners of
  emergencies) by `ps.<32 hex>` = HMAC-SHA256 under a key derived from `SIGNING_KEY_SEAL` (HKDF info
  `qadamar/audit-pseudonym/hmac-sha256/v1`; without the seal, a per-process key). Each export is audited as
  `security evidence_export {framework, packSha256, pseudonymised}`. A pack is evidence an auditor can test; it is not
  a certification, an attestation or a statement of compliance.
- `GET /admin/v1/privacy/subjects/:id` (security officer) → `{ subjectId, generatedAt, subjects, tuples, emergencies,
  certifications, publications, changes, audit: { rows, complete, retention } }`: what the control plane holds about one
  subject id (right of access), as the person concerned and as the person who acted: grants held or made (`grantedBy`),
  emergencies opened for, by or reviewed by the id, certification records certified or approved, policy publications
  published or approved, changes made or checked. Audit rows are selected by `subject` and by `actor` (the newest 1,000
  of both, merged), resolving the current per-subject pseudonym.
  The report is audited as `security subject_access_report` with that subject.
- `POST /admin/v1/privacy/subjects/:id/erasure` (security officer, CSRF) → `201` with a pending `erase_subject`
  change (two-person rule): nothing is erased until a **different** security officer calls
  `POST /admin/v1/changes/:changeId/approve` `{ reason }`, which answers the applied change with
  `erasure: { pseudonym, erased: true, changeId }`. Both the proposal and the approval are refused (`403 self_erasure`)
  when the subject is the proposer or the approver, `409 open_break_glass` while the subject has unreviewed active
  break-glass access, `409 pending_reviews` while one of the subject's grants is due for review, and `404` when no
  live mapping exists. New audit rows store `"ps.<32 hex>"`, HMAC-SHA256 of the raw id under an independent random
  per-person key. Person ids are pseudonymised in every new row: `subject`, the `actor` (except the technical actors `pep`, `pep:<credential>`, `system`, `scim`, `bootstrap`, `unknown`, and `unknown:<HMAC>`: a failed password or OIDC sign-in by an id that has no mapping is hashed under one key derived from `SIGNING_KEY_SEAL`, so a username spray mints no mapping rows), and the `makerId`, `checkerId`, `approvedBy`, `openedBy`, `subjectIds` details; a refused request to a privacy or SCIM `Users` route is audited with `{id}` in place of the path id. `audit-subjects.json` (file mode) or `gate_subject_identity`
  (PostgreSQL) is the only raw-id/key mapping and sits outside the chain; both are checked at load (each pseudonym must
  be the HMAC of its id under its key, else the start fails closed). The approval deletes that mapping and atomically
  appends `security subject_erased { pseudonym, changeId, approvedBy }` (`approvedBy` itself a pseudonym); the applied
  change keeps `{ pseudonym }` instead of the raw id. Chained rows and hashes do not change. While a mapping exists the
  audit listing and subject reports show the raw id for display; the SIEM push, `/audit/export` and the stored rows
  keep the pseudonym. After erasure the raw id resolves nothing. Legacy rows that already contain a raw id cannot be
  rewritten; use sealed retention or deployment disposal for those. New activity for the same id creates a fresh
  mapping. See `docs/compliance/iso27701.md` for what an auditor can and cannot prove afterward.

### 3.9 Audit
- `GET /admin/v1/audit?effect=allow|deny&rule=&subject=&resource=&type=decision|change|session|break_glass|security|simulation&limit=50&cursor=` →
  `{ items: [ AuditRecord ], next: "<cursor>" | null }`. Rows come chain by chain (§3.9.1, cluster), each chain in `seq`
  order; `cursor` is the previous `next`: a `seq` while the row is in chain `"0"` (as before), `"<node>:<seq>"` otherwise.
  `type` accepts exactly the row types the server writes (`AUDIT_TYPES` in `packages/pdp-http/src/audit.ts`): `decision`,
  `change`, `session`, `break_glass`, `security` and `simulation` (an admin request refused outside the other families);
  any other value is a 400.
- Decision-plane refusals: a failed PEP credential (401) on `/access/*`, `/x/*` or `/xacml/*`, and any refused
  `/x/v1/tokens/consume`, write a `security` row `{ action: "refused", effect: "deny", details: { route, error, source,
  suppressedSinceLastRow? } }`. At most one row a minute per source address, route family and error (real clock), so a
  guessing run is visible without flooding the chain; the next row counts what was left out. Refused non-GET admin and
  SCIM requests, including invalid SSO logout requests and malformed console login bodies, use the same cap. The general
  admin/SCIM refusal path also separates keys by authenticated actor (or `unknown`).
- `AuditRecord`: `{ node?, seq, ts, type, actor, action, subject?, resource?, effect?, rules?, policyVersion?, details?, prevHash, hash }`
  where `hash = sha256(prevHash + canonical(record without hash))` and the first `prevHash` of each chain is 64 zeros.
  `node` (hashed with the rest) names the node whose chain holds the row; rows of chain `"0"` (a single node, and every
  row written before chains were per node) have none. New subjects are per-subject keyed pseudonyms (§3.8); the raw id
  is never added to a new chained row. After sealed retention the first retained row follows the authenticated segment
  head rather than the genesis, and `seq` remains monotonic rather than being renumbered.
- `GET /admin/v1/audit/verify` → `{ verified: true, length }` or `{ verified: false, length, brokenAt: seq, node? }`;
  `length` counts retained rows over every chain, `node` names the broken chain when it is not `"0"`.
  PostgreSQL responses also contain `checkedAt`, the wall-clock time of that check; a cached result can be up to 60 seconds old;
  and `fullChain`, false until every retained chain was verified from its genesis or latest sealed head since the node started (§3.9.1).
  An anchored head (3.9.2) that no longer matches the log breaks the chain: a full rewrite or a truncation shows.
- `GET /admin/v1/audit/anchors` (security officer, auditor) → `{ tsa, lastError, items: [ { seq, hash, tsa, genTime, token } ] }`,
  `token` being the authority's RFC 3161 TimeStampToken (DER, base64).
- `GET /admin/v1/audit/verification` (security officer, auditor; no parameters, else 400) → `{ manifest, signature }`:
  the verification material for an offline check of the export (`packages/pdp-http/src/admin/audit-verification.ts`).
  `manifest` is `{ format: "gate-audit-verification/1", product, generatedAt, generatedBy, verification, heads, segments,
  anchors, tsa, verify }`: `verification` is the server's own result (as `/audit/verify`, after a recheck), `heads` the
  verified head `{ seq, hash }` of every chain (`"0"` with one chain), `segments` the sealed retention segments (§3.9.4)
  without their `mac` (it needs the deployment seal key), `anchors` every anchor with `tokenSha256` instead of the token
  (tokens from `/audit/anchors`) and its `heads`; `tsa` the authority's origin. `signature` is a detached EdDSA JWS over
  `canonical(manifest)`, keys at `/.well-known/jwks.json`, as for evidence packs. Each call writes
  `security audit_verification_export { manifestSha256, chains, anchors }`; it counts against the console rate limit.
  Fetch the manifest first, then export the rows with `until=` its heads (they must reach them and stop there) and the
  anchors, then run
  `node scripts/audit/verify-export.ts --rows <ndjson> --manifest <json> --jwks <json> [--anchors <json> --tsa-ca <pem>] [--pin <jwks> [--keyring <json>]]`
  (docs/MANAGED-OFFER.md §13): signature, every chain recomputed from its genesis or sealed head up to its signed head
  and named by the manifest's heads, no row after a head (an unauthenticated tail: anyone can append rows with
  recomputed hashes, so it fails the check, exit 1), heads present, each anchor consistent with the rows and its token the one signed, and `openssl ts
  -verify` of each token. `ok` (exit 0) only when a verified token or a pinned signing key anchors the evidence;
  consistent but unanchored evidence is `self-consistent only (not anchored)`, exit 3.
- `GET /admin/v1/audit/export?from=<position>&until=<position>&limit=<1..1000>` (security officer, auditor) → `200 application/x-ndjson`:
  one `AuditRecord` per line from `from` (inclusive, default 1), `limit` default 100, and the header
  `X-Audit-Next-From` to pass as the next `from`. `from` is a `seq` while there is only chain `"0"` (as before), else a
  per-chain list `"<node>:<seq>,<node>:<seq>"` (a chain not listed starts at 1); rows come chain by chain, each in `seq`
  order, so no row is skipped while other nodes keep appending. An empty body means nothing newer yet. `until` (same
  syntax, inclusive, optional) is the last `seq` to export of each chain and leaves out the chains it does not name:
  an auditor passes the signed manifest's heads (`<node>:<seq>,...`, `"0:<seq>"` with one chain) so the export stops
  exactly there. Other or repeated parameters, a malformed or repeated chain → 400.
  `pseudonymise=1` replaces person ids as in the evidence pack (§3.8) and adds `pseudonymised: true` to each row: such
  rows no longer hash to their `hash`, so the chain is checked on the server (`/audit/verify`), not by the collector.
  The rows are the hash-chained records themselves, so a collector can re-run the chain check; on PostgreSQL only
  committed rows are exported.

### 3.9.1 Storage, failover and atomic commit

| Variable | Effect |
|---|---|
| `DATABASE_URL` | PostgreSQL control plane. Must connect directly to the primary: a lagging replica or transaction-mode pooler can produce false tamper results. Unset: files in `DATA_DIR`, one node, demo only. `ssl`/`sslmode` and TLS file parameters are refused here so they cannot conflict with `DATABASE_TLS`. |
| `DATABASE_TLS` | `verify-full` (production default), `require`, or `disable`. `verify-full` verifies the server certificate chain and hostname and is mandatory for every non-local production host. `require` encrypts without server authentication. `disable` is allowed only outside production or for loopback/unix-socket hosts; `verify-full` is not meaningful on a unix socket and is refused there. The same policy covers the writer, audit reader, cluster rate-limit and synchronisation connections, replica feed/audit ingestion, preflight, migration and retention. |
| `DATABASE_TLS_CA_FILE` | Optional PEM CA bundle for `verify-full`; unset uses Node's system CA store. With a private CA, the server certificate must chain to it and name the host in `DATABASE_URL`. |
| `DATABASE_TLS_CERT_FILE`, `DATABASE_TLS_KEY_FILE` | Optional PEM client certificate and private key, set together, for PostgreSQL mutual TLS. Not valid with `disable`. Backup and restore map the same files to `PGSSLCERT`/`PGSSLKEY`. |
| `SIGNING_KEY_SEAL` | Required with `DATABASE_URL` (§3.10): the signing keyring is stored sealed in PostgreSQL. |
| `ALLOW_CLEAR_SIGNING_KEYS` | `true`: start with `DATABASE_URL` and no `SIGNING_KEY_SEAL`, the private signing keys then stored in clear in `gate_doc`. Unset: such a start is refused. |
| `GATE_CLUSTER` | `true`: every node serves the PDP API at once; one leader holds the admin plane (below). Unset: active/standby, as before. |
| `GATE_NODE_ID` | This node's audit chain, 1..64 of `[A-Za-z0-9_.-]`, first a letter or digit, unique per running process. Default `0`, the chain earlier versions wrote. Keep it stable across restarts (on Kubernetes the cluster component runs a StatefulSet and uses the pod name, `gate-0`, `gate-1`). |
| `GATE_MAX_STALENESS_MS` | Cluster: a node refuses decisions (503) once it last confirmed the shared state longer ago than this, 100..60000, default 2000. |
| `GATE_ADVERTISE_URL` | Cluster: this node's internal address (http or https), published while it leads; followers forward admin, SCIM and resource registration requests to it, or return it in their `409 not_leader` answers. |
| `TSA_URL` | RFC 3161 timestamp authority (https, or loopback for tests). Unset: no anchoring. |
| `ANCHOR_INTERVAL` | Seconds between anchors, at least 60, default 3600. |
| `TSA_CA_FILE` | The authority's CA (PEM). Set: each token's signature and chain are checked with `openssl ts -verify` before it is kept. Unset: checked offline only. |

- Policy/workflow metadata, individual subject/resource/tuple rows, decision tokens and audit rows are written in
  **one transaction**, before the request is answered. Concurrent requests staged before a writer starts share that
  transaction. A decision-only group writes its chained rows, derived metadata and any decision tokens and BLP marks in
  one prepared statement: PostgreSQL's implicit transaction for that statement is durable before it completes, so no
  separate `BEGIN` or `COMMIT` round trip is needed. Other batches keep an explicit transaction. A record write upserts
  or deletes only its changed rows and appends their change-log entries; unchanged metadata and records are not
  rewritten. A decision, a change or a refusal the database did not take is never answered as done. File mode keeps its
  atomic whole-document JSON rewrite.
- **Active/standby (default).** Several nodes may share the database: the active one holds a session advisory lock, the
  others wait in `listen()` without opening their port, and the first to get the lock reloads everything and serves.
  A health check on the port is enough for the load balancer.
- **Cluster (`GATE_CLUSTER=true`): decisions on every node, one writer for the admin plane.**
  - Every node serves `/access/v1/*` (evaluation, evaluations, search), `/x/v1/*` (explain, filter, token consume) and
    `/xacml/v3/authorize`. One node, the **leader**, holds the advisory lock and alone writes the state documents:
    proposals, approvals, policy publication, break-glass, PEP credentials, signing keys, SCIM, resource registration
    (§2.2), lockouts, the SIEM cursor and the audit checkpoint. It also anchors, pushes to the SIEM and sends break-glass
    expiry notices.
  - **Followers forward every `/admin/*`, `/scim/*` and `/x/v1/resources*` request to the leader**, so a plain Service or
    load balancer over all nodes works for the console, OIDC callbacks, SCIM and resource registration. The follower reads the body (1 MB at most, as any
    node; a larger one is refused there and never sent on), sends the request (method, path and query, body, cookies,
    `X-CSRF-Token`, other end-to-end headers; hop-by-hop headers dropped) to the leader's `GATE_ADVERTISE_URL` as read
    from `gate_sync`, and streams the answer back; it writes no audit row, the leader audits as for a direct request.
    Only an http(s) origin is contacted (no credentials, path, query or fragment; anything else gives the `409`
    fallback, and is refused at start). The hop is authenticated: an `X-Qadamar-Hop` header
    `v2.<ms>.<nonce>.<client>.<node>.<mac>`, HMAC-SHA256 over the JSON array of those five fields, the method, the path
    with its query and the base64url SHA-256 of the body, with a key derived from `SIGNING_KEY_SEAL` (HKDF, label
    `qadamar/cluster-hop/hmac-sha256/v1`). The leader accepts it only within 30 s of its wall clock and once
    (nonce remembered), for that exact method, path and body, and then takes the client address from it (rate limits,
    sign-in throttle, audit); a hop that does not verify is refused with `401` and counts against the sending
    address's rate limit. The hop between nodes is plain http unless the nodes serve TLS themselves: keep it on the
    internal network (the cluster component's NetworkPolicy admits only Qadamar pods on port 8787). Timeouts: no answer headers within 10 s, or an exchange
    longer than 30 s, ends it; an unreachable leader gives `503 unavailable` with `Retry-After: 1`.
  - **Fallback: `409 { error: "not_leader", leader }`** (`leader`: the leader's `GATE_ADVERTISE_URL`, or null), read
    or write, without an audit row, when the follower does not know the leader (none published yet), has no
    `SIGNING_KEY_SEAL`, or receives a request that already carries `X-Qadamar-Hop` (a node never forwards twice: no loop
    while leadership moves). `GET /leaderz` answers `200 { leader: true, node }` on the leader and `503` elsewhere, for
    a load balancer's admin pool; `/readyz` adds `role` and `node`.
  - **Keeping followers current.** Each metadata or record write by the leader increments `gate_sync.version`; a record
    write also increments the dense `gate_sync.records` generation and appends its rows to `gate_state_change`. The same
    transaction sends `NOTIFY gate_sync`. Every node listens on a dedicated connection and also polls every
    `min(500, bound / 4)` ms. In one repeatable-read snapshot a follower reloads the small documents (policy/workflow
    state, credentials, keyring, lockouts, SCIM, SIEM cursor) and applies only record generations after its position,
    patching its subject/resource lookups and tuple graph rather than reloading the world. A missing generation falls
    back to a full ordered row snapshot. A node records the time each read was sent once everything committed before it
    is applied; **a decision is refused with 503 when that time is older than `GATE_MAX_STALENESS_MS` (default 2 s)**,
    so a node that is behind, or lost its notification connection, never decides on policy older than the bound. It
    reconnects at the next tick and catches up; `/readyz` is 503 meanwhile. Each reload checks the policy bundle's
    signature against the keyring as a start does (§3.10): a failure is not decided on (the node is stale at once and
    retries every tick), and a follower that cannot verify it does not take the lead. A follower never writes shared
    state: a request-only document change (a PEP credential's last use) stays in memory until the next reload.
  - **Leader failover.** Followers keep deciding: they need the database, not the leader. Each tick a follower tries
    the lock; the first to get it reloads the documents and anchors (the old leader's session ended, so all it committed
    is visible), publishes its `GATE_ADVERTISE_URL` and serves the admin plane. Console sessions are rows of `gate_session` (§3.1):
    the new leader accepts the sessions opened on the old one.
  - **Decision tokens** are rows of `gate_token`, inserted with the issuing decision's audit row. Consumption locks the
    row (`SELECT ... FOR UPDATE`): a second node consuming the same token waits for the first transaction and then sees
    it used, so a token is consumed once across all nodes. In cluster mode the consuming transaction then takes a
    transaction advisory lock on the token's resource (`pg_advisory_xact_lock`, type and id hashed) and loads every
    performed action committed since this node's last synchronisation, so separation of duty is decided on every
    reservation of that resource committed before it: two distinct tokens for conflicting actions (maker on one node,
    the same person approving on another) are never both consumed. Cost: two round trips per consumption, and
    consumptions on one resource are serialised (scripts/bench/consume.ts; CHANGELOG). The use, the reservation
    (`gate_performed`, numbered under the `gate_sync` row lock so every node reads them in commit order) and the audit
    rows commit together.
    An outcome report locks the `gate_sync` row first, reads what is stored for the reservation, and appends the
    outcome as a row of its own (`gate_performed` stays append-only; `ref`, `kind` and a unique `(ref, kind)` index allow
    one reservation and one outcome per id), so it can be sent to any node and a second report sees the first.
    Expired tokens are deleted by the leader once a minute.
  - **PDP sessions and high-water marks** live in `gate_blp_session` (PDP sid, subject and credential claims, real-clock
    last use and expiry) and `gate_blp_mark` (hashed subject/credential scope, subject, level, start and last use).
    Administrative revocation tombstones live in the `gate_doc` row `blp_revocations` and in the signed replica feed.
    Open, close and revocation take the sid/subject advisory locks and commit with their audit rows, making the cap and
    revocation cluster-wide and immediate on later decisions. A mark-relevant decision verifies the token on the same locked writer connection, then upserts the
    mark with its audit rows before releasing the lock. Decision-token consumption takes the `sid` mark lock in its
    existing token transaction (§2).
  - **Rate limits are shared.** `gate_rate_limit` holds one token bucket per SHA-256-hashed IP/principal key. A node
    atomically leases `min(1000, ceil(capacity / 10))` tokens in one statement (or the larger cost of one request) and
    consumes that lease locally: there is no database round trip per request while capacity remains. Refill uses the
    database clock. Configure the same `RATE_LIMIT_PER_MINUTE` and `PEP_RATE_LIMIT_PER_MINUTE` on every node. Leases can
    strand capacity but cannot overspend the shared bucket: with N nodes and lease size B, at most N(B−1) already-leased
    tokens per key can sit unused on other nodes, bounding under-admission at that instant. A 429 caches its Retry-After
    instead of querying per refusal. Rows idle for an hour are deleted during the next lease sweep (at most one a minute
    per node). A lease/database failure fails closed with 503 and the node's normal fail-stop path. File mode and
    active/standby PostgreSQL keep the original process-local buckets. The decision counter remains per node.
- **One hash chain per node.** Each node appends only to its own chain (`gate_audit.node`, a per-node `seq`), in the
  same transaction as the changes of its requests; a second process started with the same `GATE_NODE_ID` waits for the
  first (advisory lock on the id), so no chain has two writers, and a node that restarts with the same id continues its
  chain. **Retiring a node id** (scaling down, renaming a node) leaves its chain in place: still verified at every
  start and recheck, still covered by anchors, the checkpoint, listings and export, but with no new rows; a node
  started later with that id continues it. A node id that changes at every restart (a Deployment's pod names) starts
  a new chain each time: correct, but the number of chains grows, hence the StatefulSet in the cluster component. Every
  chain is verified from its genesis like the single chain was; a recheck also requires each other chain to extend the
  head it saw last, so a rewritten, removed or truncated row in any chain is caught and `verify` names the chain.
  The checkpoint, anchors, counters, listings, export and SIEM push cover every chain. Upgrading keeps the existing rows
  untouched as chain `"0"`, which a node with the default `GATE_NODE_ID` continues.
- **Fail-stop.** If a write fails or the connection drops, the node answers `503` from then on and exits
  (`main.ts`), because its memory may be ahead of the database; a standby or a restart reloads from the database.
- Tables `gate_doc`, `gate_audit`, `gate_audit_meta`, `gate_anchor`, `gate_audit_segment`, `gate_subject_identity`,
  `gate_sync`, `gate_token`, `gate_performed`, `gate_session`, `gate_blp_mark`, `gate_blp_session`, `gate_retired`, `gate_subject`,
  `gate_resource`, `gate_tuple`, `gate_state_change` and `gate_rate_limit` (records stored as JSON text) are created by
  their owner, with row-level security forced. Record tables have keys and order/lookup indexes. `gate_audit_meta` is derived filter
  metadata, repaired from the chained rows at startup and checked with them on recheck. Every repair is logged and
  recorded as `security` / `meta_repaired`. `gate_audit_segment` holds authenticated retention seals;
  `gate_subject_identity` is the separate raw-subject/per-subject-key mapping, stored with the id JSON-encoded so every
  valid string round-trips. Its `used_at` is the last use (written at most once a day per id and node); a world
  subject's mapping, and every mapping stored before `used_at` existed, has `NULL` and is never purged. Once a day (the
  leader on PostgreSQL, every file-mode node, independent of `AUDIT_RETENTION_DAYS`) the mappings of ids that are not
  world subjects and were unused for 90 days (`SUBJECT_IDLE_DAYS`, plus one day of last-use granularity) are deleted and
  `security subject_mappings_purged { count }` is chained (actor `system`, no id). Their rows stay and verify but no
  longer resolve; the same id later gets a fresh mapping. Current world subjects are pinned at each run, so an id that
  is or becomes a world subject is never purged. Actors are never purged: an id ever used other than as the subject of a
  PEP decision row (any actor, a person-id detail such as `makerId` or `openedBy`, a non-decision row's subject) is
  pinned (`NULL`) the moment it is used that way, and local console accounts are pinned at each run.
  **Production layout:** an owner role runs the schema (`SCHEMA` in `packages/pdp-http/src/postgres.ts`, or a first start
  under that role); the service connects as another role that is not a superuser. `serviceGrants(role)` gives it
  `SELECT, INSERT, UPDATE` on `gate_doc` and `gate_audit_meta`; `SELECT, INSERT` on `gate_audit`, `gate_anchor`,
  `gate_performed`, `gate_retired` and `gate_state_change`; `SELECT` on `gate_audit_segment`; `SELECT, UPDATE` on
  `gate_sync`; and `SELECT, INSERT, UPDATE, DELETE` on `gate_subject_identity`, `gate_token`, `gate_session`,
  `gate_blp_mark`, `gate_subject`, `gate_resource`, `gate_tuple` and `gate_rate_limit`. The mapping is erasable by design.
  **The service never receives `DELETE` on `gate_audit` or `gate_audit_segment`**, and cannot rewrite the record change log. Retention
  is the owner-only operation in §3.9.4. **Upgrading from 0.4.2 or earlier** adds `gate_session` and `gate_blp_mark`,
  0.5.0 adds `gate_retired`, after 0.6.0 the audit seal/mapping tables and the four record tables, and after 0.7.0 the
  disposable shared rate-bucket table: stop every node,
  run `SCHEMA` and the grants as the owner, then start. Existing chained rows are not rewritten. The first target start
  imports the old whole-document records in one idempotent transaction, preserving array order and therefore pending
  state digests. A start against an older schema owned by another role is refused with that instruction. If the service
  role owns the tables (simplest setup), `UPDATE`, `DELETE` and `TRUNCATE` are revoked from it on append-only evidence,
  but an owner can grant them back. A compromised service role can alter derived metadata (forcing the tamper flag) or
  erase mappings (availability/privacy denial), but cannot forge chained rows or seals.
- Audit scans, listings and scoped counts use a separate read-only connection with the same 15 s statement timeout,
  so they do not occupy the decision writer queue. Reader failures are logged and reconnected with backoff; three
  consecutive failed periodic rechecks stop the node. Every returned audit row is checked against its metadata. Once
  tampering is detected, audit listings, scoped counts and compliance evidence answer 503. A metadata change that hides
  a row from a filter is caught at the next recheck: within five minutes, or at the next anchoring.
- Overview and compliance show the last completed verification result, not a live chain check. PostgreSQL rechecks run
  every five minutes and at anchoring; `/audit/verify` starts at most one recheck per minute and reuses the last result
  inside that interval, with concurrent callers sharing the same scan. Its `checkedAt` field shows the age of that result.
- Queries time out after 15 s and TCP keepalive starts after 10 s, so a half-open connection ends in fail-stop.
- **Security material is in the database.** The console accounts and PEP credentials (`credentials`), the signing
  keyring (`signing_keys`), the console lockouts (`lockouts`), the SCIM credential (`scim`) and the SIEM cursor
  (`siem`) are `gate_doc` rows, written in the same transaction as the request's state and audit rows. A PEP
  credential rotated or revoked, a signing key rotated, a lockout or a SCIM credential minted on the active node holds
  on whichever node takes over, with no file to copy. The keyring's private keys are sealed with `SIGNING_KEY_SEAL`
  (never in clear in the database when it is set); without it the node refuses to start unless
  `ALLOW_CLEAR_SIGNING_KEYS=true`. Every node needs the same seal.
- **Migration from files.** The first start of this version against a database without a `credentials` row imports,
  once, whichever of `credentials.json`, `signing-keys.json` (or a legacy `signing-private.pem`), `lockouts.json`,
  `scim-credential.json`, `siem-cursor.json` and `approval-prefs.json` exist in that node's `DATA_DIR` and have no row yet (clear keys are
  sealed before they are written), and logs the list. From then on PostgreSQL mode neither reads nor writes these files,
  nor `signing-public.pem` (use the JWKS): delete them, or keep them offline, once the first start has committed.
  `INITIAL-CREDENTIALS.txt` is still written to the `DATA_DIR` of the node that seeds a fresh database.
- **File audit checkpoint.** With `SIGNING_KEY_SEAL`, `DATA_DIR/audit-checkpoint.json` authenticates
  `{ seq, hash, verifiedAt, mac }` after every append, using the same HKDF-derived checkpoint key as PostgreSQL. Every
  start and `/audit/verify` requires both the chain head and checkpoint HMAC to match; a rewritten whole chain,
  truncation, a missing, malformed or unreadable checkpoint, or a wrong key fails stop. A deleted checkpoint is never
  re-minted (that would authenticate whatever chain replaced the genuine one). Only an empty chain gets a fresh one.
  An older non-empty chain that never had a keyed checkpoint migrates once, explicitly: the start refuses and logs its
  head `seq` and `hash`; after reviewing the chain (and its anchors), the operator starts once with
  `AUDIT_CHECKPOINT_MIGRATE=<that hash>`, which authenticates exactly that head and chains
  `security checkpoint_migrated { seq, hash }`. The value is bound to the head, so it is spent as soon as the chain
  grows and never applies to a rewritten chain; remove it afterwards. Appending after a file replacement also refuses.
  A crash between the JSONL append and its atomic checkpoint rename leaves the checkpoint exactly one row behind: the
  next start accepts that single trailing row only if it chains from the authenticated head, re-checkpoints, and chains
  `security checkpoint_completed { seq, hash }`; two rows or more beyond the checkpoint fail stop. At runtime no such
  window exists (the in-memory head refuses any row written by another process). Without `SIGNING_KEY_SEAL` (demo only), no keyed
  checkpoint can be created: a full self-consistent rewrite remains detectable only by an external RFC 3161 anchor or
  an independent copy. Production requires both the seal and TSA anchoring; the TSA interval remains 3600 seconds by
  default (`ANCHOR_INTERVAL`).
- **Audit checkpoint and takeover.** After each successful full recheck the active node (the leader, in a cluster)
  stores the verified position `{ seq, hash, verifiedAt, counters, mac }` in the `audit_checkpoint` row (through the
  writer queue, after the commits before it); with several chains it is `{ heads: { <node>: { seq, hash } },
  verifiedAt, counters, mac }` and every check below applies to each chain it names. `counters` holds each chain's
  audit counters at that head (row count, rows per type, the compliance evidence counters), read in the same snapshot
  as the verified rows, so a start adds the rows after the checkpoint instead of aggregating the whole table.
  `mac` is HMAC-SHA256 over the canonical `{ seq, hash, verifiedAt, counters }` (or `{ heads, verifiedAt, counters }`) under a key derived from `SIGNING_KEY_SEAL` with
  HKDF-SHA256 (info `qadamar/audit-checkpoint/hmac-sha256/v1`; never the seal key itself), so a role that can
  write `gate_doc` cannot forge one. A wrong `mac` is tampering (the node refuses to start). Without `SIGNING_KEY_SEAL`
  no checkpoint is written or trusted; a checkpoint without `mac` (written before 0.3.0) is ignored and the whole
  chain is read. A checkpoint with a `mac` but no `counters` (0.4.2 and earlier) is used, its counters then
  aggregated from the table. **Every profile starts from the checkpoint, `GATE_PROFILE=production` included** (up to
  0.4.2 production read the whole chain before serving, so takeover time grew with the log; PERFORMANCE.md).
  A node that takes over checks, synchronously and before its port opens, instead of the whole chain: that rows
  `1..seq` all exist (one count), that the row at `seq` and every anchored row up to it hash to themselves and to the
  recorded hash, then every row from `seq` to the head (link, hash, metadata, with metadata repair as before).
  Startup work is the rows after the checkpoint (plus the anchored rows), not the log size. A checkpoint that does not
  match the stored chain (other hash, missing rows, malformed) is tampering: the node
  refuses to start. Missing metadata before the checkpoint falls back to the full start scan, which repairs it.
  Without a checkpoint (first start, upgrade from before 0.3.0, cleared, no seal) the whole chain is read before
  serving, as before.
- **Background verification of the whole chain.** Right after a start from the checkpoint the node verifies every
  chain from its genesis in the background, while serving (the same full recheck as every five minutes: links,
  hashes, metadata, anchors, expected heads, counters reloaded). Until it ends: `/readyz` answers 200 with
  `"audit": { "verified": true, "fullChain": false }`, `/admin/v1/audit/verify` adds `"fullChain": false`, and the
  metric `gate_audit_full_chain_verified` is 0; all three turn true/1 when it succeeds (log line `Audit background
  verification complete`). `/readyz` and `/audit/verify` reuse the start's result during that scan instead of waiting
  for it; anchoring waits for it, so no anchor timestamps a head before the whole chain verified. A start without
  checkpoint reports `fullChain: true` at once.
- **What is checked when.** At start: the checkpoint's `mac`, the presence of rows `1..seq`, the row at `seq` and the
  anchored rows, and every row after the checkpoint. In the background (right after start, then every 5 minutes, at
  anchoring, and at `/audit/verify` at most once a minute): every row of every chain from its genesis.
- **Detection window and failure path.** A row rewritten **before** the checkpoint (by a role that can update
  `gate_audit`) is not read at start. It is caught by the background verification: the window is its duration (about
  9 s per million rows on a laptop, PERFORMANCE.md), then the periodic rechecks keep it closed. On detection the node
  fails closed without exiting: the audit refuses every append, so decisions (audited before they are answered) and
  audited admin writes fail (500, never a decision); `/readyz` answers 503, so the load balancer drops the node; audit
  listings, counts and compliance evidence answer 503; `gate_audit_full_chain_verified` drops to 0; the log says
  `AUDIT INTEGRITY FAILURE: chain <node> breaks at seq <n>`; and the checkpoint row is set to `null`, so the next start
  (a restart or a standby taking over) reads the whole chain and refuses the tampered log. The node does not exit on
  purpose: a restart would refuse to start anyway, so exiting adds a restart loop and takes `/admin/v1/audit/verify`
  (with `brokenAt`) away from the responder (docs/handbook/operations/audit-tamper-response.md). A background
  verification that cannot read the database is retried by the periodic rechecks; three consecutive failures stop
  the node, as before. Anchors keep their meaning: an anchored row is checked at every start, checkpoint or not.
- High availability of the database itself (replicas, failover) and its encryption at rest are the hosting's: not
  provided here. Logical backup and restore of the `gate_*` tables: `scripts/ops/backup.sh` and `restore.sh`, with the
  drill and what it measured in [DEPLOY.md](DEPLOY.md).

### 3.9.2 External anchor of the audit (RFC 3161)

- Every `ANCHOR_INTERVAL`, when the chain head moved, the node checks the chain (and, on PostgreSQL, rereads it from
  the database), then sends **only the SHA-256 head hash** to the authority with a random nonce, checks the reply is
  granted, is for that hash and nonce, is dated within 10 minutes of the node's wall clock and (with `TSA_CA_FILE`)
  is signed under that CA, and stores the token (`gate_anchor`, or `anchors.jsonl` with files).
- **Several chains (cluster):** the leader anchors the set of heads it just verified: `heads = { <node>: { seq, hash } }`
  is stored with the anchor, the authority timestamps `sha256(canonical(heads))` and the anchor's `seq` is the sum of the
  head seqs. With only chain `"0"` the anchor is its head, as before. A stored `heads` that does not hash to the
  timestamped value, or a head missing or different in its chain, breaks verification.
- The chain no longer verifies, at start and in `verify`, if an anchored head is missing or different. A database row
  changed behind the node is caught within five minutes (and at each anchoring): the head is not anchored,
  `lastError` says why, `verify` turns false, and the node appends nothing more (requests that need an audit row
  fail) until the log is investigated.
- The authority's signature is checked offline, with its certificate chain:
  `openssl ts -verify -digest <hash> -in token.der -token_in -CAfile tsa-ca.pem` (token from the anchors endpoint,
  base64-decoded). Keep copies of the tokens outside this database (SIEM, archive): someone able to rewrite the log
  and delete the anchors is only caught by a copy held elsewhere.

### 3.9.3 SIEM push export

| Variable | Effect |
|---|---|
| `SIEM_WEBHOOK_URL` | Receiver (https only; credentials or a query string in the URL are refused at start, so no token rides in it). Unset with the secret: no push. |
| `SIEM_HMAC_SECRET` | HMAC-SHA256 key shared with the receiver, at least 32 characters. Never sent, never logged. |
| `SIEM_INTERVAL_SECONDS` | Seconds between pushes, 1..86400, default 30. |
| `SIEM_BATCH_SIZE` | Rows per request, 1..1000, default 100. |

- Each request is `POST`, `Content-Type: application/x-ndjson`, body = the audit rows (as in the pull export), with
  `X-SIEM-Timestamp: <unix seconds>` and `X-SIEM-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>`.
  The receiver recomputes the HMAC over the raw body, compares in constant time and refuses timestamps older than its
  replay window (five minutes is usual). Redirects are refused; each request times out after 10 s.
- **At-least-once.** The cursor (last acknowledged `seq`; with several chains `{ seq, chains: { <node>: seq } }`, `seq`
  being chain `"0"`) is saved only after a 2xx answer: `siem-cursor.json` in
  `DATA_DIR`, or the `siem` document in PostgreSQL, committed before the next batch. A failed batch is retried with
  exponential backoff (1 s doubling to 30 s, 5 attempts) and, if still refused, again at the next interval from the
  same cursor. A crash between the receiver's 2xx and the cursor save resends that batch: receivers deduplicate by
  `(node, seq)`. Only the leader pushes; a follower that takes the lead resumes from the stored cursor.
- The payload is the audit row only: ids, rule ids, policy versions and the hash chain. Secrets (passwords, keys,
  session ids, the SCIM credential) are never written to the audit, so they cannot reach the SIEM.

### 3.9.4 Sealed audit retention

`AUDIT_RETENTION_DAYS` is unset by default (keep every row); 1..36500 enables it and requires `SIGNING_KEY_SEAL`.
Only the contiguous prefix with `ts` older than the cutoff is removed, per chain. Before deletion Qadamar records
`{ version: 1, node, firstSeq, lastSeq, removed, prefixHash, head, sealedAt, anchor?, mac }`, where `prefixHash` is
SHA-256 of the canonical removed records, `head` is the last removed `{seq, hash}`, and `mac` is HMAC-SHA256 under the
checkpoint key. `audit-segments.json` stores seals in file mode, `gate_audit_segment` in PostgreSQL. When a TSA is
configured, the sealed head (the set of sealed heads in a cluster) is RFC 3161 anchored before any deletion. A
`security audit_retention` row then records the removal at the live head. Later verification authenticates each seal,
checks segment continuity, and starts at the latest sealed head; anchors inside that prefix are covered by its seal.
Sequences are never renumbered and the next append continues at the live head. `length` counts retained rows only.
An auditor can still prove seal authenticity, retained-row integrity, and anchored sealed heads. Without a backup or
export they cannot recompute or inspect the deleted rows themselves; `prefixHash` commits to them but does not reveal them.

File mode plans and applies retention at startup and daily, with no service-role equivalent. PostgreSQL deletion is a
separate owner operation, never a permission of the running service. Stop **every** writer (all cluster nodes), back up
and preserve external evidence, then run with the table-owner URL and the deployment seal in the environment:

```sh
AUDIT_RETENTION_DAYS=365 SIGNING_KEY_SEAL='<from secret store>' \
TSA_URL='https://tsa.example/tsr' TSA_CA_FILE='/etc/gate/tsa-ca.pem' \
DATABASE_URL='postgresql://owner@db.internal/gate' node scripts/ops/audit-retention.ts
```

The script requires table ownership, verifies every retained chain, existing seal and anchor, then requires the stored
authenticated checkpoint (current or, during a seal rotation, previous key) and checks that every live chain extends
it (the row or sealed head at the checkpoint's `seq` has its `hash`); a missing, unauthenticated or unmatched
checkpoint refuses before any seal is written, re-keyed or cleared and before any row is deleted, so a chain rehashed
with plain SHA-256 is never laundered into a seal. It then requests any configured anchor and commits segment
inserts, prefix deletion, retention markers, and a cleared old checkpoint in one transaction, and revokes the
temporary `DELETE`/`UPDATE` it granted to the owner whatever the outcome. The next start verifies from the sealed
heads and writes a fresh checkpoint after a full recheck: start Qadamar at least once (until `/readyz` reports
`fullChain: true`) between two retention runs. Never run it against the
service role or while a writer is active. `gate_audit`, its metadata, seals, mappings, and anchors are all included in
`backup.sh`; restoring an older archive creates the two new tables empty.

### 3.9.5 Stateless decision replicas (`GATE_REPLICA_OF`)

A replica is a PDP node **without a database**: it decides from a copy of the shared state that database nodes (the
leader, a cluster follower or an active node) sign and stream to it, writes each decision it answers to an audit chain
of its own on local disk, durable before the answer, and ships that chain to the database, where it becomes the
replica's chain in `gate_audit`. Decisions a copy cannot take exactly as a database node would are forwarded.

| Variable | Where | Effect |
|---|---|---|
| `GATE_REPLICA_KEYS` | database nodes | `id=key,...` (32-byte keys, base64url or hex): the replicas served. `prefix*=master` is a group: each id with that prefix holds only its own key, HKDF-SHA256(master, info `qadamar/replica-key/v1/<id>`) (`scripts/ops/replica-key.ts`), so one replica's key never authenticates another. |
| `GATE_REPLICA_OF` | replica | The database nodes' origin, https (plain http only on loopback). Excludes `DATABASE_URL`. |
| `GATE_NODE_ID` | replica | Required, not `0`: the replica's id and chain. |
| `GATE_REPLICA_KEY` | replica | Its key: as listed in `GATE_REPLICA_KEYS`, or derived for its id from the group master. `GATE_REPLICA_KEY_FILE` reads it from a file instead. |
| `GATE_REPLICA_PIN` | replica | Optional: Ed25519 keys (JWKS `x`) the first snapshot must be signed by. |
| `GATE_REPLICA_CA_FILE` | replica | Optional: the CA of the database nodes' TLS certificate. |
| `GATE_MAX_STALENESS_MS` | replica | As in cluster mode (2000): no decision on state confirmed longer ago. |
| `GATE_REPLICA_AUDIT_LAG_MS` | replica | 10000: no decision while a durable local row waits longer to reach the database. |

**Endpoints (database nodes, replica requests only).** Every request carries `X-Qadamar-Replica-Hop`, the hop format of
§3.9.1 (`v2.<ms>.<nonce>.<client>.<node>.<mac>`, 30 s window, single use, method, path with query and body digest
bound) under a key HKDF-derived from the replica's key (label `qadamar/replica-hop/hmac-sha256/v1`), `node`
naming the replica; the database node verifies it under that replica's own key, so the id cannot be another's. Without
a valid hop: `401`. Every replica request also takes a token from a budget keyed on the replica id
(`PEP_RATE_LIMIT_PER_MINUTE`), whatever client address its hop names; a poll without `after` (a full snapshot) is
limited to 6 a minute per replica (`429`). Every answer carries `X-Qadamar-Replica-Signature`, a detached EdDSA JWS by
the node's active decision-token key over `{ typ: "gate-replica/v1", sha256: <base64url SHA-256 of the body> }`, and
the body names the replica (`aud`), echoes the request's `nonce` and lists the signing key (`signer`).

- `GET /x/v1/replica/state?nonce=&wait=&after=<version>.<records>&docs=<hash>&subjects=<epoch>.<n>` returns
  `{ kind: "state", at: { version, records }, docs?, docsHash, deltas? | records?, subjects, config }`. Without
  `after`: a snapshot, every record row and the documents. With it: the record changes after that generation, read from
  `gate_state_change` in one repeatable-read snapshot (the generations followers use), or every record row again when
  the log has a gap, a reorder or more than 50,000 changes. `docs` (the state document without pending changes,
  emergencies or older publications; PEP credentials without console accounts; the keyring without private keys;
  `blp_revocations` session tombstones) is
  sent only when its SHA-256 differs from the replica's. `subjects` is the audit pseudonym of every mapped subject id
  (never the per-subject keys), as a full map or the changes since `<epoch>.<n>`. `config.blpSessionRequired` is the
  database nodes' setting, which the replica applies. When nothing moved, the node holds the request until its next
  commit or reload, or `wait` ms (at most 25 s): the replica polls with `wait` = a quarter of its staleness bound. Feed
  reads run one at a time on the node's feed connection, each in its own snapshot.
- `POST /x/v1/replica/audit?nonce=` with `{ base: { seq, hash }, rows: [...] }` (5,000 rows at most, within the 1 MB body cap; a replica sends at most 1,000 rows and 768 KiB at a time) appends the rows
  to the replica's chain and answers `{ kind: "audit", head }`, or `409 { refused, head }`. See audit below.

**Trust bootstrap.** At its first start a replica trusts either the keys in `GATE_REPLICA_PIN`, or, without pins, the
keys of `/.well-known/jwks.json` fetched over TLS verified against `GATE_REPLICA_CA_FILE` (or the system store): trust on
first use anchored in the certificate. The first snapshot must be signed by one of them. A rotation
(`/admin/v1/signing-keys/rotate`) signs the new key with the old one (`introducedBy` in the keyring): a replica trusts
a key only when it is already trusted or introduced by a trusted key, and stops trusting keys the keyring no longer
lists. The trusted set and the newest generation applied are kept in `DATA_DIR/replica-trust.json` under an HMAC
(key derived from `GATE_REPLICA_KEY`); a file that does not verify stops the start. Deleting it bootstraps again (and
drops the rollback floor: do it only after a deliberate database restore).

**What is refused.** An answer whose signature does not verify against a trusted key, that names another replica or
another nonce (a replayed or swapped answer), or whose generation (`version`, `records`) is below one already applied
(rollback, across restarts too) is not applied: the replica stays on its last state and, past the staleness bound,
refuses decisions (503) with `/readyz` 503. The policy bundle's own signature is checked on every applied state, as a
follower does (§3.10). A delta applies only from the generation the request named; an answer that cannot be applied
(a refused bundle) makes the next request a full snapshot.

**What a replica decides, and what it forwards.** It answers `/access/v1/evaluation`, `/access/v1/evaluations`,
`/access/v1/search/resource`, `/x/v1/explain` and `/x/v1/filter` itself when every evaluation in the request has
- no `context.sessionToken` or legacy `context.sessionId`: the open-session registry and high-water mark are shared state (§2);
- an action under no separation-of-duty rule (no conflict set, no `requiresSecondPerson`): performed history is shared
  and changes with every consumption on any node;
- an action that is not `certified`: its permit carries a decision token, a database row consumed under a row lock;
- a subject the database already gave an audit pseudonym (the row needs it; an unknown id is decided there once, which
  maps it, and locally after the next delta).

Everything else (those evaluations, session open/close, token consumption and outcomes, decision assertions, subject and action search,
XACML, resource registration, `/admin/*`, `/scim/*`) is forwarded to `GATE_REPLICA_OF` with the replica hop carrying the
client address, and audited there on the database node's chain, exactly as if sent there. A follower that receives a
forwarded admin request passes it to the leader with its own cluster hop. The replica authenticates the PEP credential
first (its copy, at most one staleness bound old), so unauthenticated traffic is not passed on. The choice is made
before deciding: a replica never decides on stale performed history or marks, rather than including them in the feed,
because both move at every consumption and read on any node and would need a round trip to be exact anyway.
A forwarded request with `context.sessionToken` (or legacy `sessionId`) is decided on the database node like a direct one:
its sid/subject queues and `BLP_LOCK` advisory locks (§2) order it against every related decision on any node.

**Rate limits on a replica.** A replica has no database, so it cannot lease from the shared `gate_rate_limit` buckets
(§3.9.1): its per-address and per-principal buckets are process-local, at its own `RATE_LIMIT_PER_MINUTE` and
`PEP_RATE_LIMIT_PER_MINUTE`. Set those to the replica's share of the budget (the total over replicas and database nodes
is what a client can reach). A request a replica forwards is charged again on the database node, against the shared
buckets, under the real client address (from the hop) and the PEP credential. `SOD_HISTORY` does not matter on a
replica: actions under separation of duty are always forwarded, and the database nodes default to `server`.

**Audit on a replica: durability, then central visibility.** The replica's chain is a file chain (`DATA_DIR/audit.jsonl`,
`node` = its id in every hashed row, its pseudonyms the database's). Each row also carries `mac`, HMAC-SHA256 under a
key derived from `GATE_REPLICA_KEY` (`qadamar/replica-audit-checkpoint/hmac-sha256/v1`) over the row without its
hash. A decision is answered only after `fdatasync` of the rows written before it (group commit: requests arriving
during a flush share the next one; on macOS Node issues `F_FULLFSYNC`). A keyed two-slot checkpoint
(`audit-checkpoint.slots`) is updated in place at most once a second, off the answer path: a chain shorter than it was
truncated and stops the start. At start a torn last line (a crash during an append, never answered) is dropped and
`security / torn_row_dropped` is chained. Shipping: rows are sent once durable, coalesced 50 ms, in order from the head
the database last acknowledged. The database checks every row: its MAC under the replica's key, `node`, consecutive
`seq`, `prevHash` link and hash, and that `base` is its stored head (or an earlier stored row with that hash, for a
resend); it appends them to `gate_audit` under the node advisory lock of that chain, on a connection of its own. From
there the replica's chain is one chain among the others: verified from genesis at every recheck, covered by the
checkpoint, anchors (RFC 3161), listings, export and SIEM push.
- **Refused and alerted:** a row that does not verify (`tampered`), a base that disagrees with the stored chain
  (`fork`), a base beyond it (`gap`, a restored database: the replica resends from the stored head if it still has the
  rows), an empty batch below the stored head (`behind`: the replica lost rows the database holds). The database node
  appends `security / replica_audit_refused { replica, reason, replicaHead, storedHead, suppressed? }` to its own chain
  (at most one row a minute per replica and reason; `suppressed` counts the refusals in between), logs
  `REPLICA AUDIT REFUSED` and counts `gate_replica_audit_refused_total`. The replica stops deciding
  (`gate_replica_audit_refused` 1, `/readyz` 503).
- **The window** between local durability and central visibility is the shipping delay: 50 ms of coalescing plus one
  round trip and one commit when the database is reachable. It is bounded: past `GATE_REPLICA_AUDIT_LAG_MS` (10 s) of
  unshipped durable rows the replica refuses decisions. Until a row is stored centrally it exists only on the
  replica's disk: listings, compliance counts and anchors on the database do not include it yet.
- **A lost replica disk** loses at most the rows not yet shipped: at most `GATE_REPLICA_AUDIT_LAG_MS` of decisions, in
  practice the last tens of milliseconds. A replica started on an empty disk with an id the database already holds is
  refused at start (`behind`, alerted as above): give it a new `GATE_NODE_ID` (a new chain); the old chain stays,
  verified and anchored, with no new rows. A restart on the same disk resumes the local chain where it was and ships
  what the database does not have yet.
- Shipped rows are sealed out of the local file every 10,000 rows (an authenticated retention segment, §3.9.4), so the
  replica's disk does not grow with the log.

**Readiness and metrics.** `/readyz` on a replica is 200 with `role: "replica"` only while the state is within the
staleness bound, the audit lag within its bound and the chain accepted. `/metrics` adds `gate_replica_state_age_seconds`,
`gate_replica_audit_unshipped_rows`, `gate_replica_audit_lag_seconds` and `gate_replica_audit_refused`. A replica's
storage failure (an `fdatasync` that fails) latches: it answers 503 and exits (`main.ts`).

**Propagation.** A change committed by the leader wakes the held state requests at once: in the tests a subject
disabled by an approved change was decided on by the replica 25 to 55 ms after the approval returned, and a revoked PEP
credential was refused by the replica 24 to 116 ms after the revoke (PERFORMANCE.md). A replica id must not be a
database node's own `GATE_NODE_ID` (refused at start for the node's own id; another node's id makes ingestion wait on
that chain's lock and fail with 503). A replica served by a follower
learns it at the follower's next reload, within `wait`.

### 3.10 PEP credentials and decision-token signing keys

| Variable | Effect |
|---|---|
| `PEP_ROTATION_GRACE_SECONDS` | How long the previous secret of a rotated PEP credential keeps working, 0..86400, default 300. Measured on real (wall-clock) time, not the business clock, so `CLOCK=fixed` does not keep a rotated-out secret alive. |
| `INITIAL_CREDENTIALS_TTL_SECONDS` | Lifetime of `INITIAL-CREDENTIALS.txt`, 1..86400, default 3600 (§1). |
| `SIGNING_KEY_SEAL` | 32-byte key (base64url, or 64 hex characters); required with `DATABASE_URL` unless `ALLOW_CLEAR_SIGNING_KEYS=true` (§3.9.1). Set: every private signing key is sealed at rest in `signing-keys.json` (in PostgreSQL mode, the `signing_keys` row of `gate_doc`) with AES-256-GCM (format `v2.`, with the key's `kid` as additional authenticated data, so a sealed key cannot be moved to another `kid`; keys sealed in the earlier `v1.` format are still read and re-sealed as `v2.` at the next start), and (file mode) a legacy plaintext `signing-private.pem` is deleted. Once sealed, the node refuses to start without the same key. Unset: the private keys are stored in clear in `signing-keys.json` (mode 600). |
| `POLICY_SIGNATURE_ADOPT` | `1`/`on`: at start, sign a stored policy bundle that is unsigned or signed by a key no longer in the keyring, and audit it (Policy bundle signature, below). Use once, then remove. |
| `SOD_HISTORY` | `server` (default in every profile) or `caller`: whether caller-supplied `makerId`/`priorActions` count for SoD-constrained actions when the server has no recorded history (§2, server-derived separation of duty). `GATE_PROFILE=production` refuses the explicit `caller` opt-in; a demo start with `caller` logs a warning intended only for demos/tests. |

PEP credentials (`credentials.json`, or the `credentials` row of `gate_doc` in PostgreSQL mode; hashes only; the clear secret is returned once and never again):

**Stored hashes.** Console passwords: scrypt with N=2^16, r=8, p=2 (equal in cost to OWASP N=2^17, r=8, p=1 at half the
memory: 64 MiB; at most two run at once, 32 more may wait) over the 0.8.3 key of the password (scrypt N=2^14, r=8, p=1),
about 200 ms on an Apple M5 Pro, stored as `scrypt-wrap$16$8$2$<inner salt>$<salt>$<key>` so the cost can rise again.
At start each 0.8.3 hash is wrapped in place without its password, so every sign-in, for an unknown, a dormant or a
current account, runs the same two scrypt calls.
PEP keys and the SCIM token are random secrets of 192 bits or more: `hmac-sha256$<salt>$<mac>`, because stretching
adds nothing against 2^192 guesses and a slow hash on a per-request credential would let any caller spend the event
loop. PEP key and SCIM token hashes written by 0.8.3 and earlier (`<salt>:<key>`, scrypt N=2^14) still verify and are
replaced at their first use; a plain `scrypt$…` password hash is replaced at the next sign-in.


- `GET /admin/v1/pep-credentials` (access admin, security officer) → `{ items: [ { id, name, created, lastUsed?, rotated?, revoked?, previousValidUntil?, subjectTypes?, allowSubjectSearch?, resourceTypes?, contextScopes?, issuedBy? } ] }`.
  `lastUsed` is updated at most once a minute.
- `POST /admin/v1/pep-credentials` `{ name, subjectTypes?, allowSubjectSearch?, resourceTypes?, contextScopes? }` (security officer; 1..80 printable characters, unique among active
  credentials) → `201 { credential, secret }`. The secret has the form `pep.<id>.<random>`. `subjectTypes` (1..16
  subject types, fixed for the credential's life; listed in the view) binds the credential to the subject populations
  whose end users this PEP authenticates (Clark-Wilson E3, §3.12); without it, and for `bootstrap`, the binding is empty.
  `allowSubjectSearch` (boolean, default `true`, listed in the view and in the `pep_credential_create` audit row) lets the
  credential call `/access/v1/search/subject`, which lists who can access a resource; `false` answers that route with
  `403`, the other routes are unchanged. Set it to `false` for every PEP that does not need it. Under
  `GATE_PROFILE=production` credentials are created with `false`, `true` is refused (`400`), and no credential (earlier
  ones and `bootstrap` included) may search subjects. `resourceTypes` (1..16 resource types of the policy, `400`
  otherwise; fixed for the credential's life, listed in the view and the audit row) lets the credential register,
  update and retire resources of those types (§2.2); without it the credential writes no resource. `issuedBy` is the
  console user who created or last rotated the credential (`bootstrap` for the initial one): it cannot review the
  credential's `register_resources` proposals. `contextScopes` (at most one entry per protected signal, fixed for the
  credential's life, listed in the view and audit row) limits its context assertions and optionally constrains networks,
  countries or requires trusted-attester JWS evidence; the exact shape, compatibility default and wire format are in §2.
  Production requires this field at creation and gives older unscoped credentials the empty scope.
- `POST /admin/v1/pep-credentials/:id/rotate` (security officer) → `{ credential, secret }`. The previous secret stays
  valid for `PEP_ROTATION_GRACE_SECONDS`, so a PEP fleet can switch without downtime. Revoked → 409.
- `POST /admin/v1/pep-credentials/:id/revoke` (security officer) → the credential; its current and previous secrets stop
  at once, and their entries leave the in-memory verified-digest cache (expired previous secrets leave it at rotation
  or first use after expiry). Already revoked → 409.
- Audit (type `security`): `pep_credential_create`, `pep_credential_rotate`, `pep_credential_revoke` with the credential
  id; secrets and hashes never appear. Refused calls are audited as `refused`.
- Migration: a deployment with the former single shared key (`pepHash` in `credentials.json`) is converted at start to a
  named credential `bootstrap` holding the same hash, so existing PEPs keep working. Bearer values without the
  `pep.<id>.` prefix are checked against `bootstrap` only. Create one credential per PEP, move each PEP to its own
  secret, then revoke `bootstrap`.

Decision-token signing keys (Ed25519, `signing-keys.json`, or the `signing_keys` row of `gate_doc` in PostgreSQL mode):

- Every decision token and evidence-pack signature carries `kid` in its JOSE header. A token without `kid` (issued
  before the upgrade) is checked against the active key.
- `GET /.well-known/jwks.json` (no auth) → `{ keys: [ { kty: "OKP", crv: "Ed25519", x, kid, use: "sig", alg: "EdDSA" } ] }`:
  public keys only, for PEPs that verify decision tokens offline. Pick the key by `kid`.
- `GET /admin/v1/signing-keys` (access admin, security officer) → `{ items: [ { kid, created, active, verifyUntil? } ] }`.
- `POST /admin/v1/signing-keys/rotate` (security officer) → `201 { current, previous }`: a new key signs from now on;
  the previous private key is discarded and its public key stays in the JWKS and valid for consumption for 300 s (the
  longest decision-token TTL), then is removed. Audit `signing_key_rotate {kid, previousKid, previousVerifyUntil}`, appended before the keyring changes (a refused append refuses the rotation).
  Keep the JWKS of the day with exported evidence packs: a rotated key leaves the JWKS after 300 s.
- `signing-public.pem` keeps holding the active public key (file mode only; in PostgreSQL mode use the JWKS). Migration: at the first start of this version, an existing
  `signing-private.pem` becomes the first key of the keyring, so tokens and PEPs keep working.

Policy bundle signature (same keyring):

- When a `publish_policy` change is approved (two-person rule), the node signs the canonical bundle with the active
  key and stores `{ alg: "EdDSA", kid, jws }` on that publication in the history. A new store signs its initial
  bundle at first start. A key rotation re-signs the bundle in force with the new key (the old key leaves the JWKS
  after 300 s), replacing the signature on the latest publication; older publications keep theirs.
- At every start (and on a PostgreSQL takeover) the node refuses to serve when the stored bundle is not the one the
  latest publication names (`version`), or when that publication's signature does not verify against the keyring.
  An unsigned store (written before this version) or one signed by a key the keyring no longer holds (lost or
  replaced `DATA_DIR`) is refused too; after checking the bundle, start once with `POLICY_SIGNATURE_ADOPT=1`: the node
  signs it with the active key and audits `policy_signature_adopt {kid, previousKid, freshStore}` (actor `system`).
  Remove the flag afterwards (`GATE_PROFILE=production` refuses to start with it set). A store created at this start
  is signed silently only when the audit chain is empty too (a new deployment); a new state under an existing audit
  trail (state document lost or replaced) is refused the same way until adopted. With files the keyring lives in `DATA_DIR`: back it up with the volume (in PostgreSQL mode it is the `signing_keys` row of `gate_doc`).
- Verifying (PEP or auditor), from `GET /admin/v1/policy` and the public `GET /.well-known/jwks.json`:
  1. `jws` is a compact JWS with a detached payload: `<header>..<signature>` (base64url). The header is
     `{"alg":"EdDSA","kid":"…"}`; refuse any other `alg`, and take the JWKS key whose `kid` matches (it equals `kid`).
  2. Rebuild the payload: base64url (no padding) of the UTF-8 canonical JSON of `bundle` (object keys sorted
     recursively, arrays in order, no whitespace; the same encoding as `version`).
  3. Verify the Ed25519 signature over the ASCII bytes `<header>.<payload>` with that public key (`crypto.verify(null,
     …)` in Node, `jose`'s `flattenedVerify` with `{ payload, protected, signature }`, or any RFC 8037 library).
  4. Optionally recompute `version` as `pv.` + hex SHA-256 of the same canonical JSON and compare.
  Keep the JWKS of the day with the bundle if it must be verified later: a rotated key leaves the JWKS after 300 s.

### 3.11 SCIM 2.0 provisioning (RFC 7643 / RFC 7644)

`/scim/v2/Users` and `/scim/v2/Groups`, `Content-Type: application/scim+json` (or `application/json`), answers in
`application/scim+json`, errors in the SCIM `Error` schema (`{ schemas, status, detail }`).

**Authentication.** `Authorization: Bearer <credential>`, a credential of its own (the PEP key and console sessions do
not work here). Either `SCIM_BEARER_TOKEN` (32..256 characters, compared as a SHA-256 digest in constant time), or
`POST /admin/v1/scim/credential` (access admin only, session and CSRF; an access admin cannot approve changes) → 201
`{ credential }`, shown once, stored only as a salted HMAC-SHA256 (Stored hashes, §3.10) with the id of the person who minted it
(`scim-credential.json`, or the `scim` document in PostgreSQL), audited as `scim_credential_rotate`; a new one revokes
the previous one, and the route answers 409 while the env token is set.
`GET /admin/v1/scim/credential` (access admin, security officer) → `{ source: "none" | "env" }` or
`{ source: "console", rotatedBy, rotated? }`: who minted the credential and when (`rotated` is absent for a credential
minted before this field existed). Never the credential or its hash.
With neither, every SCIM request is 401. Requests are rate limited per IP and per credential like the PEP API.

**Model.** A SCIM User is a subject of type `user`, a Group a subject of type `group` without roles of its own; agents and
other subject types are not exposed. Supported attributes: User `userName`, `externalId`, `displayName`, `active`,
`groups`; Group `externalId`, `displayName`, `active`, `members` (each reference `{ value, display? }`), plus `schemas`
(the core schema only). Any other attribute or schema extension (emails, name, enterprise extension…) → 400: nothing
is silently dropped or stored. Users created by SCIM get a random id, clearance 0 and no compartments; clearance and
compartments are only changed through ordinary `update_subject` proposals, and SCIM keeps them, and every attribute it
does not manage (`unit`…), as they are.

**Groups to roles.** `SCIM_GROUP_ROLES` is a JSON object from a group's `externalId` or `displayName` to one PDP role,
one group per role (a role mapped twice is refused at start). A group without a mapping to a role of the current
policy cannot be created (422). The members of a provisioned group are exactly the users holding its role: adding a
member grants the role, removing one, deactivating or deleting the group revokes it, and a role granted by hand to a
user outside the group is revoked when the group is written. Roles that no provisioned group maps are never touched.

**Operations.**
- `POST /Users`, `POST /Groups` → 201 (direct mode) or 202 (proposal) with the resource and, for 202,
  `changeId` and `status: "pending"`. `userName` (case-insensitive), `externalId` and group `displayName` are unique (409).
- `GET /Users/:id`, `GET /Groups/:id`; `GET /Users?filter=userName eq "…"` or `externalId eq "…"`,
  `GET /Groups?filter=displayName eq "…"` or `externalId eq "…"`, with `startIndex` and `count` (at most 200). Other filters → 400.
- `PUT /Users/:id` (without `groups`, memberships are kept), `PUT /Groups/:id`.
- `PATCH` (`PatchOp`, at most 100 operations): `add`/`replace`/`remove` on `active` and on `groups` (User) or
  `members` (Group), with a `path`, without one (`{ "op": "replace", "value": { "active": false } }`), or as
  `members[value eq "id"]` for one removal. `"True"`/`"False"` strings are read as booleans. Other paths → 400.
- `DELETE` deactivates (`active: false`, group memberships revoked) and answers 204 (or 202); a subject is never removed,
  so its audit trail keeps its meaning.

**Review (safe default).** Every SCIM write is a `scim_subjects` change proposed by the maker `scim` (section 3.5), with
its impact, waiting for an approver or security officer: nothing changes until a second person approves. Each proposal
records `scimCredential: { rotatedBy, fingerprint }`: who minted the credential that sent it (`env` for
`SCIM_BEARER_TOKEN`) and 16 hex characters of the credential's SHA-256 (also in the `propose` audit row as `credential`).
The person in `rotatedBy` cannot approve it (`403 self_approval`), since that credential is in their hands; neither
can anyone approve a SCIM proposal without that record. The usual
stale check applies (approving one SCIM change makes the others pending against the old state stale; the IdP's next
sync re-proposes them). A rejected creation leaves the IdP with an id that answers 404; it re-creates the user at the
next sync. `SCIM_DIRECT=true` applies each write at once instead; the node refuses to start with it unless
`SCIM_BEARER_TOKEN` is set (a console-minted credential always goes through review). Direct writes are still validated
the same way and audited as a `change` row with action `scim.user.create|replace|patch|deactivate` or `scim.group.…`,
actor `scim`, `details: { direct: true, credential: <fingerprint>, subjectIds }`; the secret is never written. Refused SCIM writes are audited as `refused`, as for the console.

### 3.12 Clark-Wilson integrity (IVP and certifications)

IVPs are declared in the bundle, validated by `validateBundle` (refused with 422 on publication otherwise):

```json
"clarkWilson": { "tokenTtlSeconds": 15, "ivps": [
  { "id": "payment-consistent", "description": "A payment has a positive amount and a known status",
    "resourceTypes": ["payment"],
    "check": { "op": "and", "args": [
      { "op": "gt", "left": { "path": "resource.attrs.amount" }, "right": { "value": 0 } },
      { "op": "in", "left": { "path": "resource.attrs.status" }, "right": { "value": ["pending", "approved", "released"] } } ] } } ] }
```

`id` shares the rule-id namespace; `resourceTypes` must be declared `constrained` types; `check` uses the condition
language with `resource.*` paths only. An IVP holds only when its check is TRUE. Removing or editing an IVP is a
mandatory weakening (approval by a security officer, §3.5); adding one is not.

- `POST /admin/v1/integrity/verify` (security officer, auditor) → `{ verified, checked, policyVersion, items: [ { ivp, resourceType, resource, ok } ] }`
  over every stored item. Audited as `security` / `ivp_run` with effect `deny` when one fails, the failing
  `CW.IVP.<id>` rule ids, and `details: { checked, failed: [ { ivp, resourceType, resource } ] }`: ids only.
- `GET /admin/v1/integrity/certifications` (every console role except resource owner) → `{ items: [ Certification & { current } ], missing: [ { resourceType, action } ], stale: [ { resourceType, action } ] }`,
  `missing` listing the certified actions of constrained types with no **current** record, `stale` those of them that
  have records, all for another definition of the procedure (recertify them). Records are appended by approved
  `certify_tp` changes (§3.5) and kept in the state document (PostgreSQL or files).
- **A certification binds the procedure it certified.** Each record carries `fingerprint`: a SHA-256 over everything
  in the bundle that decides that one procedure (the action's definition and its type's `constrained` flag, the type's
  IVPs, the procedure's input validators and PEP binding, the roles that grant it after inheritance, the ABAC
  (including content-attribute), CBAC (context) and SoD rules that apply to it, need-to-know on its type, and the `mandatory` section). A record counts only while the
  current bundle gives the same fingerprint (`current: true`); a publication that changes any of these makes it stale,
  a change to another procedure does not. Records written by 0.4.0 carry no fingerprint: they count only while their
  `policyVersion` is the one in force. A `publish_policy` proposal lists the records it would make stale in
  `invalidatesCertifications: [ { resourceType, action, changeId } ]`, and its impact shows the access the procedure
  loses until it is recertified.
- `clarkWilson.requireCertification` (optional, a list of constrained types): a certified action on a listed type is
  denied with rule `CW.NOT_CERTIFIED` until a certification record for that type and action exists, and with
  `CW.CERTIFICATION_STALE` while its only records certified another definition of the procedure (`/x/v1/filter`
  and search answer none). The records are supplied by the server (`context.certified`, never taken from a caller).
  Absent or empty: records are evidence only and decisions do not change. Removing a type is a mandatory weakening.
- `GET /admin/v1/integrity/reservations` (access administrator, security officer, auditor) → `{ items: [ { reservation,
  subject, resource, action, reservedAt, pep?, onBehalfOf? } ], unappliedPostStates: [ { reservation, resource, action,
  boundVersion, storedVersion, reason, at } ] }`. `unappliedPostStates`: completed commands whose post-state the PDP did
  not apply because the item had moved on (§2, the PDP's copy follows the command). `items`: certified actions whose PEP never reported an
  outcome (`/x/v1/tokens/outcome`), oldest first. They keep counting for separation of duty. **Reconciliation:** for
  each one, check in the protected system whether the command ran (the audit holds the consuming decision at
  `reservedAt` on that subject and resource), then report `completed` or `failed` with the credential named in `pep`
  (the PEP credential id; its current secret works after a rotation; a revoked credential leaves the reservation
  counting for good, the conservative outcome). Until then the
  reservation stays: leaving it is the conservative choice, since reporting `failed` for an action that did run removes
  it from separation of duty.

- `clarkWilson.inputValidators` (optional, C5): declarative validators of the **input** of certified commands.

  ```json
  { "id": "approval-input", "description": "An approval carries its status and a bounded note",
    "resourceTypes": ["payment"], "actions": ["approve"],
    "fields": { "status": { "type": "string", "required": true, "enum": ["approved"] },
                "note": { "type": "string", "maxLength": 200 }, "amount": { "type": "integer", "min": 1, "max": 5000 } } }
  ```

  `type` is `string`, `number`, `integer` or `boolean`; `required`, `enum`, `min`, `max`, `maxLength` (code points)
  are the only bounds (no regular expressions: nothing to backtrack). The schema is **closed**: a field it does not
  declare fails it. Actions must be `certified` actions of the listed types. At decision, `context.input` must be
  present (`CW.INPUT_REQUIRED`) and pass every validator of (type, action) (`CW.INPUT.<id>`); the decision token then
  carries `postState: true` and consumption validates `attrs`, the post-state, again. `/x/v1/filter` answers none
  when the input is missing or fails. Removing or changing a validator is a mandatory weakening.
- `clarkWilson.requirePepBinding` (optional, E3, a list of constrained types): a certified action on a listed type is
  decided only when the subject's `type` is in the `subjectTypes` of the PEP credential that asks (decision, batch,
  search, filter, XACML and token consumption alike); otherwise `CW.SUBJECT_NOT_AUTHENTICATED`. The binding comes from
  the credential, never from the request. Console views (simulator, matrix, impact, E4 checks) answer as a PEP bound
  to the subject's population. Removing a type is a mandatory weakening.
- **E4 at run time:** the certifier and the checker of a certification record are denied the procedure it certifies
  (`CW.CERTIFIER_EXECUTES`, every link of a delegation chain, list filter included), whatever roles they gain later.

Which Clark-Wilson rules this covers, and which not: [ARCHITECTURE.md](ARCHITECTURE.md) §16.

## 4. Verification references

The package API and engine tests run with Node's coverage instrumentation and minimum line, branch and function
thresholds; the measured baseline and exact command are in [QUALITY.md](QUALITY.md). The console also has
server-rendered markup tests for labels, ARIA attributes and initial loading, empty and error presentations. These
are static client checks, not additional API conformance evidence and not a browser accessibility audit; their exact
scope is in [ACCESSIBILITY.md](ACCESSIBILITY.md). No API route or response contract is changed by those checks.

## 5. Enforcing gateway (`packages/gateway`)

A reverse-proxy PEP in front of a JSON API, built on `node:http` and the PEP SDK. Library API:

```ts
const gateway = createGateway({
  upstream: 'http://10.0.0.5:8080',                 // http origin, no path; the API sits on a private link
  pdp: new PepClient({ baseUrl, apiKey }),          // the PEP credential lives here only
  routes: [
    { method: 'GET', path: '/cases', resourceType: 'case', action: 'read', list: { items: 'items', idField: 'id' } },
    { method: 'GET', path: '/cases/:id', resourceType: 'case', action: 'read', query: ['fields'], headers: ['x-request-id'] },
    // the JSON body is the payment's state as the upstream will commit it: sent to the PDP for the IVPs
    { method: 'POST', path: '/payments/:id/approve', resourceType: 'payment', action: 'approve', postState: 'body' },
  ],
  authenticate: (req) => ({ subject: { type: 'user', id }, context: { makerId, authTime, mfaTime, authMethods, device, country, riskScore } }) /* or undefined → 401; with SOD_HISTORY=server the PDP ignores makerId/priorActions for constrained actions */,
  trustedNetworks: ['10.0.0.0/8'],                  // client address ranges evaluated as the trusted network
  trustedProxies: '10.0.0.5, 10.0.1.0/24',          // the load balancers in front (as TRUSTED_PROXIES); unset: socket address
  notify: async ({ recipients, subject, resource, action, policyVersion }) => { /* deliver */ },
  maxBodyBytes: 1_048_576, maxResponseBytes: 8_388_608, upstreamTimeoutMs: 10_000,
  log: (entry) => { /* { method, route, subject, resourceType, resource, action, outcome, status, code?, rules?, policyVersion? } */ },
});
await gateway.listen(8443, '0.0.0.0');
```

For CBAC (context) rules, the gateway fills `context.ip` from the client socket (IPv4-mapped IPv6 normalized to IPv4), and
fills `authTime`, `mfaTime`, `authMethods` and any other posture/risk signals it knows from the `Caller` returned by its
own `authenticate` session hook. No client header is read for these values; a route cannot allowlist an override. The
PDP still treats them as PEP assertions, not independent attestation.

| Situation | Answer |
|---|---|
| Method + path not in the route table | 404 `not_found` (nothing is proxied by default) |
| `authenticate` returns nothing | 401 `unauthenticated` |
| Path id that decodes to `/`, `\`, a control character, `.` or `..`, or bad percent-encoding | 400 `bad_request` |
| `X-HTTP-Method-Override`, `X-Method-Override` or `X-HTTP-Method` header, or a `_method` query parameter | 400 `bad_request`, before authentication (a permitted POST must not run as another method upstream) |
| Request body above `maxBodyBytes` | 413 `payload_too_large`, connection closed |
| PDP denies | 403 `forbidden`; the upstream is not called |
| `notify` obligation without a hook, or the hook fails | 502 `obligation_unenforceable`, before forwarding. A missing hook refuses before any decision token is spent; the hook runs after the token is consumed (a 409 notifies nobody), and when it fails the reservation is reported `failed`. A list notifies once every allowed item is released |
| Certified command (`decisionToken` obligation) | the token is consumed (`/x/v1/tokens/consume`) before forwarding; refused → 409 `conflict`. After the upstream answers, the reservation is reported (`/x/v1/tokens/outcome`): 2xx `completed`, 4xx except 408 `failed` (the upstream refused it); 3xx, 408 and 5xx leave it reserved (the command may have run before the error answer); no answer reports `failed` only when the connection was never made (refused, unresolvable, unreachable), otherwise (timeout, reset, oversized answer) it stays reserved. A report that fails leaves it reserved and the client still gets its answer; the decision log line carries `reservation: completed | failed | pending` |
| Certified command on a type with IVPs (`decisionToken.postState`) on a route without `postState: 'body'` | 502 `obligation_unenforceable`, token not spent |
| Route with `postState: 'body'` | the JSON body is also `context.input` of the decision (C5 validators, §3.12) |
| Every forwarded request | carries `gate-assertion` (§2.0.2), from `/x/v1/assertions/evaluation` or, for a list, `/x/v1/assertions/list`; a client-sent `gate-assertion` is dropped and a route cannot allowlist it |
| List the PDP gives no assertion for (no item of the type can be allowed) | 200 with an empty items field; the upstream is not called |
| Route with `postState: 'body'` whose body is not a JSON object (`application/json`), or names one key twice in any object | 400 `bad_request`, before the PDP is asked (the bytes forwarded and hashed must have one meaning for every JSON parser) |
| Unknown obligation key or malformed PDP answer | 502 `unenforceable_decision`, before forwarding |
| `redact` / `fieldAllowlist` / `maskClasses` on a body that is not a JSON object (`application/json`, identity encoding), or a class the record's `content` fragments do not carry | 502 `obligation_unenforceable` |
| PDP unreachable or erroring | 503 `pdp_unavailable` |
| Upstream non-2xx | same status for 4xx/5xx (502 otherwise), body `{ "error": "upstream_error" }` (the upstream body is not released) |
| Upstream unreachable / too large / slow | 502 `upstream_unavailable` / 502 `upstream_too_large` / 504 `upstream_timeout` (`upstreamTimeoutMs` bounds the whole exchange, not only socket idleness) |

- Obligation paths are dotted paths in the response object, as in the SDK's `enforce()`; masking replaces the text of
  `content: [ { class, text } ]` fragments of the listed classes with `[MASKED]`.
- **Lists** (GET only, since the upstream is called before the per-item decisions): a list assertion first, then one batch evaluation for the item ids found
  at `list.items` (at most 1000), denied items dropped (hidden means absent), each allowed item enforced with its own
  obligations, and only the items field released: sibling fields such as totals or cursors are dropped because they
  may count hidden items. Any item without a string id, or an item whose obligations cannot be enforced, refuses the
  whole response (502 `list_unenforceable` or `obligation_unenforceable`).
- **Headers.** Hop-by-hop fields (RFC 9110 §7.6.1: `Connection`, every field it names, `Keep-Alive`, `TE`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`, `Proxy-Authorization`, `Proxy-Authenticate`) never cross, either way. Request fields
  are an **allowlist**: `Content-Type`, `Accept`, `Accept-Language`, `If-Match`, plus the route's
  `headers` (lower-case names; credentials, `Host`, framing, `Forwarded`/`X-Forwarded-*` and method overrides cannot be
  listed: `createGateway` throws). Everything else, identity headers such as `X-User` or `X-Api-Key` included, is
  dropped. The gateway sets `Content-Length` and `Accept-Encoding: identity`. **Query:** only the parameters the
  route's `query` lists are forwarded (repeated values kept, in order); others are dropped. A rewritten body drops `Content-Length`, `Content-Encoding`, `ETag`,
  `Content-MD5`, `Digest` and `Last-Modified` of the original. Every answer carries `Cache-Control: no-store`.
- **Client address.** `context.ip` and the network are the socket's address. Behind a load balancer, set
  `trustedProxies` (the format of the PDP's `TRUSTED_PROXIES`): X-Forwarded-For is then read only from a connection a
  trusted proxy opened, and the client is its rightmost hop that is not itself a trusted proxy. Without it the header
  is ignored, and every client behind the balancer shares the balancer's address, which may pass `ipRanges` or
  `trustedNetworks` for everyone; the gateway warns at creation.
- **Network.** `trusted` only when the client address is in `trustedNetworks`.
- **Not done:** https upstreams, GraphQL, the SQL filter path for lists.

