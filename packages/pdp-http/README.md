# PDP HTTP and admin control plane

Run from the repository root using Node 22.18 or newer (TypeScript type stripping):

```sh
node packages/pdp-http/src/main.ts
```

Defaults: `HOST=127.0.0.1`, `PORT=8787`, `DATA_DIR=data/runtime`,
`WORLD_DIR=examples/toy-domain`. `CLOCK=fixed:2026-11-08T10:00:00Z` pins time.
First startup writes passwords and the PEP API key once to
`DATA_DIR/INITIAL-CREDENTIALS.txt` (JSON text, mode 600). Nothing secret is logged.
The file has `passwords` keyed by administrator username and `pepApiKey`.

Deployment settings are documented in [docs/API.md](../../docs/API.md): `PUBLIC_ORIGIN`,
`TLS_CERT_FILE`/`TLS_KEY_FILE`, the `OIDC_*` variables and `PASSWORD_LOGIN` (§3.1.1, console
sign-in through the organisation's IdP with PKCE and MFA evidence), `DATABASE_URL` (§3.9.1,
PostgreSQL control plane: one active node and waiting standbys, or with `GATE_CLUSTER=true` every node deciding
and one leader for the admin plane), and `TSA_URL`,
`TSA_CA_FILE`, `ANCHOR_INTERVAL` (§3.9.2, RFC 3161 anchoring of the audit).

```sh
curl http://127.0.0.1:8787/.well-known/authzen-configuration
node --test packages/sql/test/*.test.ts packages/pdp-http/test/*.test.ts packages/core/test/*.test.ts
```

`createServer({ port: 0, dataDir, clock })` returns `listen()`, `close()` and `url`.
`clock` also accepts a function for advancing-clock tests. `staticDir` and `rateLimit`
are optional test/deployment overrides. The default request bucket is 120/minute
per IP and principal; login is five/minute per username/IP. Login lockouts persist.
Session cookies use Path=/admin. Sessions expire on restart. Expired and consumed
JWS ids are persisted so a restart cannot replay a previously consumed token.

## Contract choices and limitations

- Emergency notifications are durable audit metadata (`details.notify`) plus the
  persisted review queue. No email, webhook or other outbound delivery transport is
  configured or implemented. This is the deviation from the API's “notified” wording.
- Emergency admission evaluates with a trusted-network baseline and refuses BLP/MAC
  restrictions and inactive or ineligible subjects. Every subsequent access request
  still evaluates its actual network and all other policy conditions.
- Impact evaluates every subject/resource/declared-action combination in both the
  trusted and the untrusted network at the server clock, with the same performed-action
  history and server-known maker as real decisions, and delegators resolved for both
  worlds. It is bounded by `IMPACT_MAX_EVALUATIONS` (docs/API.md §3.5). Owner responses
  filter impact rows and counts by resource type and id. Impact rows retain subject and
  resource types alongside their ids.
- Invalid or extra change fields are rejected. `grantedBy` is always the real maker,
  even if supplied in the tuple payload. A proposal's payload is normalized with
  timestamps and server provenance. Resource attribute updates increment its version.
- Batch evaluation and page sizes are capped at 1,000; the default search page is 100.
  The contract does not specify these bounds. Discovery is also rate limited.
- `state.json` stores the complete effective world, proposals, emergency records and
  policy publication metadata in an atomic snapshot, rather than a differential overlay.
  Only the effective world enters `stateDigest`; pending proposals, audit appends and
  sessions do not stale otherwise valid proposals. Persisted effective state wins at restart.
- Compliance's `AUDIT.*` and `ADMIN.*` identifiers describe server controls; `CW.*`,
  `BLP.*`, `MAC.*`, `NTK.*` and other engine identifiers describe actual engine rules.
  Evidence is counted from audit records. UAE IA remains unmapped.
- Not implemented: signed policy bundles and a maximum bundle age (ARCHITECTURE.md §9);
  the policy version is a content fingerprint, and only decision tokens are signed (Ed25519).
  Without `DATABASE_URL` there is one node on local files, for demonstrations only; with it,
  one node is active at a time and the others wait as standbys, or (`GATE_CLUSTER=true`) every node decides, each on
  its own audit chain, while the admin plane stays on one leader.
  No OIDC back-channel logout. One PEP API key is shared by all enforcement points.

## Verification environment

The tests use native `node:http` request/response objects in process, so all HTTP handling
is tested without a socket. A separate port-0 integration test starts a real server and
skips **only** when the environment refuses localhost binding (`listen EPERM`); on
2026-11-10 it ran and passed. The PostgreSQL tests run only when `TEST_DATABASE_URL` points
at a throwaway database (`tools/ci/postgres.sh start`) and skip otherwise.

## Layout

- `src/server.ts` builds the server; `src/main.ts` reads the environment and starts it.
- `src/router.ts`, `src/http.ts`, `src/static.ts`: routing, request limits, the console's static files.
- `src/pdp.ts`: AuthZEN evaluation, batch and search endpoints, `/x/v1/explain`, `/x/v1/filter`, token consumption.
- `src/auth.ts`, `src/oidc.ts`, `src/ratelimit.ts`, `src/tokens.ts`: sessions, password and OIDC sign-in,
  rate limits and lockouts, Ed25519 decision tokens.
- `src/runtime.ts`, `src/store.ts`, `src/postgres.ts`: effective world and its storage on files or PostgreSQL.
- `src/audit.ts`, `src/anchor.ts`: hash-chained audit and RFC 3161 anchoring.
- `src/admin/*`: the admin API (overview, model, simulator and access matrix, changes, break-glass, reviews,
  compliance, audit, session).
- `test/*.test.ts`: node:test suites; `test/helpers.ts` and `test/tsa.ts` are shared fixtures.
