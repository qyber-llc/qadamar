# Documentation truth audit (2026-11-10)

Scope: `README.md` and every file in `docs/` except `docs/market`, checked against the code and tests of v0.3.0.
`SECURITY.md` was checked too because SUPPORT.md refers to it. Method: each verifiable claim (capability, "not done"
list, count, number, default, variable, route) was traced to a file and line or to a test run on 2026-11-10; the
test and coverage figures were measured, not copied. External facts (vendor documentation, standards dates, laptop
benchmark figures) were not re-checked: no network, and PERFORMANCE.md figures are dated measurements.

**36 documentation claims corrected, 2 code defects fixed.** Files checked and found accurate: DEPLOY.md,
REBAC-ANALYSIS.md, AUTHZEN-CONFORMANCE.md (163/163 official vectors re-run: `AUTHZEN_OFFICIAL total=163 passed=163`).

## Code defects fixed (the documents were right, the code was not)

| # | Where | Defect | Fix | Evidence |
|---|---|---|---|---|
| D1 | `Dockerfile` runtime stage | DEPLOY.md §1 says the runtime stage holds the server sources, but `packages/sql` was not copied while `packages/pdp-http/src/pdp.ts:2` imports `../../sql/src/index.ts`: the image could not start. | `COPY packages/sql/...` added; `tools/ci/checks.sh` now fails when the runtime stage misses a package the server imports. | Runtime file set reproduced locally: `ERR_MODULE_NOT_FOUND .../packages/sql/src/index.ts` before, `server.ts` loads after. The image itself was not built (base image not available offline). |
| D2 | `packages/pdp-http/src/profile.ts` | The production refusal said `BREAK_GLASS_WEBHOOK must use https (plain http only on loopback)` and let loopback http pass, but the notifier refuses every http URL (`notify.ts`, `endpoint`). | The profile requires https and says so. | `packages/pdp-http/test/profile.test.ts` (new assertion: loopback http refused). |

`packages/pdp-http/src/siem.ts` now reads `SIEM_BATCH_SIZE` and `SIEM_INTERVAL_SECONDS` by name (same behaviour) so the
configuration check can see them.

## Corrected claims

| # | File / section | Old | New | Evidence |
|---|---|---|---|---|
| 1 | README, Test it | 487 package tests | 500 (core 61, sql 19, sdk 17, gateway 15, pdp-http 388; 30 need PostgreSQL) | `node --test packages/<p>/test/*.test.ts` per package with `TEST_DATABASE_URL`; 500 passed |
| 2 | README, Test it | coverage 99.3 % lines, 90.2 % branches, 95.8 % functions | 99.3 / 90.3 / 95.9 | coverage run with PostgreSQL: 99.31 / 90.32 / 95.85 |
| 3 | README, Layout | `packages/pdp-http` "Node standard library only" | "Node standard library plus `pg` (PostgreSQL mode)" | `packages/pdp-http/package.json` (`pg` 8.23.1); `postgres.ts`, `profile.ts` import `pg` |
| 4 | README, Not done yet | not done: "backups … backup/restore drills" | backup and restore scripts with a drill test exist; not done: replicas, scheduled backups, encryption at rest, a drill on production-sized data | `scripts/ops/backup.sh`, `restore.sh`; `packages/pdp-http/test/backup-restore.test.ts`; DEPLOY.md §4 |
| 5 | QUALITY.md | 190 tests, 169 passed, 21 skipped (without PostgreSQL) | 500 tests, 470 passed, 30 skipped; 500 passed with PostgreSQL | coverage runs with and without `TEST_DATABASE_URL` |
| 6 | QUALITY.md | skipped = "20 live-PostgreSQL control-plane tests and the live SQL conformance test" | 29 in pdp-http, 1 in sql | skipped test names mapped to their files |
| 7 | QUALITY.md | coverage 87.15 % / 86.15 % / 93.57 % | without PostgreSQL 91.12 / 88.98 / 94.84; with 99.31 / 90.32 / 95.85; per-package table added | coverage summaries; lcov aggregate per package |
| 8 | QUALITY.md | `postgres.ts` 13.79 % covered without a database | 14.65 % | coverage summary without PostgreSQL |
| 9 | QUALITY.md | admin console: 15 markup tests | 36 tests (render and i18n) | `node --test apps/admin/test/*.test.ts`: 36 passed |
| 10 | CI.md, What it runs | 15 admin server-rendered markup tests | 36 admin console tests (plus the new configuration, Dockerfile and SBOM checks) | as 9; `tools/ci/checks.sh` |
| 11 | PRODUCT.md §3, Cedar row | "Cedar is a candidate policy language for our core (decided in ARCHITECTURE.md)" | recommended for tenant policies (ARCHITECTURE §3.4) but not integrated; tenant rules use the JSON condition language | no Cedar dependency in any `package.json`; `packages/core/src/conditions.ts`; README "Not done yet" |
| 12 | PRODUCT.md §4 | capability table read as the product | adds what is not built: AI grounding enforcement, OCR redaction, HMAC-signed gateway-to-backend calls, search and export enforcement | no OCR or grounding code in `packages/*/src`; `packages/gateway/src/gateway.ts` forwards without a signature |
| 13 | SECURITY.md | "Only the current 0.2.x release line …; versions before 0.2.0 unsupported" | 0.3.x; before 0.3.0 | every `0.3.0` manifest; CHANGELOG `[0.3.0]` |
| 14 | API.md §0 Hidden means absent | 404 only for denied reads with `BLP.NO_READ_UP`, `MAC.COMPARTMENT`, `NET.*`, `NTK.NO_REASON` | any denied read, whatever action is explained | `pdp.ts:51-52`; `review-regressions.test.ts:15-21` |
| 15 | API.md §0 Errors | list ends at `internal` 500 | adds `unsupported_media_type` 415 and `unavailable` 503 | `http.ts:40,46`; `postgres.ts:267,315,…` |
| 16 | API.md §2.0.1 Spans | families "plus `xacml`" | `xacml` is already a family | `metrics.ts:99`; `router.ts:191` |
| 17 | API.md §3.1.2 TOTP, lost seal | cannot sign in (`503`) | the same `401`, so the password is not confirmed | `auth.ts:185,203`; `totp.test.ts:93-95` |
| 18 | API.md §3.6 Break-glass | `0 < hours ≤ 4` | and not above the bundle's `needToKnow.breakGlassMaxHours` | `admin/break-glass.ts:19` |
| 19 | API.md §3.6 Break-glass | 422 for BLP, compartments or network | adds Biba, and any other remaining deny with its rule ids | `admin/break-glass.ts:32-36` |
| 20 | API.md §3.10 `SIGNING_KEY_SEAL` | legacy plaintext `signing-private.pem` deleted | only in file mode | `tokens.ts:90-97` |
| 21 | API.md §3.10 keyring | keyring lives in `DATA_DIR`, not in the database | in PostgreSQL mode it is the `signing_keys` row of `gate_doc` | `server.ts:142-143`; `tokens.ts:32-36` |
| 22 | API.md §5 Gateway | upstream non-2xx: same status | same status for 4xx/5xx, 502 otherwise | `gateway/src/gateway.ts:148` |
| 23 | ARCHITECTURE §4 Signed decisions | token bound to a digest of the patch and subject; lives 15 s | bound to subject, action, resource id and version, policy version, single-use id; lifetime `clarkWilson.tokenTtlSeconds` (15 s in the toy bundle, at most 300) | `tokens.ts:10,100-103`; `core/src/validate.ts:135`; toy `bundle.json` |
| 24 | ARCHITECTURE §4 | `SIGNING_KEY_SEAL` mandatory with PostgreSQL | unless `ALLOW_CLEAR_SIGNING_KEYS=true`, which production refuses | `server.ts:94-95`; `profile.ts:35` |
| 25 | ARCHITECTURE §4 `search/subject` | admin plane only, within delegated scope | a PEP credential, like the other searches; the scoped console version is `/admin/v1/simulate/who-can` | `router.ts:144-145`; `pdp.ts:130-140`; `admin/simulator.ts:29` |
| 26 | ARCHITECTURE §4 `/x/v1/simulate` | listed as an endpoint | not built; the console simulates through `/admin/v1/simulate/*` | `pdp.ts` routes; `admin/simulator.ts:11-17` |
| 27 | ARCHITECTURE §6 | SCIM in API §3.10 | §3.11 | API.md heading |
| 28 | ARCHITECTURE §9 | `/metrics`: commit and active-node metrics | adds break-glass notice metrics | `metrics.ts:50-53` |
| 29 | ARCHITECTURE §14 | as-built layout without sdk and gateway | adds `packages/sdk`, `packages/gateway` | repository layout |
| 30 | ARCHITECTURE §15 tracing | span attributes: route family, status, effect, rule ids | adds HTTP method | `tracing.ts:61` |
| 31 | ARCHITECTURE §15 "Still design only" | omitted unbuilt items | adds in-SDK Wasm evaluation, gRPC, relations pushed down as SQL `EXISTS`, generated RLS backstop, AI/RAG filter, redaction service | no such code in `packages/*/src`; `sdk/src/client.ts:37-62`; `sql/src/index.ts` |
| 32 | ADMIN-UI.md, As built | 403 text "not part of your role" | "Your role does not include this section." | `apps/admin/src/i18n/security.ts:8` |
| 33 | ADMIN-UI.md, As built | policy bundles are not signed | each publication is signed (Ed25519); not distributed to separate PDPs, no bundle age | `policy-signature.ts:7-40` |
| 34 | ACCESSIBILITY.md | secret panel heading "takes focus" | is a programmatic focus target (`tabindex="-1"`); focus movement untested | `apps/admin/test/i18n.test.ts` |
| 35 | ACCESSIBILITY.md | 403 text "not part of your role" | "Your role does not include this section." | `apps/admin/src/i18n/security.ts:8` |
| 36 | PERFORMANCE.md | startup reads only rows after the last full recheck | outside `GATE_PROFILE=production` | `postgres.ts:69,377`; `server.ts:225` |

## Added (gaps, not corrections)

- `docs/CONFIGURATION.md`: the 41 variables the server reads, generated by `scripts/docs/env-table.ts`; CI fails on a
  variable read but not documented, documented but not read, or a stale file. README links it.
- README: the Clark-Wilson certification walkthrough (lina proposes, omar approves), now possible in the demo.
- QUALITY.md: per-package tests and coverage; CI.md: the release workflow.
- `docs/RELEASE.md`, `docs/SUPPORT.md` (template, every commitment TO DECIDE).

## Found, not fixed (owner or follow-up)

- Any PEP credential can call `POST /access/v1/search/subject` (who can access a resource) without a delegated scope;
  the design said admin plane only. Owner decision whether that is acceptable (`router.ts:144`, `pdp.ts:130-140`).
- Refused admin writes outside the change, review, session, security and break-glass routes (e.g. the simulator) are
  audited with `type: 'simulation'`, which `GET /admin/v1/audit?type=`
  rejects, so they cannot be filtered by type (`router.ts:181-182`, `admin/audit.ts:17`).
- SCIM requests are counted and traced under the `static` route family (`metrics.ts:88-104`).
- `IMPACT_MAX_EVALUATIONS` is validated at the first proposal (a 500 then), not at start (`admin/changes.ts:184-189`).
- Stale comment in `pdp.ts` (`/x/v1/tokens/consume`) about indexing history by resource: the index exists
  (`runtime.ts:73-89`).
- `scripts/bench/common.ts:143` resets `gate_doc`, `gate_audit`, `gate_anchor` but not `gate_audit_meta` (benchmarks only).
- Not verified: vendor and standards facts in PRODUCT, ARCHITECTURE and REBAC-ANALYSIS (no network); PostgreSQL-only
  behaviour in API.md §3.9.1 was read, not re-run beyond the test suite.
