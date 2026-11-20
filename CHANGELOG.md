# Changelog

All notable changes to Qadamar are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Approvals inbox in the console: tabs (Awaiting you, Pending, Snoozed, Applied, Rejected, All), break-glass items
  awaiting the user's review in the queue (linked to the Break-glass screen), keyboard shortcuts (J/K, Shift+J/K, X,
  S, A, Enter; none while typing) and per-user snoozes of up to 30 days that end early when the item changes.
- Approval modes: an access admin or a security officer switches each approver between `individual` (default) and
  `list` (Credentials and keys screen), at once and audited. In list mode an approver approves or rejects up to 50
  changes with one note (`POST /admin/v1/changes/decide`); every item goes through the single-decision checks and gets
  its own audit row, and the server refuses the route in individual mode (403 `individual_mode`).
- `GET /admin/v1/inbox`, `GET` and `PUT /admin/v1/approval-modes`, `POST` and `DELETE /admin/v1/inbox/snoozes`
  (docs/API.md §3.5.1), stored in the new `approval_prefs` document (`gate_doc`, or `approval-prefs.json`).

### Changed

- The signed-in console takes the look of the product's explainer videos (`apps/admin/src/styles/gate-skin.css`):
  a near-black ground with a faint grid instead of the carbon-fibre image, flat dark panels with 8px corners, small
  uppercase mono labels (left as plain text in Arabic so letters stay joined), sans-serif titles, neutral sidebar
  tiles with green only on the current screen, and colour by meaning: green permits, red denies, amber warns, ice
  marks focus. Buttons on green or red carry dark text. The sign-in page is unchanged. The carbon backdrop image is
  removed.
- The sign-in page takes the same look: the card on the video ground, and beside it the engine core from the videos
  (the PDP hexagon in turning rings, still under reduced motion) with the product name. The gate scene, its loop and
  entry videos, the door sound and the opening sequence are removed; a successful sign-in opens the console at once.
  The page is dark in every colour scheme. No generated media remain in the console (AI inventory AIS-06 retired).

### Fixed

- Approvals queue in list mode: the checkbox column took the 32% width meant for the change column; the row
  checkbox is now 24px instead of a 40px box.

## [0.12.2] - 2026-11-17

### Fixed

- Kubernetes: the database egress policy now also selects pods of component `restore`. Since the policy was narrowed to
  `server`, `migrate` and `backup`, a restore pod (the drill or a real restore) could not resolve or reach PostgreSQL.
- `scripts/managed/smoke.sh` follows the 0.10–0.12 API: PDP session tokens instead of a raw `sessionId`, a PEP
  credential scoped to `network` (production gives `bootstrap` none) that consumes the tokens it asked for and is
  revoked at the end, break-glass revoked and reviewed by a second security officer (with OIDC there is no
  access_admin fallback), the restored table count compared with the source, and PDP sessions closed at exit.
- The local test IdP has a second security officer, `noor`.
- Upgrade notes: the `used_at` entry is 0.12.1, and a bulk `UPDATE … SET used_at = now()` is warned against (it would
  make actors and world subjects purgeable for good).

## [0.12.1] - 2026-11-17

The `v0.12.0` tag was never published: its signing step failed because the key was not on the release runner.
0.12.1 carries the same code as 0.12.0 and is the first signed release.

### Changed

- The release signing key lives on the release runner; its passphrase is the repository secret
  `RELEASE_SSH_KEY_PASSPHRASE`, passed only to the packaging step, because the headless runner has no usable Keychain.
  `scripts/release/allowed_signers` and docs/RELEASE.md carry the new public key
  (`SHA256:U/RyBx903hqHtefYsdz4E8w1miTh+im23nQHSU6S3ew`).

## [0.12.0] - 2026-11-17 (tag only, not published)

### Security

- Releases are signed: `SHA256SUMS.sig` is an SSH ed25519 signature (`ssh-keygen -Y sign`, namespace `file`) checked
  against `scripts/release/allowed_signers` before publication; docs/RELEASE.md gives the key and the verification command.
- `POST /x/v1/filter` is audited: one `decision` row per answered call (`GATE.FILTER` / `GATE.FILTER_NONE`,
  `details.residual`).
- A 0.8.3 scrypt PEP key or SCIM token hash is verified on the thread pool, never with a synchronous scrypt on the event
  loop; it is still upgraded to HMAC on first success.
- Gateway: on `postState: 'body'` routes, a JSON body that repeats a key is refused (400), so the PDP and the upstream
  cannot read two different commands from the certified bytes.
- Break-glass cannot be re-opened for the same subject and resource while one is active or unreviewed
  (`409 break_glass_pending`); a revoked or expired emergency must be reviewed first. The console's break-glass review
  and revoke are closed to the grant's subject as well as its opener.
- The sovereign-uae decision replicas serve TLS from `gate-pod-tls` and are probed over HTTPS.
- The image build activates pnpm by version and sha512 hash; `new-tenant.sh` refuses images named by tag on any
  non-local overlay.
- The operations database tools (`backup.sh`, `restore.sh`, `audit-retention.ts`, `migrate-records.ts`) default to the
  production TLS profile (`verify-full`) unless `GATE_PROFILE=demo` is set.

- Subject pseudonym mappings of ids used only as PEP decision subjects are deleted after 90 days without use
  (crypto-shredding), so PEP-chosen subject ids no longer grow `gate_subject_identity` / `audit-subjects.json` and the
  in-memory map without bound; the purge is audited as `subject_mappings_purged { count }`. World subjects, local
  console accounts and any id ever used as an actor or a person detail are never purged, so admin actions stay attributed.
- Break-glass review and revoke fall back to an access_admin (never the opener or the subject) only when no security
  officer other than the opener and the subject exists among local accounts, and never when OIDC or SAML sign-in is
  configured; the audit row records `reviewerRole` and `fallback`.

### Changed

- New column `gate_subject_identity.used_at` and schema marker `gate_subject_identity_used`: the owner runs `SCHEMA` on
  upgrade; mappings that exist before the upgrade are kept.
- `GET /admin/v1/break-glass` also returns `fallbackReview`; the console offers the fallback to the eligible access_admin
  (fr, en, ar), and `break_glass_pending` reads "awaits review".
- Pull requests keep running on the self-hosted runner (owner decision); fork pull requests run no workflow (docs/CI.md).
- **`context.now` must be a full ISO-8601 instant** with an explicit `Z` or `±hh:mm` offset, on a real calendar day. A
  zone-less instant (read in the host's time zone), hour 24, a legacy `Date.parse` format or a date-only value is now
  `ENGINE.MALFORMED_REQUEST`, and the residual filter returns no rows. The Lean model refuses the same instants. The HTTP
  PDP sets `now` itself and is not affected.
- **A request whose subject, resource or context holds a number beyond ±(2^53 − 1) is `ENGINE.MALFORMED_REQUEST`**:
  two different integers there could compare equal in conditions. Store such identifiers as strings. The Lean model
  refuses the same requests.
- Gateway: notifications run only after the decision token is consumed, and for lists once every allowed item is
  released; a failed notification reports the reservation `failed`.
- docs/API.md and THREAT-MODEL.md state that a context attestation is reusable until `exp` (at most 300 s), with no
  `jti` memory on any node.

### Fixed

- In cluster mode, a node no longer exits when another node stored a subject's pseudonym first: it adopts the stored
  mapping and re-hashes only its uncommitted rows.
- `/healthz`, `/readyz` and `/leaderz` answer before the rate limiter, so a full or drained bucket map no longer takes a
  healthy node out of its pool; `/metrics` stays limited and token-gated.
- The subject access report includes what the person did: grants made, emergencies opened or reviewed, certifications,
  publications, and audit rows as actor.
- The certify_tp impact preview shows the access the certification opens. A certify_tp proposal made before this
  version answers 409 stale at approval and must be proposed again.
- Console: Approve and Reject are disabled where the server would refuse them, with the reason; the Explain drawer hides
  a decision once its session level, maker or prior actions are edited and shows those inputs; impact tooltips, version
  ranges, break-glass labels and change summaries (SCIM batches included) come from the fr/en/ar catalogues, with
  arrows that read correctly in Arabic.

## [0.11.0] - 2026-11-17

### Security

- A single evaluation that also carries an `evaluations` key no longer skips the PEP credential's context scopes.
- SDK `enforce` refuses obligations it cannot enforce (including a redaction path that crosses an array) and its
  network calls are bounded.
- Evidence packs pseudonymise the owner of each grant, like every other subject reference.
- Refused admin and SCIM requests are capped in the audit log per source, authenticated actor, route family and error,
  so a flood of refusals cannot fill it. SAML logout, OIDC back-channel logout and malformed console logins are covered.
- The OIDC state cookie is now `__Host-gate_oidc`: always `Secure`, `Path=/`, no `Domain`.
- CI and the release gate build and scan the operations image as well as the runtime image, and no workflow checkout
  keeps its git credential.
- The operations image moves to a slim base: the digest-pinned Alpine node image plus `bash` and the PostgreSQL 17
  client only, with no PostgreSQL server, LLVM or `gosu` (603 MB to 263 MB; the image scan, still blocking on fixable
  HIGH/CRITICAL, finds none). The offline local build keeps the PostgreSQL 17.11 base (`OPS_BASE=runtime-base-postgres`).
- The in-memory rate limiter, once it holds 10 000 buckets, only drops a bucket that has refilled: a sender with many
  addresses can no longer reset its own drained buckets. While every bucket is still draining, a new key is refused (429) until the first one has refilled.

### Changed

- **Policy bundle validation is closed.** Unknown keys in resource types, actions, rules and configuration objects are
  rejected, flags must be booleans, `needToKnow.protect` is required, and separation-of-duty rules and Biba
  no-read-down lists may only name declared actions. The JSON schema says the same (`additionalProperties: false`).
  A bundle that carried stray keys must be cleaned before it is accepted.
- Break-glass refuses a subject or resource id that matches more than one record, and its error message reports the
  configured hour cap rather than the fixed maximum.
- CI runs the full gate when `docs/CONFIGURATION.md` or `CHANGELOG.md` changes.
- CI and the release workflow run a backup and restore drill inside the built ops image
  (`tools/ci/ops-image-drill.sh`): the image's own scripts, PostgreSQL client and Node, as its unprivileged user,
  against a throwaway database seeded by the release image. An ops image that cannot back up and restore now fails the gate.

### Fixed

- Gateway: `If-None-Match` is no longer forwarded upstream. A 304 answer was refused as a non-2xx (502); every released
  answer is `no-store`.
- Console: impact and change responses are checked row by row (each gained, lost and obligation row), so a malformed
  answer shows as an invalid response instead of breaking the approvals or simulator screen.
- The operations image places `database-tls.ts` beside `backup.sh` and `restore.sh`: both scripts stopped at their
  first step in the image, which only had the helper under `/app`.
- Bundle validation no longer throws on a resource type without an `actions` object.
- File-mode audit: a retention interrupted after the segment was written is completed on the next start instead of
  failing verification.
- Console: the approvals screen cannot open a change other than the selected one and ignores stale responses;
  break-glass shows the real error and enforces the tenant hour limit; a submitted-change banner clears when the
  candidate changes and an unchanged candidate cannot be submitted twice; logout only navigates to HTTPS or
  same-origin URLs; an expired session requires reauthentication; an empty response is rejected where a validated
  body is required.
- The managed smoke script checks the renamed OIDC state cookie.

## [0.10.1] - 2026-11-11

### Fixed

- CI and the release gate run the browser checks again on the macOS arm64 runner: the Chrome for Testing
  headless-shell archive for that platform is pinned in `tools/ci/playwright-lock.json` (`macArm64ArchiveSha256`,
  recorded 2026-11-11), next to the Linux one. 0.10.0 was tagged but never published: its browser step refused the
  unpinned macOS download and stopped the release.

## [0.10.0] - 2026-11-11

### Security

- **PEP credentials now bound context claims to explicit scopes.** `contextScopes` limits the network, IP, country,
  device, authentication, risk and session-level signals each credential may assert, with optional network/country
  constraints. Out-of-scope claims are refused and audited on every decision mapping, never silently dropped. Scopes can
  require short-lived Ed25519 or ES256 JWS attestations from configured public keys, bound to the exact value, subject,
  PDP session when present, device/network source, PEP, audience and expiry, so a legitimate attestation cannot be
  replayed for another user, session, device or sensor. Demo keeps legacy unscoped credentials for one version with deprecation warnings; production
  requires scopes for new credentials and gives older unscoped credentials no permitted signals.
- **PDP sessions are immediately revocable.** Their existing subject and PEP-credential binding is joined by an audited
  security-officer API revoking by token id, subject or credential. Live-row deletion and tombstones commit atomically
  with audit on PostgreSQL, use the same decision locks on every cluster node, and propagate through the signed replica
  feed. Revocation invalidates both session tokens and unconsumed decision tokens issued under them (`bsid`).

### Added

- Change-impact previews partition the CBAC signals referenced by old and new rules and report gains, losses and
  obligation changes per representative context class. Countries, CIDRs, zoned time-window edges, authentication ages,
  risk thresholds, device posture, methods, missing signals and session expiry are covered, with deterministic output,
  a 32-class-per-network cap and an explicit truncation flag. Broadening and approval-time checks use the same analysis,
  and the console shows the classes in English, French and Arabic.
- `mandatory.bibaNoReadDownScope` generalizes Biba no-read-down from the compatible per-action list (`actions`, the
  default) to every read-kind action (`reads`) or every action (`all`). Point decisions and SQL filters share the option,
  effective-coverage narrowing is governed as a mandatory weakening, and the Lean model, proofs and differential fuzzing
  cover all three scopes.
- TypeScript and Python SDK context types carry per-signal attestations plus `device.id` and `networkSensorId`, and the
  enforcing gateway's `attestContext` hook supplies fresh evidence after resolving the client IP and network. The admin
  API also lists session revocation tombstones.
- Reproducible resident-memory and index-size benchmark at 10k, 100k and 500k subjects/resources/tuples,
  with raw results and limits documented in `docs/PERFORMANCE.md`.
- Tenant-partitioned loading through `GATE_TENANTS_FILE` and `GATE_SERVE_TENANTS`: only selected isolated
  tenant stores are loaded. Requests require `X-Qadamar-Tenant`; other tenants receive 421 `tenant_not_served`.
  Cluster coordination, shared rate limits, replica feeds and audit ingestion retain separate tenant databases
  and keys. Differential tests cover decisions, searches, SQL filters, live updates and PostgreSQL replicas.
- SAML encrypted assertion decryption through mounted SP key/certificate pairs, preserving signature, algorithm,
  audience, recipient, time, MFA and replay checks. Signed HTTP-Redirect single logout, correlated LogoutResponse
  handling on POST/Redirect, and SP-initiated console sign-out revoke matching sessions before contacting the IdP.
- Tested integration examples for shared PostgreSQL backend assertion replay protection and SQL filtering followed
  by point-wise history checks and obligation enforcement, with a handbook walkthrough.
- Arabic console catalogue, persisted language selection, RTL layout with logical CSS, mirrored directional icons,
  and LTR codes and numbers. Native Arabic review remains required before customer use.
- Browser assertions for 320 CSS-pixel reflow (400% equivalent), forced colors, keyboard navigation, ARIA landmarks
  and Arabic RTL layout snapshots; expanded catalogue and error-code parity tests to Arabic.
- Browser workflows in the CI gate, required in read-only CI/release jobs with hash-verified external Playwright and
  Chromium provisioning. Local missing/unlaunchable Chromium reports a clear skip. Fresh runners need an archive pin.
- README test summary generated from the gate's TAP results and checked for drift; summary parser regression tests.

### Changed

- The CI browser checks run on hosted Linux runners without extra setup: the Linux Chrome for Testing archive digest is
  pinned in `tools/ci/playwright-lock.json` (a repository variable `CI_CHROMIUM_SHA256` still overrides it).
- Centralised current test counts and removed conflicting copied coverage totals. Reconciled PRODUCT §4 with the
  implemented Ed25519 gateway assertions, searches and enforcement boundaries. Documented browser execution limits,
  outstanding human screen-reader checks and native Arabic review.

### Fixed

- French audit detail rows wrap long labels and hashes instead of clipping the 320-pixel console layout.
- Impact previews now derive representatives from ABAC and content-rule equality/in-list literals and numeric, instant
  and age boundaries. Unsupported comparisons mark the analysis incomplete and require security-officer approval, so a
  context-dependent ABAC permit can no longer look harmless merely because its literal was absent from the sample.
- CIDR impact analysis partitions old and new ranges by interval boundaries into membership classes for IPv4 and IPv6,
  rather than sampling one network address and a fixed outside list. Changes confined to a boundary such as `10.0.0.0/9`
  to `10.0.0.0/8` are now detected.
- Subject+credential revocation acquires candidate session UUIDs and selector scopes in one sorted order, revalidates
  candidates after locking, and retries SQLSTATE `40P01` before any batch is drained. This removes the cross-node lock
  inversion and avoids latching a healthy node.

## [0.9.2] - 2026-11-11

### Security

- The server image ships without the package managers bundled in the node base image (npm, corepack, yarn and their
  dependencies, which carried fixable HIGH findings in tar, minimatch, brace-expansion, glob and others) and brings its
  Alpine packages to their fixed versions (`apk upgrade`; musl among them). The server never used them. Found by the
  release image scan, which blocked 0.9.1: 0.9.1 was tagged but never published. Qadamar's own dependencies had no finding.

## [0.9.1] - 2026-11-11

### Fixed

- The release image builds again: Node 22.20's bundled corepack cannot start pnpm 12 (its entry point moved to
  `bin/pnpm.mjs`), so both Dockerfile stages install a pinned corepack (`COREPACK_VERSION`, 0.36.0) before
  activating pnpm. 0.9.0 was tagged but never published: its image-scan job failed on this and stopped the release.

## [0.9.0] - 2026-11-11

### Breaking

- **CBAC now means Context-Based Access Control** (owner decision of 11 November 2026). The content rules that were
  called CBAC are **ABAC on content attributes (mask, redact, deny)**. PEPs, SIEM rules and dashboards that match
  reason codes or explain-trace stages must be updated:

  | Before | Now |
  |---|---|
  | `CBAC.<rule id>` (content deny, mask, redact) | `ABAC.CONTENT_DENY`, `ABAC.CONTENT_MASK`, `ABAC.CONTENT_REDACT`; the rule id moves to the trace step's `policyRule` |
  | trace stage `cbac` for content rules | stage `abac`, step `kind: "content"` |
  | trace stage `context` | stage `cbac` |
  | `CTX.NETWORK`, `CTX.COUNTRY`, `CTX.IP_RANGE`, `CTX.TIME_WINDOW` | `CBAC.NETWORK`, `CBAC.COUNTRY`, `CBAC.IP_RANGE`, `CBAC.TIME_WINDOW` |
  | `CTX.DEVICE_UNMANAGED`, `CTX.DEVICE_NONCOMPLIANT` | `CBAC.DEVICE_UNMANAGED`, `CBAC.DEVICE_NONCOMPLIANT` |
  | `CTX.MFA_STALE`, `CTX.AUTH_STALE`, `CTX.AUTH_METHOD`, `CTX.RISK`, `CTX.SIGNAL_MISSING` | `CBAC.MFA_STALE`, `CBAC.AUTH_STALE`, `CBAC.AUTH_METHOD`, `CBAC.RISK`, `CBAC.SIGNAL_MISSING` |
  | Cedar export ids `CBAC.<id>` (content) and `CTX.<id>` (context) | `ABAC.<id>` and `CBAC.<id>` |
  | bundle field `cbac` | `abacContent` (see Deprecated) |

  The access matrix keeps its `content` and `context` layer keys; the console labels them "ABAC on content attributes"
  and "CBAC (context-based, Zero Trust)".
- Admin API: new tuples (`add_tuple`, break-glass, access-review certification) are stored with `notBefore`/`notAfter`
  instead of `validFrom`/`validTo`; readers of `GET /admin/v1/tuples` must accept both names (older records keep theirs).

### Deprecated

- The bundle field `cbac` (content rules) is accepted for one version and read as `abacContent`, with the warning
  `DEPRECATED_CBAC_FIELD` in the validation result (`warnings`), on the `publish_policy` change and its propose and
  approve audit rows, and in the console. A bundle with both `cbac` and `abacContent` is refused. Bundles already stored
  (PostgreSQL or files) load unchanged, keep their policy version and procedure fingerprints, and are published under
  the new name on their next change. A later version removes the legacy field.

### Security

- **A shared BLP mark no longer lapses under a still-valid session token.** The mark kept its own idle and absolute
  schedule, so it could lapse up to about a minute (idle) or up to an hour (absolute) before a token that referred to
  it, resetting the *-property floor while the token stayed usable. Opening a token and each recorded use now hold the
  mark until that token's idle or absolute expiry plus one minute (`gate_blp_mark.held_until`, added in place at start;
  single node and cluster), and neither the sweep nor a reload drops a held mark.
- **BLP session creation takes the subject bounds of a decision and caps each credential.** `subject.type` and
  `subject.id` must be 1..256 characters (a 10,000-character id minted a 13,672-character token decisions then
  refused); a token over the 4,096-character `context.sessionToken` limit is never issued. A new aggregate cap,
  `BLP_SESSIONS_PER_CREDENTIAL` (default 10,000, 1..100,000; 409 `session_limit`, audited `credential_session_cap`),
  counts every open session of a credential, so distinct subject ids no longer evade the per-subject cap.
- **Subject search sees the session marks other cluster nodes committed.** It names no `subject.id`, so it took no
  session lock and loaded no mark: after carol's L3 read on node A, node B's subject search for an L1 write still
  listed her. With `context.sessionId` it now locks the session and loads every subject's mark and expiry tombstone in
  it, as point decisions do.
- **Closing or expiring a BLP session revokes the certified-command decision tokens issued in it.** The token now
  carries the issuing session (`bsid`); `/x/v1/tokens/consume` locks and reads that session row (single node and
  PostgreSQL cluster) and refuses with 409 `conflict`, audited `CBAC.SESSION_EXPIRED`, unless it is open, live (absolute
  and idle expiry), and the same subject's and PEP credential's. Before, an approval minted in a closed session still
  reserved its command.
- `scripts/audit/verify-export.ts` **certifies rows only up to each signed head**: a row after a manifest head is not
  covered by the signature (anyone can append events with recomputed hashes behind a genuine pinned manifest), so it is
  reported as an unauthenticated tail and fails the check (exit 1). `GET /admin/v1/audit/export` takes
  `until=<node>:<seq>,...` (inclusive; chains not named are left out) so an auditor exports exactly up to the heads.
- **Console passwords are hashed with scrypt N=2^16, r=8, p=2**, the OWASP setting equal in cost to N=2^17, r=8,
  p=1 at half the memory (64 MiB, about 160 ms per sign-in on an Apple M5 Pro; at most two run at once, so 128 MiB at
  most); it was Node's default N=2^14. The new layer runs over the 0.8.3 key (scrypt N=2^14 of the password), and each
  hash carries its parameters (`scrypt-wrap$16$8$2$<inner salt>$<salt>$<key>`), so the cost can rise again. At start,
  every 0.8.3 hash (`<salt>:<key>`) is wrapped in place without its password, so a dormant account no longer answers in
  a quarter of the time of an unknown one: unknown, dormant and current accounts all run the same two scrypt calls
  (about 200 ms). A plain `scrypt$…` hash still verifies and is rehashed at the next successful sign-in, unless a
  reload replaced it meanwhile. The dummy hash for unknown accounts is no longer computed at start (it never matches,
  only its cost matters).
- **A full sign-in queue answers 503 at once.** At most 32 password checks wait for the two scrypt slots; past that,
  `POST /admin/v1/session` answers `503 unavailable` with `Retry-After: 3`, audited as a denied login with reason
  `busy`, instead of queueing without limit: a spray of random usernames could otherwise build a backlog that every
  administrator's sign-in waited behind.
- **TOTP enrolment checks the password off the event loop** (`verifySecretAsync`, in the same queue as sign-in), and
  decides on the live account record after the hash, as sign-in does.
- **PEP keys and the SCIM token are stored as salted HMAC-SHA256** (`hmac-sha256$<salt>$<mac>`), not scrypt. They are
  random secrets of 192 bits or more, so stretching adds nothing, and a wrong key no longer costs a synchronous scrypt on
  the event loop. A 0.8.3 scrypt hash is replaced at the secret's first successful use; the verified-digest cache is
  unchanged.
- **PostgreSQL TLS is an explicit, production-enforced policy.** `DATABASE_TLS=verify-full` is the production default
  and is required for non-local hosts, verifying both certificate chain and hostname. Optional private-CA and mutual-TLS
  client-key files cover every runtime, preflight, migration, retention, backup and restore connection; conflicting URL
  `ssl*` parameters are refused, as are repeated `host` parameters; local-vs-remote classification uses the same parser
  as node-postgres. The Kubernetes base/local overlays and evidence baseline carry the policy. Live tests use a
  throwaway TLS-enabled PostgreSQL to prove trusted connection and CA/hostname refusal.
- **Release images are vulnerability-scanned.** CI and release build the Dockerfile's default target, export it with
  `docker save` and scan the tar with tag-and-digest-pinned Trivy, blocking HIGH/CRITICAL vulnerabilities that have
  fixes. Scan jobs are read-only and never mount the Docker socket; only the release-publish job has write permission.
- `scripts/audit/verify-export.ts` **rejects rows of a chain the signed manifest's heads do not name**: a forged,
  self-consistent chain for an invented node passed before. It **no longer reports plain `ok` for evidence only
  self-consistent**: rows, manifest and JWKS all come from the tenant's server, so `ok` (exit 0) now requires a TSA
  token verified with `--tsa-ca` or a signing key held out of band (`--pin <jwks>`, with `--keyring <json>` for the key
  introductions after a rotation); otherwise `result` is `self-consistent only (not anchored)`, exit 3.
- `scripts/managed/new-tenant.sh` also refuses to apply a render that still holds the RFC 5737 documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), the placeholders of `TRUSTED_PROXIES` and the egress rules.
- **PDP-issued BLP sessions close the fresh-id laundering gap.** PEPs now open sessions with
  `POST /x/v1/sessions` and send short-lived Ed25519 `context.sessionToken` values bound to a PDP-chosen id, subject
  and PEP credential. The PDP verifies signature, bindings, expiry, idle last use and open/closed state inside the
  existing session queues and PostgreSQL advisory locks. All open tokens of one (credential, subject) share one
  high-water mark, and close/reopen does not erase it, so a PEP cannot reset the *-property by minting another session.
  Open sessions are capped per subject (`BLP_SESSIONS_PER_SUBJECT`, default 4), creation is rate-limited
  (`BLP_SESSION_CREATION_PER_MINUTE`, default 60) and audited, and `POST /x/v1/sessions/close` revokes a token.
  Production requires tokens and refuses raw `sessionId`; demo retains warned legacy compatibility. Batches, XACML,
  decision-token `sid` consumption, the gateway, replicas and both SDKs support the flow. PostgreSQL adds the shared
  `gate_blp_session` registry (owner schema/grants and backups included); replicas forward session operations and
  token-bearing decisions. Forged, expired, foreign-subject/credential and closed tokens are refused.
- **Key rotation acceptance is scoped by token type.** Decision tokens, backend assertions, policy signatures and
  key-introduction links again accept the retired key for only 300 seconds; `sessionVerifyUntil` gives BLP sessions
  their separate one-hour window. Public verification history remains in the keyring after the live JWKS entry ends,
  so archived evidence manifests still verify through the introduction chain without extending online acceptance.
- **Committed resource changes always invalidate AuthZEN search candidates.** The cache now uses the store's monotonic revision
  rather than the patch journal cleared at commit, so committed inserts, relabels and deletes cannot reuse stale positions. Search
  iteration is bounded by the candidate set's own length, preventing a stale empty set from trapping a residual scan. Differential
  tests commit changes between searches and compare every result with point decisions.

- **A live role assignment is a role everywhere.** ABAC conditions (`subject.roles`) and the BLP trusted-role exemption
  read only the unconditional roles, so a time-bound role escaped every forbid written against it. Point decisions,
  filters, search candidates, the Cedar request mapping and the Lean model now use the roles live at `context.now`;
  an assignment outside its window counts for nothing.
- **`CBAC.SESSION_EXPIRED` sticks across nodes.** An expired legacy session's mark stays as a tombstone until
  absolute expiry plus 15 minutes: every node loads it before deciding, none writes a fresh mark under that id, the
  sweep keeps it. A PDP-issued token is checked itself: an expired one stays refused (403) and never touches the
  shared mark, and a token scope is prefixed so no raw `sessionId` can name it.
- **Gateway behind a load balancer**: the `trustedProxies` option reads X-Forwarded-For only from a trusted proxy and
  takes the rightmost untrusted hop; without it every client had the balancer's address for `ipRanges` and
  `trustedNetworks`. The gateway warns when it is unset.
- CBAC IP ranges and time windows no longer cost a `BlockList` and an `Intl.DateTimeFormat` per range and per decision
  (one list per rule, one formatter per zone), and a bundle holds at most 4096 ranges and 4096 windows. IPv6 zone ids
  (`%`) are refused in `context.ip` and in ranges.
- The Cedar export writes IP ranges as `ip("…")` values and maps `context.ip` to the `ipaddr` extension value
  (structurally tested; no Cedar engine runs here). An ABAC rule id may not start with the reserved `CONTENT_`.
- CI: the Semgrep image is pinned by digest, and a test requires a digest on every workflow container image.

### Added

- **Console: registered resource inventory** (Attribute model, Registered inventory tab): per resource type, the
  registered resources with their labels, version and parent, 50 a page; the pending `register_resources` proposals
  naming the type, linked to Approvals; the retired ids, with whether each is live again. Backed by two read-only
  routes, `GET /admin/v1/resources/inventory` and `GET /admin/v1/resources/retired` (API.md §3.3): every console role,
  resource owners in their own scope and without retired ids (the log keeps no owner). English and French.
- **Console: resource types on PEP credentials.** Creating a credential offers the policy's resource types it may
  register (`resourceTypes`, fixed at creation, so there is nothing to edit later), and the list shows them.
- **Formal model of the decision core in Lean 4** (`formal/`, [FORMAL-MODEL.md](docs/spec/FORMAL-MODEL.md)): values and
  the three-valued condition language, request validation, the fixed pipeline (RBAC, ABAC, BLP with session level
  and high-water mark, compartments, network cap, Biba, need-to-know, ABAC on content attributes, CBAC context rules,
  live role assignments, Clark-Wilson, separation of duty) and the decision. Mechanised proofs, without `sorry` and on
  the standard axioms only: deny wins (forbids over any permits), mandatory controls before tenant policy (no grant,
  permit or relation lifts a mandatory denial), an UNKNOWN forbid denies and an UNKNOWN permit does not grant,
  malformed requests deny, determinism, obligations only on allow, a matched CBAC rule with a failed requirement or an
  absent signal denies (`cbac_deny_denies`, `cbac_missing_signal_denies`), an expired session denies, and a role
  assignment outside its window grants nothing (`expired_grant_not_eligible`). The relation check, the certification
  fingerprint, grant-window and CIDR / time-window / authentication-age arithmetic and the signal grammar are
  abstracted (oracle inputs); traces, reasons, filters and the server are not modelled. Toolchain `leanprover/lean4:v4.35.0`, core Lean only.
- **Differential test of `evaluate` against the executable Lean model** (`packages/core/test/lean-differential.test.ts`):
  random bundles and requests from the fuzz generators (now shared in `packages/core/test/fuzz-gen.ts`); decision, rule
  ids, obligations and would-denies must match, now also over context signals, CBAC context rules, role-assignment
  windows and legacy `cbac` bundles. 100,000 cases agreed before commit; no TypeScript bug found. Skips without a Lean
  toolchain unless `LEAN_REQUIRED=1`.
- CI and the release gate install elan and the Lean toolchain, each pinned by version and SHA-256 and the toolchain
  linked with `elan toolchain link`, so elan downloads nothing unchecked (`tools/ci/install-lean.sh`; Linux x86-64
  and macOS arm64 archives, digests from the GitHub release record), check the proofs (`formal/check.sh`) and run the
  differential test on 10,000 cases, in a job `formal` with `contents: read` that the `ci` and `release` jobs need: the
  release job's write token never shares a job with the downloaded toolchain. `tools/ci/checks.sh` stays offline.
- **UAE sovereign cloud overlay** (`deploy/k8s/overlays/sovereign-uae`), provider not chosen: a provider-agnostic
  production overlay on base with the cluster and replica components; TLS from the ingress to the pods and from every
  PostgreSQL client (`DATABASE_TLS=verify-full` against the CA of Secret `gate-postgres-tls`, required here); required node affinity to in-country zones and a
  hard zone spread; data-residency labels on every object and pod; a strict egress allow-list (cluster DNS, PostgreSQL,
  IdP, TSA, break-glass receiver, SIEM); images by digest; PodDisruptionBudget and HPA for the decision replicas;
  Secrets referenced only, with a documented external secret store pattern (`external-secrets.example.yaml`, not
  rendered). Every provider value is a PARAMETER placeholder. The k8s manifest test renders it and checks the production
  profile, TLS, no secret values, egress rules, digests, placement and storage classes.
- `scripts/managed/new-tenant.sh` accepts an overlay name (`OVERLAY=sovereign-uae`) and **renders without a cluster**
  when a cloud overlay has no `KUBE_CONTEXT` (or `RENDER_ONLY=1`): the tenant's manifests on stdout, nothing applied.
  Applying a cloud overlay is refused while placeholders remain (`example.invalid`, all-zero digests); the sovereign
  overlay also requires its extra Secrets, the database CA in `gate-postgres-tls` at `/etc/gate/postgres/ca.crt`, and
  database URLs without TLS parameters (Qadamar and the ops scripts refuse them). `upgrade-tenant.sh` requires
  `KUBE_CONTEXT` for a cloud overlay.
- **`GET /admin/v1/audit/verification`** (security officer, auditor): a signed manifest of the verified chain heads,
  sealed segments and anchors (token hashes), audited as `security audit_verification_export`; and
  `scripts/audit/verify-export.ts`, the customer's offline verifier of an audit export (signature, chains from genesis or
  sealed head, heads, anchors, tokens, `openssl ts -verify`). With `--keyring`, a manifest signed before a rotation
  verifies against the keyring's retained public key once that key has left the JWKS.
- Alert rules `GateDecisionLatencyHigh`, `GateAvailabilityBudgetBurn`, `GateReplicaStale` and
  `GateBreakGlassNoticeFailed`.
- docs/MANAGED-OFFER.md: SLO proposal (every objective TO DECIDE by the owner), quotas and limits cited to the code, the
  UAE sovereign cloud chapter (architecture, data residency, provider questions, runbook, open owner decisions) and the
  customer audit export procedure.

- **CBAC (context-based access control, Zero Trust).** Optional `context` bundle rules select actions/kinds, resource
  types, minimum levels and content classes, then require trusted network, countries, IPv4/IPv6 CIDRs, IANA local-time
  windows, device posture, fresh authentication/MFA, methods or a maximum behaviour-risk score on every request.
  Missing signals and failures deny with explicit `CBAC.*` codes and observed explain-trace values (stage `cbac`).
  Request fields are strictly bounded at the PDP (400 on malformed input), and both SDKs expose them. Context signals
  are authenticated-PEP assertions, not independent device/IdP attestation.
- **CBAC grant duration.** Role assignments (`subject.roleAssignments: [{ role, notBefore?, notAfter? }]`, set through
  `update_subject`) and relation tuples (`notBefore`/`notAfter`; `validFrom`/`validTo` still read) are evaluated
  against `context.now`, both bounds inclusive: outside its window a grant does not exist for that request, and the
  trace says so with `CBAC.GRANT_EXPIRED` / `CBAC.GRANT_NOT_YET` (outcome `skip`). The admin API still refuses a grant
  that starts in the future (its impact is reviewed when it takes effect). Point decisions, list filters and the Cedar
  request mapping agree; Clark-Wilson E4 counts a role assignment that starts later; SCIM updates keep assignments.
  PostgreSQL: `gate_tuple` gains derived `not_before`/`not_after` columns, backfilled from each record, and the index
  `gate_tuple_not_after`, the new schema marker (the owner runs `SCHEMA` on upgrade, as for earlier additions).
- **Session expiry.** `CBAC.SESSION_EXPIRED` denies when the request's session is known expired: the PDP still holds
  the BLP mark of a legacy `context.sessionId` past the 15-minute idle or 8-hour absolute expiry, or the PEP asserts
  `context.sessionExpired: true`. The list filter is empty for such a session. A PDP-issued `context.sessionToken` is
  checked itself: an expired, idle or closed token stays refused with 403 `invalid_session_token` before any decision
  and leaves the shared (credential, subject) mark untouched, so a fresh token still meets it.
- Point, search, SQL filter and list-assertion decisions share CBAC semantics; no decision cache crosses contexts.
  Policy impact and conservative weakening/two-person governance cover CBAC edits, applicable procedure fingerprints
  include them, and seeded differential plus live PostgreSQL tests check point/filter equivalence. Cedar exports
  network/country/CIDR/device/method/risk rules and lists action-kind, IANA-window and authentication-age gaps.
- The gateway derives IP from its socket and authentication facts from its own session, never client headers. The
  console has distinct bilingual "ABAC on content attributes" and "CBAC (context-based, Zero Trust)" sections,
  pipeline, matrix and explain labels, shows role-assignment windows and the deprecation warning.

### Changed

- **AuthZEN search now prunes by indexed residual candidates instead of evaluating every row.** Resource search caches type,
  mandatory-label, relation-known-id and tenant-attribute positions while preserving three-valued logic and original-array cursors.
  Subject search shares relation reachability and mandatory/eligibility prechecks. Every survivor still receives the full point
  decision, including delegation, obligations, break-glass, two-person and SoD history; only decisions made are audited. Random
  worlds, random predicates, pagination and PostgreSQL follower record patches are differentially tested. Large-world laptop p50/p99
  fell from 23.056/40.928 ms to 1.155/3.154 ms in file mode and from 67.739/208.187 ms to 3.277/23.563 ms with PostgreSQL.

### Fixed

- A PostgreSQL test (`read-only rechecks do not delay commits`) waited 100 ms for a commit that a loaded run could take
  longer to make. It now awaits the commit while the scan is still held, with a 20 s guard that only turns a commit
  queued behind the scan into a failure: 20 consecutive isolated runs and 5 runs of the whole PostgreSQL file passed.
- `GateNoActiveNode` never fired in cluster mode (it looked only at the Deployment and at pod names
  `gate-<hash>-<id>`), and counted a decision replica (`gate-replica-<n>`) as a Qadamar node; `GateActiveNodeNotReady` had
  the same pod match. Both now cover the StatefulSet `gate-<n>` and exclude replicas.

## [0.8.3] - 2026-11-11

### Fixed

- Releases could not be published since 0.6.0: the CI installs its tools into `.ci-bin/` inside the work tree, which
  was not ignored, so packaging refused the dirty tree. `.ci-bin/` is ignored; packaging now lists the paths when it
  refuses. No product code change since 0.8.2.

## [0.8.2] - 2026-11-11

### Security

- **The SQL list filter no longer depends on the database collation.** `packages/sql` emitted text comparisons
  without a collation, so on a database or column with a linguistic collation (ICU, most libc locales) an ordering
  could keep a row the point decision denies, or drop one it allows (`'a' < 'B'` is true under `und-x-icu`), and a
  nondeterministic ICU collation made equality, `= ANY` and array containment case- or accent-insensitive and
  `strpos` fail. Every text comparison, JSONB string text included, now carries `COLLATE "C"`. A literal with an
  unpaired surrogate, which the driver would bind as U+FFFD, is refused (400).
- **String ordering in conditions is Unicode code-point order** (`lt`, `le`, `gt`, `ge`), which is what `COLLATE "C"`
  computes. It was UTF-16 code-unit order, which differs only when a character from U+10000 meets one in
  U+E000..U+FFFF at the first difference: policies comparing such strings may decide differently. Live PostgreSQL
  tests assert filter-equals-point for every operator over ICU, nondeterministic ICU and ICU-default databases.

## [0.8.1] - 2026-11-11

### Security

- AES-256-GCM decryption fixes the authentication tag length at 16 bytes everywhere it is used (sealed signing keys
  and TOTP material, the OIDC state cookie, encrypted backups). Node otherwise accepts a truncated tag, and a valid
  truncated tag lowers forgery resistance. Found by the Semgrep CI gate, which had been failing on GitHub since 0.6.0.

### Fixed

- 0.8.0 shipped with the server manifest still at 0.7.0 (a dependency update had rewritten the file and the version
  bump missed it), so `scripts/release/pack.sh v0.8.0` refused the tag. All product manifests are 0.8.1 and the CI
  gate now refuses a version that differs between the manifests and the latest CHANGELOG release.

## [0.8.0] - 2026-11-11

### Security

- **BLP session decisions are linearizable with respect to the high-water mark.** Mark-relevant reads and writes of
  one PEP session now use an in-process per-session queue. With PostgreSQL they also hold a transaction advisory lock
  on the hashed session from before the mark reload through the decision's commit, including token consumption by
  `sid`. A lower write serialized after a read is therefore always denied, on one node or across cluster nodes.
  Batches acquire multiple sessions in sorted order. No-session requests, L0 reads and unrelated sessions do not take
  the session lock. Deterministic one-node and two-node interleaving tests and throughput diagnostics cover the
  guarantee and its cost.
- **Rate limits are cluster-wide in `GATE_CLUSTER` mode.** General and PEP budgets now lease small batches from
  per-key token buckets in PostgreSQL (`gate_rate_limit`), then consume them locally without a database round trip per
  request. Atomic leases cannot overspend; idle leases can only under-admit, bounded by N(B−1) unused tokens per key for
  N nodes and lease size B (at most 1,000, a tenth of a smaller bucket, or one larger request's cost). Refill uses the
  database clock, stale rows are swept, and lease failures fail closed. File and active/standby behavior is unchanged.
  The owner-run schema/grants and current backups include the new disposable table; older restores create it empty.
- **Oversized PDP bodies receive a clean refusal.** Bodies over 1 MB return 413 `payload_too_large` with the usual JSON
  envelope and `Connection: close`, rather than a dropped connection. Excess data is drained without buffering and the
  applicable refusal-audit paths are used, including decision-plane security rows. A real-socket test sends 3 MB.
- **Server-recorded SoD history is the default in every profile.** Unset `SOD_HISTORY` now means `server`, including
  direct runtime use and the evidence baseline. `caller` remains an explicit, warned compatibility opt-in for demos/tests
  and production refuses it. The non-loopback `/metrics` guard is verified in the demo profile as well as production.

- **Replica hardening after review.** A group entry (`prefix*=master` in `GATE_REPLICA_KEYS`) now holds a master on
  the database nodes only: each replica holds HKDF(master, its id) (`scripts/ops/replica-key.ts`), so its hops and row
  MACs cannot pass as a sibling's or extend a sibling's chain; the k8s component gives each pod only its own key
  (`GATE_REPLICA_KEY_FILE`, written by an init container) and never mounts the master. Feed reads run one snapshot at
  a time on their connection; a long poll that times out leaves no waiter behind; every replica request also spends a
  budget keyed on the replica id (not on the client its hop names); full snapshots are limited to 6 a minute per
  replica; refused audit batches write at most one row a minute per replica and reason (`suppressed` counts the
  rest); a retired signing key past its verification window introduces no new key.
- **SAML:** a LogoutRequest is accepted for 5 minutes after its `IssueInstant` (was 24 h), so the in-memory single-use
  set only has to cover that window across a restart; `SAML_MAX_AUTH_AGE_SECONDS` (default 12 h) bounds how long ago
  the IdP authenticated the user (`AuthnInstant`).

### Added

- **Stateless decision replicas (`GATE_REPLICA_OF`, docs/API.md §3.9.5).** A replica has no database connection: it
  bootstraps from a snapshot a database node signs with its Ed25519 keyring and long-polls signed deltas of the
  `gate_state_change` generations (`GET /x/v1/replica/state`), applying them as a cluster follower does. Answers are
  bound to the replica and to the request's nonce, and a generation older than one already applied is refused, across
  restarts too (`replica-trust.json`, HMAC'd); trust starts from pinned keys (`GATE_REPLICA_PIN`) or the JWKS over
  CA-verified TLS, and follows rotations through a new `introducedBy` signature the old key puts on the new one. HTTPS
  is required outside loopback. Replicas refuse decisions beyond `GATE_MAX_STALENESS_MS`, and `/readyz` says so.
- **Each replica's own durable audit chain.** Local decisions are answered after an `fdatasync` of the replica's file
  chain (group commit; every row names the replica and carries an HMAC under its key; a keyed two-slot checkpoint off
  the answer path), then shipped (`POST /x/v1/replica/audit`) and appended to `gate_audit` as that replica's chain
  after MAC, link, sequence and base checks, on a connection of their own. Gaps, forks, tampering and a replica behind
  its stored chain are refused, audited as `security / replica_audit_refused` and counted
  (`gate_replica_audit_refused_total`). `GATE_REPLICA_AUDIT_LAG_MS` (10 s) bounds how long a durable row may wait to be
  stored centrally, hence what a lost replica disk can lose; such a replica is refused at start and takes a new id.
- **What a replica does not decide on its copy:** requests with `context.sessionId` (BLP marks), actions under
  separation of duty, certified actions (decision tokens), unmapped subjects, subject and action search, XACML, token
  consumption and outcomes, assertions, registration, the console and SCIM are forwarded to the database nodes with a
  replica hop (the `X-Qadamar-Hop` format under a key derived from `GATE_REPLICA_KEY`), which carries the client address.
- `GATE_REPLICA_KEYS` on database nodes (per id, or `prefix*` for a group), a production profile for replicas, replica
  metrics, `deploy/k8s/components/replicas` (StatefulSet with a volume per pod), two alerts, `load.ts --replicas`.
- **SAML 2.0 console sign-in**, beside or instead of OIDC (`SAML_IDP_ENTITY_ID`, `SAML_IDP_SSO_URL`,
  `SAML_IDP_CERT_FILE`, `SAML_AUTHN_CONTEXT`, `SAML_ID_ATTRIBUTE`, `SAML_ROLE_ATTRIBUTE`, `SAML_SP_ENTITY_ID`,
  `SAML_ACS_URL`; docs/API.md 3.1.1). SP-initiated Web Browser SSO: HTTP-Redirect AuthnRequest, HTTP-POST Response at
  `/admin/v1/saml/acs`. The assertion must itself be signed by the pinned IdP certificate (a Response-only signature is
  refused), with RSA-SHA256 or stronger (SHA-1 anywhere refuses the message); Issuer, Audience, bearer Recipient,
  Destination and timestamps (60 s skew, 5 minutes at most) are checked; `InResponseTo` must be the request id held in
  the browser's `__Host-gate_saml` cookie and is consumed once; assertion ids are remembered (replay); a DOCTYPE is
  refused before parsing. MFA: every AuthnStatement must carry an `AuthnContextClassRef` from `SAML_AUTHN_CONTEXT`
  (required), else `mfa_required`; the production profile accepts OIDC or SAML as its IdP requirement, with the same
  MFA guarantee. Roles and the user id come from configured attributes, as with OIDC. IdP-initiated single logout
  (signed LogoutRequest over HTTP-POST at `/admin/v1/saml/logout`) ends the matching sessions on every node. SP
  metadata at `/admin/v1/saml/metadata`. The console shows a SAML sign-in button when configured (EN/FR);
  `/admin/v1/auth-methods` gains `saml`. Not done: encrypted assertions, the HTTP-Redirect logout binding, a
  LogoutResponse back to the IdP.
- **Python PEP SDK** (`sdks/python`, package `qadamar`, Python ≥ 3.9, no runtime dependency): `PepClient` for
  evaluation, batch evaluations, the three searches, explain, the SQL filter, token consumption and outcome reports,
  decision assertions and resource registration, with the TypeScript SDK's response validation (fail closed), bearer
  auth, a timeout, typed errors and verified TLS (system store or `ca_file`; no redirects, no proxy from the
  environment); `enforce()` of mask, redact and allowlist obligations on a copy, refusing unknown obligations and
  `notify`; `AssertionVerifier` for the gateway's decision assertions (JWKS cache and rotation, clock skew, binding to
  method, path, body digest and audience, replay store with an in-memory default), with Ed25519 verified in pure
  Python (RFC 8032 §6, not constant-time, public data only). `tools/ci/checks.sh` runs its unit tests, the RFC 8032
  vectors and an end-to-end test against the real PDP ([API.md](docs/API.md) §2.3).
- **Policy language specification 1.0** (`docs/spec/POLICY-LANGUAGE.md`): the grammar of conditions (every operator,
  operand forms, paths, literals, limits), the three-valued semantics with truth tables (mistyped operands are
  UNKNOWN, `eq`/`ne` structural), how permits, forbids, obligations, exemptions, IVPs and list filters consume TRUE and
  UNKNOWN, the evaluation order and deny ids, every bundle section, the `validateBundle` rules and its known
  leniencies, and a versioning and compatibility policy. `docs/spec/policy-bundle.schema.json` (JSON Schema 2020-12)
  states the structural rules; a test checks that the examples pass both the schema and `validateBundle`, that 27
  invalid bundles fail both, and that the operators of the schema, the validator and the spec are the same.
- **Cedar export** (`toCedar`, `toCedarRequest` in `packages/core`, CLI `scripts/export/cedar.ts`): Cedar policy text
  and a Cedar JSON schema for RBAC grants, ABAC permits and forbids, CBAC denies and the inactive-subject rule, plus an
  `unsupported` list with the reason for each part Cedar cannot carry (mandatory models, need-to-know, Clark-Wilson,
  separation of duty, obligations, delegation, untranslatable conditions). Qadamar's UNKNOWN is preserved by compiling
  each condition into error-free "is TRUE" and "is FALSE" Cedar expressions guarded by `has`; requests whose data does
  not fit the exported schema are refused rather than misdecided. Differential-tested against `evaluate` with a
  Cedar-subset evaluator written for the test only; not validated against the Cedar engine.
- **Integration of replicas with the other Unreleased changes.** A replica forwards every request with `context.sessionId`,
  so the database node's per-session queue and `BLP_LOCK` order it with the session's other decisions. A replica has
  no database to lease shared rate-limit buckets from: its buckets stay process-local (set its limits to its share),
  and a forwarded request is charged again on the database node's shared buckets under the real client and PEP. Audit
  shipments are bounded to 1,000 rows and 768 KiB, below the 1 MB body cap that now answers 413.

### Dependencies

- **`@node-saml/node-saml` 5.2.0** (MIT), the first runtime dependency besides `pg`, pinned exactly; it brings
  `xml-crypto` 6.4.0, `@xmldom/xmldom` 0.8.15, `xml2js`, `xmlbuilder`, `xml-encryption`, `xpath`, `sax` (BlueOak-1.0.0)
  and three `@types` packages, all MIT otherwise (THIRD-PARTY-NOTICES.md). `pnpm audit --prod`: no known
  vulnerabilities. Why a library rather than hand-written XML-DSig: verifying an XML signature means exclusive
  canonicalization, transforms, reference resolution by ID and the signature-wrapping cases that come with them; it is
  where SAML implementations have failed most (XSW, comment truncation, duplicate IDs), and a hand-written version would
  be a new, unreviewed one. node-saml is the maintained, widely deployed implementation (passport-saml lineage) and
  returns only the bytes its signature covers. Qadamar adds what 5.x only warns about or leaves out (algorithm allowlist,
  Recipient, Destination, AuthnContextClassRef, DOCTYPE) and pins its configuration (`wantAssertionsSigned`,
  `validateInResponseTo: always`, `rejectReplayedAssertions`), each covered by a test.

### Performance

- **Decision-only PostgreSQL groups now commit in one prepared statement.** Chained audit rows, derived metadata and
  any decision tokens and BLP marks share one implicit durable transaction instead of separate `BEGIN`, audit,
  metadata and `COMMIT` round trips. Other writes keep explicit transactions; the response still waits for durable
  audit, and chain, checkpoint, anchor, cluster and fail-stop semantics are unchanged. Added large-world before/after
  measurements at concurrency 8, 32 and 64.
- On one laptop, 1 leader + 2 replicas decided 1,283 requests/s against 3,177 for 3 cluster nodes (8 clients each;
  3,616 against 7,978 with 32): a replica waits for macOS `F_FULLFSYNC` (3.7 ms) on the SSD it shares with the
  PostgreSQL VM. Without that flush (diagnostic only) the same topology gave 8,366 to 8,758. A change on the leader
  reached a replica's decisions 24 to 116 ms later in the tests (docs/PERFORMANCE.md).

### Fixed

- Backup/restore drills skip with an explicit reason when PostgreSQL client tools are unavailable, unless
  `BACKUP_TESTS_REQUIRED=1`; CI sets that flag whenever `PG_TOOLS_CONTAINER` is present, so its drills cannot silently skip.
- README now agrees with the measured registration results: group commit met the 1,000 single registrations/s target
  at 32 clients, reaching 2,423.898/s at 100k and 1,962.376/s at 1M resources.

## [0.7.0] - 2026-11-11

### Security

- **Fail-open on mistyped operands fixed.** A comparison whose operands had the wrong type evaluated FALSE, and a
  `forbid` (or obligation) fires only on TRUE or UNKNOWN: `resource.attrs.amount ge 10000` did not deny when `amount`
  was the string `"50000"` or an array. Ordering (`lt`/`le`/`gt`/`ge`) other than number-number or string-string,
  `in` without an array on the right, `contains` on a non-array non-string (or a string with a non-string needle) and
  `subset` of non-arrays are now UNKNOWN, as a missing value is: a forbid fires, a permit does not grant. `eq`/`ne`
  keep structural equality across types (`"1" eq 1` is FALSE). Partial evaluation, list filters, resource search,
  impact previews and the simulator follow, since they all evaluate through `compare()`. The SQL compiler emits NULL
  (not FALSE) for such a mismatch against a typed column, so `NOT (...)` no longer keeps the row.
- **Keyed file-audit checkpoints.** `SIGNING_KEY_SEAL` now authenticates the file chain head after every append, using
  the same HKDF-derived HMAC key as PostgreSQL. Startup and `/admin/v1/audit/verify` fail stop on a mismatch, including
  a fully recomputed JSONL chain. Existing chains gain their first checkpoint without being rewritten. Production still
  requires TSA anchoring; demo documentation states the residual risk when seal/anchor are absent.
- **Sealed audit retention and subject erasure.** `AUDIT_RETENTION_DAYS` (off by default) seals expired prefixes with
  an HMAC and optional RFC 3161 anchor before deleting them, leaving verification rooted at the sealed head. File mode
  runs at start/daily; PostgreSQL uses an owner-only offline script and never grants audit `DELETE` to the service role.
  New subject ids use independent per-subject HMAC keys in a separate mapping. Security-officer erasure deletes that
  mapping and atomically audits the event without changing chain hashes. Exports keep working; auditor limits, legacy
  rows, external copies, and seal rotation are documented. Backups include the new seal and mapping tables.
- **Checkpoint downgrade closed (file mode).** A deleted or unreadable `audit-checkpoint.json` was re-minted at start, so
  whoever could write `DATA_DIR` could rehash the chain with plain SHA-256, delete the checkpoint and restart. A keyed
  start now fails stop on a non-empty chain without a valid checkpoint. An older unkeyed chain migrates once with
  `AUDIT_CHECKPOINT_MIGRATE=<reviewed head hash>` (audited `checkpoint_migrated`; spent once the chain grows). The
  append crash window is recoverable: exactly one trailing row that chains from the authenticated head is accepted
  at start, re-checkpointed and audited as `checkpoint_completed`.
- **Retention cannot launder tampering.** `audit-retention.ts` verifies the stored authenticated checkpoint (and
  anchors) before re-keying, sealing, clearing or deleting anything, refuses a missing one or a chain that does not
  extend it, and revokes the owner's temporary `DELETE`/`UPDATE` in every outcome.
- **Erasure covers every person id and needs two officers.** New audit rows pseudonymise human actors and the
  `makerId`, `checkerId`, `approvedBy`, `openedBy` and `subjectIds` details as well as the subject (the console still
  shows names while the mapping exists; the SIEM feed and export never see raw ids). Erasure is an `erase_subject`
  change approved by a second security officer; self-erasure and subjects with open break-glass or pending reviews
  are refused; `subject_erased` records the change id and the approver's pseudonym, and the applied change keeps only
  the pseudonym. Refused privacy/SCIM user routes are audited without the path id. The PostgreSQL mapping is now
  validated at load like the file one (pseudonym = HMAC(key, id)), failing closed.

### Added

- **`jsonb` column mappings for `/x/v1/filter`** (`packages/sql`): a tenant attribute whose JSON type varies per row
  maps to a JSONB column; each operator tests `jsonb_typeof` and is NULL on a mismatch, matching the point decision
  (live PostgreSQL tests check three-valued equivalence per operator and the filter-equals-point invariant).

### Changed

- **Impact previews analyze the affected set instead of the whole world grid.** Tuple edits follow direct, userset,
  parent, computed and reporting-line dependencies; subject, resource, certification and policy diffs select only the
  cells whose decisions or obligations can change. Both networks, maker/history variants and obligation comparisons are
  preserved, with differential tests against the full grid. `IMPACT_MAX_EVALUATIONS` now bounds the affected set after
  those variants, and `impact.analysis` reports unique affected cells and selection reasons. Added
  `scripts/bench/impact.ts` and 5,000-subject × 50,000-resource laptop measurements in docs/PERFORMANCE.md.
- **PostgreSQL state is per record, not a whole-document rewrite.** Subjects, resources and tuples now live in keyed,
  indexed `gate_subject`, `gate_resource` and `gate_tuple` rows with forced RLS and production/backup grants; policy,
  workflow and certification metadata remains in `gate_doc`. Ordinary writes stage only changed rows in the existing
  transaction and fail-stop model. In-memory subject/resource lookups and the tuple graph are patched with those deltas.
  File mode retains its atomic JSON document behavior.
- **Followers catch up incrementally.** Record writes advance a dense `gate_sync.records` generation and append
  `gate_state_change`, alongside the existing document version and LISTEN/NOTIFY poll. Followers apply new deltas and
  patch decision indexes; a missing generation falls back to a full ordered snapshot, while leader takeover always uses
  that snapshot. The staleness bound and policy-signature checks are unchanged.
- **Registration work is proportional to the change.** Resource arrays and id indexes are patched in place, parent
  tuples come from the graph, and level inheritance is checked only on changed resources and their direct children. Randomized tests compare this validation against full-world validation. New proposals bind to
  `v2.<record generation>.<State metadata hash>`; pre-v2 whole-world SHA-256 proposals retain exact legacy verification.
  Common record+audit commits use one data-modifying-CTE statement, with the old writer retained for other batches.
- **Automatic 0.6.0 migration and older-archive restore.** The first target start transactionally imports legacy records
  in original array order (preserving pending state digests), strips them from the metadata document, and is idempotent.
  `restore.sh` runs the same migration for older archives before validating all fourteen tables. The ops image carries
  the migration runner and its existing `pg` dependency. Upgrade requires stopped old writers and owner-run schema/grants;
  rollback is to the pre-upgrade archive, not an old binary on migrated tables.

### Performance

- `scripts/bench/records.ts` now measures migration, concurrent single registrations, batch sync and follower catch-up.
  At 100k/1M resources: single registrations 2,423.898/1,962.376 per second at 32 clients, batches of 1,000 at
  14,542.238/14,376.164 resources per second, migration 1.145/17.371 seconds, catch-up 33.067/27.676 ms. The old
  whole-array path measured 15.628/1.185 registrations per second. Every node retains the full decision world in memory.

### Fixed

- Same-id tuple replacements contribute both before and after relation content to impact analysis. The impact
  differential generator now covers every change kind and relation/policy shape in 240 seeded cases by default, with
  `IMPACT_FUZZ_RUNS` for longer runs.
- **Follower catch-up waited for the poll.** The single-statement record write never ran its `pg_notify` (an
  unreferenced `SELECT` CTE), so followers saw registrations at their next poll tick: 381/361 ms for 20 writes instead
  of about 30 ms. A test now listens for the notification.
- **Group commit for concurrent writes.** A request's commit joins the write already queued instead of queueing its
  own transaction behind it: concurrent registrations share one transaction and fsync, each answered only after the
  COMMIT holding its rows (220 to about 1,138 registrations/s at 100k before the next fix).
- **Registration under a large parent rechecked all its siblings.** Level inheritance is pairwise; only changed
  resources and their children are checked now (batch of 1,000: 1,972 to 14,542 resources/s at 100k).
- **v2 proposal digest during an uncommitted write.** While record changes are staged or in flight, the digest carries
  a per-process suffix instead of the last committed generation, so it never matches a proposal bound to that
  generation. Tests cover tuples, subjects, in-place registration and retirement, policy and certifications in file
  and PostgreSQL modes.
- **Group-committed record writes kept their audit pseudonyms but dropped new subject mappings.** The single-statement
  fast path (`postgres-fast-write.ts`) wrote the already pseudonymised audit rows but not the `gate_subject_identity`
  rows minted in the same drain, so a decision about a new subject grouped with a registration left an unresolvable,
  unerasable pseudonym. A batch carrying new mappings now takes the general path; a PostgreSQL test groups both.
- **A username spray no longer mints subject mappings.** A failed password or OIDC sign-in for an id without a mapping
  is audited as `unknown:<HMAC>` under one key derived from `SIGNING_KEY_SEAL`, not as a new per-subject mapping row;
  an id that already has a mapping is pseudonymised as before.
- The 0.6.0 automatic migration, restore of older archives, backups, grants and the production preflight
  (`GATE_TABLES`) cover the audit seal/mapping tables and the per-record tables together (sixteen tables). The ops
  image runs `migrate-records.ts` from `/app` (its relative imports did not resolve from `/opt/gate`).
- **A refused registration is rolled back for real with the per-record store.** The store patches the live record arrays
  in place, so reassigning the state a request saved kept the change: a write answered `409 proposal_limit` ("nothing
  was kept") stayed in memory and was committed with the next write, without its audit row, and a retirement in it
  skipped the retired-id log (re-registering the id was then not reviewed). The store now journals in-place patches
  until each commit point and undoes them, with the staged record deltas, when a saved state is assigned back (file and
  PostgreSQL modes); an approval that fails after applying its change restores the state the same way.
- **Followers keep the leader's record order.** Change rows are replayed by the position the leader allocated, a record
  deleted and added again in one write is stored as a move, and a reorder (`gate_state_change.move`) makes followers
  reload the position-ordered snapshot, so their arrays and legacy digest equal the leader's.
- **The 0.6.0 record migration refuses duplicate records by name.** A stored state with two subjects or resources of one
  type and id (or two tuples of one id) is refused before anything is written, naming them, instead of failing on
  `ON CONFLICT` or keeping one row silently.

## [0.6.0] - 2026-11-11

### Security

- **Separation of duty holds across cluster nodes.** Two distinct decision tokens for conflicting actions on one
  resource (a maker's `create` consumed on one node, the same person's `approve` on another before that node synced)
  could both be consumed, since each node decided on its cached performed-action history. A consumption now takes a
  transaction advisory lock on the token's resource and loads the performed actions committed since the node's last
  synchronisation before deciding again, so such pairs consume in one order and the second is refused (409).
  Single-node PostgreSQL and file mode are unchanged. Cost, measured with the new `scripts/bench/consume.ts` (two
  nodes, every consumption on one payment, a shared laptop, noisy): about 1 ms more at p50 sequentially (two round
  trips), and roughly 25-40 % fewer consumptions per second when they all contend for one resource; consumptions on
  different resources do not wait for each other's lock.
- **BLP marks are never read from a stale snapshot.** A node loaded session marks on the audit read connection, where
  the periodic recheck holds a REPEATABLE READ transaction: during a recheck a mark committed by another node could
  be missed, so a write after a classified read could be permitted. Marks are read on the writer connection while a
  recheck is open. Decisions of one session in flight at the same moment stay unordered, as on one node; docs/API.md
  §2 (Cluster) states the guarantee and why no per-session lock is taken.

### Added

- **Resource registration from the PEP plane** (`POST /x/v1/resources`, `/x/v1/resources/retire`,
  `/x/v1/resources/sync`, `/x/v1/resources/list`; docs/API.md §2.2): the application that owns the records registers,
  updates and retires them at run time, so a decision on a record created after deployment no longer ends in
  `CORE.UNKNOWN_ID`. A PEP credential writes only the resource types it was created for (`resourceTypes`, new on
  `POST /admin/v1/pep-credentials`); others, `bootstrap` included, write none. Every resource is checked against the
  bundle schema (400), parents and level inheritance (422) and, for constrained types, the IVPs (422). Batches of up to
  1000 are atomic and idempotent; versions are monotonic. New records, raised levels, added compartments or content
  classes, edits of attributes no rule reads and retirements apply at once; a lowered level, a removed compartment or
  content class, a changed integrity, owner or parent, a change to an attribute an ABAC or CBAC rule reads (or listed in
  the new optional `governedAttributes` of a resource type), and the retirement of a constrained item become a
  `register_resources` change for a second person, with its impact preview; whoever issued the credential cannot
  review it (credentials now record `issuedBy`). An existing constrained item is never changed by registration
  (`409 certified_command_required`: use its certified command). A retired id is recorded in an append-only log outside
  the state document (`gate_retired` with PostgreSQL, created by `SCHEMA` with its grants and row-level security,
  optional in older archives; `retired.jsonl` in file mode), with no cap; registering it again is always a
  `register_resources` proposal. One `change` audit row per call, metrics
  `gate_resource_registrations_total` and `gate_registered_resources_total`. In a cluster the leader answers;
  followers forward these requests over the signed hop. The parent relation tuple follows `parent`, so need-to-know
  inheritance and `/x/v1/filter` treat a registered child like a seeded one.
- **The PDP's copy of a constrained item follows its certified commands:** a token consumption's post-state (`attrs`)
  is kept with the reservation and applied when the PEP reports the command `completed` (attrs merged, version = the
  bound version + 1, audited in the outcome row, same transaction with PostgreSQL); never on `failed` or while pending.
  An item that moved on since is left alone and the post-state listed for reconciliation
  (`unappliedPostStates` in `GET /admin/v1/integrity/reservations`). In a cluster such completions are settled by the
  leader (followers forward them).
- **Hardening after review:** a consumption's post-state is accepted only for a constrained type, bounded, with keys
  its procedure declares or its IVPs read, and a policy-read attribute only as declared procedure input; registration
  writes cost 10 + one per resource; pending registration proposals are capped per PEP credential
  (`RESOURCE_PENDING_PROPOSALS_PER_PEP`, `409 proposal_limit`); a parent must be of a type the credential is bound
  to; `ALLOW_DEMO_WORLD` under the production profile is a configuration-baseline warning and a start warning.
- **SDK:** `registerResource`, `retireResource`, `syncResources`, `listResources`, with request and response
  validation.
- **SDK: pluggable replay store for decision assertions.** `AssertionVerifier` takes `replayStore` (an atomic
  `spend(nonce, expiresAt)` check-and-set); the default `MemoryReplayStore` is per process, so a backend with several
  processes or replicas must share one (Redis `SET NX PX` or a PostgreSQL unique insert; examples in docs/API.md 2.0.2,
  no new dependency). A store that throws fails the request closed: `503 replay_store_unavailable`.
- **CI: Semgrep SAST** (`semgrep/semgrep:1.95.0`, JavaScript, TypeScript and Node.js rulesets) blocks `ci.yml` and
  `release.yml` on any `ERROR` finding; `.semgrepignore` leaves out tests, fixtures and docs (docs/CI.md).
- **Browser checks:** `PLAYWRIGHT_CORE_PATH` names the playwright-core to use (no developer path in the harness any
  more; unset, a resolvable copy, then the npx cache, are tried); `E2E_REQUIRED=1` turns a skip into a failure
  (docs/ACCESSIBILITY.md).
- **STRIDE threat model:** docs/security/THREAT-MODEL.md (assets, trust boundaries, mitigations with their code paths,
  residual risks).

### Changed

- **`GATE_PROFILE=production` requires `BLP_SESSION_REQUIRED=true`** (it was reported, not required). The Kubernetes
  base sets it, and the managed smoke test sends `context.sessionId`.
- A demo start with `SOD_HISTORY` other than `server` logs a warning: separation of duty then believes the `makerId`
  and `priorActions` a PEP sends when the PDP recorded no history. Production already required `server`.
- **Demo profile listens on loopback only.** A non-loopback `HOST` is refused unless `DEMO_ALLOW_REMOTE=true`, which
  prints a warning at start. **Upgrade:** `docker run` of the image in the demo profile (its `HOST` is `0.0.0.0`) now
  needs `-e DEMO_ALLOW_REMOTE=true`; `docker-compose.yml` sets it (ports stay published on the host's loopback).
- **`/metrics` is never open on a non-loopback address:** without `METRICS_TOKEN` it answers 403 there, in every
  profile (production already required the token).
- **Production refuses to seed from the demo world.** On its first start a `GATE_PROFILE=production` node refuses a
  `WORLD_DIR` whose `world.json` is marked `"demo": true` (both shipped examples now are); `ALLOW_DEMO_WORLD=true`
  lifts it for local test deployments (`deploy/k8s/overlays/local` sets it). A node with stored state is unaffected.
  **Upgrade:** a new production tenant needs its own `WORLD_DIR` (`deploy/k8s/base` documents the parameter).
  `scripts/managed/new-tenant.sh` takes `WORLD=<dir>` (the tenant's `world.json` and `bundle.json`, mounted from the
  ConfigMap `gate-world`) and refuses a new tenant on a non-local overlay that has no world of its own, instead of
  waiting for a pod that cannot start.
- **Bundle validation is stricter:** unknown top-level keys, a non-list `inherits` and role-inheritance cycles are
  rejected with an error naming them. **Upgrade:** a stored bundle with an extra top-level key or a cycle stops the
  start (`Invalid stored bundle`): publish a corrected bundle on 0.5.0 before upgrading.
- **Sign-in hashes off the event loop:** password checks use asynchronous scrypt (same hash format, same
  constant-time comparison, the dummy hash still runs for unknown users); `Auth.login` is now async.

### Fixed

- Stale documentation: the gap register re-checked against the code (GP-03, GP-04, GP-06, GP-10, GP-18 partly done;
  GP-15, GP-23 closed), docs/SUPPORT.md named 0.3.0 as the version line, the managed-offer image tag was 0.3.0, the
  README coverage line now gives both figures (with and without PostgreSQL), and several pages counted four, seven or
  eight PostgreSQL tables instead of nine.

### Upgrade

- Production: every PEP must send `context.sessionId` for reads above L0 and for writes by subjects cleared above L0
  before you upgrade, then set `BLP_SESSION_REQUIRED=true`; without it a production node refuses to start. There is
  no opt-out: running without the requirement is the gap it closes (a PEP that omits the id escapes the mark).

## [0.5.0] - 2026-11-10

### Added

- **Console sessions are shared through PostgreSQL** (`gate_session`): a standby takeover or a leader change no longer
  signs everyone out, and logout, expiry and OIDC back-channel logout hold on every node. Only the SHA-256 of the
  session id is stored; the CSRF token is an HMAC keyed by the session id, stored nowhere. Idle (15 min) and absolute
  (8 h) limits stay on real time; the last use is written at most once a minute and each sign-in deletes expired rows.
  File mode keeps sessions in memory. **Upgrade:** the new table needs `SCHEMA` run by the owner role and
  `serviceGrants` before the nodes start. `restore.sh` still accepts 0.4.x archives, which have no `gate_session`:
  it creates the table empty.
- **`SIGNING_KEY_SEAL` rotation** with `SIGNING_KEY_SEAL_PREVIOUS`: the start re-seals the signing keyring and TOTP
  secrets under the new key and re-authenticates the audit checkpoint, in one transaction with one audit row
  (`security / seal_key_rotated`). Every start now checks that sealed material opens and stops with an explicit error,
  changing nothing, when it does not (runbook: docs/handbook/operations/rotate-credentials.md). A checkpoint under the
  previous key is trusted only while sealed material is still under it; after the rotation it is not (full verification
  before serving), and every start warns while `SIGNING_KEY_SEAL_PREVIOUS` is still set.
- **Console:** the Policies screen (Rules tab) lists the Clark-Wilson certification records with their current/stale
  state, the procedures to recertify and those never certified, and the reservations no PEP settled
  (`GET /admin/v1/integrity/reservations`); a pending `publish_policy` change in Approvals lists the certifications it
  would make stale (`invalidatesCertifications`). English and French.
- **CI:** `pnpm audit --prod --audit-level high` blocks `ci.yml` and `release.yml` on a high or critical advisory in
  the production dependencies (docs/CI.md).

### Changed

- **Takeover no longer grows with the audit, in production too.** Every profile now starts from the authenticated
  audit checkpoint and verifies only the rows after it before serving; the whole chain is verified in the background
  right after. The checkpoint also carries the audit counters (under its HMAC), so a start no longer aggregates the
  whole table. 1,001,000 rows on a laptop: start 9.1 s before (full chain), 0.09 s after (median of three); the
  background verification takes about 9 s (docs/PERFORMANCE.md). Until it ends `/readyz` reports `audit.fullChain: false`,
  `/admin/v1/audit/verify` adds `fullChain`, and the new metric `gate_audit_full_chain_verified` is 0; a rewritten row
  found then makes the node refuse every audited action and fail `/readyz`, logs `AUDIT INTEGRITY FAILURE` and clears
  the checkpoint (docs/API.md §3.9.1). `GATE_PROFILE=production` no longer forces a full scan before serving. The
  managed offer's alert rules gain `GateAuditFullChainUnverified` (the gauge at 0 for 15 min).

### Security

- **The BLP \*-property holds across requests of a session.** A PEP may send `context.sessionId` (XACML
  `urn:qadamar:1.0:environment:session-id`); the PDP keeps, per PEP credential, session and subject, the highest
  level a permitted point read reached, and decides later writes of that session at or above it (`BLP.HIGH_WATER`,
  trusted roles exempt). A caller's `sessionLevel` can raise the working level, never lower it below the mark. Searches,
  filters, explanations and list assertions apply the mark but never raise it; a decision token is consumed against the
  mark of the session that asked for it (claim `sid`). Marks lapse after 15 min idle or 8 h (real clock), live in
  memory (at most 100,000), in `DATA_DIR/sessions.json` without a database and in the new `gate_blp_mark` table with one;
  every node loads a session's marks before deciding on it. `BLP_SESSION_REQUIRED=true` denies classified reads and
  cleared writes without a session id (`BLP.SESSION_REQUIRED`); the configuration baseline reports it. Each PEP
  credential holds at most `BLP_SESSIONS_PER_PEP` marks (default 10,000), so one credential minting session ids cannot
  exhaust the others' (`BLP.SESSION_LIMIT` is its own). Only a rise is written, a use at most once a minute; without a
  database marks are saved in one batch within a second (a crash loses at most that second's raises).
- Upgrading a PostgreSQL deployment: run `SCHEMA` as the owner and grant `gate_blp_mark` (`serviceGrants`); backup and
  restore scripts include the table; `restore.sh` still accepts an archive taken before it and creates
  `gate_blp_mark` empty (marks of sessions in flight at backup time are lost, docs/DEPLOY.md).

## [0.4.2] - 2026-11-10

Fixes from Claude's v0.4.0 assessment (fourth independent evaluator), reproduced live before fixing.

### Fixed

- **The shipped server limited every PEP to 120 decisions a minute** and refused any batch over 120 items: the limit was
  hard-coded and the decision plane shared the console's budget. The decision plane (`/access/*`, `/x/*`,
  `/xacml/v3/authorize`) now has its own budget per PEP credential and per address, `PEP_RATE_LIMIT_PER_MINUTE`
  (default 60,000, at least 1,000 so the largest batch fits); console, SCIM and public routes keep
  `RATE_LIMIT_PER_MINUTE` (default 120). Invalid values stop the start. Checked through `main.ts`: 500 evaluations and a
  200-item batch, all 200.
- Console session idle (15 min) and absolute (8 h) limits run on real time: under a pinned business clock
  (`CLOCK=fixed`, demo only) sessions no longer live for ever.

### Documentation

- README states that the BLP session level comes from the PEP on each request (no server-side high-water mark) and
  that the lattice is fixed at L0..L3.
- Claude's assessment (71/100) in docs/market; the infographic shows the four evaluators and their ranked improvement
  actions.

## [0.4.1] - 2026-11-10

Fixes from the v0.4.0 assessments and the end of the Strix deep pentest.

### Changed

- **Breaking for PEPs that compared the answer exactly:** `POST /x/v1/tokens/consume` now answers
  `{ ok: true, reservation }`. Consuming a decision token reserves the certified action; the PEP reports what became of
  it with `POST /x/v1/tokens/outcome` `{ reservation, outcome: "completed" | "failed" }` (only the consuming PEP
  credential, idempotent, a different second outcome is 409 and audited, `GATE.ACTION_COMPLETED` /
  `GATE.ACTION_FAILED`). Separation of duty counts a reservation while pending and once completed, no longer once
  failed. `GET /admin/v1/integrity/reservations` lists reservations without an outcome for reconciliation
  (docs/API.md §3.12). PostgreSQL: `gate_performed` stays append-only, outcomes are their own rows.
- The gateway reports outcomes: 2xx completed, 4xx except 408 failed; 3xx, 408 and 5xx and an interrupted exchange
  leave the reservation pending (the command may have run); a connection never made is failed. SDK: `reportOutcome()`.
- Clark-Wilson certifications are bound to the procedure they certified (`procedureFingerprint`: action definition,
  IVPs, input validators, PEP binding, granting roles, applicable ABAC/CBAC/SoD rules, need-to-know with every
  relation definition and the break-glass window, mandatory section). A changed procedure is denied with
  `CW.CERTIFICATION_STALE` until recertified; a pending `publish_policy` shows `invalidatesCertifications`; the
  certifications listing marks `current` and `stale`. Records from 0.4.0 count only while their policy version is in
  force.
- Base images pinned by digest in the Dockerfile, the compose file and the local image build; CI refuses a Dockerfile
  default without a digest.

### Security

- Decision-plane refusals are audited (Strix review items): a failed PEP credential on `/access/*`, `/x/*`,
  `/xacml/*` and any refused token consumption write a `security` row, at most one a minute per source, route family
  and error, with the count left out.

### Upgrade

- Stop every 0.4.0 node before starting 0.4.1 against the same database: a 0.4.0 node cannot read outcome rows. The
  first 0.4.1 start applies the schema change once (brief table locks).

### Documentation

- Test counts, supported version line (0.4.x) and release instructions brought up to date; the v0.4.0
  assessments recorded.

## [0.4.0] - 2026-11-10

### Added

- Managed offer on Kubernetes, one dedicated instance per customer, in `GATE_PROFILE=production`: `deploy/k8s` (base,
  local overlay, alert rules), `scripts/managed` (new-tenant, smoke, delete-tenant, offline image build, local test
  PKI), an `ops` image target with the backup tools, an opt-in manifest test (`GATE_K8S_TEST=1`) and
  docs/MANAGED-OFFER.md. The local overlay runs the production profile for real against test-only stand-ins (an OIDC
  provider asserting MFA, an RFC 3161 authority, a break-glass receiver, a throwaway CA); the smoke test covers sign-in
  with MFA, PEP decisions, break-glass notice, anchoring verified offline, failover, cold start, backup and a restore
  drill.
- `TRUSTED_PROXIES` (addresses or CIDR ranges, empty by default): only from a listed peer is the client address read
  from `X-Forwarded-For`, as its rightmost untrusted entry. It keys the per-IP rate limit and login lockout, and is
  recorded in sign-in audit rows (`details.client`) and on request spans (`client.address`).
- Cluster mode (`GATE_CLUSTER=true`, `GATE_NODE_ID`, `GATE_MAX_STALENESS_MS`, `GATE_ADVERTISE_URL`): every node serves the PDP API against the shared PostgreSQL, the admin plane stays on the leader holding the advisory lock (followers answer `409 not_leader`, `GET /leaderz`), followers follow document changes by LISTEN/NOTIFY and a version number and refuse decisions beyond the staleness bound.
- One audit hash chain per node (`node` in every record of a non-"0" chain, per-node `seq`); verification, checkpoint, anchors (set of heads), listings, export (`from=<node>:<seq>,...`), SIEM cursor and counters cover every chain. Existing rows become chain "0" unchanged.
- Decision tokens and performed actions in their own tables (`gate_token`, `gate_performed`): single use across nodes, consumption serialised by a row lock.
- `scripts/bench/load.ts --nodes N`: N node processes, scaling figures in docs/PERFORMANCE.md.
- Decision assertions: the gateway forwards each request with a PDP-signed, 30 s Ed25519 JWS (`gate-assertion`) bound to subject, action, resource, decision id, policy version, backend origin, method, path and body digest, with a nonce (`POST /x/v1/assertions/evaluation`, `/x/v1/assertions/list`). The SDK verifies it on the backend (`AssertionVerifier`, `withGateAssertion` for `node:http`, `example-backend.ts`): JWKS cache with rotation, clock skew, replay cache, exact binding.
- Clark-Wilson C5: `clarkWilson.inputValidators`, closed declarative input schemas per certified command, checked at decision (`context.input`) and on the post-state at token consumption.
- Clark-Wilson E3: PEP credentials bound to subject populations (`subjectTypes`); `clarkWilson.requirePepBinding` decides certified commands only through a bound credential.
- Encrypted backups: `backup.sh` / `restore.sh` require `BACKUP_ENCRYPTION_KEY` (AES-256-GCM, `scripts/ops/archive-crypt.ts`); a tampered archive or wrong key is refused before any database is created. DEPLOY.md documents WAL archiving / PITR as the hosting's and an RPO/RTO table.
- Release engineering without new dependencies: `scripts/release/sbom.ts` (CycloneDX 1.5 SBOM from `pnpm-lock.yaml`), `scripts/release/pack.sh` (reproducible tarball and `SHA256SUMS`, signing hook `RELEASE_SIGNING_HOOK`), `.github/workflows/release.yml` on `v*` tags (docs/RELEASE.md). Support policy template with owner decisions marked TO DECIDE (docs/SUPPORT.md).
- `docs/CONFIGURATION.md`, generated from the code by `scripts/docs/env-table.ts`; CI fails when a variable is read but not documented, or documented but not read.
- Demo world: `lina` and `omar` are PDP subjects (no role), so Clark-Wilson certification works in the demo console.
- Console: a Two-step sign-in screen (status, enrolment after the current password, the otpauth URI as text and as a QR code from a dependency-free encoder, first code, recovery codes shown once) and `GET /admin/v1/session/totp`; translated, actionable messages for every server error code; real-browser checks (`pnpm --filter @product/admin e2e`) of console errors, `html lang`, accessible names, text contrast, keyboard order and focus, dialogs and reduced motion in English and French., keyboard paths, dialogs, reflow, contrast and motion (`apps/admin/e2e`, skipped without a local `playwright-core`).

### Security

- Clark-Wilson E4 at run time: a certifier and its checker are denied the procedure they certified (`CW.CERTIFIER_EXECUTES`), whatever roles they gain later.
- Audit-readiness pack `docs/compliance/` (ISO/IEC 27001:2022 Annex A, 27017, 27018, 27701, 42001, IEC 62443-4-1 and 4-2, AICPA Trust Services Criteria): control mappings with evidence paths, a gap register and an audit plan. Product evidence only: no certification, attestation or compliance claim.
- Per-framework evidence packs `GET /admin/v1/compliance/evidence?framework=<id>` built from live data (configuration baseline, time and anchor evidence, policy publications, audit chain and anchors, access reviews, approvals, break-glass, keys, security events, CI references), with a manifest of section hashes signed by the decision-token keyring; each export is audited. Console: an evidence-pack card on the Compliance screen (English and French).
- Pseudonymised audit exports (`pseudonymise=1` on the NDJSON export and the evidence pack), keyed by a key derived from `SIGNING_KEY_SEAL`.
- Subject access report `GET /admin/v1/privacy/subjects/:id` (security officer), audited.
- The configuration baseline of the evidence pack records cluster mode, the node id, the staleness bound and the
  trusted proxies.
- KIMI-01 (internal pentest 2026-11-10, Medium): `mandatoryWeakenings` now covers every protective rule. An ABAC
  `forbid`/`obligation` or CBAC `deny`/`mask`/`redact` rule that is removed, changes effect or content class, narrows
  its resource types or actions, or has its `when`/`unless`/obligations/fields changed in a way not provably stronger
  is a mandatory weakening, so its publication needs a security officer as checker (it previously compared only the
  id, effect and class of CBAC deny/mask rules, and no ABAC rule). Reclassifying an action to any other kind is also
  flagged. Tests: the pentest's two reproductions (core and through propose/approve), redaction removal, provably
  stronger edits, and a property test over random rule edits.
- KIMI-02 (Medium): the impact preview compares obligations. `Impact` gains `obligationsLost` and `obligationsGained`
  (redacted fields, masked classes, notifications, field allowlist, decision-token requirement, per still-allowed
  cell); a lost obligation makes the change `broadens: true`. The console shows them in the impact views (English and
  French). Pending proposals made before this version fail the stale-impact check on approval and must be resubmitted.
- `/access/v1/search/subject` (who can access a resource) is a per-credential capability: `allowSubjectSearch` on
  `POST /admin/v1/pep-credentials` (default `true`; `false` answers `403`). `GATE_PROFILE=production` creates
  credentials with `false`, refuses `true` and refuses subject search to every credential.
- Audit rows are bounded (Strix pentest, note): any string over 512 characters keeps a 128-character prefix, a
  truncation marker and the SHA-256 of the full value; a row over 16 KiB keeps its identity fields and replaces
  `rules` and `details` by their digest. Unauthenticated callers (sign-in names, refused routes, XACML attribute ids)
  can no longer grow the hash-chained log without bound.
- Console sign-in throttle (Strix pentest, CWE-307): the hard per-account lock is gone. Five failures from one address
  on one account still lock that pair progressively (1 min doubling, 60 min at most); failures counted per account
  hold back only clients that have failed themselves, so an anonymous caller can no longer lock a named account for an
  hour. Trade-off documented in docs/API.md: one guess per fresh address while the account delay runs, which the
  production profile's MFA makes useless. The failure that sets a lock is audited with `details.lockedSeconds`.
- Sign-in locks expire on real elapsed time (Strix pentest, CWE-1284), like the rate limiter and the PEP rotation
  grace: with `CLOCK=fixed` a lock used to never end.
- Cluster mode: followers forward `/admin/` and `/scim/` to the leader (body read and bounded at 1 MB, answer
  streamed; cookies, CSRF header and body kept) with an HMAC hop header `v2` (key derived from `SIGNING_KEY_SEAL`; the
  MAC covers timestamp, nonce, client, node, method, path with query and the SHA-256 of the body; 30 s window, single
  use, never forwarded twice; a refused hop counts against the sender's rate limit), so a plain Kubernetes Service
  serves the console; `409 not_leader` remains when the leader is unknown. `GATE_ADVERTISE_URL` must be an http(s)
  origin (checked at start, and a malformed published value is never contacted). The cluster component runs a StatefulSet with a headless Service: `GATE_NODE_ID` is the stable pod name and a
  restarted node continues its audit chain; NetworkPolicies allow node-to-node traffic on 8787.

### Fixed

- The audit API's `type` filter refused `simulation`, a type the server writes; it now accepts exactly the written
  types (`AUDIT_TYPES`, checked by a test that walks the server source), and the console's audit filter lists it.
- Behind a reverse proxy or ingress every client shared one per-IP rate-limit bucket (the proxy's address), 120
  requests per minute for the whole tenant; see `TRUSTED_PROXIES`.
- Anchor verification (`openssl ts -verify`, `TSA_CA_FILE`) always failed on Linux: the token was passed as
  `/dev/stdin`, which OpenSSL cannot open when Node gives the child a socket. It is now a private temporary file.
- The runtime image had no `openssl` command, so anchors could not be verified in it; it is installed (or, offline,
  taken from the PostgreSQL image with `RUNTIME_BASE=runtime-base-postgres`). The image runs as uid 1000 by number.
- A standby waiting for the PostgreSQL lock ignored SIGTERM when running as PID 1 and could take the lock while being
  stopped, holding it until killed (30 s without an active node during a Kubernetes rollout).
- Console text contrast over the glass window and in the access matrix, a matrix cell scrolling under the sticky column when focused, and "1 records" in English.
- `Dockerfile`: the runtime stage did not copy `packages/sql`, which the server imports, so the image could not start; CI now checks the copies.
- Documentation corrected against the code (docs/DOCS-AUDIT.md).
- Integration of the loop-3 changes. In cluster mode, the subject access report and the evidence pack's audit
  sections paged only chain "0" (a `node:seq` cursor read as a number) and kept the tail of the last chain listed
  instead of the newest rows; they now page every chain and keep the newest by time. An anchor over several chain heads
  was timed against an unrelated row: it is timed by its newest anchored row, and the pack lists each anchor's and the
  chain's heads.
- Managed offer with the cluster tables and encrypted backups: `gate-migrate` granted a hand-written copy of the old
  privileges (no `gate_sync`, `gate_token`, `gate_performed`), so the service role could not decide and the backup role
  could not dump; it now grants `serviceGrants` and `backupGrants` from the code. The backup CronJob passes
  `BACKUP_ENCRYPTION_KEY` from the Secret `gate-backup` (created by `new-tenant.sh`, required otherwise), writes
  `.dump.gcm` archives and prunes them; the ops image carries `archive-crypt.ts`; the smoke restore drill passes the key,
  checks the 7 restored tables and grants as `gate-migrate` does. An always-on test compares them with the code.
- The console had no message for `409 not_leader` (a follower in cluster mode).
- docs/CONFIGURATION.md lacked `GATE_CLUSTER`, `GATE_NODE_ID`, `GATE_MAX_STALENESS_MS`, `GATE_ADVERTISE_URL` and
  `TRUSTED_PROXIES`; it now also lists, and CI checks, the variables of the operations scripts (`BACKUP_ENCRYPTION_KEY`,
  `BACKUP_FILE`, `DATABASE_URL`, `MAINTENANCE_DATABASE_URL`). `scripts/ops` is type-checked.
- The release tarball now holds `deploy/`, `scripts/managed` and docs/MANAGED-OFFER.md.

## [0.3.0] - 2026-11-10

### Added

- Shared security material in PostgreSQL: console accounts, PEP credentials, the signing keyring, lockouts, the SCIM credential and the SIEM cursor are `gate_doc` rows used by every node; the first start imports the `DATA_DIR` files once. Startup from the last verified audit checkpoint (fast takeover), with the full recheck in the background.
- Console screen for PEP credentials, signing keys and the SCIM credential (`GET /admin/v1/scim/credential` reports its holder and last rotation); English and French console with a per-user language switch.
- XACML 3.0 JSON Profile endpoint `POST /xacml/v3/authorize` (translation onto the AuthZEN evaluation) and OTLP/HTTP JSON tracing (`OTEL_EXPORTER_OTLP_ENDPOINT`), without new dependencies.
- Enforcing gateway `packages/gateway`: reverse-proxy PEP that decides, applies obligations, consumes decision tokens and fails closed.
- Clark-Wilson integrity: integrity verification procedures, `certify_tp` changes under two-person approval, `GET /admin/v1/integrity/certifications` and `POST /admin/v1/integrity/verify`.
- `GATE_PROFILE=production` startup checks (TLS, OIDC with MFA, TOTP on local accounts, database role, `SIGNING_KEY_SEAL`, `SOD_HISTORY=server`, metrics token, TSA, break-glass webhook).
- TOTP (RFC 6238) for local password accounts with sealed secrets and one-time recovery codes; a one-time code field on the console sign-in (English and French).
- Signed break-glass notices to an https webhook on open, revoke and expiry.

### Security

- Resource-owner console scope comes from the authenticated principal (its id, plus ids mapped in `RESOURCE_OWNERS`) instead of the demo owner `carol`, across every admin route and count.
- Policy version ids are SHA-256 over the canonical bundle (`pv.` + 64 hex); older FNV ids stay readable. Each published bundle is signed with the decision-token keyring, `GET /admin/v1/policy` returns the signature and `kid`, and startup refuses a bundle whose signature does not verify (`POLICY_SIGNATURE_ADOPT` to sign an unsigned or orphaned one, audited).
- `SOD_HISTORY=server` ignores caller-supplied `makerId` and `priorActions` for SoD-constrained actions; the compose profile sets it.
- `SIGNING_KEY_SEAL` is required with `DATABASE_URL` unless `ALLOW_CLEAR_SIGNING_KEYS=true`; production refuses `ALLOW_CLEAR_SIGNING_KEYS`.
- In PostgreSQL mode, TOTP secrets and their last accepted step live in the shared `credentials` row: a code used on one node is a replay after takeover, and the production check reads TOTP enrolment from that row instead of a stale `DATA_DIR` file.
- A standby that takes over verifies the policy bundle signature against the keyring stored in PostgreSQL, including a key rotated on the previous primary.

### Fixed

- `/.well-known/jwks.json` is no longer refused by the dot-segment path guard (it answered 400).

### Security

- Gateway forwards an allowlist of headers and declared query parameters only; method overrides are refused.
- Certified commands on types with integrity checks require the post-state at token consumption; certification can be required per type.
- Audit checkpoint authenticated with an HMAC; production verifies the full chain before serving.
- Production profile checks role membership, BYPASSRLS, CREATEROLE and audit-table privileges; XACML indeterminate results audited.

## [0.2.0] - 2026-11-10

This entry summarises the repository history through commit `c151662`. The packages remain private; this changelog entry does not by itself publish a package or create a git tag.

### Added

- Domain-independent authorization engine with RBAC, ABAC, ReBAC, CBAC, Bell-LaPadula, Biba, Clark-Wilson, separation of duty and delegation checks, plus the invented toy-domain bundle.
- AuthZEN-shaped PDP endpoints, residual-to-PostgreSQL compilation, policy simulation and immutable policy publication metadata.
- Admin control plane and React console with overview, attribute model, policies, access matrix, simulator, approvals, break-glass, access reviews, audit and compliance screens.
- Independent change approval, mandatory-model weakening analysis, impact previews and server-derived maker and performed-action history for separation of duty.
- OIDC console sign-in with authorization code, PKCE and MFA evidence, alongside configurable local demonstration accounts.
- PostgreSQL control-plane storage with one active node, waiting standbys, fail-stop behaviour and atomic state/token/audit commits.
- Optional RFC 3161 audit anchoring, AuthZEN and live-SQL conformance tests, seeded differential fuzzing, bounded impact evaluation and paged searches.
- Resource-search residual prefiltering, database-backed audit reads and bounded PostgreSQL audit memory.
- Proprietary licence notice, dependency and media notices, security policy, source coverage thresholds in CI and server-rendered admin markup tests.

### Changed

- Workspace packages (`@product/core`, `@product/sql`, `@product/pdp-http`, `@product/admin`) are versioned 0.2.0 and marked `UNLICENSED`.
- Renamed the product to Qadamar and iterated the console through its purchased-template-inspired glass design, generated sign-in artwork and reduced-motion alternatives.
- Limited resource search to point decisions for candidates retained by the residual filter, with audited lookahead only when its page is requested.
- Preserved typed administrative work across session expiry and made overview and compliance verification report the latest completed audit check.

### Fixed

- Closed authorization and validation findings from adversarial and cross-model reviews, including malformed-request denial, parent classification invariants and typed built-in SQL mappings.
- Made impact previews use the same performed-action history and server-derived maker as actual decisions.
- Refilled rate limits from elapsed real time rather than the pinned business clock.
- Fixed session eviction, corrected console role messaging for screens outside the user's role and sent the server clock in the `Date` header.

### Security

- Added scrypt credential hashing, CSRF protection, role-scoped administration, login lockout and rate limiting, single-use Ed25519 decision tokens and metadata-only hash-chained audit.
- Added Secure cookies and HSTS for HTTPS deployments, sealed OIDC state, and strict OIDC token, role and MFA validation.
