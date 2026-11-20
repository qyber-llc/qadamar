# Threat model (STRIDE)

Scope: the Qadamar server (`packages/pdp-http`, engine `packages/core`, SQL compiler `packages/sql`), its
console (`apps/admin`), the PEP side (`packages/gateway`, `packages/sdk`) and the operations scripts (`scripts/ops`),
as of 0.5.0 plus the `loop6-harden` changes (2026-11-10). Rows were added until commit `4a5780c` (2026-11-11, first
released in 0.10.0), among them the cluster hop, the replica trust boundary, the PDP-to-backend decision assertion,
PEP context-claim scopes and session revocation. The model has not been re-baselined: the features of 0.6.0 to 0.12.2
(CBAC, decision replicas, cluster mode, signed decision assertions, the managed offer) are not systematically analysed,
only where a row names them; no row covers the managed offer (`deploy/k8s`, `scripts/managed`) or the changes of 0.11.0 to 0.12.2. Every mitigation names the code that implements it; a
mitigation that is a deployment duty says so. Nothing here is a claim beyond what the code does. A shorter, per-boundary
table is in the handbook ([security architecture](../handbook/architecture/security-architecture.md#stride-threat-model)).

Profiles: `GATE_PROFILE=demo` (default) is for a laptop; `production` refuses to start unless the checks of
[DEPLOY.md](../DEPLOY.md) §5 hold (`packages/pdp-http/src/profile.ts`). This model assumes production unless a line
says otherwise. Paths below are relative to `packages/pdp-http/src/` unless they name another package.

## 1. Assets

| Asset | Where | Why it matters |
|---|---|---|
| Policy bundle and world (subjects, resources, tuples) | `gate_doc` (`state`), or `DATA_DIR/state.json` in file mode | Decides every access; a silent change widens or narrows access |
| Decisions and decision tokens | answers of `/access/v1/*`, `/xacml/v3/authorize`; single-use tokens in `gate_token` | An allow is what a PEP enforces |
| Audit chain and anchors | `gate_audit`, `gate_audit_meta`, `gate_anchor` | Evidence of every decision and change; tamper evidence |
| Signing keyring (Ed25519) | `gate_doc` (`signing_keys`), sealed | Signs decision tokens, PDP session tokens, decision assertions and policy publications |
| `SIGNING_KEY_SEAL` | process environment, from the secret store | Seals the keyring and TOTP secrets; HKDF root of the checkpoint, pseudonym and cluster-hop keys (`tokens.ts` `derivedKey`) |
| Credentials | `gate_doc` (`credentials`): scrypt hashes of local passwords (N=2^16), HMAC-SHA256 of PEP keys, sealed TOTP secrets; SCIM token HMAC | Authenticate console users, PEPs and the provisioning client |
| Console sessions | `gate_session` (PostgreSQL) or memory | A stolen session acts with the user's roles |
| PDP session tokens and BLP marks | bearer tokens at the PEP; claims in `gate_blp_session`, revocations in `blp_revocations`, marks in `gate_blp_mark` or `DATA_DIR/blp-sessions.json`, `blp-revocations.json` and `sessions.json` | A stolen token acts only for its bound subject and credential until revocation, close, idle or absolute expiry; marks enforce the *-property |
| Personal data | subjects in the world, actor ids in the audit | Privacy obligations (GP-01, GP-02) |
| Backups | archives of `scripts/ops/backup.sh` | Contain all of the above |
| Replica state and chain | a replica's memory (world, policy, PEP credential hashes, public keys, pseudonyms) and `DATA_DIR` (`audit.jsonl`, `audit-checkpoint.slots`, `replica-trust.json`) | Decides like a PDP; its chain is evidence until the database stores it |
| `GATE_REPLICA_KEY` (or `GATE_REPLICA_KEY_FILE`) / `GATE_REPLICA_KEYS` | replica environment or key file / database nodes' environment, from the secret store; a group master only on the database nodes | Authenticates a replica's requests and forwarded traffic; keys its row MACs, checkpoint and trust file |

## 2. Trust boundaries

| Boundary | Who crosses it | Authentication at the boundary |
|---|---|---|
| **PEP → PDP** (decision plane) | gateways and SDK clients | Bearer PEP key, HMAC-SHA256 at rest (a random 192-bit key needs no stretching), verified once then by SHA-256 digest (`auth.ts` `pep`, `matches`); rotation with a grace period. Per-credential `contextScopes` constrain asserted signals and optional trusted-attester JWS keys authenticate them (`context-trust.ts`). PDP-issued Ed25519 session tokens are bound to that credential and one subject, expire, and can be closed or revoked by token id, subject or credential, with PostgreSQL/shared-feed tombstones (`pep-sessions.ts`) |
| **PDP → backend** (decision assertion) | the gateway forwarding an allowed request | Ed25519 assertion, 30 s, bound to method, path, body digest and audience; verified by `packages/sdk/src/assertion.ts` |
| **Browser → console** | administrators | OIDC code flow with PKCE and IdP-proven MFA (`oidc.ts`), SAML Web SSO with an MFA `AuthnContextClassRef` (`saml.ts`), or local password plus TOTP (`auth.ts` `login`, `totp.ts`); session cookie and CSRF token |
| **IdP → console** | the organisation's identity provider | ID token signature from the IdP's JWKS, `iss`/`aud`/`azp`/`exp`/`nonce` checks (`oidc.ts`) |
| **SAML IdP → console** (via the browser) | the organisation's SAML identity provider; the browser carries the posted Response and LogoutRequest, so whoever controls the browser controls the bytes | XML signature on the assertion (and on a LogoutRequest) by a pinned certificate, signature-wrapping defences, RSA-SHA256+ only, `Issuer`, `Audience`, bearer `Recipient`, `Destination`, timestamps, `InResponseTo` single use and bound to the browser's `__Host-` cookie, assertion and logout ids single use, no DOCTYPE (`saml.ts`, through `@node-saml/node-saml`) |
| **SCIM client → PDP** | the directory | Bearer token, from the environment or a stored HMAC-SHA256 (`scim.ts`) |
| **Follower → leader** (cluster hop) | another Qadamar node | HMAC hop header under a key derived from `SIGNING_KEY_SEAL`, binding method, path, body digest and client address (`forward.ts`) |
| **Replica ↔ database node** (new in 0.8) | a stateless replica (`GATE_REPLICA_OF`) fetching state, shipping its chain, forwarding requests | Requests: HMAC hop under a key derived from the replica's own key, single use, 30 s, bound to method, path, body digest and client (`router.ts`, `forward.ts`); answers: Ed25519 signature of the keyring over the body digest, bound to the replica and the request nonce, generation never below the last applied (`replica.ts`, `replica-protocol.ts`); first keys pinned or from the JWKS over verified TLS; HTTPS required outside loopback; audit rows each carry a MAC re-checked at ingestion (`replica-source.ts`, `postgres.ts` `ingestReplica`) |
| **Reverse proxy → PDP** | the ingress | `X-Forwarded-For` read only from `TRUSTED_PROXIES` (`proxy.ts`) |
| **PDP → PostgreSQL** | the service role in `DATABASE_URL` | PostgreSQL authentication; role privileges checked at start (`profile.ts` `databaseRoleFailures`); `DATABASE_TLS=verify-full` checks the certificate chain and hostname for non-local production hosts, with optional private-CA/client-key files shared by runtime and operations clients (`postgres-tls.ts`) |
| **PDP → TSA** | RFC 3161 timestamp authority | Reply bound to hash and nonce (`anchor.ts`), token checked with `openssl ts -verify` against `TSA_CA_FILE` |
| **PDP → SIEM / break-glass receiver** | outbound webhooks | HMAC-SHA256 over timestamp and body (`siem.ts`, `notify.ts`); https required for the break-glass webhook in production |
| **Operator → backups** | backup and restore jobs | `BACKUP_ENCRYPTION_KEY`, AES-256-GCM archives (`scripts/ops/archive-crypt.ts`) |
| **Operator → seal key** | the secret store and escrow | Outside the product: custody is an owner decision (GO-23) |

## 3. Threats and mitigations

### S: Spoofing

| Threat | Mitigation in the code | Residual risk |
|---|---|---|
| A caller impersonates a PEP | PEP keys are random 24-byte secrets, stored as salted HMAC-SHA256, compared in constant time (`auth.ts` `hashMachineSecret`, `verifySecret`, `matches`); revocation and rotation with a bounded grace (`PEP_ROTATION_GRACE_SECONDS`) | A stolen PEP key decides as that PEP until revoked. A wrong key costs one HMAC (a 0.8.3 scrypt hash not yet replaced: one synchronous scrypt at N=2^14), bounded by the per-address rate limit taken before authentication (`router.ts`) |
| Password guessing on the console | Throttle per client and account with progressive lockout (`auth.ts` `login`, CWE-307); a dummy hash at the current cost for unknown users so timing does not reveal accounts; scrypt (N=2^16, r=8, p=2, cost stored with each hash, older hashes rehashed at the next sign-in) runs on the libuv thread pool (`verifySecretAsync`) | Local accounts cannot change their password (GP-17); production expects the IdP |
| Sign-in without the second factor | Production requires OIDC with MFA (`amr`/`acr`, `oidc.ts`) or SAML with an allowlisted `AuthnContextClassRef` (`saml.ts`) and refuses password sign-in unless every local account has TOTP (`profile.ts`); a TOTP step is accepted once (`auth.ts` `secondFactor`) | The IdP's own MFA policy is the customer's |
| Forged ID token or login CSRF | PKCE, `state` and `nonce` sealed under a per-process key; ID token signature and claims checked (`oidc.ts`) | The back-channel logout `jti` memory is per process (docs/API.md, console sign-in) |
| Forged or replayed SAML assertion, signature wrapping, login CSRF | Assertion itself signed by a pinned certificate (a Response-only signature is refused); node-saml reads only the signed bytes, one signature with one reference to its parent and a unique `ID`; SHA-1 refused anywhere in the message; `InResponseTo` must be the request id held in this browser's `__Host-gate_saml` cookie and is consumed once; assertion ids remembered until they expire; DOCTYPE refused before parsing (`saml.ts`) | The pending, assertion and logout ids live in the leader's memory (10,000 each, oldest out): a failover cancels sign-ins in progress, and a flood from many addresses can retire a pending request early. The IdP's AuthnContext classes are only as strong as the IdP's policy behind them. XML signature verification is a third-party library (`@node-saml/node-saml` 5.2.0, xml-crypto 6.4.0), pinned and audited in CI |
| A client forges its address to dodge limits | `X-Forwarded-For` only from `TRUSTED_PROXIES`, rightmost untrusted entry (`proxy.ts`) | — |
| A PEP claims a trusted network or device posture, or replays evidence for another session | Per-credential scopes allow only configured signals and optional network/country values; out-of-scope claims are refused and audited. A scope can require Ed25519/ES256 JWS evidence from a configured attester, verified against the exact value, subject, PDP session when present, device/network source, credential, audience, key id and expiry (`context-trust.ts`). Production treats unscoped legacy credentials as having no claim scope | A compromised PEP can still assert every value its scope allows and can reuse evidence only for the same subject, session and source; without attestation the PDP cannot independently prove the claim, and with it the MDM/sensor and its private key remain a trust boundary |
| A node or outsider impersonates a cluster follower | Hop header HMAC under an HKDF key from the seal, nonce remembered, loops stopped (`forward.ts`) | Anyone holding `SIGNING_KEY_SEAL` can forge hops |
| Something impersonates a replica, or a database node to a replica | Per-replica key (`GATE_REPLICA_KEYS`), hop verified before anything is read for that replica; answers verified against trusted keys only, a key trusted only when pinned, fetched over verified TLS at first start, or introduced by a trusted key (`replica-protocol.ts` `TrustedKeys`) | Without a pin, the first start trusts whatever the CA-verified TLS endpoint serves. A group (`prefix*`) holds a master on the database nodes only; each replica holds HKDF(master, its id), so its hops and row MACs cannot pass as a sibling's (`replicaKeyFor`). In the k8s component the init container sees every pod's derived key (never the master); the gate container sees only its own |
| A request reaches the backend without passing the PEP | Decision assertions (`packages/gateway`, `packages/sdk/src/assertion.ts`): signature, audience, method, path, body digest, single-use nonce; a shared `replayStore` for several replicas | The default replay memory is per process: a multi-replica backend must plug a shared store (docs/API.md 2.0.2) |
| Production started on fictional people | A production first start refuses to seed a world marked `"demo": true` (`store.ts`) | `ALLOW_DEMO_WORLD` lifts it (local test overlay only) |

### T: Tampering

| Threat | Mitigation in the code | Residual risk |
|---|---|---|
| Policy changed outside the approval workflow | Changes are proposals reviewed by someone else: the maker cannot review their own change and a beneficiary cannot approve it (`admin/changes.ts`); bundles validated at every boundary (`packages/core/src/validate.ts`: closed top-level keys, referential integrity, no role-inheritance cycle); publications signed (Ed25519) and the stored bundle checked against its latest signed publication at start (`policy-signature.ts`) | Whoever holds the keyring can sign; `POLICY_SIGNATURE_ADOPT` (refused in production) re-adopts an unsigned bundle |
| Bulk approval (list mode) used to slip a change past the second person | `POST /admin/v1/changes/decide` runs each id through the single-decision path (`admin/inbox.ts` `decideMany`, then `decideChange`), so maker, beneficiary, credential-holder, officer-only, stale-state and break-glass checks hold per item and each decided change gets its own audit row; refused items are audited too. Only an access admin or a security officer sets the mode (audited), and the server refuses the route in individual mode | One shared note covers the whole batch, so its text says less about each item than a single decision would |
| Audit rows rewritten or removed | SHA-256 hash chain per node; HMAC checkpoints in file and PostgreSQL modes; authenticated retention seals; recheck every 5 min; RFC 3161 anchors; production service role may not `UPDATE`, `DELETE` or `TRUNCATE` `gate_audit`, `gate_anchor`, `gate_audit_segment`, `gate_performed`; owner-only retention script | A database superuser holding the seal can rewrite a chain and its checkpoint; only anchors and the SIEM copy show it. Without a seal (demo), a full file rewrite has no keyed detection. |
| A decision token replayed or altered | Ed25519-signed, short-lived, single-use `jti` stored in `gate_token` (`tokens.ts`) | — |
| A forwarded admin request altered in transit | The hop HMAC binds method, path with query and body digest (`forward.ts`) | Node-to-node traffic is plain http unless the nodes serve TLS (`TLS_CERT_FILE`; the `deploy/k8s` cluster component's `GATE_NODE_SCHEME=https`) |
| Database rows edited by a privileged role | `FORCE ROW LEVEL SECURITY` on the Qadamar tables (`postgres-schema.ts`); production refuses a superuser, `BYPASSRLS`/`CREATEROLE` or owner role (`profile.ts`); non-local transport uses `DATABASE_TLS=verify-full` | A database owner/superuser remains outside the role boundary; encryption at rest is hosting configuration |
| Backup archive tampered with | AES-256-GCM; restore refuses an archive that does not authenticate (`scripts/ops/archive-crypt.ts`, `restore.sh`) | — |
| Tampered release or image | Base images pinned by digest, enforced by `tools/ci/checks.sh`; SBOM and `SHA256SUMS` per release (`scripts/release`); release image scanned by pinned Trivy for fixable HIGH/CRITICAL vulnerabilities | Releases and images unsigned (GP-06); the first Trivy CI run is not yet recorded |

| A replica fed an old, replayed or altered state (rollback to a revoked credential, a withdrawn grant) | Signature over the exact body; `aud` and the request's `nonce` echoed; generation monotonic, the floor kept in an HMAC'd `replica-trust.json` across restarts; the bundle signature checked again; past `GATE_MAX_STALENESS_MS` without a verified answer, decisions stop (`replica.ts` `apply`, `fresh`) | Within the staleness bound a replica decides on a copy up to 2 s old (as a cluster follower); deleting `replica-trust.json` resets the floor (an operator action) |
| A replica's chain rewritten or extended on its disk, or a forged batch | Per-row HMAC under the replica's audit key, checked at every start and again by the database at ingestion; continuity (link, seq, base = stored head) checked under the chain's advisory lock; refusals audited `replica_audit_refused` and alerted (`postgres.ts` `ingestReplica`, `replica-source.ts`) | Rows not yet shipped can be deleted (not forged) by whoever owns the replica's disk: at most `GATE_REPLICA_AUDIT_LAG_MS` of decisions; the database detects the gap when the replica comes back (`behind`) |

### R: Repudiation

| Threat | Mitigation in the code | Residual risk |
|---|---|---|
| A user denies a decision, change or emergency access | Decisions, sign-ins (success and failure), changes, approvals, break-glass and key events are audit rows with the actor and client (`audit.ts`; callers in `admin/`, `auth.ts`); break-glass notices go to an external receiver (`notify.ts`); anchors date the head (`anchor.ts`) | Pulls of the NDJSON audit export are not audited (GP-11) |
| A separation-of-duty conflict hidden by the caller | With `SOD_HISTORY=server` (required in production) SoD uses only server-recorded history, never caller-supplied `makerId` or `priorActions` | The codebase has a single maintainer (GO-33) |

### I: Information disclosure

| Threat | Mitigation in the code | Residual risk |
|---|---|---|
| Secrets at rest read from the database | Keyring and TOTP secrets sealed with AES-256-GCM under `SIGNING_KEY_SEAL` (`tokens.ts` `seal`); passwords stored as scrypt hashes, PEP keys and the SCIM token as salted HMAC-SHA256 | Seal custody and escrow are owner duties (GO-23); rotation with `SIGNING_KEY_SEAL_PREVIOUS` (`seal-rotation.ts`) |
| Session or CSRF token stolen through the browser | Cookie `HttpOnly; SameSite=Strict; Path=/admin`, `Secure` behind an https origin (`admin/session.ts`); CSRF header on writes; CSP `default-src 'self'; frame-ancestors 'none'`, `nosniff`, `no-referrer`, HSTS on https (`http.ts`) | — |
| Operational data through `/metrics` | Token required in production (32+ characters, `profile.ts`); on a non-loopback listen address `/metrics` answers 403 without `METRICS_TOKEN`, in every profile (`metrics.ts`, `server.ts`) | Metric labels carry no subject, resource or path (docs/DEPLOY.md §3) |
| The demo exposed to a network | The demo profile listens on loopback only; any other address needs `DEMO_ALLOW_REMOTE=true` and prints a warning (`server.ts`) | Setting the flag exposes seeded accounts (random passwords; the credentials file expires with `INITIAL_CREDENTIALS_TTL_SECONDS`) |
| Personal data in exports | Pseudonymised audit and evidence exports under an HKDF key from the seal (`admin/privacy.ts`) | Resource ids stay readable (GP-14); no audit retention or erasure (GP-01, GP-02) |
| A PEP enumerates subjects | Subject search is off for every PEP credential in production (`auth.ts`, `allowSubjectSearch`) | — |
| A read races a lower write in one BLP session | Mark-relevant decisions use sid/subject local queues; PostgreSQL holds their transaction locks from token verification and mark reload through commit (`sessions.ts`, `pep-sessions.ts`, `postgres.ts`) | No-session requests are untracked unless `BLP_SESSION_REQUIRED`; demo raw-id compatibility retains the old trust assumption and is warned |
| A PEP mints a fresh session id per request, closes/reopens to reset the mark, or a session token is stolen | Production accepts only PDP-chosen signed session ids, bound to subject and PEP credential. Every open token of that pair shares one subject mark; close does not erase it. Open-session cap, creation rate limit and audit. Administrators revoke by token id, subject or credential; live-row deletion, decision locks and shared tombstones revoke immediately across PostgreSQL and through the replica feed, including `bsid` decision tokens (`pep-sessions.ts`, `postgres.ts`, `router.ts`) | A compromised PEP can still release whatever its decisions permit and can open a new session unless its credential is revoked. The PEP remains the enforcement boundary; this closes session-laundering and stolen-token persistence, not PEP compromise |
| Plain-http telemetry | Production refuses a plain-http OTLP collector other than loopback (`profile.ts`) | — |

### D: Denial of service

| Threat | Mitigation in the code | Residual risk |
|---|---|---|
| Request floods | Token buckets per address and per principal, a separate budget for the decision plane, `429` with `Retry-After` (`ratelimit.ts`, `router.ts`); body limit 1 MB (`http.ts`); request and header timeouts (`server.ts`) | Volumetric DDoS is the hosting's (GO-27) |
| CPU exhaustion through password hashing | Sign-in and TOTP enrolment scrypt is asynchronous (`auth.ts` `verifySecretAsync`), two at once, at most 32 waiting (then 503 with `Retry-After`, audited `busy`), and throttled; PEP and SCIM secrets are HMACs, and after one success compared by digest | A spray past the queue turns legitimate sign-ins away with 503 until it stops (no backlog builds); a 0.8.3 PEP or SCIM hash costs one synchronous scrypt per wrong secret until its first success replaces it |
| Deep policy expressions | Expression nesting capped at 32 (`packages/core/src/validate.ts`) | — |
| Unbounded session marks or token creation | BLP marks bounded per PEP and overall; open tokens capped per (credential, subject), creation rate-limited and audited (`sessions.ts`, `pep-sessions.ts`) | A hostile PEP can consume its own quotas and create/close churn, but cannot exhaust another credential's mark share |
| Replicas cut off from the database nodes | They refuse decisions past the staleness bound and while their audit backlog is older than `GATE_REPLICA_AUDIT_LAG_MS`; `/readyz` 503 drops them from the load balancer (`replica.ts` `fresh`) | Fail closed: a database outage stops replicas within seconds, as it stops cluster followers |
| Replica traffic overloads the database nodes | Only what a copy cannot decide is forwarded, after the PEP credential is checked on the replica; audit is shipped in coalesced batches on a connection of its own (`postgres.ts` `ingestReplica`) | Every replica row is still written to the shared database: its write capacity bounds the total audit volume (PERFORMANCE.md) |
| A replica key holder floods the database nodes | Every replica request spends a budget keyed on the replica id (`router.ts`), whatever client its hop names; full snapshots are limited per replica and feed reads are serialised on their connection (`replica-source.ts`, `postgres.ts`); a timed-out long poll leaves no waiter; refused audit batches write at most one row a minute per replica and reason | A key holder can still use its own budget (`PEP_RATE_LIMIT_PER_MINUTE`) |
| Loss of the node or the database | Active/standby on a PostgreSQL advisory lock, or cluster mode with a staleness bound (`GATE_MAX_STALENESS_MS`); encrypted backups (`scripts/ops`) | RTO and RPO are owner decisions (GO-13) |

### E: Elevation of privilege

| Threat | Mitigation in the code | Residual risk |
|---|---|---|
| A console user reaches an action their roles do not grant | Every admin route checks roles server-side (`auth.ts` `allowed`, `admin/`) | — |
| A policy edit silently widens access | Validation rejects typos, unknown keys, unknown roles and inheritance cycles (`packages/core/src/validate.ts`); weakenings of mandatory controls are reported (`packages/core/src/weakening.ts`); the engine fails closed on what validation would reject | — |
| Emergency access abused | Break-glass bounded to at most 4 h and `breakGlassMaxHours`, the network and the other policy denies, audited and notified (`admin/break-glass.ts`, `notify.ts`) | — |
| An engine logic error lets a tenant rule lift a mandatory denial or a forbid | Lean 4 model of the pipeline with proofs (deny wins, mandatory before tenant policy, UNKNOWN forbids deny, UNKNOWN permits do not grant) and a differential test of `evaluate` against it in CI ([FORMAL-MODEL.md](../spec/FORMAL-MODEL.md)) | The proofs are about the model; the TypeScript is tested against it, not proved. Relations, filters and the server are outside the model |
| Clark-Wilson bypass on constrained data | Certified procedures, IVPs, input validators and PEP binding (`packages/core/src/integrity.ts`, `procedures.ts`) | The post-state check relies on the PEP consuming the token |
| The service role escalates in PostgreSQL | Production refuses superuser, owner, `BYPASSRLS` and `CREATEROLE` memberships (`profile.ts`) | Migrations run as an owner role the deployer controls |
| Supply chain | Dependencies: `pnpm audit --prod --audit-level high` blocks CI; SAST: Semgrep blocks on `ERROR` findings; secrets: Gitleaks over the whole history; release image: Trivy blocks fixable HIGH/CRITICAL findings (`.github/workflows/ci.yml`, `release.yml`); CI tools (gitleaks, elan, the Lean toolchain) from release archives pinned by SHA-256, the Lean toolchain run in a `contents: read` job that the release job (`contents: write`) needs | The Semgrep and Trivy steps have not run here; their first CI runs remain unrecorded |

## 4. Residual risks, in short

1. A compromised PEP can lie about the subject, any context value its credential scope permits, the request it forwards
   and the body it reports; scopes bound the blast radius and attestations delegate proof to the configured MDM/sensor,
   but the PDP cannot see past its PEPs and attesters (docs/API.md 2.0.2). An attestation is not single use: until its
   `exp` (at most 300 s) the PEP may reuse it for the same subject, session, source and value; no node remembers `jti`.
2. Whoever holds `SIGNING_KEY_SEAL` can unseal the keyring, forge cluster hops and recompute the audit checkpoint;
   its custody is outside the product (GO-23).
3. A database superuser can rewrite a chain consistently; only external anchors and the SIEM copy reveal it.
4. Non-local database transport is CA- and hostname-verified; encryption at rest is the hosting's duty. No audit retention or erasure (GP-01, GP-02); releases unsigned (GP-06).
5. File mode (no `DATABASE_URL`) is for demonstrations only: one node, local files; the production profile refuses it.
6. No independent penetration test or DAST yet (GP-07); the internal reports are in this folder.
7. A replica holds the world, the policy and the PEP credential hashes in memory: a compromised replica host can read
   them and decide wrongly for the PEPs that use it (it holds no private signing key, console account or per-subject
   audit key). Its unshipped audit rows, at most `GATE_REPLICA_AUDIT_LAG_MS`, can be destroyed with its disk.

Review this model at each release and whenever a trust boundary is added.
