<p align="center"><img src="docs/brand/qadamar-logo.svg" alt="Qadamar" width="280"></p>

# Qadamar — access control for regulated organisations

**Every access decision. Explained.**

Open-source authorization by **Qyber LLC**.

[Delivery and quick start](docs/DELIVERY.md) · [Brand prototypes and downloads](docs/brand/index.html) · [Brand guide](docs/brand/README.md)

Open-source policy decision point (PDP), licensed under [Apache-2.0](LICENSE). Nothing in this repository is real
customer data: the demo domain is an invented agency (`examples/toy-domain`).

One decision engine for every model a regulated buyer asks for, evaluated in a fixed order that tenant policy cannot
reorder or switch off:

| Model | What it enforces here |
|---|---|
| **RBAC** | roles with inheritance grant actions on resource types |
| **ABAC** | tenant `permit` / `forbid` / obligation rules as a JSON condition language with three-valued logic; ABAC on content attributes: content classes found in a resource mask, redact or deny (`abacContent`) |
| **ReBAC** | Zanzibar-style relations (direct, group, parent, transitive reporting line) give a *reason to know*, never a clearance |
| **CBAC** | context-based, Zero Trust rules re-verify network, country, IP ranges, local time windows, device posture, authentication/MFA freshness and methods, and behaviour risk on every request; time-bounded grants (`notBefore` / `notAfter` on role assignments and relation tuples) and session expiry; missing signals deny |
| **Bell-LaPadula** | L0–L3 levels, no read up, no write down from the session level or below the session's server-side high-water mark, trusted roles, compartments, untrusted-network cap |
| **Biba** | integrity verified > system > extracted > derived: no write up, no read down for a configurable action list, every read-kind action, or every action |
| **Clark-Wilson** | constrained items change only through certified commands with single-use Ed25519 decision tokens; declared integrity checks (IVP) on items; two-person certification records (rules covered: [ARCHITECTURE.md](docs/ARCHITECTURE.md) §16) |
| **Separation of duty** | two-person rule and conflicting-action rules |
| **AI agents** | an agent acts for a person: every link of the delegation chain must pass every stage |

Design documents: [REBAC-ANALYSIS](docs/REBAC-ANALYSIS.md),
[ARCHITECTURE](docs/ARCHITECTURE.md), [ADMIN-UI](docs/ADMIN-UI.md), [API contract](docs/API.md). Operating it:
[CONFIGURATION](docs/CONFIGURATION.md), [DEPLOY](docs/DEPLOY.md), [RELEASE](docs/RELEASE.md) (tarball, SBOM, checksums;
SSH-signed from 0.12.1; 0.8.3 to 0.11.0 signed after the fact), [SUPPORT](docs/SUPPORT.md) (template, no commitment yet).

## Run it

Requirements: Node.js ≥ 22.18 (runs TypeScript directly), pnpm.

```bash
pnpm install
```

```bash
pnpm --filter @product/admin build
```

```bash
CLOCK=fixed:2026-11-08T10:00:00Z RESOURCE_OWNERS='{"ruth":["carol"]}' node packages/pdp-http/src/main.ts
```

Then open http://127.0.0.1:8787. `PORT`, `HOST`, `DATA_DIR` (default `data/runtime`, git-ignored) and `WORLD_DIR`
are configurable (every variable, with its default: [CONFIGURATION.md](docs/CONFIGURATION.md), generated from the code); `CLOCK` pins the time so the demo data (grants, break-glass windows) stays meaningful. The first
start generates the demo administrators' passwords and a PEP API key, stores only their hashes, and writes the clear
values once to `data/runtime/INITIAL-CREDENTIALS.txt` (mode 600).

Demo administrators: `amira` (access administrator, policy author), `omar` (approver), `lina` (security officer),
`ruth` (resource owner: `RESOURCE_OWNERS` above maps her to the demo resources owned by `carol`; without it she sees
nothing), `sam` (auditor). Try: propose a change as amira in the Simulator, see the impact, approve it
as omar (amira cannot), open a break-glass as lina, verify the audit chain as sam, certify a Clark-Wilson procedure
(Integrity) as lina and approve it as omar. `lina` and `omar` are also PDP subjects of the demo world, with no role:
a certifier must not be able to execute the procedure, and one without a subject is refused. The world is read only on
the first start of a `DATA_DIR`: a demo directory seeded before these two subjects were added keeps its old world
(start with an empty one).

## Test it

```bash
pnpm test
```

```bash
pnpm typecheck
```

<!-- test-summary:start -->
Measured by `bash tools/ci/checks.sh` (Node TAP totals, including subtests):

| Suite | Tests |
|---|---:|
| Packages | 943 |
| Console unit / markup | 101 |

Pass, skip, coverage, browser and Python results are reported by each CI run; optional tools change skips.
Browser totals include route subtests only when Chromium runs. See [QUALITY.md](docs/QUALITY.md).
<!-- test-summary:end -->

The gate covers engine and adversarial regressions, SQL against live PostgreSQL, AuthZEN and XACML,
SDKs and the gateway, governance, identity and storage, plus the English, French and Arabic console.
Browser checks run locally when Chromium is available and are required in CI. Their scope and limits are in
[ACCESSIBILITY.md](docs/ACCESSIBILITY.md). Coverage thresholds and measurement are in [QUALITY.md](docs/QUALITY.md).

## Layout

| Path | What |
|---|---|
| `packages/core` | the engine: `evaluate`, `buildFilter` (partial evaluation), `simulate`, `validateBundle`, `mandatoryWeakenings`. Pure, no dependency |
| `packages/sql` | residual predicate → parameterised Postgres `WHERE` |
| `packages/pdp-http` | AuthZEN Authorization API 1.0 + XACML 3.0 JSON Profile + explain / filter / tokens, OTLP traces, admin control plane, hash-chained audit. Node standard library plus `pg` (PostgreSQL mode) |
| `packages/sdk` | TypeScript PEP SDK: PDP client and `enforce()` of obligations on a JSON record |
| `sdks/python` | Python PEP SDK (`qadamar`, Python ≥ 3.9, standard library only): the same client, `enforce()` and decision-assertion verifier ([README](sdks/python/README.md)) |
| `packages/gateway` | enforcing reverse proxy (PEP) in front of a JSON API: decide, consume tokens, apply obligations, fail closed |
| `apps/admin` | the administration console (React 19, Vite 8), built to a static bundle served by the PDP; no external resource |
| `examples/toy-domain` | the demo policy bundle and world |

## Not done yet

- **Console language review:** Arabic and RTL support are implemented; native Arabic review is required before customer use. Screen-reader testing still requires a human ([ACCESSIBILITY.md](docs/ACCESSIBILITY.md)).

- **Not externally reviewed or certified.** Penetration test and certification are ahead
  ([ARCHITECTURE.md](docs/ARCHITECTURE.md) §12).
- **Formal model: partial.** A Lean 4 model of the decision core with mechanised proofs (deny wins, mandatory
  controls before tenant policy, UNKNOWN forbids deny and UNKNOWN permits do not grant, malformed requests deny,
  determinism, obligations only on allow) and a differential test of `evaluate` against it in CI. The relation graph
  and the certification fingerprint are abstracted; filters, traces and everything around the engine are outside
  ([FORMAL-MODEL.md](docs/spec/FORMAL-MODEL.md)).
- **PostgreSQL with one active node and standbys, or a cluster where every node decides** (one leader for the admin
  plane, followers bounded in staleness, one audit chain per node; state and audit committed together, fail-stop,
  keyed checkpoints, service-append-only audit tables) and **RFC 3161 anchoring** of the audit head
  ([API.md](docs/API.md) §3.9.1). Sealed retention and per-subject erasure are built (file and owner-only PostgreSQL
  paths); deleted row contents, legacy raw ids, actors, SIEMs and backups still need external procedures. Backup and
  restore scripts with a drill test (`scripts/ops`, [DEPLOY.md](docs/DEPLOY.md) §4). Not done: database replicas,
  encryption at rest (hosting), a drill on production-sized data. Load and failover figures from one laptop:
  [PERFORMANCE.md](docs/PERFORMANCE.md). Without `DATABASE_URL`,
  local files, one node, demo only.
- **Console sign-in through OIDC or SAML 2.0** (OIDC: authorization code + PKCE, back-channel logout; SAML: signed
  and encrypted assertions, SP- and IdP-initiated single logout over HTTP-POST/Redirect; MFA proven by the IdP either way; users and groups provisioned
  over SCIM 2.0). Without an IdP, the local password accounts remain (demo); they can
  require TOTP ([API.md](docs/API.md) §3.1.2). `GATE_PROFILE=production` refuses to start without TLS, verified TLS to a non-local
  PostgreSQL host, OIDC or SAML with MFA, a least-privilege database role, sealed keys, a metrics token, TSA anchoring and break-glass notices
  ([DEPLOY.md](docs/DEPLOY.md) §5).
- **Signed policy bundles** are checked by the node that stores them; distributing them to separate PDPs, and a
  maximum bundle age, are not done. The gateway (`packages/gateway`) proxies plain http upstreams and JSON only.
- **Managed offer on Kubernetes** (one instance per customer, `GATE_PROFILE=production`): manifests, tenant scripts
  and an end-to-end smoke test proven on a local cluster only, against test-only stand-ins for the IdP, the TSA and
  the break-glass receiver; no cloud overlay yet ([MANAGED-OFFER.md](docs/MANAGED-OFFER.md) §11). Behind a proxy or
  ingress, set `TRUSTED_PROXIES` ([API.md](docs/API.md) §3.1.1).
- **The BLP high-water mark is shared per subject and PEP credential.** A PEP opens a PDP-issued session and sends
  `context.sessionToken`; the signed, expiring token binds the PDP-chosen id, subject and credential. Every open token
  of that pair shares the mark, so fresh tokens and close/reopen cannot reset it ([API.md](docs/API.md) §2). Production
  requires tokens and refuses the deprecated raw `sessionId`; demo compatibility still trusts a PEP-chosen raw id and
  warns. No-session requests are untracked unless `BLP_SESSION_REQUIRED` (required in production). Open tokens are
  capped per subject, creation is rate-limited and audited, and a session can be closed or revoked at once by token id,
  subject or credential (cluster-wide, with replica-feed tombstones). Decision tokens issued under a revoked session die
  with it. A compromised PEP remains the enforcement boundary; credential claim scopes and optional signed context
  attestations bound what it may assert. Marks lapse after 15 min idle or 8 h; related decisions are linearizable on one
  node and across PostgreSQL. The lattice is fixed at L0..L3.
- **Resources are registered at run time by the application that owns them** (`/x/v1/resources`, a PEP credential bound
  to resource types; [API.md](docs/API.md) §2.2): new records, raised labels and retirements apply at once, a
  declassification, a change of integrity, owner, parent or an attribute the policy reads, and retiring a constrained
  item wait for a second person; an existing constrained item changes only through its certified command. Not done: a
  console screen for the inventory, a full-set reconciliation mode (the application pages `/x/v1/resources/list` and
  diffs). A constrained item's copy follows its completed certified commands (their post-state). A retired id comes
  back only through review (retired ids are an append-only log outside the state document). With PostgreSQL, subjects,
  resources and tuples are individual rows and followers apply a change log; file mode still rewrites its JSON document.
  Nodes can load a configured subset of isolated tenants (`GATE_TENANTS_FILE`, `GATE_SERVE_TENANTS`); each served
  tenant’s full world remains in memory. Splitting a single tenant’s graph is not implemented. Registration validates
  only the affected parent/child subtree:
  [measured 100k and 1M-resource figures](docs/PERFORMANCE.md#per-record-postgresql-storage-2026-11-11): group commit met the 1,000/s single-registration target at 32 clients, at 2,423.898/s (100k) and 1,962.376/s (1M); one sequential client still pays a durable commit per request.
- **Cedar: an export subset and a specification, not an engine.** Tenant rules use the JSON condition language (plan B
  of ARCHITECTURE.md §3.4), now specified as a versioned language with a JSON Schema
  ([POLICY-LANGUAGE.md](docs/spec/POLICY-LANGUAGE.md) 1.0). `toCedar` and `scripts/export/cedar.ts` export RBAC grants,
  ABAC permits and forbids, content-attribute denies and translatable CBAC (context) requirements to Cedar policies and a Cedar schema, and list what does not translate
  (mandatory models, need-to-know, Clark-Wilson, separation of duty, obligations, delegation). Faithfulness is
  differential-tested against a test-only Cedar-subset evaluator, not against the Cedar engine; Qadamar does not run Cedar.
- **Break-glass notices** go to one signed https webhook ([API.md](docs/API.md) §3.6.1); no e-mail or paging integration.
- A database backstop must not trust session variables set by the application.
- **SDKs beyond TypeScript:** Python is done (`sdks/python`, [API.md](docs/API.md) §2.3), installed from the repository
  path (not published to a package index). No other language yet.
