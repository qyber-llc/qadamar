# Architecture — domain-agnostic access layer

Status: **draft 1 for owner review (2026-11-07).** Builds on PRODUCT.md and REBAC-ANALYSIS.md. No performance
figure is given: budgets are set by measurement in the MVP.

## 1. Principles

1. **Deny by default, any deny wins, a rule that fails denies.**
2. **Mandatory models are built in, not configurable away.** Classification (Bell-LaPadula), compartments, Biba
   integrity, the network condition, separation of duty, no self-grant and two-person rules are code in the core.
   Tenant policies can narrow them and never disable them.
3. **Everything else is data:** the attribute schema, relations, roles and policies, versioned and immutable once
   published.
4. **One decision procedure everywhere.** The same core runs in the PDP service, in every SDK and in the second
   enforcement tier. Same input, same decision, with the policy version stamped on it.
5. **Enforce in every data path:** API, SQL, files, search, exports, AI grounding. A filter the database does not
   apply is a filter something will forget.
6. **Hidden means absent.** A refused read answers like a missing record (404, no count).

## 2. Components

```
        Admin console ── Control plane (policy store, versions, approvals, grants, audit) ── IdP / SCIM / HR
                                │ signed policy bundles + attribute snapshots
     ┌──────────────────────────┼─────────────────────────────────────────┐
     │                    PDP (stateless)                                 │
     │   decide · batch · filter (residual → SQL) · search · explain      │
     └───────▲──────────────▲──────────────▲──────────────▲───────────────┘
             │              │              │              │
       HTTP gateway     SDK (in-process)  Postgres        AI / RAG filter,
       PEP              PEP + 2nd tier    predicates+RLS  redaction service
             │              │              │              │
                 Protected application (frontend ⇄ backend ⇄ database)
```

- **Core library**: attribute model, built-in models, policy evaluation, obligations, explain. Pure and
  deterministic, no I/O.
- **PDP service**: the core behind an HTTP/gRPC API, loaded from signed bundles. Stateless, so it scales horizontally.
- **Control plane**: policy authoring, versioning, simulation, approvals, grants and relation tuples, break-glass,
  access reviews, audit store. The admin console is its UI (deliverable 4).
- **PEPs and adapters**: §5 and §6.

The admin console keeps typed catalogues for English, French and Arabic under `apps/admin/src/i18n`; key, kind and
function-arity parity is checked in the console suite. The persisted language sets the document's `lang` and `dir`.
Logical CSS mirrors navigation and layout, while code and numeric values keep LTR order. Browser geometry assertions
check the RTL shell; 320 CSS-pixel reflow and forced-colors checks extend the desktop workflow suite.
`tools/ci/checks.sh` includes these tests, with `E2E_REQUIRED=1` in CI. Human screen-reader and native Arabic reviews
remain outstanding; [ACCESSIBILITY.md](ACCESSIBILITY.md) distinguishes assertions from executed verification.
Current test totals come from CI TAP summaries into a checked README block ([QUALITY.md](QUALITY.md)).

## 3. Attribute model and policies as data

### 3.1 Model

A request is `(subject, action, resource, context, content?)`. This is the AuthZEN shape plus a content
segment.

- **Subject**: id, type (user, service, agent, external party), status, clearance, compartments, trusted flag,
  capabilities, groups and functions, plus **derived sets** computed once per request: known objects from relations,
  reporting line. Each is computed once per request, digest included.
- **Resource**: type, id, classification, compartments, integrity level, owner and parents, data domain, typed
  attributes declared in the tenant schema.
- **Context**: time, network (trusted or untrusted, resolved by the PEP from configured CIDRs), client IP and country,
  device posture, authentication/MFA times and methods, and IdP/PEP behaviour risk. Each PEP credential scopes the
  signals it may assert, with optional network/country constraints; an out-of-scope assertion is refused and audited.
  A scope can require an Ed25519/ES256 JWS from a configured MDM or network-sensor key, bound to the exact value,
  subject, PDP session when present, device/network source, PEP, audience and expiry, so evidence cannot be replayed
  across users, sessions or sources. Demo-only legacy credentials retain unscoped assertions for one version with a deprecation
  warning; production requires scopes and treats an older unscoped credential as scoped to none.
- **Content segment** (ABAC on content attributes, `abacContent`): text span plus closed content classes.
- **CBAC rules** (context-based, Zero Trust, `context`): selectors over actions, kinds, types, resource level and
  content classes, with situational requirements re-evaluated on every request; a required missing signal is UNKNOWN
  and denies. No decision cache reuses an outcome across different context signals. CBAC also bounds grants in time
  (`notBefore` / `notAfter` on role assignments and relation tuples, against `context.now`) and denies a known-expired
  session (`CBAC.SESSION_EXPIRED`).

### 3.2 Evaluation order (fixed by the core)

1. Inactive subject → deny.
2. Role eligibility (RBAC matrix of the tenant).
3. Built-in mandatory checks: clearance ≥ effective level (max of the resource and its parents), every compartment
   held, network condition, Biba no-write-up, BLP no-write-down on content unless trusted (below the session level,
   or below the session's high-water mark when the PEP names its session).
4. Need-to-know: a declared relation gives a reason to know (REBAC-ANALYSIS.md option B). Modes off, dry run and
   enforce, with would-deny records.
5. Tenant ABAC policies, including ABAC on content attributes: segments masked, redacted or denied.
6. CBAC (context-based, Zero Trust): every matched network, country/IP, local-time, device, authentication and
   risk requirement is re-verified; deny on FALSE or missing; deny an expired session.
7. Clark-Wilson certified commands and integrity checks, then separation of duty.
8. Combine: any deny wins; field allowlists intersect; redactions union.

A relation never lifts step 3 (REBAC-ANALYSIS.md §6). For the Lean model of the pipeline this is a theorem
(`mandatory_before_tenant_policy`, [spec/FORMAL-MODEL.md](spec/FORMAL-MODEL.md)), as are "any deny wins" and "an
UNKNOWN forbid denies"; a differential test in CI ties the model to `evaluate`.

### 3.3 Relations

Declared per tenant: `relation allocated(person → project) from sql "…" valid while to_date ≥ today`, or from the
product's tuple table (grants, shares, delegations), with an optional transitive closure and a depth bound (a
reporting line is capped at 20). The core compiles a relation two ways: into the subject's derived set for
point checks, and into an SQL `EXISTS` for pushdown.

### 3.4 Policy language — recommendation

| Criterion | Own DSL | **Cedar** | Rego (OPA) |
|---|---|---|---|
| Licence, maturity | Ours to build | Apache-2.0; formal model and proofs in Lean, differential testing ([cedar-spec][cedar-spec]); used by Amazon Verified Permissions ([AVP][avp]) | Apache-2.0, CNCF graduated ([OPA][opa]) |
| Readable by an access administrator | Depends on our design | Yes: permit / forbid with typed conditions | Hard: a general logic language |
| Validation against a schema | To build | Yes, at policy create/update ([Cedar docs][cedar]) | Optional |
| Partial evaluation → SQL pushdown | To build | Residual policies via type-aware partial evaluation (`tpe` feature of the `cedar-policy` crate, [docs.rs][cedar-tpe]); the SQL compiler is ours | Partial evaluation to SQL filters ([OPA filtering][opa-filter]) |
| Runs in the TS tiers (gateway, backend, web) | Yes | `@cedar-policy/cedar-wasm`, Apache-2.0, 4.14.0 on npm (checked 2026-11-07) | Rego compiles to Wasm ([OPA Wasm][opa-wasm]) |
| Obligations (field / segment redaction) | Native | Not native: one decision per field or segment action, or policy annotations read by our layer | Free-form output documents |
| Analysis for "impact of a change" | To build | Designed to be analysable; schema-typed | Harder |

**Recommendation: built-in models in our core code, tenant policies in Cedar.** Cedar has the strongest
correctness story, a schema, `forbid` semantics that match "any deny wins", and a JS/Wasm build. It also does not
lock buyers into an exotic language. Our layer adds what Cedar does not have: the mandatory models, relations
compiled from data, obligations and the SQL compiler.

**Qadamar before committing (MVP spike, one week):**
1. Type-aware partial evaluation is reachable from the Wasm build. Not verified: if it is not, residuals come from a
   Rust sidecar or the plan B below.
2. Per-decision latency in Node is within budget for list pages, measured with a recorded corpus of real decisions.
3. The rule shapes the product ships with translate to residual → SQL without loss.

**Plan B** if the gate fails: a small typed expression language of our own, stored as JSON AST and limited to
comparisons, set membership and relation checks, with our own analysis. CEL, used by Cerbos conditions
([Cerbos][cerbos-cel]) and SpiceDB caveats, is the fallback syntax for that language.

**Status (2026-11-11): plan B shipped.** The JSON AST language is specified, with its three-valued semantics, the
evaluation order and the bundle schema, in [spec/POLICY-LANGUAGE.md](spec/POLICY-LANGUAGE.md) (language 1.0) and
[spec/policy-bundle.schema.json](spec/policy-bundle.schema.json), both checked against `validateBundle` by
`packages/core/test/spec.test.ts`. Against lock-in, `packages/core/src/cedar.ts` (`toCedar`) exports the part Cedar can
decide identically: RBAC grants, ABAC permits and forbids, content-attribute denies, CBAC network/country/CIDR/device/method/risk
requirements and the inactive-subject rule, with every attribute read guarded by `has` so that Cedar's
error-skips-policy rule cannot make a forbid fail open. Context IP ranges use `context.ip.isInRange(ip("<cidr>"))`, with `context.ip` an `ipaddr` extension value. It lists
the rest (mandatory models, need-to-know, Clark-Wilson, SoD, obligations, delegation, context action-kind selectors,
IANA time windows and authentication-age requirements) in `unsupported`. Not validated
against the Cedar engine: a test-only Cedar-subset evaluator is the oracle (appendix A of the spec).

### 3.5 Versioning

Every policy set, schema and relation definition is an immutable version with a fingerprint stamped on every
decision, decision token and audit row. Assignments pin a version and never float
to a newer one. Rollback is a new reviewed version and cannot resurrect an
expired grant.

## 4. PDP API

AuthZEN Authorization API 1.0 as the base, final since January 2026 ([spec][authzen]). Extensions are namespaced.

| Endpoint | Purpose | Standard |
|---|---|---|
| `POST /access/v1/evaluation` | decide one request → effect, reasons, rule ids, obligations, policy version | AuthZEN |
| `POST /access/v1/evaluations` | batch, with `execute_all`, `deny_on_first_deny`, `permit_on_first_permit` | AuthZEN |
| `POST /access/v1/search/resource` | what can X do / see (ids, paged) | AuthZEN |
| `POST /access/v1/search/subject` | who can see Y: PEP credential, like the other searches; the console's scoped version is `POST /admin/v1/simulate/who-can` | AuthZEN |
| `POST /x/v1/filter` | the residual as a parameterised SQL predicate (Postgres first) or a search-engine filter | extension |
| `POST /x/v1/explain` | the caller's own decision with rules and relation path; a hidden record gives the 404 of a missing one | extension |
| `POST /x/v1/resources`, `/retire`, `/sync`, `/list` | the owning application registers, updates and retires its records at run time (credential bound to resource types); a declassification, a change of integrity, owner, parent or a policy-read attribute, or retiring a constrained item becomes a two-person change; existing constrained items change only through certified commands (API.md §2.2) | extension |
| `POST /x/v1/simulate` | a candidate policy version against the published one, over fixtures or a sample of real subjects; metadata only, never content. Not built: the console simulates through `/admin/v1/simulate/*` | extension |
| `GET /.well-known/authzen-configuration` | PDP metadata | AuthZEN |
| `POST /xacml/v3/authorize` | the same evaluation for XACML PEPs: categories mapped to subject / resource / action / context, Qadamar obligations as XACML obligations with stable ids, `MultiRequests` | OASIS JSON Profile of XACML 3.0 v1.1 |

**Signed decisions.** For a write, the PDP returns a short-lived decision token bound to the subject, action,
resource id, resource version, the policy version and a single-use id. It lives `clarkWilson.tokenTtlSeconds`
(15 s in the toy bundle, at most 300 s), is consumed by a committed insert before execution, and the decision is re-made on the locked row.
It is an asymmetric signature (JWS, Ed25519), so enforcement points verify without holding the signing key: the token
header names its key (`kid`) and `/.well-known/jwks.json` publishes the public keys. Keys rotate through the console;
a retired key keeps a 300 s window for decisions, assertions, policy and introductions, and a separate one-hour window
only for BLP sessions. Its public half remains offline evidence history after leaving the live JWKS, so old evidence
manifests still verify through the key-introduction chain. Private keys can be sealed at rest
(`SIGNING_KEY_SEAL`, AES-256-GCM; mandatory with PostgreSQL, where the keyring is shared by all nodes, unless
`ALLOW_CLEAR_SIGNING_KEYS=true`, which the production profile refuses). PEPs authenticate with named credentials that rotate with an overlap and can be
revoked one by one (docs/API.md §3.10). PDP-issued BLP session tokens are accepted only with the issuing credential and
subject. A security officer can revoke live sessions immediately by token id, subject or credential: their registry rows
and shared tombstones commit with the audit event, other PostgreSQL nodes see the revocation under the same decision
locks, the signed replica feed carries the tombstones, and decision tokens issued under a revoked session (`bsid`) cannot
be consumed (docs/API.md §2).

**Server-derived separation of duty.** Successful token consumption reserves the certified action; the PEP reports
afterwards whether it ran (`completed` or `failed`, `/x/v1/tokens/outcome`). The PDP persists the reservation's subject,
resource, action and time in the same PostgreSQL transaction as token use and audit, and the outcome as a row of its
own. A reservation counts while pending and once completed, never once failed; pending ones are listed for an operator
to reconcile (docs/API.md §3.12).
Each decision unions the caller's prior actions with the recorded history of the subject and its delegation chain on
that resource, so a delegate inherits the delegator's history and omission by the PEP cannot bypass a conflict. The
first recorded actor is the resource's maker: the server supplies that identity when the caller omits it and denies a
contradictory caller claim with `SOD.MAKER_MISMATCH`. For a resource with no recorded certified action,
`SOD_HISTORY=server` (default in every profile) ignores them for every SoD-constrained action, so conflict rules see an
empty history and the two-person rule denies with `SOD.MAKER_UNKNOWN`; explicit `SOD_HISTORY=caller` is a warned
compatibility opt-in for demos/tests that still falls back to the caller's history and maker. The runtime indexes each immutable performed-action array by resource, so deriving maker and history costs work proportional to that resource's history rather than the entire log.

## 5. Enforcement points

| PEP | What it does |
|---|---|
| **HTTP / GraphQL gateway** | Terminates the session, resolves network and authentication context, decides, forwards signed claims to the backend, which re-decides. GraphQL: per-field decisions through the batch API. |
| **Enforcing HTTP gateway** (built, `packages/gateway`) | A reverse proxy (node:http, the PEP SDK, no other dependency) in front of a JSON API. A route table maps method + path to resource type, id and action; anything else is 404. It refuses method overrides (`X-HTTP-Method-Override` and kin, `_method`) with 400, forwards request headers and query parameters by allowlist only (a base set plus what each route declares), and bounds the whole upstream exchange by one deadline. It asks the PDP before forwarding and answers 403 on deny; consumes the decision token of a certified command before forwarding, sending the request body as the post-state the IVPs check on routes declared `postState: 'body'` (a route that cannot supply a post-state the PDP asks for is refused); carries out `notify` through a configured hook; redacts, allowlists and masks the JSON response; refuses (502) any obligation it cannot enforce, including an unknown obligation key, a class the response does not carry, or `notify` without a hook. Lists use per-item batch decisions (not the SQL filter, which carries no obligations and which a JSON upstream cannot apply) and release only the allowed items. It strips hop-by-hop fields both ways, the caller's credentials, cookies and forwarded-for headers, never holds the PEP key outside its PDP client, bounds request and response bodies, ignores forwarded-for when resolving the trusted network, and logs one line per decision with ids, rule ids and status only. Upstream error bodies are not released. Every forwarded request carries a **decision assertion** the backend verifies (§16, E1). Not done: GraphQL, https upstreams (the upstream is expected on a private link). |
| **SDKs** | In-process core (Wasm) plus attribute loaders, used as the second tier inside the backend. TypeScript first, then Python (`sdks/python`); other languages in the order buyers ask (owner to prioritise). |
| **TypeScript PEP SDK** (built, `packages/sdk`) | No dependency. A client for evaluation, batch evaluations, the three searches, the SQL filter and decision-token consumption, validating every response shape; `enforce()` releases a deep clone of a JSON record only on allow, redacts the listed fields, masks `content` fragments of the listed classes, and refuses (throws) on a deny, an unknown obligation key, a `notify` obligation it cannot carry out, or a class it cannot locate. A reference PEP test runs it against the real server. |
| **Python PEP SDK** (built, `sdks/python`) | Python ≥ 3.9, standard library only. The same client (plus explain), response validation, `enforce()` and decision-assertion verifier as the TypeScript SDK, with Ed25519 verification in pure Python (RFC 8032 §6). Its tests include the RFC 8032 vectors and a run against the real server. |
| **Postgres** | (a) predicate compiler for list queries; (b) generated RLS policies as a backstop, with the subject stamped into session variables at connection checkout, and no subject reads zero rows. |
| **AI / RAG filter** | Grounding built for the verified reader only: retrieval pre-filtered by the same predicate, results re-checked, and tool calls (MCP) gated per action. Prompt rules qualify answers as "in what you can see". |
| **Redaction service** | Segment classification (deterministic first, model may only add), OCR, maker-checker review, output as a new image-only PDF without text layer or metadata. |
| **Files and exports** | Re-check at download time; no persistent bearer URL for an original. |

## 6. Adapters

- **Identity**: OIDC with Entra ID and Okta (claims, MFA / authentication-strength evidence, back-channel logout).
- **Provisioning**: SCIM 2.0 for users and groups (built: `/scim/v2`, API section 3.11). Groups map to roles only
  through an explicit table; every write is a two-person proposal unless direct mode is configured.
- **HR / org chart**: reporting lines and functions as relation sources.
- **Data sources**: relation definitions and resource attributes read from the protected application's database
  through read-only roles, using allow-listed queries and column classes.
- **SIEM**: export of decision and admin events. Built: signed (HMAC-SHA256 + timestamp) NDJSON push over HTTPS with a
  persisted cursor, at-least-once, and a pull endpoint (API sections 3.9, 3.9.3). Syslog and other formats by buyer demand.
  Audit content is ids, counts and rule ids, never record text.

## 7. Multi-tenancy

A tenant is an isolation boundary: its own schema, policies, relation store, signing keys and audit chain.

- **Default: single-tenant per customer**, on premises or in the customer's sovereign cloud, including air-gapped
  installs with no outbound call. Government and defence buyers will expect this.
- **Tenant partitions (implemented)**: `GATE_TENANTS_FILE` maps tenant ids to separate file stores or PostgreSQL
  databases, worlds and security keys. `GATE_SERVE_TENANTS` selects the runtimes opened by this node; all other
  tenant requests receive 421. The ingress routes `X-Qadamar-Tenant` on the original socket. No record arrays or indexes
  are constructed for unserved tenants. Each served tenant retains its complete graph, including usersets and
  parent links; decisions, search and SQL compilation use the unchanged engine.
  Cluster locks, freshness, session marks, token consumption, rate leases and audit chains stay within each tenant
  database. A replica polls and ships audit only for its selected tenants, carrying the tenant header on signed feed
  requests and forwarded traffic. Keys and DATA_DIRs are separate; manifest validation rejects overlapping directories,
  reused keys and duplicate database addresses. See [DEPLOY.md](DEPLOY.md#tenant-partitions).
- **Later, a shared-database multi-tenant managed service**: tenant id in every key and query, RLS by tenant in the product's own
  database, per-tenant keys. This only happens if the owner chooses business model 3 (PRODUCT.md §6).

## 8. Performance

- Decisions are local where possible: the SDK evaluates in-process, and the PDP service is for languages without
  an SDK and for the admin plane.
- Subject-derived sets are computed once per request.
- Lists use pushdown, not N checks. Above an id-list threshold, use the predicate, never `IN (…)` of thousands.
- **Decision cache** keyed by subject digest, action, resource version and policy version. Invalidation is by
  version change, not by time, so a revocation is never served stale.
- Budgets (p99 per decision, per list page) are defined in the MVP from a recorded corpus of real decisions, not assumed.

## 9. Availability and failure

- The PDP is stateless, active-active, loaded from signed bundles. A bundle older than a configured maximum age
  makes the PDP refuse.
- **Fail closed**: an unreachable PDP or attribute source denies. There is no fail-open switch.
- **Operational probes**: `/healthz` checks only the process; `/readyz` additionally commits pending work and requires a verified audit chain (with PostgreSQL, the latest database recheck, at most 60 s old); in active/standby mode only the active PostgreSQL node opens its port, so only it answers; in cluster mode every node answers, `/readyz` is 503 on a node whose shared state is older than its staleness bound, and `/leaderz` is 200 only on the leader. `/metrics` exports decision, route latency, audit, anchor, commit, active-node and break-glass notice metrics in Prometheus text format, optionally protected by `METRICS_TOKEN`.
- The control plane can be down without stopping decisions: publishing stops, enforcing continues.
- Break-glass is a time-boxed grant (4 h, notified, reviewed), not a bypass of the engine.

## 10. Audit

Hash-chained audit with a verifier, an HMAC checkpoint under an HKDF key derived from `SIGNING_KEY_SEAL` (file and
PostgreSQL modes), and an external RFC 3161 anchor required in production. Logged: every deny, every sensitive allow,
every admin change with maker and checker, and coalesced read audit for classified records. Every row carries the
policy version and rule ids. A file start or verification fails stop on a checkpoint/head mismatch, so rewriting the
whole JSONL chain no longer hides behind recomputed plain SHA-256 links; demo mode without a seal still needs an
external anchor or independent copy to detect that rewrite.

PostgreSQL requests staged before a writer starts share one durable commit. Decision-only groups use one prepared
statement for the chained rows, derived metadata and any decision tokens and BLP marks; its implicit transaction is
durable before the statement resolves and before any answer. Other writes use explicit transactions. This removes
network round trips, not WAL persistence, chain ordering, checkpoints, anchors or fail-stop on a write error.

Retention is an explicit segment operation, not silent row deletion. An HMAC-sealed record commits to the removed
prefix digest and its last head (also RFC 3161 anchored when a TSA is configured), a retention event extends the live
chain, and later scans start from the sealed head. File mode runs at start and daily; PostgreSQL uses an owner-only
offline ops script and never grants audit `DELETE` to the service role. Verification after retention proves the seals
and retained rows, not the contents of rows that were removed without an external copy.

New subject ids are HMAC pseudonyms under independent random per-subject keys. Only the separate mapping
(`audit-subjects.json` or `gate_subject_identity`) holds raw ids and keys; erasure deletes the mapping and appends an
audited event without changing a chained hash. SIEM and `pseudonymise=1` exports preserve those pseudonyms rather
than double-hashing them. Actor ids, detail fields, and legacy raw-subject rows are outside this erasure mechanism.

## 11. Security of the product itself

The admin plane is the crown jewel:
- MFA, and two-person approval for publishing policies and for broad grants;
- administrators manage without reading content;
- no self-grant;
- signed bundles; no secret in images.

Security tooling in CI: Gitleaks (secrets), Semgrep (SAST, `ERROR` findings block), `pnpm audit` (SCA, high and
critical block), an SBOM per release; releases and images are not signed yet. STRIDE threat model: [security/THREAT-MODEL.md](security/THREAT-MODEL.md).

## 12. Certification path

| Framework | Applies to | What it means for us |
|---|---|---|
| **ISO/IEC 27001** | The vendor organisation (ISMS) | Needed to sell to regulated buyers; scope = development and, if any, the managed service. |
| **SOC 2** (Type I then II) | A managed service | Only if business model 3 is chosen; mostly asked by international buyers. |
| **UAE Information Assurance Regulation** v1.1 (TDRA, March 2020) ([TDRA PDF][uae-ia]) | The customer entities | The product helps customers meet its access-control and audit controls. We publish a control mapping, not a certificate. |
| **Dubai ISR** (DESC) | Dubai Government entities | Text released on request to DESC; obtain it before claiming any mapping. |
| **NIST SP 800-53** AC / AU families | Vocabulary for reviewers | Map features to AC-3, AC-4, AC-5, AC-6, AC-16, AC-24 and the audit controls. |


Formal verification, partial: a Lean 4 model of the decision core with mechanised proofs of its key properties and a
differential test of the TypeScript engine against it, in CI and in the release gate. Scope, theorems and what is not
covered: [spec/FORMAL-MODEL.md](spec/FORMAL-MODEL.md).

Who oversees UAE IA today (TDRA, the UAE Cybersecurity Council or both) is reported inconsistently in secondary
sources. It must be confirmed with the regulator before any customer-facing claim.

## 13. Repository layout for the MVP (deliverable 5)

```
packages/core        attribute model, built-in models, evaluation, obligations, explain
packages/policy      Cedar adapter (or plan B), schema, versions, fingerprints
packages/sql         relation and residual → Postgres predicate, RLS generator
packages/pdp-http    AuthZEN endpoints + filter / explain / simulate
examples/toy-domain  a demo domain with fixtures
```

## 14. What the MVP decided while building (2026-11-08)

As built (see the repository README for the layout actually shipped: `packages/core`, `packages/sql`,
`packages/pdp-http`, `packages/sdk`, `packages/gateway`, `apps/admin`; no separate `packages/policy`):

- **Policy language: plan B.** Tenant rules are a JSON condition AST evaluated by the core, so partial evaluation
  for SQL pushdown is ours. The Cedar spike of §3.4 has not been run; Cedar stays a possible adapter.
- **Three-valued logic.** A comparison over a missing or null value, or over operands of the wrong type (a number
  against a string, `in` over a non-array…), is UNKNOWN (SQL semantics); `eq`/`ne` stay defined across types. A `forbid` or an
  obligation fires on TRUE or UNKNOWN, a `permit` or an exemption needs TRUE, a list filter keeps a row only when
  its predicate is TRUE. Point decisions and SQL filters therefore agree; a property test checks it.
- **Indexed search, exact point decisions at release.** Resource search evaluates the residual as TRUE/FALSE position sets over
  cached type, label, relation-known-id and tenant-attribute indexes; UNKNOWN is in neither set, so boolean negation stays Kleene.
  Subject search traverses the relation once from the resource and prefilters the candidate's own mandatory/eligibility stages.
  Both preserve original-array cursor positions and point-check every survivor, including SoD, delegation and break-glass. Record
  patches invalidate the resource index. Randomized differential tests compare complete pages against per-candidate decisions.
- **Requests are validated inside the engine** before any rule (levels, integrity, booleans, instants, the content
  scan result): a malformed value denies (`ENGINE.MALFORMED_REQUEST`) instead of skipping a check.
- **Every action kind but `read` is a write** for BLP, Biba and Clark-Wilson (an approval writes its own record).
  Biba no-read-down coverage is policy data: the compatible per-action list by default, every read-kind action with
  `bibaNoReadDownScope: "reads"`, or every action with `"all"`. Point decisions and SQL residuals share the same
  applicability helper; effective-coverage narrowing is a governed weakening.
- **The session level caps reads and writes.** A subject working below its clearance sees only what that level allows.
- **What a session read bounds what it writes.** A PEP opens a session (`POST /x/v1/sessions`) and sends the PDP's
  Ed25519 token as `context.sessionToken`. `pep-sessions.ts` verifies the PDP-chosen sid, subject, credential, expiry,
  idle last use and open registry entry inside the decision's locks. The mark (`sessions.ts`, `gate_blp_mark`) is shared
  per (credential, subject), so fresh tokens and close/reopen cannot reset it; close revokes only the token. Production
  refuses raw `sessionId`. The pure core receives only server-derived `context.highWater` and denies a lower write.
- **Delegation is a chain.** An agent must carry the person it acts for; every link passes every stage, including
  ABAC with its content attributes (a mask stays unless every link is exempt).
- **Tenant policy cannot silently loosen the mandatory models.** `mandatoryWeakenings(before, after)` lists every
  loosening; such a publication needs an independent security officer as checker. Any edit to an existing relation
  definition counts, because relations are the reasons to know and narrowing cannot be judged generically. Protective
  rules count the same way (pentest KIMI-01): each ABAC forbid or obligation and each content-attribute deny, mask or redact must
  still be covered by a rule that provably fires wherever it fired and imposes at least as much; coverage is judged
  syntactically (same effect, same or wider scope, implied conditions and exemptions, superset of obligations) and
  anything not proven stronger counts as a weakening. Every removal or non-identical edit of a CBAC (context) rule is also a
  conservative weakening; adding one is not by itself. A property test checks that every random rule edit the
  evaluator shows losing a deny or an obligation is flagged.
- **Effective level is kept in the data.** §3.2 asks for max(resource, parents). The engine sees one resource and the
  SQL filter one row, so the store refuses any resource below its parent's level, at startup and on `update_resource`:
  `level` then is the effective level everywhere. Raising a folder means raising its children first.
- **Break-glass** is admitted on a trusted-network evaluation (the network condition still applies to each access),
  never past BLP or compartments, at most 4 hours, never for oneself, reviewed by someone other than the opener.

## 15. Built after 2026-11-08, and still design only (2026-11-10)

Built since §14 (contract in [API.md](API.md)):
- **Console sign-in through the organisation's IdP**: OIDC authorization code with PKCE, MFA evidence required,
  Secure cookies and HSTS behind TLS (API.md §3.1.1).
- **PostgreSQL control plane**: one active node holding an advisory lock, waiting standbys, fail-stop on a storage
  failure, state, decision-token ids and audit committed in one transaction (API.md §3.9.1). The security material
  (accounts and PEP credentials, the signing keyring sealed with `SIGNING_KEY_SEAL`, lockouts, SCIM credential, SIEM
  cursor) is in the same database and transaction, so a rotation or revocation holds on the next active node without
  copying files; a file deployment's `DATA_DIR` is imported once. In every profile (production included since
  0.5.0), takeover verifies the audit from the last checkpoint a full recheck stored (plus the anchored rows) and
  verifies the whole chain in the background: startup work follows the rows written since that recheck, not the log
  size. The checkpoint carries an HMAC under a key derived from `SIGNING_KEY_SEAL` (HKDF, own label), so a forged one
  stops the start; it also carries the audit counters, so the start aggregates nothing over the whole table. The
  trade-off is a window, the background verification (about 9 s per million rows on a laptop), during which a row
  rewritten before the checkpoint is not yet detected; `/readyz` (`audit.fullChain`) and the metric
  `gate_audit_full_chain_verified` show it, and a detection makes the node refuse every audited action and fail
  `/readyz` (docs/API.md 3.9.1).
- **Authenticated PostgreSQL transport**: `DATABASE_TLS=verify-full` is the production default and is required for a
  non-local host. Every runtime connection (writer, audit reader, rate limit, state sync and replica feed/ingestion),
  the role preflight, owner migration/retention and the libpq backup/restore tools use that one policy. A private CA
  and a client certificate/key are file settings, never URL parameters; URL `ssl*` parameters are refused. `require`
  encrypts without server authentication; `disable` is limited to non-production or loopback/unix-socket targets.
  Live tests start TLS-enabled PostgreSQL and prove CA and hostname verification (API.md §3.9.1).
- **External audit anchor**: RFC 3161 timestamps of the chain head (API.md §3.9.2).
- **Horizontal decisions (cluster mode, `GATE_CLUSTER=true`, API.md §3.9.1)**: every node serves the PDP API against
  the shared PostgreSQL; the admin plane keeps a single writer, the leader holding the advisory lock, and followers answer
  admin and SCIM requests by forwarding them to the leader (streamed, a signed single-use hop header, never twice), so
  there is still one writer, and `409 not_leader` only when they do not know the leader. Subjects, resources and tuples
  are individual PostgreSQL rows; the `state` document retains policy and workflow metadata. Followers apply the
  append-only `gate_state_change` log by a dense record generation, patch their in-memory indexes, and fall back to a
  full row snapshot if a generation is missing. Registration applies those deltas in place to arrays, id indexes and
  the tuple graph; level inheritance is checked only on changed resources and their direct children.
  New two-person proposals bind to `v2.<record generation>.<State metadata hash>` instead of rehashing the world;
  pre-v2 whole-world SHA-256 proposals retain exact legacy verification. `LISTEN/NOTIFY` plus the polled document version and record generation
  preserves the staleness bound: a node refuses decisions (503) once it has not confirmed shared state within
  `GATE_MAX_STALENESS_MS` (2 s). Each node writes its own hash chain (node id in every hashed record, per-node `seq`) in the same
  transaction as its decision's state changes; verification, the checkpoint, anchors (the set of chain heads), the audit
  API, the SIEM cursor and the counters are per chain. Decision tokens are table rows consumed under a row lock, so
  single use holds across nodes; performed actions are a shared, commit-ordered table. General and PEP rate limits lease
  small batches from shared `gate_rate_limit` token buckets rather than dividing by an uncertain live-node count: one
  atomic statement per lease, no statement per request while it lasts, and no overspend. Idle leases can only under-admit,
  bounded by N(B−1) tokens per key for lease size B; database time controls refill. File and active/standby modes keep
  their original local buckets. A leader that stops is replaced by the first follower that takes the lock, while the
  followers keep deciding. Measured scaling: PERFORMANCE.md.
- **Consistency across nodes (what a node's cache may and may not decide).** Policy, subjects and resources: a node
  decides on its cached copy, at most `GATE_MAX_STALENESS_MS` old (refused after). Separation of duty is not left to
  the cache: a token consumption takes a per-resource transaction advisory lock and reloads the performed actions
  committed since the last synchronisation before it decides again, so conflicting actions on one resource consume in
  one order across the cluster (two round trips per consumption; same-resource consumptions serialised; measured with
  `scripts/bench/consume.ts`). Evaluations still read the cache, but they only issue tokens: the consumption is the
  check that reserves. Mark-relevant decisions of one BLP subject scope are linearizable: an in-process queue covers
  the token sid and shared subject scope, and PostgreSQL adds their transaction advisory locks before validating
  `gate_blp_session` and loading `gate_blp_mark` on the same connection. Open/cap checks, close and administrative
  revocation take the same locks.
  The lock releases only after the decision's mark and audit commit. A lower write serialized after a read therefore
  always sees its mark, on one node or across nodes; unrelated subjects proceed independently, while no-session
  requests and L0 reads bypass this machinery (API.md §2). Decision-token consumption joins the ordering through `sid`.
- **Stateless decision replicas (`GATE_REPLICA_OF`, API.md §3.9.5).** The assessors' scale finding: every deciding
  node held a PostgreSQL connection, and every decision's durable audit was a database commit. A replica holds neither.
  *Topology:* PEPs → replicas (no database) → the database nodes (leader, followers or an active node, any of them) →
  PostgreSQL. A replica bootstraps from a snapshot that a database node reads in one repeatable-read snapshot and signs
  with its decision-token keyring, then long-polls signed deltas of the same `gate_state_change` generations followers
  apply (a commit on that node wakes the held request; an idle feed answers every quarter of the staleness bound, which
  is the replica's heartbeat). It applies them exactly as a follower reloads (documents, then record deltas patched in
  place, the bundle signature checked). *Trust:* each replica has its own key (`GATE_REPLICA_KEY`, listed on the
  database nodes): its requests carry an HMAC hop under a key derived from it; answers are signed over the body digest,
  bound to the replica and to the request's nonce, so a replayed, swapped or tampered answer is refused, and generations
  never go back (the floor survives restarts in an HMAC'd file). The first keys are pinned (`GATE_REPLICA_PIN`) or taken
  from the JWKS over verified TLS; rotations are followed only through the introduction the old key signs. Transport is
  HTTPS outside loopback; the replica never holds a private signing key, a console account or a per-subject audit key.
  *What it decides:* evaluations, resource search, explain and filter whose actions have no separation of duty, no
  decision token and no session mark; the rest is forwarded with the hop (the database node audits it), so shared,
  fast-moving state (performed history, BLP marks, token rows) is never decided on a copy; a forwarded session request
  takes the database node's per-session lock like a direct one. A replica's rate limits are process-local (no shared
  lease without a database), set to its share; forwarded requests are charged again on the shared buckets. *Audit:* a local file chain
  per replica (its id in every row, a MAC per row, an fdatasync before each answer in groups, a keyed checkpoint off
  the answer path), shipped asynchronously; the database checks continuity (MACs, links, base = stored head) and appends
  it as that replica's chain, from then on verified, checkpointed and anchored with all chains. Gap, fork, tampering and
  a replica behind its stored chain are refused and alerted. *Failure modes:* database nodes unreachable: the replica
  decides for at most the staleness bound, then 503 (`/readyz` 503); its forwarded requests fail at once (503). Audit
  shipping blocked: decisions stop once a durable row waits longer than `GATE_REPLICA_AUDIT_LAG_MS` (10 s), which bounds
  what a lost replica disk can lose; a replica that lost its disk is refused at start and takes a new id. A failed
  fdatasync latches and exits. The database remains the single place where all audit rows meet, so its write capacity
  bounds the total audit volume (measured in PERFORMANCE.md); replicas still hold the whole world in memory.
- **Access matrix** and **bounded affected-set impact** (`IMPACT_MAX_EVALUATIONS`), with impact evaluated on the same
  performed-action history, certifications and server-known maker as real decisions. The admin plane diffs decision
  inputs instead of simulating the whole grid: subject/resource edits select those rows, rule edits select their action,
  type and content scope, and tuple edits follow direct, userset, parent, computed and reporting-line dependencies before
  an exact relation check. Mandatory-model and relation-rewrite edits legitimately widen to their protected types.
  Both networks and the maker/history variants still run on the selected cells; the budget applies after those variants.
  CBAC signals are partitioned from boundaries in both bundles (countries, CIDR interval membership classes, zoned time
  edges, authentication ages, risk, device posture, methods, missing values and session expiry), with per-class diffs.
  ABAC and content-rule expressions contribute equality and in-list literals, numeric thresholds and instant/age
  boundaries. One-signal variants precede the cross-product, capped at 32 per network and marked `truncated` when capped.
  Unsupported comparisons set `incomplete` with an `unsupported` explanation; either kind of incomplete analysis requires
  security-officer approval. The preview's broadening result and approval-time comparison consume this identical analysis.
  `analysis.affectedCells` and `analysis.reasons` report the selection. Differential tests compare the deltas with the
  full grid. Impact compares obligations as well as allow/deny (pentest KIMI-02): a cell that stays allowed but loses a
  redaction, mask, field restriction, notification or decision token is a broadening and is listed with what it loses.
- **Signed policy publications**: version ids are SHA-256 over the canonical bundle; each published bundle is signed
  (Ed25519, decision-token keyring, `kid`) and a node refuses to start on a bundle whose signature does not verify
  (API.md §3.10, policy bundle signature). The PDP still reads its bundle from its own store, not from a distributed
  signed artifact.
- **Resource-owner scope from the principal**: an owner's console scope is the resources owned by its authenticated
  id or the ids `RESOURCE_OWNERS` maps to it (API.md §1).
- **XACML 3.0 interoperability** (API.md §2.1): `POST /xacml/v3/authorize` speaks the OASIS JSON Profile of XACML 3.0
  v1.1. It is a translation layer only: each individual request becomes an AuthZEN evaluation, so the engine, decision
  tokens, PEP authentication, rate limits and audit rows are the ones of §4. Qadamar denies map to `Deny` (an undeclared
  action to `NotApplicable`), malformed input to `Indeterminate` with an XACML status code (audited as a deny with the
  reason), obligations to `urn:qadamar:1.0:obligation:*`; a permit with an obligation the mapping cannot express
  is recorded as a deny, issues no decision token and answers `Indeterminate`. Combined decisions, XPath content and XML are not supported.
- **Distributed tracing** (API.md §2.0.1): with `OTEL_EXPORTER_OTLP_ENDPOINT`, a request span per HTTP request and child
  spans per decision and database commit, exported as OTLP/HTTP JSON by a bounded, batched in-process exporter with
  backoff (no OpenTelemetry SDK, no dependency). The request context travels in `AsyncLocalStorage`; the exporter is
  never awaited by a request. W3C `traceparent` is honoured on the way in. Span attributes are limited to HTTP
  method, route family, status, effect and rule ids, so a trace store never holds who accessed what.

Still design only, not in the code: splitting a single tenant’s graph across PDPs (each served tenant remains
fully resident; whole-tenant partitions are implemented in §7), and the maximum bundle age of §9 beyond the staleness bound (a replica refuses decisions on state older than
`GATE_MAX_STALENESS_MS`; cluster nodes read the same database); the decision cache of §8; Cedar; SDKs for languages
other than TypeScript, and in-process (Wasm) evaluation in the SDK (the TypeScript SDK calls the PDP over HTTP); a gRPC
API; relations read from SQL sources and pushed down as an SQL `EXISTS` (§3.3: relations come from the tuple store, and
the filter passes the subject's known ids as one array parameter, `= ANY`); the generated RLS backstop, the AI / RAG
filter, the redaction service and the file re-check of §5. Quality and accessibility
evidence: [QUALITY.md](QUALITY.md), [ACCESSIBILITY.md](ACCESSIBILITY.md).

## 16. Clark-Wilson: what is enforced (2026-11-10)

**PDP-to-backend proof (2026-11-10, second round).** The gateway forwards each request with a short-lived (30 s) Ed25519
JWS binding subject, action, resource, decision id, policy version, the backend origin, method, path with query, a
SHA-256 of the forwarded body and a nonce (API.md §2.0.2). Design choice: the **PDP signs**, through
`/x/v1/assertions/*`, with its existing keyring (sealed, rotated, published in its JWKS), rather than the gateway with
a key of its own. The private key therefore never sits in the internet-facing process, a deny yields no assertion
(the PDP signs only what it allowed, on the same audited decision), and backends trust one key set, the one decision
tokens already use; a distinct `typ` stops either kind of JWS from passing as the other. The cost is no extra round
trip (the assertion comes with the decision) but a PDP dependency the gateway already had. The backend verifies with
the SDK (`AssertionVerifier`, plain `node:http` middleware `withGateAssertion`): JWKS cache with rotation, clock skew,
a nonce replay cache for the assertion's life, exact binding. The replay cache is per backend process unless the
backend passes a shared `replayStore` (an atomic check-and-set, e.g. Redis `SET NX PX`; required with several
replicas, docs/API.md §2.0.2). Limit: the PDP signs the method, path and body digest the PEP reports, so the proof is "decided and sent by a credentialed
PEP", not "a compromised PEP forwarded what it described".

Constrained data items (CDI) are resource types marked `constrained`; transformation procedures (TP) are actions marked
`certified`. Built in this round: integrity verification procedures (IVP) as declared, resource-only predicates in the
bundle (`clarkWilson.ivps`, checked by `validateBundle`), and two-person certification records of TPs. With no IVP
declared, every decision is unchanged (existing tests, plus a differential test over every toy subject × resource ×
action × network × maker variant).

| Rule | Status | How |
|---|---|---|
| **C1** IVPs confirm CDIs are valid | **Enforced** | Every IVP of the type must be TRUE (missing values fail) before a certified command is allowed (`CW.IVP.<id>`), again on the stored state when its token is consumed, and over every CDI by `POST /admin/v1/integrity/verify` (audited). The list filter carries the same predicate. |
| **C2** TPs certified to take a CDI to a valid state | **Enforced where declared** | The `certified` flag (published by two people) and a certification record (`certify_tp`: who, checker, when, policy version, and a fingerprint of everything in the bundle that decides that procedure). For types listed in `clarkWilson.requireCertification`, a certified action without a record is denied (`CW.NOT_CERTIFIED`; the records come from the server, never the caller), and one whose procedure changed since it was certified is denied until recertified (`CW.CERTIFICATION_STALE`; a policy proposal lists the records it would make stale). On a type with IVPs the token consumption must carry the state the command will commit (`attrs`; the gateway sends the request body on `postState: 'body'` routes): without it the consumption is refused (`CW.POST_STATE_REQUIRED`), and a failing check refuses it too, audited, token kept. The PDP cannot prove a procedure's code correct. |
| **C3** Separation of duty in who may run which TP | **Enforced** for declared rules | Conflicting-action rules, two-person rule, history derived by the server from consumed tokens. |
| **C4** TPs write to an append-only log | **Enforced** for the authorization event | Every decision, consumption, outcome report and refusal is in the hash-chained, anchored audit; reservations and their outcomes are persisted. The application's own data changes are its log, not ours. |
| **C5** TPs taking unconstrained input (UDI) are certified to validate it | **Enforced where declared** | `clarkWilson.inputValidators`: closed, declarative field schemas (type, required, enum, min, max, maxLength; no regular expressions) per certified action, part of the two-person-published bundle. The input is `context.input` at decision (`CW.INPUT_REQUIRED`, `CW.INPUT.<id>`) and the post-state `attrs` at token consumption, refused and audited with the token kept; the list filter agrees. The gateway hands the request body over as both on `postState: 'body'` routes. Not covered: input a backend takes outside the body the PEP sees, and validators richer than the schema (the PDP still cannot prove a procedure's own parsing correct). |
| **E1** Only certified TPs change CDIs | **Enforced at the PDP and the gateway; verifiable by the backend** | `CW.UNCERTIFIED_TP`; single-use Ed25519 tokens bound to action, item, version and policy; the gateway consumes the token before forwarding. A backend that verifies the decision assertion (above) refuses a request that did not come through a PEP with an allow for exactly that request; one that does not verify it, or a direct database write, is not stopped (the database backstop is design only). |
| **E2** Users run only the TPs listed for them, on listed CDIs | **Enforced** | RBAC / ABAC per (subject, action, type), need-to-know, mandatory models, for every link of a delegation chain. |
| **E3** Users who run TPs are authenticated | **Enforced where declared** (for the PEP path) | Each PEP credential can be bound at creation to the subject populations (`subjectTypes`) whose users that PEP authenticates (the gateway's `authenticate` hook, an IdP session). For constrained types in `clarkWilson.requirePepBinding`, a certified command is decided (and its token consumed) only when the subject's type is in the asking credential's binding, from the server's credential store, never from the request: otherwise `CW.SUBJECT_NOT_AUTHENTICATED`. An unbound or bootstrap credential cannot run them. Remaining trust: within its population, the PDP still believes which user the PEP names; it does not verify the end user's own token. |
| **E4** Only the certifier changes certifications, and may not run them | **Enforced** | `certify_tp` is proposed by a security officer only and approved by another person. Each must be a PDP subject with the same id (none: refused, fail closed), and the engine itself decides whether that subject could run the TP: a granting role, or a permit on any item of the type (roles through delegation, ABAC permits and relations count; denials caused only by the item's state, input or history do not clear the certifier). At run time the certifier and its checker are denied that TP (`CW.CERTIFIER_EXECUTES`, every link of a delegation chain, list filter included), so a role granted later changes nothing. Decertification is a bundle publication (flagged as a weakening). Only E4's console users and PDP subjects are matched by id: a person with two ids is two people. |

[cedar]: https://docs.cedarpolicy.com/
[cedar-spec]: https://github.com/cedar-policy/cedar-spec
[cedar-tpe]: https://docs.rs/crate/cedar-policy/4.11.1/source/src/lib.rs
[avp]: https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/what-is-avp.html
[opa]: https://www.openpolicyagent.org/docs
[opa-filter]: https://www.openpolicyagent.org/docs/filtering
[opa-wasm]: https://www.openpolicyagent.org/docs/wasm
[cerbos-cel]: https://docs.cerbos.dev/cerbos/latest/policies/conditions
[authzen]: https://openid.net/specs/authorization-api-1_0.html
[uae-ia]: https://government.ae/-/media/guidelines/Guidelines-2020/UAE-IA-Regulation-v11-1.pdf

### SAML logout and backend integration safety

`packages/pdp-http/src/saml.ts` delegates decryption and signature verification to the pinned node-saml dependency.
Encrypted assertions pass Qadamar's algorithm checks before and after decryption and every existing assertion check.
Mounted SP key/certificate pairs are validated at startup; metadata publishes certificates only. SLO accepts signed
POST XML or the original signed Redirect query, with separate pending logout correlation and bounded replay caches.
SP logout ends sessions before navigating to the IdP. Deleting the stored console session revokes its cookie and
CSRF authority; business PEP credentials and BLP sessions have their separate lifecycles. The admin leader owns
in-flight SAML state; a restart cancels pending logout responses as well as logins.

The SDK ReplayStore contract is unchanged. `examples/integration-safety/postgres-replay.ts` demonstrates a shared
atomic PostgreSQL nonce store using the existing driver, audience namespaces and expiry cleanup; database failures
remain closed. `filtered-backend.ts` uses generated parameterised SQL for candidates, then evaluates each row with
its authoritative maker/history and applies SDK obligations before returning data. The residual omits obligations
and per-row SoD/two-person history; passing SQL alone is never authority to execute a command. Certified commands
still need decision-token consumption and a transaction protecting the command and history. See the
[handbook walkthrough](handbook/guides/integration-safety.md).
