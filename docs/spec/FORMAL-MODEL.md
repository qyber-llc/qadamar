# Formal model of the decision core (Lean 4)

Status: **partial**. A Lean 4 model of `evaluate` (packages/core) with mechanised proofs of its key properties, and a
differential test that runs the TypeScript engine and the executable model on the same random inputs. The approach is
the one AWS uses for Cedar, "verification-guided development" ([arXiv:2407.01688](https://arxiv.org/abs/2407.01688)):
the proofs are about the model; the test ties the model to the code. Nothing here is a proof about the TypeScript.

## 1. Layout and how to run

| Path | What |
|---|---|
| `formal/lean-toolchain` | The pinned toolchain: `leanprover/lean4:v4.35.0`. Core Lean only: no Mathlib, no package. |
| `formal/Qadamar/Value.lean` | JSON values, exact numbers, structural equality, code-point string order, UTF-16 lengths |
| `formal/Qadamar/Cond.lean` | Condition language, three-valued `evalTri`, `evalExpr` (TRUE), `mayHold` (TRUE or UNKNOWN) |
| `formal/Qadamar/Request.lean` | Request validation (`requestErrors`) as a parser to a typed request |
| `formal/Qadamar/Policy.lean` | The bundle, well typed |
| `formal/Qadamar/Eval.lean` | The pipeline: every stage, the merge of obligations, the decision |
| `formal/Qadamar/Theorems.lean` | The theorems of §3 |
| `formal/Qadamar/Json.lean`, `formal/Main.lean` | The `gate-model` executable: JSON lines in, decisions out |
| `formal/check.sh` | `lake build`, then fails on any `sorry` and on any axiom beyond `propext`, `Classical.choice`, `Quot.sound` (`CheckAxioms.lean`) |
| `packages/core/test/lean-differential.test.ts` | The differential test (§4) |

```sh
bash tools/ci/install-lean.sh            # elan 4.2.4 and the formal/lean-toolchain release, each pinned by SHA-256
bash formal/check.sh                     # build the model, check the proofs, build gate-model
LEAN_REQUIRED=1 LEAN_DIFF_RUNS=10000 node --test packages/core/test/lean-differential.test.ts
```

The test finds `lake` on `PATH`, in `~/.elan/bin` or in `$LAKE`; without one it skips, unless `LEAN_REQUIRED=1`.
`LEAN_DIFF_SEED` replays a seed. `tools/ci/checks.sh` (and so `tools/ci/local.sh`) does not need Lean and stays
offline: the test skips there when no toolchain is found, and runs (2,000 cases) wherever one is installed. CI (`ci.yml`) and the release gate (`release.yml`) install
the pinned toolchain and run `formal/check.sh` and the test with `LEAN_REQUIRED=1` and 10,000 cases.

## 2. What is modelled

The decision of `evaluate(bundle, request, graph)`: `decision`, `rules` (the denying rule ids, or the allow basis),
`obligations` and `wouldDeny`, in the TypeScript order.

- **Values and conditions** (conditions.ts): JSON values, `resolvePath` (own properties, array indices and `length`,
  JSON null is MISSING), every operator with the 0.7.0 rule (a mistyped operand is UNKNOWN; `eq`/`ne` structural
  across types) and the 0.8.2 rule (strings in Unicode code-point order), Kleene `and`/`or`/`not`, `has`, `true`,
  `unknown`.
- **Validation** (request.ts): every check of `requestErrors`, the delegation chain bound (`MAX_DELEGATION_DEPTH`),
  identifier lengths in UTF-16 code units; the shape of the CBAC signals (`ip`, `country`, `device`, `authTime`,
  `mfaTime`, `authMethods`, `riskScore` 0..100, `sessionExpired`) and of `roleAssignments`. Their grammar is abstracted
  (below).
- **Live roles** (CBAC grant duration): every principal of the chain is evaluated with its unconditional roles plus the
  role assignments live at `context.now` (`withLiveRoles`, first occurrences kept), in RBAC, in the ABAC conditions
  (`subject.roles`, also through `subject.delegator`) and in the trusted-role exemption. An assignment outside its
  window counts for nothing.
- **Pipeline** (evaluate.ts): malformed request, undeclared action, inactive principal; then, for each principal of the
  chain with the `DELEGATION.` prefix: RBAC with role inheritance (cycle-safe, sorted as `Array.prototype.sort`) and
  ABAC permits; mandatory controls (mandatory.ts: BLP no-read-up with session level and high-water mark, no-write-down,
  `BLP.HIGH_WATER`, `BLP.SESSION_REQUIRED`, compartments, the untrusted-network level cap and compartments, Biba
  no-write-up and no-read-down, trusted roles). `BibaNoReadDownScope` mirrors the TS option: `actions` (the JSON
  default) checks `bibaNoReadDownActions`, `reads` checks the action kind and `all` checks every action; the theorems
  `biba_no_read_down`, `biba_no_read_down_reads` and `biba_no_read_down_all` prove the resulting denial. Need-to-know
  (off, dry run, enforce, break-glass notify); ABAC forbids
  and obligations (fire on TRUE or UNKNOWN); ABAC on content attributes (`abacContent`, legacy `cbac` read after it):
  deny, mask, redact with `unless`, codes `ABAC.CONTENT_DENY` and the mask / redact obligations; then once for the
  request CBAC, context-based (context.ts): `CBAC.SESSION_EXPIRED` for a known-expired session, then every rule whose
  selector (resource types, actions, action kinds), minimum level and content classes match, each requirement in
  `contextChecks` order (network, countries, IP ranges, time windows, device managed and compliant, MFA age,
  authentication age, methods, risk): TRUE passes, an absent signal is `CBAC.SIGNAL_MISSING`, a present one that fails
  its own code; then Clark-Wilson (uncertified
  transformation, decision token with `postState`, input validators, PEP binding, certifier-executes, certification
  required, IVPs) and separation of duty (maker mismatch, maker unknown, self-approval, conflicting prior actions).
- **Decision**: any deny wins, `[...new Set()]` of rules, obligations merged as `mergeObligations` (allowlists
  intersect, the rest unions, last decision token), none on deny.

**Abstracted** (an `Oracle` input; every theorem holds for every oracle, the differential test computes it with the
TypeScript):

- the ReBAC relation check of need-to-know (`check` in relations.ts: tuples, rewrites, break-glass validity, and the
  tuple grant windows `notBefore` / `notAfter`, legacy `validFrom` / `validTo`);
- whether a certification record carries the current `procedureFingerprint` (a SHA-256 of the bundle);
- **time arithmetic**: whether `context.now` lies in a role assignment's [notBefore, notAfter] window (`roleLive`), and
  the outcome of the CBAC requirements that need instants, CIDR membership or IANA time zones (`ipRanges`,
  `timeWindows`, `mfaMaxAgeSeconds`, `authMaxAgeSeconds`; `ctxOk`) **when their signal is present**. Whether the signal
  is present is decided by the model, so an absent one denies whatever the oracle says. The model proves nothing about
  CIDR matching, local-time windows, DST or ages: the differential test compares them on sampled inputs only;
- the grammar of the signals and of the assignment instants (IP literal without zone id, ISO country, ISO-8601
  instants, method names, assignment keys and order; `signalsValid`): when the oracle says it fails, the request is
  malformed.

**Assumptions of the model**, kept by the test generator:

- A bundle is well typed (effects and kinds from their closed sets, fields of their declared types). The TypeScript
  denies with `ENGINE.RULE_ERROR` on a rule it cannot run; the model's reader rejects such a bundle instead.
- Strings are Unicode scalar values. The test maps a lone surrogate to a distinct private-use character before
  either engine sees the request.
- Numbers are exact decimals. They agree with JavaScript doubles on what `JSON.stringify` prints (shortest
  round-trip form). Both engines refuse a request carrying, anywhere in its subject, resource or context, a number
  whose double lies beyond ±(2^53 - 1) (`ENGINE.MALFORMED_REQUEST`); numbers in the bundle beyond double precision
  remain outside the model.
- `context.now` is valid iff `validInstant` accepts it, in both engines: `YYYY-MM-DDTHH:mm:ss`, an optional fraction
  of 1 to 9 digits, then `Z` or `±hh:mm`, on a real calendar day (years 0-99 are refused, as `Date.UTC` reads them
  as 1900-1999). A zone-less instant is malformed, so no decision depends on the host's time zone.

## 3. Theorems (formal/Qadamar/Theorems.lean)

All are proved without `sorry`, over every bundle, request and oracle; `CheckAxioms.lean` lists their axioms.

| Property | Lean name | In plain words |
|---|---|---|
| Determinism | `deterministic` | Equal bundle, request and relation outcomes give equal decisions. |
| Malformed requests deny | `malformed_denies`, `malformed_decision` | A request that fails validation is denied with exactly `ENGINE.MALFORMED_REQUEST`. |
| Undeclared actions deny | `undeclared_action_denies` | An action the schema does not declare is denied (`SCHEMA.UNKNOWN_ACTION`). |
| Deny wins | `deny_wins`, `stage_denies` | Any denial of any stage, for any principal of the chain, denies, whatever grants and permits also hold. |
| Forbids win | `forbid_denies`, `forbid_denies_whatever_permits` | An applicable forbid whose condition is TRUE or UNKNOWN denies, and still does after adding any permits and replacing every role. |
| Content denies | `abac_content_deny_denies` | An ABAC content-attribute deny applies unless its exemption is TRUE; FALSE or UNKNOWN does not lift it. |
| CBAC: deny wins | `cbac_deny_denies`, `context_stage_denies` | A matched context rule with a requirement that is not TRUE denies, whatever roles, grants and permits hold. |
| CBAC: missing signal denies | `cbac_missing_signal_denies`, `missing_signal_reported` | A matched context rule whose required signal (country, IP, device, MFA or authentication time, methods, risk) is absent reports `CBAC.SIGNAL_MISSING` and denies, for every oracle. |
| CBAC: expired session | `session_expired_denies`, `malformed_signals_deny` | A session known to be expired is refused; ill-formed signals make the request malformed. |
| Grant duration | `expired_grant_not_eligible`, `live_assignment_is_a_role`, `live_chain_roles` | A role assignment outside its window leaves the live roles, the RBAC grant and the trusted-role exemption as if it were absent; a live one is a role; the pipeline decides each principal with its live roles. |
| Unknown forbids deny | `unknown_forbid_denies` | A forbid whose condition is UNKNOWN (missing or mistyped attribute) denies. |
| Unknown permits do not grant | `grantingPermit_sound`, `unknown_permit_does_not_grant`, `no_true_permit_denies` | Only a permit whose condition is TRUE grants; without a role grant, a principal whose permits are FALSE or UNKNOWN is denied. |
| Mandatory before tenant policy | `mandatory_denies`, `mandatory_before_tenant_policy` | A mandatory finding for any principal (with its live roles) denies, for every bundle with the same mandatory section and action kind (any roles, grants, permits, forbids, content and context rules, need-to-know) and every relation outcome. |
| Tenant roles cannot weaken MAC | `mandatory_untrusted_roles_irrelevant` | Adding roles that are not trusted roles changes no mandatory finding. |
| The mandatory rules | `no_read_up`, `no_write_down`, `high_water`, `compartment_required`, `network_cap`, `biba_no_write_up`, `biba_no_read_down`, `sessionOf_le_clearance` | Each condition produces its finding; an untrusted write below the session's high-water mark is denied whatever session level is asked; the working level never exceeds the clearance. |
| Obligations only on allow | `obligations_only_on_allow` | A denied decision carries no obligations. |

## 4. Differential test

`packages/core/test/lean-differential.test.ts` draws random bundles over the toy schema (roles with random grants
and cyclic or dangling inheritance, random mandatory parameters, need-to-know modes, random ABAC rules with random
conditions over present, missing and mistyped paths, content-attribute rules (under `abacContent`, one bundle in five
under the legacy `cbac`), CBAC context rules (every selector and requirement, overnight windows in three time zones),
separation-of-duty rules, IVPs, required
certification, input validators, PEP binding, flipped constrained / certified / two-person flags) and random requests
from the fuzz generators of `fuzz-gen.ts` (shared with `fuzz.test.ts`: context signals, role assignments with windows
around the clock and on its edges), with the context fields those do not draw, malformed requests and ill-formed
signals, instant formats, and half of them steered towards the allow path. For each case it asks
`evaluate` and `gate-model` and asserts the same `decision`, `rules`, `obligations` and `wouldDeny`.

Run before the CBAC extension was committed (2026-11-11): 100,000 cases over seeds 101, 202, 303 and 404, and 30,000
each over three random seeds: no disagreement. The test was checked to catch a changed model: making forbids fire on
TRUE only, comparing strings in UTF-16 order instead of code points, ignoring live role assignments, and reporting an
absent signal under the requirement's own code all fail it.

## 5. What is not covered

- The relation graph (relations.ts), the certification fingerprint, time-window, CIDR and age arithmetic, and the
  signal grammar: abstracted, see §2.
- The trace steps of grant windows (`CBAC.GRANT_EXPIRED`, `CBAC.GRANT_NOT_YET`, outcome `skip`): informational, part of
  the trace.
- The trace (`trace`), the reasons (`reasons`) and the policy version (`policyVersion`) of a decision.
- Bundle validation (`validateBundle`), weakening reports, simulation, the Cedar export.
- The list filter (filter.ts, packages/sql): its agreement with point decisions is tested by `fuzz.test.ts` and the
  live PostgreSQL tests, not modelled.
- Everything around the engine: the HTTP PDP, authentication, audit, replication, the console, the PEPs.
- No proof that the TypeScript implements the model: the differential test samples, it does not prove.

The model is a specification of the current behaviour. When `evaluate` changes, the model changes with it, in the
same commit, and the differential test says when they part.
