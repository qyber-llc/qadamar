# Qadamar policy language, version 1.0

Status: normative. Language version **1.0** describes the behaviour of `packages/core` at release 0.7.0. The key words
MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Where this text and the code disagree, the code
(`packages/core/src`) is the reference for 1.0 and the disagreement is a defect of this document.

Machine-readable companion: [`policy-bundle.schema.json`](policy-bundle.schema.json) (JSON Schema 2020-12), checked against
`validateBundle` by `packages/core/test/spec.test.ts`. Interoperability: [appendix A](#appendix-a-cedar-export) (Cedar export).

## 1. Scope and conformance

A **policy bundle** is one JSON document holding everything a tenant can configure: the resource schema, roles,
the parameters of the built-in mandatory models, need-to-know, attribute rules (ABAC), ABAC on content attributes (`abacContent`),
CBAC rules (context-based, Zero Trust, `context`), separation of duty (SoD) and Clark-Wilson integrity. A **decision** is a pure function of (bundle, request, relation
graph) (`evaluate()` in `packages/core/src/evaluate.ts`).

- A **conforming bundle** satisfies the JSON Schema (§9.1) and every semantic rule of §9.2.
- A **conforming evaluator** accepts exactly the conforming bundles and decides every request as §6 to §8 say.
- What a tenant cannot configure (the mandatory models, the evaluation order, fail-closed handling) is part of the
  language: a bundle cannot switch it off.

## 2. Bundle document

A bundle is a JSON object. Unknown top-level keys are an error (`validateBundle`, `BUNDLE_KEYS`). The fixed-shape
objects in §3 are closed too: unknown keys are an error in both the schema and `validateBundle`. Bundles submitted
through the admin API are limited to 1 MiB of JSON (`packages/pdp-http/src/http.ts`, `readRawBody`).

| Key | Required | Section | Type in `packages/core/src/types.ts` |
|---|---|---|---|
| `name` | yes | non-empty string, a label | `PolicyBundle.name` |
| `schema` | yes | §3.1 | `PolicyBundle.schema` |
| `rbac` | yes | §3.2 | `PolicyBundle.rbac` |
| `mandatory` | yes | §3.3 | `PolicyBundle.mandatory` |
| `needToKnow` | yes | §3.4 | `PolicyBundle.needToKnow` |
| `abac` | yes (see §9.3) | §3.5 | `AbacRule[]` |
| `abacContent` | no (absent = no content rules) | §3.6 | `AbacContentRule[]` |
| `cbac` | deprecated: legacy name of `abacContent`, read for one version (§10) | §3.6 | `AbacContentRule[]` |
| `context` | no (absent = no CBAC rules) | §3.7 | `ContextRule[]` |
| `sod` | yes (see §9.3) | §3.8 | `SodRule[]` |
| `clarkWilson` | yes | §3.9 | `PolicyBundle.clarkWilson` |

## 3. Sections

### 3.1 `schema`

- `resourceTypes`: object, type name → `{ actions, relations?, constrained?, governedAttributes? }`.
  - `actions`: non-empty object, action name → `{ kind, certified?, requiresSecondPerson? }`. `kind` is one of
    `read`, `write`, `delete`, `approve`, `execute`; every kind but `read` is a write for the mandatory models
    (`isWrite`, `mandatory.ts`). An action name is local to its type: `read` on `case` and `read` on `folder` are two
    actions. An action that is not declared for the resource's type is denied (`SCHEMA.UNKNOWN_ACTION`); only own
    properties count (an action named `constructor` is not declared).
  - `certified: true` makes the action a Clark-Wilson transformation procedure; `requiresSecondPerson: true` applies
    the two-person rule (§6, stage 10).
  - `relations`: relation name → `{ union: [rewrite, ...] }` with at least one rewrite: `{ "this": true }` (a direct or
    userset tuple), `{ "computed": r }` (another relation of the same object), `{ "fromParent": { "relation": p,
    "then": r } }` (relation `r` on the object reached through `p`), `{ "viaReports": { "managerRelation": m, "then":
    r, "maxDepth": 1..50 } }` (relation `r` held by someone the subject manages, up to `maxDepth` levels). Evaluation:
    `relations.ts` (`check`), at most 32 hops, cycles cut, tuples live only inside `validFrom`/`validTo`, break-glass
    tuples only when their window is at most `needToKnow.breakGlassMaxHours`.
  - `constrained: true` makes items of the type Clark-Wilson constrained data items.
  - `governedAttributes`: attribute names (`^[A-Za-z0-9_-]{1,64}$`) whose change through PEP resource registration
    needs a second person (enforced by `packages/pdp-http`, not by the decision).
- `subjectRelations`: subject type → relations, same form (for example `user#manager`, `team#member`).
- `compartments`: list of compartment names.

### 3.2 `rbac`

`roles`: role name → `{ inherits?: [role], grants: [{ resourceType, actions }] }`. A subject's roles are closed under
`inherits` (`expandRoles`); roles a subject carries but the bundle does not declare grant nothing. A grant matches when
`resourceType` equals the resource's type or is `"*"`, and `actions` contains the action or `"*"` (`rbacGrant`).

### 3.3 `mandatory`

Parameters of the built-in models (`mandatory.ts`), never the models themselves:
`trustedRoles` (roles exempt from the *-property: may write below their session level), `untrustedNetworkMaxLevel`
(0..3), `compartmentsRequireTrustedNetwork` (boolean), `bibaNoReadDownActions` (actions that must not consume
lower-integrity data), and optional `bibaNoReadDownScope`. The scope is `actions` when absent, preserving the list's
existing behavior; `reads` instead applies no-read-down to every action whose declared `kind` is `read`, and `all`
applies it to every action. In `reads` or `all` scope the list does not extend or limit that coverage. Narrowing the
effective coverage in either direction (for example `all` → `reads`, or `reads` → a list without a previously covered
read) is a mandatory weakening. Levels are integers 0..3; integrity ranks `derived` < `extracted` < `system` < `verified`.

### 3.4 `needToKnow`

`mode` (`off` | `dry_run` | `enforce`), `protect` (type → `{ relation, minLevel? }`), `breakGlassMaxHours` (in (0, 24]),
`breakGlassNotify` (list). A protected resource at or above `minLevel` needs the subject to hold `relation` on it.
`dry_run` records `wouldDeny` and does not deny.

### 3.5 `abac`

`{ id, description, effect, resourceTypes?, actions?, when, obligations? }`. `effect` is `permit` (eligibility in
addition to roles; never past the mandatory models), `forbid` (deny) or `obligation` (adds `obligations`: `fieldAllowlist`,
`redact`, `maskClasses`, `notify`, lists of strings). An absent `resourceTypes` or `actions` matches every type or
action (`appliesTo`). `when` is a condition (§4). An ABAC rule's reason code is `ABAC.<id>`, so the id prefix `CONTENT_`
is reserved: it would read as a content-attribute code (`ABAC.CONTENT_DENY`, `ABAC.CONTENT_MASK`, `ABAC.CONTENT_REDACT`,
§3.6), and both the schema and `validateBundle` reject an `abac` rule id starting with it.

### 3.6 `abacContent` (ABAC on content attributes)

`{ id, description, contentClass, effect, fields?, actions?, unless? }`. The rule applies when the resource's
`contentClasses` contains `contentClass` and the action is in `actions` (or `actions` is absent). `effect`: `deny`,
`mask` (obligation: the class is masked) or `redact` (obligation: `fields` are removed; `fields` is then required and
non-empty). `unless` is a condition; the rule does not apply when it is TRUE. These rules run inside the `abac` stage
(§6); their trace steps carry `kind: "content"` and `policyRule: <rule id>`, and their codes are `ABAC.CONTENT_DENY`,
`ABAC.CONTENT_MASK` and `ABAC.CONTENT_REDACT` (the rule id is in `policyRule`, not in the code). Obligations
(`maskClasses`, `redact`) are unchanged.

**Compatibility (one version).** A bundle that still has the legacy field `cbac` (these content rules, previously
called CBAC) is accepted and read as `abacContent`; `validateBundle` returns the warning `DEPRECATED_CBAC_FIELD` in its
`warnings` array, and the PDP records it in the publish audit row and shows it in the console. A bundle with both
`cbac` and `abacContent` is rejected (`cbac and abacContent cannot both be present`). Bundles already stored in
PostgreSQL keep loading unchanged. The legacy field will be removed in a later version.

### 3.7 `context`

CBAC rules are **context-based, Zero Trust** controls, separate from content rules. A rule is
`{ id, description?, <selector>, <requirements> }`. A selector needs at least one of `resourceTypes`, `actions` or
`actionKinds`; `minResourceLevel` and `contentClasses` can additionally restrict it to sensitive resources (content
classes match on any overlap). At least one requirement is mandatory:

| Requirement | Request assertion and failure code |
|---|---|
| `network: "trusted"` | `context.network`; `CBAC.NETWORK` |
| `countries` | upper-case ISO 3166-1 alpha-2 allow list; `context.country`; `CBAC.COUNTRY` |
| `ipRanges` | IPv4/IPv6 CIDR allow list; `context.ip`; `CBAC.IP_RANGE` |
| `timeWindows` | `{ days, from, to, timeZone }`: ISO weekdays 1 Monday..7 Sunday, local HH:mm, IANA zone; `context.now`; `CBAC.TIME_WINDOW` |
| `device: { managed?, compliant? }` | boolean posture; `context.device`; `CBAC.DEVICE_UNMANAGED`, `CBAC.DEVICE_NONCOMPLIANT` |
| `mfaMaxAgeSeconds` | `context.mfaTime`; `CBAC.MFA_STALE` (a PEP can trigger step-up MFA) |
| `authMaxAgeSeconds` | `context.authTime`; `CBAC.AUTH_STALE` |
| `authMethodsAny` | at least one listed method in `context.authMethods`; `CBAC.AUTH_METHOD` |
| `maxRiskScore` | integer `context.riskScore` no greater than the limit; `CBAC.RISK` |

Every requirement of every matched rule must be TRUE. A required signal that is absent is UNKNOWN and denies with
`CBAC.SIGNAL_MISSING`; it never silently passes. Time windows include `from`, exclude `to`, support overnight windows
(the selected weekday is the starting day) and evaluate DST through the IANA zone. Equal `from` and `to` is invalid.
Authentication age is `now - assertedTime`: it must be non-negative and at most the limit, so exactly at the limit
passes and a future timestamp denies. Rule ids share the other rule lists' namespace. Removing or editing an existing
CBAC rule is conservatively treated as a weakening for governance; adding one is not, by itself, a weakening.

Limits: at most 1000 rules, 1..100 `ipRanges` and 1..100 `timeWindows` per rule, and at most 4096 ranges and 4096
windows across all rules of a bundle (every range and window of a matched rule is checked on each request). An IPv6
zone id (`%`) is refused in a range and in `context.ip`. The engine builds one address list per rule and one formatter
per time zone, not one per decision.

### 3.8 `sod`

`{ id, description, conflicting: [action, action, ...] }` (two or more). A subject whose delegation chain already
performed one of `conflicting` on the resource (`context.priorActions`) may not perform another.

### 3.9 `clarkWilson`

`tokenTtlSeconds` (in (0, 300]), and optionally: `ivps` (`{ id, description, resourceTypes, check }`: a condition over
`resource.*` paths only, on constrained types), `requireCertification` (constrained types whose certified actions need
a current certification record), `requirePepBinding` (constrained types whose certified actions need the PEP credential
bound to the subject's type), `inputValidators` (`{ id, description, resourceTypes, actions, fields }`, on certified
actions; each field `{ type: string|number|integer|boolean, required?, enum?, min?, max?, maxLength? }`, closed: an
undeclared input field fails the validator; `procedures.ts`).

## 4. Condition language: syntax

Conditions are JSON values, not text. Grammar (each production is a JSON object; `Json` is any JSON value):

```
Expr      = Compare | Has | Junction | Not | True
Compare   = { "op": CompareOp, "left": Operand, "right": Operand }
CompareOp = "eq" | "ne" | "lt" | "le" | "gt" | "ge" | "in" | "contains" | "subset"
Has       = { "op": "has", "path": Path }
Junction  = { "op": ("and" | "or"), "args": [ Expr, Expr* ] }      ; at least one argument
Not       = { "op": "not", "arg": Expr }
True      = { "op": "true" }
Operand   = { "path": Path } | { "value": Json }                   ; "path" wins when both are present
Path      = Root "." Segment ( "." Segment )*
Root      = "subject" | "resource" | "action" | "context"
```

The operators are `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `in`, `contains`, `subset`, `has`, `and`, `or`, `not`, `true`.
FALSE is written `{ "op": "not", "arg": { "op": "true" } }`. The operator `unknown` exists only inside the engine
(produced by partial evaluation, `conditions.ts`) and is rejected in a bundle.

**Paths.** A path is split on `.`; a segment cannot contain a dot. The roots bind, for the principal under evaluation
(§6): `subject` (the `Subject`: `type`, `id`, `active`, `roles`, `clearance`, `compartments`, `integrity`, `attrs`,
`delegator`), `resource` (`type`, `id`, `level`, `compartments`, `integrity`, `owner`, `parent`, `version`,
`contentClasses`, `attrs`), `action` (`{ name, kind }`) and `context` (`network`, `now`, `sessionLevel`, `sessionId`,
`highWater`, `sessionRequired`, `makerId`, `serverMakerId`, `priorActions`, `certified`, `pepSubjectTypes`, `input`,
`attrs`). Tenant data SHOULD live under `*.attrs.*`. Each segment reads an own property of a non-null object;
anything else (a missing key, a scalar on the way, an inherited property) resolves to **missing** (`resolvePath`).
JSON `null` is missing (SQL NULL). Array elements are reachable by index segments (`subject.roles.0`); producers
SHOULD NOT rely on it. In an IVP check only `resource` is bound; the other roots are missing. `context.sessionId` is
server-derived: the shared subject/credential scope of a verified PDP session token (or a legacy demo id), never the
bearer token. `context.sessionToken` is request transport and is not exposed to policy.

**Literals.** `value` is any JSON value; `null` is missing. Numbers are JSON numbers (finite by construction).

**Limits** (`validate.ts`, `checkExpr`, `request.ts`):

| Limit | Value |
|---|---|
| Nesting | a node at depth > 32 is rejected (root at depth 0; `and`, `or`, `not` add one) |
| `and` / `or` arguments | at least one |
| Rule ids (`abac`, `abacContent`, `context`, `sod`, `ivps`, `inputValidators`) | `^[A-Za-z0-9_.-]{1,64}$`, unique across all six lists |
| Request ids (`type`, `id`, `action`, `sessionId`, makers) | non-empty, at most 256 characters |
| Delegation chain | at most 4 delegators |
| Bundle over the admin API | 1 MiB |

## 5. Condition language: semantics

A condition evaluates to TRUE, FALSE or UNKNOWN (Kleene's strong three-valued logic, as SQL;
`packages/core/src/conditions.ts`, `evalTri`).

### 5.1 Comparisons

If either operand is missing, the comparison is UNKNOWN. Otherwise (`compare`):

| Operator | Defined when | Result when defined |
|---|---|---|
| `eq` | always | structural equality of the canonical JSON (`canonical`, `version.ts`): object key order ignored, array order significant, `"1"` ≠ `1`, `1` = `1.0` |
| `ne` | always | not `eq` |
| `lt` `le` `gt` `ge` | both numbers, or both strings | numeric order; for strings, Unicode code-point order (see below) |
| `in` | right is an array | some element of right `eq` left |
| `contains` | left is an array; or left and right are strings | array: some element `eq` right; string: right is a substring (the empty string always is) |
| `subset` | both are arrays | every element of left `eq` some element of right |

**Mistyped operands are UNKNOWN** (since 0.7.0): an ordering of anything but number-number or string-string, `in`
without an array on the right, `contains` on a non-array non-string or a string with a non-string needle, `subset` of
non-arrays. `eq` and `ne` are never mistyped. Two literals are decided the same way.

**Strings compare by code point** (after 0.8.1; `codePointCompare`): no locale, no case or accent folding, no
normalization (`"é"` precomposed and `"e"` + U+0301 differ). Ordering is Unicode code-point order, which is UTF-8 byte
order and PostgreSQL `COLLATE "C"`; equality, `in`, `contains` and `subset` are exact. Through 0.8.1 ordering used
JavaScript's UTF-16 code units, which put U+E000..U+FFFF above every character from U+10000. An unpaired surrogate
(not Unicode) sorts with the characters from U+10000; the SQL filter compiler refuses a literal holding one.

### 5.2 Connectives

`has p` is TRUE when `p` resolves to a non-null value, else FALSE; it is never UNKNOWN. `true` is TRUE.

| `and` | TRUE | FALSE | UNKNOWN |
|---|---|---|---|
| **TRUE** | TRUE | FALSE | UNKNOWN |
| **FALSE** | FALSE | FALSE | FALSE |
| **UNKNOWN** | UNKNOWN | FALSE | UNKNOWN |

| `or` | TRUE | FALSE | UNKNOWN |
|---|---|---|---|
| **TRUE** | TRUE | TRUE | TRUE |
| **FALSE** | TRUE | FALSE | UNKNOWN |
| **UNKNOWN** | TRUE | UNKNOWN | UNKNOWN |

| `not` | TRUE | FALSE | UNKNOWN |
|---|---|---|---|
| | FALSE | TRUE | UNKNOWN |

An n-ary `and` is FALSE if any argument is FALSE, else UNKNOWN if any is UNKNOWN, else TRUE; `or` dually. All
arguments are evaluated (no short-circuit is observable: evaluation has no effects and no errors).

### 5.3 How rules consume a condition (fail closed)

| Consumer | Takes effect on | Code |
|---|---|---|
| ABAC `permit` | TRUE | `eligibility`, `evalExpr` |
| ABAC `forbid` | TRUE or UNKNOWN | `abac`, `mayHold` |
| ABAC `obligation` | TRUE or UNKNOWN | `abac`, `mayHold` |
| Content-attribute `unless` (exemption) | TRUE | `content`, `evalExpr` |
| Clark-Wilson IVP `check` (holds) | TRUE | `integrity.ts`, `evalExpr` |
| List filter (row kept) | TRUE | `filter.ts`, `partial`; SQL `WHERE` in `packages/sql` |

So a missing or mistyped value never grants, never exempts, and always lets a forbid fire. Partial evaluation
(`partial`) substitutes everything but `resource.*` and keeps the same three values, so a list filter keeps exactly
the rows a point decision would allow on those stages (property-tested in `packages/core/test`).

## 6. Evaluation pipeline

`evaluate()` (`evaluate.ts`, `pipeline`) runs, for a request whose subject may act for a chain of delegators
(`principals`: the subject, then each delegator), these stages in this order:

| # | Stage | Per principal | Denies with |
|---|---|---|---|
| 0 | Request validation (`requestErrors`) | — | `ENGINE.MALFORMED_REQUEST` (stops) |
| 1 | Action declared for the type | — | `SCHEMA.UNKNOWN_ACTION` (stops) |
| 2 | Active | yes | `CORE.INACTIVE`, `DELEGATION.INACTIVE` (stops) |
| 3 | Eligibility: an RBAC grant, else the first applicable ABAC `permit` that is TRUE | yes | `RBAC.NOT_ELIGIBLE` |
| 4 | Mandatory: Bell-LaPadula with session level and high-water mark, compartments, untrusted network, Biba | yes | `BLP.NO_READ_UP`, `MAC.COMPARTMENT`, `NET.UNTRUSTED_LEVEL`, `NET.UNTRUSTED_COMPARTMENT`, `BLP.SESSION_REQUIRED`, `BLP.NO_WRITE_DOWN`, `BLP.HIGH_WATER`, `BIBA.NO_WRITE_UP`, `BIBA.NO_READ_DOWN` |
| 5 | Need-to-know | yes | `NTK.NO_REASON` (enforce; any unknown mode denies) |
| 6 | ABAC `forbid` and `obligation` | yes | `ABAC.<id>` |
| 7 | ABAC on content attributes (`abacContent`, trace stage `abac`, `kind: "content"`) | yes | `ABAC.CONTENT_DENY` (mask and redact add obligations: `ABAC.CONTENT_MASK`, `ABAC.CONTENT_REDACT`) |
| 8 | CBAC (context-based, Zero Trust; trace stage `cbac`) | once (request-wide) | `CBAC.NETWORK`, `CBAC.COUNTRY`, `CBAC.IP_RANGE`, `CBAC.TIME_WINDOW`, `CBAC.DEVICE_UNMANAGED`, `CBAC.DEVICE_NONCOMPLIANT`, `CBAC.MFA_STALE`, `CBAC.AUTH_STALE`, `CBAC.AUTH_METHOD`, `CBAC.RISK`, `CBAC.SIGNAL_MISSING`, `CBAC.SESSION_EXPIRED` |
| 9 | Clark-Wilson | once | `CW.UNCERTIFIED_TP`, `CW.INPUT_REQUIRED`, `CW.INPUT.<id>`, `CW.SUBJECT_NOT_AUTHENTICATED`, `CW.CERTIFIER_EXECUTES`, `CW.NOT_CERTIFIED`, `CW.CERTIFICATION_STALE`, `CW.IVP.<id>` |
| 10 | Separation of duty | once (whole chain) | `SOD.MAKER_MISMATCH`, `SOD.MAKER_UNKNOWN`, `SOD.SELF_APPROVAL`, `SOD.<id>` |

Combining: after stage 2 every stage runs and every deny is collected; the request is allowed when nothing denied
(**any deny wins**, so the order fixes the trace, not the outcome). A rule that throws denies with
`ENGINE.RULE_ERROR`. Denies for a delegator carry the prefix `DELEGATION.`. Obligations of an allowed decision merge
(`mergeObligations`): `fieldAllowlist` intersected, `redact`, `maskClasses` and `notify` unioned; a certified action
adds a single-use `decisionToken`; a denied decision carries no obligations. The decision names its basis
(`rules`), its trace and `policyVersion` (§10).

**CBAC grant duration.** A role assignment or relation tuple outside its `notBefore`/`notAfter` window (§7, §8) does
not exist for the request. The trace then shows a `cbac` step with outcome `skip` and rule `CBAC.GRANT_EXPIRED` or
`CBAC.GRANT_NOT_YET` (`policyRule` the role, or `NTK.<relation>` for a direct relation grant; `requirement`
`roleAssignment` or `relationTuple`). It is informational and denies nothing by itself: the decision is whatever the
remaining grants give.

## 7. Request model

`Subject`, `Resource`, `Context` in `types.ts`, validated by `request.ts` before any rule runs: `active` boolean,
`roles` and `compartments` lists of strings, optional `roleAssignments` (`[{ role, notBefore?, notAfter? }]`, at most 256,
each role declared; a role counts in addition to `roles` only while `context.now` is inside its window, both bounds
inclusive), `clearance` and `level` integers 0..3, `integrity` one of the four ranks,
`resource.contentClasses` a list (empty when scanned and clean), `context.network` `trusted` or `untrusted`,
`context.now` an ISO-8601 instant with seconds and an explicit `Z` or offset (a zone-less instant would be read in
the host's time zone), every number in the subject, resource and context within ±(2^53 - 1) (beyond it two different
integers can compare equal), an agent MUST carry a `delegator`. Optional Zero Trust signals are `ip` (an IPv4
or IPv6 literal without a zone id, at most 45 characters), `country` (assigned ISO 3166-1 alpha-2, upper case), `device` (exactly
`{ managed: boolean, compliant: boolean }`), `authTime` and `mfaTime` (ISO-8601 instants), `authMethods` (at most 16
names matching `[A-Za-z0-9_.-]{1,32}`), and integer `riskScore` 0..100. Malformed values deny in core and are HTTP 400
at the PDP boundary. Server-derived context fields (`highWater`, `sessionRequired`, `serverMakerId`, `certified`,
`pepSubjectTypes`) are set by the PDP, not by the caller. `sessionExpired` is set to `true` by the PDP when the BLP
session mark of `context.sessionId` has passed its idle (15 min) or absolute (8 h) expiry; an authenticated PEP may
also assert `true` itself (a caller's `false` changes nothing). It denies with `CBAC.SESSION_EXPIRED`, and the
filter/SQL residual is FALSE.

**Context signals are asserted by the authenticated PEP.** The PDP validates their shape, bounds and temporal/CIDR
semantics; it cannot verify that a device really is managed or compliant, that an IdP really performed MFA, or that a
risk score is correct. PEP/session provenance is therefore part of the deployment's trust boundary. The gateway takes
`ip` from its socket (behind its `trustedProxies`, from the rightmost untrusted X-Forwarded-For hop) and authentication facts from its own authenticated session, never from client headers. No
decision cache reuses an outcome across different context signals; search/filter evaluation uses the same requirements
as the point decision.

## 8. Relations

Need-to-know reads the relation graph only through `check` (`relations.ts`, §3.1). Relations never grant an action:
they give a reason to know, after eligibility and the mandatory models. A tuple's optional `notBefore`/`notAfter`
(ISO-8601 instants, both inclusive; the legacy `validFrom`/`validTo` are read as the same window, and
`notBefore`/`notAfter` win when both are present) bound it in time against `context.now` (CBAC grant duration, §6).

## 9. Validation

### 9.1 Structural rules (JSON Schema)

[`policy-bundle.schema.json`](policy-bundle.schema.json) states the shapes of §2 to §4: required keys, enums, numeric
ranges, the rule-id pattern, non-empty scopes, the condition grammar with rooted paths, `redact` needing `fields`,
closed fixed-shape objects and input-field rules.

### 9.2 Semantic rules (`validateBundle` only)

`validateBundle` (`packages/core/src/validate.ts`) checks the schema rules above and also:

1. Condition depth at most 32 (§4).
2. Rule ids unique across `abac`, `abacContent`, `context`, `sod`, `ivps` and `inputValidators`; `cbac` and
   `abacContent` not both present (§3.6); no `abac` rule id starts with the reserved `CONTENT_` (§3.5).
3. Role `inherits` names declared roles, without a cycle; grants name declared types (or `*`) and actions of that type
   (or `*`).
4. `mandatory.trustedRoles` names declared roles. `mandatory.bibaNoReadDownActions` and `sod[].conflicting` name
   actions declared on some resource type.
5. `needToKnow.protect` names declared types and a relation declared on the type.
6. Relation rewrites name relations declared on the same type (`computed`, `fromParent.relation`, `viaReports.then`).
7. ABAC and CBAC (`context`) `resourceTypes` name declared types; ABAC, content-attribute and CBAC `actions` name
   actions declared on some type.
8. IVPs apply to constrained types and read `resource.*` paths only.
9. `requireCertification` and `requirePepBinding` list constrained types.
10. Input validators apply to certified actions of declared types.
11. CBAC (`context`) rules have a selector and a requirement, valid ISO countries, CIDRs (no zone id) and IANA zones, distinct window edges,
   bounded lists (at most 4096 ranges and 4096 windows per bundle), device booleans, integer ages 0..31536000 and risk
   limits 0..100.

Every error is returned (not only the first). The PDP refuses to store or simulate a bundle with errors
(`packages/pdp-http/src/store.ts`, `admin/changes.ts`).

### 9.3 Known leniencies of `validateBundle` 1.0

Accepted by `validateBundle` but not conforming; the engine then fails closed:

- `abac` or `sod` absent: every decision that reaches the missing section denies with `ENGINE.RULE_ERROR`. Producers
  MUST emit them (empty lists).
- Rewrites with more than one form, `this` other than `true`, ABAC obligation values of another shape: rejected by the
  schema only. A grant whose `actions` is not a list makes `validateBundle` throw (callers treat it as invalid).

## 10. Versioning and compatibility

- **Language version.** `MAJOR.MINOR`. A MINOR version only adds optional constructs: every bundle valid under 1.x
  stays valid and decides identically under 1.y, y > x. A change that rejects a valid bundle or changes a decision is a
  MAJOR version. Clarifications of this text that do not change behaviour keep the version.
- **No forward compatibility.** A consumer rejects what it does not know (unknown top-level keys, operators, effects,
  kinds, modes): an older PDP fails closed on a newer bundle. A bundle carries no language-version field in 1.0; adding
  one is a MINOR change for producers and requires consumers of that version.
- **Policy versions.** Each stored bundle is identified by `pv.` + SHA-256 of its canonical JSON (`policyVersion`,
  `version.ts`), stamped on every decision, decision token and audit row; ids from before SHA-256 (`pv.` + 16 hex,
  FNV-1a) remain readable (`legacyPolicyVersion`). Assignments pin a version (ARCHITECTURE.md §3.5).
- **Deprecated `cbac` field.** Content rules were named CBAC and stored under `cbac` until 11 November 2026; CBAC now
  means the context model (`context`). The old field is read as `abacContent` for one version with the warning
  `DEPRECATED_CBAC_FIELD` (§3.6) and will then be removed. The former codes `CBAC.<rule id>` (content) and `CTX`-prefixed
  context codes are replaced by `ABAC.CONTENT_*` and `CBAC.*`.
- **History.** Release 0.7.0 made mistyped operands UNKNOWN (they were FALSE, which let a `forbid` fail open); 1.0 is
  defined from that behaviour.
- **This document** changes with the code in the same commit; `spec.test.ts` fails when the schema, `validateBundle`
  and the operator list drift apart.

## Appendix A. Cedar export

`toCedar(bundle)` (`packages/core/src/cedar.ts`) returns `{ schema, policies, unsupported }`: a Cedar schema (JSON
format, namespace `Qadamar`), Cedar policy text, and one `{ rule, reason }` per part of the bundle the policies do not
carry. `toCedarRequest(bundle, request)` maps a Qadamar request to Cedar's JSON request and entity formats, or throws
`CedarMappingError` when the request has no faithful form. CLI: `node scripts/export/cedar.ts <bundle.json> [--out
<dir>]` writes `policies.cedar`, `schema.cedarschema.json` and `unsupported.json`.

**IP addresses.** A CBAC `ipRanges` requirement is exported as `context has ip && (context.ip.isInRange(ip("<cidr>"))
|| ...)`: Cedar's `isInRange` takes an `ipaddr`, so each range is an `ip(...)` extension value, the schema declares
`context.ip` as the extension type `ipaddr`, and `toCedarRequest` sends the address as the JSON entity format's
extension value `{ "__extn": { "fn": "ip", "arg": "<literal>" } }`. These forms are checked structurally only (below).

**Limitation: not validated against the Cedar engine.** No Cedar tooling runs in this repository. Faithfulness is
tested against a reference evaluator for the emitted Cedar subset written for the test only
(`packages/core/test/cedar.test.ts`, clearly marked as a test oracle): it parses the policy text and applies Cedar's
semantics (errors skip a policy, forbid overrides permit). The test checks Qadamar's `evaluate` and the oracle agree on
every request of the `authzen-todo` example world, on random RBAC/ABAC/content-deny bundles with random, partly missing
data (`FUZZ_RUNS`, 300 bundles × 30 requests by default), that no exported condition ever errors, and that on
`toy-domain` Cedar never allows less than Qadamar. Running `cedar validate` and `cedar authorize` on the output is not
done.

### A.1 Mapping

| Qadamar | Cedar |
|---|---|
| Subject | entity `Qadamar::Subject`, id `["type","id"]`, attributes `id`, `type`, `active`, `roles`, `clearance`, `compartments`, `integrity`, `attrs`; parents: its roles |
| Role, `inherits` | entity `Qadamar::Role`; a role's parents are the roles it inherits |
| Resource type `t` | entity type `Qadamar::t` (a type name that is not a Cedar identifier is unsupported) |
| Action `a` | `Qadamar::Action::"a"`, applying to every type that declares `a` |
| RBAC grant | `permit (principal in Qadamar::Role::"r", action in [...], resource is Qadamar::t);` (`*` drops the constraint) |
| Inactive subject | `forbid (principal, action, resource) unless { principal.active };` |
| ABAC `permit` | `permit (...) when { <scope> && <condition is TRUE> };` |
| ABAC `forbid` | `forbid (...) when { <scope> } unless { <condition is FALSE> };` |
| Content-attribute `deny` | `forbid (...) when { resource.contentClasses.contains("c") } unless { <exemption is TRUE> };` |
| CBAC network, countries, IP ranges, device, methods and risk | `forbid (...) when { <selector> } unless { <every signal is present and accepted> }`; IP uses `ip(...)` / `.isInRange(...)`, optional values have `has` guards |

### A.2 Three-valued conditions in a two-valued language

Cedar has no UNKNOWN: reading a missing attribute is an **error**, and a policy whose condition errors is skipped. A
skipped `forbid` does not deny, which is the opposite of Qadamar (a forbid fires on UNKNOWN). The export therefore never
lets Cedar error: each Qadamar condition compiles into two Cedar expressions, *is TRUE* and *is FALSE*, built so that
every attribute read sits behind a `has` guard (`resource.attrs has "status" && resource.attrs["status"] != "closed"`).
A comparison is TRUE when its operands are present and it holds, FALSE when they are present and it does not; `and`,
`or`, `not` combine the pairs by the tables of §5.2 (TRUE of `and` is the conjunction of TRUEs, FALSE of `and` the
disjunction of FALSEs, `not` swaps them). UNKNOWN is "neither": a permit gets *is TRUE*, a forbid fires *unless is
FALSE*. The oracle counts Cedar errors and the test requires zero.

### A.3 Types

Cedar is statically typed and Qadamar is not. The export fixes the type of each `*.attrs.*` path from what it is compared
with (a literal, a built-in field, or another typed path) and declares it, optional, in the schema: Long (64-bit
integers), String, Boolean, sets of those, records for nested paths. `contains` with a string needle is a set test
unless the path is known to be a String (then `like "*needle*"`). A path read with two types, or never typed, makes the
rules that read it unsupported. `toCedarRequest` keeps only declared attributes and refuses (`CedarMappingError`) a
value that does not fit its declared type: Cedar would refuse such entity data against the schema, while Qadamar would
read it as UNKNOWN (§5.1), so the PEP decides that request with Qadamar. JSON `null` and absent values are left out:
missing in both.

### A.4 What is not exported (listed in `unsupported`)

| `rule` | Why | Effect of the gap |
|---|---|---|
| `mandatory` (always) | BLP levels, session level and server-side high-water mark, compartments, untrusted-network caps, Biba: a built-in lattice plus PDP session state | Cedar allows more |
| `delegation` (always) | an agent is decided with every person it acts for; Cedar has one principal; `toCedarRequest` refuses a delegator | request refused |
| `SOD.MAKER_MISMATCH` (always), `SOD.<id>`, `SOD.SELF_APPROVAL.<type>.<action>` | separation of duty and the two-person rule read performed-action history | Cedar allows more |
| `NTK.<type>` (mode `enforce`) | need-to-know over Zanzibar tuples with validity windows, break-glass caps and notices, depth-bounded manager chains, a 32-hop bound. Qadamar has no relation-based *permits*: relations only restrict. A Cedar `in` hierarchy would need the PEP to materialise the live graph per request | Cedar allows more |
| `CW.<type>` | certified commands, single-use decision tokens bound to the resource version, IVPs, certification records, input validators, PEP binding | Cedar allows more |
| `CBAC.<id>` | `actionKinds` has no action attribute in Cedar; IANA local-time/DST windows and instant-age arithmetic for MFA/authentication freshness have no faithful expression. Those complete rules stay in Qadamar; network, country, CIDR, device, method and risk rules export | Cedar allows more for unsupported rules |
| `ABAC.<id>` (obligation and content mask, redact) | obligations are not part of a Cedar decision | decision unchanged |
| `ABAC.<id>` (condition, content exemption included) | string ordering, non-integer numbers, `action.*` paths, object literals, `eq` on lists (ordered in Qadamar, sets in Cedar), paths other than the request fields and `*.attrs.*`, untyped or conflicting paths, a substring test with a path as needle, comparisons always UNKNOWN | permit: Cedar allows less; forbid / content deny: Cedar allows more |
| `schema.<type>`, `RBAC.<role>` | a resource type name that is not a Cedar identifier | grants: Cedar allows less; requests refused |

For the exported subset, with mandatory checks satisfied, no delegation, need-to-know off or in dry run, and data
that fits the schema, the Cedar decision is the Qadamar decision.
