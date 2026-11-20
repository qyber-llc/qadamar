# Author policy bundles and conditions

Policy bundles express eligibility, attribute conditions, content restrictions, and the obligations a PEP must apply before releasing a record. Qadamar uses a small JSON condition language with SQL-like three-valued logic, so missing data fails closed instead of accidentally granting a permit or an exemption.

## On this page

- [Grant eligibility with policy roles](#grant-eligibility-with-policy-roles)
- [Write ABAC rules](#write-abac-rules)
- [Use the condition language](#use-the-condition-language)
- [Apply content-class rules](#apply-content-class-rules)
- [Enforce obligations at the PEP](#enforce-obligations-at-the-pep)

## Grant eligibility with policy roles

Policy RBAC roles grant named actions on resource types. A grant can target one type or `*`, and its action list can name actions or use `*`. Roles can inherit other roles; expansion is cycle-safe, and an unknown inherited or assigned role does not create a grant.

A subject is eligible when an expanded role grants the action or an applicable ABAC `permit` evaluates to TRUE. Otherwise the engine emits `RBAC.NOT_ELIGIBLE`. On success, the basis names `RBAC.<role>` or `ABAC.<rule-id>`.

Policy roles are application-domain roles such as `investigator` or `finance_approver`. They are separate from the console roles such as `access_admin` and `approver`, which authorize administrative API calls. Sources: `packages/core/src/evaluate.ts`, `packages/pdp-http/src/auth.ts`.

The toy domain shows inheritance: `investigator` inherits `viewer`, and `case_lead` inherits `investigator`. The AuthZEN Todo example shows both role inheritance and an ownership-based ABAC permit for `can_update_todo` and `can_delete_todo`. Sources: `examples/toy-domain/bundle.json`, `examples/authzen-todo/bundle.json`.

## Write ABAC rules

Every ABAC rule has an `id`, `description`, `effect`, and `when`. Optional `resourceTypes` and `actions` restrict its scope; omitting either applies the rule across all declared types or actions.

| Effect | Evaluation stage | Behavior |
|---|---|---|
| `permit` | Eligibility | Can supply eligibility only when the condition is TRUE. It cannot bypass mandatory or later controls. |
| `forbid` | ABAC | Denies when the condition is TRUE or UNKNOWN. |
| `obligation` | ABAC | Adds obligations when the condition is TRUE or UNKNOWN. |

A rule id uses 1–64 letters, digits, underscores, dots, or hyphens and shares one namespace across ABAC, content-attribute (`abacContent`), CBAC (`context`), SoD, IVP, and input-validator entries. Duplicate ids fail validation. Use stable ids because they appear in decisions, traces, audit rows, impact previews, and compliance mappings. Sources: `packages/core/src/validate.ts`, `packages/core/src/evaluate.ts`.

The toy rule `owner-read` permits a case owner to read without a reading role, while `closed-is-read-only` forbids `update` and `delete` when `resource.attrs.status` is `closed`. `informant-redaction` adds a redaction obligation below L3 clearance. Source: `examples/toy-domain/bundle.json`.

## Use the condition language

An expression is a JSON object. Operands are `{ "path": "subject.id" }` or `{ "value": <JSON> }`. Paths must start with `subject.`, `resource.`, `action.`, or `context.`.

| Operator | Meaning |
|---|---|
| `eq`, `ne` | Deep JSON equality or inequality. |
| `lt`, `le`, `gt`, `ge` | Ordered comparison of two finite numbers or two strings. Other type pairings return false. |
| `in` | Left value is an element of the right array. |
| `contains` | Left array contains the right value, or left string contains the right substring. |
| `subset` | Every element of the left array occurs in the right array. |
| `has` | The path exists and is neither missing nor null. |
| `and`, `or` | Combine one or more nested expressions. |
| `not` | Negate one expression. |
| `true` | Always TRUE. |

The reserved `unknown` operator represents UNKNOWN in a residual filter; authors do not need to emit it. Condition nesting deeper than 32 fails bundle validation. Sources: `packages/core/src/conditions.ts`, `packages/core/src/validate.ts`.

A missing path or JSON null is UNKNOWN in a comparison. Three-valued logic follows SQL: `NOT UNKNOWN` is UNKNOWN, false dominates `and`, and true dominates `or`.

| Rule use | Result needed |
|---|---|
| ABAC permit | TRUE only |
| ABAC forbid | TRUE or UNKNOWN fires |
| ABAC obligation | TRUE or UNKNOWN fires |
| Content-attribute `unless` exemption | TRUE only |
| IVP check | TRUE only |
| SQL `WHERE` residual | TRUE keeps the row |

For example, a forbid that requires `resource.attrs.status = "open"` also fires when `status` is absent. That is deliberate fail-closed behavior, not a rule error. Source: `packages/core/src/conditions.ts`.

## Apply content-class rules (ABAC on content attributes)

Content rules, in the bundle's `abacContent` list, are ABAC on content attributes: they match classes already listed in `resource.contentClasses`. The closed class can represent content such as `pii.iban` or `finance.amount`; Qadamar does not scan text or infer those labels.

| Effect | Result when the class is present and no TRUE exemption applies |
|---|---|
| `deny` | Deny the action with `ABAC.CONTENT_DENY`. |
| `mask` | Add the class to `maskClasses` (`ABAC.CONTENT_MASK`). |
| `redact` | Add the rule's `fields` to the redaction set (`ABAC.CONTENT_REDACT`). |

Optional `actions` limit the rule to named actions. Optional `unless` exempts only when its expression is TRUE. A redact rule requires at least one field. These rules run in the `abac` trace stage; each step carries `kind: "content"` and `policyRule` = the rule id, since the code no longer names the rule. A bundle that still uses the legacy field `cbac` for these rules is accepted for one version and read as `abacContent`, with the warning `DEPRECATED_CBAC_FIELD`; giving both `cbac` and `abacContent` fails validation. In the toy domain, `finance-mask` masks amounts unless the subject holds `finance_approver`, and `no-iban-export` denies export of resources carrying `pii.iban`.

Sources: `packages/core/src/types.ts`, `packages/core/src/evaluate.ts`, `packages/core/src/request.ts`, `examples/toy-domain/bundle.json`.

## Apply CBAC rules (context-based, Zero Trust)

CBAC rules (context-based, Zero Trust, bundle field `context`) are a separate list from the content rules
above. Give each rule an id, at least one action/kind/type selector, optional minimum level or content classes,
and at least one requirement: trusted network, allowed countries or IPv4/IPv6 CIDRs, IANA local-time windows, managed
or compliant device posture, MFA/authentication maximum age, accepted authentication methods, or maximum risk score.

Every matched requirement is re-evaluated on every request. A failed requirement denies with its `CBAC.*` code; a
required absent signal is UNKNOWN and denies with `CBAC.SIGNAL_MISSING`. `CBAC.MFA_STALE` lets a PEP start step-up MFA.
A known-expired session (`context.sessionExpired`) denies with `CBAC.SESSION_EXPIRED`. CBAC also bounds grants in time:
a role assignment or relation tuple with `notBefore`/`notAfter` exists only inside that window (see
[relations](relations-and-delegation.md)).
Time windows include their start and exclude their end, and authentication exactly at its age limit passes. Selectors
can require stronger context for higher levels or sensitive content classes. Removing or editing an existing rule goes
through conservative weakening review; adding a rule appears in impact preview without automatically being a weakening.

Signals are assertions by the authenticated PEP, limited by its credential's `contextScopes` and optional value
constraints. Out-of-scope claims are refused and audited. Qadamar validates shape, CIDRs and time semantics; a scope can
also require an MDM/sensor's signed Ed25519 or ES256 attestation bound to the exact value, subject, PDP session when
present, device/network source, PEP, audience and expiry.
Without that hook Qadamar cannot prove real device compliance or MFA itself. See
[the normative rule and request contract](../../spec/POLICY-LANGUAGE.md#37-context) and [API](../../API.md#2-pdp-api-authzen-authorization-api-10--extensions).

## Enforce obligations at the PEP

Obligations are instructions attached to an allow, not post-processing performed by the core:

- `fieldAllowlist`: the only dotted record paths the PEP may return. Multiple allowlists intersect.
- `redact`: dotted paths whose values become null. Redactions union.
- `maskClasses`: content fragment classes whose text must be masked. Masks union.
- `notify`: recipients that must be notified. Recipients union.
- `decisionToken`: a certified command's single-use token requirement, with its lifetime, the bound resource version, and `postState: true` when consumption must carry the post-state.

A deny carries no obligations. The SDK's `enforce()` returns a deep clone only after applying allowlists, redaction, and masking. Redacted fields become `null`; masked text becomes `[MASKED]`. Masking requires `record.content` to be an array of `{ class, text }` fragments and refuses if a required class cannot be found. The SDK refuses `notify` because it has no notification channel; the gateway instead requires a working `notify` hook.

Do not log an allow and then ignore its obligations. A PEP that cannot apply every obligation must release nothing. Sources: `packages/core/src/evaluate.ts`, `packages/sdk/src/enforce.ts`, `packages/gateway/src/gateway.ts`.

## Related pages

- [Write and validate a policy bundle](../guides/policy-authoring.md)
- [Integrate obligation enforcement](../guides/integrator.md)
- [Follow a decision through the core](decision-model.md)
- [Understand certified commands and decision tokens](integrity-and-separation.md)
