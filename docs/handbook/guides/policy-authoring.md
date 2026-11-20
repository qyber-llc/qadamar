# Write and publish a policy bundle

A policy bundle describes the complete authorization model for one domain, including its resources, roles, mandatory parameters, relations, conditions, content rules, SoD rules, and Clark-Wilson controls. Author it as JSON, validate every reference and condition, preview its impact, and publish it only through independent approval.

## On this page

- [Choose the authoring path](#choose-the-authoring-path)
- [Declare schema and roles](#declare-schema-and-roles)
- [Configure mandatory controls and relations](#configure-mandatory-controls-and-relations)
- [Write conditions, content rules, and obligations](#write-conditions-content-rules-and-obligations)
- [Add SoD and Clark-Wilson controls](#add-sod-and-clark-wilson-controls)
- [Validate and read errors](#validate-and-read-errors)
- [Preview and publish](#preview-and-publish)
- [Study the worked examples](#study-the-worked-examples)

## Choose the authoring path

Use the console for tenant rule changes. In **Policies → Candidate editor**, the editable JSON contains exactly `rbac`, `abac`, `abacContent`, and `sod`. The console copies `name`, `schema`, `mandatory`, `needToKnow`, and `clarkWilson` unchanged from the published bundle and displays them as read-only sections.

Use `POST /admin/v1/changes` with `kind: "publish_policy"` for a complete bundle change, including schema, mandatory parameters, need-to-know, IVPs, or certification requirements. The server accepts only a complete validated bundle in `payload.bundle`, computes impact, and queues the change. An access administrator, policy author, or security officer can propose it; an independent approver or security officer must approve it. A detected mandatory weakening requires a security officer as checker.

Cedar is **Not available**. Conditions use Qadamar's JSON AST. Sources: `apps/admin/src/screens/PolicyEditorPane.tsx`, `packages/pdp-http/src/admin/changes.ts`, `packages/core/src/validate.ts`.

## Declare schema and roles

Start from a copy of `examples/toy-domain/bundle.json` for a governed case-and-payment domain, or `examples/authzen-todo/bundle.json` for a smaller RBAC-plus-ownership example. Keep changes in a new candidate file rather than editing the seed used by the demo.

1. Name every resource type and its actions. Each action kind is `read`, `write`, `delete`, `approve`, or `execute`.
2. Mark sensitive state-changing types `constrained` and eligible commands `certified` only when you will implement decision-token consumption.
3. Declare `granted` or other relations needed by need-to-know and administration.
4. Declare compartments used by subjects and resources.
5. Define policy roles and grants. Use inheritance for shared rights and an ABAC permit for an ownership exception rather than creating many near-duplicate roles.

A minimal resource and role shape is:

```json
{
  "schema": {
    "compartments": ["PROJECT-A"],
    "resourceTypes": {
      "case": {
        "actions": {
          "read": { "kind": "read" },
          "update": { "kind": "write" },
          "approve": { "kind": "approve", "certified": true, "requiresSecondPerson": true }
        },
        "relations": {
          "allocated": { "union": [{ "this": true }] },
          "granted": { "union": [{ "this": true }] }
        }
      }
    }
  },
  "rbac": {
    "roles": {
      "viewer": { "grants": [{ "resourceType": "case", "actions": ["read"] }] },
      "case_lead": {
        "inherits": ["viewer"],
        "grants": [{ "resourceType": "case", "actions": ["update", "approve"] }]
      }
    }
  }
}
```

This is a fragment, not a publishable bundle; add the remaining required sections shown in the examples. A resource type marked `constrained` must not contain an uncertified non-read action that you intend to allow. Sources: `packages/core/src/types.ts`, `packages/core/src/validate.ts`, `packages/core/src/evaluate.ts`.

## Configure mandatory controls and relations

Set `mandatory` explicitly:

- `trustedRoles`: direct subject roles exempt only from no-write-down.
- `untrustedNetworkMaxLevel`: highest level reachable from an untrusted network.
- `compartmentsRequireTrustedNetwork`: whether any compartment also requires a trusted network.
- `bibaNoReadDownActions`: actions that cannot rely on resource integrity below the subject's integrity when `bibaNoReadDownScope` is absent or `actions`.
- `bibaNoReadDownScope` (optional): `reads` applies no-read-down to every read-kind action instead of the list; `all` applies it to every action. Switching to broader coverage is allowed through ordinary independent review; any loss of previously effective coverage is a mandatory weakening and needs a security officer.

Configure `needToKnow.mode` as `off`, `dry_run`, or `enforce`. For each protected type, set the relation and optional `minLevel`. Start with `dry_run` to inspect `wouldDeny`, then move to `enforce` after reviewing the warnings. Lowering the mode later is a mandatory weakening and needs security-officer approval.

Relations support direct tuples, usersets, computed relations, parent traversal, and bounded reporting lines. The toy `knows` relation combines `direct_knows` with `viaReports`, while `member` can inherit through a `parent` tuple. The resource `parent` attribute is separate and enforces classification inheritance.

Keep the bundle's break-glass cap at or below your operational maximum, and list notification recipients. The admin API additionally caps an emergency at 4 hours. Sources: `packages/core/src/mandatory.ts`, `packages/core/src/relations.ts`, `packages/core/src/weakening.ts`, `examples/toy-domain/bundle.json`.

## Write conditions, content rules, and obligations

ABAC `permit` supplies eligibility only on TRUE. `forbid` and `obligation` fire on TRUE or UNKNOWN. A content-attribute `unless` exempts only on TRUE. These differences are central when a value may be absent.

The toy examples cover the common patterns:

```json
{
  "id": "owner-read",
  "description": "The owner of a case may read it even without a reading role",
  "effect": "permit",
  "resourceTypes": ["case"],
  "actions": ["read"],
  "when": {
    "op": "eq",
    "left": { "path": "resource.owner" },
    "right": { "path": "subject.id" }
  }
}
```

```json
{
  "id": "closed-is-read-only",
  "description": "A closed case cannot be updated",
  "effect": "forbid",
  "resourceTypes": ["case"],
  "actions": ["update", "delete"],
  "when": {
    "op": "eq",
    "left": { "path": "resource.attrs.status" },
    "right": { "value": "closed" }
  }
}
```

Use `and`, `or`, and `not` to compose conditions. Use `has` when existence matters, but remember that an absent value in a forbid still makes the comparison UNKNOWN and therefore fires. An obligation can set `fieldAllowlist`, `redact`, `maskClasses`, or `notify`; the PEP must implement each one.

Content rules (`abacContent`, ABAC on content attributes) match `resource.contentClasses`. Use `deny` for prohibited content, `mask` to require fragment masking, and `redact` with a non-empty `fields` list. Supply `contentClasses: []` only for a resource scanned clean. They report `ABAC.CONTENT_DENY`, `ABAC.CONTENT_MASK` or `ABAC.CONTENT_REDACT` in the `abac` stage, with the rule id in the trace step's `policyRule`. A bundle still using the legacy field name `cbac` is accepted for one version with the warning `DEPRECATED_CBAC_FIELD`; rename it to `abacContent`. Sources: `packages/core/src/conditions.ts`, `packages/core/src/evaluate.ts`, `examples/toy-domain/bundle.json`.

## Add CBAC rules (context-based, Zero Trust)

Keep content rules in `abacContent`; put CBAC (context-based, Zero Trust) requirements in the separate optional `context` list. This
example applies only to L2+ reads carrying financial data and requires every listed signal:

```json
{
  "id": "sensitive-finance-zero-trust",
  "description": "Fresh strong authentication on a healthy corporate device",
  "resourceTypes": ["case"],
  "actionKinds": ["read"],
  "minResourceLevel": 2,
  "contentClasses": ["finance.amount"],
  "network": "trusted",
  "countries": ["AE"],
  "ipRanges": ["10.0.0.0/8", "2001:db8:1234::/48"],
  "device": { "managed": true, "compliant": true },
  "mfaMaxAgeSeconds": 300,
  "authMethodsAny": ["webauthn"],
  "maxRiskScore": 40
}
```

Use a real corporate IPv6 range in place of the illustrative documentation prefix above. Every matched requirement must
pass on every request; an absent signal denies with `CBAC.SIGNAL_MISSING`. Add `timeWindows` with ISO weekdays, local
HH:mm bounds and an IANA zone for office-hour restrictions, or `authMaxAgeSeconds` for overall authentication freshness.
The console presents **Content rules (ABAC on content attributes)** and **CBAC (context-based, Zero Trust)** separately.
Removing or loosening a CBAC rule requires independent security-officer review. See [rule semantics](../../spec/POLICY-LANGUAGE.md#37-context).

## Add SoD and Clark-Wilson controls

An SoD rule names at least two conflicting actions on one resource:

```json
{
  "id": "create-vs-approve",
  "description": "Whoever created a payment cannot approve it",
  "conflicting": ["create", "approve"]
}
```

The runtime builds history from successfully consumed certified-action tokens. For production, configure `SOD_HISTORY=server`; otherwise the compatibility fallback trusts caller-supplied maker and prior-action claims. Add `requiresSecondPerson` only when the first certified action on a new resource can establish a maker without needing that same second person.

Set `clarkWilson.tokenTtlSeconds` above zero and at most 300. Add IVPs only for constrained types and read only `resource.*` paths:

```json
{
  "id": "payment-consistent",
  "description": "A payment has a positive amount and a known status",
  "resourceTypes": ["payment"],
  "check": {
    "op": "and",
    "args": [
      { "op": "gt", "left": { "path": "resource.attrs.amount" }, "right": { "value": 0 } },
      { "op": "in", "left": { "path": "resource.attrs.status" }, "right": { "value": ["pending", "approved", "released"] } }
    ]
  }
}
```

Place this object in `clarkWilson.ivps`. If a type has IVPs, its certified-command PEP must send the proposed post-state `attrs` at token consumption. Add `requireCertification` only after planning the two-person `certify_tp` workflow; otherwise certified actions deny until their records exist. Editing or removing an existing IVP is a mandatory weakening. Sources: `packages/core/src/integrity.ts`, `packages/core/src/weakening.ts`, `packages/pdp-http/src/pdp.ts`, `packages/pdp-http/src/runtime.ts`.

### Validate command input and bind PEPs

Two optional `clarkWilson` fields control who may run a certified command and with what input:

- `inputValidators` (C5) declares the input a certified command accepts. Each validator names `resourceTypes` and `actions` that must be certified commands of declared types, and `fields`, each with a `type` of `string`, `number`, `integer`, or `boolean` and the optional keys `required`, `enum`, `min`, `max`, and `maxLength`. The schema is closed: an undeclared field fails the validator.
- `requirePepBinding` (E3) lists constrained types whose certified commands are decided only for a subject whose type is bound to the calling PEP credential. A security officer sets that binding as the credential's `subjectTypes`; see [Manage PEP credentials](security-officer.md#manage-pep-credentials).

This fragment, merged into `examples/toy-domain/bundle.json`, passes `validateBundle`:

```json
{
  "clarkWilson": {
    "tokenTtlSeconds": 15,
    "inputValidators": [
      {
        "id": "payment-approval-input",
        "description": "An approval carries the approved status and a bounded amount",
        "resourceTypes": ["payment"],
        "actions": ["approve"],
        "fields": {
          "status": { "type": "string", "required": true, "enum": ["approved"] },
          "amount": { "type": "number", "required": true, "min": 0, "max": 1000000 }
        }
      }
    ],
    "requirePepBinding": ["payment"]
  }
}
```

At decision time, the PEP sends the command's input as the object `context.input`. A missing input denies with `CW.INPUT_REQUIRED`, and a failed validator with `CW.INPUT.<validator id>`. A subject whose type is not bound to the calling credential denies with `CW.SUBJECT_NOT_AUTHENTICATED`. A command with validators also gets `postState: true` in its decision-token obligation: at consumption, the PEP must send `attrs`, which the PDP checks as the command's input and against the IVPs. Declare every field the PEP sends in both places. The enforcing gateway's `postState: "body"` route sends the request body as both.

The certifier and the checker of a procedure can never run it: the engine denies them with `CW.CERTIFIER_EXECUTES` from the moment the certification record exists. Removing or changing an input validator, or removing a type from `requirePepBinding`, is a mandatory weakening. Sources: `packages/core/src/types.ts`, `packages/core/src/validate.ts`, `packages/core/src/procedures.ts`, `packages/core/src/evaluate.ts`, `packages/pdp-http/src/pdp.ts`.

## Validate and read errors

Validate a candidate locally from the repository root before submitting it:

```bash
node --input-type=module -e '
import { readFileSync } from "node:fs";
import { validateBundle } from "./packages/core/src/index.ts";
const result = validateBundle(JSON.parse(readFileSync(process.argv[1], "utf8")));
if (!result.ok) {
  console.error(result.errors.join("\n"));
  process.exit(1);
}
console.log(`Valid bundle: ${result.bundle.name}`);
' examples/toy-domain/bundle.json
```

The validator returns all errors it finds. In the console they appear under **Bundle validation errors**. The admin API returns 422 `unprocessable` with the same messages in `details`.

| Error text or family | What to fix |
|---|---|
| `bundle must be an object`, `name is required`, required sections | Restore the complete top-level JSON structure. |
| `type <t> needs actions`, `kind must be ...` | Declare at least one action with a supported kind on every type. |
| `computed ... is not declared`, `parent relation ... is not declared` | Correct relation names and references within the same relation set. |
| `maxDepth must be 1..50` | Bound reporting-line traversal in that range. |
| `inherits unknown role`, `grants on unknown type`, `not an action of` | Align RBAC references with the declared schema. |
| `path must start with subject., resource., action. or context.` | Use a supported condition root and exact case. |
| `unknown operator`, `operand needs path or value`, `and/or needs at least one argument` | Correct the JSON expression shape. |
| `condition nested too deeply` | Reduce nesting to at most 32 levels. |
| `resourceTypes/actions must be a non-empty list of declared ...` | Correct rule scope, or omit it to cover all declared values. |
| `not a valid id`, `duplicate rule id` | Use unique 1–64 character ids from letters, digits, `_`, `.`, and `-`. |
| `redact needs fields` | Add at least one response field to a content-attribute redact rule. |
| `cbac and abacContent cannot both be present` | Keep only `abacContent`. A bundle with only the legacy `cbac` field is accepted with the warning `DEPRECATED_CBAC_FIELD` (in `warnings`, the publish audit row and the console); rename it. |
| `sod ... needs two or more actions` | Put at least two distinct conflicting action names in the rule. |
| `tokenTtlSeconds must be in (0, 300]` | Choose a positive token lifetime no greater than 300 seconds. |
| `breakGlassMaxHours must be in (0, 24]` | Choose a positive bundle cap no greater than 24 hours; the admin API remains capped at 4. |
| `integrity check reads resource.* paths only` | Remove subject, action, and context reads from an IVP. |
| `resourceTypes must be ... constrained types`, `requirePepBinding must list declared constrained types` | Apply IVPs, certification requirements, and PEP binding only to constrained types. |
| `inputValidator <id>: resourceTypes and actions must name certified commands of declared types` | Scope each input validator to certified commands only. |
| `fields must declare at least one field`, `needs a type (string, number, integer, boolean) and only required, enum, min, max, maxLength` | Declare at least one field, each with a supported type and only the supported keys. |

Publication adds referential checks: a compartment, role, resource type, or relation still in use cannot be removed. Resource level updates also enforce parent-level consistency. Sources: `packages/core/src/validate.ts`, `packages/pdp-http/src/admin/changes.ts`.

## Preview and publish

In the console:

1. Open **Policies → Candidate editor**.
2. Edit `rbac`, `abac`, `abacContent`, and `sod` until **Valid candidate** appears.
3. Select **Preview impact**. Review **Gained access**, **Lost access**, and both policy fingerprints. For CBAC rules, also expand **Changes by context class**: the preview derives country, CIDR interval, local time-edge, MFA/authentication-age, risk, device, method, missing-signal, and session-expiry representatives from both bundles, plus literals and numeric/instant boundaries from ABAC and content-rule expressions. If it reports truncation or unsupported expressions, split or simplify the change and preview each part; unevaluated combinations are not evidence of no impact, and incomplete analysis requires security-officer approval.
4. Enter a reason of at least 20 characters in **Reason for policy release (at least 20 characters)**.
5. Select **Submit for approval**, then follow the change in **Approvals**.

For a full bundle through the API, submit `{ "kind": "publish_policy", "payload": { "bundle": <candidate> }, "reason": "<at least 20 characters>" }` to `/admin/v1/changes`. The response is 201 with a pending `Change`, not a published policy. The approver sees `weakensMandatory` when the candidate loosens protected controls; only a security officer can approve such a change.

At approval, the server revalidates the bundle, refuses stale state or changed impact, signs the published bundle, and appends the publication and approval metadata. Sources: `apps/admin/src/screens/PolicyEditorPane.tsx`, `packages/pdp-http/src/admin/changes.ts`, `packages/pdp-http/src/policy-signature.ts`.

## Study the worked examples

**Toy domain.** `case` uses group, parent, allocation, delegation, grant, and reporting-line relations. `payment` is constrained, with certified `create`, `approve`, and `release`, an intentionally uncertified `edit`, a two-person approval, and create/approve and create/release conflicts. `owner-read`, `no-export-untrusted`, `closed-is-read-only`, `informant-redaction`, `finance-mask`, and `no-iban-export` demonstrate the ABAC effects, content attributes included. The toy bundle has no IVPs; use the IVP example above when adding them.

**AuthZEN Todo.** The bundle has no compartments and need-to-know is off. `viewer`, `editor`, `admin`, and `evil_genius` use inheritance. The `owner-todo-write` permit combines a role test with `resource.owner = subject.attrs.email`, allowing update or delete on an owned todo. Its world contains both encoded directory ids and email aliases; ownership comes from the stored resource, not request-supplied owner properties.

Sources: `examples/toy-domain/bundle.json`, `examples/toy-domain/world.json`, `examples/authzen-todo/bundle.json`, `examples/authzen-todo/world.json`.

## Related pages

- [Understand policy conditions and obligations](../concepts/policy-and-content.md)
- [Understand IVPs and decision tokens](../concepts/integrity-and-separation.md)
- [Propose changes as an access administrator](access-administrator.md)
- [Review policy changes as an approver](approver.md)
