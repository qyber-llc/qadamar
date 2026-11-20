# Decision reasons and rule identifiers

Rule ids explain which built-in check or tenant rule produced a denial, an allow basis, an obligation, or a dry-run warning. Use the tables below to interpret a response and choose a safe fix; never fix a denial by suppressing its audit record or by assuming that a relation overrides a mandatory control.

## On this page

- [Read rules and traces](#read-rules-and-traces)
- [Engine and schema identifiers](#engine-and-schema-identifiers)
- [Eligibility and mandatory identifiers](#eligibility-and-mandatory-identifiers)
- [Need-to-know and ABAC identifiers](#need-to-know-and-abac-identifiers)
- [CBAC identifiers (context-based, Zero Trust)](#cbac-identifiers-context-based-zero-trust)
- [Clark-Wilson and SoD identifiers](#clark-wilson-and-sod-identifiers)
- [Delegation prefixes](#delegation-prefixes)
- [PDP, impact, governance, and compliance identifiers](#pdp-impact-governance-and-compliance-identifiers)

## Read rules and traces

On deny, `rules` contains the denying rule ids and `reasons` contains their explanations. On allow, `rules` contains the eligibility and need-to-know basis entries; `reasons` is empty. Obligations appear in `obligations` and as `obligation` trace entries. A deny has no obligations.

Each trace entry has a `stage`: `inactive`, `rbac`, `mandatory`, `delegation`, `need_to_know`, `abac`, `cbac`, `clark_wilson`, `sod`, or `engine`. The **Stage** column below gives the stage a rule id is recorded under. "Audit only" means the id appears in audit rows, not in a decision trace.

The PDP audit row also includes obligation rule ids, so its `rules` can contain entries such as `ABAC.CONTENT_MASK` and `CW.DECISION_TOKEN` that are not in the core allow-basis array. `wouldDeny` is a separate dry-run warning list, not a current denial.

Sources: `packages/core/src/evaluate.ts`, `packages/core/src/types.ts`, `packages/pdp-http/src/runtime.ts`.

## Engine and schema identifiers

| Rule id | Stage | Meaning | Typical fix |
|---|---|---|---|
| `ENGINE.MALFORMED_REQUEST` | `engine` | A required subject, resource, action, or context value is missing or invalid. This includes missing `contentClasses`, invalid levels or integrity, bad timestamps, a `context.input` that is not an object, and an overlong delegation chain. | Correct the stored snapshot or request context. Supply `contentClasses: []` only for a scanned-clean resource. |
| `SCHEMA.UNKNOWN_ACTION` | `engine` | The action is not declared for this resource type, or its kind is invalid. | Use an action declared on that type, or publish a reviewed schema addition. Check exact spelling and case. |
| `CORE.UNKNOWN_ID` | None (empty trace) | The PDP could not resolve the subject or resource reference. | Correct the type and id or provision the entity through the controlled workflow. Do not send attributes in place of a stored entity. |
| `CORE.INACTIVE` | `inactive` | The requesting subject is inactive, or its delegator cannot be found. | Reactivate only through a reviewed `update_subject` proposal when justified. |
| `ENGINE.RULE_ERROR` | Stage of the failing rule (`abac`, `cbac`), or `engine` | A rule or the guarded pipeline threw during evaluation. | Inspect the rule expression and input shape, validate the bundle, and test the specific case. The engine denies rather than ignoring the failure. |

`CORE.UNKNOWN_ID` is added by the HTTP runtime; the other identifiers in this table come from the core. Sources: `packages/core/src/evaluate.ts`, `packages/core/src/request.ts`, `packages/pdp-http/src/runtime.ts`.

## Eligibility and mandatory identifiers

| Rule id | Stage | Meaning | Typical fix |
|---|---|---|---|
| `RBAC.NOT_ELIGIBLE` | `rbac` | No expanded role grant or TRUE ABAC permit allows this action for the principal. | Assign an appropriate policy role through review or add a narrow permit. Then check the remaining stages. |
| `RBAC.<role>` | `rbac` | The named policy role supplied eligibility. This is an allow basis, not a denial. | No fix. Verify that the role and its inherited grants match intent. |
| `ABAC.<rule-id>` | `abac` | A permit supplied eligibility, a forbid denied, or an obligation rule added obligations. | Read the rule description and condition. Adjust the rule or facts through reviewed publication, not request-supplied attributes. |
| `BLP.NO_READ_UP` | `mandatory` | The resource level exceeds the subject's working level. | Lower the working session only if appropriate, assign sufficient clearance through review, or use a less-classified resource. A relation does not help. |
| `BLP.NO_WRITE_DOWN` | `mandatory` | A non-read action would write below the session level without a direct trusted role. | Work at an appropriate session level, change the resource level through review, or use the narrowly governed trusted-role process. |
| `BLP.HIGH_WATER` | `mandatory` | This subject and PEP credential already read above the resource in an open PDP session. The server-side high-water mark is shared by all their open tokens; fresh tokens, close/reopen and a lower `sessionLevel` cannot lower it. Related decisions are serialized locally and across PostgreSQL. | Write at or above the mark, or wait for the old mark to lapse after the real working session ends (15 min idle, 8 h absolute). Use the trusted-role process only when intended. |
| `BLP.SESSION_REQUIRED` | `mandatory` | `BLP_SESSION_REQUIRED` is on and the request has no session: a read above L0, or a write by a subject cleared above L0. Production accepts only `context.sessionToken`. | Open a session with the SDK's `openSession` and pass its token on every related decision. |
| `BLP.SESSION_LIMIT` | `engine` | No database and 100,000 open session marks: the read would need a new mark and cannot record it. | Retry once sessions lapse (15 min idle), or run with PostgreSQL. |
| `MAC.COMPARTMENT` | `mandatory` | The subject lacks at least one resource compartment. | Add only the required compartment through independent review, or use a resource for which the subject is compartmented. |
| `NET.UNTRUSTED_LEVEL` | `mandatory` | The resource exceeds the untrusted-network maximum. | Use a trusted network resolved by the PEP. Do not let the caller simply label itself trusted. |
| `NET.UNTRUSTED_COMPARTMENT` | `mandatory` | Compartmented content is not allowed from this untrusted network. | Use a trusted network. Changing the bundle setting is a mandatory weakening requiring security-officer approval. |
| `BIBA.NO_WRITE_UP` | `mandatory` | A lower-integrity writer attempted a non-read action on higher-integrity data. | Use a suitably verified writer or correct the data's provenance through the governed model. |
| `BIBA.NO_READ_DOWN` | `mandatory` | A configured action would rely on resource integrity below the subject's integrity. | Verify or upgrade the input data before approval, or use a subject with appropriate integrity. |
| `MAC` | `mandatory` | No principal had an earlier denial and every mandatory check passed. A pass entry in the trace only; it is not in `rules`. | No fix. |

Sources: `packages/core/src/evaluate.ts`, `packages/core/src/mandatory.ts`.

## Need-to-know and ABAC identifiers

| Rule id | Stage | Meaning | Typical fix |
|---|---|---|---|
| `NTK.NO_REASON` | `need_to_know` | No live required relation exists. In `dry_run`, this appears in `wouldDeny` as a warning rather than a current denial. | Add a valid, bounded relation through two-person review, or correct its validity window. Check other denials too. |
| `NTK.<relation>` | `need_to_know` | The named relation supplied a reason to know. This is an allow basis. | No fix. Inspect the returned tuple path and expiry. |
| `NTK.BREAK_GLASS` | `need_to_know` | A break-glass tuple in the successful path added notification obligations. | No fix to the identifier. Review the emergency independently and ensure the PEP performs notification. |
| `ABAC.CONTENT_DENY` | `abac` (`kind: "content"`) | A content rule (ABAC on content attributes, `abacContent`) denied the action; the trace step's `policyRule` names the rule. | Remove the action, use an authorized content view, or establish a TRUE exemption. |
| `ABAC.CONTENT_MASK`, `ABAC.CONTENT_REDACT` | `abac` (`kind: "content"`) | A content rule added mask or redact obligations; the trace step's `policyRule` names the rule. | No fix to the identifier. Ensure the PEP applies the obligations. |

For ABAC, missing or null data makes a permit or exemption fail to establish TRUE, while a forbid or obligation fires on UNKNOWN. For content attributes, Qadamar acts only on classes already present in the stored resource. Before this naming, these codes were `CBAC.<rule-id>` in stage `cbac`; a bundle still carrying the legacy `cbac` field is read as `abacContent` for one version, with the validation warning `DEPRECATED_CBAC_FIELD`. Sources: `packages/core/src/evaluate.ts`, `packages/core/src/conditions.ts`.

## CBAC identifiers (context-based, Zero Trust)

| Rule id | Stage | Meaning | Typical fix |
|---|---|---|---|
| `CBAC.NETWORK`, `CBAC.COUNTRY`, `CBAC.IP_RANGE`, `CBAC.TIME_WINDOW` | `cbac` | The asserted network, country, IP or local decision time is outside the matched rule. | Use an allowed network/location/time or review the selector and PEP signal source. |
| `CBAC.DEVICE_UNMANAGED`, `CBAC.DEVICE_NONCOMPLIANT` | `cbac` | The PEP/MDM posture does not meet the rule. | Enrol or remediate the device and refresh the PEP's posture assertion. |
| `CBAC.MFA_STALE` | `cbac` | `mfaTime` is too old or in the future. | Trigger step-up MFA and retry with the new assertion. |
| `CBAC.AUTH_STALE`, `CBAC.AUTH_METHOD` | `cbac` | Authentication is too old/in the future, or no accepted method is present. | Re-authenticate with an accepted method. |
| `CBAC.RISK` | `cbac` | The IdP/PEP behaviour risk exceeds `maxRiskScore`. | Follow the organisation's risk-review or step-up process. |
| `CBAC.SIGNAL_MISSING` | `cbac` | A required signal is absent, hence UNKNOWN and denied. | Supply the current authenticated-PEP assertion; never substitute a default allow. |
| `CBAC.SESSION_EXPIRED` | `cbac` | `context.sessionExpired` is true: the BLP mark of `context.sessionId` passed its idle (15 min) or absolute (8 h) expiry, or the authenticated PEP asserted it. The SQL filter residual is FALSE. | Sign in again and send a new `sessionId`. |
| `CBAC.GRANT_EXPIRED`, `CBAC.GRANT_NOT_YET` | `cbac`, outcome `skip` | A role assignment or relation tuple is outside its `notBefore`/`notAfter` window at `context.now`, so it does not exist for this request. `policyRule` is the role, or `NTK.<relation>` for a direct relation grant; `requirement` is `roleAssignment` or `relationTuple`. Informational: the decision is whatever the remaining grants give. | Renew or extend the grant through a reviewed change if access is still needed. |

CBAC traces identify the policy rule, requirement and observed value. Qadamar validates assertions but does not
independently attest devices or IdP events. Sources: `packages/core/src/context.ts`, `packages/core/src/evaluate.ts`.

## Clark-Wilson and SoD identifiers

| Rule id | Stage | Meaning | Typical fix |
|---|---|---|---|
| `CW.UNCERTIFIED_TP` | `clark_wilson` | A non-read action on a constrained type is not marked certified. | Use the declared certified command or publish a reviewed action-model correction. Do not call the application directly without a PEP. |
| `CW.DECISION_TOKEN` | `clark_wilson` | The certified command requires a single-use token. This is an obligation, not a denial. | Consume the token before execution with the bound resource version and required post-state. |
| `CW.NOT_CERTIFIED` | `clark_wilson` | This type is in `clarkWilson.requireCertification`, but no certification record covers the action. | Complete the independent `certify_tp` workflow or use an already certified procedure. |
| `CW.IVP.<ivp-id>` | `clark_wilson` | An integrity verification procedure was not TRUE on current or proposed resource state. | Correct the resource or post-state attributes so every IVP is TRUE, then retry within token validity. |
| `CW.INPUT_REQUIRED` | `clark_wilson` | Input validators cover this certified command, and no `context.input` was supplied (or, at token consumption, no post-state `attrs`). | Send the command's input as `context.input`, and the post-state as `attrs` at consumption. |
| `CW.INPUT.<validator-id>` | `clark_wilson` | The input failed this validator: a missing required field, a wrong type, enum, or bound, or an undeclared field. | Correct the input to match the validator's field schema. |
| `CW.SUBJECT_NOT_AUTHENTICATED` | `clark_wilson` | The type is in `clarkWilson.requirePepBinding`, and the calling PEP credential is not bound to the subject's type. | Call through a PEP credential bound to that subject type. A security officer sets `subjectTypes` when creating the credential. |
| `CW.CERTIFIER_EXECUTES` | `clark_wilson` | The subject, or a principal in its delegation chain, certified or approved the certification of this procedure. | Use another person. A certifier never runs the procedure they certified. |
| `CW.POST_STATE_REQUIRED` | Audit only (token consumption) | The token-consumption request omitted post-state `attrs` on a type with IVPs. The token was not consumed. | Send the attributes as the command will commit them and retry. |
| `SOD.MAKER_UNKNOWN` | `sod` | A two-person action has no known maker. | Establish maker history through a valid initial certified action. In server-history mode, caller claims cannot fill the gap. |
| `SOD.SELF_APPROVAL` | `sod` | The maker, or someone in their delegation chain, attempted the two-person action. | Use an independent actor with appropriate eligibility and history. |
| `SOD.MAKER_MISMATCH` | `sod` | The caller's maker claim contradicts server-derived history. | Remove the incorrect claim and let the PDP derive the maker; investigate inconsistent history. |
| `SOD.<sod-rule-id>` | `sod` | The subject or delegation chain already performed a different action in this conflict set on the resource. | Assign an independent actor. Do not erase history or move the action to another identity to evade SoD. |

The input-validator, PEP-binding, and certifier checks run for every certified command, including at token consumption, where the new decision uses the consuming PEP's binding and the post-state as input. Sources: `packages/core/src/evaluate.ts`, `packages/core/src/procedures.ts`, `packages/core/src/integrity.ts`, `packages/pdp-http/src/pdp.ts`.

## Delegation prefixes

After the initial subject, findings for a delegator use `DELEGATION.` in place of the unprefixed form. The complete set is:

- `DELEGATION.INACTIVE`, stage `delegation`.
- `DELEGATION.RBAC.NOT_ELIGIBLE` and allow basis `DELEGATION.RBAC.<role>`, stage `rbac`.
- `DELEGATION.BLP.NO_READ_UP`, `DELEGATION.BLP.NO_WRITE_DOWN`, `DELEGATION.MAC.COMPARTMENT`, `DELEGATION.NET.UNTRUSTED_LEVEL`, `DELEGATION.NET.UNTRUSTED_COMPARTMENT`, `DELEGATION.BIBA.NO_WRITE_UP`, and `DELEGATION.BIBA.NO_READ_DOWN`, stage `delegation`.
- `DELEGATION.NTK.NO_REASON`, allow basis `DELEGATION.NTK.<relation>`, and obligation `DELEGATION.NTK.BREAK_GLASS`, stage `need_to_know`.
- `DELEGATION.ABAC.<rule-id>` for permits, forbids, and obligations, stage `abac`.
- `DELEGATION.ABAC.CONTENT_DENY`, `DELEGATION.ABAC.CONTENT_MASK`, and `DELEGATION.ABAC.CONTENT_REDACT` for content-attribute denials, masks, and redactions, stage `abac`.

Clark-Wilson and SoD findings are evaluated with the entire chain and do not receive this prefix. An allow needs every delegation link to pass; fix the named delegator's missing eligibility, attributes, or relation rather than weakening the agent's checks. Source: `packages/core/src/evaluate.ts`.

## PDP, impact, governance, and compliance identifiers

These identifiers do not originate from the core's `evaluate()` but can appear in PDP responses, audit rows, impact results, or compliance mappings.

| Identifier | Where it appears | Meaning and action |
|---|---|---|
| `XACML.INDETERMINATE` | XACML audit row | The request was malformed, missing an attribute, or requested unsupported combined decisions. Correct the XACML request; transport success can still carry `Indeterminate`. |
| `XACML.OBLIGATION_UNEXPRESSIBLE` | XACML response trace (stage `engine`) and audit row | An allow carried an obligation the XACML mapping could not express. Qadamar converted it to a deny and issued no token. Use a PEP that supports the required mapping. |
| `GATE.LIST_ASSERTION` | Audit row of `/x/v1/assertions/list` | The subject may act on some item of the type, so the PDP signed a list assertion. The PEP still decides each item. |
| `GATE.LIST_NONE` | Audit row of `/x/v1/assertions/list` | No item of the type can be allowed; no assertion was signed. |
| `GATE.FILTER` | Audit row of `/x/v1/filter` | The PDP released a list predicate that can match some item of the type (`details.residual`: `true` or `conditional`). The PEP's query applies it. |
| `GATE.FILTER_NONE` | Audit row of `/x/v1/filter` | The released predicate is FALSE (`details.residual: false`): no item of the type can be listed. |
| `ABSENT` | Impact gained/lost cell | The cell did not exist on the other side of the comparison, usually because a subject or resource was added or removed. Inspect the candidate payload. |
| `ADMIN.TWO_PERSON` | Change approval/rejection audit row | Records the independent administrative decision. Verify maker and checker differ. |
| `ADMIN.ACCESS_REVIEW` | Access-review proposal audit row | Marks a proposal created by certification or revocation from **Access reviews**. |
| `AUDIT.APPEND` | Compliance mapping | Denotes audit-event evidence coverage; it is not an engine denial rule. |
| `AUDIT.HASH_CHAIN` | Compliance mapping | Denotes chain-verification evidence; it is not an engine denial rule. |

Sources: `packages/pdp-http/src/xacml.ts`, `packages/pdp-http/src/pdp.ts`, `packages/core/src/simulate.ts`, `packages/pdp-http/src/admin/changes.ts`, `packages/pdp-http/src/admin/compliance-map.ts`.

## Related pages

- [Follow a decision through the core](../concepts/decision-model.md)
- [Understand mandatory controls](../concepts/mandatory-controls.md)
- [Understand certified commands and SoD](../concepts/integrity-and-separation.md)
- [Resolve HTTP error codes](error-codes.md)
