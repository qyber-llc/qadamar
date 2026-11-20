# ADR 0001: Fixed evaluation pipeline

This ADR records the decision to implement mandatory access-control models in a fixed core pipeline rather than as tenant-authored rules. It applies to point decisions, residual filters, simulation, and every HTTP mapping in the code at commit b09bc44 (after 0.3.0).

## On this page

- [Status](#status)
- [Context](#context)
- [Decision](#decision)
- [Consequences](#consequences)
- [Alternatives](#alternatives)
- [Evidence](#evidence)

## Status

Accepted in the initial engine commit `eeeb7a8` on 2026-11-08 and retained through v0.3.0. Later changes added Clark–Wilson integrity checks, and commit `b09bc44` added the C5, E3, and E4 checks to the Clark–Wilson stage, without making the pipeline configurable.

## Context

A general-purpose policy language lets a tenant express its own rules, but a mistaken rule can silently bypass classification, integrity, or separation-of-duty requirements. Regulated use cases need predictable interaction between RBAC, ABAC, ReBAC, content rules, mandatory access controls, and delegation. List filtering must preserve the same result as point evaluation.

The original architecture recommended built-in models with a separate tenant policy language. The implementation chose a JSON condition AST for that language; [ADR 0007](0007-json-condition-ast.md) covers that separate choice.

## Decision

Implement one pure `evaluate(bundle, request, graph)` pipeline with this fixed order:

1. validate request and action;
2. require active subject and delegators;
3. require RBAC or ABAC-permit eligibility for every principal;
4. enforce Bell–LaPadula, compartments, network, and Biba;
5. enforce relation-based need-to-know;
6. apply ABAC forbids and obligations;
7. apply ABAC on content attributes (deny, mask, and redaction rules);
8. CBAC (context-based, Zero Trust): re-verify every matched context requirement, denying failed or missing signals and expired sessions;
9. apply Clark–Wilson certification, integrity, input-validator (C5), PEP-binding (E3), certifier-exclusion (E4), and token controls;
10. apply two-person and conflicting-action separation of duty.

Any denial wins. Malformed input and throwing rules deny. A denied response carries no obligations. Relations can supply a reason to know but cannot lift a mandatory control.

Mirror the same resource-dependent stages in `buildFilter()` and exclude history-dependent SoD and obligations from the residual. Require an independent security officer when `mandatoryWeakenings()` detects a candidate policy loosening.

## Consequences

### Positive

- The order and fail-closed semantics are reviewable in one small function.
- Every protocol uses the same decision logic, audit shape, and policy version.
- Tenant policy cannot turn off the mandatory models.
- Delegation cannot become a privilege-laundering path because every principal repeats the checks.
- Partial evaluation and impact analysis reuse the same model definitions.

### Negative and operational

- New model interactions require core changes and differential tests, not just a new tenant rule.
- The fixed pipeline can produce denials that a simpler application-specific policy would not need.
- Residual filtering is not a complete decision: callers still need point checks for obligations and SoD.
- Conservative UNKNOWN handling can deny when data is incomplete; integrations must keep required attributes complete.
- `mandatoryWeakenings()` deliberately flags any existing relation rewrite because generic narrowing cannot be proven, so some legitimate edits need security-officer approval.

## Alternatives

- **Tenant-authored mandatory rules:** rejected because omission or reordering could silently widen access.
- **A general policy engine for all models:** not chosen; mandatory lattice semantics and obligations remain product code even if another language is added later.
- **Early exit on first deny:** not used for most stages. Evaluating the full pipeline gives a fuller explanation, at the cost of additional work on denied requests.

## Evidence

- Pipeline and denial aggregation: `packages/core/src/evaluate.ts`.
- Mandatory models: `packages/core/src/mandatory.ts`.
- Three-valued conditions: `packages/core/src/conditions.ts`.
- Residual filtering: `packages/core/src/filter.ts`.
- Weakening detection: `packages/core/src/weakening.ts` and `packages/pdp-http/src/admin/changes.ts`.
- Clark–Wilson C5, E3, E4 checks shared by point decisions and filters: `packages/core/src/procedures.ts`.
- Initial implementation history: git commit `eeeb7a8`; adversarial fail-closed corrections in `7715e7e`.

## Related pages

- [Decision engine](../decision-engine.md)
- [ADR 0007: JSON condition AST](0007-json-condition-ast.md)
- [ADR 0005: Server-derived SoD](0005-server-derived-sod.md)
