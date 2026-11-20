# ADR 0007: JSON condition AST

This ADR records the implementation of tenant ABAC conditions (content-attribute exemptions included) as a small JSON abstract syntax tree with SQL-like three-valued logic, instead of integrating Cedar. The same AST supports point evaluation, conservative fail-closed behavior, partial evaluation, and parameterised PostgreSQL compilation.

## On this page

- [Status](#status)
- [Context](#context)
- [Decision](#decision)
- [Consequences](#consequences)
- [Alternatives](#alternatives)
- [Evidence](#evidence)

## Status

Accepted as “plan B” during the initial MVP implementation and retained in v0.3.0 and in the code at commit b09bc44 (after 0.3.0). The Cedar spike described in the original design was not run; Cedar remains unintegrated.

## Context

The engine needs permit, forbid, obligation, and exemption conditions over subject, resource, action, and context. List queries need a residual after non-resource values are known. The semantics must agree between JavaScript evaluation and PostgreSQL, especially for missing values.

A general language would add expressive power and possibly formal analysis, but it also adds a runtime, schema mapping, and partial-evaluation integration. The MVP needed a bounded, inspectable subset that could run without another runtime dependency.

## Decision

- Store conditions as JSON operands and operators over `subject.*`, `resource.*`, `action.*`, and `context.*`.
- Support comparisons, membership, containment, subset, presence, boolean composition, NOT, TRUE, and an internal UNKNOWN residual.
- Treat missing and null paths as UNKNOWN. Use Kleene AND/OR/NOT semantics.
- Require exactly TRUE for permits and exemptions. Fire forbids and obligations on TRUE or UNKNOWN. Keep a list-filter row only when its predicate is TRUE.
- Validate operator shape, paths, finite numbers, nesting, rule scope, and Clark–Wilson resource-only predicates before publication.
- Partially evaluate all non-resource operands and preserve resource paths for the residual.
- Compile residuals to typed, parameterised PostgreSQL expressions. Reject unmapped paths, incorrect built-in types, unsafe identifiers, and unsupported array contents.
- Keep Cedar and other policy-language adapters as possible future work, not current capability.

## Consequences

### Positive

- One small evaluator defines point, filter, IVP, and SQL behavior.
- UNKNOWN handling fails closed rather than treating absent data as a permit or exemption.
- The SQL compiler emits parameters, not interpolated values, and preserves SQL NULL behavior.
- Bundle validation catches many malformed conditions before publication.
- No policy-language runtime dependency is required.

### Negative and operational

- The language has no general functions, regular expressions, arithmetic, custom types, or Cedar formal model.
- Strict type mapping is integration work. A wrong tenant attribute declaration can cause 400 or a semantics mismatch if the underlying data is inaccurate.
- Need-to-know known sets are ID lists in residuals; very large sets can produce large SQL parameters and need workload testing.
- Relation rewrites are policy data but not arbitrary SQL source queries; external graph adapters are not implemented.
- Future language migration would require semantic equivalence evidence, not just syntax translation.

## Alternatives

- **Cedar:** not integrated. The original design saw stronger formal analysis potential, but its WASM partial-evaluation gate was not verified.
- **Rego/OPA or CEL:** not integrated; either would add a runtime and a second semantics mapping.
- **Arbitrary JavaScript rules:** rejected because they would compromise determinism, safe validation, and SQL partial evaluation.

## Evidence

- AST types: `packages/core/src/types.ts`.
- Three-valued evaluation and partial evaluation: `packages/core/src/conditions.ts`.
- Residual construction: `packages/core/src/filter.ts`.
- Validation: `packages/core/src/validate.ts`.
- PostgreSQL compiler: `packages/sql/src/index.ts`.
- Built-in mapping checks: `packages/pdp-http/src/pdp.ts`.
- Design history: `docs/ARCHITECTURE.md` sections 3.4 and 14.

## Related pages

- [Decision engine](../decision-engine.md)
- [ADR 0001: Fixed evaluation pipeline](0001-fixed-evaluation-pipeline.md)
- [ADR 0002: Minimal dependencies](0002-minimal-dependencies.md)
- [ADR 0008: In-memory ReBAC tuples](0008-in-memory-rebac.md)
