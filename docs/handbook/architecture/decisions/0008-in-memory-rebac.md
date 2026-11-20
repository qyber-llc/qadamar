# ADR 0008: In-memory ReBAC tuples

This ADR records the choice to store relation tuples in Qadamar’s state and evaluate a bounded graph in memory rather than deploy a separate Zanzibar-style graph database. Relations remain need-to-know inputs, never replacements for classification or integrity controls.

## On this page

- [Status](#status)
- [Context](#context)
- [Decision](#decision)
- [Consequences](#consequences)
- [Alternatives](#alternatives)
- [Evidence](#evidence)

## Status

Accepted with the initial engine commit `eeeb7a8`. Reverse traversal for list known sets was added in `aaa4f04`; residual prefiltering for resource search was added in `c587ba4`.

## Context

Reason-to-know rules need direct grants, groups/usersets, computed relations, parent traversal, and bounded reporting lines. A separate graph service would add deployment, synchronisation, consistency, and backup concerns. It would also create a “new enemy” risk if a revocation had not reached the graph used for a decision.

The initial product targets one Qadamar instance per customer with state loaded on the active node. In cluster mode (commit `b09bc44`, [ADR 0011](0011-cluster-mode.md)) every deciding node loads the same state from PostgreSQL. That makes a local tuple graph sufficient for the current scale and avoids another network dependency.

## Decision

- Store tuples in the same logical state as subjects, resources, and policy.
- Index each immutable tuple array once by object and subject, plus type/relation metadata.
- Support direct/userset, computed, from-parent, and via-reports rewrites.
- Require live validity windows; break-glass tuples also obey a maximum duration.
- Bound general traversal to 32 hops and reporting depth to the declared value capped at 50. Detect cycles and cache failed paths only to deny.
- Return the successful relation path for explanation.
- Derive list known sets through reverse reachability, then rerun exact point checks on candidates before returning sorted IDs.
- Keep relations below mandatory controls in the fixed pipeline.
- Do not add a SpiceDB/OpenFGA adapter.

## Consequences

### Positive

- Decisions and relation changes use the same active state without cross-service consistency tokens.
- No separate graph database needs deployment, backup, or credential management.
- Relation paths are explainable and traversal is deterministic.
- Reverse reachability avoids scanning every resource for many list filters.
- Break-glass uses the same relation mechanism and cannot bypass mandatory controls.

### Negative and operational

- The full state of each served tenant, including tuples, is loaded into memory. PostgreSQL stores subject/resource/tuple rows individually. Whole-tenant partitions (`GATE_TENANTS_FILE`, `GATE_SERVE_TENANTS`) can exclude other tenants; a single graph remains fully resident.
- Hop and reporting-depth limits mean deeper graphs do not produce access beyond their bound.
- A known set becomes an ID-list residual and can be large for broadly related subjects.
- External application or HR relationships must be provisioned into Qadamar tuples; there is no live SQL relation-source adapter or external graph synchronisation.
- The design would need revision for shared cross-application graph data or substantially larger relation sets.

## Alternatives

- **SpiceDB/OpenFGA or another graph service:** deferred until external sharing, scale, hierarchy, or customer-standard requirements justify its consistency and operations costs.
- **Application-specific hand-written relation SQL:** not used by the current engine; declared rewrites provide domain-independent evaluation and explanation.
- **Unbounded recursive traversal:** rejected to keep evaluation bounded and cycle-safe.

## Evidence

- Tuple and rewrite contract: `packages/core/src/types.ts`.
- Point and reverse traversal: `packages/core/src/relations.ts`.
- Filter known sets: `packages/core/src/filter.ts`.
- Graph indexing and reuse: `packages/pdp-http/src/runtime.ts`.
- Tuple administration and validity constraints: `packages/pdp-http/src/admin/changes.ts`.
- Performance history: `aaa4f04`, `c587ba4`, and `docs/PERFORMANCE.md`.

## Related pages

- [Decision engine](../decision-engine.md)
- [Data and storage](../data-and-storage.md)
- [ADR 0007: JSON condition AST](0007-json-condition-ast.md)
- [ADR 0003: PostgreSQL single active node](0003-postgresql-single-active-node.md)
