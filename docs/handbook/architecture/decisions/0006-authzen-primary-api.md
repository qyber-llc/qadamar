# ADR 0006: AuthZEN as the primary API

This ADR records the choice of OpenID AuthZEN Authorization API 1.0 as the primary PEP–PDP wire contract, with namespaced Qadamar extensions and XACML translation rather than a proprietary-only protocol. It lets the same engine serve different enforcement clients without changing decision semantics.

## On this page

- [Status](#status)
- [Context](#context)
- [Decision](#decision)
- [Consequences](#consequences)
- [Alternatives](#alternatives)
- [Evidence](#evidence)

## Status

Accepted in the initial architecture and implemented from the MVP. Official Todo interoperability vector replay was added in `a99d090`; the XACML JSON translation was added in v0.3.0 commit `6cd36fb`; decision assertions (`/x/v1/assertions/*`) were added in commit `b09bc44` (after 0.3.0).

## Context

A PDP needs a stable contract for evaluation, batch evaluation, and search. A standard API reduces custom client work and makes interoperability testable. Qadamar also needs explanation, SQL residual filters, and single-use decision tokens, which require extensions beyond basic evaluation.

Some enterprise PEPs speak XACML. Supporting XACML as a second independent engine would risk semantic drift and duplicated audit behavior.

## Decision

- Implement AuthZEN-shaped `/access/v1/evaluation`, `/evaluations`, `/search/resource`, `/search/subject`, `/search/action`, and discovery.
- Put explanation, residual filtering, token consumption, and decision assertions under `/x/v1/*`.
- Keep PDP-resolved identity and resource attributes; request bodies carry references and limited context, not authoritative roles or clearance.
- Return rule IDs, reasons, obligations, policy version, and optional decision token in response context.
- Implement XACML 3.0 JSON Profile at `/xacml/v3/authorize` by translating each individual request into the same AuthZEN evaluation. Map outcomes, obligations, advice, and `MultiRequests` without creating a second policy engine.
- Audit XACML indeterminate results as denies and refuse unexpressible permit obligations.
- Test with the official OpenID Todo vectors and report their exact scope without calling the result certification.

## Consequences

### Positive

- TypeScript and other HTTP clients can integrate without adopting a proprietary request model.
- Batch and search share the same core and audit pipeline as single evaluation.
- XACML clients receive the same policy, token, and denial behavior.
- Qadamar extensions remain visibly separate from standard paths.
- External vector replay gives reproducible evidence for the covered AuthZEN decisions.

### Negative and operational

- AuthZEN does not remove integration work for obligations, resource synchronisation, or fail-closed PEP behavior.
- Qadamar’s response includes extension fields that strict clients must understand or safely reject.
- XACML support is a subset: XML, XPath, combined decisions, PAP, and other profile areas are not implemented.
- The 163-vector result covers Todo decision corpora, not full OpenID certification, search/discovery certification levels, or HTTPS checks.
- XACML deny-biased PEP configuration is essential; Qadamar cannot force correct behavior in an external permit-biased PEP.

## Alternatives

- **Proprietary-only JSON API:** rejected because it increases integration cost and makes independent interoperability testing harder.
- **XACML as the primary internal model:** not chosen; the current core uses Qadamar’s bundle and JSON condition AST, and translation keeps one decision authority.
- **gRPC:** **Not available**.

## Evidence

- PDP routes and extensions: `packages/pdp-http/src/pdp.ts` and `router.ts`.
- XACML translation: `packages/pdp-http/src/xacml.ts`.
- SDK contract: `packages/sdk/src/types.ts` and `client.ts`.
- Vector provenance, exact result, and limits: `docs/AUTHZEN-CONFORMANCE.md` and `packages/pdp-http/test/authzen-official.test.ts`.
- XACML addition: git commit `6cd36fb`.

## Related pages

- [Integration](../integration.md)
- [Decision engine](../decision-engine.md)
- [ADR 0007: JSON condition AST](0007-json-condition-ast.md)
- [ADR 0002: Minimal dependencies](0002-minimal-dependencies.md)
