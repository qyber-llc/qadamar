# ADR 0004: Hash-chained audit with RFC 3161

This ADR records the decision to use canonical SHA-256-linked audit records with optional external RFC 3161 timestamps instead of an unverified application log or a new ledger service. It provides tamper evidence while keeping evidence formats inspectable and exportable.

## On this page

- [Status](#status)
- [Context](#context)
- [Decision](#decision)
- [Consequences](#consequences)
- [Alternatives](#alternatives)
- [Evidence](#evidence)

## Status

Accepted in commit `ebad282` on 2026-11-10. v0.3.0 adds authenticated checkpoints, mandatory production CA validation, and stricter production database-role checks.

Extended in commit `b09bc44` (after 0.3.0) for [cluster mode](0011-cluster-mode.md): in PostgreSQL mode each node writes its own chain (`gate_audit.node`, a per-node `seq`), rows of earlier versions form chain `"0"` unchanged, and an anchor covers the set of chain heads. The decision below applies to each chain.

## Context

Authorization and administration need a durable record of what was decided, by which rule, and under which policy version. A mutable database log cannot reliably show later editing or truncation. A trusted timestamp can bind a chain head to an external time without sending business content to the authority.

The solution must work in file-backed demos and PostgreSQL, support SIEM export, and avoid requiring a separate blockchain or ledger product.

## Decision

- Serialize each record without `hash` as canonical JSON and set `hash = SHA-256(prevHash + canonicalRecord)`.
- Start each chain from 64 zeros and require contiguous positive sequence numbers within it. In PostgreSQL mode, name the chain in the hashed record (`node`, absent for chain `"0"`) and allow one writer per chain.
- Store only decision/admin metadata, not credentials or business-record content.
- Refuse appends after detected integrity failure.
- On PostgreSQL, separate chained source rows from derived filter metadata and compare both during verification.
- Periodically send a moved head's SHA-256 imprint and nonce to an RFC 3161 TSA; retain the DER token, hash, sequence, TSA, and generation time. With several chains, the anchored hash is SHA-256 of the canonical set of chain heads, stored with the anchor as `heads`.
- Validate response status, hash algorithm, imprint, nonce, and time. With `TSA_CA_FILE`, also invoke `openssl ts -verify`; production requires this CA check.
- Export raw NDJSON records by pull and signed at-least-once push, with a per-chain position. Support detached Ed25519 signatures for compliance evidence and evidence-pack manifests.
- Preserve external copies because a database owner who rewrites both chain and anchors defeats local-only detection.

## Consequences

### Positive

- Editing, insertion, deletion, reordering, and truncation are detectable against a trusted head or anchor.
- Only a hash leaves for timestamping, reducing disclosure to the TSA.
- Auditors can independently recompute the chain and verify TSA tokens with standard OpenSSL tooling.
- PostgreSQL metadata can be repaired without treating it as the evidence source.
- SIEM duplicates are safe to deduplicate by sequence.

### Negative and operational

- Hash chaining does not prove that the original event was truthful or that the business command committed.
- Full scans become more expensive as the chain grows. Production deliberately chooses this cost at every startup.
- TSA availability affects new anchors, not the validity of the existing chain. Monitoring must detect stale anchoring.
- Historical evidence verification needs the JWKS and CA material of the time, not only current endpoints.
- Total compromise of Qadamar, database ownership, and all external evidence is outside the detection boundary.

## Alternatives

- **Plain append-only table or file:** rejected because privileged rewriting leaves no cryptographic evidence.
- **Sign every audit record:** not chosen; chain verification plus periodic external anchors avoids a signing operation per event and limits key dependence. The chain itself is not a digital signature.
- **External ledger/blockchain:** not added; it would create another stateful dependency and consistency boundary.
- **Send full records to the TSA:** rejected; only the head imprint is necessary for timestamp evidence.

## Evidence

- Hash format and file verification: `packages/pdp-http/src/audit.ts`.
- PostgreSQL scans, metadata, checkpoints: `packages/pdp-http/src/postgres.ts`.
- Per-node chains, multi-chain anchors, and judgement: `packages/pdp-http/src/postgres-chains.ts`; tests in `packages/pdp-http/test/postgres.test.ts` ("per-node chains verify…", "an earlier version's single chain becomes chain "0"…").
- RFC 3161 request, reply, and OpenSSL verification: `packages/pdp-http/src/anchor.ts`.
- Scheduling and failure behavior: `packages/pdp-http/src/server.ts`.
- SIEM and pull export: `packages/pdp-http/src/siem.ts`.
- Initial implementation: git commit `ebad282`; hardening in `75b5109` and `6cd36fb`; per-node chains in `b09bc44`.

## Related pages

- [Audit and evidence](../audit-and-evidence.md)
- [Respond to an audit tamper alert](../../operations/audit-tamper-response.md)
- [ADR 0003: PostgreSQL single active node](0003-postgresql-single-active-node.md)
- [ADR 0002: Minimal dependencies](0002-minimal-dependencies.md)
