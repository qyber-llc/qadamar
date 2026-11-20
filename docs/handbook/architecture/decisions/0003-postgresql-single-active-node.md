# ADR 0003: PostgreSQL single active node

This ADR records the choice of one active Qadamar node with waiting standbys over an active-active stateless PDP fleet. It prioritises simple current-state consistency and atomic state/audit writes over horizontal write throughput. Single-active remains the default PostgreSQL mode; [ADR 0011](0011-cluster-mode.md) adds an opt-in cluster mode.

## On this page

- [Status](#status)
- [Amendment](#amendment)
- [Context](#context)
- [Decision](#decision)
- [Consequences](#consequences)
- [Alternatives](#alternatives)
- [Evidence](#evidence)

## Status

Accepted in commit `ebad282` on 2026-11-10. Shared security documents and authenticated checkpoints were added in v0.3.0 commit `6cd36fb`; production always performs a full startup audit scan.

**Amended by [ADR 0011](0011-cluster-mode.md)** in commit `b09bc44` on 2026-11-10. Single active node remains the default PostgreSQL mode; cluster mode is opt-in.

## Amendment

The decision below is recorded as accepted for 0.3.0 and is not rewritten. At commit b09bc44 (after 0.3.0):

- Without `GATE_CLUSTER`, the behavior described here holds: one node waits for `LEADER_LOCK` (`0x47415445`) and serves, standbys wait without a port.
- Every node now also holds `NODE_LOCK` for its `GATE_NODE_ID` and appends to its own audit chain; with the default id `0` it continues the earlier single chain.
- Decision tokens moved from a shared document to the `gate_token` table, and new performed actions to `gate_performed`. Schema migration runs under `MIGRATE_LOCK`.
- After 0.6.0, subjects, resources and tuples moved from the state document to ordered per-record tables. Their migration is automatic, transactional and idempotent; only policy/workflow metadata remains in `gate_doc`.
- With `GATE_CLUSTER=true`, every node decides and only the lock holder (the leader) writes state metadata and records and serves the admin plane. See ADR 0011.

## Context

Decisions depend on current policy, tuples, resource versions, certification, and performed-action history. Multiple active writers would need conflict handling and cache invalidation, while decision-token single use and audit sequence assignment require a coherent writer. The original stateless active-active design did not have an implementation for those protocols.

A small deployment also needs a standby that can take over without copying credentials or signing keys. The product targets single-customer instances, so a single active decision writer is a reasonable initial scaling boundary.

## Decision

- Store documents in `gate_doc`, chained records in `gate_audit` and `gate_audit_meta`, and anchors in `gate_anchor`.
- Use one PostgreSQL session advisory lock (`0x47415445`) to elect the active process.
- Block standbys in `listen()` before opening a port. After lock acquisition, reload shared state and verify policy and audit before serving.
- Serialize state changes and audit rows through one writer queue and commit them in one transaction before responding.
- Fail stop on writer failure; a supervisor restarts the process or a standby takes over.
- Store accounts, credentials, lockouts, SCIM credential, SIEM cursor, tokens, and signing keyring in shared documents.
- Keep console sessions and OIDC pending state in memory, explicitly accepting reauthentication after takeover.
- Start from an HMAC-authenticated checkpoint followed by immediate full background verification, in every profile (production included since 0.5.0; it verified the full chain before serving until 0.4.2).

## Consequences

### Positive

- There is one sequence authority and one current decision state.
- Single-use decision tokens and performed-action history need no distributed consensus protocol in the application.
- State and audit either become durable together or the successful response is not sent.
- Credential and signing-key rotation survives takeover without file copying.
- Load balancers can identify the active node by its listening port and readiness.

### Negative and operational

- One writer bounds throughput and every audited decision pays commit latency.
- Failover interrupts in-flight requests and console sessions.
- Production takeover time grows with audit length because startup scans the full chain.
- PostgreSQL is still a dependency and potential single point of failure; database HA is separate.
- A transaction-mode pooler or lagging replica can break lock and audit assumptions. Connect directly to the primary.
- Checkpointing has a bounded pre-checkpoint tamper-detection window until its background recheck (every profile since 0.5.0).

## Alternatives

- **Active-active with shared database:** deferred at the time. It would need distributed single-use, audit sequencing, and state-coherence protocols plus new load and failure testing. Implemented later for decisions only, as cluster mode ([ADR 0011](0011-cluster-mode.md)).
- **Independent signed-bundle PDPs:** **Not available**. Signed publication verification exists only for the node’s own store; distribution and maximum bundle age are not implemented.
- **External graph or consensus store:** not added. ReBAC uses stored tuples in Qadamar’s own state and the core performs traversal in memory.

## Evidence

- Lock, schema, writer queue, reader, checkpoint: `packages/pdp-http/src/postgres.ts`.
- Standby startup, shared documents, failure handling: `packages/pdp-http/src/server.ts` and `main.ts`.
- Shared security material: `packages/pdp-http/src/auth.ts` and `tokens.ts`.
- Production role checks and full startup scan: `packages/pdp-http/src/profile.ts` and `server.ts`.
- Initial decision: git commit `ebad282`; v0.3.0 changes in `6cd36fb`.

## Related pages

- [Data and storage](../data-and-storage.md)
- [Fail over the active node](../../operations/failover.md)
- [ADR 0004: Hash-chained audit with RFC 3161](0004-hash-chain-rfc3161.md)
- [ADR 0011: Cluster mode](0011-cluster-mode.md)
- [Well-Architected review](../well-architected-review.md)
