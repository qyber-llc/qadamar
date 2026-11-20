# Well-Architected review

This review assesses the code at commit b09bc44 (after 0.3.0) against the six AWS Well-Architected pillars without claiming an AWS review, certification, or production service level. The design has strong denial, integrity, and audit controls. Cluster mode removes the single deciding node, but the admin plane still has one writer, sessions are process-local, operational dependencies are external, and production evidence is incomplete.

## On this page

- [Review method](#review-method)
- [Operational excellence](#operational-excellence)
- [Security](#security)
- [Reliability](#reliability)
- [Performance efficiency](#performance-efficiency)
- [Cost optimisation](#cost-optimisation)
- [Sustainability](#sustainability)
- [Improvement backlog](#improvement-backlog)

## Review method

Each pillar lists verified strengths, current risks, and the evidence behind them. "Backlog" means a recommended change that is **Not available**, not a committed roadmap or delivery date. No score is assigned: the repository does not contain production incident history, customer workload evidence, external security review, cost data, or energy measurements.

## Operational excellence

### Strengths

- Production startup fails with a consolidated list of insecure configuration problems before migration or lock acquisition (`packages/pdp-http/src/profile.ts`).
- Liveness, readiness, and leadership have different probes. `/readyz` commits pending work, checks audit integrity with bounded caching, and in cluster mode fails when the node is past its staleness bound. `/leaderz` identifies the admin-plane node for a load balancer (`packages/pdp-http/src/metrics.ts`, `packages/pdp-http/src/router.ts`).
- Prometheus metrics have bounded route-family labels and exclude user, resource, IP, raw path, and secret values (`packages/pdp-http/src/metrics.ts`).
- Backup and restore scripts cover all eighteen tables, encrypt archives with AES-256-GCM, refuse an archive that does not authenticate, avoid passwords in process arguments, and restore into a newly created database (`scripts/ops/backup.sh`, `scripts/ops/restore.sh`, `scripts/ops/archive-crypt.ts`).
- Kubernetes manifests for one dedicated instance per customer ship in `deploy/k8s`, with a migration Job, a backup CronJob, NetworkPolicies, Pod Security `restricted`, and Prometheus alert rules (`deploy/k8s/monitoring/alerts.yaml`). See [MANAGED-OFFER.md](../../MANAGED-OFFER.md).
- Release engineering produces a versioned tarball, a CycloneDX SBOM, and `SHA256SUMS` (`scripts/release/pack.sh`, `scripts/release/sbom.ts`, docs/RELEASE.md). The environment-variable table is generated from code and checked in CI (`scripts/docs/env-table.ts --check`).
- Administrative proposals include impact previews, written reasons, state digests, and two-person review (`packages/pdp-http/src/admin/changes.ts`).
- CI runs type checking, the console build, package tests with coverage thresholds, console tests, and seeded fuzzing (`tools/ci/checks.sh`).

### Risks

- The managed offer is **Partial**: proven only on a local Kubernetes cluster with test stand-ins for the IdP, TSA, certificates, and database. No cloud overlay ships, and the manifests run single-active mode, not cluster mode.
- SIEM export lag, trace drops, reader reconnect state, follower staleness, and storage failure have no dedicated Prometheus metrics. Operators correlate logs, readiness, and external systems.
- Console sessions and OIDC login state are process-local. A standby takeover or a leader change is an administrative interruption that needs a user communication procedure.
- The backup scripts provide logical snapshots, not WAL archiving, point-in-time recovery, off-site copies, or key management. Scheduling exists only in the Kubernetes CronJob.
- Full production startup verification grows with the audit chains and can become a recovery-time risk (`packages/pdp-http/src/postgres.ts`).
- Root-seal rotation and TOTP reset are not implemented. Recovery procedures are manual and need strong change control.
- Releases from 0.12.1 sign `SHA256SUMS` with an SSH ed25519 key held on the release runner (`RELEASE_SIGNING_HOOK` = `scripts/release/sign-ssh.sh`); the key is a file on one machine, not hardware-held, and container images are not signed.

## Security

### Strengths

- The core fails closed on malformed requests, unknown IDs, rule errors, UNKNOWN permits, mandatory-control failures, and missing maker data (`packages/core/src`).
- Mandatory classification, compartments, network, and integrity checks cannot be reordered or replaced by tenant rules (`packages/core/src/evaluate.ts`).
- PEP, SCIM, console, and back-channel identities use distinct authentication paths. Production requires OIDC MFA evidence, server-derived SoD, sealed private keys, and least-privilege database roles (`packages/pdp-http/src/profile.ts`).
- Decision tokens are signed, short-lived, single-use across nodes, version-bound, and re-decided at consumption (`packages/pdp-http/src/tokens.ts`, `packages/pdp-http/src/pdp.ts`, `packages/pdp-http/src/postgres.ts`).
- Decision assertions let a backend refuse requests that did not come through a credentialed PEP with an allow for exactly that request (`packages/sdk/src/assertion.ts`).
- Clark-Wilson E3 (PEP subject-type binding), E4 (certifier exclusion), and C5 (input validators) are enforced where declared (`packages/core/src/procedures.ts`).
- Audit records are hash-chained per node and optionally RFC 3161 anchored over every chain head. Production verifies every chain in full at each start (`packages/pdp-http/src/audit.ts`, `postgres-chains.ts`, `server.ts`).
- `TRUSTED_PROXIES` makes per-IP limits and lockouts apply per client behind an ingress without trusting client-written header entries (`packages/pdp-http/src/proxy.ts`).
- The gateway denies by route default, strips unapproved headers, bounds upstream work, and refuses responses it cannot sanitise (`packages/gateway/src`).

### Risks

- There is no independent penetration test, formal model check, or certification. Repository tests and 163 AuthZEN vector replays are useful evidence, not external assurance.
- The PEP is trusted to assert the end user within its bound population. A compromised PEP can choose another subject of that population (`packages/pdp-http/src/runtime.ts`).
- A backend that does not verify decision assertions, or a direct database path, bypasses Qadamar. Business-database RLS is not implemented. The assertion nonce cache is per backend process.
- A database owner can rewrite chains and anchors. Independent TSA, SIEM, and backup custody is required to detect a full rewrite.
- Token consumption and performed-action history occur before the upstream business write. A failed or different upstream write can make evidence diverge from business state (`packages/gateway/src/gateway.ts`).
- `SIGNING_KEY_SEAL` has no supported online rotation or recovery workflow. Loss affects signing, TOTP, checkpoint verification, and pseudonym stability.
- The production profile does not check database TLS, host encryption, backup storage, IdP policy, `TRUSTED_PROXIES`, cluster settings, or external evidence retention.

## Reliability

### Strengths

- PostgreSQL state, audit rows, tokens, and performed actions commit in one transaction before successful responses. A writer failure stops the node rather than letting divergent memory serve (`packages/pdp-http/src/postgres.ts`).
- In single-active mode a standby cannot serve before it acquires the lock and reloads shared state, keyring, credentials, performed actions, and audit (`packages/pdp-http/src/server.ts`).
- In cluster mode followers keep deciding when the leader stops, and a follower takes the admin plane by acquiring the lock. A follower that falls behind refuses decisions instead of deciding on stale policy (`packages/pdp-http/src/postgres.ts`; tests in `packages/pdp-http/test/postgres.test.ts`).
- Approval refuses stale state or changed impact. Token consumption refuses stale resource or policy versions (`packages/pdp-http/src/admin/changes.ts`, `packages/pdp-http/src/pdp.ts`).
- Audit reads use a separate reconnecting read-only connection, and verification streams in bounded batches (`packages/pdp-http/src/postgres.ts`).
- SIEM export is at least once with a durable per-chain position. Break-glass notification failures are audited and metered (`packages/pdp-http/src/siem.ts`, `packages/pdp-http/src/notify.ts`).
- The backup/restore drill restores all rows, indexes, and RLS policies, verifies the chain, and accepts a new decision (`packages/pdp-http/test/backup-restore.test.ts`).

### Risks

- The admin plane has one writer. In cluster mode a leader change interrupts console sessions, SCIM, anchoring, SIEM push, and break-glass notices until a follower takes the lock; in single-active mode decisions also stop until a standby takes over.
- PostgreSQL is a single shared dependency for every node. Database replication and failover are outside the product, and a database outage stops decisions on every node.
- Requests in flight during a single-active failover can fail. The failover benchmark is loopback with no load balancer and must not be read as an availability target (docs/PERFORMANCE.md).
- Production takeover and every node start include a full audit scan, so recovery grows with evidence volume.
- Console sessions are not durable or replicated. Users sign in again after takeover.
- Break-glass webhook delivery is best-effort after retries, and an in-flight notice can be lost at process stop. The audit event remains authoritative (`packages/pdp-http/src/notify.ts`).
- A backup snapshot loses writes committed after it unless hosting adds WAL or replication. The scripts alone offer no continuous RPO.

## Performance efficiency

### Strengths

- The decision core is synchronous and performs no I/O. Tuple graphs, reference lookups, and performed-action indexes are cached against immutable arrays (`packages/core/src`, `packages/pdp-http/src/runtime.ts`).
- Cluster mode adds deciding nodes, each with its own writer connection and audit chain, so decision commits are no longer serialized through one node (`packages/pdp-http/src/postgres.ts`).
- Resource search prefilters candidates with the residual when point-only history checks are not required, and stops after a page plus lookahead (`packages/pdp-http/src/pdp.ts`).
- PostgreSQL audit memory is bounded; reads and full scans use the reader connection and 10,000-row batches (`packages/pdp-http/src/postgres.ts`).
- Impact analysis has a configurable upper bound and refuses oversized affected sets before evaluation; differential tests compare its deltas with the full grid (`packages/pdp-http/src/admin/changes.ts`).
- SQL filters use parameters and strict mappings rather than constructing values as SQL text (`packages/sql/src/index.ts`).

### Risks

- Every audited PostgreSQL decision waits for a commit on its node's writer connection. With durable commits the nodes share the database's WAL flush, so cluster scaling is sub-linear.
- State, relation tuples, and performed history are loaded in memory on every node. No sharded state or external graph store is implemented.
- File audit operations read and parse the chain. PostgreSQL production startup verifies every chain in full.
- All figures come from one Apple M5 Pro laptop, loopback HTTP, synthetic worlds, and a benchmark-only high rate limit. They are not production capacity or latency guarantees (docs/PERFORMANCE.md).
- Large world, single-active PostgreSQL (5,000 subjects, 50,000 resources, commit c151662): 482.367 single evaluations/s at p99 52.734 ms, and 27.471 resource searches/s at p99 53.106 ms at concurrency 1 (docs/PERFORMANCE.md).
- Cluster mode, small world (1,000 subjects, 10,000 resources), single evaluations, 8 concurrent clients per node, PostgreSQL 17 in Docker on the same laptop with `synchronous_commit = on`, machine not idle, median of three runs: 410.294 requests/s on one node, 605.309 on two (1.48×), 735.195 on three (1.79×). Batch, search, and filter were not measured with several nodes (docs/PERFORMANCE.md).
- There is no decision cache, adaptive batching policy, or workload-aware autoscaling signal beyond latency and commit histograms.

## Cost optimisation

### Strengths

- A single process hosts PDP, admin APIs, and static console assets, reducing the number of application services to operate.
- The PDP's only direct runtime package dependency is `pg`; core, SQL, SDK, and gateway avoid separate runtime stacks (`packages/pdp-http/package.json`).
- Bounded audit memory and streamed verification reduce the need to size nodes for the entire audit history.
- In cluster mode every node serves decisions, so no node is idle by design.
- File mode supports local evaluation without PostgreSQL for demonstrations; production uses ordinary PostgreSQL tables and standard client tools.
- Batched evaluations and group commit can share HTTP and database overhead (`packages/pdp-http/src/router.ts`, `packages/pdp-http/src/postgres.ts`).

### Risks

- In single-active mode, including the shipped Kubernetes manifests, the standby is idle. No cost measurements exist for either mode.
- Full-chain verification and large state documents consume CPU and I/O as evidence and state grow, on every node.
- External IdP, TSA, SIEM, OTLP, backup storage, and database HA have deployment-specific costs that are not included in the repository.
- There is no audit archival or retention mechanism to control long-term database and backup growth.
- No prices, customer volumes, or infrastructure cost figures are available, so a total-cost-of-ownership claim would be unsupported.

## Sustainability

### Strengths

- Bounded PostgreSQL audit memory and batched scans avoid retaining the complete audit chains in application memory (`packages/pdp-http/src/postgres.ts`).
- Residual prefiltering avoids full point decisions for candidates excluded from resource search (`packages/pdp-http/src/pdp.ts`).
- Metadata-only traces, metrics, and audit exports reduce payload size compared with exporting business content.
- A bounded affected set prevents unexpectedly large administrative simulations without evaluating the whole world for local changes (`packages/pdp-http/src/admin/changes.ts`).

### Risks

- No energy, carbon, utilisation, or hardware-lifecycle measurement exists. Sustainability benefits beyond reduced work are hypotheses, not measured outcomes.
- A single-active standby is underutilised by design.
- Periodic full-chain scans run on every node, and production startup scans repeatedly read historical data. Their energy cost grows with retention.
- There is no workload scheduling, carbon-aware placement, retention tiering, or power-policy guidance.
- Consolidating components reduces operational units but does not by itself demonstrate lower environmental impact.

## Improvement backlog

Priorities below are recommendations from this review. Every item is **Not available** at commit b09bc44.

| Priority | Pillar | Recommended improvement and acceptance evidence |
| --- | --- | --- |
| P0 | Security | Commission an independent threat-led security review and penetration test of the PDP, admin, gateway, assertion verifier, OIDC, token, cluster, and database boundaries. Track findings to verified fixes. |
| P0 | Reliability | Add and rehearse database high availability and WAL-based recovery. Measure RPO/RTO with production-scale state and audit, including load-balancer behavior and leader changes. |
| P0 | Security | Define a controlled root-seal rotation and recovery design with re-encryption, dual-key migration, checkpoint continuity, and rollback tests. |
| P0 | Security | Close the evidence gap between token consumption and business commit. Evaluate an application acknowledgement or transactional outbox and test upstream failure semantics. |
| P1 | Operational excellence | Prove the managed offer on a real cloud: cloud overlay, managed PostgreSQL, real IdP, TSA, and ingress. Decide whether the manifests should run cluster mode, and test node loss and drains. |
| P1 | Reliability | Reduce takeover and start time without weakening integrity. Done in 0.5.0: production starts from the authenticated checkpoint (with counters) and verifies the whole chain in the background, measured in docs/PERFORMANCE.md; remaining: `/readyz` still waits for a periodic full recheck once a minute on long logs. |
| P1 | Security | Add a business-database enforcement backstop, and a shared nonce cache for assertion verification across backend replicas. Test direct-path and confused-deputy attacks. |
| P1 | Operational excellence | Add SIEM position age, trace-drop, storage-failure, reader-health, and follower-staleness telemetry with alert runbooks and cardinality limits. |
| P1 | Reliability | Make the admin plane survive a leader change without re-sign-in: durable or shared console-session and logout state, or a tested reauthentication procedure. |
| P1 | Performance efficiency | Benchmark cluster mode with batch, search, and filter, more than three nodes, TLS, and a database on its own host. Define workload-specific budgets only after measurement. |
| P2 | Cost optimisation | Add audit archival and retention with verifiable restore, then measure database, backup, and verification cost before and after. |
| P2 | Sustainability | Measure utilisation and energy per decision for file, single-active, and cluster modes. Use those measurements to guide retention and consolidation. |
| P2 | Operational excellence | Supply a supported TOTP reset with identity proofing and audit, replacing manual credential-document edits. |

Removed since the previous review because they are implemented: Kubernetes packaging (now Partial, see the P1 managed-offer item), active-active decision serving (cluster mode), signed gateway-to-backend claims (decision assertions), encrypted backup archives, and TOTP enrolment in the console.

## Related pages

- [Architecture overview](overview.md)
- [Security architecture](security-architecture.md)
- [Data and storage](data-and-storage.md)
- [Audit and evidence](audit-and-evidence.md)
- [ADR 0011: Cluster mode](decisions/0011-cluster-mode.md)
- [Capacity and performance](../operations/capacity.md)
- [Back up and restore](../operations/backup-restore.md)
