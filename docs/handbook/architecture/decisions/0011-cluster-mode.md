# ADR 0011: Cluster mode: every node decides, one leader administers

This ADR records the decision to let several Qadamar nodes decide at once against one PostgreSQL database while one leader keeps the only write access to the state documents and serves the admin plane. It amends [ADR 0003](0003-postgresql-single-active-node.md): single active node remains the default PostgreSQL mode, and cluster mode is opt-in with `GATE_CLUSTER=true`.

## On this page

- [Status](#status)
- [Context](#context)
- [Decision](#decision)
- [Consequences](#consequences)
- [Alternatives](#alternatives)
- [Evidence](#evidence)

## Status

Accepted in commit `b09bc44` on 2026-11-10 (after 0.3.0). Amends [ADR 0003](0003-postgresql-single-active-node.md) and extends [ADR 0004](0004-hash-chain-rfc3161.md) to one hash chain per node.

## Context

In single-active mode one node answers every request. Each audited decision waits for a commit on that node's one writer connection, and the node's event loop bounds throughput. docs/PERFORMANCE.md records that one node did not go faster with more clients: on one laptop, 24 clients on one node gave 555.391 requests/s against 1,079.128 for 8 clients on each of three cluster nodes in the same minute (small world, single evaluations, PostgreSQL 17 in Docker, machine not idle).

ADR 0003 deferred active-active serving because it needed answers to four problems:

1. **Audit sequencing.** One chain with one `seq` cannot have several concurrent writers.
2. **Single use.** A decision token must be consumed once across every node.
3. **State coherence.** A node must not decide on policy older than a known bound after an approved change.
4. **Admin conflicts.** Concurrent writers of the state documents (policy, model, credentials, keyring) would need merge rules.

The decision path needs only problems 1 to 3 solved. The admin plane carries most of problem 4 and has low traffic.

## Decision

Add an opt-in cluster mode to the PostgreSQL ledger (`packages/pdp-http/src/postgres.ts`, `postgres-chains.ts`, `postgres-schema.ts`, `router.ts`):

- **Opt-in.** `GATE_CLUSTER=true` with `DATABASE_URL` enables it; it is ignored without `DATABASE_URL`. Without it, ADR 0003's active/standby behavior is unchanged.
- **One chain per node.** Each node appends only to its own audit chain, named by `GATE_NODE_ID` (1 to 64 characters from `[A-Za-z0-9_.-]`, starting with a letter or digit; default `0`). `gate_audit` and `gate_audit_meta` gain a `node` column and the key `(node, seq)`. The node id is part of the hashed record, absent for chain `"0"`, so rows of earlier versions stay valid as chain `"0"`. A session advisory lock (`NODE_LOCK` `0x47415446`, `hashtext(node id)`) makes a second process with the same id wait: one writer per chain.
- **Every node decides.** Every node serves `/access/v1/*`, `/x/v1/*`, and `/xacml/v3/authorize`, and commits each request's audit rows, tokens, and performed actions in one transaction on its own writer connection.
- **One leader administers.** The node that obtains `LEADER_LOCK` (`0x47415445`) with `pg_try_advisory_lock` is the leader. Only the leader writes `gate_doc` (policy, model, changes, emergencies, credentials, keyring, lockouts, SCIM credential, SIEM cursor, audit checkpoint). It also anchors, pushes to the SIEM, sends break-glass expiry notices, and deletes decision tokens expired for more than 60 seconds, once a minute. A follower never writes a document: what a request would change in one (a PEP credential's last use) stays in its memory until the next reload.
- **Followers refuse the admin plane.** On a follower, every `/admin/` and `/scim/` request, read or write, answers `409 {"error":"not_leader","message":…,"leader":<GATE_ADVERTISE_URL or null>}` without an audit row. Followers never proxy. `GET /leaderz` answers 200 `{leader: true, node}` on the leader and on any node outside cluster mode, 503 on a follower. `/readyz` adds `role` and `node`.
- **Change propagation.** Each metadata or record write increments `gate_sync.version` and sends `NOTIFY gate_sync` in the same transaction, delivered at commit. Record writes also increment dense `gate_sync.records` generations and append `gate_state_change`. Every node listens and polls every `max(20, min(500, GATE_MAX_STALENESS_MS / 4))` ms. A follower reloads metadata and applies only new record deltas in one repeatable-read snapshot, patching its decision indexes; a missing generation falls back to a full ordered snapshot. It checks the policy-bundle signature against the keyring as at start. A bundle that fails is not decided on, and the node stays stale until a later reload holds.
- **Staleness bound.** A node records the time each synchronisation read was sent, once everything committed before it is applied. If that time is older than `GATE_MAX_STALENESS_MS` (default 2000, integer in 100..60000), decisions answer `503 unavailable` and `/readyz` answers 503. A lost notification connection is reconnected at the next tick.
- **Shared single use.** Decision tokens are rows of `gate_token`, inserted with the issuing decision's audit row. Consumption locks the row with `SELECT ... FOR UPDATE`, so a second node consuming the same token waits and then sees it used.
- **Shared history.** Performed actions are rows of `gate_performed`, numbered under the `gate_sync` row lock so that a node reading number *n* has every number below it. Nodes load new rows on each synchronisation.
- **Seeding.** A follower decides only on state a leader seeded: it waits until the `state` and `credentials` documents exist, or takes the lead itself.
- **Leader failover.** Followers keep deciding when the leader stops. Each tick a follower tries `LEADER_LOCK`; the first to get it reloads metadata, a full ordered record snapshot and anchors (the old leader's session ended, so everything it committed is visible), publishes its `GATE_ADVERTISE_URL` in `gate_sync.leader`, and serves the admin plane. A follower that cannot verify the policy releases the lock.
- **Verification.** Every chain is verified from its genesis. A recheck also requires each other chain to extend the head it saw last, so a rewritten, removed, or truncated row in any chain is caught and `verify` names the chain. An anchor covers the set of chain heads: `seq` is the sum of the head seqs and `hash` is SHA-256 of canonical `heads`. The checkpoint, counters, listings, export (`from=<node>:<seq>,...`), SIEM push, evidence packs, and subject access reports cover every chain.
- **Schema change.** `SCHEMA` now has eighteen tables, including ordered subject/resource/tuple rows, their append-only change log and disposable shared rate buckets. It runs under `MIGRATE_LOCK` (`0x4741544d`). Upgrading a database whose tables another role owns requires the owner to run `SCHEMA` and grants first; the first target start imports legacy records transactionally.
- **Shared rate-limit leases; per-node decision counter.** General and PEP buckets lease small batches from `gate_rate_limit` without a query per request; console sessions are shared rows.

## Consequences

### Positive

- Decision throughput can grow with nodes. On one laptop (small world, single evaluations, 8 clients per node, PostgreSQL 17 in Docker with `synchronous_commit = on`, machine not idle, median of three runs) one node gave 410.294 requests/s, two gave 605.309 (1.48×), and three gave 735.195 (1.79×). These are measurements under those conditions, not capacity targets (docs/PERFORMANCE.md).
- A leader stop no longer stops decisions: followers keep deciding and one of them takes the admin plane.
- No node decides on policy older than the staleness bound; a node behind refuses instead.
- Decision tokens stay single use and SoD history stays complete across nodes.
- Audit chains keep one writer each, so ADR 0004's verification applies per chain unchanged, and existing databases upgrade without rewriting a row.
- The admin plane keeps one writer, so administrative changes need no merge rules.

### Negative and operational

- The admin plane, anchoring, SIEM push, and break-glass notices still depend on one leader. A leader change interrupts them and signs console users out.
- PostgreSQL remains a single shared dependency. With durable commits nodes share its WAL flush, so scaling is sub-linear; docs/PERFORMANCE.md measured close to linear scaling only with `synchronous_commit = off`, which Qadamar does not recommend.
- Deployments need two routes: decision traffic to every node (health `/readyz`), admin and SCIM traffic to the leader (health `/leaderz`). Followers return `409 not_leader` instead of proxying.
- Each node needs a unique `GATE_NODE_ID` and, to name the leader in `409` answers, a `GATE_ADVERTISE_URL`.
- Leased rate limits cannot overspend, but unused leases on N nodes can under-admit by up to N(B−1) tokens per key. A lease costs one database statement; ordinary requests within it cost none.
- Every node loads the full state and periodically rechecks every chain of each served tenant. Whole-tenant partitions (`GATE_SERVE_TENANTS` with `GATE_TENANTS_FILE`) open only selected independent tenant databases/runtimes; their locks, freshness, rate leases, replica feeds and audit ingestion remain per database. Memory and scan cost still multiply with replicas of the same tenant; no individual tenant graph is sharded.
- Decisions may lag an approved change by up to the staleness bound.
- The production profile does not check the cluster settings; it only records them in the evidence-pack configuration baseline.
- **Partial:** batch, search, and filter were not benchmarked with several nodes; more than three nodes and a database on its own host were not measured. The Kubernetes manifests in `deploy/k8s` run single-active mode, not cluster mode.

## Alternatives

- **Keep single-active only:** rejected as the only option because one node's event loop and writer connection bound decision throughput; kept as the default.
- **One shared chain with a global sequence:** rejected. Every append would serialize on one row or lock across nodes, which removes the throughput gain.
- **Every node writes the state documents:** rejected. Concurrent policy, credential, and keyring changes would need conflict resolution, and the two-person review assumes one current state.
- **Followers proxy admin requests to the leader:** not chosen. Returning `409 not_leader` with the leader's address keeps followers free of credentials forwarding and lets the load balancer route by `/leaderz`.
- **Polling only, or notification only:** not chosen. `LISTEN/NOTIFY` gives low latency; the version poll bounds staleness when a notification is lost.
- **Independent signed-bundle PDPs without a shared database:** **Not available**. Single-use tokens and shared SoD history would need another protocol.

## Evidence

- Locks, sync, staleness, leader takeover, token sweep: `packages/pdp-http/src/postgres.ts` (`LEADER_LOCK`, `NODE_LOCK`, `MIGRATE_LOCK`, `fresh()`, `sync()`, `lead()`, `consumeToken()`).
- Per-node chains, cursors, multi-chain anchors, checkpoint format: `packages/pdp-http/src/postgres-chains.ts`.
- Tables, RLS policies, `serviceGrants`, `backupGrants`: `packages/pdp-http/src/postgres-schema.ts`.
- `409 not_leader`, `/leaderz`, `503` on staleness: `packages/pdp-http/src/router.ts`; `/readyz` role and freshness: `packages/pdp-http/src/metrics.ts`.
- Environment variables: `packages/pdp-http/src/main.ts`, documented in docs/CONFIGURATION.md.
- Tests in `packages/pdp-http/test/postgres.test.ts`:
  - "2 cluster nodes decide at once on their own chains…" and "3 cluster nodes…" (`/leaderz`, `409 not_leader`, change reaching every follower within the bound);
  - "a follower that falls behind or loses its notification connection refuses decisions, then catches up by reloading";
  - "a follower does not decide on a state document whose policy signature does not verify…";
  - "a decision token is consumed once across nodes, also when two nodes race for it";
  - "per-node chains verify; a node restarts on its own chain; a rewritten or missing row in one chain is caught and named";
  - "leader failover: the followers keep deciding, one of them takes the admin plane, and its changes reach the other";
  - "an earlier version's single chain becomes chain "0" without rewriting a row, and continues there";
  - "cluster: a follower signs decision assertions the leader's JWKS verifies…; evidence, export and subject report cover every chain".
- Tests in `packages/pdp-http/test/evidence.test.ts`: "cluster: reports page through every chain by its "node:seq" cursor…" and "cluster: an anchor over several chain heads…".
- Behavior specification: docs/API.md §3.9.1. Measurements and test-run observations: docs/PERFORMANCE.md, "Horizontal scaling: cluster mode".

## Related pages

- [Architecture overview](../overview.md)
- [Data and storage](../data-and-storage.md)
- [Audit and evidence](../audit-and-evidence.md)
- [Integration](../integration.md)
- [ADR 0003: PostgreSQL single active node](0003-postgresql-single-active-node.md)
- [ADR 0004: Hash-chained audit with RFC 3161](0004-hash-chain-rfc3161.md)
