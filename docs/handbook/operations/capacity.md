# Capacity and performance

Qadamar's cost depends on state size, relation selectivity, batch shape, audit length, and PostgreSQL commit latency, so plan capacity from measurements of your own workload. Every figure on this page comes from [docs/PERFORMANCE.md](../../PERFORMANCE.md) and is shown with its conditions. They were measured on one laptop with synthetic data. They are not service targets, limits, or guarantees.

## On this page

- [Measurement conditions](#measurement-conditions)
- [Single-node results](#single-node-results)
- [Multi-node scaling in cluster mode](#multi-node-scaling-in-cluster-mode)
- [Capacity drivers](#capacity-drivers)
- [Plan and measure your workload](#plan-and-measure-your-workload)
- [Apply operational guidance](#apply-operational-guidance)

## Measurement conditions

These conditions apply to the single-node results ([docs/PERFORMANCE.md, Method and machine](../../PERFORMANCE.md#method-and-machine)):

- Apple M5 Pro, 18 cores, 48.0 GiB RAM, macOS 26.5.1 arm64; Node.js 22.23.3; PostgreSQL 17.11.
- Server in-process on loopback; client with Node.js `fetch`; response parsing included in latency.
- Fixed business clock `2026-11-08T10:00:00Z`; benchmark-only rate limit of 1,000,000,000, so throttling does not hide engine cost.
- 1-second warm-up and 20-second admission window, plus the drain of in-flight requests.
- Unmodified toy-domain bundle; synthetic active L3 investigators with both compartments; synthetic cases; one `allocated` tuple per subject on average; trusted-network `read` requests.
- Batches of exactly 50 evaluations with `execute_all`; resource search asks for one page of 50.
- Concurrency 8, except large-world resource search at concurrency 1.

Do not extrapolate to another database, policy, network, or selectivity profile.

## Single-node results

### Indexed resource search, 2026-11-11

Large world, one page of 50, concurrency 1, one run per mode. The baseline already evaluated one residual per candidate; it is not the older 111-second point-wise baseline. See [the method, maxima and caveats](../../PERFORMANCE.md#indexed-authzen-search-candidates-2026-11-11).

| Mode | Requests/s before → after | p50 ms before → after | p99 ms before → after |
| --- | ---: | ---: | ---: |
| File | 40.726 → 779.380 | 23.056 → 1.155 | 40.928 → 3.154 |
| PostgreSQL | 12.740 → 234.940 | 67.739 → 3.277 | 208.187 → 23.563 |

The PostgreSQL after-run maximum was 139.513 ms. Index construction and distinct indexed values still consume memory; subject and action searches were not separately timed.

### Decision-only PostgreSQL statements, 2026-11-11

Large world, single evaluations, one run before and one after the one-statement decision writer. See [the full method and profiling breakdown](../../PERFORMANCE.md#decision-only-postgresql-statements-2026-11-11). Both versions already used group commit.

| Concurrency | Requests/s before | Requests/s after | p50 ms before → after | p99 ms before → after |
| ---: | ---: | ---: | ---: | ---: |
| 8 | 2,057.079 | 2,678.269 | 3.410 → 2.010 | 8.677 → 9.177 |
| 32 | 5,554.612 | 7,312.518 | 5.316 → 3.641 | 13.818 → 13.933 |
| 64 | 7,165.896 | 8,263.535 | 8.420 → 6.903 | 16.532 → 32.136 |

One prepared statement commits audit and metadata, plus any tokens and BLP marks, before the response. This removes round trips, not the durable WAL wait. Median latency improved; the concurrency-64 p99 was worse in this run, so do not infer a tail-latency guarantee.

### Historical throughput and latency, commit c151662

Large world: 5,000 subjects, 50,000 resources, 5,000 tuples. Values from [Latest measurements (commit c151662)](../../PERFORMANCE.md#latest-measurements-commit-c151662). Commit c151662 predates 0.3.0; these scenarios were not remeasured for the code at commit b09bc44.

| Scenario | Mode | Concurrency | Requests/s | p99 latency |
| --- | --- | ---: | ---: | ---: |
| Single evaluation | File | 8 | 6,412.992 | 2.740 ms |
| Single evaluation | PostgreSQL | 8 | 482.367 | 52.734 ms |
| Batch of 50 | PostgreSQL | 8 | 201.336 | 68.273 ms |
| Resource search | File | 1 | 29.298 | 58.387 ms |
| Resource search | PostgreSQL | 1 | 27.471 | 53.106 ms |
| SQL filter | PostgreSQL | 8 | 8,092.621 | 2.208 ms |

The SQL filter figure measures generation of the SQL predicate through Qadamar, not its execution in the application's database. File-mode single evaluation measured 7,973.220 requests/s in the previous run with no change to that path; the source attributes the difference to run-to-run variation on one laptop.

### PostgreSQL memory, small world

Small world: 1,000 subjects, 10,000 resources, 1,000 tuples. Heap MiB at the start and end of each scenario; all scenarios shared one process, so growth accumulates from left to right.

| Run | Evaluation | Batch | Search | Filter |
| --- | --- | --- | --- | --- |
| Before bounding audit memory | 44 → 38 | 47 → 383 | 759 → 1082 | 1269 → 2289 |
| Commit c151662 | 35 → 42 | 32 → 44 | 43 → 42 | 106 → 89 |

The source reads this as the PostgreSQL heap no longer growing with audit length in that run. It is not a memory limit.

### Active/standby failover, commit c151662

Small world, PostgreSQL, five repetitions, concurrency 4, 2 seconds of steady authenticated single evaluations. Recovery runs from closing the old server to the first successful evaluation on the new listener. No load balancer; the standby listened on a new ephemeral port.

| Measure | Min | Median | Max |
| --- | ---: | ---: | ---: |
| Recovery, ms | 213.933 | 274.840 | 329.709 |
| Failed requests during recovery | 1,246 | 2,530 | 3,201 |

The failed-request counts are the load generator calling a closed port; they are not a production failure rate. These results predate the authenticated checkpoint. Since 0.5.0 every profile starts from the checkpoint: at 1,001,000 rows a start from the checkpoint takes about 0.1 s against 9 s for a full-chain start (the demo checkpoint of 0.4.2 still took 1.3 s aggregating counters) (docs/PERFORMANCE.md). Measure your own.

## Multi-node scaling in cluster mode

From [Horizontal scaling](../../PERFORMANCE.md#horizontal-scaling-cluster-mode-1-2-and-3-deciding-nodes-2026-11-10), measured on 2026-11-10.

Conditions:

- `scripts/bench/load.ts --nodes N` started N cluster nodes as separate Node.js processes (node ids `a`, `b`, `c`) and ran 8 concurrent clients per node from one load-generator process, each client pinned to one node.
- Small world (1,000 subjects, 10,000 resources), single evaluations only, PostgreSQL mode. Each run reset the Qadamar tables, warmed up 2 seconds, and measured 15 seconds. Sizes were interleaved over three rounds; the table shows the median run.
- PostgreSQL 17.11 (`postgres:17-alpine`, default configuration, `synchronous_commit = on`) in Docker 29.8.2, on the same Apple M5 Pro (Docker VM: 18 CPUs, 15.7 GiB). Node.js 22.23.3, macOS 26.5.1.
- The machine was not idle: the 1-minute load average was between 11.6 and 24.6, and single runs varied by up to 1.8 times.

```bash
node scripts/bench/load.ts --world=tmp/bench-small --mode=postgres --scenario=evaluation \
  --duration=15 --warmup=2 --concurrency=8 --nodes=3 --seed=20261108
```

| Nodes | Requests/s (median run) | Three runs | p50 ms | p99 ms | Errors | Scaling |
| ---: | ---: | --- | ---: | ---: | ---: | ---: |
| 1 | 410.294 | 410.294, 538.037, 380.359 | 13.784 | 118.476 | 0 | 1.00× |
| 2 | 605.309 | 682.871, 605.309, 502.864 | 16.928 | 159.220 | 0 | 1.48× |
| 3 | 735.195 | 735.195, 945.842, 524.530 | 24.344 | 187.684 | 0 | 1.79× |

Diagnostic runs of 10 seconds, same commands, not part of the table:

- 24 clients on one node gave 555.391 requests/s, against 1,079.128 for 8 clients on each of three nodes in the same minute.
- With `synchronous_commit = off`, a durability trade-off Qadamar does not recommend, 1, 2, and 3 nodes gave 453.465, 831.002, and 1,670.086 requests/s. With durable commits the nodes share PostgreSQL's WAL flush on the laptop's Docker disk, which the source gives as the reason for sub-linear scaling.

Test observations from `packages/pdp-http/test/postgres.test.ts` on the same laptop, not guarantees: with a 500 ms staleness bound, followers decided on an approved policy change 13 to 163 ms after the leader answered; when the leader stopped, a follower took the admin plane 29 to 122 ms later while the two other followers kept deciding with no failed request.

Not measured: batch, search, and filter with several nodes; more than three nodes; a database on its own host. Above roughly 1,000 requests per second the single load-generator process may itself be the limit.

## Capacity drivers

| Driver | Effect in this implementation |
| --- | --- |
| Audited PostgreSQL decisions | Every decision waits for its state and audit commit. Concurrent decision-only requests share one prepared statement and durable implicit transaction; each node still has one writer connection, so statement and WAL latency bound per-node throughput (`packages/pdp-http/src/postgres.ts`). Cluster mode adds nodes, which share the database's WAL flush. |
| BLP session shape | Mark-relevant decisions of one session serialize on a local queue and a PostgreSQL transaction advisory lock through commit. Different sessions use different locks; no-session requests and L0 reads bypass them. Same-session latency includes waiting for earlier decisions, while the existing per-node writer queue remains a bound for all traffic. |
| Batch shape | One `/access/v1/evaluations` request holds up to 1,000 evaluations and costs one principal rate-limit token per evaluation. Audit rows still scale with entries (`packages/pdp-http/src/pdp.ts`, `router.ts`). |
| Resource-search selectivity | Cached residual indexes select original-array positions before point decisions; index construction and memory grow with stored resources and distinct indexed attribute values. Subject search shares relation reachability, then point-checks survivors (`packages/core/src/candidates.ts`, `packages/pdp-http/src/pdp.ts`). |
| Relation shape | Point traversal is bounded at 32 hops (`packages/core/src/relations.ts`). Broad relations produce large ID sets. |
| State size | Every node holds the full decision worlds of its served tenants in memory. `GATE_SERVE_TENANTS` with `GATE_TENANTS_FILE` excludes other tenant runtimes; it does not shard an individual graph. Registration patches arrays/indexes and validates only changed resources and their children; one laptop measured 2,423.898 single registrations/s at 100k and 1,962.376/s at 1M with 32 concurrent clients (group commit). A 1,000-resource batch measured 14,542.238 and 14,376.164 items/s (docs/PERFORMANCE.md). |
| Audit length | Verification streams the chain in batches of 10,000 rows. Periodic full rechecks and the background verification after each start still cost I/O and CPU as history grows (about 9 s per million rows on a laptop); the start itself does not. |
| Impact previews | Proposal impact spans affected subjects × resources × actions over both networks and maker/history variants. Tuple and rule diffs avoid the full world grid; broad mandatory or relation changes can still select it. `IMPACT_MAX_EVALUATIONS` (default 100,000) refuses larger affected sets (`packages/pdp-http/src/admin/changes.ts`). |
| Rate limits | 120 requests per minute per IP and per principal by default. Benchmarks disable this limiter. Behind a proxy, set `TRUSTED_PROXIES` or every client shares the proxy's per-IP bucket. |
| Export and telemetry | SIEM, TSA, and OTLP work is asynchronous to decisions but still uses CPU, network, and database reads. |
| TLS and proxying | Benchmarks on loopback do not measure your TLS terminator, load balancer, gateway, application, or database network latency. |

## Plan and measure your workload

### 1. Define the workload

Record subject, resource, tuple, and performed-action counts; policy complexity and Clark-Wilson use; the mix of single, batch, search, and filter requests; page and batch sizes; storage, database location, TLS path, and concurrency; audit growth and the recovery-time budget; and expected per-IP and per-principal request rates, probes included.

### 2. Reproduce the benchmark as a baseline only

Generation overwrites its output files; use separate directories:

```bash
node scripts/bench/world.ts --output=tmp/bench-small \
  --subjects=1000 --resources=10000 --tuples=1000 --seed=20261108
node scripts/bench/world.ts --output=tmp/bench-large \
  --subjects=5000 --resources=50000 --tuples=5000 --seed=20261108
```

File-mode load:

```bash
node scripts/bench/load.ts --world=tmp/bench-small --mode=file \
  --duration=20 --warmup=1 --concurrency=8 --seed=20261108
```

For PostgreSQL, set `TEST_DATABASE_URL` to a **throwaway** database and use `--mode=postgres`. Each PostgreSQL run recreates all eighteen Qadamar tables and loses their data; never point it at data you need (`scripts/bench/common.ts`). `--scenario` accepts `all`, `evaluation`, `batch`, `search`, or `filter`; `--nodes N` (PostgreSQL only) runs N cluster nodes.

Failover benchmark:

```bash
node scripts/bench/failover.ts --world=tmp/bench-small \
  --concurrency=4 --steady=2 --repeats=5 --seed=20261108
```

Keep the JSON reports outside the repository, with exact commands, versions, and dataset hashes.

### 3. Measure production-shaped behaviour

Test through the real TLS proxy, PEP or gateway, application database, and production PostgreSQL. Include normal and worst-case batch sizes, sparse search pages, policy publication and impact previews, signing-key rotation, token consumption, periodic rechecks under load, full production startup and takeover at expected audit lengths, leader change in cluster mode, backup and restore, and rate limiting. Use `gate_http_request_duration_seconds`, `gate_commit_duration_seconds`, database telemetry, process memory, and end-to-end PEP measurements together.

## Apply operational guidance

- **Set budgets from your own percentiles and conditions.** Do not turn laptop figures into an SLA.
- **Protect the commit path.** Keep the PostgreSQL primary healthy and watch commit latency; every audited decision waits for it.
- **Scale out with cluster mode when one node's writer is the limit.** Measure the gain on your database: in the published run, three nodes gave 1.79 times one node.
- **Use batches deliberately.** Compare end-to-end latency, rate-limit cost, audit volume, and failure scope.
- **Prefer SQL pushdown where it fits.** Apply the residual predicate in the application database, then make point decisions and enforce obligations.
- **Bound impact previews.** Split proposals that exceed `IMPACT_MAX_EVALUATIONS` rather than raising it without measuring.
- **Plan audit growth.** Production startup scans every chain. Measure recovery time regularly. Audit archival is **Not available**.
- **Account for throttling.** The 120-per-minute buckets apply per IP and per principal, with per-evaluation cost for batches.
- **Do not infer database HA.** The benchmarks measure Qadamar takeover only, not PostgreSQL replication or failover.
- **Re-measure after upgrades.** The latest decision-write comparison is one laptop run per concurrency; the historical c151662 figures predate 0.3.0.

## Related pages

- [Monitoring and alerts](monitoring.md)
- [Fail over the active node](failover.md)
- [Back up and restore](backup-restore.md)
- [Decision engine](../architecture/decision-engine.md)
- [Data and storage](../architecture/data-and-storage.md)
- [Well-Architected review](../architecture/well-architected-review.md)


## Tenant partition memory

Run `node scripts/bench/memory.ts` for fresh-process RSS, heap and index cardinalities at 10k, 100k and 500k subjects,
resources and tuples. [Measured results and limits](../../PERFORMANCE.md#tenant-partition-memory-2026-11-11) compare
ten isolated worlds with one assigned world; they exclude HTTP, database connections and audit memory. At the
largest size, retained index heap fell by about 90% when serving one of ten equal tenants. A single tenant remains
fully resident. Plan capacity for the sum of assigned worlds plus one runtime/connection set per tenant, including
high-cardinality policy attributes. A replica also loads only its selected tenants. Changing assignment needs a
restart and load-balancer drain; probe readiness and scrape metrics separately with each tenant header.
