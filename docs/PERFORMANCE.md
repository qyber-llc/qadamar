# Performance baseline

The first sections are **baseline numbers before the chantier 4 optimisations**; the results after them are in the last section. They were measured once on one laptop, not on a production cluster. They are not capacity targets or production availability guarantees.

## Method and machine

The synthetic worlds use the unmodified `examples/toy-domain/bundle.json`. Every subject is an active synthetic investigator with L3 clearance and both toy compartments; every resource is a synthetic case. Each world has one `allocated` tuple per subject on average. All requests are trusted-network `read` requests selected from those allocations by the seeded workload generator. The resource search asks for one page of 50 results, and a batch contains exactly 50 evaluations with `execute_all` semantics.

The server runs in-process and listens on loopback. The client uses Node's `fetch`; the business clock is fixed at `2026-11-08T10:00:00Z`, and the benchmark-only rate limit is 1,000,000,000 so throttling does not obscure engine costs. Each scenario has a 1 s warm-up and a 20 s request-admission window. Elapsed time also includes draining requests already in flight, and requests/s uses that actual elapsed time. Latencies include response-body parsing and use nearest-rank percentiles over all completed requests, including failures. Memory is the combined benchmark/server process, sampled immediately before and after the measured window.

| Machine detail | Measured value |
|---|---|
| OS | macOS 26.5.1 (build 25F80), arm64 |
| CPU | Apple M5 Pro, 18 cores |
| Memory | 51,539,607,552 bytes (48.0 GiB) |
| Node | 22.23.3 |
| PostgreSQL | 17.11 (`SHOW server_version`) |

The two worlds and all four storage/endpoint combinations were measured sequentially, followed by failover; the complete capture took about 14 minutes. Large-world search was measured at concurrency 1 to bound its drain time; every other load scenario used concurrency 8.

## Reproduce

Run from the repository root with Node >= 22.18. Generation overwrites the two JSON files in the selected output directory, so use separate synthetic directories.

```bash
node scripts/bench/world.ts --output=tmp/bench-small --subjects=1000 --resources=10000 --tuples=1000 --seed=20261108
node scripts/bench/world.ts --output=tmp/bench-large --subjects=5000 --resources=50000 --tuples=5000 --seed=20261108
```

`world.ts` accepts `--output`, `--subjects`, `--resources`, `--tuples`, and `--seed`. It copies the toy bundle and writes only clearly marked synthetic data.

For file mode, run all four scenarios:

```bash
node scripts/bench/load.ts --world=tmp/bench-small --mode=file --duration=20 --warmup=1 --concurrency=8 --seed=20261108
```

For PostgreSQL mode, set `TEST_DATABASE_URL` in the environment to a **throwaway local database**, then replace `--mode=file` with `--mode=postgres`. The URL is never included in output. Each PostgreSQL load invocation drops and recreates `gate_doc`, `gate_audit`, and `gate_anchor`; do not point it at data that must be kept.

`load.ts` accepts `--scenario=all` (the default), or `evaluation`, `batch`, `search`, and `filter`. For the large-world baseline, evaluation, batch, and filter were run separately by adding `--scenario=<name>` and `--world=tmp/bench-large` to the command above. Search was isolated as follows:

```bash
node scripts/bench/load.ts --world=tmp/bench-large --mode=file --scenario=search --duration=20 --warmup=1 --concurrency=1 --seed=20261108
node scripts/bench/load.ts --world=tmp/bench-large --mode=postgres --scenario=search --duration=20 --warmup=1 --concurrency=1 --seed=20261108
```

Every load report is JSON on stdout and includes the fixed seed, exact command line, world sizes, response errors, latency, throughput, and RSS/heap samples. Progress messages go to stderr.

For five PostgreSQL failovers:

```bash
node scripts/bench/failover.ts --world=tmp/bench-small --concurrency=4 --steady=2 --repeats=5 --seed=20261108
```

`failover.ts` also resets the three `gate_*` tables once at suite start. Its options are `--world`, `--concurrency`, `--steady`, `--repeats`, and `--seed`. It emits the exact command and per-repetition and min/median/max results as JSON.

## Small world: 1,000 subjects, 10,000 resources, 1,000 tuples

Requests and errors are counts; latency is milliseconds; memory is MiB before → after.

### File mode

| Scenario | Concurrency | Requests | Errors | Requests/s | p50 | p95 | p99 | Max | RSS MiB | Heap MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Single evaluation | 8 | 40,069 | 0 | 2,003.186 | 3.592 | 6.128 | 7.606 | 74.022 | 202.6 → 242.3 | 60.8 → 69.6 |
| Batch of 50 | 8 | 1,017 | 0 | 50.599 | 155.488 | 229.024 | 252.734 | 272.286 | 243.1 → 217.7 | 30.6 → 32.2 |
| Resource search | 8 | 14 | 4 | 0.366 | 11,505.623 | 30,664.214 | 30,664.214 | 30,664.214 | 218.0 → 192.0 | 36.7 → 27.4 |
| SQL filter | 8 | 6,753 | 0 | 337.425 | 21.440 | 34.088 | 38.549 | 45.632 | 192.0 → 189.0 | 38.5 → 32.1 |

The four search errors were `fetch TypeError`; the other ten requests returned valid responses. The measured search window, including the in-flight drain, was 38.278 s.

### PostgreSQL mode

| Scenario | Concurrency | Requests | Errors | Requests/s | p50 | p95 | p99 | Max | RSS MiB | Heap MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Single evaluation | 8 | 7,176 | 0 | 358.712 | 21.404 | 32.373 | 41.723 | 57.081 | 175.5 → 194.7 | 44.3 → 41.7 |
| Batch of 50 | 8 | 935 | 0 | 46.713 | 167.336 | 188.256 | 228.131 | 311.725 | 196.5 → 177.6 | 41.5 → 65.0 |
| Resource search | 8 | 9 | 0 | 0.270 | 33,394.288 | 33,394.449 | 33,394.449 | 33,394.449 | 494.6 → 695.0 | 184.2 → 540.7 |
| SQL filter | 8 | 6,899 | 0 | 344.719 | 20.685 | 34.232 | 37.403 | 44.018 | 665.3 → 688.0 | 152.1 → 363.5 |

The search window, including the drain, was 33.395 s.

## Large world: 5,000 subjects, 50,000 resources, 5,000 tuples

### File mode

| Scenario | Concurrency | Requests | Errors | Requests/s | p50 | p95 | p99 | Max | RSS MiB | Heap MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Single evaluation | 8 | 8,240 | 0 | 411.707 | 17.641 | 28.528 | 31.722 | 47.731 | 272.6 → 408.3 | 80.2 → 123.2 |
| Batch of 50 | 8 | 181 | 0 | 8.775 | 906.254 | 1,235.019 | 1,714.574 | 1,916.190 | 249.2 → 284.8 | 80.8 → 101.2 |
| Resource search | 1 | 1 | 0 | 0.009 | 111,480.826 | 111,480.826 | 111,480.826 | 111,480.826 | 168.4 → 177.9 | 82.7 → 59.9 |
| SQL filter | 8 | 1,270 | 0 | 63.199 | 120.881 | 179.612 | 203.715 | 224.477 | 310.8 → 420.8 | 135.8 → 176.3 |

The single search response completed in 111.481 s, so its percentile statistics all describe that same observation.

### PostgreSQL mode

| Scenario | Concurrency | Requests | Errors | Requests/s | p50 | p95 | p99 | Max | RSS MiB | Heap MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Single evaluation | 8 | 4,155 | 0 | 207.695 | 39.182 | 45.070 | 52.109 | 73.738 | 276.3 → 404.8 | 68.2 → 135.1 |
| Batch of 50 | 8 | 170 | 0 | 8.489 | 905.143 | 1,202.317 | 2,006.378 | 2,300.033 | 276.6 → 248.5 | 91.9 → 69.4 |
| Resource search | 1 | 1 | 0 | 0.009 | 114,408.001 | 114,408.001 | 114,408.001 | 114,408.001 | 410.1 → 407.7 | 289.4 → 277.5 |
| SQL filter | 8 | 1,223 | 0 | 60.825 | 123.411 | 182.986 | 205.606 | 270.485 | 335.8 → 396.5 | 146.0 → 103.1 |

The single search response completed in 114.408 s.

## PostgreSQL failover

The failover run used the small world, concurrency 4, and 2 s of steady authenticated single-evaluation traffic per repetition. Active and standby nodes shared the database and local credential/signing directory. At each stop, the old active server was closed without waiting for it before awaiting the standby. Recovery time runs from that close call through the first successful authenticated evaluation on the newly listening standby. Failures are requests to the old endpoint that completed with an error during that interval, plus any failed standby readiness evaluation. Failover traffic used `Connection: close` so persistent sockets could not keep the retiring node open.

| Repetition | Recovery ms | Failed requests during recovery | Steady-state failures |
|---:|---:|---:|---:|
| 1 | 81.426 | 157 | 0 |
| 2 | 90.933 | 299 | 0 |
| 3 | 92.516 | 294 | 0 |
| 4 | 81.208 | 327 | 0 |
| 5 | 91.929 | 230 | 0 |
| **Min** | **81.208** | **157** | **0** |
| **Median** | **90.933** | **294** | **0** |
| **Max** | **92.516** | **327** | **0** |

There was no load balancer in this measurement: the standby used a new ephemeral port. The failed-request counts therefore describe how quickly this local loop retried a closed port, not a production request failure rate. Database replication, database failover, and load-balancer health-check behaviour were not measured.

## After the chantier 4 optimisations

Same machine, same commands, seeds and synthetic worlds as the baseline above, run on the merged code:
reverse traversal for relation known sets, lazy search paging, bounded impact analysis, and two fixes the baseline
pointed to: the tuple index is built once per tuple list instead of once per decision, and subjects and resources are
found through an index instead of a scan of the whole list. One laptop, loopback HTTP, not a production cluster.

### Before and after, large world (5,000 subjects, 50,000 resources), file mode

| Scenario | Requests/s before | Requests/s after | p99 ms before | p99 ms after |
|---|---:|---:|---:|---:|
| Single evaluation | 411.707 | 7,973.220 | 31.722 | 2.503 |
| Batch of 50 | 8.775 | 402.994 | 1,714.574 | 43.957 |
| Resource search (one page, concurrency 1) | 0.009 | 0.514 | 111,480.826 | 2,851.928 |
| SQL filter | 63.199 | 10,677.933 | 203.715 | 2.017 |

### Small world: 1,000 subjects, 10,000 resources, 1,000 tuples

File mode:

| Scenario | Concurrency | Requests | Errors | Requests/s | p50 | p95 | p99 | Max | RSS MiB | Heap MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Single evaluation | 8 | 146,971 | 0 | 7,347.946 | 0.814 | 2.235 | 3.826 | 56.547 | 227.9 → 264.5 | 80.3 → 86.2 |
| Batch of 50 | 8 | 11,265 | 0 | 563.086 | 12.633 | 20.419 | 24.541 | 36.788 | 270.7 → 274.9 | 100.8 → 46.5 |
| Resource search | 8 | 73 | 0 | 3.296 | 2,365.093 | 3,552.388 | 5,675.302 | 5,675.302 | 275.0 → 275.3 | 47.6 → 50.7 |
| SQL filter | 8 | 212,365 | 0 | 10,617.935 | 0.635 | 1.496 | 2.028 | 6.503 | 276.2 → 306.2 | 25.2 → 144.2 |

PostgreSQL mode:

| Scenario | Concurrency | Requests | Errors | Requests/s | p50 | p95 | p99 | Max | RSS MiB | Heap MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Single evaluation | 8 | 8,225 | 0 | 411.200 | 16.977 | 33.925 | 137.286 | 176.938 | 174.8 → 191.6 | 44.4 → 38.1 |
| Batch of 50 | 8 | 9,451 | 0 | 472.484 | 13.659 | 34.615 | 45.850 | 116.930 | 234.9 → 714.4 | 47.0 → 382.9 |
| Resource search | 8 | 119 | 0 | 5.905 | 1,308.252 | 2,163.867 | 2,618.467 | 2,744.439 | 970.1 → 1803.7 | 759.0 → 1081.9 |
| SQL filter | 8 | 112,320 | 0 | 5,615.790 | 0.723 | 4.501 | 9.925 | 138.119 | 1774.2 → 2258.5 | 1269.1 → 2289.2 |

### Large world: 5,000 subjects, 50,000 resources, 5,000 tuples

File mode:

| Scenario | Concurrency | Requests | Errors | Requests/s | p50 | p95 | p99 | Max | RSS MiB | Heap MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Single evaluation | 8 | 159,470 | 0 | 7,973.220 | 0.863 | 1.944 | 2.503 | 28.585 | 276.7 → 433.8 | 98.8 → 265.8 |
| Batch of 50 | 8 | 8,066 | 0 | 402.994 | 18.262 | 30.129 | 43.957 | 94.724 | 275.5 → 196.3 | 102.3 → 78.8 |
| Resource search | 1 | 11 | 0 | 0.514 | 1,830.461 | 2,851.928 | 2,851.928 | 2,851.928 | 165.0 → 156.3 | 81.1 → 86.8 |
| SQL filter | 8 | 213,564 | 0 | 10,677.933 | 0.616 | 1.569 | 2.017 | 9.096 | 323.6 → 441.4 | 143.4 → 148.0 |

PostgreSQL mode:

| Scenario | Concurrency | Requests | Errors | Requests/s | p50 | p95 | p99 | Max | RSS MiB | Heap MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Single evaluation | 8 | 11,333 | 0 | 566.580 | 10.455 | 29.936 | 65.602 | 196.062 | 250.1 → 292.3 | 91.9 → 145.7 |
| Batch of 50 | 8 | 9,004 | 0 | 450.155 | 16.413 | 28.215 | 37.555 | 140.710 | 280.3 → 667.3 | 74.8 → 462.4 |
| Resource search | 1 | 23 | 0 | 1.134 | 793.326 | 1,291.361 | 1,627.598 | 1,627.598 | 691.3 → 1428.0 | 470.1 → 1135.9 |
| SQL filter | 8 | 192,817 | 0 | 9,625.943 | 0.651 | 1.718 | 2.526 | 60.656 | 357.7 → 444.0 | 170.6 → 90.7 |

### Failover after the optimisations (PostgreSQL, small world, five repetitions)

| Repetition | Recovery ms | Failed requests during recovery | Steady-state failures |
|---:|---:|---:|---:|
| 1 | 72.559 | 160 | 0 |
| 2 | 98.788 | 264 | 0 |
| 3 | 167.331 | 1967 | 0 |
| 4 | 84.476 | 182 | 0 |
| 5 | 85.669 | 231 | 0 |
| **Min** | **72.559** | **160** | **0** |
| **Median** | **85.669** | **231** | **0** |
| **Max** | **167.331** | **1967** | **0** |

### What the numbers still show

- **PostgreSQL mode is bound by the commit**: every audited decision waits for its transaction (one connection,
  group commit), so single evaluations stay near 566.580 requests/s against
  7,973.220 in file mode. Batches amortise it.
- **Memory grew in PostgreSQL mode** in these runs: the active node kept every audit row in memory. Fixed after
  these measurements (the node now keeps only the chain head, pending rows and fixed counters; audit reads go to the
  database on a separate connection); not re-measured yet.
- **Resource search decided candidates one by one** in these runs (one to three seconds per sparse page). Fixed after
  these measurements: candidates are prefiltered with the residual, so a page decides about the page size; not re-measured yet.
- Failover recovery stayed under 170 ms; one repetition lost 1967 requests during recovery because the
  load generator keeps firing at the stopped node.

## Latest measurements (commit c151662)

Same machine, commands, seeds and synthetic worlds, after bounding the PostgreSQL audit memory and prefiltering resource
search with the residual. Raw JSON reports were kept outside the repository; numbers below are copied from them.

Large world (5,000 subjects, 50,000 resources), previous run vs now:

| Scenario | Requests/s before | Requests/s now | p99 ms before | p99 ms now |
|---|---:|---:|---:|---:|
| Single evaluation, file | 7,973.220 | 6,412.992 | 2.503 | 2.740 |
| Single evaluation, PostgreSQL | 566.580 | 482.367 | 65.602 | 52.734 |
| Batch of 50, PostgreSQL | 450.155 | 201.336 | 37.555 | 68.273 |
| Resource search, file (concurrency 1) | 0.514 | 29.298 | 2,851.928 | 58.387 |
| Resource search, PostgreSQL (concurrency 1) | 1.134 | 27.471 | 1,627.598 | 53.106 |
| SQL filter, PostgreSQL | 9,625.943 | 8,092.621 | 2.526 | 2.208 |

PostgreSQL mode, small world, heap MiB at the start → end of each scenario (all scenarios share one process, so growth
accumulates from left to right):

| Run | Evaluation | Batch | Search | Filter |
|---|---|---|---|---|
| Before (c151662^ code) | 44 → 38 | 47 → 383 | 759 → 1082 | 1269 → 2289 |
| Now | 35 → 42 | 32 → 44 | 43 → 42 | 106 → 89 |

Failover (PostgreSQL, small world, five repetitions): recovery 213.933 / 274.840 / 329.709 ms
(min / median / max), previously 72.559 / 85.669 / 167.331 ms; failed requests during recovery
1246 / 2530 / 3201 (previously 160 / 231 / 1967).

What this shows:

- **Memory no longer grows with the audit** in PostgreSQL mode: the heap stays around 40 to 90 MiB where it reached
  2 GiB before.
- **Resource search is now tens of milliseconds** per page instead of seconds (about 55 times faster on the large world).
- **Failover is slower**: the standby now verifies the whole stored chain in batches before it serves, instead of
  reading it into memory, so recovery went from about 85 ms to about 275 ms (median), and the load generator counts
  more failed requests while it waits. Faster takeover would need the verified prefix to be checkpointed.
  That checkpoint now exists (API.md §3.9.1) and, since 0.5.0, is used in every profile: startup reads only the rows
  after the last full recheck. `failover.ts` stops nodes within seconds, before the five-minute recheck has stored a
  checkpoint, so it does not show it; [Start-up and takeover against audit length](#start-up-and-takeover-against-audit-length-2026-11-10)
  measures it.
- File-mode single evaluations measured lower than the previous run (6,413 vs 7,973 requests/s) with no change to that
  path: run-to-run variation on one laptop is of that order; treat single figures with that margin.

## Horizontal scaling: cluster mode, 1, 2 and 3 deciding nodes (2026-11-10)

Cluster mode (API.md §3.9.1, `GATE_CLUSTER=true`) lets every node decide against the shared PostgreSQL, each on its own
audit chain. Measured on the same laptop as above, small world (1,000 subjects, 10,000 resources), single evaluations
only, the path every decision takes (audit row committed before the answer).

**Method.** `scripts/bench/load.ts --nodes N` starts N nodes as separate Node processes (`scripts/bench/node.ts`,
cluster mode, node ids `a`, `b`, `c`; `a` seeds the database and leads), then runs 8 concurrent clients per node from
one load-generator process, each client pinned to one node. Each run resets the `gate_*` tables, warms up 2 s and
measures 15 s. The three sizes were run interleaved (1, 2, 3, 1, 2, 3, 1, 2, 3) to spread the machine's background
load over all of them; the table gives the median run and all three values.

```bash
for round in 1 2 3; do for n in 1 2 3; do
  node scripts/bench/load.ts --world=tmp/bench-small --mode=postgres --scenario=evaluation \
    --duration=15 --warmup=2 --concurrency=8 --nodes=$n --seed=20261108
done; done
```

PostgreSQL 17.11 (`postgres:17-alpine`, default configuration, `synchronous_commit = on`) in Docker 29.8.2 on the same
Apple M5 Pro (18 CPUs, 48 GiB; Docker VM 18 CPUs, 15.7 GiB, no CPU cap on the container), Node 22.23.3, macOS 26.5.1.
**The machine was not idle:** other workloads kept the 1-minute load average between 11.6 and 24.6 during these runs,
so single runs vary by up to 1.8 times; read the medians, not single figures.

| Nodes | Requests/s (median) | Requests/s, three runs | Per node (median run) | p50 ms | p99 ms | Errors | Scaling |
|---:|---:|---|---|---:|---:|---:|---:|
| 1 | 410.294 | 410.294, 538.037, 380.359 | 410.294 | 13.784 | 118.476 | 0 | 1.00× |
| 2 | 605.309 | 682.871, 605.309, 502.864 | 302.391 / 302.918 | 16.928 | 159.220 | 0 | 1.48× |
| 3 | 735.195 | 735.195, 945.842, 524.530 | 242.399 / 246.131 / 246.664 | 24.344 | 187.684 | 0 | 1.79× |

Two diagnostic runs (10 s each, same commands, not part of the table) show where the limit is:

- **One node does not go faster with more clients:** 24 clients on one node gave 555.391 requests/s, against 1,079.128
  for 8 clients on each of three nodes in the same minute. A single node is bound by its own event loop and its one
  writer connection, which is what the cluster removes.
- **With `synchronous_commit = off`** (a durability trade-off Qadamar does not recommend; measured only to locate the
  bottleneck), 1, 2 and 3 nodes gave 453.465, 831.002 and 1,670.086 requests/s: close to linear. With durable commits
  the nodes share PostgreSQL's WAL flush on this laptop's Docker disk, which is why the table scales sub-linearly
  (1.48× and 1.79×). On a database host with a faster log device the curve should sit between the two; not measured.

Correctness under load was checked by the tests rather than the benchmark (`packages/pdp-http/test/postgres.test.ts`,
cluster section): with a 500 ms bound, an approved policy change was decided on by every follower 13 to 163 ms after
the leader answered; a follower held behind refused decisions (503) until it caught up; after `pg_terminate_backend`
on every sync connection, followers were deciding again within 4 to 9 ms; when the leader stopped, a follower took the
admin plane 29 to 122 ms later while the two followers kept deciding with no failed request. These are test-run
observations on this laptop, not guarantees.

What this does not show: batch, search and filter scenarios with several nodes; more than three nodes; a database on its
own host; the load generator was one process, so above roughly a thousand requests per second it may itself limit.

## Start-up and takeover against audit length (2026-11-10)

What a starting (or taking-over) PostgreSQL node does before it opens its port, against the length of the audit
chain. Same laptop as above (Apple M5 Pro, Node 22.23.3, PostgreSQL 17 in Docker via `tools/ci/postgres.sh`, 2 CPUs,
1 GiB), measured once each, other work running on the machine: treat differences under about 20% as noise.

**Method.** `scripts/bench/startup.ts --rows N --tail 1000 --repeats 3` resets the `gate_*` tables, appends N decision
rows through the ledger (5,000 per commit), runs a full recheck (which stores the authenticated checkpoint), appends
1,000 more rows (written after the checkpoint, as on a busy active node), then three times: opens the ledger with the
checkpoint set to `null` (the whole chain verified before serving: what `GATE_PROFILE=production` did on every start
up to 0.4.2), and opens it from the checkpoint, timing the open, then the full background verification. `startMs` is
`PgLedger.open` (locks, migration check, documents, chain verification, counters), the part a takeover waits for.

| 1,001,000 rows | Start (min / median / max) | Rows read at start | Background full verification |
|---|---|---|---|
| Before: full chain at start (production up to 0.4.2) | 8,689 / 9,114 / 9,284 ms | 1,001,000 | none |
| Before: from checkpoint (demo profile only, counters aggregated over the table) | 1,318 / 1,359 / 1,542 ms | 1,001 | 8,776 / 8,958 / 9,282 ms |
| After: from checkpoint (every profile, counters in the checkpoint) | 77 / 93 / 115 ms | 1,001 | 8,339 / 9,089 / 9,096 ms |
| After: full chain (no checkpoint yet: first start, cleared after tampering) | 8,287 / 8,902 / 10,904 ms | 1,001,000 | none |

At 101,000 rows, after: from checkpoint 44 / 57 / 73 ms, full chain 680 / 719 / 1,590 ms, background verification
678 / 735 / 765 ms.

What this shows:

- **A production takeover no longer grows with the audit:** about 0.1 s at one million rows (it was about 9 s, and
  about 9 s more per further million). What remains is proportional to the rows written since the last full recheck
  (at most five minutes of traffic) plus the anchored rows.
- **The demo checkpoint alone was not enough:** it still spent about 1.3 s per million rows aggregating the audit
  counters over the whole table (`count(*)`, per-type and per-control evidence). The checkpoint now carries those
  counters under its HMAC, and the start adds the rows it reads after it.
- **The whole chain is still verified, after the port opens:** the background verification costs what the full start
  did (about 9 s per million rows on this laptop). That duration is the detection window for a row rewritten before
  the checkpoint (docs/API.md §3.9.1); `/readyz` reports `audit.fullChain: false` and `gate_audit_full_chain_verified`
  is 0 until it ends.
- Not measured here: end-to-end failover with a load generator at these lengths (`failover.ts` stops nodes before the
  five-minute recheck stores a checkpoint), and anything on server hardware.

## Affected-set impact previews (2026-11-11)

One laptop: the Apple M5 Pro (18 cores, 48 GiB), macOS 26.5.1, Node 22.23.3 described above. These are three sequential
in-process runs in one process, not production latency or throughput targets; there was no separate warm-up, and other
laptop work can account for the spread. The benchmark constructs no HTTP requests and writes no decisions or audit rows.

The world is the existing synthetic generator's 5,000 subjects, 50,000 cases and 5,000 allocations. The single-tuple
case adds one allocation. The policy case removes `finance-mask` after assigning `finance.amount` to one allocated case:
it selects 5,000 subjects × one resource × five case actions and produces two obligation losses. A mandatory-model or
broad ABAC edit can still select the whole grid and exceed the budget; this policy case is deliberately not such an edit.

```bash
node scripts/bench/world.ts --output=/tmp/gate-impact-bench-world --subjects=5000 --resources=50000 --tuples=5000 --seed=20261108
node scripts/bench/impact.ts --world=/tmp/gate-impact-bench-world --repeats=3
```

| Change | Affected cells | Evaluated with network variants | Three runs, ms | Median, ms | Reported delta |
|---|---:|---:|---|---:|---|
| No-op | 0 | 0 | 174.662 / 186.029 / 193.405 | 186.029 | none |
| One allocation tuple | 5 | 10 | 150.731 / 156.657 / 161.914 | 156.657 | 2 gained |
| Remove one content-mask rule | 25,000 | 50,000 | 849.337 / 919.887 / 1,041.228 | 919.887 | 2 obligations lost |

The roughly 0.15–0.19 s floor is the state diff and tuple-index setup, including on a no-op; zero cells does not mean
zero work. The policy run includes 100,000 before/after decisions over the selected cells. These measurements do not
compare against a full 5,000 × 50,000 preview: at five actions and two networks that would be 2.5 billion reported cell
evaluations before maker/history variants, far beyond the old default budget. Differential correctness is tested on
worlds where the full grid is feasible, not inferred from this benchmark.

## Per-record PostgreSQL storage (2026-11-11)

One run at each size on the same Apple M5 Pro laptop and local PostgreSQL 17 container described above, with other work
running. These are not capacity targets. `scripts/bench/records.ts` builds a legacy whole-document database and times
its real migration, then starts one leader and one follower. Registration is 1,000 independent single-resource
`POST /x/v1/resources` calls across 32 clients, each validated, audited and committed durably; no request is a batch.
Batch measures one `/x/v1/resources/sync` of 1,000 new records. Catch-up holds the follower during 20 further writes,
releases it, and times until an HTTP evaluation there sees the last resource.

```bash
node scripts/bench/records.ts --resources=100000 --registrations=1000 --concurrency=32 --batch=1000 --catchup=20
node scripts/bench/records.ts --resources=1000000 --registrations=1000 --concurrency=32 --batch=1000 --catchup=20
```

| Resources | Migration | Registration elapsed | Single registrations/s | Batch of 1,000 | Batch resources/s | Follower catch-up |
|---:|---:|---:|---:|---:|---:|---:|
| 100,000 | 1,145.256 ms | 412.559 ms | 2,423.898 | 68.765 ms | 14,542.238 | 33.067 ms |
| 1,000,000 | 17,371.402 ms | 509.586 ms | 1,962.376 | 69.560 ms | 14,376.164 | 27.676 ms |

The same runs on the previous commit (cee0921, before the three fixes below):

| Resources | Migration | Registration elapsed | Single registrations/s | Batch of 1,000 | Batch resources/s | Follower catch-up |
|---:|---:|---:|---:|---:|---:|---:|
| 100,000 | 1,168.821 ms | 4,534.464 ms | 220.533 | 507.032 ms | 1,972.263 | 381.397 ms |
| 1,000,000 | 22,464.083 ms | 4,891.240 ms | 204.447 | 702.302 ms | 1,423.888 | 361.273 ms |

What changed, each found by profiling this benchmark:

- **Catch-up: the record write did not notify.** The single-statement write (`postgres-fast-write.ts`) put `pg_notify`
  in a `SELECT` CTE the main query never referenced; PostgreSQL does not run such a CTE, so followers learned of record
  writes only at their poll tick (a quarter of the staleness bound, at most 500 ms). The statement now references it;
  catch-up is back to the delta work itself, as at b23b034 (about 39/34 ms there). A PostgreSQL test listens for it.
- **Single registrations: group commit.** Each request queued a write of its own behind the running one; the queued
  write drained every request staged meanwhile, but each later request still paid a transaction of its own, so 1,000
  registrations took about 970 transactions. A request now joins the write already queued and not started, which
  drains everything staged before it starts: one transaction and one fsync per group, each request still answered only
  after the COMMIT holding its rows. Alone this took 100k from 220.533 to about 1,138 registrations/s.
- **Validation is pairwise.** Level inheritance compares a resource with its parent only, but each registration also
  rechecked every child of every ancestor, so registering under one folder grew with that folder's size (the batch was
  quadratic). Only changed resources and the children of changed resources are checked now; the randomized test
  against full-world validation still holds.

The earlier whole-array implementation measured 15.628/s at 100k and 1.185/s at 1M under a sequential 100-write
version of this benchmark. Single registrations now pass the requested **1,000/s** on this laptop, at 32 concurrent
clients; a lone sequential client still pays one durable commit per request (about 3 ms here). A diagnostic with
`synchronous_commit=off` was never used for these results or in production. Each figure is one run.

Every node still holds the full world and decision indexes in memory. Startup memory and the full-snapshot fallback were
not timed. Gap correctness is covered by a PostgreSQL test. Migration is measured above; it is one-time and runs before
nodes serve traffic.

## Decision-only PostgreSQL statements (2026-11-11)

One run before and one after the decision-write optimization on the same Apple M5 Pro (18 cores, 48 GiB), macOS
26.5.1 and Node 22.23.3 as above. PostgreSQL used the local `postgres:17-alpine` container started by
`tools/ci/postgres.sh` (2 CPUs, 1 GiB, default configuration, `synchronous_commit = on`). The large world was the same
generated 5,000-subject, 50,000-resource, 5,000-tuple dataset and seed. Each single-evaluation run warmed up for 2 s
and admitted requests for 20 s, then drained. The three before runs completed first, followed by the three after runs;
these are laptop observations, not production targets.

```bash
node scripts/bench/load.ts --world=/tmp/gate-throughput-large --mode=postgres --scenario=evaluation \
  --duration=20 --warmup=2 --concurrency=8 --seed=20261108
# Repeat with --concurrency=32 and --concurrency=64.
```

| Concurrency | Requests/s before | Requests/s after | Change | p50 ms before → after | p99 ms before → after | Errors |
|---:|---:|---:|---:|---:|---:|---:|
| 8 | 2,057.079 | 2,678.269 | 1.30× | 3.410 → 2.010 | 8.677 → 9.177 | 0 / 0 |
| 32 | 5,554.612 | 7,312.518 | 1.32× | 5.316 → 3.641 | 13.818 → 13.933 | 0 / 0 |
| 64 | 7,165.896 | 8,263.535 | 1.15× | 8.420 → 6.903 | 16.532 → 32.136 | 0 / 0 |

The baseline here is the code immediately before this change, which already had group commit; it is not the older
482.367 requests/s measurement above. Median latency improved at every concurrency. Tail latency did not: p99 was
almost unchanged at 8 and 32, and was 15.604 ms higher at 64. One run cannot separate the effect of deeper queues from
ordinary tail variation. Raw JSON reports were kept outside the repository.

### What profiling showed

A separate 5 s diagnostic at concurrency 32 wrapped the real PostgreSQL client's queries. Before the change it observed
1,496 groups and 23,936 audit rows (16.000 rows/group). After it observed 2,877 groups and 33,670 rows (11.703/group).
Groups form from requests already staged when the writer becomes available; there is no artificial wait or fixed target
batch size, so a faster writer can drain smaller groups.

| Writer operation before | Mean ms/group |
|---|---:|
| `BEGIN` | 0.218 |
| Multi-row audit `INSERT` | 1.151 |
| Multi-row metadata `INSERT` | 1.062 |
| `COMMIT`, including the durable WAL wait | 0.884 |
| **Total of the four round trips** | **3.315** |

After the change, one prepared statement containing the audit and metadata CTEs took **1.666 ms/group** (p50 1.373,
p99 4.295), including its implicit durable commit. This removes network round trips and statement overhead, not the WAL
flush. The per-row CPU microbenchmark measured 1.499 µs for event bounding, 1.347 µs for canonical serialization and
0.515 µs for SHA-256, so serialization and hashing were not the database-path bottleneck. The per-node advisory chain
lock is taken at startup, not per decision. This workload had no BLP session marks or decision-token rows; the combined
token/mark statement is covered by a real-PostgreSQL correctness test, but their performance was not measured here.

The implementation retains the same per-node chain, row order, metadata, checkpoints, anchors and fail-stop behavior.
A decision-only statement is atomic and returns only after its implicit transaction is durable; mixed state writes keep
explicit `BEGIN`/`COMMIT` transactions. A mark-relevant BLP session decision (below) keeps its own explicit transaction
under the session advisory lock; its decision-only statement then runs inside that transaction, before its `COMMIT`.

## BLP session ordering diagnostics (2026-11-11)

These are test diagnostics on the development laptop, not capacity results. They cover only the new ordering cost; the
worlds, HTTP stack and database are the small test fixtures. In a focused run,
`packages/pdp-http/test/session-ordering.test.ts` ran 5,000 trivial concurrent tasks with no session queue at
561,656/s and with independent local session queues at 187,780/s (**5.33 µs per queued task**). During the full test
suite the same microbenchmark measured 205,522/s and 70,384/s (**14.21 µs**), showing the effect of machine load. It
excludes authorization, audit, HTTP, files and PostgreSQL. In the focused HTTP barrier test, 16 independent session
reads completed in 18.8 ms while one session was held after its decision, and a no-session write completed in 0.7 ms;
the held session's later write waited and was then denied.

With two cluster nodes sharing the throwaway PostgreSQL 17 database, the `throughput: independent sessions` test in
`packages/pdp-http/test/postgres.test.ts` issued 24 requests per node concurrently. In the focused run, 48 no-session
decisions completed in 66.5 ms (**721.4/s**) and 48 reads in 48 independent sessions in 66.6 ms (**720.7/s**). During
the full suite the figures were 63.6 ms (**754.9/s**) and 82.4 ms (**582.3/s**), the session run about 23% slower.
Each session decision adds the advisory-lock acquisition and reads the mark on the writer connection inside its commit
transaction. These two runs are observations, not a bound on overhead or an SLA. Same-session requests intentionally
wait for one another; different sessions have different advisory locks, and no-session requests and L0 reads bypass them.

## Stateless replicas: 1 leader + 2 replicas against 3 cluster nodes (2026-11-11)

Replicas (API.md §3.9.5) decide without a database: each decision is answered after an `fdatasync` of the replica's
own audit file, and the rows reach PostgreSQL later, by ingestion on the database node. Same laptop and world as the
cluster section (small world, single evaluations, every decision audited durably before its answer), measured on this
branch.

**Method.** `scripts/bench/load.ts --nodes=3` (three cluster nodes, as above) against `--nodes=1 --replicas=2`: node `a`
(cluster mode, with `GATE_REPLICA_KEYS`) plus two replica processes (`scripts/bench/node.ts` with `GATE_REPLICA_OF`, no
`DATABASE_URL`, each with its own `DATA_DIR` on the laptop's SSD). The load generator pins the same number of clients to
each of the three processes. 15 s measured after 2 s of warm-up, the two topologies interleaved, three rounds at 8 and
then at 32 clients per process.

```bash
for c in 8 32; do for round in 1 2 3; do for cfg in "--nodes=3" "--nodes=1 --replicas=2"; do
  node scripts/bench/load.ts --world=tmp/bench-small --mode=postgres --scenario=evaluation \
    --duration=15 --warmup=2 --concurrency=$c $cfg --seed=20261108
done; done; done
```

Apple M5 Pro, Node 22.23.3, PostgreSQL 17 (`postgres:17-alpine`, default configuration, `synchronous_commit = on`) in
Docker on the same machine. The machine was not idle (1-minute load average 8.5 to 12.2 during the runs).

| Clients per process | Topology | Requests/s (median) | Three runs | Per process (median run) | p50 ms | p99 ms | Errors |
|---:|---|---:|---|---|---:|---:|---:|
| 8 | 3 cluster nodes | 3,177.542 | 3,177.542, 3,043.003, 3,507.548 | 1,056.915 / 1,060.580 / 1,060.047 | 5.942 | 43.300 | 0 |
| 8 | 1 leader + 2 replicas | 1,282.777 | 1,365.698, 1,245.053, 1,282.777 | leader 129.004 / replicas 575.089, 578.685 | 14.073 | 93.384 | 0 |
| 32 | 3 cluster nodes | 7,977.754 | 9,217.082, 7,977.754, 6,961.781 | 2,653.722 / 2,666.780 / 2,657.253 | 10.027 | 55.319 | 0 |
| 32 | 1 leader + 2 replicas | 3,616.003 | 4,202.142, 3,462.686, 3,616.003 | leader 891.238 / replicas 1,360.685, 1,364.080 | 19.676 | 169.948 | 0 |

**On this laptop the replica topology is slower: 0.40× the cluster at 8 clients per process, 0.45× at 32.** What the
numbers show, and two diagnostics that locate it:

- **A replica is bound by its own durable write.** Node on macOS turns `fdatasync` into `F_FULLFSYNC`, a flush of the
  drive's cache: 3.67 ms per append + `fdatasync` on this SSD (200 calls, measured). A replica's group commit pays one
  per group, so with 8 clients it answers about 575 decisions/s. A diagnostic build that skipped that `fdatasync` (not
  shipped, never a configuration) gave 8,758 and 8,366 requests/s for the same 8-client runs, the replicas at 3,855 to
  4,088 each: without the flush a replica decides about four times faster than a cluster node, since it has no database
  round trip. On a Linux host with an NVMe log device `fdatasync` typically costs a fraction of that; not measured here.
- **The two durability costs are not equal here.** PostgreSQL's WAL `fdatasync` runs inside Docker's Linux VM (a
  `sync` there measured under 1 µs) and does not pay the host drive-cache flush that the replicas pay, so this
  comparison favours the cluster; it is the comparison the laptop allows.
- **The leader slows down while it serves replicas** (129 decisions/s against about 1,060 for a cluster node): its WAL
  syncs share the one SSD with the replicas' `F_FULLFSYNC` calls, and the database writes every replica row as well
  (ingestion, on a connection of its own; at 8 clients about 1,150 replica rows/s). Sampling `pg_stat_activity` during
  such a run showed both the leader's writer and the ingestion connection mostly in `IO:WalSync` and
  `LWLock:WALWrite`. The database stays the place where every audit row is written: its write capacity bounds the
  total audit volume whatever the topology.

What replicas change, independent of throughput on this machine: no deciding node holds a PostgreSQL connection or
waits for a database round trip per decision (the database is needed for the state feed within the staleness bound and
for audit ingestion within the audit-lag bound); replica decisions keep their latency when the database is slow but
reachable; and replicas can be added without adding database connections. What this does not show: replicas on hosts
of their own (the realistic deployment), a database on its own host, batch, search and filter scenarios, more than two
replicas, and Linux `fdatasync` costs.

**Propagation (tests, `packages/pdp-http/test/replica.test.ts`, 500 ms bound).** A subject disabled by an approved
change was decided on by the replica 25 to 55 ms after the approval returned, and a revoked PEP credential was refused
by the replica 24 to 116 ms after the revoke (the 116 ms with the whole test suite running at once; test runs while
building this, on this laptop): the commit wakes the
held feed request at once. A replica whose feed is held refuses decisions once the bound has passed since its last
confirmation (489 ms after the feed was held, bound 500 ms, in the last run) and decides again after the next
verified answer (489 ms after the feed returned, the feed loop's retry backoff).
Test-run observations, not guarantees.

## Indexed AuthZEN search candidates (2026-11-11)

One run before and one after on the same Apple M5 Pro laptop, Node 22.23.3 and synthetic large world (5,000 subjects, 50,000
resources, 5,000 tuples, seed 20261108) described above. PostgreSQL was the local 17 container. Each scenario used concurrency 1,
a 1 s warm-up and a 5 s request-admission window, then drained. The before code was the committed parent, which already built one
residual per resource search but evaluated it against every candidate; this is not another measurement of the 111 s pre-prefilter
baseline above. Other laptop work was not excluded, so these are observations, not latency guarantees.

```bash
node scripts/bench/world.ts --output=/tmp/gate-search-baseline-world --subjects=5000 --resources=50000 --tuples=5000 --seed=20261108
node scripts/bench/load.ts --world=/tmp/gate-search-baseline-world --mode=file --scenario=search --duration=5 --warmup=1 --concurrency=1 --seed=20261108
# With TEST_DATABASE_URL set to the throwaway local database, repeat with --mode=postgres.
```

| Mode | Version | Requests | Requests/s | p50 ms | p95 ms | p99 ms | Max ms | Errors |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| File | Before | 204 | 40.726 | 23.056 | 33.222 | 40.928 | 50.822 | 0 |
| File | After | 3,897 | 779.380 | 1.155 | 2.216 | 3.154 | 15.299 | 0 |
| PostgreSQL | Before | 64 | 12.740 | 67.739 | 144.422 | 208.187 | 208.187 | 0 |
| PostgreSQL | After | 1,175 | 234.940 | 3.277 | 7.825 | 23.563 | 139.513 | 0 |

A CPU profile of the before file run attributed about 28% of sampled time to residual path resolution and 25% to canonical JSON
construction/comparison. The index now resolves each used resource path once per stored-array generation, groups equal JSON values,
and combines original-position bit sets with separate TRUE and FALSE sets. Relation known ids still come from reverse graph
traversal. Full point decisions run only for survivors, including on SoD actions; subject search likewise shares forward relation
reachability before its point checks. In-place record patches invalidate the index.

The first use of an attribute path still costs a pass over the stored resources, and index memory grows with resource count and
distinct values on paths the policy reads. These runs do not isolate that one-time or memory cost: the after runs produced far more
audit rows, so their before/after heap samples are not an index-memory comparison. PostgreSQL's 139.513 ms maximum also shows that
the tail is not uniformly tens of milliseconds. Subject and action searches were covered by differential tests but not separately
benchmarked. Raw JSON reports and the CPU profile were kept outside the repository.


## Tenant partition memory (2026-11-11)

The existing architecture has a single tenant per store: subjects and resources do not contain tenant keys. Tenant
partitioning therefore selects **whole isolated runtimes**, with separate stores and security namespaces, rather
than removing graph vertices from a shared world. `GATE_TENANTS_FILE` describes the worlds and
`GATE_SERVE_TENANTS` selects those loaded by a node or replica (see DEPLOY.md, Tenant partitions).

### Reproduce and scope

```sh
node scripts/bench/memory.ts
# Optional total counts per kind, each at most 500000:
node scripts/bench/memory.ts 10000,100000,500000
```

No database, downloads or generated world files are needed. Every case runs in a fresh Node process with
`--expose-gc`. Ten deterministic tenants have equal numbers of subjects, resources and allocated relation tuples;
ids intentionally overlap between tenants. Each subject is an active investigator with L3 clearance; each resource
is a L1 case with an owner and one status attribute. The toy bundle is shared by the benchmark worlds.
The first case retains all ten worlds; the second retains only the first. At 500k **per kind**, that means 1.5 million
records across all tenants versus 150,000 on one partition. Counts below are per kind, not total records.

Samples follow forced GC: baseline, world arrays loaded, then the real PDP lookup/position and relation indexes
primed plus resource-search type and `resource.attrs.status` path indexes warmed. Output reports RSS, heap,
external/array-buffer memory, retained index heap delta, lookup-map entries, relation keys/references, search position
entries and bitset bytes. Cardinalities describe this fixture’s known unique-id, one-tuple-per-object shape; heap
delta measures all these retained indexes together, not a serialized-size estimate. GC and allocator behavior make
RSS noisy. No attempt was made to force memory back to the OS.

This is an **engine retained-memory benchmark**, not an HTTP server/replica startup peak or a throughput test. It
excludes credentials, audit retention, PostgreSQL connections, feed buffers, policy impact previews and HTTP traffic.
High-cardinality policy attributes and dense/userset graphs can cost substantially more. It does not establish a
production limit or demonstrate a reduction within one tenant. The separate runtime selection and actual PostgreSQL
replica behavior are exercised by `packages/pdp-http/test/tenants.test.ts`.

Measured on macOS arm64, Apple M5 Pro, 48 GiB RAM, Node 22.23.3. One sequential run, not an average; raw byte
samples are committed in [memory-2026-11-11.jsonl](../scripts/bench/results/memory-2026-11-11.jsonl).

| Total per kind | Served tenants | Loaded per kind | RSS after indexing MiB | Heap after indexing MiB | Index heap delta MiB |
|---:|---:|---:|---:|---:|---:|
| 10,000 | 10 / 10 | 10,000 | 130.2 | 24.4 | 10.5 |
| 10,000 | 1 / 10 | 1,000 | 94.3 | 9.8 | 1.1 |
| 100,000 | 10 / 10 | 100,000 | 308.1 | 187.6 | 122.2 |
| 100,000 | 1 / 10 | 10,000 | 132.5 | 26.2 | 12.3 |
| 500,000 | 10 / 10 | 500,000 | 998.2 | 875.3 | 581.0 |
| 500,000 | 1 / 10 | 50,000 | 212.9 | 95.0 | 58.2 |

At 500k per kind, selecting one tenant reduced retained indexed RSS by 78.7% and index heap by
90.0%. Fixed process overhead keeps RSS from scaling exactly with record count. This comparison changes
the assignment from all ten tenants to one; it preserves every record of the served tenant. No compact index
representation change is included, and these figures must not be presented as compressing an individual world.

For that largest fixture the all-tenant case has 4.5 million lookup-map entries, 500k relation object keys and 500k
subject keys, one million tuple references in those two maps, and 500k object ids in type lists. The one-tenant case
has one tenth of those counts. Each resource-search path additionally retains a position per resource and two
bitsets (defined/missing), plus a type bitset. In this fixture status has one distinct value per tenant; real policy
attributes with many distinct values need their own measurement.

Operational limits: assignment changes need a restart, one tenant’s full graph still stays resident, and runtime and
connection overhead grows with the number of served tenants. PostgreSQL remains a separate database per tenant;
there is no new shared-table tenancy or intra-tenant graph sharding. Differential tests compare standalone/all-tenant
and selected-tenant decisions, batches, resource/subject search, SQL output and PostgreSQL query results, then apply
an approved revocation and check cluster/replica convergence and tenant-specific audit chains and rate leases.
