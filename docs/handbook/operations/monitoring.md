# Monitoring and alerts

Qadamar exposes public liveness, readiness, and leader probes, process-local Prometheus metrics, audit verification endpoints, and optional OTLP traces. Monitor both service availability and evidence freshness, and add log and SIEM sequence checks, because several failure modes have no dedicated metric. This page describes the code at commit b09bc44 (after 0.3.0) and the alert rules shipped in `deploy/k8s/monitoring/alerts.yaml`.

## On this page

- [Probe health, readiness, and leadership](#probe-health-readiness-and-leadership)
- [Metrics reference](#metrics-reference)
- [Route families](#route-families)
- [Alert rules shipped for Kubernetes](#alert-rules-shipped-for-kubernetes)
- [Recommended alerts](#recommended-alerts)
- [Traces and logs](#traces-and-logs)
- [Operational caveats](#operational-caveats)

## Probe health, readiness, and leadership

| Endpoint | Authentication | Answer | Use |
| --- | --- | --- | --- |
| `GET /healthz` | None | `200 {"status":"ok"}` when the process answers HTTP. Checks nothing else. | Liveness only. |
| `GET /readyz` | None | `200 {"status":"ready","active":true,"audit":{"verified":true}}` when pending writes commit and the audit verifies. With PostgreSQL the body adds `role` (`leader` or `follower`), `node`, and `audit.fullChain` (false while the background verification after a start from the checkpoint runs). Otherwise `503 {"status":"unavailable"}`. | Load-balancer readiness. |
| `GET /leaderz` | None | `200 {"leader":true}` on the leader, and on any node outside cluster mode. `503 {"leader":false}` on a follower. With PostgreSQL the body adds `node`. | Cluster mode: route `/admin/` and `/scim/` to the node answering 200. |
| `GET /metrics` | `Authorization: Bearer $METRICS_TOKEN` whenever the node binds a non-loopback address; without a token there it answers 403. On loopback it is public unless a token is set. | Prometheus text format. Production requires a token of at least 32 characters. | Scrape over a protected path. |

`/readyz` results are cached for 5 seconds of real time. With PostgreSQL the audit part uses the shared recheck, which can be up to 60 seconds old (`packages/pdp-http/src/metrics.ts`, `postgres.ts`).

In cluster mode, `/readyz` also returns 503 while the node has not confirmed the shared state within `GATE_MAX_STALENESS_MS` (default 2000 ms). Freshness is evaluated on every call, not cached. The same node answers PDP requests with `503 unavailable` until it catches up.

In active/standby mode, a standby opens no port while it waits, so it answers no probe and cannot be scraped. Monitor it through its supervisor and logs (`packages/pdp-http/src/server.ts`).

Every request, probes and scrapes included, counts against the per-IP rate limit of 120 requests per minute (`packages/pdp-http/src/router.ts`). Behind a proxy, the IP is the client address resolved through `TRUSTED_PROXIES`; without it, every client and probe behind the proxy shares one bucket ([Reverse proxy settings](configuration.md#reverse-proxy-settings)).

## Metrics reference

Source: `packages/pdp-http/src/metrics.ts`. Counters and histograms are process-local and restart from zero after a restart or failover.

| Metric | Type and labels | Meaning and cautions |
| --- | --- | --- |
| `gate_decisions_total` | Counter, `effect` = `allow` or `deny` | Decisions appended to this node's audit log. Denials are often normal policy outcomes. |
| `gate_http_request_duration_seconds_bucket` | Histogram, `route`, `le` | Request latency by [route family](#route-families). Bounds: 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30 seconds, and `+Inf`. A route family appears after its first request. |
| `gate_http_request_duration_seconds_sum`, `_count` | Histogram, `route` | Total seconds and request count per route family. Includes probes and errors. There is no status label. |
| `gate_audit_length` | Gauge | Head sequence of the audit chain this node writes. In cluster mode each node reports its own chain. It is not a verification result. |
| `gate_audit_full_chain_verified` | Gauge | PostgreSQL: 1 once every chain was verified from its genesis since the process started; 0 while the background verification after a start from the checkpoint runs, and after an integrity failure. Alert `GateAuditFullChainUnverified` fires when it stays 0 for 15 minutes; keep that above one full recheck of your log (about 9 s per million rows on a laptop). |
| `gate_audit_last_anchor_age_seconds` | Gauge | Seconds since the latest anchor's TSA `genTime`, never below 0; `-1` when no anchor exists. |
| `gate_commit_duration_seconds_bucket`, `_sum`, `_count` | Histogram, `le` only | Latency of state and audit commits. Observed only in PostgreSQL mode; in file mode the series stay at zero. Same bounds as above. |
| `gate_active_node` | Gauge | Always `1` on a process that answers the scrape. In cluster mode every serving node reports 1, so it does not identify the leader; use `/leaderz`. |
| `gate_break_glass_notices_total` | Counter, `outcome` = `sent` or `failed` | Break-glass webhook notices delivered, or given up after the last retry. In cluster mode notices are sent by the leader. |

No metric label carries a subject, resource, principal, IP address, raw path, or secret.

### Useful queries

The examples use Grafana's `$__rate_interval`; substitute a window suited to your scrape interval.

Decision rate by effect:

```promql
sum by (effect) (rate(gate_decisions_total[$__rate_interval]))
```

Request latency by route family:

```promql
histogram_quantile(0.99,
  sum by (le, route) (
    rate(gate_http_request_duration_seconds_bucket[$__rate_interval])
  )
)
```

Commit latency:

```promql
histogram_quantile(0.99,
  sum by (le) (rate(gate_commit_duration_seconds_bucket[$__rate_interval]))
)
```

Break-glass notices given up after retries:

```promql
increase(gate_break_glass_notices_total{outcome="failed"}[$__rate_interval])
```

These queries are starting points, not service-level objectives. Set thresholds from your own measurements.

## Route families

`routeFamily()` bounds the `route` label (`packages/pdp-http/src/metrics.ts`):

| Label | Requests |
| --- | --- |
| `health` | `/healthz` |
| `readiness` | `/readyz` |
| `metrics` | `/metrics` |
| `discovery` | `/.well-known/authzen-configuration` |
| `evaluation` | `/access/v1/evaluation` |
| `evaluations` | `/access/v1/evaluations` |
| `search` | Any `/access/v1/search/*` |
| `explain` | `/x/v1/explain` |
| `filter` | `/x/v1/filter` |
| `tokens` | `/x/v1/tokens/consume` |
| `xacml` | `/xacml/v3/authorize` |
| `session` | `/admin/v1/session` |
| `oidc` | Any `/admin/v1/oidc/*` |
| `admin` | Other `/admin/v1/*` |
| `static` | Everything else |

`static` includes `/leaderz`, `/.well-known/jwks.json`, `/x/v1/assertions/evaluation`, `/x/v1/assertions/list`, `/scim/v2/*`, console assets, and unknown paths. Derive error rates from an ingress or logs, because status is not a label.

## Alert rules shipped for Kubernetes

`deploy/k8s/monitoring/alerts.yaml` is a Prometheus Operator `PrometheusRule` named `qadamar`, written for the managed offer's active/standby tenants in namespaces `gate-*`. It assumes the scrape job sends the metrics token and keeps `namespace` and `pod` labels, that kube-state-metrics runs, and that the ingress controller is ingress-nginx. Thresholds marked as parameters in the file are starting values, not service levels.

| Alert | Severity | Expression (summary) | For |
| --- | --- | --- | --- |
| `GateNoActiveNode` | critical | No ready replica of Deployment `gate` (`kube_deployment_status_replicas_ready < 1`), or no Qadamar pod answers its scrape (`sum(up) < 1`) | 1m |
| `GateActiveNodeNotReady` | critical | `gate_active_node == 1` in the namespace while no Qadamar pod is Ready (`kube_pod_status_ready`) | 2m |
| `GateFailover` | warning | More than one pod reported `gate_active_node == 1` within 15 minutes | none |
| `GateAnchoringStale` | warning | `gate_audit_last_anchor_age_seconds > 7200` (2 × the default `ANCHOR_INTERVAL`), or `== -1` while `gate_audit_length > 0` | 15m |
| `GateAuditFullChainUnverified` | warning | `gate_audit_full_chain_verified == 0`: the whole chain not verified from its genesis since start (background verification still running, or an integrity failure) | 15m |
| `GateBackupMissing` | warning | No successful `gate-backup` CronJob run for 93600 seconds (26 hours), or a failed `gate-backup-*` Job | 10m |
| `GateCommitLatencyHigh` | warning | p99 of `gate_commit_duration_seconds` over 5 minutes above 0.25 seconds | 10m |
| `GateHigh5xxRate` | critical | Share of 5xx in `nginx_ingress_controller_requests` above 0.02 over 5 minutes | 5m |

The standby's scrape always fails because it has no port; no rule alerts on a single failed scrape. Runbook actions per alert are in [docs/MANAGED-OFFER.md §8](../../MANAGED-OFFER.md#8-on-call-alerts-deployk8smonitoringalertsyaml).

**Partial:** there is no `gate_audit_verified` metric, so `GateActiveNodeNotReady` infers integrity failure from readiness, and no rule alerts on `gate_break_glass_notices_total{outcome="failed"}`. The rules are not adapted to cluster mode: `GateFailover` and `GateActiveNodeNotReady` assume one serving pod.

## Recommended alerts

For deployments outside the shipped rules, or in addition to them:

| Condition | Detection | Response |
| --- | --- | --- |
| No serving node | Supervisor down, scrape absent, or `/healthz` failing on every node | Check whether a standby took over, or a follower took the lead; follow [Fail over the active node](failover.md). |
| Readiness unavailable | `/readyz` returns 503 beyond its 5-second cache | Remove the node from traffic. Inspect storage, staleness, and audit logs before restarting. |
| Cluster: no leader | No node returns 200 on `/leaderz` | Admin plane and SCIM unavailable; see [Leader change in cluster mode](failover.md#leader-change-in-cluster-mode). |
| Cluster: node stale | `/readyz` returns 503 on one node while others are ready | Check that node's database connectivity and `State sync` log lines. |
| Audit verification false | `/admin/v1/audit/verify` returns `verified: false`, or logs report a broken chain or checkpoint | Follow [Respond to an audit tamper alert](audit-tamper-response.md). |
| No anchor yet | `gate_audit_last_anchor_age_seconds == -1` after anchoring should have run | Check `TSA_URL`, the leader's logs, and `GET /admin/v1/audit/anchors`. |
| Anchor stale | Age exceeds `ANCHOR_INTERVAL` plus your tolerated TSA delay | Check TSA availability and `lastError`. Verify the chain before assuming an export problem. |
| Break-glass notice failed | Failed-outcome counter increases or a `notify_failed` audit row appears | Notify through an independent channel and follow [Review break-glass access](break-glass-review.md). |
| Commit latency degrades | Commit histogram exceeds your budget | Check PostgreSQL primary health, locks, and load. |
| Audit stops growing during known decisions | `gate_audit_length` flat while decisions succeed | Check storage and audit integrity at once. |
| SIEM lag or fork | The receiver's highest contiguous sequence falls behind, or one sequence arrives with different bytes | Check exporter logs and cursor. Different bytes are an integrity incident. |

Qadamar exposes no metric for SIEM cursor lag, dropped trace spans, staleness age, reader reconnects, or process memory. Use host monitoring and external SIEM and collector health checks.

## Traces and logs

### OTLP spans

With `OTEL_EXPORTER_OTLP_ENDPOINT`, Qadamar exports OTLP/HTTP JSON spans (`packages/pdp-http/src/tracing.ts`):

- one SERVER span per request, named `<METHOD> <route family>`, with `http.request.method`, `http.response.status_code`, `gate.route_family`, and `client.address` (the address resolved through `TRUSTED_PROXIES`);
- `gate.decision` spans with effect and rule IDs, and `gate.commit` spans for PostgreSQL commits;
- `gate.dropped_child_spans` on a request span when more than 100 child spans were suppressed.

Spans carry no subject, resource, action name, raw path, header, credential, session ID, or error message. An incoming unsampled `traceparent` suppresses the request trace.

The exporter queues at most 2,048 spans, sends batches of up to 512, and never delays a response. It retries on 429, 502, 503, and 504 and drops the batch on any other non-2xx status. A full queue drops new spans. Dropped spans are not exposed as a metric.

### Log lines to route into operations review

- `Storage failure, stopping:` — fail-stop after a storage error;
- `Readiness check failed:` — commit, recheck, or verification failure;
- `Audit periodic recheck failed (n/3):` — three consecutive failures stop the node;
- `Audit checkpoint does not match the stored chain` — treated as tampering;
- `AUDIT INTEGRITY FAILURE:` — a recheck found a rewritten or missing row while serving: audited actions are refused, follow the tamper runbook;
- `Audit background verification complete` — the whole chain verified after a start from the checkpoint;
- `Audit read connection failed:` — reconnect in progress;
- `Audit anchoring failed:` — TSA or verification problem;
- `Audit metadata repaired:` — derived metadata rebuilt; explain it;
- `SIEM export failed:` — the batch stays at its cursor for retry;
- `Break-glass notice outcome not recorded:` — the failure could not be persisted;
- `State sync connection lost:`, `State sync failed:` — cluster node at risk of passing its staleness bound;
- `Node <id> took the leader lock: the admin plane is served here`, `Leader takeover failed:` — cluster leader change;
- `Trace export failed; retrying with backoff` — collector degradation.

Do not log environment variables, `DATABASE_URL`, bearer headers, CSRF tokens, initial credentials, or response business content in your supervisor or ingress.

## Operational caveats

- Metrics restart at zero after a restart or failover. Use `rate()` and `increase()`, and annotate failovers.
- In active/standby mode, `gate_active_node` has no zero series on a standby. Model availability from scrape absence plus process supervision.
- `/readyz` and `/admin/v1/audit/verify` can reuse a recent PostgreSQL recheck. Note their timing during incident triage.
- `gate_audit_length` is a head value for one node's chain. It does not prove the chain is valid or anchored.
- Benchmarks disable the rate limiter. Do not compare benchmark request rates with a deployment that keeps the 120-per-minute buckets ([Capacity and performance](capacity.md)).

## Related pages

- [Configuration reference](configuration.md)
- [Capacity and performance](capacity.md)
- [Fail over the active node](failover.md)
- [Respond to an audit tamper alert](audit-tamper-response.md)
- [Review break-glass access](break-glass-review.md)
- [Audit and evidence](../architecture/audit-and-evidence.md)
