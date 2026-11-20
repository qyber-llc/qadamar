# Operate Qadamar

An operator runs the PDP and the console, protects signing and backup material, watches readiness and audit integrity, and rehearses recovery. This page lists the operator's tasks and routes each one to its runbook. The operations runbooks and the repository documents they cite are the procedures of record; this page does not repeat them.

## On this page

- [Who this guide is for](#who-this-guide-is-for)
- [What you need](#what-you-need)
- [Choose the deployment mode](#choose-the-deployment-mode)
- [Find the runbook for a task](#find-the-runbook-for-a-task)
- [Use the reference documents](#use-the-reference-documents)

## Who this guide is for

Operators deploy, configure, monitor, back up, upgrade, and recover Qadamar. Two runbooks also need people with console roles: verifying the audit chain after a tamper alert needs an auditor or security officer, and closing a break-glass event needs a security officer who did not open it.

## What you need

- PostgreSQL for any deployment that is not a local demonstration. File mode keeps state in local JSON files and is for the walkthrough in [Get started](getting-started.md).
- A secret store for `SIGNING_KEY_SEAL`, `BACKUP_ENCRYPTION_KEY`, `METRICS_TOKEN`, the OIDC client secret, and the webhook secrets. A backup does not contain `SIGNING_KEY_SEAL`, so keep that key independently.
- `GATE_PROFILE=production` on production nodes. The server then refuses to start unless every production check passes (`packages/pdp-http/src/profile.ts`). [Troubleshoot startup refusal](../operations/deploy.md#troubleshoot-startup-refusal) explains each refusal.

Every environment variable, with its default and range, is listed in `docs/CONFIGURATION.md`. That file is generated from the code and checked in CI. [Configuration reference](../operations/configuration.md) groups the variables by task.

## Choose the deployment mode

| Mode | Behaviour | Where it is described |
|---|---|---|
| File mode | Local demonstration only | [Get started](getting-started.md), [Run a file-backed demonstration](../operations/deploy.md#run-a-file-backed-demonstration) |
| PostgreSQL, single active node | One node decides and administers. Standbys wait on a database advisory lock and take over when the active node stops. | [Deploy Qadamar](../operations/deploy.md), [Fail over the active node](../operations/failover.md) |
| PostgreSQL, cluster mode (`GATE_CLUSTER=true`) | Every node decides. One leader holds the admin plane. | [Deploy in cluster mode](../operations/deploy.md#deploy-in-cluster-mode), [Leader change in cluster mode](../operations/failover.md#leader-change-in-cluster-mode), [ADR 0011](../architecture/decisions/0011-cluster-mode.md) |
| Managed offer on Kubernetes | One dedicated Qadamar per customer, run by the provider | [Deploy the managed offer on Kubernetes](../operations/deploy.md#deploy-the-managed-offer-on-kubernetes), [docs/MANAGED-OFFER.md](../../MANAGED-OFFER.md) |

In cluster mode, three behaviours affect routing and alerting:

- `GET /leaderz` answers 200 on the leader and 503 on a follower. Route `/admin/` and `/scim/` to the node that answers 200. Outside cluster mode it always answers 200.
- A follower answers every `/admin/` and `/scim/` request with 409 `{"error":"not_leader","leader":...}`. `leader` is the leader's `GATE_ADVERTISE_URL`, or `null` when none is set.
- A node that has not confirmed the shared state within `GATE_MAX_STALENESS_MS` (default 2000, range 100–60000) answers PDP requests with 503 `unavailable`. Route PEP traffic so that a 503 is retried on another node: the SDK and the gateway do not retry (the gateway answers 503 `pdp_unavailable`).

Sources: `packages/pdp-http/src/router.ts`, `packages/pdp-http/src/postgres.ts`.

## Find the runbook for a task

| Task | Runbook |
|---|---|
| Deploy, verify, and troubleshoot startup | [Deploy Qadamar](../operations/deploy.md) |
| Set or change configuration | [Configuration reference](../operations/configuration.md), `docs/CONFIGURATION.md` |
| Watch probes, metrics, traces, and logs | [Monitoring and alerts](../operations/monitoring.md) |
| Size and measure the deployment | [Capacity and performance](../operations/capacity.md) |
| Rotate PEP credentials, signing keys, and SCIM, webhook, IdP, and database secrets | [Rotate keys and credentials](../operations/rotate-credentials.md) |
| Take over from a failed or retiring active node | [Fail over the active node](../operations/failover.md) |
| Back up, restore, and run the recovery drill | [Back up and restore](../operations/backup-restore.md) |
| Upgrade or roll back | [Upgrade Qadamar](../operations/upgrade.md) |
| Respond to a broken audit chain | [Respond to an audit tamper alert](../operations/audit-tamper-response.md) |
| Support the review of an emergency grant | [Review break-glass access](../operations/break-glass-review.md) |
| Onboard, upgrade, or remove a managed tenant | `docs/MANAGED-OFFER.md` §5 and §6 |

## Use the reference documents

- `docs/DEPLOY.md`: image, Compose with PostgreSQL and two nodes, probes, encrypted backup and restore, and the production profile.
- `docs/API.md`: every route, including readiness, metrics, audit storage, anchoring, SIEM, credentials, SCIM, and cluster behaviour.
- `docs/MANAGED-OFFER.md`: the Kubernetes tenant layout, isolation, onboarding, upgrade, alerts, and what is not covered yet.
- `docs/PERFORMANCE.md`: recorded benchmarks with their hardware, worlds, and modes. Treat them as observations, never as capacity targets or SLOs.
- `docs/RELEASE.md` and `docs/SUPPORT.md`: how releases are built and what support covers.
- [Limits and quotas](../reference/limits-and-quotas.md): request, search, audit, token, rate, gateway, and impact bounds.

## Related pages

- [Run a local demonstration](getting-started.md)
- [Manage keys and security operations](security-officer.md)
- [Verify audit evidence after recovery](auditor.md)
- [Read limits and quotas](../reference/limits-and-quotas.md)
