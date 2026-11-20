# Qadamar handbook

Qadamar is an access-control decision point: a policy decision point (PDP) with an embedded admin plane and console, an SDK and an enforcing gateway. This handbook explains what Qadamar decides, how each role uses it, how it is built, and how to run it. It describes the code at commit `b09bc44` (after 0.3.0), including the unreleased changes listed in [CHANGELOG.md](../../CHANGELOG.md).

## On this page

- [Choose a reading path](#choose-a-reading-path)
- [Get started](#get-started)
- [Concepts](#concepts)
- [Role guides](#role-guides)
- [Reference](#reference)
- [Architecture](#architecture)
- [Architecture decision records](#architecture-decision-records)
- [Operations](#operations)
- [Conventions](#conventions)
- [Related repository documents](#related-repository-documents)

## Choose a reading path

Read the pages of your path in order. Each path starts with the shortest page that answers "what is this for me".

| You are | You want to | Read, in order |
|---|---|---|
| **Evaluator** | Decide whether Qadamar fits | [Understand Qadamar](concepts/overview.md), [Run the toy-domain demo](guides/getting-started.md), [Follow a decision through the core](concepts/decision-model.md), [Architecture overview](architecture/overview.md), [Well-Architected review](architecture/well-architected-review.md), [Capacity and performance](operations/capacity.md), [Functional FAQ](reference/faq.md) |
| **Administrator** (access administrator, policy author, resource owner) | Model the domain, write policy, grant and review access | [Run the toy-domain demo](guides/getting-started.md), [Administer access and propose changes](guides/access-administrator.md), [Write and publish a policy bundle](guides/policy-authoring.md), [Review access within your ownership scope](guides/resource-owner.md), [Author policy bundles and conditions](concepts/policy-and-content.md), [Use relations and delegation safely](concepts/relations-and-delegation.md), [Understand mandatory controls](concepts/mandatory-controls.md), [Roles and permissions matrix](reference/roles-and-permissions.md) |
| **Approver** | Check and approve other people's changes | [Review and approve changes](guides/approver.md), [Govern policy change and audit evidence](concepts/governance-and-audit.md), [Understand integrity and separation of duty](concepts/integrity-and-separation.md), [Decision reasons and rule identifiers](reference/decision-reasons.md) |
| **Security officer** | Run break-glass, certifications, credentials, keys and compliance | [Manage security operations](guides/security-officer.md), [Review break-glass access](operations/break-glass-review.md), [Rotate keys and credentials](operations/rotate-credentials.md), [Understand integrity and separation of duty](concepts/integrity-and-separation.md), [Security architecture](architecture/security-architecture.md), [Respond to an audit tamper alert](operations/audit-tamper-response.md) |
| **Auditor** | Verify the audit chain and export evidence | [Investigate and export audit evidence](guides/auditor.md), [Govern policy change and audit evidence](concepts/governance-and-audit.md), [Audit and evidence](architecture/audit-and-evidence.md), [Respond to an audit tamper alert](operations/audit-tamper-response.md), [Decision reasons and rule identifiers](reference/decision-reasons.md) |
| **Integrator** | Connect an application (PEP) to Qadamar | [Run the toy-domain demo](guides/getting-started.md), [Integrate a policy enforcement point](guides/integrator.md), [Integration](architecture/integration.md), [Decision reasons and rule identifiers](reference/decision-reasons.md), [HTTP error codes](reference/error-codes.md), [Limits and quotas](reference/limits-and-quotas.md), [API contract](../API.md) |
| **Operator** | Deploy, monitor, back up, fail over and upgrade | [Operate Qadamar](guides/operator.md), [Deploy Qadamar](operations/deploy.md), [Configuration reference](operations/configuration.md), [Monitoring and alerts](operations/monitoring.md), [Back up and restore](operations/backup-restore.md), [Fail over the active node](operations/failover.md), [Upgrade Qadamar](operations/upgrade.md), [Managed offer](../MANAGED-OFFER.md) |
| **Architect** | Understand the design and its trade-offs | [Architecture overview](architecture/overview.md), [Decision engine](architecture/decision-engine.md), [Data and storage](architecture/data-and-storage.md), [Security architecture](architecture/security-architecture.md), [Integration](architecture/integration.md), [Architecture decision records](#architecture-decision-records), [Well-Architected review](architecture/well-architected-review.md) |

## Get started

- [Run the toy-domain demo](guides/getting-started.md): start Qadamar in file mode, make a decision with `curl`, and apply a change through two-person approval. About 10 minutes.

## Concepts

What Qadamar decides and why. Terms are defined once, in the [Glossary](concepts/glossary.md).

1. [Understand Qadamar](concepts/overview.md): the problem, the components, the deployment shapes and the current boundaries.
2. [Follow a decision through the core](concepts/decision-model.md): subjects, resources, actions, context, policy bundles, the pipeline and the result.
3. [Understand mandatory controls](concepts/mandatory-controls.md): clearance, compartments, network, integrity and fail-closed behaviour.
4. [Use relations and delegation safely](concepts/relations-and-delegation.md): relation tuples, need-to-know, agents and break-glass.
5. [Author policy bundles and conditions](concepts/policy-and-content.md): policy roles, ABAC (including content attributes), three-valued logic, CBAC (context, Zero Trust) and obligations.
6. [Understand integrity and separation of duty](concepts/integrity-and-separation.md): Clark-Wilson, input validators, PEP binding, decision tokens and SoD.
7. [Govern policy change and audit evidence](concepts/governance-and-audit.md): approvals, signatures, impact, reviews, audit chains and evidence packs.
8. [Glossary](concepts/glossary.md).

## Role guides

Tasks per console role, plus the integrator and the operator.

- [Administer access and propose changes](guides/access-administrator.md) (`access_admin`)
- [Write and publish a policy bundle](guides/policy-authoring.md) (`policy_author`)
- [Review and approve changes](guides/approver.md) (`approver`)
- [Manage security operations](guides/security-officer.md) (`security_officer`)
- [Review access within your ownership scope](guides/resource-owner.md) (`resource_owner`)
- [Investigate and export audit evidence](guides/auditor.md) (`auditor`)
- [Integrate a policy enforcement point](guides/integrator.md) (application developers)
- [Enforce safely across replicas and SQL lists](guides/integration-safety.md) (tested backend examples)
- [Operate Qadamar](guides/operator.md) (operators; routes to the [operations](#operations) runbooks)

## Reference

- [Decision reasons and rule identifiers](reference/decision-reasons.md)
- [HTTP error codes](reference/error-codes.md)
- [Roles and permissions matrix](reference/roles-and-permissions.md)
- [Limits and quotas](reference/limits-and-quotas.md)
- [Functional FAQ](reference/faq.md)
- [Configuration](../CONFIGURATION.md): every environment variable, generated from the code and checked in CI.
- [API contract](../API.md): every route, request and response.

## Architecture

1. [Architecture overview](architecture/overview.md): system context, containers, and the file, PostgreSQL, cluster and Kubernetes deployment views.
2. [Decision engine](architecture/decision-engine.md): fixed pipeline, three-valued logic, deny overrides, delegation, Clark-Wilson, SoD and partial evaluation.
3. [Data and storage](architecture/data-and-storage.md): data model, tables, row-level security, locks, checkpoints and per-node audit chains.
4. [Audit and evidence](architecture/audit-and-evidence.md): hash chains, RFC 3161 anchors, verification, SIEM export, evidence packs and privacy reports.
5. [Security architecture](architecture/security-architecture.md): trust boundaries, authentication, sessions, keys, the production profile and STRIDE.
6. [Integration](architecture/integration.md): AuthZEN, XACML, OIDC, SCIM, SIEM, OTLP, the SDK, the gateway and decision assertions.
7. [Well-Architected review](architecture/well-architected-review.md): strengths, risks and an improvement backlog.

## Architecture decision records

Each ADR records context, the decision, consequences, alternatives and evidence.

| ADR | Decision | Status |
|---|---|---|
| [0001](architecture/decisions/0001-fixed-evaluation-pipeline.md) | Fixed evaluation pipeline | Accepted |
| [0002](architecture/decisions/0002-minimal-dependencies.md) | Minimal dependencies | Accepted |
| [0003](architecture/decisions/0003-postgresql-single-active-node.md) | PostgreSQL single active node | Amended by 0011 |
| [0004](architecture/decisions/0004-hash-chain-rfc3161.md) | Hash-chained audit with RFC 3161 | Accepted |
| [0005](architecture/decisions/0005-server-derived-sod.md) | Server-derived separation of duty | Accepted |
| [0006](architecture/decisions/0006-authzen-primary-api.md) | AuthZEN as the primary API | Accepted |
| [0007](architecture/decisions/0007-json-condition-ast.md) | JSON condition AST | Accepted |
| [0008](architecture/decisions/0008-in-memory-rebac.md) | In-memory ReBAC tuples | Accepted |
| [0009](architecture/decisions/0009-apache-licence.md) | Proprietary licence | Accepted |
| [0010](architecture/decisions/0010-production-profile.md) | Production profile with fail-closed preflight | Accepted |
| [0011](architecture/decisions/0011-cluster-mode.md) | Cluster mode: every node decides, one leader administers | Accepted |

## Operations

Runbooks for operators and security officers.

| Task | Page |
|---|---|
| Install, configure the production profile, run behind a proxy, run a cluster or the managed offer | [Deploy Qadamar](operations/deploy.md) |
| Find the setting for a task | [Configuration reference](operations/configuration.md) |
| Watch metrics, probes and alerts | [Monitoring and alerts](operations/monitoring.md) |
| Size a deployment | [Capacity and performance](operations/capacity.md) |
| Take over from a failed node or change cluster leader | [Fail over the active node](operations/failover.md) |
| Back up, restore and drill a recovery | [Back up and restore](operations/backup-restore.md) |
| Move to a new version | [Upgrade Qadamar](operations/upgrade.md) |
| Rotate PEP credentials, keys and secrets | [Rotate keys and credentials](operations/rotate-credentials.md) |
| Review an emergency access | [Review break-glass access](operations/break-glass-review.md) |
| Respond to a broken audit chain | [Respond to an audit tamper alert](operations/audit-tamper-response.md) |

## Conventions

- **Scope.** Statements describe the code at commit `b09bc44`. Pages cite repository-relative source paths for behaviour that is not obvious.
- **Partial** marks a capability whose enforcement or tooling has a stated boundary. **Not available** marks a capability the code does not have.
- **Performance.** Figures come only from [docs/PERFORMANCE.md](../PERFORMANCE.md), with their measurement conditions. They are measurements, not service-level objectives.
- **Terminology.** The [Glossary](concepts/glossary.md) is authoritative. Console screens are named as the console names them: Overview, Attribute model, Policies, Access matrix, Simulator, Approvals, Break-glass, Access reviews, Credentials and keys, Audit, Compliance and Two-step sign-in.
- **No compliance claim.** Evidence packs and control mappings are product evidence, not a certification or an attestation.

To check the code this handbook describes, run the repository's standard checks from the repository root:

```bash
pnpm typecheck
pnpm --filter @product/admin build
pnpm test
pnpm --filter @product/admin test
```

`bash tools/ci/local.sh` runs the full local CI gate: it starts a throwaway PostgreSQL 17 container, runs the checks (including 2,000 fuzz runs of the core) and removes the container. Tests that need a live database are skipped when `TEST_DATABASE_URL` is unset.

## Related repository documents

- [API contract](../API.md), [Configuration](../CONFIGURATION.md), [Deployment notes](../DEPLOY.md), [Managed offer](../MANAGED-OFFER.md)
- [Performance](../PERFORMANCE.md), [Quality evidence](../QUALITY.md), [AuthZEN conformance](../AUTHZEN-CONFORMANCE.md), [Accessibility](../ACCESSIBILITY.md)
- [Release process](../RELEASE.md), [Support policy](../SUPPORT.md), [Changelog](../../CHANGELOG.md), [Security policy](../../SECURITY.md)
- The [handbook review record](REVIEW.md)
