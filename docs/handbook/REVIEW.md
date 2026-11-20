# Handbook review record

This page records the editorial review that merged the two handbook halves into one handbook and brought it up to date with the code at commit `b09bc44` (after 0.3.0). It lists what changed, how many statements were checked against the code, and what remains unverified.

## On this page

- [Scope and method](#scope-and-method)
- [What changed](#what-changed)
- [Claims checked and corrected](#claims-checked-and-corrected)
- [Notable corrections](#notable-corrections)
- [Getting-started run](#getting-started-run)
- [Diagram and link checks](#diagram-and-link-checks)
- [Remaining unverified](#remaining-unverified)
- [Findings outside the handbook](#findings-outside-the-handbook)

## Scope and method

- **Input.** Two handbooks written in parallel against v0.3.0: a functional half (`concepts/`, `guides/`, `reference/`) and a technical half (`architecture/`, `architecture/decisions/`, `operations/`), each with its own landing page.
- **Standard.** Task-first pages, exact statements, no speculation. Every route, method, role gate, environment variable, default, limit, rule identifier, error code, metric name, console screen name and number was compared with the code at `b09bc44`. Wrong statements were fixed, unverifiable ones removed, limited features marked **Partial** and absent ones **Not available**.
- **Ground truth.** Source code first (`packages/*/src`, `apps/admin/src`, `scripts/`, `deploy/` read-only). Repository documents that are generated or CI-checked (`docs/CONFIGURATION.md`, checked with `node scripts/docs/env-table.ts --check`) are linked instead of copied. Performance figures come only from `docs/PERFORMANCE.md`, with their conditions.
- **Out of scope.** No code, `README.md`, `CHANGELOG.md`, `docs/isms/`, `docs/compliance/`, `deploy/` or `scripts/` was changed.

## What changed

- **One landing page.** [README.md](README.md) replaces both landing pages: reading paths for eight audiences (evaluator, administrator, approver, security officer, auditor, integrator, operator, architect), one table of contents, one set of conventions and the verification commands.
- **One vocabulary.** The [Glossary](concepts/glossary.md) gained 26 terms (among them cluster mode, leader, follower, staleness bound, node chain, decision assertion, evidence pack, subject access report, input validator, PEP binding, certifier, trusted proxy, managed offer). Console screens use their console names, for example Two-step sign-in and Credentials and keys.
- **No duplicate pages.** [Operate Qadamar](guides/operator.md) is now a short routing guide to the operations runbooks; its copied deploy, backup and monitoring procedures were removed. [Configuration reference](operations/configuration.md) no longer repeats the variable table: it groups settings by task and links [docs/CONFIGURATION.md](../CONFIGURATION.md). The security officer guide links the break-glass and rotation runbooks instead of repeating them.
- **New ADR.** [ADR 0011: Cluster mode](architecture/decisions/0011-cluster-mode.md). [ADR 0003](architecture/decisions/0003-postgresql-single-active-node.md) is marked "Amended by ADR 0011" with an amendment note; its history is unchanged.
- **Post-0.3.0 features added** where each audience needs them:

| Feature | Pages |
|---|---|
| Cluster mode (`GATE_CLUSTER`, per-node audit chains, leader-only admin plane, `/leaderz`, staleness bound) | concepts/overview, governance-and-audit, glossary; reference/error-codes, limits-and-quotas, roles-and-permissions, faq; guides/integrator, auditor, operator; architecture/overview, data-and-storage, audit-and-evidence, integration, well-architected-review, ADR 0011; operations/deploy, failover, monitoring, upgrade, audit-tamper-response, capacity |
| Managed offer on Kubernetes | concepts/overview; guides/operator; architecture/overview; operations/deploy, backup-restore, monitoring |
| `TRUSTED_PROXIES` | concepts/mandatory-controls; guides/integrator; architecture/security-architecture; operations/deploy, configuration |
| Signed decision assertions and the SDK verifier | concepts/overview; guides/integrator, security-officer; architecture/integration, security-architecture; reference/error-codes, limits-and-quotas |
| Clark-Wilson C5, E3, E4 | concepts/integrity-and-separation, decision-model, policy-and-content, relations-and-delegation; reference/decision-reasons; guides/policy-authoring, security-officer, approver; architecture/decision-engine, security-architecture |
| Encrypted backups | operations/backup-restore, upgrade, rotate-credentials; architecture/audit-and-evidence |
| Two-step sign-in screen, translated errors | guides/access-administrator, approver, security-officer; reference/roles-and-permissions, faq; architecture/security-architecture |
| Evidence packs, pseudonymised exports, subject access report | concepts/governance-and-audit; guides/security-officer, auditor; reference/roles-and-permissions; architecture/audit-and-evidence |
| Release engineering | operations/deploy |
| Configuration reference | operations/configuration (links docs/CONFIGURATION.md) |

## Claims checked and corrected

A claim is one checkable fact: a route, a default, a role gate, a rule identifier, a number or a behaviour. Counts per section are approximate (counted by hand while editing).

| Section | Pages | Claims checked | Corrected |
|---|---|---|---|
| Concepts and reference | 13 | 520 | 55 |
| Role guides (except getting started) | 8 | 330 | 31 |
| Getting started (run for real) | 1 | 35 | 5 |
| Architecture and ADRs | 18 | 515 | 79 |
| Operations | 10 | 490 | 88 |
| Landing page and cross-page checks | 2 | 25 | 4 |
| **Total** | **52** | **about 1,915** | **about 262** |

Cross-page checks, run over the whole handbook after editing:

- All 57 distinct routes named in the handbook exist in `packages/pdp-http/src/router.ts`, `pdp.ts` or `admin/*.ts`.
- All 103 upper-case identifiers (environment variables, rule ids) appear in the code or in the generated configuration, except nine entity names of the logical data model diagram and the guide's shell variable `PEP_API_KEY`.
- All 32 `gate_*` names (metrics, tables, RLS policies) exist in the code, the deploy files or `docs/DEPLOY.md`; `gate_service` is a documented placeholder role name, and `gate_audit_verified` is cited only to say that no such metric exists.
- All 10 performance figures appear in `docs/PERFORMANCE.md` and are quoted with their conditions.

## Notable corrections

- **Clark-Wilson coverage.** C5 was described as not available and E4 as unenforced; both are enforced (`CW.INPUT_REQUIRED`, `CW.INPUT.<id>`, `CW.CERTIFIER_EXECUTES`). E1 and E3 stay **Partial**.
- **Two-step sign-in.** Several pages said TOTP enrolment was API-only; the console has a Two-step sign-in screen.
- **Decision assertions.** The integrator guide said signed identity claims to the backend were not available; the gateway forwards a `gate-assertion` header on every request, verified by `AssertionVerifier`.
- **Kubernetes.** The architecture overview said there was no Kubernetes deployment; the managed offer ships `deploy/k8s` (marked **Partial** where its limits apply).
- **Storage.** Four tables became seven (`gate_sync`, `gate_token`, `gate_performed` added), with the three advisory locks and the generated `serviceGrants` and `backupGrants`.
- **Evidence-pack signature.** It covers the manifest of section hashes, not the pack itself; the verification steps were fixed.
- **Traces.** Request spans now carry `client.address`; the page said traces carried no address.
- **Delegation chain.** Confirmed at most five principals: the subject plus four delegators (`MAX_DELEGATION_DEPTH` counts delegation links).
- **Capacity.** A "100,000 actions" claim had no source and was removed; only `docs/PERFORMANCE.md` figures remain.
- **Mermaid.** Six sequence messages used `;`, which ends a Mermaid statement; they were rewritten.
- **Getting started.** The PEP key was exported in one terminal and used in another; the steps now use one terminal. The optional untrusted-network and `CASE-7` results are now stated exactly.
- **Retries.** Pages that said "PEPs retry another node" now say that the SDK and the gateway do not retry; routing must.

## Getting-started run

[Run the toy-domain demo](guides/getting-started.md) was run against a local server in file mode with a temporary `DATA_DIR` outside the repository and a free port, using Node.js 22.23.3 and pnpm 12.16.1. It was run twice, with identical results: once in the working tree, and once from a clean `git archive` export of `b09bc44`, because another agent had uncommitted code changes in the working tree during the review. `pnpm install --offline --frozen-lockfile` and `pnpm --filter @product/admin build` succeeded. Results, each matching the page:

| Step | Observed |
|---|---|
| Server start | `PDP listening at http://127.0.0.1:<port>`; `INITIAL-CREDENTIALS.txt` created with mode 600, deleted after the first sign-in |
| Bob reads `CASE-14` (trusted) | 200, `decision: true`, rules `RBAC.viewer`, `NTK.knows`, obligations `redact: [informant_name]`, `maskClasses: [finance.amount]`, `notify: []`; context keys `rules`, `reasons`, `obligations`, `policy_version`, `would_deny` |
| Untrusted network, no context | `decision: true`, same rules |
| Bob reads `CASE-7` | `decision: false`, `BLP.NO_READ_UP`, `MAC.COMPARTMENT`, `NTK.NO_REASON` |
| Dan before the change | `decision: false`, `NTK.NO_REASON` |
| Impact preview as `amira` | one gained cell: Dan `read` `CASE-14`, previously `NTK.NO_REASON`; nothing lost |
| Submit | 201, `pending` |
| `amira` approves her own change | 403 `self_approval` |
| `omar` approves | 200, `applied` |
| Dan after the change | `decision: true`, `RBAC.viewer`, `NTK.knows` |
| Second server on a used port | exits with `EADDRINUSE` |

The console steps were checked against the console's English strings (`apps/admin/src/i18n/simulator.ts`, `approvals.ts`); the run used the equivalent admin API calls, not a browser. Credentials were read by the test script from the file and not displayed in the results.

## Diagram and link checks

An offline checker (not committed) read every page and checked:

- every relative link resolves to a file, and every `#anchor` resolves to a heading slug (GitHub rules, duplicate suffixes included);
- every Mermaid block structurally, per diagram type: flowchart (brackets, quotes, `subgraph`/`end`, dangling edges, unquoted brackets in labels), sequenceDiagram (participants, arrows, notes, `alt`/`opt`/`loop`/`par`/`rect` balance, `;` in messages), stateDiagram-v2 (transitions, composite states) and erDiagram (relationships, entity blocks).

Final result: 52 pages, 0 problems. Mermaid itself was not run (no network), so a diagram can still fail on a rule the checker does not model.

## Remaining unverified

- The XACML "unsupported combined decisions" detail behind `XACML.INDETERMINATE`.
- That PEP credential names must be unique only among active credentials.
- The assertion example backend and the C5/E3 decision flows were read, not executed. The assertion replay cache lives in each verifier instance; the multi-replica case was not tested.
- Import of legacy decision tokens on upgrade (code present, no test).
- Rolling upgrade of a mixed-version cluster: marked **Not available**. Running 0.3.0 against a migrated schema: marked "do not".
- Console screens beyond the getting-started labels were checked from source and strings, not in a browser.
- `docs/compliance/` and `docs/isms/` were being edited during this review; links to them point to their README only.
- **Uncommitted code in the working tree.** During the review another agent changed code without committing (among others `auth.ts`, `router.ts`, `pdp.ts`, `server.ts`, `admin/changes.ts`, `audit.ts`, `core/src/weakening.ts`, `core/src/simulate.ts`, and a new `forward.ts`: a PEP credential `allowSubjectSearch` flag, forwarding admin requests from a follower to the leader, wider weakening checks, obligation changes in impact previews, a `simulation` audit type filter). The handbook describes `b09bc44` and does not document them. Editors read the working tree; the passages that touch these files (weakening findings, audit type filter, PEP credentials, follower `409 not_leader`, impact fields) were compared with `git show b09bc44:` and match the commit. When those changes are committed, these pages need an update: guides/approver, security-officer, integrator, auditor; reference/error-codes, roles-and-permissions; architecture/integration, ADR 0011; operations/failover, deploy.

## Findings outside the handbook

Reported, not fixed (outside this review's scope):

- **Break-glass screen for auditors.** The console shows the Break-glass screen to `auditor` (`apps/admin/src/utils/permissions.ts`), but `GET /admin/v1/break-glass` allows only `access_admin` and `security_officer`, so the screen gets 403. The roles matrix records the mismatch.
- **docs/MANAGED-OFFER.md §11** still says backups have no archive encryption; `scripts/ops/backup.sh` now requires `BACKUP_ENCRYPTION_KEY`.
- **Expired decision tokens** in `gate_token` are deleted only by a cluster leader; in single-active mode nothing deletes them.
- **No PEP retry.** The SDK and the gateway do not retry another node on `503 unavailable`.
- **Alerts.** The shipped alert rules are not adapted to cluster mode, and no metric reports a failed audit verification directly.

## Related pages

- [Handbook home](README.md)
- [Glossary](concepts/glossary.md)
- [Changelog](../../CHANGELOG.md)
