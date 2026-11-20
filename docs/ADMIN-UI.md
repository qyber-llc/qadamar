# Admin console (IHM) — information architecture

Status: **draft 1 for owner review (2026-11-07).** Builds on [REBAC-ANALYSIS.md](REBAC-ANALYSIS.md)
and [ARCHITECTURE.md](ARCHITECTURE.md).

**As built (2026-11-10).** This document is the design brief; the shipped console differs as follows, and
[API.md](API.md) is the contract it calls:
- It is a React 19 single-page application built with Vite into a static bundle the control plane serves. It loads
  no external fonts, CDNs, analytics or outbound calls, but it is not dependency-free.
- It has twelve screens: the nine below plus an **Access matrix** (every person against every record, layer by layer),
  **Credentials and keys** (below) and **Two-step sign-in** (TOTP for local accounts, API.md §3.1.2), and a sign-in
  screen (local password or the organisation's OIDC IdP).
- **Credentials and keys** (`#/credentials`, access administrator and security officer; API.md §3.10, §3.11): PEP
  credentials (name, created, last used, rotated, revoked, previous secret's grace end, resource types), create (with
  the resource types it may register, checkboxes from the policy, fixed at creation), rotate and revoke (revoke asks
  for confirmation) for security officers; the decision-token signing keys (kid, signing or verify-only
  until) and their rotation, confirmed, for security officers; the SCIM credential's holder and last rotation, with
  the two-person rule spelled out, rotated (confirmed) by access administrators only. A secret returned by create or
  rotate appears once in a panel with a copy button; "I have stored it", a new secret or leaving the screen clears it,
  and it never reaches the URL or browser storage. Actions a role cannot perform are not shown; a 403 still reads as
  "Your role does not include this section." The Audit filter includes the `security` type.
- **Registered inventory** (`#/model?tab=inventory`, every role; API.md §2.2, §3.3): a resource-type picker, then the
  resources of that type registered by PEPs (or seeded) with their labels, version and parent, 50 a page with previous
  and next; the pending `register_resources` proposals naming the type, each linked to its review on Approvals; and the
  retired ids with their last version and whether the id is live again (not listed for a resource owner, whose scope
  the retired-id log cannot express). Read-only: registration stays with the PEPs, decisions with Approvals.
- **Languages: English and French.** `apps/admin/src/i18n/` holds one typed catalogue per area (`en`, and `fr` typed
  as the same shape, so a missing key fails `tsc`; `test/i18n.test.ts` also walks both). The sidebar's EN/FR switch
  sets the language, stored per user in `localStorage` (`qadamar-lang:<user id>`, plus the last choice for the sign-in
  screen; blocked storage falls back to the browser language) and mirrored on `<html lang>`. Dates use the catalogue's
  month names; level and role labels follow the language. Server errors are shown by their stable code through `i18n/errors.ts` (en, fr, with a fallback), the server's own
  English text, when it says more, as a detail marked `lang="en"`. The product name is
  never translated.
- Tenant policies are a JSON condition AST evaluated by the core (ARCHITECTURE.md §14), not Cedar.
- The console uses the `/admin/v1/*` routes (for example `/admin/v1/simulate/what-can`, `/who-can`, `/impact`,
  `/matrix`). `/x/v1/simulate` does not exist; `/x/v1/explain` and `/x/v1/filter` are PDP routes for enforcement points.
- Each policy publication is signed (Ed25519, ARCHITECTURE.md §15), but bundles are not distributed to separate PDPs
  and no bundle age is enforced; the compliance export is a metadata-only pack with a
  detached Ed25519 JWS.
- Accessibility: what is and is not verified is in [ACCESSIBILITY.md](ACCESSIBILITY.md).

## 1. Purpose and design posture

The admin console is the user interface of the control plane (ARCHITECTURE.md §2). It lets regulated organisations
author policies, manage attributes and relation grants, simulate changes before they take effect, execute two-person
approvals, handle emergency break-glass, run periodic access reviews, and inspect the hash-chained audit trail.

Target environments include sovereign and air-gapped networks (PRODUCT.md §2). The console ships as a zero-dependency
static bundle served by the control plane, with no external fonts, CDNs, analytics or outbound calls. The visual
language is sober, high-contrast and dense enough for security operations.

## 2. Personas and separation of duty

No single persona can author, approve and audit a change alone. Every administrative session requires MFA and is evaluated by the same PDP core as application traffic (ARCHITECTURE.md §11).

| Persona | Responsibilities | Allowed actions | Explicit prohibitions |
|---|---|---|---|
| **Access administrator** | Day-to-day subject clearances, compartment assignments, relation grants (≤ 90 days) | Propose subject/resource attribute changes and need-to-know grants; run simulator; submit changes for approval | **Never reads business content** (metadata and IDs only); cannot approve own submissions (P64) |
| **Policy author** | Maintains the tenant attribute schema, declared relations and Cedar policy sets | Draft candidate policy versions; view locked core invariants; run impact simulations; submit versions for publishing | Cannot publish a policy version alone; cannot weaken or disable built-in mandatory models |
| **Approver (second person)** | Independent maker-checker verification on access-broadening changes and policy releases | Inspect diffs, written reasons and pre-computed simulation previews; approve or reject queued changes | **Cannot approve a change where `maker_id == caller_id`** (enforced in core and disabled in UI) |
| **Security officer / CIO** | Oversight of exceptions, incident response, network boundaries and audit integrity | Review and close break-glass events; trigger emergency revocations; verify audit hash chain; configure trusted CIDRs | Cannot suppress audit rows or alter historical policy versions |
| **Resource owner** | Periodic recertification of who holds access to their cases, projects or deals | Open and complete access review campaigns; certify or revoke active grants and relation tuples within owned scope | Sees only resources within delegated ownership scope; hidden records remain absent |
| **Auditor** | Internal or external compliance verification | Read-only access to policies, version history, approvals, access review sign-offs, audit explorer and compliance exports | Read-only across the entire console; zero mutation endpoints permitted; no access to application content |

## 3. Product invariants expressed as UX rules

These rules are non-configurable properties of Qadamar (ARCHITECTURE.md §1, §11):

1. **Hidden means absent.** If an administrator or resource owner is not authorised for a scope, out-of-scope
   resources do not appear in selectors, simulations or audit aggregates. The UI never displays "3 hidden records" or
   redacted placeholders that leak existence; out-of-scope lookups return the same empty/404 state as missing IDs.
2. **Administrators manage access without reading content.** Every screen displays resource identifiers, types,
   classification labels (`L0`–`L3`), compartments, integrity levels and relation tuples—never record bodies, financial
   amounts, document text or attachments.
3. **Nothing applies without an impact preview.** Any change to a policy, schema, clearance, compartment or grant must
   first run through the simulator (`POST /x/v1/simulate`) to compute the delta of subjects and resources gaining or
   losing access. CBAC previews also show those deltas per representative context class in English and French, and warn
   when the 32-class-per-network cap truncates the analysis or an unsupported ABAC expression makes it incomplete.
   Incomplete analysis requires security-officer approval. The "Submit for approval" action stays locked until the
   preview completes and is bound by digest to the approval request.
4. **Written reason and two-person approval.** Every mutation requires a human-written justification (minimum length
   enforced). Any change that broadens access or publishes a policy version enters the **Approvals** queue and requires
   a distinct second person (`checker_id != maker_id`).
5. **Mandatory models are visibly locked.** The evaluation pipeline's built-in stages—inactive deny, RBAC eligibility,
   Bell-LaPadula (`L0`–`L3`), compartments, network condition, Biba integrity and need-to-know—are rendered in the
   policy screen as read-only system cards so authors see the exact evaluation order without being able to edit,
   reorder or bypass them.
6. **Relations and break-glass never lift mandatory controls.** The UI makes explicit in both the Simulator and the
   Break-glass form that a relation tuple or emergency grant only satisfies Step 4 (*Reason to know*). It never
   overrides insufficient clearance, missing compartments or an untrusted network (REBAC-ANALYSIS.md §6).

## 4. Navigation tree and screen specifications

```
Qadamar Admin Console
├── 1. Overview
├── 2. Attribute Model
├── 3. Policies
├── 4. Simulator
├── 5. Approvals
├── 6. Break-Glass
├── 7. Access Reviews
├── 8. Audit Explorer
└── 9. Compliance Reports
```

### Screen-by-screen architecture

| Screen | Purpose | Main objects | Key actions | Personas | PDP & control-plane APIs used |
|---|---|---|---|---|---|
| **1. Overview** | Operational posture of the access layer at a glance | Active policy bundle (version, SHA-256 fingerprint, bundle age), PDP fleet status, pending approvals counter, active break-glass banner, audit hash-chain status, expiring grants summary | Jump to pending approvals or unreviewed break-glass events; trigger on-demand hash-chain verification; inspect PDP configuration | All personas (scoped to role) | `GET /.well-known/authzen-configuration` (PDP metadata & bundle version); control-plane status & chain verifier |
| **2. Attribute Model** | Declare the tenant's domain schema, mandatory lattices and relation sources without writing core code | **Subject schema** (status, clearance `L0`–`L3`, compartments, trusted flag, roles); **Resource schema** (type, level, compartments, Biba integrity `verified > system > extracted > derived`, owner, parent); **Compartments** registry; **Trusted network CIDRs**; **Declared relations** (tuple store or SQL source, validity window, transitivity cap) | Add/deprecate compartment label; edit trusted network CIDRs; declare relation source (`person → resource`); stage schema change for simulation | Policy author, Access administrator, Security officer (read-only for Auditor) | `POST /x/v1/simulate` (preview schema/attribute change impact); `POST /x/v1/filter` (verify SQL predicate compilation for declared relations) |
| **3. Policies** | Inspect the fixed evaluation pipeline and author versioned tenant policies in Cedar | **Locked core invariants** (Steps 1–4: inactive check, RBAC matrix, BLP/compartments/network/Biba, need-to-know mode `off`/`dry_run`/`enforce`); **Tenant Cedar policies** (`permit`/`forbid`); **ABAC on content attributes (mask, redact, deny; `abacContent`)**; **CBAC (context-based, Zero Trust, `context`)**; **Policy versions** (immutable snapshots with SHA-256 fingerprints); **Clark-Wilson certifications** in the Rules tab (each record current or stale, procedures to recertify, procedures never certified; `GET /admin/v1/integrity/certifications`, every role but resource owner) and **unsettled reservations** (`GET /admin/v1/integrity/reservations`, access administrator, security officer, auditor) | View side-by-side version diff; edit Cedar policy in candidate draft; validate against schema; run impact preview; submit candidate version for two-person publishing | Policy author, Approver, Auditor (read-only) | `POST /x/v1/simulate` (candidate version vs published version); `POST /access/v1/evaluation` (unit-test individual policy assertions) |
| **4. Simulator** | Deterministic what-if analysis and pre-commit impact preview across three modes | **Mode A: "What can X see"** (subject, network context, action → allowed resources + SQL predicate); **Mode B: "Who can see Y"** (resource, action → permitted subjects within caller's scope); **Mode C: "Impact of a change before apply"** (staged attribute/grant/policy delta → gained/lost access matrix) | Run simulation; inspect per-row rule IDs, obligations and relation paths (e.g. `allocated until 2026-12-31`); toggle network (`trusted` vs `untrusted`); attachwritten reason and submit staged change for approval | Access administrator, Policy author, Approver, Security officer, Resource owner | Mode A: `POST /access/v1/search/resource`, `POST /x/v1/filter`, `POST /x/v1/explain`; Mode B: `POST /access/v1/search/subject`, `POST /x/v1/explain`; Mode C: `POST /x/v1/simulate`, `POST /access/v1/evaluations` |
| **5. Approvals** | Enforce Clark-Wilson two-person integrity on policy publishing and access-broadening changes | **Approval request** (ID, maker, timestamp, written reason, change type, cryptographic digest, embedded simulation delta showing exact permissions gained/lost, status; for `publish_policy`, the certifications approval would make stale, from `invalidatesCertifications`) | Inspect diff and impact preview; **Approve** (executes signed transaction) or **Reject** with reason; filter by pending / approved / rejected | Approver, Access administrator, Policy author, Security officer (Auditor read-only) | `POST /x/v1/simulate` (re-verify impact on current state before commit); `POST /access/v1/evaluation` (verify `checker_id != maker_id` via P64/P65) |
| **6. Break-Glass** | Time-boxed emergency need-to-know grants with mandatory notification and post-incident review | **Active break-glass grants** (subject, target resource, reason, 4h countdown timer, notification receipt); **CIO review queue** (expired/closed break-glass sessions awaiting sign-off, decisions logged during the window) | Open emergency grant (requires ≥ 20-char reason; capped at 4h; never bypasses clearance, compartments or network); revoke early; mark reviewed / escalate in CIO queue | Access administrator (open; revoke and review only when no other security officer exists), Security officer / CIO (open, revoke, review), Auditor (read-only) | `POST /access/v1/evaluation` & `POST /x/v1/explain` (confirm subject already satisfies Step 3 clearance/compartments/network before opening Step 4 break-glass) |
| **7. Access Reviews** | Periodic recertification of need-to-know grants, compartments and high-privilege roles | **Review campaigns** (scope, due date, completion %); **Expiring grants** (≤ 90-day tuple grants nearing their expiry, `notAfter`); **Certification items** (subject, resource/compartment, current relation path, last decision date) | Certify (extend with reason and new expiry ≤ 90d) or Revoke (immediate removal on next request); filter by expiring within 7/30 days | Resource owner, Security officer, Access administrator, Auditor (read-only) | `POST /access/v1/search/subject` (enumerate holders per resource); `POST /access/v1/search/resource` (enumerate access per subject); `POST /x/v1/explain` |
| **8. Audit Explorer** | Tamper-evident investigation of allow/deny decisions, admin mutations and read-audit events | **Audit records** (event ID, timestamp, subject, action, resource ID, effect, rule IDs, obligations, policy version fingerprint, row SHA-256 + previous hash); **Hash-chain verifier banner** | Filter by effect (`allow`/`deny`), rule ID (e.g. `P02`, `P30`, `P105`, `P121`), subject, resource or policy version; open decision detail drawer; verify hash chain against external anchor | Security officer / CIO, Auditor | `POST /x/v1/explain` (reconstruct rule evaluation path for current state vs recorded policy version) |
| **9. Compliance Reports** | Map live enforcement and audit evidence to regulatory control frameworks | **Control mappings** (NIST SP 800-53 AC-3, AC-4, AC-5, AC-6, AC-16, AC-24, AU-2/9/10; UAE IA Regulation v1.1 access-control and audit controls, exact control ids to be mapped from the TDRA text; ISO/IEC 27001); **Evidence packs** | Inspect control-to-rule mapping and live pass/fail evidence counts; generate and export signed offline evidence bundle (JSON / CSV summary, zero business content) | Auditor, Security officer / CIO | Control-plane evidence export & `GET /.well-known/authzen-configuration` |

## 5. End-to-end change lifecycle in the UI

Every administrative change that broadens access or updates a policy follows a single deterministic workflow across screens:

```
[2. Attribute Model / 3. Policies / 4. Simulator]
   Maker drafts change + enters written reason (≥ 20 chars)
        │
        ▼
[4. Simulator — Mode C (POST /x/v1/simulate)]
   Computes exact delta (who gains / loses access to which resource IDs)
   Binds preview digest to draft
        │
        ▼
[5. Approvals Queue]
   Maker sees "You cannot approve your own change" (Approve disabled)
   Second person (Approver) reviews reason + diff + simulation delta
        │
        ▼
[Control Plane Commit + Signed Bundle]
   Re-evaluates on locked state, publishes new immutable version or tuple,
   appends maker + checker + policy fingerprint to SHA-256 audit chain
```
