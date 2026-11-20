# Administer access and propose changes

An access administrator models the domain, inspects effective access, and proposes subject, resource, relation, and policy changes. The console never applies these ordinary changes directly: preview the impact, provide a reason, and leave the final decision to an independent approver or security officer.

## On this page

- [Inspect the domain model](#inspect-the-domain-model)
- [Simulate effective access](#simulate-effective-access)
- [Propose a relation grant](#propose-a-relation-grant)
- [Update subject or resource attributes](#update-subject-or-resource-attributes)
- [Read the impact before submitting](#read-the-impact-before-submitting)
- [Propose a policy publication](#propose-a-policy-publication)
- [Sign in and read errors](#sign-in-and-read-errors)

## Inspect the domain model

Open **Attribute model** and use its four tabs:

- **Schema & lattices** shows L0–L3 labels, compartments, integrity ordering, resource types, action properties, need-to-know protection, and relation rewrites.
- **Subjects** shows status, policy roles, clearance, compartments, integrity, and delegation metadata.
- **Resources** shows level, compartments, integrity, owner, and content classes.
- **Relation tuples** shows direct and userset relations, validity, grant reason, and break-glass markers.

Use **Search**, **Level**, **Compartment**, and **Status** to narrow the tables. Select **Simulate** or **Edit** on a row to move to the corresponding workflow. The console shows metadata only, not business record bodies.

Open **Policies** to inspect **Evaluation pipeline**, **Tenant rules**, **Role eligibility matrix**, and **Version history**. The pipeline cards distinguish system-locked controls from tenant rules. Sources: `apps/admin/src/screens/AttributeModelScreen.tsx`, `apps/admin/src/screens/ModelTablesPane.tsx`, `apps/admin/src/screens/PoliciesScreen.tsx`.

## Simulate effective access

Use **Simulator** before changing access:

1. Select **What can a person see** to evaluate every resource in scope for one subject and action, or **Who can see a resource** to evaluate every subject for one resource and action.
2. Select the **Action** and set **Trusted network** on or off.
3. Read the decision, denying or basis rules, relation path, and obligations.
4. Select **Explain** to open **Explain decision**. Inspect **Trace by evaluation stage**, **Relation path**, and **Obligations**.
5. Change **Session level**, **Maker ID**, or **Prior actions** only to test a specific scenario, then select **Re-evaluate**. These are simulation inputs, not changes to the stored world.

Use **Access matrix** to compare every visible subject-resource pair for one action. Its layers are **Rights**, **Clearance**, **Need to know**, **Conditions**, **Content rules (ABAC on content attributes)**, **CBAC (context-based, Zero Trust)**, and **Controls**. Choose a cell for the full trace. Simulator calls do not append decision audit rows. Sources: `apps/admin/src/screens/SimulatorScreen.tsx`, `apps/admin/src/components/ExplainDrawer.tsx`, `packages/pdp-http/src/admin/simulator.ts`.

## Propose a relation grant

1. Open **Simulator → Impact of a change**.
2. Under **Change type**, select **Grant a relation**.
3. Select the **Subject**, **Relation**, and **Resource**.
4. Leave **Subject relation (optional)** empty for a direct subject. For a userset, enter a declared relation such as `member`.
5. For `granted` or `allocated`, set **Valid until (≤ 90 days)** within 90 days of the server date. Future-start grants require a new proposal when they become effective.
6. Select **Preview impact** and inspect both gained and lost access.
7. Enter a ticket reference and justification in **Reason for change (at least 20 characters)**.
8. Select **Submit for approval**. Follow **Open in Approvals →** to see the pending change.

The server prevents a grant to yourself and prevents break-glass tuples through this ordinary workflow. Use **Break-glass** only for an emergency. A relation can produce no access gain when mandatory controls, eligibility, ABAC (including content attributes), CBAC, Clark-Wilson, or SoD still deny; that is expected behavior, not a failed relation write.

Sources: `apps/admin/src/screens/SimulatorImpactFields.tsx`, `packages/pdp-http/src/admin/changes.ts`.

To revoke an ordinary relation, select **Revoke a relation**, choose the tuple, preview, and submit. Revocation also needs two-person approval. Break-glass tuples use their own independent revoke workflow instead.

## Update subject or resource attributes

For a subject:

1. Select **Update subject attributes**.
2. Select the subject and edit **Clearance**, **Roles (comma-separated)**, **Status**, and declared **Compartments**.
3. Preview and submit with a reason.

For a resource:

1. Select **Update resource attributes**.
2. Select the resource and edit **Classification level**, **Integrity level**, and **Compartments**.
3. Preview and submit with a reason.

Subject integrity is not editable through this console workflow. Resource edits increment the stored resource version, which invalidates decision tokens bound to the earlier version. A resource cannot sit below its parent's classification; raise children before raising a parent. Self-updates are refused as self-grants.

Sources: `packages/pdp-http/src/admin/changes.ts`, `apps/admin/src/screens/SimulatorImpactPane.tsx`.

## Read the impact before submitting

**Gained access** lists cells denied before and allowed after. **Lost access** lists the reverse. For a gain, the rule column explains the previous denial; for a loss, it explains the new denial. An empty gain list does not mean the change is irrelevant: inspect the payload and the losses.

The computed analysis includes both networks and maker/history variants for actions that need them. It evaluates only the affected cells; the evaluation count's tooltip reports the unique affected-cell count and why those cells were selected. The **Trusted network** switch beside the form affects the context used by the row's **Explain** action; it does not restrict the impact analysis to one network. The explanation drawer evaluates current state, so use the impact table itself for the after-state outcome.

Check every row that broadens access, then provide a precise reason. The server binds the proposal to the current state digest and impact and checks both again at approval. Sources: `packages/pdp-http/src/admin/changes.ts`, `apps/admin/src/components/ImpactTables.tsx`, `apps/admin/src/components/ExplainDrawer.tsx`.

## Propose a policy publication

1. Open **Policies → Candidate editor**.
2. Edit only `rbac`, `abac`, `abacContent`, `context`, and `sod`. The other sections are read-only in this screen. Content rules (`abacContent`) are ABAC on content attributes; CBAC rules (`context`) are context-based, Zero Trust and re-verify situational signals on every request. A legacy candidate with a `cbac` field shows the warning `DEPRECATED_CBAC_FIELD`; rename it to `abacContent`.
3. Resolve every item under **Bundle validation errors** until **Valid candidate** appears.
4. Select **Preview impact** and review the complete delta.
5. Enter the release reason and select **Submit for approval**.

Use the admin API's `publish_policy` change for schema, mandatory parameters, need-to-know, or Clark-Wilson changes. A proposal that weakens mandatory controls needs an independent security officer rather than an ordinary approver. All policy publications receive a version fingerprint and detached signature when approved.

The access administrator cannot approve or reject any change, including someone else's. Sign in as an approver or security officer to complete the workflow. Sources: `apps/admin/src/screens/PolicyEditorPane.tsx`, `packages/pdp-http/src/admin/changes.ts`.

## Sign in and read errors

- **Two-step sign-in.** A local password account can turn on TOTP in **Two-step sign-in**, which every console role can open. After that, enter the code in **One-time code (if enrolled)** at each sign-in. An account that signs in through the organisation's identity provider has nothing to set up there. See [Turn on two-step sign-in](security-officer.md#turn-on-two-step-sign-in).
- **Error messages.** The console shows a translated message, in English or French, for each stable error code, and adds the server's own English text under **Server detail** when it says more. For example, `stale` means the state changed after simulation and the maker must simulate and submit again. See [Error codes](../reference/error-codes.md).
- **Cluster mode.** A 409 `not_leader` means the console reached a follower node. Open the console through the address that reaches the leader, or ask your operator.

Sources: `apps/admin/src/screens/TwoStepScreen.tsx`, `apps/admin/src/api/errorText.ts`, `apps/admin/src/i18n/errors.ts`, `packages/pdp-http/src/router.ts`.

## Related pages

- [Write a policy bundle](policy-authoring.md)
- [Review and approve changes](approver.md)
- [Understand impact, versions, and signatures](../concepts/governance-and-audit.md)
- [Run the first guided change](getting-started.md)
