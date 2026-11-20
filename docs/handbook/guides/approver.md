# Review and approve changes

An approver provides the independent second decision for access and policy changes. Verify the maker, reason, payload, and simulated impact before approving, and reject or return anything that no longer matches the current state.

## On this page

- [Open and inspect a pending change](#open-and-inspect-a-pending-change)
- [Understand the approval checks](#understand-the-approval-checks)
- [Approve or reject](#approve-or-reject)
- [Handle stale and special changes](#handle-stale-and-special-changes)
- [Sign in and read errors](#sign-in-and-read-errors)

## Open and inspect a pending change

1. Sign in with the `approver` console role. The demo account is `omar`.
2. Open **Approvals** and select **Pending**.
3. Select the change in the **Change register**. Other tabs are **Applied**, **Rejected**, and **All changes**.
4. Verify **Proposed by**, **Created**, **Reason**, and **State digest**. Confirm that the change is the one described in the ticket.
5. Expand **Change payload** and inspect the exact bundle, tuple, subject attributes, resource attributes, or certification target.
6. Read **Gained access** and **Lost access**. Check subject, resource, action, and rule ids, not only the totals.
7. For CBAC changes, expand **Changes by context class** and verify the country, CIDR, time, device, freshness, risk, and session classes where the gain or loss occurs. A truncation warning means some combinations were not evaluated; ask for a smaller change rather than inferring safety from the aggregate totals. An unsupported-expression warning also means the analysis is incomplete. Any incomplete analysis requires security-officer approval, never an ordinary approver.
8. Use **Explain** on an impact row when you need the current-state trace. The explanation does not evaluate a separate candidate world; the impact tables carry the after-state result.

`Broadens (+n)` means at least one gained cell exists. `Narrows / neutral` means there are none; it does not remove the need for review. `Evaluated` counts compared cells across network, representative context, and required maker/history variants, not production traffic or unique real users. Sources: `apps/admin/src/screens/ApprovalsScreen.tsx`, `packages/pdp-http/src/admin/changes.ts`.

## Understand the approval checks

The server repeats authorization and consistency checks even if the console hides an invalid action.

| Check | Meaning |
|---|---|
| Independent maker and checker | You cannot approve or reject your own proposal. The server returns 403 `self_approval`. |
| Approval authority | Only `approver` and `security_officer` can decide. An access administrator or policy author cannot. |
| Pending status | An already applied or rejected change returns 409 `conflict`. |
| Beneficiary exclusion | You cannot approve a tuple grant or subject update for yourself, or a SCIM proposal containing yourself. |
| SCIM credential independence | You cannot approve a SCIM proposal made through the credential you minted, or one without credential-origin metadata. |
| Mandatory weakening | A policy publication that loosens protected controls requires a security officer, not an ordinary approver. |
| Certifier independence | For `certify_tp`, neither maker nor checker may be able to execute the procedure, and both need matching PDP subjects. |
| Current state | The current state digest must equal the proposal's digest. |
| Current impact | Recomputed impact must exactly equal the stored preview. |
| Grant validity | A replaced or new grant must still be live and unexpired at approval. |

A failed check does not apply the change. The audit trail records administrative refusals with route and error metadata. Sources: `packages/pdp-http/src/admin/changes.ts`, `packages/pdp-http/src/router.ts`.

## Approve or reject

1. Under **Review note or rejection reason (required)**, record what you verified or why the change is unsafe. A non-empty note is required; use a substantive ticket reference and finding.
2. Select **Approve** only when the payload and impact match the authorized intent. The status becomes **Applied**.
3. Select **Reject** when the proposal should not apply. The status becomes **Rejected**.
4. Read the confirmation and locate the record under the corresponding status tab.

The maker cannot approve **or reject** their own change, so do not treat rejection as a way to bypass independent review. Approving a `publish_policy` change signs and publishes the bundle; approving `certify_tp` appends the certification record; approving an access review replaces or removes its tuple.

Sources: `apps/admin/src/screens/ApprovalsScreen.tsx`, `packages/pdp-http/src/admin/changes.ts`.

## Handle stale and special changes

When the console shows **The state changed since this was simulated**, do not approve. Ask the maker to select **Re-simulate in Simulator →**, review the new impact, and submit a new proposal. A changed digest, changed impact, or expired grant produces 409 `stale`.

For mandatory weakening, inspect the `weakensMandatory` findings in the change returned by the API. Examples include a higher untrusted-network ceiling, a lower need-to-know mode, a longer break-glass cap or token lifetime, removed or changed IVPs and input validators, removed certification or PEP-binding requirements, redefined relations, and removed SoD coverage. These changes require a security officer as checker.

For `certify_tp`, a certification record admits the procedure only for types in `clarkWilson.requireCertification`. Whether or not the type requires certification, the record also denies the procedure to its maker and checker from then on, with `CW.CERTIFIER_EXECUTES`, whatever roles they gain later. Approving one therefore makes you unable to run that procedure. For SCIM proposals, approving one can make other proposals against the old state stale; the identity provider must re-propose from current state.

Break-glass is not approved here. It applies immediately through **Break-glass** and receives independent post-incident review there. Sources: `packages/pdp-http/src/admin/changes.ts`, `packages/pdp-http/src/admin/break-glass.ts`, `packages/core/src/weakening.ts`.

## Sign in and read errors

- **Two-step sign-in.** A local password account can turn on TOTP in **Two-step sign-in**. After that, enter the code in **One-time code (if enrolled)** at each sign-in. See [Turn on two-step sign-in](security-officer.md#turn-on-two-step-sign-in).
- **Error messages.** The console shows a translated message, in English or French, for each stable error code, and adds the server's own English text under **Server detail** when it says more. `self_approval` means you made the change; `stale` means the maker must simulate and submit again; `conflict` means the change is no longer pending. See [Error codes](../reference/error-codes.md).
- **Cluster mode.** A 409 `not_leader` means the console reached a follower node, which never takes an admin request. Open the console through the address that reaches the leader, or ask your operator. Nothing was approved or rejected.

Sources: `apps/admin/src/screens/TwoStepScreen.tsx`, `apps/admin/src/i18n/errors.ts`, `packages/pdp-http/src/router.ts`.

## Related pages

- [Propose and preview changes](access-administrator.md)
- [Review policy weakening as a security officer](security-officer.md)
- [Understand the change lifecycle](../concepts/governance-and-audit.md)
- [Resolve 403 and 409 responses](../reference/error-codes.md)
