# Review access within your ownership scope

A resource owner inspects effective access and recertifies or revokes eligible relation grants for owned resources. Every certification or revocation still becomes a two-person proposal, and resources outside the authenticated owner's scope remain absent from lists, simulations, impacts, and counts.

## On this page

- [Understand your scope](#understand-your-scope)
- [Inspect access before reviewing](#inspect-access-before-reviewing)
- [Find grants that need review](#find-grants-that-need-review)
- [Certify a grant](#certify-a-grant)
- [Revoke a grant](#revoke-a-grant)

## Understand your scope

When `resource_owner` is your only console role, Qadamar includes resources whose `owner` is your authenticated user id or an owner id explicitly mapped to you by `RESOURCE_OWNERS`. The mapping is server configuration, not an identity-provider claim.

In the demo, `ruth` answers for owner id `carol` only when the server starts with:

```bash
RESOURCE_OWNERS='{"ruth":["carol"]}'
```

The scope covers **Attribute model**, **Simulator**, **Access matrix**, **Approvals**, **Access reviews**, and **Overview** counts. Out-of-scope direct lookups return 404. The unscoped **Audit**, **Break-glass**, and **Compliance** screens are not available to a resource-owner-only account. Sources: `packages/pdp-http/src/runtime.ts`, `apps/admin/src/utils/permissions.ts`.

## Inspect access before reviewing

1. Open **Attribute model → Resources** and confirm the resource's level, compartments, integrity, owner, and content classes.
2. Open **Relation tuples** and inspect the subject, relation, validity, granter, and reason.
3. Open **Simulator → Who can see a resource**, select the resource and action, and inspect each decision and relation path.
4. Use **Access matrix** to compare all visible subjects for the action, or **Explain decision** on a result to inspect the current-state trace.

A subject in the tables is in scope only through a relation to an owned resource. Do not infer that the owner can see every resource associated with that subject elsewhere. Sources: `packages/pdp-http/src/runtime.ts`, `packages/pdp-http/src/admin/model.ts`, `packages/pdp-http/src/admin/simulator.ts`.

## Find grants that need review

Open **Access reviews**. The server includes live, non-break-glass tuples when:

- a `granted` or `allocated` relation expires within 30 days; or
- a `granted` relation began at least 90 days ago, even without an expiry.

Use **Horizon** to select **All candidates**, **Expiring within 7 days**, **Expiring within 30 days**, or **Older than 90 days**. Use **Search** to filter by subject, resource, relation, or reason. Check **Valid until**, **Days left**, and **Granted by & reason** before deciding.

Break-glass events are not access-review candidates; they have their own security-officer queue. Sources: `packages/pdp-http/src/admin/reviews.ts`, `apps/admin/src/screens/AccessReviewsScreen.tsx`.

## Certify a grant

1. In **Recertification decision**, select **Certify**.
2. Choose the new **Until** date. It must be in the future, within 90 days, and later than the current expiry when one exists.
3. Enter at least 20 characters in **Review justification**.
4. Select **Preview impact** and inspect gained and lost access for the replacement tuple.
5. Select **Certify** to submit. The message **Review decision queued for approval** confirms that no change has applied yet.
6. Follow **Open in Approvals →** and ask an independent approver or security officer to decide.

You cannot certify a tuple you granted or one for which you are the subject. Certification creates an `add_tuple` proposal that replaces the old tuple on approval, rather than editing history in place. Sources: `packages/pdp-http/src/admin/reviews.ts`, `packages/pdp-http/src/admin/changes.ts`, `apps/admin/src/screens/AccessReviewsScreen.tsx`.

## Revoke a grant

1. Select **Revoke** in **Recertification decision**.
2. Enter at least 20 characters in **Review justification**.
3. Select **Preview impact** and inspect the access that will be lost.
4. Select **Revoke** to create a `remove_tuple` proposal.
5. Wait for independent approval. The tuple is not removed until approval applies the change, and its own expiry still applies in the meantime.

For an emergency, do not use the slower ordinary review path: ask a security officer to use **Break-glass → Revoke early** on an actual emergency grant. Sources: `packages/pdp-http/src/admin/reviews.ts`, `packages/pdp-http/src/admin/break-glass.ts`.

## Related pages

- [Understand access reviews](../concepts/governance-and-audit.md)
- [Inspect changes as an approver](approver.md)
- [Open emergency access as a security officer](security-officer.md)
- [Review role and scope permissions](../reference/roles-and-permissions.md)
