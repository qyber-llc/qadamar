# Review break-glass access

Break-glass creates a short-lived `granted` relation that supplies a reason to know without waiving clearance, compartments, network, eligibility, integrity, or other pipeline checks. This runbook covers controlled opening, notification checks, revocation, expiry, and the independent review required to close the event, for the code at commit b09bc44 (after 0.3.0). The console screen is **Break-glass**.

## On this page

- [Open a controlled emergency grant](#open-a-controlled-emergency-grant)
- [Monitor active access](#monitor-active-access)
- [Revoke or expire the grant](#revoke-or-expire-the-grant)
- [Review and close the event](#review-and-close-the-event)
- [Respond to notification failure](#respond-to-notification-failure)
- [Audit checklist](#audit-checklist)

## Open a controlled emergency grant

### Preconditions

- The opener is an access administrator or security officer using an authenticated admin session and CSRF token.
- The opener is not the subject. Self-grant returns `403 forbidden`.
- The resource type declares a `granted` relation.
- The written reason has at least 20 characters, not counting leading and trailing spaces (`422 unprocessable` otherwise), and explains the incident and need.
- Requested duration is greater than zero and no more than four hours, and no more than the bundle’s `breakGlassMaxHours` if lower.
- Production has `BREAK_GLASS_WEBHOOK` (https) and `BREAK_GLASS_WEBHOOK_SECRET` configured (`packages/pdp-http/src/profile.ts`).
- In cluster mode, every break-glass call goes to the leader: followers answer `409 not_leader`. The expiry sweep and all webhook notices also run on the leader (`packages/pdp-http/src/server.ts`).

### Procedure

1. Confirm the incident, subject, resource, and minimum necessary duration through the organisation’s emergency process.
2. Check that the subject already has the required clearance, compartments, integrity, active status, and role or ABAC eligibility. Break-glass does not repair missing eligibility.
3. Open the emergency through the console or:

   ```http
   POST /admin/v1/break-glass
   Content-Type: application/json
   X-CSRF-Token: <session token>

   {
     "subjectId": "alice",
     "resourceId": "CASE-14",
     "reason": "Incident INC-42 requires temporary investigator access",
     "hours": 1,
     "network": "untrusted"
   }
   ```

   `network` affects only this admission evaluation and defaults to `trusted`. Every later application request supplies and enforces its own network context (`packages/pdp-http/src/admin/break-glass.ts`).
4. Require HTTP 201. A 422 means the proposed grant would still be denied; read the returned rule IDs and do not treat the emergency as opened.
5. Record the returned emergency ID, `expiresAt`, opener, and tuple ID from state/audit evidence.
6. Confirm the `break_glass` / `open` audit row and the signed `opened` notice. The notice contains IDs and time, not the free-text reason (`packages/pdp-http/src/notify.ts`).
7. Have the subject perform the minimum required action through the normal PEP. The PDP evaluates the temporary relation on every request and adds the configured notification recipients to the decision obligations.

Opening applies immediately without a second-person approval because it is an emergency control. Independent review is mandatory afterwards. The opener and the subject cannot review or revoke the event: the server answers `403 self_approval` (`packages/pdp-http/src/admin/break-glass.ts`).

## Monitor active access

During the window:

1. Track `active` entries in `GET /admin/v1/break-glass` and the overview count.
2. Review decision audit rows for the emergency subject and resource, including rule IDs and policy versions.
3. Verify that the PEP enforces `notify` obligations. The admin webhook does not replace application-level notification obligations returned by the engine.
4. Watch `gate_break_glass_notices_total{outcome="failed"}` and `outcome="sent"` on the node that sends notices: the active node, or the leader in cluster mode.
5. Confirm the emergency does not exceed its intended resource or action scope. The tuple supplies the relation named by the resource’s need-to-know configuration; it does not grant new RBAC rights.
6. Revoke early when the incident need ends. Do not leave access running merely because expiry is near.

An event with status `reviewed` can still appear in `active` until `expiresAt`. Review is an accountability decision, not a revocation (`packages/pdp-http/src/admin/break-glass.ts`).

## Revoke or expire the grant

### Revoke early

A security officer other than the opener and subject calls `POST /admin/v1/break-glass/:id/revoke` with a reason of at least 20 characters. Revocation removes the tuple from current state and emits a `revoked` notice. The next decision cannot use it (`packages/pdp-http/src/admin/break-glass.ts`).

A second revocation returns 409. Record the audit row and confirm access now denies when no other live relation applies.

### Expire automatically

The relation evaluator rejects a tuple after `validTo`; this does not depend on a timer or webhook (`packages/core/src/relations.ts`). Expiry is inclusive of the exact `validTo` instant and denied after it.

When the break-glass notifier is configured, a one-minute sweep finds expired, unrevoked events that were not already marked, audits `break_glass expire`, sets `expiryNotified`, commits, and sends the `expired` notice. Without a configured notifier, the sweep returns early, but the relation still expires on every decision (`packages/pdp-http/src/server.ts`, `packages/pdp-http/src/admin/break-glass.ts`).

After expiry, verify that no decision uses the emergency tuple and that the expiry audit/notice exists when notification is configured. The event remains available for review.

## Review and close the event

1. Assign a security officer who neither opened the emergency nor is its subject.
2. Gather the emergency reason, opener, duration, decision rows, notices, related incident record, and any revocation or expiry evidence.
3. Check whether access was necessary, proportionate, within the approved window, and consistent with mandatory controls.
4. Investigate unexpected subjects, resources, actions, networks, rule changes, or notification failures.
5. Reconcile certified-action history with the application’s actual writes. Token consumption alone does not prove the upstream commit (`packages/pdp-http/src/pdp.ts`, `packages/gateway/src/gateway.ts`).
6. Submit:

   ```http
   POST /admin/v1/break-glass/:id/review
   Content-Type: application/json
   X-CSRF-Token: <session token>

   {
     "outcome": "justified",
     "note": "Access matched INC-42, stayed within the approved window, and was revoked after recovery."
   }
   ```

   Use `escalated` instead of `justified` when further investigation or disciplinary/control action is required.
7. Require success and verify `reviewedBy`, `outcome`, and the review audit row. A second review returns 409.
8. If the event is still active and access is no longer justified, have an eligible different security officer revoke it as well. Review alone does not remove access.

## Respond to notification failure

Webhook delivery is asynchronous and never delays or rolls back the emergency request. Qadamar makes up to five attempts, each with a 10-second timeout and exponential backoff from 1 to 30 seconds, and refuses redirects. It then writes `break_glass notify_failed deny` and increments the failed counter (`packages/pdp-http/src/notify.ts`, `packages/pdp-http/src/server.ts`).

On failure:

1. Notify the incident/security channel through an independent approved method. Do not treat the emergency as unreported merely because the webhook failed silently in the background.
2. Check receiver availability, HTTPS, HMAC secret, timestamp acceptance, and redirect behavior.
3. Find the audit `notify_failed` row and its emergency ID, event, attempts, and short error (`HTTP <status>`, `timeout`, or `transport error`).
4. Preserve the original audit event as authoritative. A notice in flight at process stop can be lost.
5. Restore the receiver and use a later controlled event to verify delivery. A webhook replay API is **Not available**.
6. Record any manually delivered notification in the incident review; do not fabricate a successful delivery metric or audit row.

## Audit checklist

- Emergency ID, subject, resource, opener, reason, and duration match the incident.
- Admission returned 201 and did not bypass mandatory restrictions.
- `open`, all relevant decisions, `revoke` or `expire`, and `review` rows form one coherent timeline.
- Reviewer differs from opener and subject; outcome and note are complete.
- Any active access after review has an explicit continuing justification or is revoked.
- Webhook signatures and notice IDs were checked by the receiver; failures were handled independently.
- Obligations from decision responses were enforced by the PEP.
- Resource version and performed-action history reconcile with the application’s actual business writes.
- Any follow-up access change uses a new reviewed proposal; the emergency tuple is not extended as a routine grant.

## Related pages

- [Decision engine](../architecture/decision-engine.md)
- [Security architecture](../architecture/security-architecture.md)
- [Monitoring and alerts](monitoring.md)
- [Respond to an audit tamper alert](audit-tamper-response.md)
- [Rotate keys and credentials](rotate-credentials.md)
