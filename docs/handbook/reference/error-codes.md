# HTTP error codes

The PDP and admin APIs use a small set of HTTP error codes with sanitized messages. Treat authorization denials, stale proposals, transport failures, and unsupported media differently, and preserve the optional `details` array and `Retry-After` header when troubleshooting.

## On this page

- [Read the error envelope](#read-the-error-envelope)
- [Resolve client errors](#resolve-client-errors)
- [Resolve server errors](#resolve-server-errors)
- [Handle SCIM, XACML, and gateway variants](#handle-scim-xacml-and-gateway-variants)

## Read the error envelope

Most PDP and admin errors have this shape:

```json
{
  "error": "bad_request",
  "message": "Invalid JSON",
  "details": ["Optional structured detail"]
}
```

`details` is present only for some errors. A 429 also sets `Retry-After` in seconds. Unexpected exceptions become 500 `internal` without stack traces or internals. The tables cover every code thrown as `HttpError` under `packages/pdp-http/src` in the code at commit b09bc44 (after 0.3.0), plus two responses that the router builds directly: `invalid_request` and `not_leader`.

Sources: `packages/pdp-http/src/http.ts`, `packages/pdp-http/src/router.ts`.

## Resolve client errors

| HTTP | Code | Meaning and typical action |
|---:|---|---|
| 400 | `bad_request` | Invalid JSON or fields, an incomplete or aborted body, unsafe path, invalid paging or filters, wrong SQL mapping, or another malformed request. Correct the request; the PDP does not guess missing values. |
| 400 | `invalid_request` | The OIDC back-channel logout did not contain exactly one valid logout token. The router builds this response directly; it is not thrown as `HttpError`. |
| 401 | `unauthenticated` | Missing, expired, revoked, or invalid console session, PEP credential, SCIM credential, or metrics token. Authenticate again or rotate the credential; do not retry unchanged. |
| 403 | `forbidden` | The authenticated identity lacks the required role or scope, CSRF validation failed, self-grant or beneficiary restrictions apply, a certifier could run the procedure, TOTP was requested for an account that is not a local password account, or another security check refused the operation. Review role, ownership, and the sanitized message. |
| 403 | `context_claim_forbidden` | The PEP asserted a signal outside its credential's `contextScopes`, a network/country outside its constraint, or an attestation that does not accompany an allowed asserted signal. Correct the credential scope or request; nothing was silently dropped. |
| 403 | `invalid_context_attestation` | A required context attestation is missing, malformed, expired, signed by an untrusted key, or bound to another value, PEP credential, signal, or audience. Obtain fresh evidence from the configured attester. |
| 403 | `invalid_session_token` | The PDP session token is forged, expired, closed, revoked, or bound to another subject or PEP credential. Open a fresh session with the correct credential; any decision token issued under the revoked session is also unusable. |
| 403 | `self_approval` | The maker tried to decide their own change, the SCIM credential holder tried to decide its proposal, or the emergency opener or subject tried to review or revoke it. Use an independent authorized person. |
| 403 | `password_login_disabled` | Local password login is disabled because the deployment requires SSO. Use **Sign in with your organisation**. |
| 404 | `not_found` | The route or entity does not exist, or it is outside the caller's visible scope. Do not infer existence from this response; check identifiers and scope. |
| 409 | `conflict` | The resource is already in that state, a name is already used, a decision token cannot be consumed, TOTP enrolment cannot start, or the operation conflicts with current state. Re-read current state and correct the request. |
| 409 | `stale` | A proposal's state, impact, or grant validity changed since preview. Create and review a fresh proposal rather than approving the old one. |
| 409 | `not_leader` | Cluster mode: this node is a follower, and it refuses every `/admin/` and `/scim/` request, read or write, without an audit row. The body is `{ "error": "not_leader", "message": "...", "leader": <GATE_ADVERTISE_URL of the leader, or null> }`. Send the request to the leader; a load balancer can find it with `GET /leaderz`. |
| 413 | `payload_too_large` | The PDP request body exceeded 1 MB. The response uses the usual JSON envelope and `Connection: close`; reduce the body before retrying. |
| 415 | `unsupported_media_type` | The endpoint requires its declared JSON or form media type. Use `application/json`, the accepted profile variants, or `application/x-www-form-urlencoded` where specified. |
| 422 | `unprocessable` | The request is well-formed JSON but fails validation or policy invariants. Read `details` for bundle errors, mandatory denials, invalid validity windows, or other precise findings. |
| 429 | `rate_limited` | A token bucket or login lockout refused the request. Wait for `Retry-After`, reduce request or batch cost, and address repeated login failures. |

Both the PDP and gateway return 413 `payload_too_large` for oversized bodies. Sources: `packages/pdp-http/src/http.ts`, `packages/pdp-http/src/pdp.ts`, `packages/pdp-http/src/admin/changes.ts`, `packages/pdp-http/src/auth.ts`, `packages/pdp-http/src/router.ts`.

## Resolve server errors

| HTTP | Code | Meaning and typical action |
|---:|---|---|
| 500 | `internal` | An unexpected server failure occurred. Inspect server logs and storage health; the response deliberately contains no internals. |
| 502 | `idp_unavailable` | The identity provider could not be reached or returned inconsistent metadata during OIDC discovery. Check IdP availability and configuration. |
| 503 | `unavailable` | Storage or audit integrity is unavailable, TOTP is used without `SIGNING_KEY_SEAL`, or, in cluster mode, the node has not confirmed the shared policy state within its staleness bound (`GATE_MAX_STALENESS_MS`) and refuses PDP and XACML decisions. Retry a stale-node decision on another node; for storage or audit failures, stop dependent writes and investigate before restarting or failing over. |

A failing audit or store must not be converted into a local allow. `GET /readyz` returns 503 with `{ "status": "unavailable" }` rather than the usual error envelope, including on a node past its staleness bound. `GET /leaderz` returns 503 with `{ "leader": false, "node": "<id>" }` on a follower. Sources: `packages/pdp-http/src/oidc.ts`, `packages/pdp-http/src/postgres.ts`, `packages/pdp-http/src/auth.ts`, `packages/pdp-http/src/metrics.ts`, `packages/pdp-http/src/router.ts`.

## Handle SCIM, XACML, and gateway variants

SCIM uses the same HTTP status and internal code set, but its body follows the SCIM Error schema: `schemas`, `status` as a string, and `detail`. Do not expect the normal `error` and `message` fields.

XACML returns HTTP 200 with `Indeterminate` for request syntax, missing attributes, processing errors, and obligations it cannot express. Check `Status.StatusCode.Value` and `StatusDetail`; `XACML.INDETERMINATE` and `XACML.OBLIGATION_UNEXPRESSIBLE` appear in audit metadata. Configure XACML PEPs as deny-biased. Sources: `packages/pdp-http/src/scim.ts`, `packages/pdp-http/src/xacml.ts`.

The gateway has a separate refusal envelope `{ "error": "<code>" }`:

| HTTP | Gateway code | Meaning |
|---:|---|---|
| 400 | `bad_request` | Invalid path, body, post-state JSON, or method override. |
| 401 | `unauthenticated` | The gateway's `authenticate` hook did not return a valid caller. |
| 403 | `forbidden` | The PDP denied the action; upstream was not called. |
| 404 | `not_found` | No declared gateway route matches. |
| 409 | `conflict` | Decision-token consumption failed. |
| 413 | `payload_too_large` | Request body exceeded `maxBodyBytes`; the connection closes. |
| 500 | `internal` | Unexpected gateway failure. |
| 502 | `obligation_unenforceable` | A notification, token, content transformation, or response obligation could not be enforced. |
| 502 | `unenforceable_decision` | The PDP response was malformed or unsupported, or an allow came without a decision assertion. |
| 502 | `list_unenforceable` | A list exceeded 1,000 items or lacked usable string ids. |
| 502 | `upstream_unavailable` | The upstream could not be reached. |
| 502 | `upstream_too_large` | The upstream response exceeded `maxResponseBytes`. |
| 502 | `upstream_error` | The upstream returned a non-2xx response; its body is suppressed. Other 4xx/5xx statuses can be preserved with this code. |
| 503 | `pdp_unavailable` | The PDP was unreachable or returned an SDK-level error. |
| 504 | `upstream_timeout` | The complete upstream exchange exceeded its deadline. |

Source: `packages/gateway/src/gateway.ts`.

## Related pages

- [Interpret decision rule ids](decision-reasons.md)
- [Handle stale changes as an approver](../guides/approver.md)
- [Handle SDK and gateway failures](../guides/integrator.md)
- [Read request and rate limits](limits-and-quotas.md)


## Tenant partition ingress

With `GATE_TENANTS_FILE`, 400 `tenant_required` means the request must carry exactly one valid `X-Qadamar-Tenant`
header. HTTP 421 `tenant_not_served` means this node has no runtime for that tenant; route to its assigned partition.
Neither error is a policy decision, and neither falls back to a different tenant. Ingress has no tenant audit chain
for those refusals; count them at the edge. Existing PEP authentication is still required after tenant selection.
