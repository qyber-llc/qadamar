# Roles and permissions matrix

Console roles authorize control-plane screens and admin API operations; policy RBAC roles authorize application actions inside the decision engine. Keep these two identity domains separate, and remember that independent approval and resource-owner scope add further restrictions beyond the basic role checks.

## On this page

- [Compare console and policy roles](#compare-console-and-policy-roles)
- [Read the console and admin API matrix](#read-the-console-and-admin-api-matrix)
- [Understand scope and independence rules](#understand-scope-and-independence-rules)
- [Use the demo identities](#use-the-demo-identities)

## Compare console and policy roles

A console role belongs to an authenticated administrator and is checked by `allowed()` or scope functions in the HTTP layer. A policy role belongs to a stored application subject and grants resource actions through `bundle.rbac.roles`. For example, the demo console user `lina` has the console role `security_officer`, while the demo application subject `dan` has a policy role also named `security_officer`. They are different identities.

The `scim_provisioner` role is an internal provisioning permission, not a normal console persona. It can create only `scim_subjects` proposals and cannot make other change kinds. Source: `packages/pdp-http/src/admin/changes.ts`.

## Read the console and admin API matrix

“Scoped” means only resources and associated subjects within the authenticated resource owner's scope. “Review” means an additional independent person must approve. “API” marks an operation the console does not offer. In cluster mode, only the leader serves these operations; a follower answers every `/admin/` and `/scim/` request with 409 `not_leader`.

| Capability | access_admin | policy_author | approver | security_officer | resource_owner | auditor |
|---|---|---|---|---|---|---|
| Read overview | Yes | Yes | Yes | Yes | Scoped | Yes |
| Read schema and policy with its history | Yes | Yes | Yes | Yes | Yes | Yes |
| Read subjects, resources, tuples | Yes | Yes | Yes | Yes | Scoped | Yes |
| Read change list with payload and impact | Yes | Yes | Yes | Yes | Scoped visible changes | Yes |
| Simulator, access matrix, explain | Yes | Yes | Yes | Yes | Scoped | No |
| Propose `add_tuple` | Review | No | No | Review | No | No |
| Propose `update_subject` / `update_resource` | Review | No | No | Review | No | No |
| Propose `remove_tuple` | Review | No | No | Review | Scoped review | No |
| Propose `publish_policy` | Review | Review | No | Review | No | No |
| Propose `certify_tp` (API) | No | No | No | Review | No | No |
| Approve or reject, never own | No | No | Yes | Yes | No | No |
| List break-glass | Yes | No | No | Yes | No | No |
| Open break-glass | Yes | No | No | Yes | No | No |
| Revoke or review break-glass, never own/subject | No | No | No | Yes | No | No |
| List and perform access reviews | No | No | No | Yes | Scoped | No |
| Read PEP credentials and signing keys | Yes | No | No | Yes | No | No |
| Create, rotate, revoke PEP credentials; bind `subjectTypes` at creation (API) | No | No | No | Yes | No | No |
| Rotate signing key | No | No | No | Yes | No | No |
| Read SCIM credential metadata | Yes | No | No | Yes | No | No |
| Rotate console-minted SCIM credential | Yes | No | No | No | No | No |
| Audit search, verify, anchors, NDJSON export, `pseudonymise=1` | No | No | No | Yes | No | Yes |
| Compliance view and signed export | No | No | No | Yes | No | Yes |
| Evidence pack `GET /admin/v1/compliance/evidence` | No | No | No | Yes | No | Yes |
| Subject access report `GET /admin/v1/privacy/subjects/<id>` (API) | No | No | No | Yes | No | No |
| Read integrity certifications `GET /admin/v1/integrity/certifications` (API) | Yes | Yes | Yes | Yes | No | Yes |
| Run IVP verification `POST /admin/v1/integrity/verify` (API) | No | No | No | Yes | No | Yes |

The console's route table exposes **Break-glass** navigation to an auditor, but `GET /admin/v1/break-glass` accepts only access administrators and security officers. An auditor therefore receives 403 on that screen's data request. This is a console permission mismatch, not audit read permission.

Sources: `packages/pdp-http/src/auth.ts`, `packages/pdp-http/src/router.ts`, `packages/pdp-http/src/admin/index.ts`, `packages/pdp-http/src/admin/changes.ts`, `packages/pdp-http/src/admin/security.ts`, `packages/pdp-http/src/admin/integrity.ts`, `packages/pdp-http/src/admin/evidence.ts`, `packages/pdp-http/src/admin/privacy.ts`, `packages/pdp-http/src/siem.ts`, `packages/pdp-http/src/scim.ts`, `apps/admin/src/utils/permissions.ts`.

## Understand scope and independence rules

A user with only `resource_owner` sees resources whose `owner` equals the authenticated console id or an id mapped by `RESOURCE_OWNERS`. Associated subjects are visible only through tuples to those resources. Out-of-scope direct lookups return 404, and unscoped audit, break-glass, and compliance remain forbidden.

Additional invariants apply regardless of role:

- The maker cannot approve or reject their own change.
- A beneficiary cannot approve their own grant, subject update, or SCIM subject set.
- The holder of a SCIM credential cannot approve that credential's proposals.
- A mandatory-weakening publication needs a security officer as checker.
- A procedure's certifier and its approver must not be able to execute it, and are denied it afterwards (`CW.CERTIFIER_EXECUTES`).
- A reviewer cannot certify a tuple they granted or for which they are the subject.
- A break-glass opener or emergency subject cannot review or revoke that emergency.

TOTP enrolment is available to any local password account with a valid session and CSRF token, independent of console role, on the console's **Two-step sign-in** screen. The routes are `GET /admin/v1/session/totp` (status) and `POST /admin/v1/session/totp/enrol` and `/activate`. An account signed in through OIDC receives 403, and TOTP needs `SIGNING_KEY_SEAL`. Sources: `packages/pdp-http/src/runtime.ts`, `packages/pdp-http/src/admin/changes.ts`, `packages/pdp-http/src/admin/reviews.ts`, `packages/pdp-http/src/admin/break-glass.ts`, `packages/pdp-http/src/auth.ts`.

## Use the demo identities

| Local demo account | Console roles |
|---|---|
| `amira` | `access_admin`, `policy_author` |
| `omar` | `approver` |
| `lina` | `security_officer` |
| `ruth` | `resource_owner` |
| `sam` | `auditor` |

These accounts are generated for demonstration only. Production uses OIDC claims mapped to console roles or deliberately retained local accounts with TOTP. `RESOURCE_OWNERS='{"ruth":["carol"]}'` gives Ruth the demo's Carol-owned scope; without the mapping she sees only resources owned by `ruth`.

Source: `packages/pdp-http/src/auth.ts`.

## Related pages

- [Administer access](../guides/access-administrator.md)
- [Review changes](../guides/approver.md)
- [Work within resource-owner scope](../guides/resource-owner.md)
- [Understand policy roles](../concepts/policy-and-content.md)
