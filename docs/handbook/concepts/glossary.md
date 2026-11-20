# Glossary

This glossary defines Qadamar terms as the code at commit b09bc44 (after 0.3.0) uses them. It distinguishes application policy objects from console roles and separates decision outputs from the actions a PEP must perform.

## On this page

- [A–C](#ac)
- [D–L](#dl)
- [M–P](#mp)
- [R–Z](#rz)

## A–C

**ABAC (attribute-based access control)** — Rules that compare subject, resource, action, and context values. Qadamar supports `permit`, `forbid`, and `obligation` effects.

**ABAC on content attributes** — Content rules in the bundle's `abacContent` list, matched by content classes already assigned to a resource. Effects are `deny`, `mask`, and `redact`; codes are `ABAC.CONTENT_DENY`, `ABAC.CONTENT_MASK`, and `ABAC.CONTENT_REDACT`, in the `abac` trace stage. Formerly called CBAC (legacy bundle field `cbac`, still read for one version with the warning `DEPRECATED_CBAC_FIELD`).

**Access review** — Recertification or revocation of an eligible relation grant. The review itself creates a normal two-person change proposal.

**Action** — A domain-specific operation declared on a resource type. Its kind is `read`, `write`, `delete`, `approve`, or `execute`.

**Active node** — In PostgreSQL mode without cluster mode, the one node that serves requests while the others wait as standbys.

**Admin plane** — The `/admin/v1` and `/scim/v2` APIs that the console and provisioning use. In cluster mode only the leader serves it.

**Admin role** — See **console role**.

**Agent** — A subject acting for a person through `attrs.delegatedBy`. Every principal in its delegation chain must pass the applicable checks.

**Approver** — A console role that can approve or reject another person's pending change. It cannot propose changes.

**Audit record** — A metadata event in Qadamar's SHA-256 hash chain. It contains identifiers and rule information, not business record bodies. See **node chain**.

**Break-glass** — A short-lived `granted` relation for emergency need-to-know. It never lifts mandatory controls and requires independent review or revocation by a security officer.

**CBAC (context-based access control, Zero Trust)** — Rules in the bundle's `context` list that re-verify situational PEP assertions on every request, plus grant duration (`notBefore`/`notAfter` on role assignments and relation tuples) and session expiry. A missing required signal is UNKNOWN and denies. Codes are `CBAC.*`, trace stage `cbac`.

**Certification record** — A two-person record that certifies an action as a transformation procedure for a constrained type. It affects decisions for types in `clarkWilson.requireCertification`, and its certifier and approver are denied that procedure.

**Certified command** — An action marked `certified`. An allowed evaluation emits a decision-token obligation.

**Certifier** — The security officer who proposed a certification record, or the person who approved it. A certifier cannot be able to run the procedure when certifying it and is denied it afterwards with `CW.CERTIFIER_EXECUTES` (Clark-Wilson E4).

**Change proposal** — A pending administrative change with a maker, payload, reason, impact, and state digest. It ends as `applied` or `rejected` after independent review.

**Clark-Wilson** — The family of integrity controls covering constrained items, certified commands, IVPs, input validators, PEP binding, certifiers, decision tokens, and separation of duty. E1 and E3 are Partial, as documented in the integrity concepts.

**Clearance** — A subject's maximum confidentiality level, L0 through L3.

**Cluster mode** — A PostgreSQL deployment, enabled with `GATE_CLUSTER`, in which every node decides against the shared state. The leader holds the admin plane; followers answer it with 409 `not_leader`.

**Compartment** — A named access restriction. A subject must hold every compartment on a resource.

**Condition** — A JSON expression used by ABAC, content-attribute exemptions, and IVPs. Comparisons can be TRUE, FALSE, or UNKNOWN.

**Console** — The browser application for administrators, served by the Qadamar node, in English and French.

**Console role** — Authorization for the admin plane: `access_admin`, `policy_author`, `approver`, `security_officer`, `resource_owner`, or `auditor`. It is not a policy role.

**Constrained data item** — A resource whose type is marked `constrained`. Its non-read actions must be certified.

**Content class** — A closed label such as `pii.iban` that describes detected content. Qadamar consumes the label; it does not perform the scan.

**Context** — Request facts such as network, session level, maker, prior actions, command input, and decision time. The PDP derives security-sensitive parts, such as certification records, history, and the PEP binding, on the server.

## D–L

**Decision** — The engine result containing allow or deny, rule ids, reasons, obligations, trace, dry-run warnings, and policy version.

**Decision assertion** — A 30-second Ed25519 JWS that the PDP signs for an allowed request through `/x/v1/assertions/evaluation` or `/x/v1/assertions/list`. It binds subject, action, resource, decision id, policy version, the backend origin, method, path, and body digest. The gateway forwards it in the `gate-assertion` header; a backend verifies it with the SDK's `AssertionVerifier`. It is not a decision token.

**Decision token** — A short-lived, single-use Ed25519 JWS issued for an allowed certified command. Consumption revalidates the action on current PDP state.

**Delegation chain** — The subject followed by each person it acts for. At most five principals are accepted: the subject and up to four delegators.

**Dry run** — Need-to-know mode that reports `wouldDeny` without denying for a missing relation.

**Effective level** — The resource level used by point decisions and SQL filters. Store invariants keep a child at or above its parent's level.

**Eligibility** — The first authorization requirement: an expanded RBAC grant or a TRUE ABAC permit for every principal.

**Evidence pack** — A per-framework export of live evidence with a manifest of section hashes and a detached signature, from `GET /admin/v1/compliance/evidence`. It is product evidence, not a certification.

**Fail closed** — Deny when input, policy evaluation, storage, or enforcement cannot establish a safe allow. A PEP also refuses obligations it cannot enforce.

**Field allowlist** — An obligation listing the only dotted record fields a PEP may return. Multiple allowlists intersect.

**File mode** — Storage in local files on one node, for the demo and evaluation only.

**Follower** — In cluster mode, a node that decides but does not hold the admin plane. `GET /leaderz` returns 503 on a follower.

**Gateway** — Qadamar's reverse-proxy PEP for JSON HTTP APIs. It decides, consumes tokens, filters lists, applies obligations, forwards a decision assertion, and fails closed.

**Hidden means absent** — The behavior that hides unauthorized resources rather than revealing their existence. `/x/v1/explain` returns 404 for unknown ids and denied reads; resource-owner scope returns 404 for out-of-scope lookups.

**Impact preview** — A before-and-after comparison that reports gained and lost subject-resource-action cells for a candidate administrative change.

**Input validator** — A declared field schema, in `clarkWilson.inputValidators`, for the input of a certified command (Clark-Wilson C5). It checks `context.input` at decision and the post-state at token consumption.

**Integrity** — Biba trust rank: `derived`, `extracted`, `system`, or `verified`.

**IVP (integrity verification procedure)** — A resource-only condition that must be TRUE for a constrained item. IVPs run at decision, filtering, token consumption, and administrative verification.

**JWS (JSON Web Signature)** — The signature format used for decision tokens, decision assertions, policy publications, and compliance exports and evidence packs.

**Leader** — In cluster mode, the one node that holds the admin plane and SCIM. `GET /leaderz` returns 200 on the leader, and on any node outside cluster mode.

## M–P

**Maker** — The person who proposed an administrative change, or the person whose earlier action makes them ineligible for a later two-person action.

**Managed offer** — One dedicated Qadamar per customer on Kubernetes, described in `docs/MANAGED-OFFER.md`. It is proven end to end only on a local test cluster.

**Mandatory controls** — Built-in classification, compartment, network, and integrity checks that relations and tenant permits cannot bypass.

**Masking** — Replacement of classified `content` fragment text with `[MASKED]` by the SDK or gateway.

**Need-to-know** — A relation-based reason to access a protected resource. Modes are `off`, `dry_run`, and `enforce`.

**Node chain** — The audit hash chain one node writes in PostgreSQL mode, named by `GATE_NODE_ID`. Chain `0` is the chain of a non-cluster node and of rows from earlier versions.

**Notification obligation** — Recipients attached to an allow. The SDK refuses these; the gateway requires a notification hook.

**Obligation** — Work the PEP must complete for an allow, such as redaction, masking, notification, field restriction, or token consumption. Denials carry none.

**PDP (policy decision point)** — The service that evaluates access requests, searches, filters, and token consumption from stored policy and attributes.

**PDP API** — The `/access/v1`, `/x/v1`, and `/xacml/v3` endpoints that PEPs call with a PEP credential.

**PEP (policy enforcement point)** — The application component that asks for a decision and enforces it. It must authenticate the end user and apply all obligations.

**PEP binding** — The subject types a PEP credential is bound to at creation (`subjectTypes`). For types in `clarkWilson.requirePepBinding`, certified commands run only for subjects of a bound type (Clark-Wilson E3).

**Performed-action history** — Server-persisted subject-resource-action records created by successful certified-token consumption and used for SoD.

**Policy bundle** — The versioned JSON description of schema, RBAC, mandatory parameters, need-to-know, ABAC (including content attributes), CBAC (context), SoD, and Clark-Wilson controls.

**Policy role** — An application RBAC role declared in `bundle.rbac.roles`, distinct from a console role.

**Policy version** — `pv.` plus SHA-256 of canonical bundle JSON in the current format. Older 16-hex FNV fingerprints remain readable.

**PostgreSQL mode** — Storage of state, audit, and shared security material in PostgreSQL, selected with `DATABASE_URL`. Without cluster mode, one node is active and the others are standbys.

**Post-state** — The resource attributes as a certified command will commit them. Token consumption checks them with IVPs and input validators when required.

**Pseudonymised export** — An audit export or evidence pack requested with `pseudonymise=1`, in which person ids are replaced by keyed `ps.` pseudonyms.

## R–Z

**RBAC (role-based access control)** — Policy roles and inheritance that grant actions on resource types.

**Reason to know** — The basis supplied by a successful need-to-know relation path. It never grants clearance or integrity.

**ReBAC (relationship-based access control)** — Relation tuples and rewrites that compute reasons to know from direct, group, parent, and reporting-line relationships.

**Redaction** — Replacement of listed response fields with `null` by the SDK or gateway.

**Relation tuple** — A stored `object#relation@subject` fact, optionally with a userset, `notBefore`/`notAfter` validity window, grant metadata, or break-glass marker.

**Residual** — The resource-only predicate left after Qadamar partially evaluates a list authorization request. The SQL compiler turns it into a parameterized PostgreSQL `WHERE` clause.

**Resource** — The stored item being accessed, identified by type and id and carrying classification, integrity, attributes, and content classes.

**Resource owner** — A console role scoped to resources whose `owner` matches the authenticated user id or an id mapped by `RESOURCE_OWNERS`.

**SCIM** — The provisioning API for users and groups. Writes normally become two-person `scim_subjects` proposals.

**Separation of duty (SoD)** — Two-person action rules and bundle-defined conflicting-action rules on one resource.

**Session level** — The subject's working classification for a request, capped at clearance.

**Signing key** — An Ed25519 key used for decision tokens, decision assertions, policy publications, and evidence packs. Public keys are exposed through JWKS.

**SoD history mode** — `SOD_HISTORY=server` (default) ignores caller maker/history for SoD-constrained actions and uses PDP-recorded history; explicit `caller` is a warned compatibility opt-in for demos/tests that trusts those claims.

**Stale proposal** — A pending change whose stored state, impact, or grant validity no longer matches at approval. Approval returns 409 `stale`; the maker must submit a new proposal.

**Staleness bound** — In cluster mode, the longest time, `GATE_MAX_STALENESS_MS`, a node may go without confirming the shared state. Past it the node refuses decisions with 503 `unavailable` and fails `/readyz`.

**Standby** — In PostgreSQL mode without cluster mode, a node waiting to take over from the active node.

**Subject** — The stored person, service, agent, group, or external entity requesting an action.

**Subject access report** — Everything the control plane holds about one subject id, from `GET /admin/v1/privacy/subjects/<id>`, for a security officer.

**TOTP** — Time-based one-time passwords for local password accounts, enrolled on the console's **Two-step sign-in** screen.

**Trace** — The stage-by-stage explanation of passes, denials, obligations, and dry-run warnings, including successful relation paths.

**Trusted proxy** — A reverse proxy listed in `TRUSTED_PROXIES`. Only from such a peer does the PDP read the client address from `X-Forwarded-For`, for rate limiting, login lockout, sign-in audit rows, and request spans.

**Two-person rule** — Independent maker-checker control for admin changes, or an action-level prohibition on the maker performing that action.

**Two-step sign-in** — The console screen where a local password account enrols and activates TOTP.

**UNKNOWN** — The third condition value produced by missing or null operands. Permits and exemptions require TRUE; forbids and obligations fire on TRUE or UNKNOWN.

**Userset** — A tuple subject qualified by `subjectRelation`, such as all `member` users of a team.

**World** — The bundle, subjects, resources, and tuples used for a decision or impact simulation.

## Related pages

- [Understand Qadamar](overview.md)
- [Follow a decision through the core](decision-model.md)
- [Understand integrity and separation of duty](integrity-and-separation.md)
- [Read the roles and permissions matrix](../reference/roles-and-permissions.md)
