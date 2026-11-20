# Functional FAQ

These answers address common integration and administration questions for Qadamar, written against commit b09bc44 (after 0.3.0) and last revised, before this sentence was added, in commit 15b13f6 (2026-11-11, first released in 0.9.0); later releases are not reviewed here (see CHANGELOG.md). They point to the exact behavioral reference where a decision depends on policy, deployment configuration, or PEP responsibilities.

## On this page

- [Decisions and policy](#decisions-and-policy)
- [Enforcement and integration](#enforcement-and-integration)
- [Administration and evidence](#administration-and-evidence)
- [Availability and assurance](#availability-and-assurance)

## Decisions and policy

### Is a matching role enough to allow access?

No. A role or TRUE ABAC permit supplies only eligibility. Mandatory controls, need-to-know, ABAC forbids (content attributes included), CBAC (context, Zero Trust), Clark-Wilson, and SoD can still deny. Every delegation link must pass its applicable stages too. See [the decision pipeline](../concepts/decision-model.md).

### Does a relation grant clearance or bypass a compartment?

No. A relation supplies only a reason to know. Break-glass follows the same rule and is admitted only if the temporary relation produces a full allow. See [relations and delegation](../concepts/relations-and-delegation.md).

### Why did a rule fire when an attribute was missing?

A missing or null comparison operand is UNKNOWN. Permits and exemptions need TRUE; forbids and obligations fire on TRUE or UNKNOWN. Use `has` for an explicit existence test and validate representative missing-data cases. See [condition semantics](../concepts/policy-and-content.md).

### Can an allow contain work for the PEP?

Yes. It can require field allowlisting, redaction, masking, notification, or decision-token consumption. A deny contains no obligations. The included SDK refuses unsupported obligations, and the gateway refuses the request when its hooks or record shape cannot enforce them.

### Are policy roles the same as console roles?

No. Policy roles grant application actions to stored subjects. Console roles authorize administrators to use the control plane. The same name in the toy domain does not make them the same identity or permission system. See [roles and permissions](roles-and-permissions.md).

## Enforcement and integration

### Does Qadamar authenticate the end user?

The PEP must authenticate the end user and supply the subject reference. The PDP authenticates the PEP and resolves that reference against its own store. The gateway provides an `authenticate` hook for this responsibility. For constrained types listed in `clarkWilson.requirePepBinding`, certified commands run only for subject types the PEP credential is bound to. Within those types, the PDP still trusts the user the PEP names. See [PEP binding](../concepts/integrity-and-separation.md#bind-certified-commands-to-a-pep).

### Is a SQL filter sufficient before releasing records?

No. The residual covers resource-dependent authorization but not obligations, two-person checks, or SoD history. Re-check rows and enforce obligations before release. Database RLS generation and installation are **Not available**.

### Is verifying a decision-token signature enough to execute?

No. Consume the token at the PDP. Consumption checks single use, expiry, exact claims, resource version, current policy, a fresh decision for the consuming PEP, and the required post-state against IVPs and input validators. Offline verification does not perform those checks.

### Can the PEP supply the maker and prior actions?

Only in the explicit, warned compatibility opt-in `SOD_HISTORY=caller`, where server-recorded actions are added. The default in every profile is `SOD_HISTORY=server`, which ignores those caller claims for SoD-constrained actions. Production refuses caller mode. See [integrity and separation of duty](../concepts/integrity-and-separation.md).

### Does the gateway support any upstream API?

No. It supports declared HTTP routes in front of a plain-HTTP JSON upstream. HTTPS upstreams and GraphQL are **Not available**. The gateway forwards a signed decision assertion in the `gate-assertion` header; the backend verifies it with the SDK's `AssertionVerifier` or `withGateAssertion`.

### Can a backend tell that a request was authorized?

Yes, if it verifies the decision assertion. The assertion is a 30-second Ed25519 JWS, signed by the PDP only on an allow, bound to the subject, action, resource, decision id, policy version, backend origin, method, path, and body digest. The SDK verifier checks the signature against the PDP's JWKS, the binding, and a replay cache for the assertion's life. The replay cache is per backend process by default; several replicas must share one through the verifier's `replayStore` option (docs/API.md §2.0.2). The proof means the request was decided and sent by a credentialed PEP; it does not prove that a compromised PEP forwarded what it described.

## Administration and evidence

### Does an ordinary admin change apply immediately?

No. A validated proposal remains pending until an independent approver or security officer accepts the exact state and impact. Break-glass applies immediately as the emergency exception, and `SCIM_DIRECT=true` is an explicit provisioning alternative that requires an environment-provided token.

### Why does `/x/v1/explain` return 404 for a known resource?

It returns 404 for an unknown id or any denied read so hidden resources look absent. The scoped admin **Explain decision** API returns the full decision instead. Check the same request in **Simulator** when your role permits it.

### Why can a resource owner not find a record?

Owner-only scope includes the authenticated id and owner ids explicitly mapped by `RESOURCE_OWNERS`. It does not include every record related to the person, and out-of-scope lookups intentionally return 404. See [resource-owner tasks](../guides/resource-owner.md).

### Is the audit log impossible to alter?

Qadamar makes alteration evident through sequence and hash-chain checks; it does not make storage physically immutable. Optional RFC 3161 anchors strengthen the evidence, but you must retain anchors and exports off-box to detect replacement of both the log and its local anchors. See [audit verification](../guides/auditor.md).

### Does the Compliance screen certify compliance?

No. It maps product rules to selected controls, reports matching audit counts, and exports signed evidence packs for eight frameworks. UAE IA controls are unmapped. Evidence packs are product evidence for an auditor to test, not a certification, attestation, or statement of compliance. See [compliance evidence](../concepts/governance-and-audit.md#export-compliance-evidence).

## Availability and assurance

### What performance should I expect?

There is no universal throughput or latency figure. Use `docs/PERFORMANCE.md` only with its stated laptop, synthetic worlds, concurrency, storage mode, and version conditions; its measurements are not capacity targets or production SLAs. Run your own representative tests.

### Is Qadamar highly available?

PostgreSQL mode supports one active Qadamar node with waiting standbys and fail-stop storage behavior. Cluster mode (`GATE_CLUSTER`) lets every node decide against the shared PostgreSQL; the admin plane and SCIM stay on the leader, and followers answer them with 409 `not_leader`. A node past its staleness bound refuses decisions with 503, so the PEP must retry another node. Database high availability is **Not available**; database replication and failover belong to hosting. File mode is single-node and demo-only.

### Has the product been independently reviewed or certified?

No independent penetration test, formal model check, product certification, or browser WCAG conformance is claimed. The AuthZEN Todo vector replay is interoperability evidence, not OpenID certification. See `README.md`, `SECURITY.md`, `docs/AUTHZEN-CONFORMANCE.md`, and `docs/ACCESSIBILITY.md`.

### Which languages does the console and SDK support?

The console has English and French catalogues. It translates server errors by their stable code and shows the server's English message as a detail when it adds information. Server error messages themselves remain English. The PEP SDK is TypeScript; SDKs for other languages are **Not available**. Sources: `apps/admin/src/i18n/index.tsx`, `apps/admin/src/api/errorText.ts`, `apps/admin/src/i18n/errors.ts`, `packages/sdk/src/index.ts`.

## Related pages

- [Understand Qadamar](../concepts/overview.md)
- [Look up decision reasons](decision-reasons.md)
- [Look up error codes](error-codes.md)
- [Read limits and quotas](limits-and-quotas.md)
