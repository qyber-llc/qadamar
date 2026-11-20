# Manage security operations

A security officer handles emergency access, procedure certifications, PEP credentials, signing keys, compliance evidence, subject access requests, and the approval of mandatory-control weakening. Use independent people for each maker-checker step, and keep secrets and verification material outside the console after their one-time display.

## On this page

- [Open and close emergency access](#open-and-close-emergency-access)
- [Certify procedures and run IVPs](#certify-procedures-and-run-ivps)
- [Manage PEP credentials](#manage-pep-credentials)
- [Rotate decision-token signing keys](#rotate-decision-token-signing-keys)
- [Review compliance and export evidence](#review-compliance-and-export-evidence)
- [Answer a subject access request](#answer-a-subject-access-request)
- [Approve mandatory weakening](#approve-mandatory-weakening)
- [Turn on two-step sign-in](#turn-on-two-step-sign-in)

## Open and close emergency access

An access administrator or security officer can open break-glass. Only a security officer can revoke or review an emergency, and never one they opened or one in which they are the subject (403 `self_approval`). In the demo, have Amira open the emergency so that Lina can review it.

- **Open.** In **Break-glass → Open emergency grant**, select the **Subject** and **Resource**, set **Hours (1–4)**, enter **Incident justification (at least 20 characters)**, and select **Open break-glass grant**. The API also enforces the bundle's `breakGlassMaxHours` when it is lower than 4. If the console shows **Mandatory rules still denying access**, nothing was opened: break-glass supplies only a reason to know and does not waive clearance, compartments, network, eligibility, or integrity.
- **Revoke early.** In **Active grants**, enter a **Written revoke reason** of at least 20 characters and select **Revoke early**. The relation tuple is removed at once.
- **Review.** In **Post-incident review queue**, write a review note and select **Justified** or **Escalated**. The outcome and reviewer are stored and audited.

When `BREAK_GLASS_WEBHOOK` is configured, a signed HTTPS notice reports each open, revoke, and expiry with ids and times only, never the incident reason. Email and paging integrations are **Not available**. For the full procedure, monitoring, and notification-failure response, follow [Review break-glass access](../operations/break-glass-review.md). Sources: `packages/pdp-http/src/admin/break-glass.ts`, `packages/pdp-http/src/notify.ts`.

## Certify procedures and run IVPs

A console screen for certification and IVP runs is **Not available**. Certification proposals appear in **Approvals** like any other change. Use the admin API:

- `GET /admin/v1/integrity/certifications` lists certification records and the certified actions that have no record. Every console role except resource owner can read it.
- `POST /admin/v1/changes` with `kind: "certify_tp"` and `payload: { "resourceType": "payment", "action": "approve" }` proposes a certification. Only a security officer can propose it, and an independent approver or security officer must approve it.
- `POST /admin/v1/integrity/verify` runs every declared IVP over every stored item. Security officers and auditors can call it. The response reports `verified`, `checked`, `policyVersion`, and per-item results, and the run is audited as a `security` event with action `ivp_run`.

The maker and the checker must each be a PDP subject with the same id as their console user, and neither may be able to execute the procedure at proposal or approval time. A certification record admits the procedure only for types listed in `clarkWilson.requireCertification`. Whatever the type, the record also denies the procedure to its certifier and its checker with `CW.CERTIFIER_EXECUTES`, even if they gain the right later. Sources: `packages/pdp-http/src/admin/integrity.ts`, `packages/pdp-http/src/admin/changes.ts`, `packages/pdp-http/src/runtime.ts`, `packages/core/src/procedures.ts`.

## Manage PEP credentials

Open **Credentials and keys → PEP credentials**. Use one credential per enforcement point. An access administrator can see the list; only a security officer can create, rotate, or revoke.

- **Create.** Enter a unique name in **PEP name (1 to 80 characters)** and select **Create credential**. Copy the secret from **Secret, shown once** into the PEP's secret store, then select **I have stored it**.
- **Rotate.** Select **Rotate** and store the new secret. The previous secret stays valid for `PEP_ROTATION_GRACE_SECONDS`, 300 seconds by default, and the row shows **Previous secret valid until**.
- **Revoke.** Select **Revoke** and confirm. The current and previous secrets stop at once.

**Bind a credential to subject types (PEP binding).** A credential can be bound to the subject types its PEP authenticates. For constrained types listed in `clarkWilson.requirePepBinding`, a certified command is allowed only when the subject's type is one of the calling credential's `subjectTypes`; otherwise the decision denies with `CW.SUBJECT_NOT_AUTHENTICATED`. A credential with no `subjectTypes` is bound to no type. Binding is **Partial**: the console cannot set it. Set it when you create the credential through the API:

```http
POST /admin/v1/pep-credentials
Content-Type: application/json
X-CSRF-Token: <session token>

{ "name": "payments-gateway", "subjectTypes": ["user"] }
```

`subjectTypes` lists 1 to 16 distinct types, each 1–64 characters from letters, digits, `_`, `.`, and `-`. Rotation keeps the binding. To change it, create a new credential and revoke the old one.

**Scope context claims.** Also set `contextScopes` through the creation API to the only signals this PEP may assert:
`network`, `ip`, `country`, `device`, `authTime`, `mfaTime`, `authMethods`, `riskScore`, or `sessionLevel`. For example,
`[{ "signal": "network", "networks": ["trusted"] }, { "signal": "country", "countries": ["AE", "FR"] }]` permits only
trusted-network assertions and AE/FR country claims. An out-of-scope claim is refused and audited. Production requires
this field and treats older unscoped credentials as having `[]`; demo compatibility keeps them permissive for one version
with deprecation warnings. Rotation preserves scopes; use a new credential to change them.

For independently proven device or network posture, add `attestation: { audience, keys }` to that signal's scope. Keys
are public Ed25519 (`EdDSA`) or P-256 (`ES256`) JWKs with unique `kid`s, never private key material. Give the exact API
format to the MDM/sensor operator ([API](../../API.md#2-pdp-api-authzen-authorization-api-10--extensions)); the PEP sends
each resulting JWS as `context.attestations.<signal>`. It must name the request subject (`sub`), the PDP session (`sid`)
when a session token is used, and for device/network evidence the source (`src`) stated as `device.id` or
`networkSensorId`. It is reusable only for that same subject, session and source. Missing, expired, wrong-audience,
wrong-credential, wrong-subject, wrong-session, wrong-source or wrong-value evidence is refused.

**Revoke PDP sessions.** `POST /admin/v1/blp-sessions/revoke` ends current BLP sessions immediately, including their
unconsumed decision tokens. Send one selector: `{ "sessionId": "..." }`, `{ "credential": "..." }`, or
`{ "subject": { "type": "user", "id": "..." } }` with optional `credential`. The response reports `revoked` and up to
100 `sessionIds`; repeating it is safe. `GET /admin/v1/blp-sessions/revocations` lists shared tombstones. Use credential
revocation as well when the PEP itself is compromised, so it cannot open replacements.

For overlap rotation, the move away from the shared `bootstrap` credential, and rollback, follow [Rotate keys and credentials](../operations/rotate-credentials.md#rotate-a-pep-credential). Sources: `apps/admin/src/screens/CredentialsScreen.tsx`, `packages/pdp-http/src/admin/security.ts`, `packages/pdp-http/src/auth.ts`, `packages/core/src/procedures.ts`.

## Rotate decision-token signing keys

1. Open **Credentials and keys → Decision-token signing keys**.
2. Save the current public JWKS with any evidence that must remain verifiable offline.
3. Select **Rotate signing key** and confirm.
4. Update any verifier that pins the active `kid` rather than reading `/.well-known/jwks.json`.

The new key signs decision tokens, decision assertions, the policy bundle in force, and later evidence packs. The previous private key is discarded at once; its public key stays in the JWKS for 300 seconds and then leaves it. The bundle in force is re-signed during rotation. A backend that uses the SDK's `AssertionVerifier` fetches the JWKS again when it meets an unknown `kid`. Private keys are sealed with `SIGNING_KEY_SEAL` when it is set; the production profile requires it.

The **SCIM credential** card is read-only for a security officer. Only an access administrator can rotate a console-minted SCIM credential, and that person cannot approve its proposals. For the full procedure, follow [Rotate keys and credentials](../operations/rotate-credentials.md#rotate-the-decision-token-signing-key). Sources: `packages/pdp-http/src/tokens.ts`, `packages/pdp-http/src/admin/security.ts`, `packages/pdp-http/src/policy-signature.ts`.

## Review compliance and export evidence

Open **Compliance**. Security officers and auditors can open it.

- The framework tables map NIST SP 800-53 Rev. 5 and ISO/IEC 27001:2022 Annex A controls to the rule ids that enforce them, with **Decisions**, **Denies**, and **Last seen** counted from the audit. UAE Information Assurance has no mapped controls. **Export evidence pack** returns these mappings and counts with a detached signature.
- The **Evidence pack per framework** card builds a pack for one framework from live data: configuration baseline, time and anchors, policy publications and certifications, audit chain head and anchors, access reviews, approvals, break-glass, keys and PEP credentials, security events, and CI references. Choose the **Framework**, optionally select **Replace person ids with pseudonyms**, and select **Export signed evidence pack**. The card shows the **Pack SHA-256** and the hash of each manifest section, and offers **Download JSON**.

The API equivalent is `GET /admin/v1/compliance/evidence?framework=<id>`, with `&pseudonymise=1` to replace person ids. Framework ids are `iso27001`, `iso27017`, `iso27018`, `iso27701`, `iso42001`, `iec62443-4-1`, `iec62443-4-2`, and `soc2`. Any other parameter, or a repeated one, returns 400. Each export is audited as a `security` event with action `evidence_export`.

Evidence packs and counts are product evidence for an auditor to test. They are not a certification, an attestation, or a statement of compliance. To verify a pack, follow [Export and verify compliance evidence](auditor.md#export-and-verify-compliance-evidence). Sources: `packages/pdp-http/src/admin/compliance.ts`, `packages/pdp-http/src/admin/compliance-map.ts`, `packages/pdp-http/src/admin/evidence.ts`, `apps/admin/src/screens/EvidencePackCard.tsx`.

## Answer a subject access request

A console screen for this report is **Not available**. Call `GET /admin/v1/privacy/subjects/<url-encoded id>` with a security officer session. Only a security officer can call it. The id is 1–256 characters after decoding.

The report lists everything the control plane holds about that id: matching subjects, relation tuples, emergencies, changes that name the id as maker, checker, or in their payload, and the newest 1,000 audit rows for the subject. `audit.complete` is `false` when older rows were left out. Audit rows are append-only and hash-chained, so they are reported, not erased. The report itself is audited as a `security` event with action `subject_access_report`.

To share audit rows without exposing people, export them with `pseudonymise=1` (see [Export raw audit records](auditor.md#export-raw-audit-records)). Pseudonyms are stable across exports only when `SIGNING_KEY_SEAL` is set; without it they change when the process restarts. Sources: `packages/pdp-http/src/admin/privacy.ts`, `packages/pdp-http/src/server.ts`.

## Approve mandatory weakening

In **Approvals**, a policy publication with `weakensMandatory` findings can be approved only by a security officer who is not the maker. Review each finding. They include a raised untrusted-network ceiling, a lowered need-to-know mode, a longer break-glass cap or token lifetime, removed or changed IVPs and input validators, removed certification or PEP-binding requirements, redefined relations, removed compartments, and removed SoD or content rules. Sources: `packages/core/src/weakening.ts`, `packages/pdp-http/src/admin/changes.ts`.

## Turn on two-step sign-in

Every console role can open **Two-step sign-in**. It applies to local password accounts. An account that signed in through the organisation's identity provider gets its second factor there, and the screen says so.

1. Enter your current password and select **Start setup**.
2. Scan the QR code with an authenticator app, or type the **Setup key**. The key is shown once.
3. Enter the 6-digit code in **6-digit code from the app** and select **Turn on two-step sign-in**.
4. Store the ten recovery codes, then select **I have stored them**. Each recovery code works once; only their hashes are kept.

From then on, the sign-in screen asks for **One-time code (if enrolled)**. The screen cannot turn two-step sign-in off; an operator resets it on the server, see [Local passwords and TOTP reset](../operations/rotate-credentials.md#local-passwords-and-totp-reset). Setup needs `SIGNING_KEY_SEAL`, because TOTP secrets are sealed at rest; without it the screen says the server cannot store second factors.

The API equivalent is `GET /admin/v1/session/totp` for the status (`active`, `pending`, `available`), then `POST /admin/v1/session/totp/enrol` with `{ "password": "<current password>" }` and `POST /admin/v1/session/totp/activate` with `{ "code": "<six-digit code>" }`, with a session and CSRF token. The production profile requires OIDC with MFA, and either disables local password sign-in or requires every local account to have TOTP active. Sources: `apps/admin/src/screens/TwoStepScreen.tsx`, `packages/pdp-http/src/auth.ts`, `packages/pdp-http/src/router.ts`, `packages/pdp-http/src/profile.ts`.

## Related pages

- [Review break-glass access](../operations/break-glass-review.md)
- [Rotate keys and credentials](../operations/rotate-credentials.md)
- [Understand Clark-Wilson coverage](../concepts/integrity-and-separation.md)
- [Review changes as an approver](approver.md)
- [Verify and export evidence as an auditor](auditor.md)
