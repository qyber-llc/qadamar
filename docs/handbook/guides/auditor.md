# Investigate and export audit evidence

An auditor has read-only access to policies, changes, integrity checks, the audit chain, and compliance mappings. Search by exact metadata, verify the chain and the signatures, and export the raw audit rows and a signed evidence pack when assembling evidence.

## On this page

- [Inspect policy and change history](#inspect-policy-and-change-history)
- [Search the audit log](#search-the-audit-log)
- [Verify the audit chain](#verify-the-audit-chain)
- [Run integrity verification](#run-integrity-verification)
- [Export raw audit records](#export-raw-audit-records)
- [Export and verify compliance evidence](#export-and-verify-compliance-evidence)

## Inspect policy and change history

Open **Policies → Version history** to inspect each version fingerprint, publication time, maker, checker, and reason. **Evaluation pipeline** and **Tenant rules** show the bundle in force; the full bundle and current signature are available from `GET /admin/v1/policy`.

Open **Approvals → All changes** to inspect pending, applied, and rejected proposals, their payloads, reasons, impacts, makers, checkers, and review notes. The auditor role cannot approve, reject, simulate, or mutate anything.

`GET /admin/v1/integrity/certifications` is also available to auditors and lists transformation-procedure certifications and certified actions without records. Sources: `packages/pdp-http/src/admin/model.ts`, `packages/pdp-http/src/admin/index.ts`, `packages/pdp-http/src/admin/integrity.ts`.

## Search the audit log

1. Open **Audit**.
2. Set **Type** to `decision`, `change`, `break_glass`, `session`, or `security`, or leave **All types**.
3. Set **Outcome** to **Allow** or **Deny** when needed.
4. Enter an exact **Rule**, **Subject**, or **Resource** id. These are exact metadata matches, not free-text search.
5. Select a record number to inspect its time, actor, action, subject, resource, policy version, previous hash, record hash, and metadata details.
6. Use **Next page →** for older records and **First page** to return to the start. The console requests 50 records per page.

In cluster mode every node writes its own chain, each row carries its `node`, and the API's page cursor takes the form `<node>:<seq>`. Decision rows include rule ids from the decision and any obligations. Administrative events use types such as `change` and `security`; refused admin mutations are also recorded. The auditor-only console does not expose the simulator's **Explain decision** action. Sources: `apps/admin/src/screens/AuditExplorerScreen.tsx`, `packages/pdp-http/src/admin/audit.ts`, `packages/pdp-http/src/runtime.ts`.

## Verify the audit chain

1. Select **Verify chain** on **Audit**.
2. Read **Chain verified (n records)** or **Chain broken at #seq**.
3. For PostgreSQL, inspect the API's `checkedAt` when present: the endpoint can reuse a completed recheck for up to 60 seconds rather than scanning again for every caller.

Verification checks sequence numbers, `prevHash` links, and `hash = SHA-256(prevHash + canonical(record without hash))` on every chain, plus keyed file/PostgreSQL checkpoints, authenticated retention seals, and stored RFC 3161 anchors. A sealed prefix starts verification at its signed head; unsealed gaps or changed seals fail. After subject erasure, the old raw id no longer resolves its pseudonymous rows, but their hashes, pseudonym correlations, and the `subject_erased` event remain verifiable. Deleted retention prefixes are represented by prefix digests and sealed heads, not recoverable row contents without an external copy. A broken result is an investigation trigger, not something to repair by editing rows.

`GET /admin/v1/audit/anchors` returns the configured timestamp authority, last anchoring error, and anchor tokens. Keep external copies of anchors and audit exports; local anchors stored beside a rewritten log do not provide an independent off-box copy. Sources: `packages/pdp-http/src/audit.ts`, `packages/pdp-http/src/admin/audit.ts`, `docs/API.md` §3.9.

## Run integrity verification

Call `POST /admin/v1/integrity/verify` with an auditor session and CSRF token. The response reports whether every declared IVP passed, how many checks ran, the policy version, and each result. The server appends a `security` event with action `ivp_run`, including failing rule ids and item identifiers when checks fail.

A separate `GET /admin/v1/integrity/certifications` shows the certification evidence. Absence of a record does not block a certified action unless its type is listed in `clarkWilson.requireCertification`. Sources: `packages/pdp-http/src/admin/integrity.ts`, `packages/core/src/evaluate.ts`.

## Export raw audit records

Use `GET /admin/v1/audit/export` with the same session cookie used for other admin GET requests. Security officers and auditors can call it, and CSRF is not required for this GET. For example:

```bash
curl -sS 'http://127.0.0.1:8787/admin/v1/audit/export?from=1&limit=1000' \
  -H 'Cookie: sid=<admin session id>' \
  -D audit-headers.txt \
  -o gate-audit-000001.ndjson
```

- `from` is the inclusive starting position, default 1. With one chain it is a sequence number. In cluster mode it is a list of `<node>:<seq>` positions, for example `from=node-a:120,node-b:87`; a chain left out starts at 1.
- `until` is optional, same syntax, inclusive: the last position to export of each chain; chains it leaves out are not exported. To verify offline with `scripts/audit/verify-export.ts`, fetch the signed manifest (`GET /admin/v1/audit/verification`) first and pass its heads, for example `until=0:1234`: the verifier fails on any row after a signed head, because such rows are not covered by the signature.
- `limit` is 1–1000, default 100.
- `pseudonymise=1` replaces the actor, the subject, and person ids in the details with keyed pseudonyms of the form `ps.<32 hex characters>`. Service actors such as `pep`, `system`, and `scim` stay readable. Equal ids keep equal pseudonyms within one key, so maker-checker separation stays checkable.
- The response is `application/x-ndjson`, one complete `AuditRecord` per line.
- Read `X-Audit-Next-From` and pass it unchanged as the next `from`. It is a number with one chain and a `<node>:<seq>` list in cluster mode.
- An empty body means there are no newer rows. Unknown or repeated query parameters return 400.

Do not put the session id in the URL. Unpseudonymised records include the fields needed to rerun the chain check. A pseudonymised row carries `pseudonymised: true` and no longer matches its `hash`; verify the chain on the server with **Verify chain** or `GET /admin/v1/audit/verify`. Sources: `packages/pdp-http/src/siem.ts`, `packages/pdp-http/src/admin/privacy.ts`, `packages/pdp-http/src/router.ts`.

## Export and verify compliance evidence

Open **Compliance**. Each control lists its enforcing rule ids, **Decisions**, **Denies**, and **Last seen**. Counts describe matching audit evidence, not whether your organisation is compliant. The screen offers two signed exports.

**Evidence pack per framework.** Choose the **Framework**, optionally select **Replace person ids with pseudonyms**, and select **Export signed evidence pack**, then **Download JSON**. The API equivalent is `GET /admin/v1/compliance/evidence?framework=<id>`, with `&pseudonymise=1` when needed. Framework ids are `iso27001`, `iso27017`, `iso27018`, `iso27701`, `iso42001`, `iec62443-4-1`, `iec62443-4-2`, and `soc2`. The response has three parts:

- `pack`: the live evidence sections for the framework's controls, with a disclaimer.
- `manifest`: `packSha256`, the SHA-256 (hex) of the canonical `pack`, and one SHA-256 per section.
- `signature`: a detached EdDSA JWS over the canonical `manifest`.

**Export evidence pack.** This export, `GET /admin/v1/compliance/export`, returns the framework mappings and counts as `pack`, with a detached `signature` over the canonical `pack`.

To verify either export:

1. Store the export with the day's `/.well-known/jwks.json` response.
2. Select the JWKS key whose `kid` matches the JWS header, and require `alg: EdDSA`.
3. Canonicalize the signed object (`manifest` for a per-framework pack, `pack` for the mappings export): recursively sorted object keys, arrays in original order, no whitespace.
4. Base64url-encode that canonical JSON without padding as the detached payload.
5. Verify the Ed25519 signature over `<base64url header>.<base64url payload>`.
6. For a per-framework pack, recompute the SHA-256 of the canonical `pack` and of each section, and compare them with the manifest.

Keep the JWKS, because a rotated key leaves it after 300 seconds. UAE Information Assurance has no mapped controls. Neither export is a certification; use the NDJSON export for the raw audit rows. Sources: `packages/pdp-http/src/admin/compliance.ts`, `packages/pdp-http/src/admin/evidence.ts`, `packages/pdp-http/src/tokens.ts`, `packages/pdp-http/src/admin/compliance-map.ts`.

## Related pages

- [Understand audit and evidence](../concepts/governance-and-audit.md)
- [Look up decision rule ids](../reference/decision-reasons.md)
- [Review compliance as a security officer](security-officer.md)
- [Read audit and export limits](../reference/limits-and-quotas.md)
