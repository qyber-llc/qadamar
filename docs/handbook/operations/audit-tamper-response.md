# Respond to an audit tamper alert

An audit integrity failure is a security incident and a fail-closed service condition, not a maintenance task to clear. Preserve storage and external evidence first, isolate writers, establish the last independently trusted head of every audit chain, and restore only from evidence whose provenance you can explain. This runbook applies to the code at commit b09bc44 (after 0.3.0), where PostgreSQL mode keeps one audit chain per node.

## On this page

- [Recognise the alert](#recognise-the-alert)
- [Contain and preserve evidence](#contain-and-preserve-evidence)
- [Triage the failure](#triage-the-failure)
- [Recover service](#recover-service)
- [Complete the incident record](#complete-the-incident-record)

## Recognise the alert

Possible indicators include:

- `GET /admin/v1/audit/verify` (security officer or auditor) returns `verified: false` with `brokenAt`, and `node` when the broken chain is not chain `"0"`;
- `/readyz` returns 503 or audit listings/counts/compliance evidence return 503;
- startup reports `Audit integrity failure`, an anchor mismatch, an invalid checkpoint/MAC, or (file mode) `no checkpoint for a non-empty chain`: a deleted checkpoint is a tamper indicator, never a reason to set `AUDIT_CHECKPOINT_MIGRATE`;
- `audit-retention.ts` refuses with `the live chains do not extend the authenticated checkpoint` or `missing or unauthenticated checkpoint`;
- logs report `Audit periodic recheck failed`, `Audit checkpoint does not match the stored chain ... treated as tampering`, or a metadata mismatch;
- anchoring stops and `lastError` records a verification or recheck failure;
- `gate_audit_last_anchor_age_seconds` becomes stale while readiness or audit verification also degrades;
- external SIEM and Qadamar disagree about sequence continuity or a record hash.

A TSA or SIEM transport failure alone is not proof of tampering. Distinguish export/availability errors from chain verification errors before invoking the full incident process (`packages/pdp-http/src/server.ts`, `packages/pdp-http/src/postgres.ts`).

## Contain and preserve evidence

1. **Declare an integrity incident.** Involve the security officer, database administrator, and incident commander. Record the exact version, node, database identity, and first detection time.
2. **Remove the affected node from traffic.** Do not let it continue making decisions over an untrusted log. Qadamar itself refuses new appends after detecting tampering (`packages/pdp-http/src/postgres.ts`, `packages/pdp-http/src/audit.ts`).
3. **Stop all Qadamar writers to the affected database.** In cluster mode every node writes its own chain, so stop every node. Preserve the single-writer boundary during forensic capture, and do not start repeated failover cycles that overwrite logs or checkpoints.
4. **Do not edit evidence.** Do not remove rows, empty tables, clear `audit_checkpoint`, remove anchors, rebuild metadata by hand, or use `POLICY_SIGNATURE_ADOPT`. None of these repairs a broken chain.
5. **Capture read-only evidence.** With the database administrator, copy all eighteen `gate_*` tables (including audit segments and subject mappings), database logs, role and grant state, and relevant transaction logs using approved forensic procedures. Avoid writes to the suspect store.
6. **Preserve node evidence.** Collect Qadamar and supervisor logs, artifact version, environment names with secret values redacted, process events, and relevant host/file metadata. In file mode, preserve the entire stopped `DATA_DIR`, including audit and anchors.
7. **Secure independent copies.** Export and freeze SIEM records, previous backups, TSA tokens and CA bundles, historical JWKS, policy publications, and compliance packs. Work from copies, not the only original.
8. **Record the current state.** Note `brokenAt` and `node`, the reported length and heads, the last verified `checkedAt`, the last valid anchor and the chain heads it covers, the SIEM's highest contiguous sequence per chain, and the last known-good backup point.

If active compromise is suspected, restrict database-owner and host access and rotate exposed credentials only after preserving the evidence needed to attribute their use.

## Triage the failure

### 1. Classify the mismatch

| Finding | Meaning and next check |
| --- | --- |
| Record hash does not match canonical contents | Record was changed, corrupted, or serialized unexpectedly. Compare the row with SIEM and backups at the same sequence. |
| Sequence gap or `prevHash` mismatch | Row insertion, removal, reordering, or restore mismatch within one node's chain. Locate the first missing or forked sequence of that chain. |
| Chain shorter than a known head or anchor | Rows removed from the end, or a restore to an earlier snapshot. Reconcile later records from independent exports. |
| Anchor differs from the stored chain | The current chains do not contain the externally timestamped head. With several chains, an anchor covers the set of chain heads (`heads`). Treat the anchor as the trusted comparison point until disproven. |
| Only `gate_audit_meta` differs | Derived metadata is inconsistent. The chained rows may be intact; startup can repair metadata and audit `meta_repaired`, but investigate how the write occurred. |
| Checkpoint MAC or checkpoint row mismatch | Possible `gate_doc` tampering, wrong `SIGNING_KEY_SEAL`, or restored mismatched documents. Verify seal identity and compare with a known-good snapshot. |
| Failure appears only after a checkpointed startup (`AUDIT INTEGRITY FAILURE` in the log, `gate_audit_full_chain_verified` 0, `/readyz` 503) | A pre-checkpoint row may have been rewritten; the background verification caught it and cleared the checkpoint, so any restart now reads the whole chain and refuses it. Let the preserved evidence be scanned. |
| TSA unavailable but local verification passes | Availability incident, not chain tamper. Keep existing anchors and restore TSA connectivity. |
| SIEM duplicate records with same `seq` and identical bytes | Expected at-least-once retry, not tamper. Deduplicate and inspect cursor acknowledgement timing. |
| Same `seq` with different bytes | Evidence fork. Quarantine both copies and establish provenance from TSA and backup history. |

Verification algorithms and metadata checks are in `packages/pdp-http/src/audit.ts`, `postgres.ts`, and `postgres-chains.ts`.

### 2. Establish the last trusted position

Use the strongest independent evidence available:

1. a TSA token whose imprint and CA chain verify;
2. an independently retained SIEM chain that verifies and matches a TSA anchor;
3. a validated backup whose policy, anchors, and chain verify;
4. a previous authenticated PostgreSQL checkpoint, only when its HMAC verifies with the correct seal-derived key and external evidence agrees.

Recompute the chain independently from the genesis to the candidate head. Verify the anchor with:

```bash
openssl ts -verify -digest <anchored-record-hash> \
  -in token.der -token_in -CAfile tsa-ca.pem
```

Do not declare a self-consistent replacement chain trustworthy merely because its internal hashes verify. An attacker able to rewrite the database can recompute hashes.

### 3. Assess scope and root cause

Determine whether the change came from:

- an authorised restore or migration performed incompletely;
- derived metadata corruption rather than chained-row modification;
- wrong database, wrong seal, or mixed `DATA_DIR` artifacts;
- a service-role metadata write causing denial of service;
- a database owner/superuser or host administrator rewriting records;
- application defect, storage corruption, or unapproved manual SQL.

Review database role memberships and privileges, host access, restore logs, deployment history, and Qadamar version changes. Preserve a timeline for every privileged action.

## Recover service

Recovery is a new, verified service boundary, not an in-place cleanup of suspect evidence.

1. **Quarantine the suspect store.** Keep it unchanged for investigation and legal/evidence retention requirements.
2. **Select a known-good recovery point.** Use the last independently trusted backup or export. Reconcile later valid records from SIEM and anchors without inventing replacements for missing events.
3. **Restore into a new database.** Follow [Back up and restore](backup-restore.md). Do not overwrite the suspect database.
4. **Reapply least-privilege roles.** Remove unauthorised owner memberships and audit-table update/delete/truncate privileges. Production preflight must pass (`packages/pdp-http/src/profile.ts`).
5. **Rotate compromised access.** Rotate database, PEP, SCIM, webhook, backup, and signing credentials as scope requires. Root-seal rotation is **Not available**; escalate for a controlled recovery design.
6. **Start one isolated Qadamar node.** Use the correct seal and intended artifact. Require full policy and audit verification before any traffic.
7. **Verify against external evidence.** Compare recovered records and anchors with SIEM/TSA copies, confirm current policy signature, and document any unrecovered interval explicitly.
8. **Write a new test decision.** Confirm state and audit commit, chain extension, SIEM delivery, and subsequent verification.
9. **Restore redundancy gradually.** Admit one node, then add the standby or the other cluster nodes after the incident commander approves, and rehearse a takeover or leader change.
10. **Keep the forensic copy.** Do not reuse it for normal service or delete it after recovery.

If no independently trusted evidence exists, report the loss of confidence honestly. Qadamar cannot reconstruct trustworthy historical events from a rewritten store alone.

## Complete the incident record

Document:

- first bad sequence and all affected record ranges;
- detection source and detection-to-containment time;
- last independently trusted head and its TSA/SIEM proof;
- root cause and the privileged identities involved;
- recovered database and backup identifiers;
- any decisions, approvals, emergencies, or performed actions not recovered;
- credential and role changes completed;
- business-write reconciliation, especially certified tokens consumed before an upstream failure;
- control improvements and their owners, such as off-site evidence custody, database-role correction, monitoring, or restore-drill changes.

Review pending break-glass and policy changes from the affected period. Reapprove them through new proposals when their state digest or provenance is uncertain. Do not silently continue with a history whose maker/checker evidence is in doubt.

## Related pages

- [Audit and evidence](../architecture/audit-and-evidence.md)
- [Back up and restore](backup-restore.md)
- [Fail over the active node](failover.md)
- [Rotate keys and credentials](rotate-credentials.md)
- [Monitoring and alerts](monitoring.md)
- [Security architecture](../architecture/security-architecture.md)
