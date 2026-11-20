// Admin API contracts matching docs/API.md §1 and §3.
export * from './coreTypes';

import type {
  Context,
  Integrity,
  Json,
  Level,
  Obligations,
  PolicyBundle,
  Ref,
  RelationDef,
  ResourceTypeDef,
  RoleAssignment,
  Tuple,
} from './coreTypes';

export type ConsoleRole =
  | 'access_admin'
  | 'policy_author'
  | 'approver'
  | 'security_officer'
  | 'resource_owner'
  | 'auditor';

export interface AdminTuple extends Tuple {
  readonly id: string;
}

export interface SessionUser {
  readonly id: string;
  readonly name: string;
  readonly roles: readonly ConsoleRole[];
}

export interface SessionResponse {
  readonly user: SessionUser;
  readonly csrfToken: string;
}

export interface OverviewResponse {
  readonly policy: {
    readonly name: string;
    readonly version: string;
    readonly publishedAt: string;
    readonly publishedBy: string;
    readonly approvedBy: string;
  };
  readonly needToKnowMode: 'off' | 'dry_run' | 'enforce';
  readonly counts: {
    readonly pendingChanges: number;
    readonly activeBreakGlass: number;
    readonly breakGlassToReview: number;
    readonly expiringGrants30d: number;
  };
  readonly audit: {
    readonly verified: boolean;
    readonly length: number;
    readonly head: string;
  };
  readonly pdp: {
    readonly status: string;
    readonly uptimeSeconds: number;
    readonly decisions: number;
  };
}

export interface SchemaResponse {
  readonly resourceTypes: Readonly<Record<string, ResourceTypeDef>>;
  readonly subjectRelations?: Readonly<Record<string, Readonly<Record<string, RelationDef>>>>;
  readonly compartments: readonly string[];
  readonly mandatory: PolicyBundle['mandatory'];
  readonly needToKnow: PolicyBundle['needToKnow'];
}

export interface PolicyHistoryEntry {
  readonly version: string;
  readonly publishedAt: string;
  readonly publishedBy: string;
  readonly approvedBy: string;
  readonly reason: string;
}

export interface PolicyResponse {
  readonly current: {
    readonly version: string;
    readonly bundle: PolicyBundle;
  };
  readonly history: readonly PolicyHistoryEntry[];
}

export interface AdminSubject {
  readonly type: string;
  readonly id: string;
  readonly name: string;
  readonly unit: string;
  readonly active: boolean;
  readonly roles: readonly string[];
  /** CBAC grant duration: roles held only inside their window. */
  readonly roleAssignments?: readonly RoleAssignment[];
  readonly clearance: Level;
  readonly compartments: readonly string[];
  readonly integrity: Integrity;
  readonly delegatedBy?: string;
}

export interface AdminResource {
  readonly type: string;
  readonly id: string;
  readonly title: string;
  readonly status: string;
  readonly level: Level;
  readonly compartments: readonly string[];
  readonly integrity: Integrity;
  readonly owner: string;
  readonly contentClasses: readonly string[];
}

export type MatrixLayer = 'rights' | 'clearance' | 'needToKnow' | 'conditions' | 'content' | 'context' | 'controls';
export type LayerOutcome = 'pass' | 'deny' | 'would_deny' | 'obligation' | 'none';

export interface MatrixCell {
  readonly subject: string;
  readonly resource: string;
  readonly applicable: boolean;
  readonly decision?: boolean;
  readonly layers?: Readonly<Record<MatrixLayer, { readonly o: LayerOutcome; readonly rules: readonly string[]; readonly reason?: string }>>;
  readonly path?: readonly string[];
  readonly obligations?: Obligations;
}

export interface MatrixResponse {
  readonly action: string;
  readonly network: 'trusted' | 'untrusted';
  readonly layers: readonly MatrixLayer[];
  readonly actions: readonly string[];
  readonly subjects: readonly { readonly id: string; readonly type: string; readonly name: string; readonly roles: readonly string[]; readonly roleAssignments?: readonly RoleAssignment[]; readonly clearance: Level; readonly compartments: readonly string[] }[];
  readonly resources: readonly { readonly id: string; readonly type: string; readonly title: string; readonly level: Level; readonly compartments: readonly string[]; readonly contentClasses: readonly string[] }[];
  readonly cells: readonly MatrixCell[];
}

export interface WhatCanItem {
  readonly resource: { readonly type: string; readonly id: string; readonly title: string; readonly level: Level };
  readonly decision: boolean;
  readonly rules: readonly string[];
  readonly reasons: readonly string[];
  readonly path?: readonly string[];
  readonly obligations: Obligations;
  readonly wouldDeny?: readonly string[];
}

export interface WhoCanItem {
  readonly subject: { readonly type: string; readonly id: string; readonly name: string };
  readonly decision: boolean;
  readonly rules: readonly string[];
  readonly reasons: readonly string[];
  readonly path?: readonly string[];
  readonly obligations?: Obligations;
  readonly wouldDeny?: readonly string[];
}

export interface ImpactEntry {
  readonly subject: string;
  readonly resource: string;
  readonly action: string;
  readonly rules: readonly string[];
}

/** What one side imposes and the other does not; fieldAllowlist: both sides (null = every field) when it changed. */
export interface ObligationDelta {
  readonly redact: readonly string[];
  readonly maskClasses: readonly string[];
  readonly notify: readonly string[];
  readonly fieldAllowlist?: { readonly before: readonly string[] | null; readonly after: readonly string[] | null };
  readonly decisionToken?: true;
}

/** A cell allowed before and after whose obligations changed. */
export interface ObligationChangeEntry extends ImpactEntry {
  readonly obligations: ObligationDelta;
}

export interface ImpactAnalysis {
  readonly affectedCells: number;
  readonly reasons: readonly string[];
}

export interface ImpactContextClass {
  readonly context: Context;
  readonly evaluated: number;
  readonly gained: readonly ImpactEntry[];
  readonly lost: readonly ImpactEntry[];
  readonly obligationsLost: readonly ObligationChangeEntry[];
  readonly obligationsGained: readonly ObligationChangeEntry[];
}

export interface ImpactContextAnalysis {
  readonly cap: number;
  readonly evaluatedClasses: number;
  readonly truncated: boolean;
  readonly incomplete?: boolean;
  readonly unsupported?: readonly string[];
  readonly classes: readonly ImpactContextClass[];
}

export interface Impact {
  readonly evaluated: number;
  readonly analysis?: ImpactAnalysis;
  readonly contextAnalysis?: ImpactContextAnalysis;
  readonly gained: readonly ImpactEntry[];
  readonly lost: readonly ImpactEntry[];
  /** Still allowed with less protection (broadening); absent from servers before KIMI-02. */
  readonly obligationsLost?: readonly ObligationChangeEntry[];
  /** Still allowed with more protection (narrowing). */
  readonly obligationsGained?: readonly ObligationChangeEntry[];
  readonly policyVersionBefore: string;
  readonly policyVersionAfter: string;
}

export type ChangeKind = 'add_tuple' | 'remove_tuple' | 'update_subject' | 'update_resource' | 'publish_policy' | 'certify_tp' | 'register_resources' | 'scim_subjects';

export type ChangePayload =
  | Tuple
  | { readonly tupleId: string }
  | { readonly id: string; readonly set: { readonly clearance?: Level; readonly compartments?: readonly string[]; readonly roles?: readonly string[]; readonly roleAssignments?: readonly RoleAssignment[]; readonly active?: boolean } }
  | { readonly id: string; readonly set: { readonly level?: Level; readonly compartments?: readonly string[]; readonly integrity?: Integrity } }
  | { readonly bundle: PolicyBundle }
  | { readonly resourceType: string; readonly action: string }
  | RegisterResourcesPayload;

/** register_resources (docs/API.md §2.2): proposed by a PEP credential, never by a person. */
export interface RegisterResourcesPayload {
  readonly resources: readonly Ref[];
  readonly retire?: readonly Ref[];
}

/** docs/API.md §3.3: one registered resource of the inventory, with its labels. */
export interface InventoryResource {
  readonly id: string;
  readonly title: string;
  readonly level: Level;
  readonly compartments: readonly string[];
  readonly integrity: Integrity;
  readonly owner: string | null;
  readonly contentClasses: readonly string[];
  readonly version: number;
  readonly parent?: Ref;
}

/** docs/API.md §3.3: an id retired by its PEP; registering it again always waits for a second person. */
export interface RetiredResource {
  readonly id: string;
  readonly version: number;
  readonly retiredAt: string;
  readonly registeredAgain: boolean;
}

export interface InventoryPage<T> {
  readonly type: string;
  readonly total: number;
  readonly items: readonly T[];
  readonly next: string | null;
}

export interface ChangeRecord {
  readonly id: string;
  readonly kind: ChangeKind;
  readonly payload: ChangePayload;
  readonly reason: string;
  readonly makerId: string;
  readonly createdAt: string;
  readonly status: 'pending' | 'applied' | 'rejected';
  readonly impact: Impact;
  readonly broadens: boolean;
  readonly stateDigest: string;
  readonly checkerId?: string;
  readonly decidedAt?: string;
  readonly decisionReason?: string;
  /** publish_policy (0.4.1): certifications in force that the new bundle would make stale (docs/API.md §3.12). */
  readonly invalidatesCertifications?: readonly (ProcedureRef & { readonly changeId: string })[];
  /** register_resources: the PEP credential that proposed it. */
  readonly pepCredential?: { readonly id: string; readonly issuedBy?: string };
  /** scim_subjects: who last minted the SCIM credential that proposed it. */
  readonly scimCredential?: { readonly rotatedBy: string; readonly fingerprint: string };
  /** publish_policy: the mandatory protections the bundle would weaken (approval needs a security officer). */
  readonly weakensMandatory?: readonly string[];
  /** publish_policy: deprecations the PDP reported (DEPRECATED_CBAC_FIELD). */
  readonly warnings?: readonly string[];
}

/** A transformation procedure: a certified action of a constrained resource type (docs/API.md §3.12). */
export interface ProcedureRef {
  readonly resourceType: string;
  readonly action: string;
}

/** A certification record; `current` is false once the procedure's definition changed (recertify it). */
export interface Certification extends ProcedureRef {
  readonly certifiedBy: string;
  readonly approvedBy: string;
  readonly certifiedAt: string;
  readonly policyVersion: string;
  readonly changeId: string;
  readonly reason: string;
  readonly fingerprint?: string;
  readonly current: boolean;
}

/** GET /admin/v1/integrity/certifications: `missing` has no current record, `stale` is the part of it with old records. */
export interface CertificationsResponse {
  readonly items: readonly Certification[];
  readonly missing: readonly ProcedureRef[];
  readonly stale: readonly ProcedureRef[];
}

/** GET /admin/v1/integrity/reservations: a certified action whose PEP never reported an outcome (docs/API.md §3.12). */
export interface Reservation {
  readonly reservation: string;
  readonly subject: Ref;
  readonly resource: Ref;
  readonly action: string;
  readonly reservedAt: string;
  readonly pep?: string;
  readonly onBehalfOf?: readonly Ref[];
}

export interface BreakGlassRecord {
  readonly id: string;
  readonly subjectId: string;
  readonly resourceId: string;
  readonly reason: string;
  readonly openedBy: string;
  readonly openedAt: string;
  readonly expiresAt: string;
  readonly status: string;
  readonly outcome?: 'justified' | 'escalated';
  readonly note?: string;
  readonly reviewedBy?: string;
  readonly reviewedAt?: string;
}

/** docs/API.md §3.5.1: how an approver decides, set per user by an access admin or a security officer. */
export type ApprovalMode = 'individual' | 'list';
export interface InboxResponse {
  readonly approvalMode: ApprovalMode;
  /** Queue items this user snoozed, still in force: `change:<id>` or `emergency:<id>`, back on `until` (YYYY-MM-DD). */
  readonly snoozes: readonly { readonly item: string; readonly until: string }[];
}
export interface ApprovalModeItem {
  readonly id: string;
  readonly mode: ApprovalMode;
  readonly setBy?: string;
  readonly at?: string;
}
export interface BulkDecisionResult {
  readonly id: string;
  readonly ok: boolean;
  readonly status?: string;
  readonly error?: string;
  readonly message?: string;
}

export interface BreakGlassListResponse {
  readonly active: readonly BreakGlassRecord[];
  readonly toReview: readonly BreakGlassRecord[];
  readonly reviewed: readonly BreakGlassRecord[];
  /** Ids the caller may review or revoke as the access_admin fallback; absent from servers before this rule. */
  readonly fallbackReview?: readonly string[];
}

/** A time-bound role assignment ending within 30 days (security officers only). */
export interface RoleAssignmentReview {
  readonly subject: Ref;
  readonly role: string;
  readonly notBefore?: string;
  readonly notAfter: string;
  readonly daysLeft: number;
}

export interface ReviewItem {
  readonly tupleId: string;
  readonly subject: Ref | string;
  readonly resource: Ref | string;
  readonly relation: string;
  readonly validTo?: string;
  readonly daysLeft: number;
  readonly grantedBy?: string;
  readonly reason?: string;
}

export interface ComplianceControl {
  readonly id: string;
  readonly title: string;
  readonly enforcedBy: readonly string[];
  readonly evidence: { readonly decisions: number; readonly denies: number; readonly lastSeen: string | null };
}

export interface ComplianceFramework {
  readonly id: string;
  readonly name: string;
  readonly controls: readonly ComplianceControl[];
}

/** A framework the server can build a signed evidence pack for (GET /admin/v1/compliance/evidence). */
export interface EvidenceFrameworkRef {
  readonly id: string;
  readonly name: string;
}

export interface EvidenceManifest {
  readonly framework: string;
  readonly generatedAt: string;
  readonly packSha256: string;
  readonly sections: Readonly<Record<string, string>>;
}

export interface EvidencePackResult {
  readonly pack: Readonly<Record<string, Json>>;
  readonly manifest: EvidenceManifest;
  readonly signature: string;
}

export interface AuditRecord {
  readonly seq: number;
  readonly ts: string;
  readonly type: string;
  readonly actor: string;
  readonly action: string;
  readonly subject?: string | Ref;
  readonly resource?: string | Ref;
  readonly effect?: string;
  readonly rules?: readonly string[];
  readonly policyVersion?: string;
  readonly details?: Readonly<Record<string, Json>>;
  readonly prevHash: string;
  readonly hash: string;
}

export interface AuditVerifyResponse {
  readonly verified: boolean;
  readonly length: number;
  readonly brokenAt?: number;
}

/** docs/API.md §3.10: a PEP's named credential; the secret is returned once, by create and rotate only. */
export interface PepCredential {
  readonly id: string;
  readonly name: string;
  readonly created: string;
  readonly lastUsed?: string;
  readonly rotated?: string;
  readonly revoked?: string;
  readonly previousValidUntil?: string;
  readonly subjectTypes?: readonly string[];
  readonly allowSubjectSearch?: boolean;
  /** The resource types this PEP may register and retire (docs/API.md §2.2); fixed at creation, none when absent. */
  readonly resourceTypes?: readonly string[];
  readonly issuedBy?: string;
}

export interface PepCredentialSecret {
  readonly credential: PepCredential;
  readonly secret: string;
}

/** docs/API.md §3.10: a decision-token signing key (public metadata only). */
export interface SigningKey {
  readonly kid: string;
  readonly created: string;
  readonly active: boolean;
  readonly verifyUntil?: string;
}

/** docs/API.md §3.11: who holds the SCIM credential, never the credential itself. */
export interface ScimCredentialInfo {
  readonly source: 'env' | 'none' | 'console';
  readonly rotatedBy?: string;
  readonly rotated?: string;
}
