import type {
  AdminResource,
  AdminSubject,
  AdminTuple,
  ApprovalModeItem,
  AuditRecord,
  BulkDecisionResult,
  InboxResponse,
  AuditVerifyResponse,
  BreakGlassListResponse,
  CertificationsResponse,
  BreakGlassRecord,
  ChangeRecord,
  ComplianceFramework,
  EvidenceFrameworkRef,
  EvidencePackResult,
  Decision,
  Impact,
  InventoryPage,
  InventoryResource,
  Json,
  OverviewResponse,
  PepCredential,
  PepCredentialSecret,
  PolicyResponse,
  Reservation,
  RetiredResource,
  ReviewItem,
  SchemaResponse,
  ScimCredentialInfo,
  SessionResponse,
  SigningKey,
  MatrixResponse,
  WhatCanItem,
  WhoCanItem,
} from './types';

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function fail(label: string): never {
  throw new Error(`Invalid API response for ${label}`);
}

export function validateSessionResponse(v: unknown): SessionResponse {
  if (!isRecord(v) || typeof v.csrfToken !== 'string' || !isRecord(v.user)) {
    fail('session');
  }
  const u = v.user;
  if (typeof u.id !== 'string' || typeof u.name !== 'string' || !Array.isArray(u.roles)) {
    fail('session.user');
  }
  return v as unknown as SessionResponse;
}

export function validateOverviewResponse(v: unknown): OverviewResponse {
  if (
    !isRecord(v) ||
    !isRecord(v.policy) ||
    typeof v.needToKnowMode !== 'string' ||
    !isRecord(v.counts) ||
    !isRecord(v.audit) ||
    !isRecord(v.pdp)
  ) {
    fail('overview');
  }
  return v as unknown as OverviewResponse;
}

export function validateSchemaResponse(v: unknown): SchemaResponse {
  if (
    !isRecord(v) ||
    !isRecord(v.resourceTypes) ||
    !Array.isArray(v.compartments) ||
    !isRecord(v.mandatory) ||
    !isRecord(v.needToKnow)
  ) {
    fail('schema');
  }
  return v as unknown as SchemaResponse;
}

export function validatePolicyResponse(v: unknown): PolicyResponse {
  if (
    !isRecord(v) ||
    !isRecord(v.current) ||
    typeof v.current.version !== 'string' ||
    !isRecord(v.current.bundle) ||
    !Array.isArray(v.history)
  ) {
    fail('policy');
  }
  return v as unknown as PolicyResponse;
}

export function validateItemsResponse<T>(label: string, itemCheck?: (item: unknown) => boolean) {
  return (v: unknown): { readonly items: readonly T[] } => {
    if (!isRecord(v) || !Array.isArray(v.items)) {
      fail(label);
    }
    if (itemCheck && !v.items.every(itemCheck)) {
      fail(`${label}.items`);
    }
    return v as unknown as { readonly items: readonly T[] };
  };
}

export const validateSubjectsResponse = validateItemsResponse<AdminSubject>(
  'subjects',
  (x) => isRecord(x) && typeof x.id === 'string' && typeof x.name === 'string',
);

export const validateResourcesResponse = validateItemsResponse<AdminResource>(
  'resources',
  (x) => isRecord(x) && typeof x.id === 'string' && typeof x.type === 'string',
);

export const validateTuplesResponse = validateItemsResponse<AdminTuple>(
  'tuples',
  (x) => isRecord(x) && typeof x.id === 'string' && typeof x.relation === 'string',
);

export const validateWhatCanResponse = validateItemsResponse<WhatCanItem>(
  'what-can',
  (x) => isRecord(x) && isRecord(x.resource) && typeof x.decision === 'boolean',
);

export const validateWhoCanResponse = validateItemsResponse<WhoCanItem>(
  'who-can',
  (x) => isRecord(x) && isRecord(x.subject) && typeof x.decision === 'boolean',
);

export function validateMatrix(v: unknown): MatrixResponse {
  if (!isRecord(v) || typeof v.action !== 'string' || !Array.isArray(v.layers) || !Array.isArray(v.actions)
    || !Array.isArray(v.subjects) || !Array.isArray(v.resources) || !Array.isArray(v.cells)) fail('matrix');
  for (const c of v.cells as unknown[]) {
    if (!isRecord(c) || typeof c.subject !== 'string' || typeof c.resource !== 'string' || typeof c.applicable !== 'boolean') fail('matrix.cell');
    if (c.applicable && (typeof c.decision !== 'boolean' || !isRecord(c.layers))) fail('matrix.cell.layers');
  }
  return v as unknown as MatrixResponse;
}

export function validateDecision(v: unknown): Decision {
  if (
    !isRecord(v) ||
    typeof v.decision !== 'boolean' ||
    !Array.isArray(v.rules) ||
    !Array.isArray(v.trace) ||
    !isRecord(v.obligations)
  ) {
    fail('decision');
  }
  return v as unknown as Decision;
}

const isStrings = (v: unknown): boolean => Array.isArray(v) && v.every((x) => typeof x === 'string');
const listOf = (v: unknown, item: (x: unknown) => boolean): boolean => Array.isArray(v) && v.every(item);
// The impact tables dereference every one of these fields: a malformed row is an invalid response, not a render crash.
const isImpactEntry = (v: unknown): boolean =>
  isRecord(v) && typeof v.subject === 'string' && typeof v.resource === 'string' && typeof v.action === 'string' && isStrings(v.rules);
const isAllowlistSide = (v: unknown): boolean => v === null || isStrings(v);
const isObligationEntry = (v: unknown): boolean => {
  if (!isImpactEntry(v) || !isRecord((v as Record<string, unknown>).obligations)) return false;
  const o = (v as { obligations: Record<string, unknown> }).obligations;
  return isStrings(o.redact) && isStrings(o.maskClasses) && isStrings(o.notify) &&
    (o.fieldAllowlist === undefined || (isRecord(o.fieldAllowlist) && isAllowlistSide(o.fieldAllowlist.before) && isAllowlistSide(o.fieldAllowlist.after))) &&
    (o.decisionToken === undefined || o.decisionToken === true);
};

export function validateImpact(v: unknown): Impact {
  if (
    !isRecord(v) ||
    typeof v.evaluated !== 'number' ||
    !listOf(v.gained, isImpactEntry) ||
    !listOf(v.lost, isImpactEntry) ||
    (v.obligationsLost !== undefined && !listOf(v.obligationsLost, isObligationEntry)) ||
    (v.obligationsGained !== undefined && !listOf(v.obligationsGained, isObligationEntry))
  ) {
    fail('impact');
  }
  return v as unknown as Impact;
}

export function validateChangeRecord(v: unknown): ChangeRecord {
  if (
    !isRecord(v) ||
    typeof v.id !== 'string' ||
    typeof v.kind !== 'string' ||
    typeof v.status !== 'string' ||
    !isRecord(v.impact)
  ) {
    fail('change');
  }
  validateImpact(v.impact);
  return v as unknown as ChangeRecord;
}

export const validateChangesResponse = validateItemsResponse<ChangeRecord>(
  'changes',
  (x) => { try { validateChangeRecord(x); return true; } catch { return false; } },
);

export function validateBreakGlassRecord(v: unknown): BreakGlassRecord {
  if (
    !isRecord(v) ||
    typeof v.id !== 'string' ||
    typeof v.subjectId !== 'string' ||
    typeof v.resourceId !== 'string' ||
    typeof v.status !== 'string'
  ) {
    fail('break-glass record');
  }
  return v as unknown as BreakGlassRecord;
}

export function validateBreakGlassList(v: unknown): BreakGlassListResponse {
  if (
    !isRecord(v) ||
    !Array.isArray(v.active) ||
    !Array.isArray(v.toReview) ||
    !Array.isArray(v.reviewed)
  ) {
    fail('break-glass list');
  }
  return v as unknown as BreakGlassListResponse;
}

export const validateReviewsResponse = validateItemsResponse<ReviewItem>(
  'reviews',
  (x) => isRecord(x) && typeof x.tupleId === 'string' && typeof x.relation === 'string',
);

export function validateComplianceResponse(v: unknown): { readonly frameworks: readonly ComplianceFramework[]; readonly evidenceFrameworks?: readonly EvidenceFrameworkRef[] } {
  if (!isRecord(v) || !Array.isArray(v.frameworks)) {
    fail('compliance');
  }
  if (v.evidenceFrameworks !== undefined && (!Array.isArray(v.evidenceFrameworks) ||
    !v.evidenceFrameworks.every((f) => isRecord(f) && typeof f.id === 'string' && typeof f.name === 'string'))) {
    fail('compliance evidence frameworks');
  }
  return v as unknown as { readonly frameworks: readonly ComplianceFramework[]; readonly evidenceFrameworks?: readonly EvidenceFrameworkRef[] };
}

export function validateEvidencePack(v: unknown): EvidencePackResult {
  const m = isRecord(v) ? v.manifest : undefined;
  if (!isRecord(v) || !isRecord(v.pack) || typeof v.signature !== 'string' || !isRecord(m) || typeof m.framework !== 'string' ||
    typeof m.generatedAt !== 'string' || typeof m.packSha256 !== 'string' || !isRecord(m.sections) ||
    !Object.values(m.sections).every((hash) => typeof hash === 'string')) {
    fail('evidence pack');
  }
  return v as unknown as EvidencePackResult;
}

export function validateComplianceExport(v: unknown): {
  readonly pack: Readonly<Record<string, Json>>;
  readonly signature: string;
} {
  if (!isRecord(v) || !isRecord(v.pack) || typeof v.signature !== 'string') {
    fail('compliance export');
  }
  return v as unknown as { readonly pack: Readonly<Record<string, Json>>; readonly signature: string };
}

export function validateAuditList(v: unknown): {
  readonly items: readonly AuditRecord[];
  readonly next: string | null;
} {
  if (!isRecord(v) || !Array.isArray(v.items) || (v.next !== null && typeof v.next !== 'string')) {
    fail('audit list');
  }
  return v as unknown as { readonly items: readonly AuditRecord[]; readonly next: string | null };
}

export function validateAuditVerify(v: unknown): AuditVerifyResponse {
  if (!isRecord(v) || typeof v.verified !== 'boolean' || typeof v.length !== 'number') {
    fail('audit verify');
  }
  return v as unknown as AuditVerifyResponse;
}

const optionalString = (v: unknown): boolean => v === undefined || typeof v === 'string';
const isProcedure = (v: unknown): boolean => isRecord(v) && typeof v.resourceType === 'string' && typeof v.action === 'string';
const isRef = (v: unknown): boolean => isRecord(v) && typeof v.type === 'string' && typeof v.id === 'string';

export function validateCertifications(v: unknown): CertificationsResponse {
  const ok = isRecord(v) && Array.isArray(v.items) && Array.isArray(v.missing) && Array.isArray(v.stale)
    && v.items.every((c) => isProcedure(c) && isRecord(c) && typeof c.current === 'boolean' && typeof c.certifiedBy === 'string'
      && typeof c.approvedBy === 'string' && typeof c.certifiedAt === 'string' && typeof c.changeId === 'string')
    && v.missing.every(isProcedure) && v.stale.every(isProcedure);
  if (!ok) fail('certifications');
  return v as unknown as CertificationsResponse;
}

export const validateReservations = validateItemsResponse<Reservation>(
  'reservations',
  (x) => isRecord(x) && typeof x.reservation === 'string' && isRef(x.subject) && isRef(x.resource) && typeof x.action === 'string'
    && typeof x.reservedAt === 'string' && optionalString(x.pep) && (x.onBehalfOf === undefined || (Array.isArray(x.onBehalfOf) && x.onBehalfOf.every(isRef))),
);

const optionalStrings = (v: unknown): boolean => v === undefined || (Array.isArray(v) && v.every((s) => typeof s === 'string'));

function isPepCredential(v: unknown): v is PepCredential {
  return isRecord(v) && typeof v.id === 'string' && typeof v.name === 'string' && typeof v.created === 'string'
    && optionalString(v.lastUsed) && optionalString(v.rotated) && optionalString(v.revoked) && optionalString(v.previousValidUntil)
    && optionalStrings(v.resourceTypes) && optionalStrings(v.subjectTypes);
}

function inventoryPage<T>(label: string, item: (x: Record<string, unknown>) => boolean) {
  return (v: unknown): InventoryPage<T> => {
    const ok = isRecord(v) && typeof v.type === 'string' && typeof v.total === 'number' && (v.next === null || typeof v.next === 'string')
      && Array.isArray(v.items) && v.items.every((x) => isRecord(x) && typeof x.id === 'string' && item(x));
    if (!ok) fail(label);
    return v as unknown as InventoryPage<T>;
  };
}
export const validateInventoryPage = inventoryPage<InventoryResource>('resource inventory', (x) => typeof x.level === 'number'
  && Array.isArray(x.compartments) && typeof x.integrity === 'string' && typeof x.version === 'number' && Array.isArray(x.contentClasses)
  && (x.parent === undefined || isRef(x.parent)));
export const validateRetiredPage = inventoryPage<RetiredResource>('retired resources', (x) => typeof x.version === 'number'
  && typeof x.retiredAt === 'string' && typeof x.registeredAgain === 'boolean');

export function validatePepCredentials(v: unknown): { readonly items: readonly PepCredential[] } {
  if (!isRecord(v) || !Array.isArray(v.items) || !v.items.every(isPepCredential)) fail('PEP credentials');
  return v as unknown as { readonly items: readonly PepCredential[] };
}

export function validatePepCredentialSecret(v: unknown): PepCredentialSecret {
  if (!isRecord(v) || !isPepCredential(v.credential) || typeof v.secret !== 'string') fail('PEP credential secret');
  return v as unknown as PepCredentialSecret;
}

export function validatePepCredential(v: unknown): PepCredential {
  if (!isPepCredential(v)) fail('PEP credential');
  return v;
}

export function validateSigningKeys(v: unknown): { readonly items: readonly SigningKey[] } {
  const ok = isRecord(v) && Array.isArray(v.items) && v.items.every((k) => isRecord(k) && typeof k.kid === 'string'
    && typeof k.created === 'string' && typeof k.active === 'boolean' && optionalString(k.verifyUntil));
  if (!ok) fail('signing keys');
  return v as unknown as { readonly items: readonly SigningKey[] };
}

export function validateScimCredentialInfo(v: unknown): ScimCredentialInfo {
  if (!isRecord(v) || !['env', 'none', 'console'].includes(String(v.source)) || !optionalString(v.rotatedBy) || !optionalString(v.rotated)) {
    fail('SCIM credential');
  }
  return v as unknown as ScimCredentialInfo;
}

export function validateScimCredentialSecret(v: unknown): { readonly credential: string } {
  if (!isRecord(v) || typeof v.credential !== 'string') fail('SCIM credential secret');
  return v as unknown as { readonly credential: string };
}

const isMode = (v: unknown): boolean => v === 'individual' || v === 'list';
export function validateInbox(v: unknown): InboxResponse {
  if (!isRecord(v) || !isMode(v.approvalMode) || !listOf(v.snoozes, (x) => isRecord(x) && typeof x.item === 'string' && typeof x.until === 'string')) fail('inbox');
  return v as unknown as InboxResponse;
}
export function validateApprovalModes(v: unknown): { readonly items: readonly ApprovalModeItem[] } {
  if (!isRecord(v) || !listOf(v.items, (x) => isRecord(x) && typeof x.id === 'string' && isMode(x.mode) && optionalString(x.setBy) && optionalString(x.at))) fail('approval modes');
  return v as unknown as { readonly items: readonly ApprovalModeItem[] };
}
export function validateApprovalMode(v: unknown): ApprovalModeItem {
  if (!isRecord(v) || typeof v.id !== 'string' || !isMode(v.mode)) fail('approval mode');
  return v as unknown as ApprovalModeItem;
}
export function validateBulkDecision(v: unknown): { readonly approve: boolean; readonly results: readonly BulkDecisionResult[] } {
  if (!isRecord(v) || typeof v.approve !== 'boolean' || !listOf(v.results, (x) => isRecord(x) && typeof x.id === 'string' && typeof x.ok === 'boolean' &&
    optionalString(x.status) && optionalString(x.error) && optionalString(x.message))) fail('bulk decision');
  return v as unknown as { readonly approve: boolean; readonly results: readonly BulkDecisionResult[] };
}
