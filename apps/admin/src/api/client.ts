import type {
  AdminResource, AdminSubject, AdminTuple, ApprovalMode, ApprovalModeItem, AuditRecord, AuditVerifyResponse, BulkDecisionResult, InboxResponse,
  BreakGlassListResponse, BreakGlassRecord, CertificationsResponse, ChangeKind, ChangePayload, ChangeRecord,
  ComplianceFramework, Decision, EvidenceFrameworkRef, EvidencePackResult, Impact, InventoryPage, InventoryResource, Json, Level, MatrixResponse, OverviewResponse,
  PepCredential, PepCredentialSecret, PolicyResponse, Reservation, ReviewItem, RoleAssignmentReview, SchemaResponse, ScimCredentialInfo, SessionResponse,
  RetiredResource, SigningKey, WhatCanItem, WhoCanItem,
} from './types';
import {
  validateApprovalMode, validateApprovalModes, validateAuditList, validateAuditVerify, validateBreakGlassList, validateBreakGlassRecord, validateBulkDecision, validateInbox,
  validateChangeRecord, validateChangesResponse, validateComplianceExport, validateComplianceResponse, validateEvidencePack,
  validateDecision, validateImpact, validateOverviewResponse, validatePolicyResponse,
  validateResourcesResponse, validateReviewsResponse, validateSchemaResponse, validateSessionResponse,
  validateSubjectsResponse, validateTuplesResponse, validateWhatCanResponse, validateWhoCanResponse,
  validateMatrix, validatePepCredential, validatePepCredentials, validatePepCredentialSecret, validateScimCredentialInfo,
  validateScimCredentialSecret, validateSigningKeys, validateCertifications, validateReservations, validateInventoryPage, validateRetiredPage,
} from './validators';

const inventoryQuery = (type: string, cursor: string, limit: number): string =>
  new URLSearchParams({ type, limit: String(limit), ...(cursor ? { cursor } : {}) }).toString();

export interface ErrorEnvelope {
  readonly error: string;
  readonly message: string;
  readonly details?: unknown;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;
  readonly retryAfter: number | null;
  readonly retryDeadlineMs: number | null;

  constructor(status: number, code: string, message: string, details?: unknown, retryAfter: number | null = null, retryDeadlineMs: number | null = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.retryAfter = retryAfter;
    this.retryDeadlineMs = retryDeadlineMs;
  }
}

let csrfToken: string | null = null;
let unauthenticatedHandler: (() => void) | null = null;
let serverClockOffsetMs = 0;
let sessionGeneration = 0;
const pendingControllers = new Set<AbortController>();

export function setCsrfToken(token: string | null): void { csrfToken = token; }
export function onUnauthenticated(handler: (() => void) | null): void { unauthenticatedHandler = handler; }
export function getServerNowMs(): number { return Date.now() + serverClockOffsetMs; }
export function getSessionGeneration(): number { return sessionGeneration; }

export function resetSessionGeneration(): number {
  sessionGeneration += 1;
  for (const ctrl of pendingControllers) ctrl.abort();
  pendingControllers.clear();
  return sessionGeneration;
}

export function parseRetryAfter(retryHeader: string | null): { readonly retryAfter: number | null; readonly retryDeadlineMs: number | null } {
  if (!retryHeader) return { retryAfter: null, retryDeadlineMs: null };
  const trimmed = retryHeader.trim();
  if (/^\d+$/.test(trimmed)) {
    const secs = Number.parseInt(trimmed, 10);
    if (Number.isFinite(secs) && secs >= 0) return { retryAfter: secs, retryDeadlineMs: Date.now() + secs * 1000 };
  }
  const dateMs = Date.parse(trimmed);
  if (!Number.isNaN(dateMs)) {
    const diffMs = Math.max(0, dateMs - getServerNowMs());
    return { retryAfter: Math.ceil(diffMs / 1000), retryDeadlineMs: Date.now() + diffMs };
  }
  return { retryAfter: null, retryDeadlineMs: null };
}

interface RequestOptions<T> {
  readonly method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  readonly body?: unknown;
  readonly skipAuthRedirect?: boolean;
  readonly validate?: (data: unknown) => T;
}

async function request<T>(path: string, options: RequestOptions<T> = {}): Promise<T> {
  const method = options.method ?? 'GET';
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && csrfToken) headers['X-CSRF-Token'] = csrfToken;

  const startGen = sessionGeneration;
  const controller = new AbortController();
  if (!options.skipAuthRedirect) pendingControllers.add(controller);

  let response: Response;
  try {
    response = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers,
      signal: controller.signal,
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
    });
  } finally {
    pendingControllers.delete(controller);
  }

  const dateHeader = response.headers.get('Date');
  if (dateHeader) {
    const parsedServerMs = Date.parse(dateHeader);
    if (!Number.isNaN(parsedServerMs)) serverClockOffsetMs = parsedServerMs - Date.now();
  }

  if (!options.skipAuthRedirect && startGen !== sessionGeneration) {
    throw new ApiError(401, 'session_changed', 'Session changed before response completed.');
  }
  if (response.status === 204 && !options.validate) return undefined as T;

  const { retryAfter, retryDeadlineMs } = parseRetryAfter(response.headers.get('Retry-After'));
  let payload: unknown = null;
  if ((response.headers.get('Content-Type') ?? '').includes('application/json')) {
    try { payload = await response.json(); } catch { payload = null; }
  }

  if (!options.skipAuthRedirect && startGen !== sessionGeneration) {
    throw new ApiError(401, 'session_changed', 'Session changed before response completed.');
  }

  if (!response.ok) {
    const env = (typeof payload === 'object' && payload !== null ? payload : {}) as Partial<ErrorEnvelope>;
    const code = typeof env.error === 'string' ? env.error : `http_${response.status}`;
    const msg = typeof env.message === 'string' && env.message.trim().length > 0 ? env.message : `Request failed with status ${response.status}`;
    const apiErr = new ApiError(response.status, code, msg, env.details, retryAfter, retryDeadlineMs);
    if (response.status === 401 && !options.skipAuthRedirect) {
      resetSessionGeneration();
      setCsrfToken(null);
      if (unauthenticatedHandler) unauthenticatedHandler();
    }
    throw apiErr;
  }

  if (options.validate) {
    try { return options.validate(payload); } catch (err) {
      throw new ApiError(response.status, 'invalid_response', err instanceof Error ? err.message : 'Unexpected API response shape');
    }
  }
  return payload as T;
}

export const api = {
  /** `code`: the authenticator code or a recovery code, for local accounts with TOTP. */
  async signIn(username: string, password: string, code = ''): Promise<SessionResponse> {
    resetSessionGeneration();
    const res = await request<SessionResponse>('/admin/v1/session', { method: 'POST', body: { username, password, ...(code ? { code } : {}) }, skipAuthRedirect: true, validate: validateSessionResponse });
    resetSessionGeneration();
    setCsrfToken(res.csrfToken);
    return res;
  },
  /** Which sign-in methods the server offers; before sign-in, so no auth redirect. */
  async authMethods(): Promise<{ password: boolean; sso: boolean; saml: boolean }> {
    return request('/admin/v1/auth-methods', { skipAuthRedirect: true, validate: (d) => {
      const v = d as { password?: unknown; sso?: unknown; saml?: unknown };
      if (typeof v?.password !== 'boolean' || typeof v?.sso !== 'boolean' || typeof v?.saml !== 'boolean') throw new Error('auth-methods shape');
      return { password: v.password, sso: v.sso, saml: v.saml };
    } });
  },
  async getSession(): Promise<SessionResponse> {
    const res = await request<SessionResponse>('/admin/v1/session', { method: 'GET', skipAuthRedirect: true, validate: validateSessionResponse });
    setCsrfToken(res.csrfToken);
    return res;
  },
  async signOut(): Promise<void> {
    const result = await request<{ logoutUrl?: string } | undefined>('/admin/v1/session', { method: 'DELETE', skipAuthRedirect: true });
    resetSessionGeneration();
    setCsrfToken(null);
    if (result?.logoutUrl) {
      try {
        const logoutUrl = new URL(result.logoutUrl, window.location.origin);
        if (logoutUrl.protocol === 'https:' || logoutUrl.origin === window.location.origin) {
          window.location.assign(logoutUrl.href);
        }
      } catch {
        // An invalid logout URL leaves the console on its own signed-out state.
      }
    }
  },
  /** Refreshes the idle window while the operator is working; a 401 opens the sign-in dialog over the page. */
  keepAlive: () => request<SessionResponse>('/admin/v1/session', { method: 'GET', validate: validateSessionResponse }),
  getOverview: () => request<OverviewResponse>('/admin/v1/overview', { validate: validateOverviewResponse }),
  getSchema: () => request<SchemaResponse>('/admin/v1/schema', { validate: validateSchemaResponse }),
  getPolicy: () => request<PolicyResponse>('/admin/v1/policy', { validate: validatePolicyResponse }),
  getSubjects: () => request<{ readonly items: readonly AdminSubject[] }>('/admin/v1/subjects', { validate: validateSubjectsResponse }),
  getResources: () => request<{ readonly items: readonly AdminResource[] }>('/admin/v1/resources', { validate: validateResourcesResponse }),
  getTuples: () => request<{ readonly items: readonly AdminTuple[] }>('/admin/v1/tuples', { validate: validateTuplesResponse }),
  /** docs/API.md §3.3: the registered resources of one type, or the ids retired from it, a page at a time. */
  getResourceInventory: (type: string, cursor = '', limit = 50) =>
    request<InventoryPage<InventoryResource>>(`/admin/v1/resources/inventory?${inventoryQuery(type, cursor, limit)}`, { validate: validateInventoryPage }),
  getRetiredResources: (type: string, cursor = '', limit = 50) =>
    request<InventoryPage<RetiredResource>>(`/admin/v1/resources/retired?${inventoryQuery(type, cursor, limit)}`, { validate: validateRetiredPage }),
  simulateMatrix: (body: { readonly action: string; readonly network: 'trusted' | 'untrusted' }) =>
    request<MatrixResponse>('/admin/v1/simulate/matrix', { method: 'POST', body, validate: validateMatrix }),
  simulateWhatCan: (body: { readonly subjectId: string; readonly action: string; readonly network: 'trusted' | 'untrusted' }) =>
    request<{ readonly items: readonly WhatCanItem[] }>('/admin/v1/simulate/what-can', { method: 'POST', body, validate: validateWhatCanResponse }),
  simulateWhoCan: (body: { readonly resourceId: string; readonly action: string; readonly network: 'trusted' | 'untrusted' }) =>
    request<{ readonly items: readonly WhoCanItem[] }>('/admin/v1/simulate/who-can', { method: 'POST', body, validate: validateWhoCanResponse }),
  explain: (body: {
    readonly subjectId: string; readonly resourceId: string; readonly action: string; readonly network: 'trusted' | 'untrusted';
    readonly sessionLevel?: Level; readonly makerId?: string; readonly priorActions?: readonly string[];
  }) => request<Decision>('/admin/v1/explain', { method: 'POST', body, validate: validateDecision }),
  simulateImpact: (body: { readonly kind: ChangeKind; readonly payload: ChangePayload }) =>
    request<Impact>('/admin/v1/simulate/impact', { method: 'POST', body, validate: validateImpact }),
  createChange: (body: { readonly kind: ChangeKind; readonly payload: ChangePayload; readonly reason: string }) =>
    request<ChangeRecord>('/admin/v1/changes', { method: 'POST', body, validate: validateChangeRecord }),
  getChanges: (status?: 'pending' | 'applied' | 'rejected') =>
    request<{ readonly items: readonly ChangeRecord[] }>(`/admin/v1/changes${status ? `?status=${encodeURIComponent(status)}` : ''}`, { validate: validateChangesResponse }),
  approveChange: (id: string, reason: string) =>
    request<ChangeRecord>(`/admin/v1/changes/${encodeURIComponent(id)}/approve`, { method: 'POST', body: { reason }, validate: validateChangeRecord }),
  rejectChange: (id: string, reason: string) =>
    request<ChangeRecord>(`/admin/v1/changes/${encodeURIComponent(id)}/reject`, { method: 'POST', body: { reason }, validate: validateChangeRecord }),
  // docs/API.md §3.5.1: bulk decisions (list mode only), the caller's mode and snoozes, and the modes administrators set
  decideChanges: (ids: readonly string[], approve: boolean, reason: string) =>
    request<{ readonly approve: boolean; readonly results: readonly BulkDecisionResult[] }>('/admin/v1/changes/decide', { method: 'POST', body: { ids, approve, reason }, validate: validateBulkDecision }),
  getInbox: () => request<InboxResponse>('/admin/v1/inbox', { validate: validateInbox }),
  snooze: (item: string, until: string) => request<unknown>('/admin/v1/inbox/snoozes', { method: 'POST', body: { item, until } }),
  unsnooze: (item: string) => request<unknown>(`/admin/v1/inbox/snoozes/${encodeURIComponent(item)}`, { method: 'DELETE' }),
  getApprovalModes: () => request<{ readonly items: readonly ApprovalModeItem[] }>('/admin/v1/approval-modes', { validate: validateApprovalModes }),
  setApprovalMode: (userId: string, mode: ApprovalMode) =>
    request<ApprovalModeItem>(`/admin/v1/approval-modes/${encodeURIComponent(userId)}`, { method: 'PUT', body: { mode }, validate: validateApprovalMode }),
  getBreakGlass: () => request<BreakGlassListResponse>('/admin/v1/break-glass', { validate: validateBreakGlassList }),
  openBreakGlass: (body: { readonly subjectId: string; readonly resourceId: string; readonly reason: string; readonly hours: number }) =>
    request<BreakGlassRecord>('/admin/v1/break-glass', { method: 'POST', body, validate: validateBreakGlassRecord }),
  revokeBreakGlass: (id: string, reason: string) =>
    request<BreakGlassRecord>(`/admin/v1/break-glass/${encodeURIComponent(id)}/revoke`, { method: 'POST', body: { reason }, validate: validateBreakGlassRecord }),
  reviewBreakGlass: (id: string, outcome: 'justified' | 'escalated', note: string) =>
    request<BreakGlassRecord>(`/admin/v1/break-glass/${encodeURIComponent(id)}/review`, { method: 'POST', body: { outcome, note }, validate: validateBreakGlassRecord }),
  getReviews: () => request<{ readonly items: readonly ReviewItem[]; readonly roleAssignments?: readonly RoleAssignmentReview[] }>('/admin/v1/reviews', { validate: validateReviewsResponse }),
  decideReview: (tupleId: string, body: { readonly decision: 'certify' | 'revoke'; readonly reason: string; readonly newValidTo?: string }) =>
    request<ChangeRecord>(`/admin/v1/reviews/${encodeURIComponent(tupleId)}`, { method: 'POST', body, validate: validateChangeRecord }),
  getCompliance: () => request<{ readonly frameworks: readonly ComplianceFramework[]; readonly evidenceFrameworks?: readonly EvidenceFrameworkRef[] }>('/admin/v1/compliance', { validate: validateComplianceResponse }),
  exportEvidencePack: (framework: string, pseudonymise: boolean) => request<EvidencePackResult>(
    `/admin/v1/compliance/evidence?framework=${encodeURIComponent(framework)}${pseudonymise ? '&pseudonymise=1' : ''}`, { validate: validateEvidencePack }),
  exportCompliance: () => request<{ readonly pack: Readonly<Record<string, Json>>; readonly signature: string }>('/admin/v1/compliance/export', { validate: validateComplianceExport }),
  getAudit(params: { readonly effect?: string; readonly rule?: string; readonly subject?: string; readonly resource?: string; readonly type?: string; readonly limit?: number; readonly cursor?: string }) {
    const q = new URLSearchParams();
    if (params.effect) q.set('effect', params.effect);
    if (params.rule) q.set('rule', params.rule);
    if (params.subject) q.set('subject', params.subject);
    if (params.resource) q.set('resource', params.resource);
    if (params.type) q.set('type', params.type);
    q.set('limit', String(params.limit ?? 50));
    if (params.cursor) q.set('cursor', params.cursor);
    return request<{ readonly items: readonly AuditRecord[]; readonly next: string | null }>(`/admin/v1/audit?${q.toString()}`, { validate: validateAuditList });
  },
  // docs/API.md §3.12: Clark-Wilson certification records and the reservations no PEP settled
  getCertifications: () => request<CertificationsResponse>('/admin/v1/integrity/certifications', { validate: validateCertifications }),
  getReservations: () => request<{ readonly items: readonly Reservation[] }>('/admin/v1/integrity/reservations', { validate: validateReservations }),
  verifyAuditChain: () => request<AuditVerifyResponse>('/admin/v1/audit/verify', { validate: validateAuditVerify }),
  // docs/API.md §3.10 and §3.11: secrets come back once, from create and rotate only.
  getPepCredentials: () => request<{ readonly items: readonly PepCredential[] }>('/admin/v1/pep-credentials', { validate: validatePepCredentials }),
  /** `resourceTypes`: what the PEP may register (docs/API.md §2.2); empty sends none, so the credential registers nothing. */
  createPepCredential: (name: string, resourceTypes: readonly string[] = []) =>
    request<PepCredentialSecret>('/admin/v1/pep-credentials', { method: 'POST', body: { name, ...(resourceTypes.length ? { resourceTypes } : {}) }, validate: validatePepCredentialSecret }),
  rotatePepCredential: (id: string) =>
    request<PepCredentialSecret>(`/admin/v1/pep-credentials/${encodeURIComponent(id)}/rotate`, { method: 'POST', body: {}, validate: validatePepCredentialSecret }),
  revokePepCredential: (id: string) =>
    request<PepCredential>(`/admin/v1/pep-credentials/${encodeURIComponent(id)}/revoke`, { method: 'POST', body: {}, validate: validatePepCredential }),
  getSigningKeys: () => request<{ readonly items: readonly SigningKey[] }>('/admin/v1/signing-keys', { validate: validateSigningKeys }),
  rotateSigningKey: () => request<unknown>('/admin/v1/signing-keys/rotate', { method: 'POST', body: {} }),
  /** docs/API.md §3.1.2: TOTP for the signed-in local account. The otpauth URI and recovery codes come back once. */
  getTotpStatus: () => request<{ readonly active: boolean; readonly pending: boolean; readonly available: boolean }>('/admin/v1/session/totp', { validate: (d) => {
    const v = d as { active?: unknown; pending?: unknown; available?: unknown } | null;
    if (typeof v?.active !== 'boolean' || typeof v.pending !== 'boolean' || typeof v.available !== 'boolean') throw new Error('totp status shape');
    return { active: v.active, pending: v.pending, available: v.available };
  } }),
  enrolTotp: (password: string) => request<{ readonly otpauthUri: string }>('/admin/v1/session/totp/enrol', { method: 'POST', body: { password }, validate: (d) => {
    const uri = (d as { otpauthUri?: unknown } | null)?.otpauthUri;
    if (typeof uri !== 'string' || !uri.startsWith('otpauth://totp/')) throw new Error('totp enrol shape');
    return { otpauthUri: uri };
  } }),
  activateTotp: (code: string) => request<{ readonly recoveryCodes: readonly string[] }>('/admin/v1/session/totp/activate', { method: 'POST', body: { code }, validate: (d) => {
    const codes = (d as { recoveryCodes?: unknown } | null)?.recoveryCodes;
    if (!Array.isArray(codes) || !codes.every((c) => typeof c === 'string')) throw new Error('totp activate shape');
    return { recoveryCodes: codes as string[] };
  } }),
  getScimCredential: () => request<ScimCredentialInfo>('/admin/v1/scim/credential', { validate: validateScimCredentialInfo }),
  rotateScimCredential: () =>
    request<{ readonly credential: string }>('/admin/v1/scim/credential', { method: 'POST', body: {}, validate: validateScimCredentialSecret }),
};
