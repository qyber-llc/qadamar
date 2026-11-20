export type JsonValue = null | boolean | number | string | readonly JsonValue[] | JsonObject;
export interface JsonObject { readonly [key: string]: JsonValue }

export interface Ref { readonly type: string; readonly id: string }
export interface TypeRef { readonly type: string }
export interface Action { readonly name: string }

export type ContextSignal = 'network' | 'ip' | 'country' | 'device' | 'authTime' | 'mfaTime' | 'authMethods' | 'riskScore' | 'sessionLevel';
export type ContextAttestations = Readonly<Partial<Record<ContextSignal, string>>>;

export interface EvaluationContext {
  readonly network?: 'trusted' | 'untrusted';
  /** Network sensor identity signed as src by a required network attestation. */
  readonly networkSensorId?: string;
  /** Compact gate-context-attestation+jwt evidence for signals whose credential scope requires it. */
  readonly attestations?: ContextAttestations;
  /** Zero Trust signals asserted by the authenticated PEP; malformed values are refused by the PDP. */
  readonly ip?: string;
  readonly country?: string;
  readonly device?: { readonly id?: string; readonly managed: boolean; readonly compliant: boolean };
  readonly authTime?: string;
  readonly mfaTime?: string;
  readonly authMethods?: readonly string[];
  readonly riskScore?: number;
  readonly sessionLevel?: 0 | 1 | 2 | 3;
  /** Deprecated outside production: a PEP-chosen working-session id. Prefer a PDP-issued sessionToken. */
  readonly sessionId?: string;
  /** Returned by openSession: binds the subject and this PEP credential to the shared BLP high-water mark. */
  readonly sessionToken?: string;
  /** The PEP knows this session ended: the PDP denies (CBAC.SESSION_EXPIRED). False changes nothing. */
  readonly sessionExpired?: boolean;
  readonly makerId?: string;
  readonly priorActions?: readonly string[];
  readonly attrs?: JsonObject;
  readonly [key: string]: JsonValue | undefined;
}

export interface EvaluationRequest {
  readonly subject: Ref;
  readonly action: Action;
  readonly resource: Ref;
  readonly context?: EvaluationContext;
}

export interface OpenSessionResponse {
  readonly token: string;
  readonly sessionId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly idleSeconds: number;
}
export interface CloseSessionResponse { readonly ok: true }

export type PartialEvaluationRequest = Partial<EvaluationRequest>;
export type EvaluationSemantic = 'execute_all' | 'deny_on_first_deny' | 'permit_on_first_permit';
export interface BatchEvaluationRequest extends PartialEvaluationRequest {
  readonly evaluations: readonly PartialEvaluationRequest[];
  readonly options?: { readonly evaluations_semantic?: EvaluationSemantic };
}

export interface Obligations {
  readonly fieldAllowlist?: readonly string[];
  readonly redact: readonly string[];
  readonly maskClasses: readonly string[];
  readonly notify: readonly string[];
  /** postState: the type has integrity checks, so consumption must carry the item's state as the command commits it. */
  readonly decisionToken?: { readonly ttlSeconds: number; readonly resourceVersion: number | null; readonly postState?: true };
}

export interface DecisionContext {
  readonly rules: readonly string[];
  readonly reasons: readonly string[];
  readonly obligations: Obligations;
  readonly policy_version: string;
  readonly would_deny: readonly string[];
  readonly decision_token?: string;
}

export interface Evaluation {
  readonly decision: boolean;
  readonly context: DecisionContext;
}

export interface BatchEvaluationResponse { readonly evaluations: readonly Evaluation[] }
export interface Page { readonly token?: string; readonly limit?: number }
export interface SearchResponse<T> { readonly results: readonly T[]; readonly page: { readonly next_token: string } }
export interface ActionSearchResponse { readonly results: readonly { readonly name: string }[] }

export interface ResourceSearchRequest {
  readonly subject: Ref;
  readonly action: Action;
  readonly resource: TypeRef;
  readonly context?: EvaluationContext;
  readonly page?: Page;
}
export interface SubjectSearchRequest {
  readonly subject: TypeRef;
  readonly action: Action;
  readonly resource: Ref;
  readonly context?: EvaluationContext;
  readonly page?: Page;
}
export interface ActionSearchRequest {
  readonly subject: Ref;
  readonly resource: Ref;
  readonly context?: EvaluationContext;
}

export type ColumnType = 'number' | 'text' | 'boolean' | 'text[]';
export type ColumnMapping = string | {
  readonly column: string;
  readonly kind?: 'scalar' | 'text[]';
  readonly type?: ColumnType;
};
export interface FilterRequest {
  readonly subject: Ref;
  readonly action: Action;
  readonly resource: TypeRef;
  readonly context?: EvaluationContext;
  readonly dialect?: 'postgres';
  readonly columns: Readonly<Record<string, ColumnMapping>>;
}
export interface FilterResponse {
  readonly residual: JsonObject;
  readonly sql: { readonly text: string; readonly params: readonly JsonValue[] };
}

export interface ConsumeTokenRequest {
  readonly token: string;
  readonly action: string | Action;
  readonly resource: Ref;
  readonly resourceVersion: number | null;
  /** The constrained item's attributes as the certified command will commit them, checked by the PDP's IVPs. */
  readonly attrs?: JsonObject;
}
/** `reservation`: the certified action is reserved, not yet done; report its outcome with reportOutcome once it ran.
 *  Absent only from a PDP before 0.5. */
export interface ConsumeTokenResponse { readonly ok: true; readonly reservation?: string }
/** completed: the command ran (the upstream answered 2xx); failed: it did not run, so it stops counting for SoD. */
export type ActionOutcome = 'completed' | 'failed';
export interface OutcomeReportRequest { readonly reservation: string; readonly outcome: ActionOutcome }
export interface OutcomeReportResponse { readonly ok: true; readonly reservation: string; readonly outcome: ActionOutcome }

/** The forwarded request a decision assertion is bound to (docs/API.md 2.0.2). */
export interface RequestBinding {
  /** The backend origin the request goes to. */
  readonly audience: string;
  readonly method: string;
  /** Path with the query exactly as forwarded. */
  readonly path: string;
  /** base64url SHA-256 of the forwarded body (of the empty body when there is none). */
  readonly bodySha256: string;
}
export interface AssertedEvaluationRequest extends EvaluationRequest { readonly request: RequestBinding }
/** An evaluation; on allow, `assertion` is the compact JWS to forward in the `gate-assertion` header. */
export interface AssertedEvaluation extends Evaluation { readonly assertion?: string }
export interface ListAssertionRequest {
  readonly subject: Ref;
  readonly action: Action;
  readonly resource: TypeRef;
  readonly context?: EvaluationContext;
  readonly request: RequestBinding;
}
export interface ListAssertion { readonly decision: boolean; readonly policy_version: string; readonly assertion?: string }

export interface RequestOptions { readonly signal?: AbortSignal }

/** Text is replaceable only when its content class is explicit; arbitrary strings are never scanned. */
export type ContentFragment = { class: string; text: string };
/** A JSON object carrying classified text as `content: [{ class: "finance.amount", text: "…" }]`. */
export type StructuredRecord = JsonObject & { content?: ContentFragment[] };

/** Resource registration (docs/API.md §2.2): the records an application owns, as the PDP decides on them. */
export type Level = 0 | 1 | 2 | 3;
export type Integrity = 'derived' | 'extracted' | 'system' | 'verified';
export interface ResourceRecord {
  readonly type: string;
  readonly id: string;
  readonly level: Level;
  readonly compartments: readonly string[];
  readonly integrity: Integrity;
  /** The content scan result (content classes found, read by ABAC on content attributes); empty when scanned and clean. Required: unscanned is not clean. */
  readonly contentClasses: readonly string[];
  readonly owner?: string;
  readonly parent?: Ref;
  /** Optional: the PDP numbers versions itself when absent; when given, it must be above the stored one. */
  readonly version?: number;
  readonly attrs?: JsonObject;
}
/** proposed: queued for two-person review (a declassification, or a change of integrity, owner or parent). */
export type RegistrationStatus = 'created' | 'updated' | 'unchanged' | 'retired' | 'proposed';
export interface RegistrationItem {
  readonly type: string; readonly id: string; readonly status: RegistrationStatus;
  readonly version?: number; readonly changeId?: string;
}
export interface RegistrationResult { readonly items: readonly RegistrationItem[]; readonly counts: Readonly<Record<RegistrationStatus, number>> }
/** At most 1000 resources and retirements together; kept whole or not at all. */
export interface ResourceSyncRequest { readonly resources?: readonly ResourceRecord[]; readonly retire?: readonly Ref[] }
export interface ResourceListRequest { readonly type: string; readonly cursor?: string; readonly limit?: number }
export interface ResourceListResponse { readonly resources: readonly (Ref & { readonly version: number })[]; readonly next_cursor: string }
