import { enforce as enforceDecision } from './enforce.ts';
import { PdpHttpError, PdpNetworkError, PdpResponseError, PepError } from './errors.ts';
import type {
  ActionSearchRequest, ActionSearchResponse, AssertedEvaluation, AssertedEvaluationRequest, ListAssertion, ListAssertionRequest, BatchEvaluationRequest, BatchEvaluationResponse, ConsumeTokenRequest,
  ConsumeTokenResponse, Evaluation, EvaluationRequest, FilterRequest, FilterResponse, JsonObject, OutcomeReportRequest, OutcomeReportResponse, Ref,
  CloseSessionResponse, OpenSessionResponse, RequestOptions, ResourceSearchRequest, SearchResponse, SubjectSearchRequest,
  RegistrationResult, ResourceListRequest, ResourceListResponse, ResourceRecord, ResourceSyncRequest,
} from './types.ts';
import { actions, asserted, batch, closedSession, consumed, evaluation, filter, listAsserted, openedSession, references, reported } from './validation.ts';
import { checkList, checkRecord, checkRef, checkSync, listed, registration } from './resources.ts';

export interface PepClientOptions {
  readonly baseUrl: string;
  readonly apiKey: string;
  readonly fetch?: typeof globalThis.fetch;
  readonly timeoutMs?: number;
}

export class PepClient {
  readonly #baseUrl: string;
  readonly #apiKey: string;
  readonly #fetch: typeof globalThis.fetch;
  readonly #timeoutMs: number;

  constructor(options: PepClientOptions) {
    const url = new URL(options.baseUrl);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
      throw new TypeError('baseUrl must be an HTTP(S) URL without credentials, query, or fragment');
    }
    if (!options.apiKey || /[\r\n]/.test(options.apiKey)) throw new TypeError('apiKey must be a non-empty header-safe string');
    const timeoutMs = options.timeoutMs ?? 10_000;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new TypeError('timeoutMs must be positive and finite');
    this.#baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.#apiKey = options.apiKey;
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#timeoutMs = timeoutMs;
  }

  openSession(subject: Ref, options?: RequestOptions): Promise<OpenSessionResponse> {
    return this.#post('/x/v1/sessions', { subject }, openedSession, options);
  }
  closeSession(token: string, options?: RequestOptions): Promise<CloseSessionResponse> {
    return this.#post('/x/v1/sessions/close', { token }, closedSession, options);
  }
  evaluate(request: EvaluationRequest, options?: RequestOptions): Promise<Evaluation> {
    return this.#post('/access/v1/evaluation', request, evaluation, options);
  }
  evaluateBatch(request: BatchEvaluationRequest, options?: RequestOptions): Promise<BatchEvaluationResponse> {
    return this.#post('/access/v1/evaluations', request, batch, options);
  }
  searchResources(request: ResourceSearchRequest, options?: RequestOptions): Promise<SearchResponse<Ref>> {
    return this.#post('/access/v1/search/resource', request, references, options);
  }
  searchSubjects(request: SubjectSearchRequest, options?: RequestOptions): Promise<SearchResponse<Ref>> {
    return this.#post('/access/v1/search/subject', request, references, options);
  }
  searchActions(request: ActionSearchRequest, options?: RequestOptions): Promise<ActionSearchResponse> {
    return this.#post('/access/v1/search/action', request, actions, options);
  }
  filter(request: FilterRequest, options?: RequestOptions): Promise<FilterResponse> {
    return this.#post('/x/v1/filter', request, filter, options);
  }
  consumeToken(request: ConsumeTokenRequest, options?: RequestOptions): Promise<ConsumeTokenResponse> {
    return this.#post('/x/v1/tokens/consume', request, consumed, options);
  }
  /** After running a consumed certified command: what became of it. Once per reservation (the same report again is
   *  answered alike; another outcome is refused, 409). Unsure whether it ran: do not report; it stays reserved. */
  reportOutcome(request: OutcomeReportRequest, options?: RequestOptions): Promise<OutcomeReportResponse> {
    return this.#post('/x/v1/tokens/outcome', request, reported, options);
  }
  /** An evaluation plus, on allow, a decision assertion signed by the PDP for the backend (docs/API.md 2.0.2). */
  evaluateAsserted(request: AssertedEvaluationRequest, options?: RequestOptions): Promise<AssertedEvaluation> {
    return this.#post('/x/v1/assertions/evaluation', request, asserted, options);
  }
  /** A list request: an assertion when the subject may act on some item of the type; the PEP filters the items. */
  assertList(request: ListAssertionRequest, options?: RequestOptions): Promise<ListAssertion> {
    return this.#post('/x/v1/assertions/list', request, listAsserted, options);
  }
  /** Registers or updates one record of a type this credential is bound to. A change that could widen access to a
   *  known record (lower level, removed compartment or content class, other integrity, owner or parent) is not applied:
   *  it comes back `proposed` with the id of the change awaiting a second person (HTTP 202). */
  async registerResource(resource: ResourceRecord, options?: RequestOptions): Promise<RegistrationResult> {
    checkRecord(resource, 'resource');
    return this.#post('/x/v1/resources', { resource }, registration, options);
  }
  /** Retires a record: decisions on it fail closed (CORE.UNKNOWN_ID) from then on. Retiring it again is a no-op. */
  async retireResource(resource: Ref, options?: RequestOptions): Promise<RegistrationResult> {
    checkRef(resource, 'resource');
    return this.#post('/x/v1/resources/retire', { resource: { type: resource.type, id: resource.id } }, registration, options);
  }
  /** Registers and retires up to 1000 records at once, all or nothing; sending the same batch again changes nothing. */
  async syncResources(request: ResourceSyncRequest, options?: RequestOptions): Promise<RegistrationResult> {
    checkSync(request);
    return this.#post('/x/v1/resources/sync', request, registration, options);
  }
  /** The registered ids and versions of one bound type, in id order; pass `next_cursor` back until it is empty. */
  async listResources(request: ResourceListRequest, options?: RequestOptions): Promise<ResourceListResponse> {
    checkList(request);
    return this.#post('/x/v1/resources/list', request, listed, options);
  }
  async enforce<T extends JsonObject>(request: EvaluationRequest, record: T, options?: RequestOptions): Promise<T> {
    return enforceDecision(await this.evaluate(request, options), record);
  }

  async #post<T>(path: string, body: unknown, validate: (value: unknown) => T, options?: RequestOptions): Promise<T> {
    let serialized: string;
    try { serialized = JSON.stringify(body); }
    catch { throw new PepError('invalid_request', 'The request body must be JSON-serializable'); }
    if (serialized === undefined) throw new PepError('invalid_request', 'The request body must be JSON-serializable');

    if (options?.signal?.aborted) throw new PdpNetworkError('request_aborted', 'The PDP request was aborted');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#timeoutMs);
    const signal = options?.signal ? AbortSignal.any([controller.signal, options.signal]) : controller.signal;
    let response: Response;
    let text: string;
    let reached = false;
    try {
      response = await this.#fetch(`${this.#baseUrl}${path}`, {
        method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json', authorization: `Bearer ${this.#apiKey}` },
        body: serialized,
        signal,
        // the bearer key must never follow a redirect to another host
        redirect: 'error',
      });
      reached = true;
      // the timeout covers the body: a stalled response must not hang the caller
      text = await response.text();
    } catch {
      if (options?.signal?.aborted) throw new PdpNetworkError('request_aborted', 'The PDP request was aborted');
      if (controller.signal.aborted) throw new PdpNetworkError('request_timeout', 'The PDP request timed out');
      throw new PdpNetworkError('network_error', reached ? 'The PDP response could not be read' : 'The PDP could not be reached');
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) {
      let code = 'http_error';
      try {
        const parsed: unknown = JSON.parse(text);
        if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) && 'error' in parsed) {
          const candidate = parsed.error;
          if (typeof candidate === 'string' && /^[a-z0-9_.-]{1,64}$/.test(candidate)) code = candidate;
        }
      } catch { /* A non-JSON error response still produces a sanitized HTTP error. */ }
      const retry = response.headers.get('retry-after');
      const retryAfter = retry !== null && retry.length <= 64 && !/[\r\n\0]/.test(retry) ? retry : undefined;
      throw new PdpHttpError(response.status, code, retryAfter);
    }
    let value: unknown;
    try { value = JSON.parse(text); }
    catch { throw new PdpResponseError('PDP returned invalid JSON'); }
    return validate(value);
  }
}

export function createPepClient(options: PepClientOptions): PepClient { return new PepClient(options); }
