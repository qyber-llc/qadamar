import { PdpResponseError } from './errors.ts';
import type {
  ActionSearchResponse, AssertedEvaluation, BatchEvaluationResponse, ListAssertion, ConsumeTokenResponse, DecisionContext, Evaluation, OutcomeReportResponse,
  CloseSessionResponse, FilterResponse, JsonObject, JsonValue, Obligations, OpenSessionResponse, Ref, SearchResponse,
} from './types.ts';

const EVALUATION_KEYS = new Set(['decision', 'context']);
const CONTEXT_KEYS = new Set(['rules', 'reasons', 'obligations', 'policy_version', 'would_deny', 'decision_token']);
const OBLIGATION_KEYS = new Set(['fieldAllowlist', 'redact', 'maskClasses', 'notify', 'decisionToken']);

function malformed(): never { throw new PdpResponseError(); }
export function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) malformed();
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) malformed();
  return value as Record<string, unknown>;
}
function onlyKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): void {
  if (Object.keys(value).some((key) => !allowed.has(key))) malformed();
}
function string(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) malformed();
  return value;
}
function strings(value: unknown): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) malformed();
  return [...value] as string[];
}
export function json(value: unknown, depth = 0): JsonValue {
  if (depth > 100) malformed();
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) malformed();
    return value;
  }
  if (Array.isArray(value)) return value.map((item) => json(item, depth + 1));
  if (typeof value === 'object') {
    const source = object(value);
    const result: Record<string, JsonValue> = {};
    for (const [key, item] of Object.entries(source)) Object.defineProperty(result, key, {
      value: json(item, depth + 1), enumerable: true, writable: true, configurable: true,
    });
    return result;
  }
  return malformed();
}

function obligations(value: unknown): Obligations {
  const source = object(value);
  onlyKeys(source, OBLIGATION_KEYS);
  const result: {
    fieldAllowlist?: string[]; redact: string[]; maskClasses: string[]; notify: string[];
    decisionToken?: { ttlSeconds: number; resourceVersion: number | null; postState?: true };
  } = {
    redact: strings(source.redact), maskClasses: strings(source.maskClasses), notify: strings(source.notify),
  };
  if (source.fieldAllowlist !== undefined) result.fieldAllowlist = strings(source.fieldAllowlist);
  if (source.decisionToken !== undefined) {
    const token = object(source.decisionToken);
    onlyKeys(token, new Set(['ttlSeconds', 'resourceVersion', 'postState']));
    if (token.postState !== undefined && token.postState !== true) malformed();
    if (typeof token.ttlSeconds !== 'number' || !Number.isFinite(token.ttlSeconds) || token.ttlSeconds <= 0) malformed();
    if (token.resourceVersion !== null && (typeof token.resourceVersion !== 'number' || !Number.isSafeInteger(token.resourceVersion))) malformed();
    result.decisionToken = { ttlSeconds: token.ttlSeconds, resourceVersion: token.resourceVersion, ...(token.postState ? { postState: true as const } : {}) };
  }
  return result;
}

function context(value: unknown): DecisionContext {
  const source = object(value);
  onlyKeys(source, CONTEXT_KEYS);
  const result: {
    rules: string[]; reasons: string[]; obligations: Obligations; policy_version: string; would_deny: string[]; decision_token?: string;
  } = {
    rules: strings(source.rules), reasons: strings(source.reasons), obligations: obligations(source.obligations),
    policy_version: string(source.policy_version), would_deny: strings(source.would_deny),
  };
  if (source.decision_token !== undefined) result.decision_token = string(source.decision_token);
  return result;
}

export function evaluation(value: unknown): Evaluation {
  const source = object(value);
  onlyKeys(source, EVALUATION_KEYS);
  if (typeof source.decision !== 'boolean') malformed();
  return { decision: source.decision, context: context(source.context) };
}

export function batch(value: unknown): BatchEvaluationResponse {
  const source = object(value);
  onlyKeys(source, new Set(['evaluations']));
  if (!Array.isArray(source.evaluations)) malformed();
  return { evaluations: source.evaluations.map(evaluation) };
}

export function openedSession(value: unknown): OpenSessionResponse {
  const source = object(value);
  onlyKeys(source, new Set(['token', 'sessionId', 'issuedAt', 'expiresAt', 'idleSeconds']));
  if (!Number.isSafeInteger(source.idleSeconds) || (source.idleSeconds as number) <= 0) malformed();
  return { token: string(source.token), sessionId: string(source.sessionId), issuedAt: string(source.issuedAt),
    expiresAt: string(source.expiresAt), idleSeconds: source.idleSeconds as number };
}

export function closedSession(value: unknown): CloseSessionResponse {
  const source = object(value); onlyKeys(source, new Set(['ok']));
  if (source.ok !== true) malformed();
  return { ok: true };
}

function ref(value: unknown): Ref {
  const source = object(value);
  onlyKeys(source, new Set(['type', 'id']));
  return { type: string(source.type), id: string(source.id) };
}

export function references(value: unknown): SearchResponse<Ref> {
  const source = object(value);
  onlyKeys(source, new Set(['results', 'page']));
  if (!Array.isArray(source.results)) malformed();
  const page = object(source.page);
  onlyKeys(page, new Set(['next_token']));
  if (typeof page.next_token !== 'string') malformed();
  return { results: source.results.map(ref), page: { next_token: page.next_token } };
}

export function actions(value: unknown): ActionSearchResponse {
  const source = object(value);
  onlyKeys(source, new Set(['results']));
  if (!Array.isArray(source.results)) malformed();
  return { results: source.results.map((item) => {
    const action = object(item);
    onlyKeys(action, new Set(['name']));
    return { name: string(action.name) };
  }) };
}

export function filter(value: unknown): FilterResponse {
  const source = object(value);
  onlyKeys(source, new Set(['residual', 'sql']));
  const residual = json(source.residual);
  if (residual === null || Array.isArray(residual) || typeof residual !== 'object') malformed();
  const sql = object(source.sql);
  onlyKeys(sql, new Set(['text', 'params']));
  if (typeof sql.text !== 'string' || !Array.isArray(sql.params)) malformed();
  return { residual: residual as JsonObject, sql: { text: sql.text, params: sql.params.map((item) => json(item)) } };
}

export function consumed(value: unknown): ConsumeTokenResponse {
  const source = object(value);
  onlyKeys(source, new Set(['ok', 'reservation']));
  if (source.ok !== true) malformed();
  return source.reservation === undefined ? { ok: true } : { ok: true, reservation: string(source.reservation) };
}

export function reported(value: unknown): OutcomeReportResponse {
  const source = object(value);
  onlyKeys(source, new Set(['ok', 'reservation', 'outcome']));
  if (source.ok !== true || (source.outcome !== 'completed' && source.outcome !== 'failed')) malformed();
  return { ok: true, reservation: string(source.reservation), outcome: source.outcome };
}

/** An allow without an assertion is malformed: the gateway would have nothing to prove the decision with. */
export function asserted(value: unknown): AssertedEvaluation {
  const { assertion, ...rest } = object(value);
  const e = evaluation(rest);
  if (e.decision !== (assertion !== undefined)) malformed();
  return assertion === undefined ? e : { ...e, assertion: string(assertion) };
}

export function listAsserted(value: unknown): ListAssertion {
  const source = object(value);
  onlyKeys(source, new Set(['decision', 'policy_version', 'assertion']));
  if (typeof source.decision !== 'boolean' || source.decision !== (source.assertion !== undefined)) malformed();
  return { decision: source.decision, policy_version: string(source.policy_version), ...(source.assertion === undefined ? {} : { assertion: string(source.assertion) }) };
}
