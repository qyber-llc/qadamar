import type { Obligations } from '../../core/src/index.ts';
import type { Runtime } from './runtime.ts';
import { HttpError } from './http.ts';
import { evaluation, evaluationSessions } from './pdp.ts';
import { SESSION_ATTRIBUTE } from './sessions.ts';
import type { SessionBindings } from './pep-sessions.ts';
import type { ContextTrust } from './context-trust.ts';

/** OASIS JSON Profile of XACML 3.0 v1.1 mapped onto the AuthZEN evaluation, so decisions and audit rows are the same.
 *  Mapping table, limits and what is not supported: docs/API.md §2.1. */
const XACML = 'urn:oasis:names:tc:xacml:';
const GATE = 'urn:qadamar:1.0:';
const XS = 'http://www.w3.org/2001/XMLSchema#';
export const XACML_MAX_REQUESTS = 1000; // the /access/v1/evaluations limit

type Kind = 'subject' | 'resource' | 'action' | 'environment';
export const CATEGORY: Readonly<Record<Kind, string>> = {
  subject: `${XACML}1.0:subject-category:access-subject`, resource: `${XACML}3.0:attribute-category:resource`,
  action: `${XACML}3.0:attribute-category:action`, environment: `${XACML}3.0:attribute-category:environment`,
};
const SHORTHAND: Readonly<Record<string, Kind | null>> = { AccessSubject: 'subject', Resource: 'resource', Action: 'action', Environment: 'environment',
  RecipientSubject: null, IntermediarySubject: null, Codebase: null, RequestingMachine: null };
const CATEGORY_IDS: Readonly<Record<string, Kind>> = { 'access-subject': 'subject', resource: 'resource', action: 'action', environment: 'environment',
  ...Object.fromEntries(Object.entries(CATEGORY).map(([kind, urn]) => [urn, kind as Kind])) };
export const ATTRIBUTE = {
  subjectId: `${XACML}1.0:subject:subject-id`, subjectType: `${GATE}subject:subject-type`,
  resourceId: `${XACML}1.0:resource:resource-id`, resourceType: `${GATE}resource:resource-type`,
  actionId: `${XACML}1.0:action:action-id`,
  network: `${GATE}environment:network`, networkSensorId: `${GATE}environment:network-sensor-id`, sessionLevel: `${GATE}environment:session-level`, sessionId: SESSION_ATTRIBUTE,
  attestationNetwork: `${GATE}environment:attestation:network`, attestationSessionLevel: `${GATE}environment:attestation:session-level`,
  sessionToken: `${GATE}environment:session-token`,
  makerId: `${GATE}environment:maker-id`, priorAction: `${GATE}environment:prior-action`,
} as const;
export const STATUS = { ok: `${XACML}1.0:status:ok`, missing: `${XACML}1.0:status:missing-attribute`,
  syntax: `${XACML}1.0:status:syntax-error`, processing: `${XACML}1.0:status:processing-error` } as const;
export const OBLIGATION = { redact: `${GATE}obligation:redact`, mask: `${GATE}obligation:mask`, notify: `${GATE}obligation:notify`,
  fieldAllowlist: `${GATE}obligation:field-allowlist`, decisionToken: `${GATE}obligation:decision-token` } as const;
export const ADVICE = { basis: `${GATE}advice:decision-basis`, wouldDeny: `${GATE}advice:would-deny` } as const;
const XS_SHORTHAND = new Set(['string', 'boolean', 'integer', 'double', 'time', 'date', 'dateTime', 'anyURI', 'hexBinary',
  'base64Binary', 'dayTimeDuration', 'yearMonthDuration']);
const KNOWN_OBLIGATIONS = new Set(['redact', 'maskClasses', 'notify', 'fieldAllowlist', 'decisionToken']);

type Obj = Record<string, unknown>;
interface Missing { AttributeId: string; Category: string; DataType: string }
class Fault extends Error {
  readonly code: keyof typeof STATUS; readonly missing?: Missing[];
  constructor(code: keyof typeof STATUS, message: string, missing?: Missing[]) { super(message); this.code = code; this.missing = missing; }
}
const syntax = (message: string): Fault => new Fault('syntax', message);
interface Attr { dataType: string; values: unknown[] }
interface Category { kind: Kind | null; id?: string; attributes: ReadonlyMap<string, Attr> }
interface Evaluation { decision: boolean; context: { rules: string[]; obligations: Obligations; policy_version: string; would_deny: string[]; decision_token?: string } }

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
function obj(v: unknown, what: string): Obj { if (!isObj(v)) throw syntax(`${what} must be an object`); return v; }
const many = (v: unknown): unknown[] => (v === undefined ? [] : Array.isArray(v) ? v : [v]);

function dataType(declared: unknown, values: unknown[], id: string): string {
  if (declared !== undefined) {
    if (typeof declared !== 'string' || !declared) throw syntax(`DataType of ${id} must be a non-empty string`);
    return XS_SHORTHAND.has(declared) ? `${XS}${declared}` : declared;
  }
  // an omitted DataType is inferred from the JSON type of the value(s)
  const kinds = new Set(values.map((v) => typeof v === 'string' ? 'string' : typeof v === 'boolean' ? 'boolean'
    : Number.isInteger(v) ? 'integer' : typeof v === 'number' && Number.isFinite(v) ? 'double' : 'invalid'));
  if (kinds.has('invalid') || (kinds.size > 1 && !(kinds.size === 2 && kinds.has('integer') && kinds.has('double')))) throw syntax(`Value of ${id} has no single JSON data type`);
  return `${XS}${kinds.has('double') ? 'double' : [...kinds][0] ?? 'string'}`;
}
function category(raw: unknown, kind: Kind | null): Category {
  const c = obj(raw, 'Category');
  if (c.Id !== undefined && (typeof c.Id !== 'string' || !c.Id)) throw syntax('Category Id must be a non-empty string');
  const attributes = new Map<string, Attr>();
  for (const item of many(c.Attribute)) {
    const a = obj(item, 'Attribute');
    if (typeof a.AttributeId !== 'string' || !a.AttributeId) throw syntax('AttributeId must be a non-empty string');
    if (!Object.hasOwn(a, 'Value')) throw syntax(`Attribute ${a.AttributeId} has no Value`);
    const values = Array.isArray(a.Value) ? a.Value : [a.Value];
    const type = dataType(a.DataType, values, a.AttributeId);
    const prior = attributes.get(a.AttributeId);
    if (prior && prior.dataType !== type) throw syntax(`Attribute ${a.AttributeId} is given with two data types`);
    attributes.set(a.AttributeId, { dataType: type, values: [...(prior?.values ?? []), ...values] });
  }
  return { kind, ...(typeof c.Id === 'string' ? { id: c.Id } : {}), attributes };
}
function categories(request: Obj): Category[] {
  const all: Category[] = [];
  for (const [key, value] of Object.entries(request)) {
    if (Object.hasOwn(SHORTHAND, key)) all.push(...many(value).map((c) => category(c, SHORTHAND[key] ?? null)));
    if (key !== 'Category') continue;
    for (const raw of many(value)) {
      const id = obj(raw, 'Category').CategoryId;
      if (typeof id !== 'string' || !id) throw syntax('CategoryId must be a non-empty string');
      all.push(category(raw, Object.hasOwn(CATEGORY_IDS, id) ? CATEGORY_IDS[id]! : null));
    }
  }
  return all;
}

/** Reads one Qadamar attribute: absent → undefined; present with another type or arity → syntax error (never guessed). */
function values(c: Category | undefined, id: string, types: readonly string[], single: boolean): unknown[] | undefined {
  const a = c?.attributes.get(id);
  if (!a) return undefined;
  if (!types.includes(a.dataType)) throw syntax(`${id} must have DataType ${types.join(' or ')}`);
  if (single && a.values.length !== 1) throw syntax(`${id} must have exactly one value`);
  const integer = types[0] === `${XS}integer`;
  if (!a.values.every((v) => integer ? Number.isSafeInteger(v) : typeof v === 'string' && v.length > 0)) throw syntax(`${id} has an invalid value`);
  return a.values;
}
function authzenBody(cats: Category[]): Obj {
  const by = new Map<Kind, Category>();
  for (const c of cats) {
    if (c.kind === null) continue;
    if (by.has(c.kind)) throw syntax(`Repeated ${c.kind} category: use MultiRequests for several decisions`);
    by.set(c.kind, c);
  }
  const text = [`${XS}string`]; const id = [`${XS}string`, `${XS}anyURI`];
  const missing: Missing[] = [];
  const need = (kind: Kind, attribute: string, types: string[]): unknown => {
    const found = values(by.get(kind), attribute, types, true)?.[0];
    if (found === undefined) missing.push({ AttributeId: attribute, Category: CATEGORY[kind], DataType: types[0]! });
    return found;
  };
  const subject = { type: values(by.get('subject'), ATTRIBUTE.subjectType, text, true)?.[0] ?? 'user', id: need('subject', ATTRIBUTE.subjectId, id) };
  const resource = { type: need('resource', ATTRIBUTE.resourceType, text), id: need('resource', ATTRIBUTE.resourceId, id) };
  const action = { name: need('action', ATTRIBUTE.actionId, text) };
  if (missing.length) throw new Fault('missing', 'Required attributes are missing', missing);
  const env = by.get('environment');
  const network = values(env, ATTRIBUTE.network, text, true)?.[0];
  const networkSensorId = values(env, ATTRIBUTE.networkSensorId, text, true)?.[0];
  const sessionLevel = values(env, ATTRIBUTE.sessionLevel, [`${XS}integer`], true)?.[0];
  const sessionId = values(env, ATTRIBUTE.sessionId, text, true)?.[0];
  const sessionToken = values(env, ATTRIBUTE.sessionToken, text, true)?.[0];
  const attestationNetwork = values(env, ATTRIBUTE.attestationNetwork, text, true)?.[0];
  const attestationSessionLevel = values(env, ATTRIBUTE.attestationSessionLevel, text, true)?.[0];
  const makerId = values(env, ATTRIBUTE.makerId, id, true)?.[0];
  const priorActions = values(env, ATTRIBUTE.priorAction, text, false);
  const attestations = { ...(attestationNetwork === undefined ? {} : { network: attestationNetwork }),
    ...(attestationSessionLevel === undefined ? {} : { sessionLevel: attestationSessionLevel }) };
  return { subject, resource, action, context: { ...(network === undefined ? {} : { network }), ...(networkSensorId === undefined ? {} : { networkSensorId }),
    ...(sessionLevel === undefined ? {} : { sessionLevel }), ...(sessionId === undefined ? {} : { sessionId }), ...(sessionToken === undefined ? {} : { sessionToken }),
    ...(Object.keys(attestations).length ? { attestations } : {}),
    ...(makerId === undefined ? {} : { makerId }), ...(priorActions === undefined ? {} : { priorActions }) } };
}

const assign = (attributeId: string, value: string): Obj => ({ AttributeId: attributeId, Value: value });
const expression = (id: string, attribute: string, list: readonly string[]): Obj => ({ Id: id, AttributeAssignment: list.map((v) => assign(`${id}:${attribute}`, v)) });
const UNEXPRESSIBLE = 'Decision carries an obligation the XACML mapping cannot express';
/** A Permit carrying an obligation this mapping does not know would be released without it: recorded as a deny with no
 *  decision token (fail closed), then answered Indeterminate. */
export const unexpressible = (d: { obligations: Obligations }): { rule: string; reason: string } | undefined =>
  Object.keys(d.obligations).some((key) => !KNOWN_OBLIGATIONS.has(key)) ? { rule: 'XACML.OBLIGATION_UNEXPRESSIBLE', reason: UNEXPRESSIBLE } : undefined;
function obligations(o: Obligations, token: string | undefined): Obj[] {
  if (Object.keys(o).some((key) => !KNOWN_OBLIGATIONS.has(key))) throw new Fault('processing', UNEXPRESSIBLE);
  return [
    ...(o.redact.length ? [expression(OBLIGATION.redact, 'field', o.redact)] : []),
    ...(o.maskClasses.length ? [expression(OBLIGATION.mask, 'content-class', o.maskClasses)] : []),
    ...(o.notify.length ? [expression(OBLIGATION.notify, 'recipient', o.notify)] : []),
    // an empty allowlist means "no field": it is sent even when empty
    ...(o.fieldAllowlist ? [expression(OBLIGATION.fieldAllowlist, 'field', o.fieldAllowlist)] : []),
    ...(token ? [expression(OBLIGATION.decisionToken, 'jws', [token])] : []),
  ];
}
function result(e: Evaluation, policyIds: boolean): Obj {
  const c = e.context;
  // no policy is written for an action the schema does not declare on this resource type
  const notApplicable = !e.decision && c.rules.length === 1 && c.rules[0] === 'SCHEMA.UNKNOWN_ACTION';
  const duties = e.decision ? obligations(c.obligations, c.decision_token) : [];
  const advice = [{ Id: ADVICE.basis, AttributeAssignment: [...c.rules.map((r) => assign(`${ADVICE.basis}:rule-id`, r)), assign(`${ADVICE.basis}:policy-version`, c.policy_version)] },
    ...(c.would_deny.length ? [expression(ADVICE.wouldDeny, 'rule-id', c.would_deny)] : [])];
  return { Decision: e.decision ? 'Permit' : notApplicable ? 'NotApplicable' : 'Deny', Status: { StatusCode: { Value: STATUS.ok } },
    ...(duties.length ? { Obligations: duties } : {}), AssociatedAdvice: advice,
    ...(policyIds ? { PolicyIdentifierList: { PolicyIdReference: c.rules.map((Id) => ({ Id })) } } : {}) };
}
/** Malformed input is an Indeterminate result, audited as a deny with its reason; anything else (store, audit)
 *  propagates and fails the HTTP request. */
export function indeterminate(rt: Runtime, err: unknown): Obj {
  const f = err instanceof Fault ? err : err instanceof HttpError && err.status === 400 ? syntax('Invalid attribute value') : undefined;
  if (!f) throw err;
  rt.audit.append({ type: 'decision', actor: 'pep', action: 'xacml', effect: 'deny', rules: ['XACML.INDETERMINATE'],
    details: { status: f.code, reason: f.message, ...(f.missing ? { missing: f.missing.map((m) => m.AttributeId) } : {}) } });
  return { Decision: 'Indeterminate', Status: { StatusCode: { Value: STATUS[f.code] }, StatusMessage: f.message,
    ...(f.missing ? { StatusDetail: { MissingAttributeDetail: f.missing } } : {}) } };
}
function individual(rt: Runtime, cats: Category[], policyIds: boolean, pepTypes: readonly string[], pep: string | undefined, bindings?: SessionBindings, trust?: ContextTrust): Obj {
  try {
    // the same evaluation, decision token and audit row as POST /access/v1/evaluation
    const e = evaluation(rt, authzenBody(cats), unexpressible, pepTypes, undefined, pep, bindings, trust) as Evaluation;
    if (e.context.rules.includes('XACML.OBLIGATION_UNEXPRESSIBLE')) {
      return { Decision: 'Indeterminate', Status: { StatusCode: { Value: STATUS.processing }, StatusMessage: UNEXPRESSIBLE } };
    }
    return result(e, policyIds);
  } catch (err) { return indeterminate(rt, err); }
}
function requests(raw: Obj): { policyIds: boolean; individuals: Array<{ cats: Category[] } | { error: unknown }> } {
  const request = obj(raw.Request, 'Request');
  for (const flag of ['ReturnPolicyIdList', 'CombinedDecision']) if (request[flag] !== undefined && typeof request[flag] !== 'boolean') throw syntax(`${flag} must be a boolean`);
  if (request.CombinedDecision === true) throw new Fault('processing', 'CombinedDecision is not supported');
  const policyIds = request.ReturnPolicyIdList === true;
  const all = categories(request);
  if (request.MultiRequests === undefined) return { policyIds, individuals: [{ cats: all }] };
  const refs = obj(request.MultiRequests, 'MultiRequests').RequestReference;
  if (!Array.isArray(refs) || refs.length === 0) throw syntax('MultiRequests needs a non-empty RequestReference array');
  if (refs.length > XACML_MAX_REQUESTS) throw syntax(`At most ${XACML_MAX_REQUESTS} request references`);
  const byId = new Map<string, Category>();
  for (const c of all) {
    if (c.id === undefined) continue;
    if (byId.has(c.id)) throw syntax('Category Id values must be unique');
    byId.set(c.id, c);
  }
  // categories without an Id cannot be referenced: they are shared by every individual request
  const shared = all.filter((c) => c.id === undefined);
  const individuals = refs.map((ref): { cats: Category[] } | { error: unknown } => {
    try {
      const ids = obj(ref, 'RequestReference').ReferenceId;
      if (!Array.isArray(ids) || ids.length === 0 || !ids.every((id) => typeof id === 'string')) throw syntax('ReferenceId must be a non-empty array of strings');
      const chosen = ids.map((id: string) => { const found = byId.get(id); if (!found) throw syntax('ReferenceId names no category'); return found; });
      return { cats: [...shared, ...chosen] };
    } catch (error) { return { error }; }
  });
  return { policyIds, individuals };
}
function decideAll(rt: Runtime, raw: Obj, pepTypes: readonly string[], pep: string | undefined, bindings?: SessionBindings, trust?: ContextTrust): Obj[] {
  const { policyIds, individuals } = requests(raw);
  return individuals.map((entry) => 'error' in entry ? indeterminate(rt, entry.error) : individual(rt, entry.cats, policyIds, pepTypes, pep, bindings, trust));
}
/** The same individual requests, used only to choose their mark-relevant session locks before deciding. */
export function xacmlSessions(rt: Runtime, raw: Obj, pep?: string): string[] {
  try {
    return [...new Set(requests(raw).individuals.flatMap((entry) => {
      if ('error' in entry) return [];
      try { return evaluationSessions(rt, authzenBody(entry.cats), pep); } catch { return []; }
    }))];
  } catch { return []; }
}
/** `pep`: the calling credential, which scopes the session-id attribute (sessions.ts). */
export function xacml(rt: Runtime, raw: Obj, pepTypes: readonly string[] = [], pep?: string, bindings?: SessionBindings, trust?: ContextTrust): { Response: Obj[] } {
  try { return { Response: decideAll(rt, raw, pepTypes, pep, bindings, trust) }; } catch (err) { return { Response: [indeterminate(rt, err)] }; }
}
export const xacmlMalformed = (rt: Runtime): { Response: Obj[] } => ({ Response: [indeterminate(rt, syntax('Request body is not a JSON object'))] });
/** Rate-limit cost, as for /access/v1/evaluations: one token per individual request. */
export function xacmlCost(raw: Obj): number {
  const multi = isObj(raw.Request) && isObj(raw.Request.MultiRequests) ? raw.Request.MultiRequests.RequestReference : undefined;
  return Array.isArray(multi) ? Math.max(1, multi.length) : 1;
}
