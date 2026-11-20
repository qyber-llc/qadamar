// Bundle validation at the trust boundary (a candidate policy version before simulation or publishing). Structural
// checks plus referential integrity, so a typo ('Forbid', 'Write', 'Enforce') cannot silently widen or narrow access.
// Returns every error found. The engine also fails closed on what this would reject.
import { cidrParts, validAuthMethods, validClock, validCountry, validTimeZone } from './context.ts';
import type { AbacContentRule, ContextRule, PolicyBundle, RelationDef } from './types.ts';

const OPS = new Set(['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'in', 'contains', 'subset', 'has', 'and', 'or', 'not', 'true']);
const KINDS = new Set(['read', 'write', 'delete', 'approve', 'execute']);
const ROOTS = ['subject.', 'resource.', 'action.', 'context.'];
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isStrArr = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === 'string');
const isLevel = (v: unknown): boolean => Number.isInteger(v) && (v as number) >= 0 && (v as number) <= 3;
const own = (o: unknown, k: string): boolean => isObj(o) && Object.hasOwn(o, k);
const BUNDLE_KEYS = new Set(['name', 'schema', 'rbac', 'mandatory', 'needToKnow', 'abac', 'abacContent', 'cbac', 'context', 'sod', 'clarkWilson']);
export const DEPRECATED_CONTENT_FIELD = 'DEPRECATED_CBAC_FIELD: the legacy field cbac (content rules) was read as abacContent; rename it, a later version removes it';
const SCHEMA_KEYS = new Set(['resourceTypes', 'subjectRelations', 'compartments']);
const RESOURCE_TYPE_KEYS = new Set(['actions', 'relations', 'constrained', 'governedAttributes']);
const ACTION_KEYS = new Set(['kind', 'certified', 'requiresSecondPerson']);
const RELATION_KEYS = new Set(['union']);
const REWRITE_KEYS = new Set(['this', 'computed', 'fromParent', 'viaReports']);
const FROM_PARENT_KEYS = new Set(['relation', 'then']);
const VIA_REPORTS_KEYS = new Set(['managerRelation', 'then', 'maxDepth']);
const RBAC_KEYS = new Set(['roles']);
const ROLE_KEYS = new Set(['inherits', 'grants']);
const GRANT_KEYS = new Set(['resourceType', 'actions']);
const MANDATORY_KEYS = new Set(['trustedRoles', 'untrustedNetworkMaxLevel', 'compartmentsRequireTrustedNetwork', 'bibaNoReadDownActions', 'bibaNoReadDownScope']);
const NEED_TO_KNOW_KEYS = new Set(['mode', 'protect', 'breakGlassMaxHours', 'breakGlassNotify']);
const PROTECT_KEYS = new Set(['relation', 'minLevel']);
const ABAC_KEYS = new Set(['id', 'description', 'effect', 'resourceTypes', 'actions', 'when', 'obligations']);
const OBLIGATION_KEYS = new Set(['fieldAllowlist', 'redact', 'maskClasses', 'notify']);
const CONTENT_KEYS = new Set(['id', 'description', 'contentClass', 'effect', 'fields', 'actions', 'unless']);
const SOD_KEYS = new Set(['id', 'description', 'conflicting']);
const CLARK_WILSON_KEYS = new Set(['tokenTtlSeconds', 'ivps', 'requireCertification', 'inputValidators', 'requirePepBinding']);
const IVP_KEYS = new Set(['id', 'description', 'resourceTypes', 'check']);
const INPUT_VALIDATOR_KEYS = new Set(['id', 'description', 'resourceTypes', 'actions', 'fields']);
const CONTEXT_KEYS = new Set(['id', 'description', 'resourceTypes', 'actions', 'actionKinds', 'minResourceLevel', 'contentClasses',
  'network', 'countries', 'ipRanges', 'timeWindows', 'device', 'mfaMaxAgeSeconds', 'authMaxAgeSeconds', 'authMethodsAny', 'maxRiskScore']);
export const MAX_CONTEXT_ITEMS = 4096;
const REQUIREMENTS = ['network', 'countries', 'ipRanges', 'timeWindows', 'device', 'mfaMaxAgeSeconds', 'authMaxAgeSeconds', 'authMethodsAny', 'maxRiskScore'];

function checkExpr(e: unknown, where: string, errors: string[], depth = 0): void {
  if (depth > 32) return void errors.push(`${where}: condition nested too deeply`);
  if (!isObj(e) || typeof e.op !== 'string' || !OPS.has(e.op)) return void errors.push(`${where}: unknown operator`);
  const path = (p: unknown, w: string): void => {
    if (typeof p !== 'string' || !ROOTS.some((r) => p.startsWith(r))) errors.push(`${w}: path must start with subject., resource., action. or context.`);
  };
  if (e.op === 'and' || e.op === 'or') {
    if (!Array.isArray(e.args) || e.args.length === 0) return void errors.push(`${where}: ${e.op} needs at least one argument`);
    e.args.forEach((a, i) => checkExpr(a, `${where}.args[${i}]`, errors, depth + 1));
  } else if (e.op === 'not') checkExpr(e.arg, `${where}.arg`, errors, depth + 1);
  else if (e.op === 'has') path(e.path, where);
  else if (e.op !== 'true') {
    for (const side of ['left', 'right'] as const) {
      const o = e[side];
      if (!isObj(o) || (!own(o, 'path') && !own(o, 'value'))) errors.push(`${where}.${side}: operand needs path or value`);
      else if (own(o, 'path')) path(o.path, `${where}.${side}`);
      else if (typeof o.value === 'number' && !Number.isFinite(o.value)) errors.push(`${where}.${side}: numbers must be finite`);
    }
  }
}

/** Role inheritance must be acyclic: a cycle is a policy-authoring error (expandRoles tolerates it, so it would pass silently). */
function roleCycles(roles: Record<string, unknown>, errors: string[]): void {
  const state = new Map<string, 'open' | 'done'>();
  const parents = (r: string): string[] => {
    const role = roles[r];
    return isObj(role) && isStrArr(role.inherits) ? role.inherits.filter((p) => Object.hasOwn(roles, p)) : [];
  };
  const visit = (r: string, path: string[]): void => {
    if (state.get(r) === 'done') return;
    if (state.get(r) === 'open') return void errors.push(`role inheritance cycle: ${[...path.slice(path.indexOf(r)), r].join(' -> ')}`);
    state.set(r, 'open');
    for (const p of parents(r)) visit(p, [...path, r]);
    state.set(r, 'done');
  };
  for (const r of Object.keys(roles)) visit(r, []);
}

/** Every path an expression reads; tolerant of malformed input (checkExpr reports that). */
function exprPaths(e: unknown, out: string[] = [], depth = 0): string[] {
  if (!isObj(e) || depth > 32) return out;
  if (Array.isArray(e.args)) for (const a of e.args) exprPaths(a, out, depth + 1);
  if (e.arg !== undefined) exprPaths(e.arg, out, depth + 1);
  if (typeof e.path === 'string') out.push(e.path);
  for (const side of [e.left, e.right]) if (isObj(side) && typeof side.path === 'string') out.push(side.path);
  return out;
}

const FIELD_TYPES = new Set(['string', 'number', 'integer', 'boolean']);
const FIELD_KEYS = new Set(['type', 'required', 'enum', 'min', 'max', 'maxLength']);
function checkField(where: string, rule: unknown, errors: string[]): void {
  if (!isObj(rule) || !FIELD_TYPES.has(rule.type as string) || Object.keys(rule).some((k) => !FIELD_KEYS.has(k))) return void errors.push(`${where}: needs a type (string, number, integer, boolean) and only required, enum, min, max, maxLength`);
  if (rule.required !== undefined && typeof rule.required !== 'boolean') errors.push(`${where}: required must be a boolean`);
  if (rule.enum !== undefined && (!Array.isArray(rule.enum) || rule.enum.length === 0 || rule.enum.some((x) => !['string', 'number', 'boolean'].includes(typeof x)))) errors.push(`${where}: enum must list strings, numbers or booleans`);
  for (const k of ['min', 'max'] as const) if (rule[k] !== undefined && (typeof rule[k] !== 'number' || !Number.isFinite(rule[k]))) errors.push(`${where}: ${k} must be a finite number`);
  if (rule.maxLength !== undefined && !(Number.isInteger(rule.maxLength) && (rule.maxLength as number) >= 0)) errors.push(`${where}: maxLength must be a non-negative integer`);
}
/** C5 validators apply to certified commands only: an input check on any other action would never run. */
function checkInputValidators(list: unknown, types: Record<string, { actions: Record<string, unknown> }>, unique: (id: string, kind: string) => void, errors: string[]): void {
  if (list === undefined) return;
  if (!Array.isArray(list)) return void errors.push('clarkWilson.inputValidators must be a list');
  for (const v of list as unknown[]) {
    if (!isObj(v)) { errors.push('clarkWilson.inputValidators entries must be objects'); continue; }
    const id = v.id as string;
    unique(id, 'inputValidator');
    if (Object.keys(v).some((key) => !INPUT_VALIDATOR_KEYS.has(key))) errors.push(`inputValidator ${id}: unknown inputValidator key`);
    if (typeof v.description !== 'string' || v.description.length === 0) errors.push(`inputValidator ${id}: description is required`);
    const scoped = isStrArr(v.resourceTypes) && v.resourceTypes.length > 0 && isStrArr(v.actions) && v.actions.length > 0;
    if (!scoped || (v.resourceTypes as string[]).some((t) => !Object.hasOwn(types, t) || (v.actions as string[]).some((a) => {
      const def = Object.hasOwn(types[t]!.actions, a) ? types[t]!.actions[a] : undefined;
      return !isObj(def) || def.certified !== true;
    }))) errors.push(`inputValidator ${id}: resourceTypes and actions must name certified commands of declared types`);
    if (!isObj(v.fields) || Object.keys(v.fields).length === 0) { errors.push(`inputValidator ${id}: fields must declare at least one field`); continue; }
    for (const [name, rule] of Object.entries(v.fields)) checkField(`inputValidator ${id}.${name}`, rule, errors);
  }
}

function checkRelations(type: string, rels: Record<string, RelationDef>, errors: string[]): void {
  for (const [name, def] of Object.entries(rels)) {
    if (!isObj(def) || !Array.isArray(def.union) || def.union.length === 0) { errors.push(`relation ${type}#${name} needs a non-empty union`); continue; }
    if (Object.keys(def).some((key) => !RELATION_KEYS.has(key))) errors.push(`relation ${type}#${name}: unknown relation key`);
    for (const r of def.union) {
      if (isObj(r) && Object.keys(r).some((key) => !REWRITE_KEYS.has(key))) errors.push(`relation ${type}#${name}: unknown relation rewrite key`);
      if ('computed' in r && !Object.hasOwn(rels, r.computed)) errors.push(`relation ${type}#${name}: computed ${r.computed} is not declared`);
      if ('fromParent' in r) {
        if (isObj(r.fromParent) && Object.keys(r.fromParent).some((key) => !FROM_PARENT_KEYS.has(key))) errors.push(`relation ${type}#${name}: unknown fromParent key`);
        if (!Object.hasOwn(rels, r.fromParent.relation)) errors.push(`relation ${type}#${name}: parent relation ${r.fromParent.relation} is not declared`);
      }
      if ('viaReports' in r) {
        if (isObj(r.viaReports) && Object.keys(r.viaReports).some((key) => !VIA_REPORTS_KEYS.has(key))) errors.push(`relation ${type}#${name}: unknown viaReports key`);
        if (!Object.hasOwn(rels, r.viaReports.then)) errors.push(`relation ${type}#${name}: ${r.viaReports.then} is not declared`);
        if (!(Number.isInteger(r.viaReports.maxDepth) && r.viaReports.maxDepth >= 1 && r.viaReports.maxDepth <= 50)) errors.push(`relation ${type}#${name}: maxDepth must be 1..50`);
      }
    }
  }
}

function checkScope(r: { id: string; actions?: unknown; resourceTypes?: unknown }, kind: string, types: Record<string, { actions: Record<string, unknown> }>, all: ReadonlySet<string>, errors: string[]): void {
  if (r.resourceTypes !== undefined && (!isStrArr(r.resourceTypes) || r.resourceTypes.length === 0 || r.resourceTypes.some((t) => !Object.hasOwn(types, t)))) {
    errors.push(`${kind} ${r.id}: resourceTypes must be a non-empty list of declared types`);
  }
  if (r.actions !== undefined && (!isStrArr(r.actions) || r.actions.length === 0 || r.actions.some((a) => !all.has(a)))) {
    errors.push(`${kind} ${r.id}: actions must be a non-empty list of declared actions`);
  }
}

function checkContextRules(list: unknown, types: Record<string, { actions: Record<string, unknown> }>, all: ReadonlySet<string>, unique: (id: string, kind: string) => void, errors: string[]): void {
  if (list === undefined) return;
  if (!Array.isArray(list) || list.length > 1000) return void errors.push('context must be a list of at most 1000 rules');
  // per-bundle totals bound the work of one decision (each range and window is checked on every matched request)
  const total = (key: 'ipRanges' | 'timeWindows'): number => (list as unknown[]).reduce<number>((n, r) => n + (isObj(r) && Array.isArray(r[key]) ? (r[key] as unknown[]).length : 0), 0);
  for (const key of ['ipRanges', 'timeWindows'] as const) if (total(key) > MAX_CONTEXT_ITEMS) errors.push(`context: at most ${MAX_CONTEXT_ITEMS} ${key} in all rules together`);
  for (const value of list as unknown[]) {
    if (!isObj(value)) { errors.push('context entries must be objects'); continue; }
    const r = value as unknown as ContextRule;
    const id = typeof r.id === 'string' ? r.id : String(r.id);
    unique(r.id, 'context');
    if (Object.keys(value).some((key) => !CONTEXT_KEYS.has(key))) errors.push(`context ${id}: unknown rule key`);
    if (r.description !== undefined && (typeof r.description !== 'string' || r.description.length > 1024)) errors.push(`context ${id}: description must be a string of at most 1024 characters`);
    checkScope(r, 'context', types, all, errors);
    if (r.resourceTypes === undefined && r.actions === undefined && r.actionKinds === undefined) errors.push(`context ${id}: selector needs resourceTypes, actions or actionKinds`);
    if (r.actionKinds !== undefined && (!Array.isArray(r.actionKinds) || r.actionKinds.length === 0 || r.actionKinds.some((kind) => !KINDS.has(kind)))) errors.push(`context ${id}: actionKinds must be a non-empty list of action kinds`);
    if (r.minResourceLevel !== undefined && !isLevel(r.minResourceLevel)) errors.push(`context ${id}: minResourceLevel must be 0..3`);
    if (r.contentClasses !== undefined && (!isStrArr(r.contentClasses) || r.contentClasses.length === 0 || r.contentClasses.length > 100 || r.contentClasses.some((name) => name.length === 0 || name.length > 128))) errors.push(`context ${id}: contentClasses must be 1..100 non-empty names`);
    if (!REQUIREMENTS.some((key) => value[key] !== undefined)) errors.push(`context ${id}: at least one requirement is needed`);
    if (r.network !== undefined && r.network !== 'trusted') errors.push(`context ${id}: network must be trusted`);
    if (r.countries !== undefined && (!Array.isArray(r.countries) || r.countries.length === 0 || r.countries.length > 249 || !r.countries.every(validCountry))) errors.push(`context ${id}: countries must be a non-empty ISO country allow list`);
    if (r.ipRanges !== undefined && (!Array.isArray(r.ipRanges) || r.ipRanges.length === 0 || r.ipRanges.length > 100 || !r.ipRanges.every((range) => cidrParts(range) !== undefined))) errors.push(`context ${id}: ipRanges must be 1..100 IPv4 or IPv6 CIDR ranges`);
    if (r.timeWindows !== undefined) {
      if (!Array.isArray(r.timeWindows) || r.timeWindows.length === 0 || r.timeWindows.length > 100) errors.push(`context ${id}: timeWindows must be 1..100 windows`);
      for (const window of Array.isArray(r.timeWindows) ? r.timeWindows as unknown[] : []) {
        if (!isObj(window) || Object.keys(window).some((key) => !['days', 'from', 'to', 'timeZone'].includes(key)) ||
          !Array.isArray(window.days) || window.days.length === 0 || window.days.length > 7 || window.days.some((day) => !Number.isInteger(day) || day < 1 || day > 7) ||
          !validClock(window.from) || !validClock(window.to) || window.from === window.to || !validTimeZone(window.timeZone)) errors.push(`context ${id}: each time window needs ISO days, different HH:mm from/to and an IANA timeZone`);
      }
    }
    if (r.device !== undefined && (!isObj(r.device) || Object.keys(r.device).length === 0 || Object.keys(r.device).some((key) => !['managed', 'compliant'].includes(key)) ||
      (r.device.managed !== undefined && typeof r.device.managed !== 'boolean') || (r.device.compliant !== undefined && typeof r.device.compliant !== 'boolean'))) errors.push(`context ${id}: device needs managed and/or compliant booleans`);
    for (const key of ['mfaMaxAgeSeconds', 'authMaxAgeSeconds'] as const) if (r[key] !== undefined && (!Number.isInteger(r[key]) || r[key] < 0 || r[key] > 31_536_000)) errors.push(`context ${id}: ${key} must be an integer 0..31536000`);
    if (r.authMethodsAny !== undefined && (!validAuthMethods(r.authMethodsAny) || r.authMethodsAny.length === 0)) errors.push(`context ${id}: authMethodsAny must be a non-empty short method list`);
    if (r.maxRiskScore !== undefined && (!Number.isInteger(r.maxRiskScore) || r.maxRiskScore < 0 || r.maxRiskScore > 100)) errors.push(`context ${id}: maxRiskScore must be an integer 0..100`);
  }
}

export function validateBundle(input: unknown): { ok: true; bundle: PolicyBundle; warnings: string[] } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: ['bundle must be an object'] };
  const b = input as unknown as PolicyBundle;
  const legacyContent = own(input, 'cbac');
  if (legacyContent && own(input, 'abacContent')) errors.push('cbac and abacContent cannot both be present');
  for (const k of Object.keys(input)) if (!BUNDLE_KEYS.has(k)) errors.push(`unknown top-level key ${k}`);
  if (typeof b.name !== 'string' || b.name.length === 0) errors.push('name is required');
  if (isObj(b.schema) && Object.keys(b.schema).some((key) => !SCHEMA_KEYS.has(key))) errors.push('schema: unknown key');
  const types = isObj(b.schema?.resourceTypes) ? b.schema.resourceTypes : {};
  if (!isObj(b.schema?.resourceTypes)) errors.push('schema.resourceTypes is required');
  if (!isStrArr(b.schema?.compartments)) errors.push('schema.compartments must be a list of names');
  for (const [t, def] of Object.entries(types)) {
    if (!isObj(def?.actions) || Object.keys(def.actions).length === 0) { errors.push(`type ${t} needs actions`); continue; }
    if (Object.keys(def).some((key) => !RESOURCE_TYPE_KEYS.has(key))) errors.push(`type ${t}: unknown type key`);
    if (def.constrained !== undefined && typeof def.constrained !== 'boolean') errors.push(`type ${t}: constrained must be a boolean`);
    for (const [a, ad] of Object.entries(def.actions)) {
      if (!KINDS.has(ad?.kind)) errors.push(`${t}.${a}: kind must be read, write, delete, approve or execute`);
      if (isObj(ad)) {
        if (Object.keys(ad).some((key) => !ACTION_KEYS.has(key))) errors.push(`${t}.${a}: unknown action key`);
        for (const key of ['certified', 'requiresSecondPerson'] as const) if (ad[key] !== undefined && typeof ad[key] !== 'boolean') errors.push(`${t}.${a}: ${key} must be a boolean`);
      }
    }
    checkRelations(t, (def.relations ?? {}) as Record<string, RelationDef>, errors);
    const governed: unknown = (def as { governedAttributes?: unknown }).governedAttributes;
    if (governed !== undefined && (!isStrArr(governed) || governed.some((a) => !/^[A-Za-z0-9_-]{1,64}$/.test(a)))) errors.push(`type ${t}: governedAttributes must list attribute names`);
  }
  const all = new Set(Object.values(types).flatMap((t) => Object.keys(t?.actions ?? {})));
  for (const [t, rels] of Object.entries(b.schema?.subjectRelations ?? {})) checkRelations(t, rels as Record<string, RelationDef>, errors);
  if (isObj(b.rbac) && Object.keys(b.rbac).some((key) => !RBAC_KEYS.has(key))) errors.push('rbac: unknown key');
  const roles = isObj(b.rbac?.roles) ? b.rbac.roles : {};
  if (!isObj(b.rbac?.roles)) errors.push('rbac.roles is required');
  for (const [name, role] of Object.entries(roles)) {
    if (!isObj(role) || !Array.isArray(role.grants)) { errors.push(`role ${name} must be an object with grants`); continue; }
    if (Object.keys(role).some((key) => !ROLE_KEYS.has(key))) errors.push(`role ${name}: unknown role key`);
    if (role.inherits !== undefined && !isStrArr(role.inherits)) errors.push(`role ${name}: inherits must be a list of roles`);
    else for (const parent of role.inherits ?? []) if (!Object.hasOwn(roles, parent)) errors.push(`role ${name} inherits unknown role ${parent}`);
    for (const g of role.grants ?? []) {
      if (isObj(g) && Object.keys(g).some((key) => !GRANT_KEYS.has(key))) errors.push(`role ${name}: unknown grant key`);
      if (g.resourceType !== '*' && !Object.hasOwn(types, g.resourceType)) { errors.push(`role ${name} grants on unknown type ${g.resourceType}`); continue; }
      const declared = g.resourceType === '*' ? null : Object.keys(types[g.resourceType]?.actions ?? {});
      for (const a of g.actions) if (a !== '*' && declared && !declared.includes(a)) errors.push(`role ${name}: ${a} is not an action of ${g.resourceType}`);
    }
  }
  roleCycles(roles, errors);
  const m = b.mandatory;
  if (!isObj(m)) errors.push('mandatory is required');
  else {
    if (Object.keys(m).some((key) => !MANDATORY_KEYS.has(key))) errors.push('mandatory: unknown key');
    if (!isLevel(m.untrustedNetworkMaxLevel)) errors.push('mandatory.untrustedNetworkMaxLevel must be 0..3');
    if (typeof m.compartmentsRequireTrustedNetwork !== 'boolean') errors.push('mandatory.compartmentsRequireTrustedNetwork must be true or false');
    if (!isStrArr(m.trustedRoles)) errors.push('mandatory.trustedRoles must be a list of roles');
    else for (const r of m.trustedRoles) if (!Object.hasOwn(roles, r)) errors.push(`mandatory.trustedRoles: unknown role ${r}`);
    if (!isStrArr(m.bibaNoReadDownActions)) errors.push('mandatory.bibaNoReadDownActions must be a list of actions');
    else if (m.bibaNoReadDownActions.some((a) => !all.has(a))) errors.push('mandatory.bibaNoReadDownActions must list declared actions');
    if (m.bibaNoReadDownScope !== undefined && !['actions', 'reads', 'all'].includes(m.bibaNoReadDownScope)) errors.push('mandatory.bibaNoReadDownScope must be actions, reads or all');
  }
  const nk = b.needToKnow;
  if (!isObj(nk) || !['off', 'dry_run', 'enforce'].includes(nk.mode)) errors.push('needToKnow.mode must be off, dry_run or enforce');
  else {
    if (Object.keys(nk).some((key) => !NEED_TO_KNOW_KEYS.has(key))) errors.push('needToKnow: unknown key');
    if (!(nk.breakGlassMaxHours > 0 && nk.breakGlassMaxHours <= 24)) errors.push('needToKnow.breakGlassMaxHours must be in (0, 24]');
    if (!isStrArr(nk.breakGlassNotify)) errors.push('needToKnow.breakGlassNotify must be a list');
    if (!isObj(nk.protect)) errors.push('needToKnow.protect is required');
    else for (const [t, p] of Object.entries(nk.protect)) {
      if (isObj(p) && Object.keys(p).some((key) => !PROTECT_KEYS.has(key))) errors.push(`needToKnow on ${t}: unknown protect key`);
      if (!Object.hasOwn(types, t)) errors.push(`needToKnow protects unknown type ${t}`);
      else if (!Object.hasOwn(types[t]?.relations ?? {}, p.relation)) errors.push(`needToKnow on ${t}: relation ${p.relation} is not declared`);
      if (p.minLevel !== undefined && !isLevel(p.minLevel)) errors.push(`needToKnow on ${t}: minLevel must be 0..3`);
    }
  }
  const ids = new Set<string>();
  const unique = (id: string, kind: string): void => {
    if (typeof id !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(id)) errors.push(`${kind} id ${String(id)} is not a valid id`);
    if (ids.has(id)) errors.push(`duplicate rule id ${id}`);
    ids.add(id);
  };
  for (const r of b.abac ?? []) {
    unique(r.id, 'abac');
    if (Object.keys(r).some((key) => !ABAC_KEYS.has(key))) errors.push(`abac ${r.id}: unknown rule key`);
    if (isObj(r.obligations) && Object.keys(r.obligations).some((key) => !OBLIGATION_KEYS.has(key))) errors.push(`abac ${r.id}: unknown obligations key`);
    // ABAC.<id> would read as a content-attribute code (ABAC.CONTENT_DENY, _MASK, _REDACT)
    if (typeof r.id === 'string' && r.id.startsWith('CONTENT_')) errors.push(`abac ${r.id}: the id prefix CONTENT_ is reserved for content-attribute codes`);
    if (!['permit', 'forbid', 'obligation'].includes(r.effect)) errors.push(`abac ${r.id}: effect must be permit, forbid or obligation`);
    checkScope(r, 'abac', types, all, errors);
    checkExpr(r.when, `abac ${r.id}`, errors);
  }
  // ABAC on content attributes; the legacy field name is reported back so the author finds the rule
  const field = legacyContent ? 'cbac' : 'abacContent';
  const content: unknown = legacyContent ? b.cbac : b.abacContent;
  if (content !== undefined && !Array.isArray(content)) errors.push(`${field} must be a list`);
  for (const r of Array.isArray(content) ? content as AbacContentRule[] : []) {
    unique(r.id, field);
    if (Object.keys(r).some((key) => !CONTENT_KEYS.has(key))) errors.push(`${field} ${r.id}: unknown rule key`);
    if (!['deny', 'mask', 'redact'].includes(r.effect)) errors.push(`${field} ${r.id}: effect must be deny, mask or redact`);
    if (typeof r.contentClass !== 'string' || r.contentClass.length === 0) errors.push(`${field} ${r.id}: contentClass is required`);
    if (r.effect === 'redact' && (!isStrArr(r.fields) || r.fields.length === 0)) errors.push(`${field} ${r.id}: redact needs fields`);
    checkScope(r, field, types, all, errors);
    if (r.unless) checkExpr(r.unless, `${field} ${r.id}`, errors);
  }
  checkContextRules(b.context, types, all, unique, errors);
  for (const r of b.sod ?? []) {
    unique(r.id, 'sod');
    if (Object.keys(r).some((key) => !SOD_KEYS.has(key))) errors.push(`sod ${r.id}: unknown rule key`);
    if (!isStrArr(r.conflicting) || r.conflicting.length < 2) errors.push(`sod ${r.id} needs two or more actions`);
    else if (r.conflicting.some((a) => !all.has(a))) errors.push(`sod ${r.id}: conflicting must name declared actions`);
  }
  if (isObj(b.clarkWilson) && Object.keys(b.clarkWilson).some((key) => !CLARK_WILSON_KEYS.has(key))) errors.push('clarkWilson: unknown key');
  if (!(b.clarkWilson?.tokenTtlSeconds > 0 && b.clarkWilson.tokenTtlSeconds <= 300)) errors.push('clarkWilson.tokenTtlSeconds must be in (0, 300]');
  const ivps: unknown = b.clarkWilson?.ivps;
  if (ivps !== undefined && !Array.isArray(ivps)) errors.push('clarkWilson.ivps must be a list');
  for (const i of Array.isArray(ivps) ? ivps as unknown[] : []) {
    if (!isObj(i)) { errors.push('clarkWilson.ivps entries must be objects'); continue; }
    const id = i.id as string;
    unique(id, 'ivp');
    if (Object.keys(i).some((key) => !IVP_KEYS.has(key))) errors.push(`ivp ${id}: unknown ivp key`);
    if (typeof i.description !== 'string' || i.description.length === 0) errors.push(`ivp ${id}: description is required`);
    if (!isStrArr(i.resourceTypes) || i.resourceTypes.length === 0 || i.resourceTypes.some((t) => !Object.hasOwn(types, t) || types[t]?.constrained !== true)) {
      errors.push(`ivp ${id}: resourceTypes must be a non-empty list of declared constrained types`);
    }
    checkExpr(i.check, `ivp ${id}`, errors);
    if (exprPaths(i.check).some((p) => !p.startsWith('resource.'))) errors.push(`ivp ${id}: an integrity check reads resource.* paths only`);
  }
  const required: unknown = b.clarkWilson?.requireCertification;
  if (required !== undefined && (!isStrArr(required) || required.some((t) => !Object.hasOwn(types, t) || types[t]?.constrained !== true))) {
    errors.push('clarkWilson.requireCertification must list declared constrained types');
  }
  const binding: unknown = b.clarkWilson?.requirePepBinding;
  if (binding !== undefined && (!isStrArr(binding) || binding.some((t) => !Object.hasOwn(types, t) || types[t]?.constrained !== true))) {
    errors.push('clarkWilson.requirePepBinding must list declared constrained types');
  }
  checkInputValidators(b.clarkWilson?.inputValidators, types, unique, errors);
  if (errors.length > 0) return { ok: false, errors };
  if (!legacyContent) return { ok: true, bundle: b, warnings: [] };
  const { cbac: legacy, ...modern } = b;
  return { ok: true, bundle: { ...modern, abacContent: legacy ?? [] }, warnings: [DEPRECATED_CONTENT_FIELD] };
}
