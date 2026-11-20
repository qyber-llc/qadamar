import type { Level, PolicyBundle } from '../api/types';
import { contentRules } from '../api/types';
import { msgs } from '../i18n';

const v = () => msgs().policies.validation;

// Client-side shape & referential integrity check mirroring packages/core/src/validate.ts
const OPS = new Set(['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'in', 'contains', 'subset', 'has', 'and', 'or', 'not', 'true']);
const KINDS = new Set(['read', 'write', 'delete', 'approve', 'execute']);
const ROOTS = ['subject.', 'resource.', 'action.', 'context.'];
const TENANT_KEYS = new Set(['rbac', 'abac', 'abacContent', 'context', 'sod']);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isStrArr = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === 'string');
const isLevel = (v: unknown): v is Level => Number.isInteger(v) && (v as number) >= 0 && (v as number) <= 3;

function checkExpr(e: unknown, where: string, errors: string[], depth = 0): void {
  if (depth > 32) { errors.push(v().tooDeep(where)); return; }
  if (!isObj(e) || typeof e.op !== 'string' || !OPS.has(e.op)) { errors.push(v().unknownOp(where)); return; }
  const checkPath = (p: unknown, w: string) => {
    if (typeof p !== 'string' || !ROOTS.some((r) => p.startsWith(r))) {
      errors.push(v().pathRoot(w));
    }
  };
  if (e.op === 'and' || e.op === 'or') {
    if (!Array.isArray(e.args) || e.args.length === 0) { errors.push(v().needsArg(where, e.op)); return; }
    e.args.forEach((a, i) => checkExpr(a, `${where}.args[${i}]`, errors, depth + 1));
  } else if (e.op === 'not') {
    checkExpr(e.arg, `${where}.arg`, errors, depth + 1);
  } else if (e.op === 'has') {
    checkPath(e.path, where);
  } else if (e.op !== 'true') {
    for (const side of ['left', 'right'] as const) {
      const o = e[side];
      if (!isObj(o) || (!Object.hasOwn(o, 'path') && !Object.hasOwn(o, 'value'))) errors.push(v().operand(`${where}.${side}`));
      else if (Object.hasOwn(o, 'path')) checkPath(o.path, `${where}.${side}`);
      else if (typeof o.value === 'number' && !Number.isFinite(o.value)) errors.push(v().finite(`${where}.${side}`));
    }
  }
}

function checkRelations(type: string, rels: unknown, errors: string[]): void {
  if (!isObj(rels)) { errors.push(v().relationsObject(type)); return; }
  for (const [name, def] of Object.entries(rels)) {
    if (!isObj(def) || !Array.isArray(def.union) || def.union.length === 0) {
      errors.push(v().relationUnion(`${type}#${name}`));
      continue;
    }
    for (const r of def.union) {
      if (!isObj(r)) { errors.push(v().unionEntry(`${type}#${name}`)); continue; }
      if ('computed' in r && (typeof r.computed !== 'string' || !Object.hasOwn(rels, r.computed))) {
        errors.push(v().computedUndeclared(`${type}#${name}`, String(r.computed)));
      }
      if ('fromParent' in r) {
        const fp = r.fromParent;
        if (!isObj(fp) || typeof fp.relation !== 'string' || !Object.hasOwn(rels, fp.relation)) {
          errors.push(v().parentUndeclared(`${type}#${name}`));
        }
      }
      if ('viaReports' in r) {
        const vr = r.viaReports;
        if (!isObj(vr) || typeof vr.then !== 'string' || !Object.hasOwn(rels, vr.then)) {
          errors.push(v().viaReportsUndeclared(`${type}#${name}`));
        } else if (!(Number.isInteger(vr.maxDepth) && (vr.maxDepth as number) >= 1 && (vr.maxDepth as number) <= 50)) {
          errors.push(v().maxDepth(`${type}#${name}`));
        }
      }
    }
  }
}

function checkRuleScope(
  r: Record<string, unknown>,
  id: string,
  kind: string,
  types: Record<string, Record<string, unknown>>,
  allActions: ReadonlySet<string>,
  errors: string[],
): void {
  if (r.resourceTypes !== undefined && (!isStrArr(r.resourceTypes) || r.resourceTypes.length === 0 || r.resourceTypes.some((t) => !Object.hasOwn(types, t)))) {
    errors.push(v().resourceTypes(kind, id));
  }
  if (r.actions !== undefined && (!isStrArr(r.actions) || r.actions.length === 0 || r.actions.some((a) => !allActions.has(a)))) {
    errors.push(v().actions(kind, id));
  }
}

const CONTEXT_KEYS = new Set(['id', 'description', 'resourceTypes', 'actions', 'actionKinds', 'minResourceLevel', 'contentClasses',
  'network', 'countries', 'ipRanges', 'timeWindows', 'device', 'mfaMaxAgeSeconds', 'authMaxAgeSeconds', 'authMethodsAny', 'maxRiskScore']);
const REQUIREMENTS = ['network', 'countries', 'ipRanges', 'timeWindows', 'device', 'mfaMaxAgeSeconds', 'authMaxAgeSeconds', 'authMethodsAny', 'maxRiskScore'];
const nonEmptyStrings = (value: unknown, maximum = 100): boolean => isStrArr(value) && value.length > 0 && value.length <= maximum && value.every((item) => item.length > 0);
const boundedAge = (value: unknown): boolean => value === undefined || (Number.isInteger(value) && Number(value) >= 0 && Number(value) <= 31_536_000);
function validContextRule(r: Record<string, unknown>): boolean {
  if (Object.keys(r).some((key) => !CONTEXT_KEYS.has(key))) return false;
  if (r.resourceTypes === undefined && r.actions === undefined && r.actionKinds === undefined) return false;
  if (!REQUIREMENTS.some((key) => r[key] !== undefined)) return false;
  if (r.actionKinds !== undefined && (!Array.isArray(r.actionKinds) || r.actionKinds.length === 0 || r.actionKinds.some((kind) => typeof kind !== 'string' || !KINDS.has(kind)))) return false;
  if (r.minResourceLevel !== undefined && !isLevel(r.minResourceLevel)) return false;
  if (r.contentClasses !== undefined && !nonEmptyStrings(r.contentClasses)) return false;
  if (r.network !== undefined && r.network !== 'trusted') return false;
  if (r.countries !== undefined && (!nonEmptyStrings(r.countries, 249) || (r.countries as string[]).some((country) => !/^[A-Z]{2}$/.test(country)))) return false;
  if (r.ipRanges !== undefined && (!nonEmptyStrings(r.ipRanges) || (r.ipRanges as string[]).some((range) => !/^\S+\/\d{1,3}$/.test(range)))) return false;
  if (r.timeWindows !== undefined && (!Array.isArray(r.timeWindows) || r.timeWindows.length === 0 || r.timeWindows.length > 100 || r.timeWindows.some((window) => {
    if (!isObj(window) || !Array.isArray(window.days) || window.days.length === 0 || window.days.some((day) => !Number.isInteger(day) || Number(day) < 1 || Number(day) > 7)) return true;
    if (typeof window.from !== 'string' || typeof window.to !== 'string' || window.from === window.to || !/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(window.from) || !/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(window.to)) return true;
    try { new Intl.DateTimeFormat('en', { timeZone: String(window.timeZone) }); return false; } catch { return true; }
  }))) return false;
  if (r.device !== undefined && (!isObj(r.device) || Object.keys(r.device).length === 0 || Object.keys(r.device).some((key) => !['managed', 'compliant'].includes(key)) ||
    (r.device.managed !== undefined && typeof r.device.managed !== 'boolean') || (r.device.compliant !== undefined && typeof r.device.compliant !== 'boolean'))) return false;
  if (!boundedAge(r.mfaMaxAgeSeconds) || !boundedAge(r.authMaxAgeSeconds)) return false;
  if (r.authMethodsAny !== undefined && (!nonEmptyStrings(r.authMethodsAny, 16) || (r.authMethodsAny as string[]).some((method) => !/^[A-Za-z0-9_.-]{1,32}$/.test(method)))) return false;
  return r.maxRiskScore === undefined || (Number.isInteger(r.maxRiskScore) && Number(r.maxRiskScore) >= 0 && Number(r.maxRiskScore) <= 100);
}

export type CandidateResult = { readonly ok: true; readonly bundle: PolicyBundle; readonly warnings: readonly string[] } | { readonly ok: false; readonly errors: readonly string[] };

export function validateCandidateBundle(input: unknown): CandidateResult {
  const errors: string[] = [];
  if (!isObj(input)) return { ok: false, errors: [v().bundleObject] };
  if (typeof input.name !== 'string' || input.name.trim().length === 0) errors.push(v().name);

  const schema = isObj(input.schema) ? input.schema : null;
  const rawTypes = schema && isObj(schema.resourceTypes) ? schema.resourceTypes : null;
  const validTypes: Record<string, Record<string, unknown>> = {};
  const allActions = new Set<string>();

  if (!rawTypes) {
    errors.push(v().resourceTypesRequired);
  } else {
    for (const [t, def] of Object.entries(rawTypes)) {
      if (!isObj(def) || !isObj(def.actions) || Object.keys(def.actions).length === 0) {
        errors.push(v().typeActions(t));
        continue;
      }
      validTypes[t] = def;
      for (const [a, ad] of Object.entries(def.actions)) {
        allActions.add(a);
        if (!isObj(ad) || typeof ad.kind !== 'string' || !KINDS.has(ad.kind)) {
          errors.push(v().actionKind(`${t}.${a}`));
        }
      }
      if (def.relations !== undefined) checkRelations(t, def.relations, errors);
    }
  }
  if (!schema || !isStrArr(schema.compartments)) errors.push(v().compartments);
  if (schema && schema.subjectRelations !== undefined) {
    if (!isObj(schema.subjectRelations)) errors.push(v().subjectRelations);
    else for (const [t, rels] of Object.entries(schema.subjectRelations)) checkRelations(t, rels, errors);
  }

  const rbac = isObj(input.rbac) ? input.rbac : null;
  const roles = rbac && isObj(rbac.roles) ? rbac.roles : null;
  if (!roles) {
    errors.push(v().rolesRequired);
  } else {
    for (const [name, role] of Object.entries(roles)) {
      if (!isObj(role) || !Array.isArray(role.grants)) {
        errors.push(v().roleShape(name));
        continue;
      }
      if (role.inherits !== undefined) {
        if (!isStrArr(role.inherits)) errors.push(v().roleInherits(name));
        else for (const parent of role.inherits) if (!Object.hasOwn(roles, parent)) errors.push(v().roleUnknownParent(name, parent));
      }
      for (const g of role.grants) {
        if (!isObj(g) || typeof g.resourceType !== 'string' || !isStrArr(g.actions)) {
          errors.push(v().grantShape(name));
          continue;
        }
        if (g.resourceType !== '*' && !Object.hasOwn(validTypes, g.resourceType)) {
          errors.push(v().grantUnknownType(name, g.resourceType));
          continue;
        }
        const typeActions = validTypes[g.resourceType]?.actions;
        const declared = g.resourceType === '*' ? null : isObj(typeActions) ? Object.keys(typeActions) : [];
        for (const a of g.actions) {
          if (a !== '*' && declared && !declared.includes(a)) errors.push(v().grantUnknownAction(name, a, g.resourceType));
        }
      }
    }
  }

  const m = input.mandatory;
  if (!isObj(m)) {
    errors.push(v().mandatoryRequired);
  } else {
    if (!isLevel(m.untrustedNetworkMaxLevel)) errors.push(v().untrustedMax);
    if (typeof m.compartmentsRequireTrustedNetwork !== 'boolean') errors.push(v().compartmentsTrusted);
    if (!isStrArr(m.trustedRoles)) errors.push(v().trustedRoles);
    else if (roles) for (const r of m.trustedRoles) if (!Object.hasOwn(roles, r)) errors.push(v().trustedRoleUnknown(r));
    if (!isStrArr(m.bibaNoReadDownActions)) errors.push(v().bibaActions);
    if (m.bibaNoReadDownScope !== undefined && (typeof m.bibaNoReadDownScope !== 'string' || !['actions', 'reads', 'all'].includes(m.bibaNoReadDownScope))) errors.push(v().bibaScope);
  }

  const nk = input.needToKnow;
  if (!isObj(nk) || typeof nk.mode !== 'string' || !['off', 'dry_run', 'enforce'].includes(nk.mode)) {
    errors.push(v().ntkMode);
  } else {
    if (!(typeof nk.breakGlassMaxHours === 'number' && nk.breakGlassMaxHours > 0 && nk.breakGlassMaxHours <= 24)) {
      errors.push(v().ntkHours);
    }
    if (!isStrArr(nk.breakGlassNotify)) errors.push(v().ntkNotify);
    if (!isObj(nk.protect)) {
      errors.push(v().ntkProtect);
    } else {
      for (const [t, p] of Object.entries(nk.protect)) {
        if (!isObj(p) || typeof p.relation !== 'string') { errors.push(v().ntkRelationRequired(t)); continue; }
        const tDef = validTypes[t];
        const tRels = tDef && isObj(tDef.relations) ? tDef.relations : {};
        if (!Object.hasOwn(validTypes, t)) errors.push(v().ntkUnknownType(t));
        else if (!Object.hasOwn(tRels, p.relation)) errors.push(v().ntkRelationUndeclared(t, p.relation));
        if (p.minLevel !== undefined && !isLevel(p.minLevel)) errors.push(v().ntkMinLevel(t));
      }
    }
  }

  const ids = new Set<string>();
  const unique = (id: unknown, kind: string): string | null => {
    if (typeof id !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(id)) { errors.push(v().invalidId(kind, String(id))); return null; }
    if (ids.has(id)) errors.push(v().duplicateId(id));
    ids.add(id);
    return id;
  };

  if (!Array.isArray(input.abac)) {
    errors.push(v().rulesArray('abac'));
  } else {
    for (let i = 0; i < input.abac.length; i++) {
      const r = input.abac[i];
      if (!isObj(r)) { errors.push(v().ruleObject(`abac[${i}]`)); continue; }
      const rid = unique(r.id, 'abac') ?? `abac[${i}]`;
      if (typeof r.id === 'string' && r.id.startsWith('CONTENT_')) errors.push(v().abacContentPrefix(rid));
      if (typeof r.effect !== 'string' || !['permit', 'forbid', 'obligation'].includes(r.effect)) {
        errors.push(v().abacEffect(rid));
      }
      checkRuleScope(r, rid, 'abac', validTypes, allActions, errors);
      checkExpr(r.when, `abac ${rid}`, errors);
    }
  }

  // ABAC on content attributes; the legacy name cbac is read for one version, never together with abacContent
  const legacy = Object.hasOwn(input, 'cbac');
  if (legacy && Object.hasOwn(input, 'abacContent')) errors.push(v().contentBoth);
  const field = legacy ? 'cbac' : 'abacContent';
  const content = input[field];
  if (content !== undefined && !Array.isArray(content)) {
    errors.push(v().rulesArray(field));
  } else {
    for (const [i, r] of (content ?? []).entries()) {
      if (!isObj(r)) { errors.push(v().ruleObject(`${field}[${i}]`)); continue; }
      const rid = unique(r.id, field) ?? `${field}[${i}]`;
      if (typeof r.effect !== 'string' || !['deny', 'mask', 'redact'].includes(r.effect)) errors.push(v().contentEffect(field, rid));
      if (typeof r.contentClass !== 'string' || r.contentClass.length === 0) errors.push(v().contentClass(field, rid));
      if (r.effect === 'redact' && (!isStrArr(r.fields) || r.fields.length === 0)) errors.push(v().contentRedact(field, rid));
      checkRuleScope(r, rid, field, validTypes, allActions, errors);
      if (r.unless !== undefined) checkExpr(r.unless, `${field} ${rid}`, errors);
    }
  }

  if (input.context !== undefined && !Array.isArray(input.context)) {
    errors.push(v().rulesArray('context'));
  } else {
    for (const [i, r] of (input.context ?? []).entries()) {
      if (!isObj(r)) { errors.push(v().ruleObject(`context[${i}]`)); continue; }
      const rid = unique(r.id, 'context') ?? `context[${i}]`;
      if (!validContextRule(r)) errors.push(v().contextRule(rid));
      checkRuleScope(r, rid, 'context', validTypes, allActions, errors);
    }
  }

  if (!Array.isArray(input.sod)) {
    errors.push(v().rulesArray('sod'));
  } else {
    for (let i = 0; i < input.sod.length; i++) {
      const r = input.sod[i];
      if (!isObj(r)) { errors.push(v().ruleObject(`sod[${i}]`)); continue; }
      const rid = unique(r.id, 'sod') ?? `sod[${i}]`;
      if (!isStrArr(r.conflicting) || r.conflicting.length < 2) errors.push(v().sodActions(rid));
    }
  }

  const cw = input.clarkWilson;
  if (!isObj(cw) || typeof cw.tokenTtlSeconds !== 'number' || !(cw.tokenTtlSeconds > 0 && cw.tokenTtlSeconds <= 300)) {
    errors.push(v().cwTtl);
  }

  if (errors.length > 0) return { ok: false, errors };
  if (!legacy) return { ok: true, bundle: input as unknown as PolicyBundle, warnings: [] };
  const { cbac: renamed, ...modern } = input;
  return { ok: true, bundle: { ...modern, abacContent: renamed } as unknown as PolicyBundle, warnings: [v().contentLegacy] };
}

export interface EditableTenantSections {
  readonly rbac: PolicyBundle['rbac'];
  readonly abac: PolicyBundle['abac'];
  readonly abacContent: NonNullable<PolicyBundle['abacContent']>;
  readonly context: readonly import('../api/types').ContextRule[];
  readonly sod: PolicyBundle['sod'];
}

export function extractTenantSections(bundle: PolicyBundle): EditableTenantSections {
  return { rbac: bundle.rbac, abac: bundle.abac, abacContent: contentRules(bundle), context: bundle.context ?? [], sod: bundle.sod };
}

export function validateTenantCandidate(
  input: unknown,
  publishedBundle: PolicyBundle,
): CandidateResult {
  if (!isObj(input)) return { ok: false, errors: [v().draftObject] };
  const keyErrors: string[] = [];
  // a draft pasted from an older bundle may still say cbac: accepted in place of abacContent, with a warning
  const contentKey = Object.hasOwn(input, 'cbac') && !Object.hasOwn(input, 'abacContent') ? 'cbac' : 'abacContent';
  for (const key of Object.keys(input)) {
    if (!TENANT_KEYS.has(key) && key !== contentKey) keyErrors.push(v().lockedSection(key));
  }
  for (const requiredKey of TENANT_KEYS) {
    if (!Object.hasOwn(input, requiredKey === 'abacContent' ? contentKey : requiredKey)) keyErrors.push(v().missingSection(requiredKey));
  }
  if (keyErrors.length > 0) return { ok: false, errors: keyErrors };

  return validateCandidateBundle({
    name: publishedBundle.name,
    schema: publishedBundle.schema,
    rbac: input.rbac,
    mandatory: publishedBundle.mandatory,
    needToKnow: publishedBundle.needToKnow,
    abac: input.abac,
    [contentKey]: input[contentKey],
    context: input.context,
    sod: input.sod,
    clarkWilson: publishedBundle.clarkWilson,
  });
}
