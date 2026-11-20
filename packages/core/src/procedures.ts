// Clark-Wilson checks on who runs a certified command and with what input, independent of the item's state, so the
// point decision (evaluate) and the list filter (buildFilter) share them: C5 input validation, E3 PEP binding of the
// subject's population, E4 certifiers never run what they certified. Pure.
import type { Context, InputFieldRule, InputValidatorDef, Json, PolicyBundle, Subject } from './types.ts';

export interface ProcedureFinding { readonly rule: string; readonly reason: string }

export function validatorsFor(bundle: PolicyBundle, type: string, action: string): readonly InputValidatorDef[] {
  return (bundle.clarkWilson.inputValidators ?? []).filter((v) => v.resourceTypes.includes(type) && v.actions.includes(action));
}

function fieldOk(rule: InputFieldRule, value: Json): boolean {
  const typed = rule.type === 'string' ? typeof value === 'string'
    : rule.type === 'boolean' ? typeof value === 'boolean'
      : typeof value === 'number' && Number.isFinite(value) && (rule.type === 'number' || Number.isInteger(value));
  if (!typed) return false;
  if (rule.enum !== undefined && !rule.enum.includes(value as string | number | boolean)) return false;
  if (typeof value === 'number' && ((rule.min !== undefined && value < rule.min) || (rule.max !== undefined && value > rule.max))) return false;
  return !(typeof value === 'string' && rule.maxLength !== undefined && [...value].length > rule.maxLength);
}

/** Ids of the validators the input fails: a missing required field, a wrong type or bound, or any undeclared field. */
export function failedValidators(validators: readonly InputValidatorDef[], input: unknown): string[] {
  const record = input !== null && typeof input === 'object' && !Array.isArray(input) ? input as Record<string, Json> : undefined;
  return validators.filter((v) => {
    if (!record) return true;
    if (Object.keys(record).some((k) => !Object.hasOwn(v.fields, k))) return true;
    return Object.entries(v.fields).some(([name, rule]) => (Object.hasOwn(record, name) ? !fieldOk(rule, record[name] as Json) : rule.required === true));
  }).map((v) => v.id);
}

/** Denials of a certified command that depend on the caller and the input, never on the item. */
export function procedureFindings(bundle: PolicyBundle, chain: readonly Subject[], type: string, action: string, ctx: Context): ProcedureFinding[] {
  const out: ProcedureFinding[] = [];
  const validators = validatorsFor(bundle, type, action);
  if (validators.length > 0) {
    if (ctx.input === undefined) out.push({ rule: 'CW.INPUT_REQUIRED', reason: `${action} on ${type} validates its input and none was supplied` });
    else for (const id of failedValidators(validators, ctx.input)) out.push({ rule: `CW.INPUT.${id}`, reason: `input validation ${id} failed` });
  }
  const subject = chain[0];
  if ((bundle.clarkWilson.requirePepBinding ?? []).includes(type) && !(subject && (ctx.pepSubjectTypes ?? []).includes(subject.type))) {
    out.push({ rule: 'CW.SUBJECT_NOT_AUTHENTICATED', reason: `the PEP credential is not bound to ${subject?.type ?? 'these'} subjects for ${type} procedures` });
  }
  const certifiers = new Set((ctx.certified ?? []).filter((c) => c.resourceType === type && c.action === action).flatMap((c) => c.by ?? []));
  if (chain.some((p) => certifiers.has(p.id))) out.push({ rule: 'CW.CERTIFIER_EXECUTES', reason: `a certifier of ${action} on ${type} cannot run it` });
  return out;
}
