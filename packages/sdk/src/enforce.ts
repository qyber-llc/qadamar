import { AccessDeniedError, ObligationError } from './errors.ts';
import type { Evaluation, JsonObject, JsonValue } from './types.ts';
import { evaluation as validateEvaluation } from './validation.ts';

export const MASKED_TEXT = '[MASKED]';
const FORBIDDEN_SEGMENTS = new Set(['__proto__', 'prototype', 'constructor']);

type MutableRecord = Record<string, JsonValue>;
type MutableJson = null | boolean | number | string | MutableJson[] | MutableRecord;

function isObject(value: unknown): value is MutableRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function define(target: MutableRecord, key: string, value: JsonValue): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}
function clone(value: JsonValue, seen: WeakSet<object>, depth: number): MutableJson {
  if (depth > 100) throw new ObligationError('The JSON record is too deeply nested');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new ObligationError('The record must contain only finite JSON numbers');
    return value;
  }
  if (typeof value !== 'object') throw new ObligationError('The record must contain only JSON values');
  if (seen.has(value)) throw new ObligationError('The record must not contain cycles');
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const result: MutableJson[] = [];
      for (let index = 0; index < value.length; index++) {
        if (!Object.hasOwn(value, index)) throw new ObligationError('The record must not contain sparse arrays');
        result.push(clone(value[index] as JsonValue, seen, depth + 1));
      }
      return result;
    }
    if (!isObject(value) || Object.getOwnPropertySymbols(value).length > 0) {
      throw new ObligationError('The record must contain only plain JSON objects');
    }
    const result: MutableRecord = {};
    for (const [key, item] of Object.entries(value)) define(result, key, clone(item, seen, depth + 1) as JsonValue);
    return result;
  } finally {
    seen.delete(value);
  }
}

function path(value: string): string[] {
  const parts = value.split('.');
  if (parts.some((part) => part.length === 0 || FORBIDDEN_SEGMENTS.has(part))) {
    throw new ObligationError('An obligation contains an unsafe or empty field path');
  }
  return parts;
}
function read(source: MutableRecord, parts: readonly string[]): { found: boolean; value?: MutableJson } {
  let current: MutableJson = source;
  for (const part of parts) {
    if (!isObject(current) || !Object.hasOwn(current, part)) return { found: false };
    current = current[part] as MutableJson;
  }
  return { found: true, value: current };
}
function write(target: MutableRecord, parts: readonly string[], value: MutableJson): void {
  let current = target;
  for (const part of parts.slice(0, -1)) {
    const existing = Object.hasOwn(current, part) ? current[part] : undefined;
    if (!isObject(existing)) {
      const child: MutableRecord = {};
      define(current, part, child);
      current = child;
    } else current = existing;
  }
  const leaf = parts.at(-1);
  if (leaf !== undefined) define(current, leaf, value as JsonValue);
}
function allowlisted(source: MutableRecord, fields: readonly string[]): MutableRecord {
  const paths = fields.map(path).sort((left, right) => left.length - right.length);
  const result: MutableRecord = {};
  for (const parts of paths) {
    const found = read(source, parts);
    if (found.found) write(result, parts, found.value as MutableJson);
  }
  return result;
}
function redact(record: MutableRecord, fields: readonly string[]): void {
  for (const field of fields) {
    const parts = path(field);
    let current: MutableJson = record;
    for (const [index, part] of parts.entries()) {
      // An array on the path cannot be redacted by key: refuse rather than release it unredacted.
      if (Array.isArray(current)) throw new ObligationError('A redaction path crosses an array; no record was released');
      if (!isObject(current) || !Object.hasOwn(current, part)) break;
      if (index === parts.length - 1) define(current, part, null);
      else current = current[part] as MutableJson;
    }
  }
}
function mask(record: MutableRecord, classes: readonly string[]): void {
  if (classes.length === 0) return;
  if (!Object.hasOwn(record, 'content') || !Array.isArray(record.content)) {
    throw new ObligationError('Masked content requires record.content to be an array of class/text fragments');
  }
  const fragments = record.content;
  for (const fragment of fragments) {
    if (!isObject(fragment) || typeof fragment.class !== 'string' || typeof fragment.text !== 'string') {
      throw new ObligationError('Every record.content fragment must have string class and text fields');
    }
  }
  for (const required of classes) {
    if (!fragments.some((fragment) => isObject(fragment) && fragment.class === required)) {
      throw new ObligationError('A required content class could not be located; no record was released');
    }
  }
  for (const fragment of fragments) {
    if (isObject(fragment) && classes.includes(fragment.class as string)) fragment.text = MASKED_TEXT;
  }
}

/**
 * Returns a deep clone only for a valid allow decision. Redaction and allowlisting accept dotted object paths.
 * A decisionToken obligation is refused unless `decisionTokenConsumed: true` acknowledges its consumption.
 * Masking uses only explicit record.content fragments and refuses missing classes or unsupported obligations.
 */
export function enforce<T extends JsonObject>(decision: Evaluation, record: T, options: { readonly decisionTokenConsumed?: boolean } = {}): T {
  const valid = validateEvaluation(decision);
  if (!valid.decision) throw new AccessDeniedError();
  const obligations = valid.context.obligations;
  if (obligations.notify.length > 0) throw new ObligationError('Notification obligations require a notification-capable PEP');
  // Single-use consumption is the PEP's job: refuse unless the caller says consumeToken already succeeded.
  if (obligations.decisionToken !== undefined && options.decisionTokenConsumed !== true) {
    throw new ObligationError('A decision token must be consumed (single-use) before release; pass the consumed acknowledgement once consumeToken succeeded');
  }
  const cloned = clone(record, new WeakSet(), 0) as MutableRecord;
  if (!isObject(cloned)) throw new ObligationError('The record must be a JSON object');
  const result = obligations.fieldAllowlist === undefined ? cloned : allowlisted(cloned, obligations.fieldAllowlist);
  redact(result, obligations.redact);
  mask(result, obligations.maskClasses);
  return result as T;
}
