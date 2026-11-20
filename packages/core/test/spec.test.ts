// docs/spec/policy-bundle.schema.json against validateBundle: the examples pass both, a set of invalid bundles fails
// both, and the condition operators of the schema are exactly those validateBundle accepts.
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';
import { canonical, validateBundle } from '../src/index.ts';

type Schema = { readonly [k: string]: unknown };
const root = new URL('../../../', import.meta.url);
const schema: Schema = JSON.parse(readFileSync(new URL('docs/spec/policy-bundle.schema.json', root), 'utf8'));
const spec = readFileSync(new URL('docs/spec/POLICY-LANGUAGE.md', root), 'utf8');

// A JSON Schema (2020-12) subset evaluator for the keywords the schema file uses; the next test pins that list.
const KEYWORDS = new Set(['$schema', '$id', 'title', 'description', '$defs', '$ref', 'type', 'enum', 'const', 'properties', 'required',
  'additionalProperties', 'items', 'minItems', 'maxItems', 'minLength', 'maxLength', 'minProperties', 'pattern', 'minimum', 'maximum', 'exclusiveMinimum', 'oneOf', 'not', 'if', 'then']);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const TYPES: Record<string, (v: unknown) => boolean> = {
  object: isObj, array: Array.isArray, string: (v) => typeof v === 'string', boolean: (v) => typeof v === 'boolean',
  number: (v) => typeof v === 'number', integer: (v) => Number.isInteger(v), null: (v) => v === null,
};

function check(s: Schema, v: unknown, at = '$'): string[] {
  const out: string[] = [];
  const sub = (x: unknown, val: unknown, where: string): void => { out.push(...check(x as Schema, val, where)); };
  if (typeof s.$ref === 'string') sub(s.$ref.replace('#/$defs/', '').split('/').reduce((n: unknown, k) => (n as Schema)[k], schema.$defs), v, at);
  if (s.type !== undefined && ![s.type].flat().some((t) => TYPES[t as string]?.(v))) return [...out, `${at}: not ${String(s.type)}`];
  if (Array.isArray(s.enum) && !s.enum.some((x) => canonical(x) === canonical(v))) out.push(`${at}: not one of ${s.enum.join(', ')}`);
  if (s.const !== undefined && canonical(s.const) !== canonical(v)) out.push(`${at}: not ${String(s.const)}`);
  if (typeof v === 'string') {
    if (typeof s.minLength === 'number' && [...v].length < s.minLength) out.push(`${at}: too short`);
    if (typeof s.maxLength === 'number' && [...v].length > s.maxLength) out.push(`${at}: too long`);
    if (typeof s.pattern === 'string' && !new RegExp(s.pattern, 'u').test(v)) out.push(`${at}: does not match ${s.pattern}`);
  }
  if (typeof v === 'number') {
    if (typeof s.minimum === 'number' && v < s.minimum) out.push(`${at}: below ${s.minimum}`);
    if (typeof s.maximum === 'number' && v > s.maximum) out.push(`${at}: above ${s.maximum}`);
    if (typeof s.exclusiveMinimum === 'number' && v <= s.exclusiveMinimum) out.push(`${at}: not above ${s.exclusiveMinimum}`);
  }
  if (Array.isArray(v)) {
    if (typeof s.minItems === 'number' && v.length < s.minItems) out.push(`${at}: fewer than ${s.minItems} items`);
    if (typeof s.maxItems === 'number' && v.length > s.maxItems) out.push(`${at}: more than ${s.maxItems} items`);
    if (s.items !== undefined) v.forEach((x, i) => sub(s.items, x, `${at}[${i}]`));
  }
  if (isObj(v)) {
    const props = (s.properties ?? {}) as Schema;
    for (const k of (s.required ?? []) as string[]) if (!Object.hasOwn(v, k)) out.push(`${at}: ${k} is required`);
    if (typeof s.minProperties === 'number' && Object.keys(v).length < s.minProperties) out.push(`${at}: fewer than ${s.minProperties} properties`);
    for (const [k, x] of Object.entries(v)) {
      if (Object.hasOwn(props, k)) sub(props[k], x, `${at}.${k}`);
      else if (s.additionalProperties === false) out.push(`${at}: unknown property ${k}`);
      else if (isObj(s.additionalProperties)) sub(s.additionalProperties, x, `${at}.${k}`);
    }
  }
  if (Array.isArray(s.oneOf)) {
    const matches = s.oneOf.filter((x) => check(x as Schema, v, at).length === 0).length;
    if (matches !== 1) out.push(`${at}: matches ${matches} of oneOf`);
  }
  if (s.not !== undefined && check(s.not as Schema, v, at).length === 0) out.push(`${at}: matches not`);
  if (s.if !== undefined && check(s.if as Schema, v, at).length === 0 && s.then !== undefined) sub(s.then, v, at);
  return out;
}

const examples = readdirSync(new URL('examples/', root)).map((d) => ({ d, bundle: JSON.parse(readFileSync(new URL(`examples/${d}/bundle.json`, root), 'utf8')) }));
const toy = examples.find((e) => e.d === 'toy-domain')?.bundle;

test('spec: the schema file uses only the JSON Schema keywords the test evaluator implements', () => {
  const walk = (s: unknown, at: string, inMap: boolean): void => {
    if (Array.isArray(s)) return s.forEach((x, i) => walk(x, `${at}[${i}]`, false));
    if (!isObj(s)) return;
    for (const [k, v] of Object.entries(s)) {
      if (!inMap) assert.ok(KEYWORDS.has(k), `${at}: keyword ${k} is not implemented by the test evaluator`);
      if (k === 'enum' || k === 'const' || k === 'required') continue;
      walk(v, `${at}.${k}`, !inMap && (k === 'properties' || k === '$defs'));
    }
  };
  walk(schema, '$', false);
});

test('spec: every example bundle validates against the schema and validateBundle', () => {
  assert.ok(examples.length >= 2);
  for (const { d, bundle } of examples) {
    assert.deepEqual(check(schema, bundle), [], d);
    const v = validateBundle(bundle);
    assert.ok(v.ok, `${d}: ${v.ok ? '' : v.errors.join('; ')}`);
  }
});

test('spec: invalid bundles are rejected by both the schema and validateBundle', () => {
  const cases: Record<string, (b: any) => void> = {
    'unknown top-level key': (b) => { b.extra = 1; },
    'unknown schema key': (b) => { b.schema.resourceType = {}; },
    'unknown resource-type key': (b) => { b.schema.resourceTypes.payment.constraned = true; },
    'unknown action key': (b) => { b.schema.resourceTypes.payment.actions.approve.certifed = true; },
    'non-boolean constrained': (b) => { b.schema.resourceTypes.payment.constrained = 'true'; },
    'non-boolean certified': (b) => { b.schema.resourceTypes.case.actions.close.certified = 'true'; },
    'non-boolean requiresSecondPerson': (b) => { b.schema.resourceTypes.payment.actions.approve.requiresSecondPerson = 'true'; },
    'unknown relation key': (b) => { b.schema.resourceTypes.case.relations.member.unions = []; },
    'unknown relation rewrite key': (b) => { b.schema.resourceTypes.case.relations.member.union[0].direct = true; },
    'unknown fromParent key': (b) => { b.schema.resourceTypes.case.relations.member.union[1].fromParent.parent = 'parent'; },
    'unknown viaReports key': (b) => { b.schema.resourceTypes.case.relations.knows.union[1].viaReports.depth = 20; },
    'unknown rbac key': (b) => { b.rbac.role = {}; },
    'unknown role key': (b) => { b.rbac.roles.viewer.inherit = []; },
    'unknown grant key': (b) => { b.rbac.roles.viewer.grants[0].action = ['read']; },
    'unknown mandatory key': (b) => { b.mandatory.bibaNoReadDownAction = []; },
    'unknown needToKnow key': (b) => { b.needToKnow.breakglassNotify = []; },
    'unknown protect key': (b) => { b.needToKnow.protect.case.level = 1; },
    'missing protect': (b) => { delete b.needToKnow.protect; },
    'non-object protect': (b) => { b.needToKnow.protect = []; },
    'unknown ABAC key': (b) => { b.abac[0].action = ['read']; },
    'unknown obligations key': (b) => { b.abac[3].obligations.notifiy = []; },
    'content resourceTypes is not legal': (b) => { b.abacContent[0].resourceTypes = ['case']; },
    'unknown sod key': (b) => { b.sod[0].conflicts = ['create', 'approve']; },
    'unknown clarkWilson key': (b) => { b.clarkWilson.tokenTTLSeconds = 15; },
    'unknown ivp key': (b) => { b.clarkWilson.ivps = [{ id: 'i', description: 'i', resourceTypes: ['payment'], check: { op: 'true' }, actions: ['read'] }]; },
    'unknown input-validator key': (b) => { b.clarkWilson.inputValidators = [{ id: 'iv', description: 'd', resourceTypes: ['payment'], actions: ['create'], fields: { amount: { type: 'number' } }, when: { op: 'true' } }]; },
    'empty name': (b) => { b.name = ''; },
    'missing mandatory': (b) => { delete b.mandatory; },
    'effect Forbid': (b) => { b.abac[1].effect = 'Forbid'; },
    'kind Write': (b) => { b.schema.resourceTypes.case.actions.update.kind = 'Write'; },
    'mode Enforce': (b) => { b.needToKnow.mode = 'Enforce'; },
    'unknown operator': (b) => { b.abac[0].when = { op: 'xor', args: [] }; },
    'unknown operator (internal unknown)': (b) => { b.abac[0].when = { op: 'unknown' }; },
    'unrooted path': (b) => { b.abac[0].when = { op: 'eq', left: { path: 'subject' }, right: { value: 1 } }; },
    'has without root': (b) => { b.abac[0].when = { op: 'has', path: 'attrs.x' }; },
    'empty and': (b) => { b.abac[0].when = { op: 'and', args: [] }; },
    'operand without path or value': (b) => { b.abac[0].when = { op: 'eq', left: {}, right: { value: 1 } }; },
    'token ttl 0': (b) => { b.clarkWilson.tokenTtlSeconds = 0; },
    'token ttl 301': (b) => { b.clarkWilson.tokenTtlSeconds = 301; },
    'break-glass 48 h': (b) => { b.needToKnow.breakGlassMaxHours = 48; },
    'level 4': (b) => { b.mandatory.untrustedNetworkMaxLevel = 4; },
    'sod with one action': (b) => { b.sod[0].conflicting = ['create']; },
    'redact without fields': (b) => { b.abacContent.push({ id: 'r', description: 'r', contentClass: 'x', effect: 'redact' }); },
    'bad rule id': (b) => { b.abac[0].id = 'bad id!'; },
    'ABAC rule id with the reserved CONTENT_ prefix': (b) => { b.abac[0].id = 'CONTENT_DENY'; },
    'empty scope': (b) => { b.abac[0].resourceTypes = []; },
    'maxDepth 0': (b) => { b.schema.resourceTypes.case.relations.knows.union[1].viaReports.maxDepth = 0; },
    'empty union': (b) => { b.schema.resourceTypes.case.relations.member.union = []; },
    'type without actions': (b) => { b.schema.resourceTypes.folder.actions = {}; },
    'governed attribute name': (b) => { b.schema.resourceTypes.case.governedAttributes = ['bad name']; },
    'ivp without description': (b) => { b.clarkWilson.ivps = [{ id: 'i', description: '', resourceTypes: ['payment'], check: { op: 'true' } }]; },
    'input field with an unknown key': (b) => { b.clarkWilson.inputValidators = [{ id: 'iv', description: 'd', resourceTypes: ['payment'], actions: ['create'], fields: { amount: { type: 'number', foo: 1 } } }]; },
    'input validator without fields': (b) => { b.clarkWilson.inputValidators = [{ id: 'iv', description: 'd', resourceTypes: ['payment'], actions: ['create'], fields: {} }]; },
    'context risk above 100': (b) => { b.context = [{ id: 'risk', actions: ['read'], maxRiskScore: 101 }]; },
    'context weekday 8': (b) => { b.context = [{ id: 'time', actions: ['read'], timeWindows: [{ days: [8], from: '09:00', to: '10:00', timeZone: 'Asia/Dubai' }] }]; },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const b = structuredClone(toy);
    mutate(b);
    assert.ok(check(schema, b).length > 0, `${name}: the schema accepts it`);
    assert.equal(validateBundle(b).ok, false, `${name}: validateBundle accepts it`);
  }
});

test('spec: the condition operators of the schema are those validateBundle accepts, and the spec names each', () => {
  const ops = (schema.$defs as any).expr.oneOf.flatMap((v: any) => v.properties.op.enum ?? [v.properties.op.const]);
  assert.deepEqual([...ops].sort(), ['and', 'contains', 'eq', 'ge', 'gt', 'has', 'in', 'le', 'lt', 'ne', 'not', 'or', 'subset', 'true']);
  const sample = (op: string): unknown => (op === 'and' || op === 'or' ? { op, args: [{ op: 'true' }] } : op === 'not' ? { op, arg: { op: 'true' } }
    : op === 'has' ? { op, path: 'subject.attrs.x' } : op === 'true' ? { op } : { op, left: { path: 'subject.id' }, right: { value: 'x' } });
  for (const op of ops) {
    const b = structuredClone(toy);
    b.abac[0].when = sample(op);
    assert.deepEqual(check(schema, b), [], op);
    assert.ok(validateBundle(b).ok, op);
    assert.ok(spec.includes(`\`${op}\``), `POLICY-LANGUAGE.md does not name ${op}`);
  }
  assert.match(spec, /^# Qadamar policy language, version 1\.0/m);
});
