// Cedar export (docs/spec/POLICY-LANGUAGE.md, appendix A): the part of a bundle Cedar can decide the same way as Qadamar,
// as a Cedar JSON schema and Cedar policy text, plus every rule it cannot carry and why. Qadamar's three-valued conditions
// compile into two error-free Cedar expressions per condition, "is TRUE" and "is FALSE", every attribute read guarded by
// `has`: a permit needs TRUE, a forbid fires unless FALSE, exactly as in evaluate(). Expects a bundle validateBundle
// accepted. Not validated against the Cedar engine: packages/core/test/cedar.test.ts differential-tests the output
// against evaluate() with a Cedar-subset test oracle.
import { evalTri, type Env } from './conditions.ts';
import { contentRules } from './content.ts';
import { actionDef, liveRoles, withLiveRoles } from './evaluate.ts';
import { requestErrors } from './request.ts';
import type { ContextRule, Expr, Json, Operand, PolicyBundle, Request } from './types.ts';

export const CEDAR_NAMESPACE = 'Qadamar';
type Scalar = 'Long' | 'String' | 'Boolean';
type CType = Scalar | 'IpAddr' | `Set<${Scalar}>`;
type Slot = CType | 'Record' | 'conflict';

export interface Unsupported { readonly rule: string; readonly reason: string }
export interface CedarExport {
  /** Cedar schema in the JSON schema format, namespace CEDAR_NAMESPACE. */
  readonly schema: Json;
  /** Cedar policy text. */
  readonly policies: string;
  readonly unsupported: readonly Unsupported[];
}
export interface CedarUid { readonly type: string; readonly id: string }
export interface CedarEntity { readonly uid: CedarUid; readonly attrs: Record<string, Json>; readonly parents: readonly CedarUid[] }
/** A Qadamar request in Cedar's JSON request and entity formats. */
export interface CedarRequest {
  readonly principal: CedarUid;
  readonly action: CedarUid;
  readonly resource: CedarUid;
  readonly context: Record<string, Json>;
  readonly entities: readonly CedarEntity[];
}
/** The request has no faithful Cedar form (malformed, delegated, or data that does not fit the schema): decide it with Qadamar. */
export class CedarMappingError extends Error {}
class Skip extends Error {}

const BUILTIN: Readonly<Record<string, CType>> = {
  'subject.id': 'String', 'subject.type': 'String', 'subject.active': 'Boolean', 'subject.roles': 'Set<String>',
  'subject.clearance': 'Long', 'subject.compartments': 'Set<String>', 'subject.integrity': 'String',
  'resource.id': 'String', 'resource.type': 'String', 'resource.level': 'Long', 'resource.compartments': 'Set<String>',
  'resource.integrity': 'String', 'resource.owner': 'String', 'resource.version': 'Long', 'resource.contentClasses': 'Set<String>',
  'context.network': 'String', 'context.now': 'String', 'context.ip': 'IpAddr', 'context.country': 'String',
  'context.authTime': 'String', 'context.mfaTime': 'String', 'context.authMethods': 'Set<String>', 'context.riskScore': 'Long',
};
const OPTIONAL = new Set(['resource.owner', 'resource.version', 'context.ip', 'context.country', 'context.authTime', 'context.mfaTime', 'context.authMethods', 'context.riskScore']);
const VAR = { subject: 'principal', resource: 'resource', context: 'context' } as const;
type Root = keyof typeof VAR;
const RESERVED = new Set(['true', 'false', 'if', 'then', 'else', 'in', 'is', 'like', 'has', 'Subject', 'Role', 'Action']);
const ns = (name: string): string => `${CEDAR_NAMESPACE}::${name}`;
const isScalar = (t: unknown): t is Scalar => t === 'Long' || t === 'String' || t === 'Boolean';
const elem = (t: string): Scalar | undefined => (t.startsWith('Set<') ? (t.slice(4, -1) as Scalar) : undefined);
const isObj = (v: unknown): v is Record<string, Json> => typeof v === 'object' && v !== null && !Array.isArray(v);
const surrogate = (s: string): boolean => /\p{Cs}/u.test(s);

/** A Cedar string literal; `star` escapes `*` for a `like` pattern. */
function str(s: string, star = false): string {
  if (surrogate(s)) throw new Skip('a string with an unpaired surrogate has no Cedar form');
  let out = '';
  for (const ch of s) {
    const c = ch.codePointAt(0) as number;
    out += ch === '"' || ch === '\\' ? `\\${ch}` : star && ch === '*' ? '\\*' : c < 0x20 || c === 0x7f ? `\\u{${c.toString(16)}}` : ch;
  }
  return `"${out}"`;
}

// ---------- paths and their types ----------

interface PathRef { readonly root: Root; readonly key: string; readonly builtin?: string; readonly attrs?: readonly string[] }

function parsePath(p: string): PathRef {
  const [root = '', field = '', ...rest] = p.split('.');
  if (!Object.hasOwn(VAR, root)) throw new Skip(`${p}: ${root === 'action' ? 'Cedar actions carry no attributes; scope the rule with actions instead' : 'unknown root'}`);
  if (field === 'attrs' && rest.length > 0 && rest.every((s) => s.length > 0)) return { root: root as Root, key: p, attrs: rest };
  if (rest.length === 0 && Object.hasOwn(BUILTIN, p)) return { root: root as Root, key: p, builtin: field };
  throw new Skip(`${p}: only the request fields of the Qadamar model and ${root}.attrs.* paths are exported`);
}
const safePath = (p: string): PathRef | undefined => { try { return parsePath(p); } catch { return undefined; } };

/** 'Set' is the empty list: a set of any element type. */
function litType(v: Json): CType | 'Set' | null {
  if (v === null) return null;
  if (typeof v === 'boolean') return 'Boolean';
  if (typeof v === 'string') return 'String';
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new Skip(`${v}: Cedar numbers are 64-bit integers (decimal is an extension with other operators)`);
    return 'Long';
  }
  if (Array.isArray(v)) {
    const ts = new Set(v.map(litType));
    const [t] = ts;
    if (ts.size === 0) return 'Set';
    if (ts.size > 1 || !isScalar(t)) throw new Skip('a list literal must hold values of one scalar type to be a Cedar set');
    return `Set<${t}>`;
  }
  throw new Skip('object literals are not exported');
}
const safeLit = (v: Json): CType | 'Set' | null | undefined => { try { return litType(v); } catch { return undefined; } };

/** Attribute types under *.attrs, inferred from the literals and built-in fields each path is compared with. */
class Types {
  readonly slots = new Map<string, Slot>();

  add(p: PathRef | undefined, t: CType | undefined): boolean {
    if (!p?.attrs || !t) return false;
    const cur = this.slots.get(p.key);
    if (cur === t || cur === 'conflict') return false;
    this.slots.set(p.key, cur === undefined ? t : 'conflict');
    return true;
  }

  of(p: PathRef): Slot | undefined {
    if (p.builtin) return BUILTIN[p.key];
    const record = [...this.slots.keys()].some((k) => k.startsWith(`${p.key}.`));
    const own = this.slots.get(p.key);
    if (record) return own === undefined ? 'Record' : 'conflict'; // read as a value and walked into
    return own;
  }

  /** Attribute names declared directly under a prefix (e.g. resource.attrs). */
  children(prefix: string): string[] {
    const keys = [...this.slots.keys()].filter((k) => k.startsWith(`${prefix}.`));
    return [...new Set(keys.map((k) => k.slice(prefix.length + 1).split('.')[0] as string))].sort();
  }
}

type Pair = readonly [PathRef, PathRef, 'same' | 'elementOf'];
interface Facts { readonly types: Types; readonly pairs: Pair[]; readonly contains: [PathRef, Scalar][] }

function collect(e: Expr, facts: Facts, depth = 0): void {
  if (depth > 64 || e.op === 'true' || e.op === 'unknown' || e.op === 'has') return;
  if ('args' in e) { for (const a of e.args) collect(a, facts, depth + 1); return; }
  if (e.op === 'not') { collect(e.arg, facts, depth + 1); return; }
  const { types, pairs, contains } = facts;
  const side = (o: Operand) => ('path' in o ? { p: safePath(o.path) } : { t: safeLit(o.value) });
  const l = side(e.left), r = side(e.right);
  const scalar = (t: unknown): Scalar | undefined => (isScalar(t) ? t : undefined);
  const set = (t: unknown): CType | undefined => (typeof t === 'string' && elem(t) ? t as CType : undefined);
  switch (e.op) {
    case 'eq': case 'ne':
      if (l.p && r.p) pairs.push([l.p, r.p, 'same']);
      else types.add(l.p ?? r.p, scalar(l.t ?? r.t));
      break;
    case 'lt': case 'le': case 'gt': case 'ge':
      types.add(l.p, 'Long'); types.add(r.p, 'Long');
      break;
    case 'in': {
      const s = set(r.t), x = scalar(l.t);
      if (l.p && r.p) pairs.push([l.p, r.p, 'elementOf']);
      else if (l.p) types.add(l.p, s ? elem(s) : undefined);
      else types.add(r.p, x ? `Set<${x}>` : undefined);
      break;
    }
    case 'contains': {
      const s = set(l.t), x = scalar(r.t);
      if (l.p && r.p) pairs.push([r.p, l.p, 'elementOf']);
      else if (l.p && x) contains.push([l.p, x]);
      else if (r.p && s) types.add(r.p, elem(s));
      break;
    }
    case 'subset':
      if (l.p && r.p) pairs.push([l.p, r.p, 'same']);
      else types.add(l.p ?? r.p, set(l.t ?? r.t));
      break;
  }
}

function settle(types: Types, pairs: readonly Pair[]): void {
  const typed = (t: Slot | undefined): t is CType => t !== undefined && t !== 'Record' && t !== 'conflict';
  for (let changed = true; changed;) {
    changed = false;
    for (const [a, b, rel] of pairs) {
      const ta = types.of(a), tb = types.of(b);
      if (rel === 'same') changed = (typed(ta) && types.add(b, ta)) || (typed(tb) && types.add(a, tb)) || changed;
      else changed = (isScalar(ta) && types.add(b, `Set<${ta}>`)) || (typed(tb) && types.add(a, elem(tb))) || changed;
    }
  }
}

interface Analysis { readonly types: Types; readonly badTypes: ReadonlySet<string> }
const analyses = new WeakMap<PolicyBundle, Analysis>();

function analyze(bundle: PolicyBundle): Analysis {
  const hit = analyses.get(bundle);
  if (hit) return hit;
  const facts: Facts = { types: new Types(), pairs: [], contains: [] };
  for (const r of bundle.abac) if (r.effect !== 'obligation') collect(r.when, facts);
  for (const r of contentRules(bundle)) if (r.effect === 'deny' && r.unless) collect(r.unless, facts);
  const { types, pairs } = facts;
  settle(types, pairs);
  // `contains` on an attribute is a set test, unless the attribute is known to be a string (then a substring test)
  for (const [p, t] of facts.contains) if (!(types.of(p) === 'String' && t === 'String')) types.add(p, `Set<${t}>`);
  settle(types, pairs);
  const badTypes = new Set(Object.keys(bundle.schema.resourceTypes).filter((t) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(t) || RESERVED.has(t)));
  const out = { types, badTypes };
  analyses.set(bundle, out);
  return out;
}

// ---------- conditions: Qadamar's TRUE and FALSE as two Cedar expressions ----------

/** The loosest operator at the top level of a Cedar expression: '||', '&&', ' ' (a relation) or '' (a primary). */
function loosest(x: string): string {
  let depth = 0, quoted = false, found = '';
  for (let i = 0; i < x.length; i++) {
    const c = x[i];
    if (quoted) { if (c === '\\') i++; else if (c === '"') quoted = false; continue; }
    if (c === '"') quoted = true;
    else if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth--;
    else if (depth === 0 && c === ' ') {
      const op = x.slice(i + 1, i + 3);
      if (op === '||') return '||';
      found = op === '&&' ? '&&' : found || ' ';
    }
  }
  return found;
}
const wrap = (x: string, when: (op: string) => boolean): string => (when(loosest(x)) ? `(${x})` : x);
function junction(xs: readonly string[], unit: string, zero: string, sep: string, inner: string): string {
  const kept = xs.filter((x) => x !== unit);
  if (kept.includes(zero)) return zero;
  return kept.length === 0 ? unit : kept.length === 1 ? kept[0] as string : kept.map((x) => wrap(x, (op) => op === inner)).join(sep);
}
// && binds tighter than ||: an || inside an && needs parentheses; an && inside an || keeps them for the reader
const conj = (xs: readonly string[]): string => junction(xs, 'true', 'false', ' && ', '||');
const disj = (xs: readonly string[]): string => junction(xs, 'false', 'true', ' || ', '&&');
const neg = (x: string): string => (x === 'true' ? 'false' : x === 'false' ? 'true' : `!${wrap(x, (op) => op !== '')}`);

interface Tri { readonly t: string; readonly f: string }
const UNKNOWN_TRI: Tri = { t: 'false', f: 'false' };
/** A comparison: TRUE when its operands are present and it holds, FALSE when present and it does not, else UNKNOWN. */
const defined = (guard: string, holds: string, fails = neg(holds)): Tri => ({ t: conj([guard, holds]), f: conj([guard, fails]) });

const ORDER = { lt: ['<', '>='], le: ['<=', '>'], gt: ['>', '<='], ge: ['>=', '<'] } as const;

interface Compiled { readonly cedar: string; readonly guard: string; readonly type: CType | 'Set'; readonly empty?: boolean }

/** `principal.attrs["a"]["b"]`, guarded by `principal.attrs has "a" && principal.attrs["a"] has "b"`. */
function attrsAccess(root: Root, segs: readonly string[]): { cedar: string; guard: string } {
  let cedar = `${VAR[root]}.attrs`;
  const guards: string[] = [];
  for (const s of segs) { guards.push(`${cedar} has ${str(s)}`); cedar = `${cedar}[${str(s)}]`; }
  return { cedar, guard: conj(guards) };
}

function compilePath(o: string, types: Types): Compiled {
  const p = parsePath(o);
  const t = types.of(p);
  if (t === 'conflict') throw new Skip(`${o} is compared with values of different types`);
  if (t === undefined) throw new Skip(`the type of ${o} is not fixed by any comparison in the exported rules`);
  if (t === 'Record') throw new Skip(`${o} is a record of attributes, not a value`);
  if (!p.builtin) return { ...attrsAccess(p.root, p.attrs as readonly string[]), type: t };
  const v = VAR[p.root];
  return { cedar: `${v}.${p.builtin}`, guard: OPTIONAL.has(p.key) ? `${v} has ${p.builtin}` : 'true', type: t };
}

const literal = (v: Json): string => (Array.isArray(v) ? `[${v.map(literal).join(', ')}]` : typeof v === 'string' ? str(v) : String(v));

function comparison(e: Extract<Expr, { left: Operand }>, types: Types): Tri {
  if ('value' in e.left && 'value' in e.right) {
    const r = evalTri(e, {} as Env); // two literals: decided now
    return { t: r === true ? 'true' : 'false', f: r === false ? 'true' : 'false' };
  }
  for (const o of [e.left, e.right]) if ('value' in o) litType(o.value); // a literal's own problem is the reason, not the path's
  const side = (o: Operand): Compiled | null => {
    if ('path' in o) return compilePath(o.path, types);
    const t = litType(o.value);
    return t === null ? null : { cedar: literal(o.value), guard: 'true', type: t, empty: Array.isArray(o.value) && o.value.length === 0 };
  };
  const l = side(e.left), r = side(e.right);
  if (!l || !r) return UNKNOWN_TRI; // a null literal: UNKNOWN whatever the other side holds
  const guard = conj([l.guard, r.guard]);
  const isSet = (t: CType | 'Set'): boolean => t === 'Set' || elem(t) !== undefined;
  const mistyped = (): never => { throw new Skip(`${e.op} of ${l.type} and ${r.type} is always UNKNOWN in Qadamar; not exported`); };
  switch (e.op) {
    case 'eq': case 'ne': {
      if (!isScalar(l.type) || l.type !== r.type) throw new Skip(`${e.op} of ${l.type} and ${r.type}: Qadamar compares lists in order and Cedar sets without, and Cedar strict validation refuses mixed types; only equal scalar types are exported`);
      const c = defined(guard, `${l.cedar} == ${r.cedar}`, `${l.cedar} != ${r.cedar}`);
      return e.op === 'eq' ? c : { t: c.f, f: c.t };
    }
    case 'lt': case 'le': case 'gt': case 'ge':
      if (l.type !== 'Long' || r.type !== 'Long') throw new Skip(`${e.op} of ${l.type} and ${r.type}: Cedar orders 64-bit integers only (no string ordering)`);
      return defined(guard, `${l.cedar} ${ORDER[e.op][0]} ${r.cedar}`, `${l.cedar} ${ORDER[e.op][1]} ${r.cedar}`);
    case 'in':
      if (!isScalar(l.type) || !(r.type === 'Set' || elem(r.type) === l.type)) return mistyped();
      return r.empty ? { t: 'false', f: guard } : defined(guard, `${r.cedar}.contains(${l.cedar})`);
    case 'contains':
      if (l.type === 'String' && r.type === 'String') {
        if (!('value' in e.right)) throw new Skip('a substring test needs a literal needle (Cedar like takes a pattern literal)');
        return defined(guard, `${l.cedar} like "*${str(e.right.value as string, true).slice(1, -1)}*"`);
      }
      if (!isScalar(r.type) || !(l.type === 'Set' || elem(l.type) === r.type)) return mistyped();
      return l.empty ? { t: 'false', f: guard } : defined(guard, `${l.cedar}.contains(${r.cedar})`);
    case 'subset':
      if (!isSet(l.type) || !isSet(r.type) || (l.type !== r.type && l.type !== 'Set' && r.type !== 'Set')) return mistyped();
      if (l.empty) return { t: guard, f: 'false' };
      return defined(guard, r.empty ? `${l.cedar}.isEmpty()` : `${r.cedar}.containsAll(${l.cedar})`);
  }
}

function condition(e: Expr, types: Types, depth = 0): Tri {
  if (depth > 64) throw new Skip('condition nested too deeply');
  switch (e.op) {
    case 'true': return { t: 'true', f: 'false' };
    case 'unknown': return UNKNOWN_TRI;
    case 'and': case 'or': {
      const parts = e.args.map((a) => condition(a, types, depth + 1));
      const ts = parts.map((p) => p.t), fs = parts.map((p) => p.f);
      return e.op === 'and' ? { t: conj(ts), f: disj(fs) } : { t: disj(ts), f: conj(fs) };
    }
    case 'not': { const c = condition(e.arg, types, depth + 1); return { t: c.f, f: c.t }; }
    case 'has': {
      const p = parsePath(e.path);
      const t = types.of(p);
      if (t === undefined || t === 'conflict') throw new Skip(`has ${e.path}: no comparison fixes the attribute's type, so the schema cannot declare it`);
      const g = p.builtin ? compilePath(e.path, types).guard : attrsAccess(p.root, p.attrs as readonly string[]).guard;
      return { t: g, f: neg(g) };
    }
    default: return comparison(e, types);
  }
}

// ---------- policies ----------

const NOT_MAPPED: readonly Unsupported[] = [
  { rule: 'mandatory', reason: 'Bell-LaPadula (levels, session level, server-side high-water mark), compartments, the untrusted-network limits and Biba are built-in models decided before tenant rules; Cedar has no lattice and the session state lives in the PDP. Cedar allows more: keep the mandatory stage in Qadamar or the PEP.' },
  { rule: 'delegation', reason: 'an agent is decided together with every person in its delegation chain; a Cedar request has one principal. toCedarRequest refuses a subject with a delegator.' },
  { rule: 'SOD.MAKER_MISMATCH', reason: 'a caller-supplied maker that contradicts the server-derived one denies in Qadamar; it is request history, not policy. Cedar allows more.' },
];

function emit(effect: 'permit' | 'forbid', id: string, description: string | undefined, scope: string, when: string, unless = 'false'): string {
  const notes = [`@id(${str(id)})`, ...(description ? [`@description(${str(description)})`] : [])].join('\n');
  return `${notes}\n${effect} (${scope})${when === 'true' ? '' : `\nwhen { ${when} }`}${unless === 'false' ? '' : `\nunless { ${unless} }`};`;
}

const actionScope = (actions: readonly string[] | undefined): string =>
  (actions ? `action in [${actions.map((a) => `${ns('Action')}::${str(a)}`).join(', ')}]` : 'action');

function typeScope(types: readonly string[] | undefined, bad: ReadonlySet<string>): string {
  if (!types) return 'true';
  const invalid = types.find((t) => bad.has(t));
  if (invalid !== undefined) throw new Skip(`resource type ${invalid} is not a Cedar identifier`);
  return disj(types.map((t) => `resource is ${ns(t)}`));
}

function rbacPolicies(bundle: PolicyBundle, bad: ReadonlySet<string>, out: string[], unsupported: Unsupported[]): void {
  for (const [role, def] of Object.entries(bundle.rbac.roles)) {
    for (const g of def.grants) {
      if (g.actions.length === 0) continue;
      const id = `RBAC.${role}`;
      if (bad.has(g.resourceType)) { unsupported.push({ rule: id, reason: `grant on ${g.resourceType}: not a Cedar identifier. Cedar allows less.` }); continue; }
      const resource = g.resourceType === '*' ? 'resource' : `resource is ${ns(g.resourceType)}`;
      out.push(emit('permit', id, undefined, `principal in ${ns('Role')}::${str(role)}, ${actionScope(g.actions.includes('*') ? undefined : g.actions)}, ${resource}`, 'true'));
    }
  }
}

function modelGaps(bundle: PolicyBundle, bad: ReadonlySet<string>): Unsupported[] {
  const out: Unsupported[] = [...NOT_MAPPED];
  for (const t of bad) out.push({ rule: `schema.${t}`, reason: `resource type ${t} is not a Cedar identifier: its grants and scoped rules are not exported, and toCedarRequest refuses its resources` });
  const nk = bundle.needToKnow;
  if (nk.mode === 'enforce') {
    for (const [t, p] of Object.entries(nk.protect)) {
      out.push({ rule: `NTK.${t}`, reason: `need-to-know denies ${t} without a live ${p.relation} relation: Zanzibar tuples with validity windows, break-glass caps and notices, depth-bounded manager chains and a 32-hop bound. A Cedar \`in\` hierarchy would need the PEP to materialise that graph per request; not exported. Cedar allows more.` });
    }
  }
  for (const [t, def] of Object.entries(bundle.schema.resourceTypes)) {
    if (def.constrained || Object.values(def.actions).some((a) => a.certified)) {
      out.push({ rule: `CW.${t}`, reason: 'Clark-Wilson: certified commands, single-use decision tokens bound to the resource version, integrity verification procedures, certification records, input validators and PEP binding need state and obligations Cedar does not have. Cedar allows more.' });
    }
    for (const [a, ad] of Object.entries(def.actions)) {
      if (ad.requiresSecondPerson) out.push({ rule: `SOD.SELF_APPROVAL.${t}.${a}`, reason: 'two-person rule: the maker comes from performed-action history. Cedar allows more.' });
    }
  }
  for (const r of bundle.sod) out.push({ rule: `SOD.${r.id}`, reason: 'separation of duty reads the actions this subject already performed on the resource (history). Cedar allows more.' });
  return out;
}

function contextRequirement(rule: ContextRule, key: string): string {
  if (key === 'network') return 'context.network == "trusted"';
  if (key === 'countries') return conj(['context has country', `[${(rule.countries ?? []).map((country) => str(country)).join(', ')}].contains(context.country)`]);
  if (key === 'ipRanges') return conj(['context has ip', disj((rule.ipRanges ?? []).map((range) => `context.ip.isInRange(ip(${str(range)}))`))]);
  if (key === 'authMethodsAny') return conj(['context has authMethods', disj((rule.authMethodsAny ?? []).map((method) => `context.authMethods.contains(${str(method)})`))]);
  if (key === 'maxRiskScore') return conj(['context has riskScore', `context.riskScore <= ${rule.maxRiskScore ?? 0}`]);
  if (key === 'device.managed') return conj(['context has device', 'context.device has managed', `context.device.managed == ${String(rule.device?.managed)}`]);
  return conj(['context has device', 'context.device has compliant', `context.device.compliant == ${String(rule.device?.compliant)}`]);
}

/** Cedar has no Qadamar action-kind attribute, IANA local-time windows or instant arithmetic: those stay in Qadamar. */
function contextPolicy(rule: ContextRule, bad: ReadonlySet<string>): string {
  const unsupported = [rule.actionKinds ? 'actionKinds' : undefined, rule.timeWindows ? 'timeWindows' : undefined,
    rule.mfaMaxAgeSeconds !== undefined ? 'mfaMaxAgeSeconds' : undefined, rule.authMaxAgeSeconds !== undefined ? 'authMaxAgeSeconds' : undefined].filter(Boolean);
  if (unsupported.length) throw new Skip(`${unsupported.join(', ')} have no faithful Cedar expression; decide this CBAC rule in Qadamar`);
  const selector = [typeScope(rule.resourceTypes, bad)];
  if (rule.minResourceLevel !== undefined) selector.push(`resource.level >= ${rule.minResourceLevel}`);
  if (rule.contentClasses) selector.push(disj(rule.contentClasses.map((name) => `resource.contentClasses.contains(${str(name)})`)));
  const requirements = [rule.network === undefined ? undefined : 'network', rule.countries === undefined ? undefined : 'countries',
    rule.ipRanges === undefined ? undefined : 'ipRanges', rule.device?.managed === undefined ? undefined : 'device.managed',
    rule.device?.compliant === undefined ? undefined : 'device.compliant', rule.authMethodsAny === undefined ? undefined : 'authMethodsAny',
    rule.maxRiskScore === undefined ? undefined : 'maxRiskScore'].filter((key): key is string => key !== undefined);
  return emit('forbid', `CBAC.${rule.id}`, rule.description, `principal, ${actionScope(rule.actions)}, resource`, conj(selector), conj(requirements.map((key) => contextRequirement(rule, key))));
}

/** The Cedar form of the bundle's tenant rules, and what it cannot carry (docs/spec/POLICY-LANGUAGE.md, appendix A). */
export function toCedar(bundle: PolicyBundle): CedarExport {
  const { types, badTypes } = analyze(bundle);
  const unsupported = modelGaps(bundle, badTypes);
  const policies: string[] = [emit('forbid', 'CORE.INACTIVE', 'An inactive subject is denied', 'principal, action, resource', 'true', 'principal.active')];
  rbacPolicies(bundle, badTypes, policies, unsupported);
  const rule = (id: string, gap: string, fn: () => string): void => {
    try { policies.push(fn()); } catch (err) {
      if (!(err instanceof Skip)) throw err;
      unsupported.push({ rule: id, reason: `${err.message}. ${gap}` });
    }
  };
  for (const r of bundle.abac) {
    const id = `ABAC.${r.id}`;
    if (r.effect === 'obligation') { unsupported.push({ rule: id, reason: 'obligations (field allowlists, redaction, masking, notices) are not part of a Cedar decision; the decision is unaffected' }); continue; }
    rule(id, r.effect === 'permit' ? 'Cedar allows less.' : 'Cedar allows more.', () => {
      const c = condition(r.when, types);
      const scope = typeScope(r.resourceTypes, badTypes);
      // a forbid fires on TRUE or UNKNOWN: unless the condition is certainly FALSE
      const scoped = `principal, ${actionScope(r.actions)}, resource`;
      return r.effect === 'permit' ? emit('permit', id, r.description, scoped, conj([scope, c.t])) : emit('forbid', id, r.description, scoped, scope, c.f);
    });
  }
  // rule ids are unique across the bundle, so content rules share the ABAC prefix without colliding
  for (const r of contentRules(bundle)) {
    const id = `ABAC.${r.id}`;
    if (r.effect !== 'deny') { unsupported.push({ rule: id, reason: `${r.effect} is an obligation on the released content; the decision is unaffected` }); continue; }
    rule(id, 'Cedar allows more.', () => {
      const exempt = r.unless ? condition(r.unless, types).t : 'false';
      return emit('forbid', id, r.description, `principal, ${actionScope(r.actions)}, resource`, `resource.contentClasses.contains(${str(r.contentClass)})`, exempt);
    });
  }
  for (const r of bundle.context ?? []) rule(`CBAC.${r.id}`, 'Cedar allows more; keep the complete CBAC stage in Qadamar.', () => contextPolicy(r, badTypes));
  return { schema: cedarSchema(bundle, types, badTypes), policies: `${policies.join('\n\n')}\n`, unsupported };
}

// ---------- schema ----------

function typeJson(types: Types, key: string): Json | null {
  const t = types.of(parsePath(key));
  if (t === undefined || t === 'conflict') return null;
  if (t === 'Record') return { type: 'Record', attributes: optional(types, key) };
  const e = elem(t);
  return t === 'IpAddr' ? { type: 'Extension', name: 'ipaddr' } : e ? { type: 'Set', element: { type: e } } : { type: t };
}

/** Every attribute declared under a prefix, optional (a missing attribute is UNKNOWN, guarded by `has`). */
function optional(types: Types, prefix: string): Record<string, Json> {
  return Object.fromEntries(types.children(prefix).flatMap((k) => {
    const j = typeJson(types, `${prefix}.${k}`);
    return j === null ? [] : [[k, { ...(j as object), required: false }]];
  }));
}

function shape(root: Root, types: Types): Json {
  const attributes: Record<string, Json> = {};
  for (const [k, t] of Object.entries(BUILTIN)) {
    if (!k.startsWith(`${root}.`)) continue;
    const e = elem(t);
    attributes[k.slice(root.length + 1)] = { ...(t === 'IpAddr' ? { type: 'Extension', name: 'ipaddr' } : e ? { type: 'Set', element: { type: e } } : { type: t }), ...(OPTIONAL.has(k) ? { required: false } : {}) };
  }
  if (root === 'context') attributes.device = { type: 'Record', required: false, attributes: {
    managed: { type: 'Boolean', required: false }, compliant: { type: 'Boolean', required: false },
  } };
  attributes.attrs = { type: 'Record', attributes: optional(types, `${root}.attrs`) };
  return { type: 'Record', attributes };
}

function cedarSchema(bundle: PolicyBundle, types: Types, bad: ReadonlySet<string>): Json {
  const entityTypes: Record<string, Json> = {
    Role: { memberOfTypes: ['Role'] },
    Subject: { memberOfTypes: ['Role'], shape: shape('subject', types) },
  };
  const actions: Record<string, string[]> = {};
  for (const [t, def] of Object.entries(bundle.schema.resourceTypes)) {
    if (bad.has(t)) continue;
    entityTypes[t] = { shape: shape('resource', types) };
    for (const a of Object.keys(def.actions)) actions[a] = [...(actions[a] ?? []), t];
  }
  const context = shape('context', types);
  return {
    [CEDAR_NAMESPACE]: {
      entityTypes,
      actions: Object.fromEntries(Object.entries(actions).map(([a, ts]) => [a, { appliesTo: { principalTypes: ['Subject'], resourceTypes: ts, context } }])),
    },
  };
}

// ---------- requests ----------

function conform(v: unknown, t: CType, where: string): Json {
  const fail = (): never => { throw new CedarMappingError(`${where} is not a ${t} (the exported schema): decide this request with Qadamar`); };
  const e = elem(t);
  if (e) return Array.isArray(v) ? v.map((x, i) => conform(x, e, `${where}[${i}]`)) : fail();
  if (t === 'Long') return Number.isSafeInteger(v) ? v as number : fail();
  if (t === 'Boolean') return typeof v === 'boolean' ? v : fail();
  // the Cedar JSON entity format's extension value: { "__extn": { "fn": "ip", "arg": "<literal>" } }
  if (t === 'IpAddr') return typeof v === 'string' && !surrogate(v) ? { __extn: { fn: 'ip', arg: v } } : fail();
  return typeof v === 'string' && !surrogate(v) ? v : fail();
}

/** Only the attributes the schema declares, in its types; null and absent values are left out (Qadamar reads both as missing). */
function pickAttrs(types: Types, prefix: string, v: unknown): Record<string, Json> {
  if (v === undefined || v === null) return {};
  if (!isObj(v)) throw new CedarMappingError(`${prefix} is not an object: decide this request with Qadamar`);
  return Object.fromEntries(types.children(prefix).flatMap((k) => {
    const x = Object.hasOwn(v, k) ? v[k] : undefined;
    const key = `${prefix}.${k}`;
    const t = types.of(parsePath(key));
    if (x === undefined || x === null || t === undefined || t === 'conflict') return [];
    return [[k, t === 'Record' ? pickAttrs(types, key, x) : conform(x, t, key)]];
  }));
}

function attrsOf(root: Root, value: object, types: Types): Record<string, Json> {
  const v = value as Record<string, unknown>;
  const out: Record<string, Json> = {};
  for (const [k, t] of Object.entries(BUILTIN)) {
    if (!k.startsWith(`${root}.`)) continue;
    const name = k.slice(root.length + 1);
    if ((v[name] === undefined || v[name] === null) && OPTIONAL.has(k)) continue;
    out[name] = conform(v[name], t, k);
  }
  if (root === 'context' && v.device !== undefined && v.device !== null) {
    const device = isObj(v.device) ? v.device : (() => { throw new CedarMappingError('context.device is not an object: decide this request with Qadamar'); })();
    out.device = Object.fromEntries(['managed', 'compliant'].flatMap((key) => device[key] === undefined ? [] : [[key, conform(device[key], 'Boolean', `context.device.${key}`)]]));
  }
  out.attrs = pickAttrs(types, `${root}.attrs`, v.attrs);
  return out;
}

const wellFormed = (s: string, where: string): string => {
  if (surrogate(s)) throw new CedarMappingError(`${where} has an unpaired surrogate: decide this request with Qadamar`);
  return s;
};

/** The Cedar request and entities for a Qadamar request, against toCedar(bundle). Throws CedarMappingError when the request
 *  has no faithful Cedar form; the PEP then decides it with Qadamar (a Cedar engine would refuse it against the schema). */
export function toCedarRequest(bundle: PolicyBundle, req: Request): CedarRequest {
  const errors = requestErrors(req);
  if (errors.length > 0) throw new CedarMappingError(`malformed request (Qadamar denies it): ${errors.join('; ')}`);
  if (req.subject.delegator) throw new CedarMappingError('a delegation chain has no Cedar form: decide this request with Qadamar');
  if (req.context.sessionExpired === true) throw new CedarMappingError('an expired session has no Cedar form (Qadamar denies it: CBAC.SESSION_EXPIRED)');
  const { types, badTypes } = analyze(bundle);
  if (!actionDef(bundle, req.resource.type, req.action)) throw new CedarMappingError(`${req.action} is not an action of ${req.resource.type} (Qadamar denies it)`);
  if (badTypes.has(req.resource.type)) throw new CedarMappingError(`resource type ${req.resource.type} is not a Cedar identifier`);
  const role = (r: string): CedarUid => ({ type: ns('Role'), id: wellFormed(r, 'role') });
  const principal = { type: ns('Subject'), id: wellFormed(JSON.stringify([req.subject.type, req.subject.id]), 'subject id') };
  const resource = { type: ns(req.resource.type), id: wellFormed(req.resource.id, 'resource.id') };
  return {
    principal,
    action: { type: ns('Action'), id: wellFormed(req.action, 'action') },
    resource,
    context: attrsOf('context', req.context, types),
    entities: [
      { uid: principal, attrs: attrsOf('subject', withLiveRoles(req.subject, req.context.now), types), parents: liveRoles(req.subject, req.context.now).map(role) },
      { uid: resource, attrs: attrsOf('resource', req.resource, types), parents: [] },
      ...Object.entries(bundle.rbac.roles).map(([r, d]) => ({ uid: role(r), attrs: {}, parents: (d.inherits ?? []).map(role) })),
    ],
  };
}
