import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  CedarMappingError, evaluate, indexTuples, toCedar, toCedarRequest, validateBundle,
  type AbacRule, type AbacContentRule, type CedarRequest, type Context, type Expr, type Json, type Operand, type PolicyBundle,
  type Request, type Resource, type Subject, type Tuple,
} from '../src/index.ts';

// =====================================================================================================================
// TEST ORACLE, not product code and not Cedar: a reference evaluator for the subset of Cedar that toCedar() emits
// (policy scopes with `in` / `is`, when / unless, && || !, == != < <= > >=, has, like, is, ., [""], contains,
// containsAll, isEmpty, set literals), following the Cedar semantics: a policy whose condition errors (a missing
// attribute, a type error) is not satisfied; any satisfied forbid denies; otherwise a satisfied permit allows.
// It counts errors, so the test can also check the claim that the exported conditions never error. The real Cedar
// engine is not available here (no download): this is the stated limitation of the differential test.
// =====================================================================================================================
class CSet { readonly items: readonly V[]; constructor(items: readonly V[]) { this.items = items; } }
class Rec { readonly fields: ReadonlyMap<string, V>; constructor(fields: ReadonlyMap<string, V>) { this.fields = fields; } }
class Ent { readonly type: string; readonly id: string; constructor(type: string, id: string) { this.type = type; this.id = id; } }
type V = boolean | number | string | CSet | Rec | Ent;
class CedarError extends Error {}
const STAR = Symbol('star');
type Pattern = (string | typeof STAR)[];
type Node =
  | { k: 'lit'; v: V } | { k: 'var'; v: string } | { k: 'set'; items: Node[] }
  | { k: '&&' | '||'; l: Node; r: Node } | { k: '!' | 'neg'; e: Node } | { k: 'cmp'; op: string; l: Node; r: Node }
  | { k: 'has' | 'get'; e: Node; attr: string } | { k: 'like'; e: Node; pat: Pattern } | { k: 'is'; e: Node; type: string }
  | { k: 'call'; e: Node; m: string; args: Node[] };
interface Policy { effect: string; principalIn?: Ent; actions?: Ent[]; resourceIs?: string; when: Node[]; unless: Node[] }
type Tok = { k: 'str'; raw: string } | { k: 'int'; v: number } | { k: 'id'; v: string } | { k: 'op'; v: string };

function tokens(src: string): Tok[] {
  const re = /\s+|\/\/[^\n]*|("(?:[^"\\]|\\.)*")|(\d+)|([A-Za-z_][A-Za-z0-9_]*)|(::|==|!=|<=|>=|&&|\|\||[()[\]{},;.<>!@-])/y;
  const out: Tok[] = [];
  while (re.lastIndex < src.length) {
    const at = re.lastIndex;
    const m = re.exec(src);
    if (!m) throw new Error(`oracle: cannot tokenize at ${src.slice(at, at + 20)}`);
    if (m[1]) out.push({ k: 'str', raw: m[1].slice(1, -1) });
    else if (m[2]) out.push({ k: 'int', v: Number(m[2]) });
    else if (m[3]) out.push({ k: 'id', v: m[3] });
    else if (m[4]) out.push({ k: 'op', v: m[4] });
  }
  return out;
}

function unescape(raw: string, pattern: boolean): Pattern {
  const out: Pattern = [];
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i] as string;
    if (c !== '\\') { out.push(pattern && c === '*' ? STAR : c); continue; }
    const n = raw[++i];
    if (n === 'u') {
      const m = /^\{([0-9a-fA-F]{1,6})\}/.exec(raw.slice(i + 1));
      if (!m) throw new Error('oracle: bad \\u escape');
      out.push(String.fromCodePoint(parseInt(m[1] as string, 16)));
      i += m[0].length;
    } else if (n === '*' && pattern) out.push('*');
    else if (n === '"' || n === '\\' || n === "'") out.push(n);
    else if (n === 'n' || n === 'r' || n === 't' || n === '0') out.push({ n: '\n', r: '\r', t: '\t', 0: '\0' }[n]);
    else throw new Error(`oracle: escape \\${n} is not valid here`);
  }
  return out;
}
const text = (raw: string): string => unescape(raw, false).join('');

function parse(src: string): Policy[] {
  const t = tokens(src);
  let i = 0;
  const peek = (v: string): boolean => { const x = t[i]; return x !== undefined && (x.k === 'op' || x.k === 'id') && x.v === v; };
  const eat = (v: string): void => { if (!peek(v)) throw new Error(`oracle: expected ${v} at token ${i}`); i++; };
  const str = (): string => { const x = t[i++]; if (x?.k !== 'str') throw new Error('oracle: expected a string'); return x.raw; };
  const ident = (): string => { const x = t[i++]; if (x?.k !== 'id') throw new Error('oracle: expected an identifier'); return x.v; };
  const path = (first: string): { name: string; id?: string } => {
    const parts = [first];
    while (peek('::')) { i++; if (t[i]?.k === 'str') return { name: parts.join('::'), id: text(str()) }; parts.push(ident()); }
    return { name: parts.join('::') };
  };
  const entity = (): Ent => { const p = path(ident()); if (p.id === undefined) throw new Error('oracle: expected an entity'); return new Ent(p.name, p.id); };
  const list = (close: string): Node[] => {
    const xs: Node[] = [];
    while (!peek(close)) { xs.push(expr()); if (!peek(close)) eat(','); }
    eat(close);
    return xs;
  };
  function primary(): Node {
    const x = t[i++];
    if (!x) throw new Error('oracle: unexpected end');
    if (x.k === 'int') return { k: 'lit', v: x.v };
    if (x.k === 'str') return { k: 'lit', v: text(x.raw) };
    if (x.k === 'op' && x.v === '[') return { k: 'set', items: list(']') };
    if (x.k === 'op' && x.v === '(') { const e = expr(); eat(')'); return e; }
    if (x.k === 'id' && (x.v === 'true' || x.v === 'false')) return { k: 'lit', v: x.v === 'true' };
    if (x.k === 'id' && ['principal', 'action', 'resource', 'context'].includes(x.v) && !peek('::')) return { k: 'var', v: x.v };
    if (x.k === 'id') { const p = path(x.v); if (p.id === undefined) throw new Error('oracle: bare name'); return { k: 'lit', v: new Ent(p.name, p.id) }; }
    throw new Error(`oracle: unexpected ${x.v}`);
  }
  function member(): Node {
    let e = primary();
    for (;;) {
      if (peek('.')) {
        i++;
        const name = ident();
        if (peek('(')) { i++; e = { k: 'call', e, m: name, args: list(')') }; } else e = { k: 'get', e, attr: name };
      } else if (peek('[')) { i++; const s = text(str()); eat(']'); e = { k: 'get', e, attr: s }; } else return e;
    }
  }
  function unary(): Node {
    if (peek('!')) { i++; return { k: '!', e: unary() }; }
    if (peek('-')) { i++; return { k: 'neg', e: unary() }; }
    return member();
  }
  function rel(): Node {
    const l = unary();
    for (const op of ['==', '!=', '<=', '>=', '<', '>']) if (peek(op)) { i++; return { k: 'cmp', op, l, r: unary() }; }
    if (peek('has')) { i++; return { k: 'has', e: l, attr: t[i]?.k === 'str' ? text(str()) : ident() }; }
    if (peek('like')) { i++; return { k: 'like', e: l, pat: unescape(str(), true) }; }
    if (peek('is')) { i++; return { k: 'is', e: l, type: path(ident()).name }; }
    return l;
  }
  function chain(next: () => Node, op: '&&' | '||'): Node {
    let l = next();
    while (peek(op)) { i++; l = { k: op, l, r: next() }; }
    return l;
  }
  const and = (): Node => chain(rel, '&&');
  function expr(): Node { return chain(and, '||'); }

  const out: Policy[] = [];
  while (i < t.length) {
    while (peek('@')) { i++; ident(); eat('('); str(); eat(')'); }
    const effect = ident();
    assert.ok(effect === 'permit' || effect === 'forbid', `oracle: effect ${effect}`);
    const p: Policy = { effect, when: [], unless: [] };
    eat('('); eat('principal');
    if (peek('in')) { i++; p.principalIn = entity(); }
    eat(','); eat('action');
    if (peek('in')) { i++; eat('['); p.actions = []; while (!peek(']')) { p.actions.push(entity()); if (!peek(']')) eat(','); } eat(']'); }
    eat(','); eat('resource');
    if (peek('is')) { i++; p.resourceIs = path(ident()).name; }
    eat(')');
    while (peek('when') || peek('unless')) {
      const which = ident() as 'when' | 'unless';
      eat('{'); p[which].push(expr()); eat('}');
    }
    eat(';');
    out.push(p);
  }
  return out;
}

const fromJson = (v: Json): V => {
  if (Array.isArray(v)) return new CSet(v.map(fromJson));
  if (v !== null && typeof v === 'object') return new Rec(new Map(Object.entries(v).map(([k, x]) => [k, fromJson(x)])));
  if (v === null) throw new Error('oracle: null is not a Cedar value');
  return v;
};
function same(a: V, b: V): boolean {
  if (a instanceof CSet && b instanceof CSet) return a.items.every((x) => b.items.some((y) => same(x, y))) && b.items.every((y) => a.items.some((x) => same(x, y)));
  if (a instanceof Rec && b instanceof Rec) return a.fields.size === b.fields.size && [...a.fields].every(([k, x]) => b.fields.has(k) && same(x, b.fields.get(k) as V));
  if (a instanceof Ent && b instanceof Ent) return a.type === b.type && a.id === b.id;
  return a === b;
}
const likeMatch = (s: string, pat: Pattern): boolean =>
  new RegExp(`^${pat.map((p) => (p === STAR ? '.*' : p.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&'))).join('')}$`, 'su').test(s);

const oracleErrors = { count: 0 };

function authorize(policies: readonly Policy[], req: CedarRequest): boolean {
  const key = (e: { type: string; id: string }): string => JSON.stringify([e.type, e.id]);
  const store = new Map(req.entities.map((e) => [key(e.uid), e]));
  const ancestors = (uid: { type: string; id: string }): Set<string> => {
    const seen = new Set<string>();
    const stack = [...(store.get(key(uid))?.parents ?? [])];
    while (stack.length) {
      const p = stack.pop() as { type: string; id: string };
      if (seen.has(key(p))) continue;
      seen.add(key(p));
      stack.push(...(store.get(key(p))?.parents ?? []));
    }
    return seen;
  };
  const vars: Record<string, V> = {
    principal: new Ent(req.principal.type, req.principal.id), action: new Ent(req.action.type, req.action.id),
    resource: new Ent(req.resource.type, req.resource.id), context: fromJson(req.context),
  };
  const fields = (x: V): ReadonlyMap<string, V> => {
    if (x instanceof Rec) return x.fields;
    if (x instanceof Ent) { const e = store.get(key(x)); return e ? (fromJson(e.attrs) as Rec).fields : new Map(); }
    throw new CedarError('has / attribute access on a non-record');
  };
  const bool = (x: V): boolean => { if (typeof x !== 'boolean') throw new CedarError('not a boolean'); return x; };
  const set = (x: V): CSet => { if (!(x instanceof CSet)) throw new CedarError('not a set'); return x; };
  function ev(n: Node): V {
    switch (n.k) {
      case 'lit': return n.v;
      case 'var': return vars[n.v] as V;
      case 'set': return new CSet(n.items.map(ev));
      case '&&': return bool(ev(n.l)) ? bool(ev(n.r)) : false;
      case '||': return bool(ev(n.l)) ? true : bool(ev(n.r));
      case '!': return !bool(ev(n.e));
      case 'neg': { const x = ev(n.e); if (typeof x !== 'number') throw new CedarError('negation of a non-Long'); return -x; }
      case 'cmp': {
        const l = ev(n.l), r = ev(n.r);
        if (n.op === '==') return same(l, r);
        if (n.op === '!=') return !same(l, r);
        if (typeof l !== 'number' || typeof r !== 'number') throw new CedarError('ordering a non-Long');
        return n.op === '<' ? l < r : n.op === '<=' ? l <= r : n.op === '>' ? l > r : l >= r;
      }
      case 'has': return fields(ev(n.e)).has(n.attr);
      case 'get': { const f = fields(ev(n.e)); if (!f.has(n.attr)) throw new CedarError(`missing attribute ${n.attr}`); return f.get(n.attr) as V; }
      case 'like': { const x = ev(n.e); if (typeof x !== 'string') throw new CedarError('like on a non-string'); return likeMatch(x, n.pat); }
      case 'is': { const x = ev(n.e); if (!(x instanceof Ent)) throw new CedarError('is on a non-entity'); return x.type === n.type; }
      case 'call': {
        const recv = set(ev(n.e));
        if (n.m === 'isEmpty') return recv.items.length === 0;
        const arg = ev(n.args[0] as Node);
        if (n.m === 'contains') return recv.items.some((x) => same(x, arg));
        if (n.m === 'containsAll') return set(arg).items.every((x) => recv.items.some((y) => same(x, y)));
        throw new CedarError(`unknown method ${n.m}`);
      }
    }
  }
  const principalAncestors = ancestors(req.principal);
  let permitted = false;
  for (const p of policies) {
    if (p.principalIn && !(same(vars.principal as V, p.principalIn) || principalAncestors.has(key(p.principalIn)))) continue;
    if (p.actions && !p.actions.some((a) => same(vars.action as V, a))) continue;
    if (p.resourceIs && req.resource.type !== p.resourceIs) continue;
    let satisfied: boolean;
    try {
      satisfied = p.when.every((w) => bool(ev(w))) && p.unless.every((u) => !bool(ev(u)));
    } catch (err) {
      if (!(err instanceof CedarError)) throw err;
      oracleErrors.count++;
      satisfied = false; // an erroring policy is skipped
    }
    if (satisfied && p.effect === 'forbid') return false;
    if (satisfied) permitted = true;
  }
  return permitted;
}
// ================================================ end of the test oracle ===========================================

const FIXED_GAPS = ['mandatory', 'delegation', 'SOD.MAKER_MISMATCH'];
const load = (dir: string, f: string) => JSON.parse(readFileSync(new URL(`../../../examples/${dir}/${f}`, import.meta.url), 'utf8'));

test('cedar: the oracle reads Cedar it was not written for (sanity of the oracle itself)', () => {
  const src = '@id("x")\npermit (principal in A::Role::"r", action in [A::Action::"read"], resource is A::doc)\nwhen { [1, -2].contains(-2) && "a*b\\u{1f600}" like "a\\**" && !(context.k has "z") && context.k["q"] == "\\"" }\nunless { 1 > 2 || resource.x };';
  const req: CedarRequest = {
    principal: { type: 'A::Subject', id: 's' }, action: { type: 'A::Action', id: 'read' }, resource: { type: 'A::doc', id: 'd' },
    context: { k: { q: '"' } }, entities: [{ uid: { type: 'A::Subject', id: 's' }, attrs: {}, parents: [{ type: 'A::Role', id: 'r' }] }],
  };
  const before = oracleErrors.count;
  assert.equal(authorize(parse(src), req), false); // `resource.x` errors in unless: the policy is skipped
  assert.equal(oracleErrors.count, before + 1);
  assert.equal(authorize(parse(src.replace(' || resource.x', '')), req), true);
  oracleErrors.count = before;
});

test('cedar: the authzen-todo bundle exports whole and decides every request of its world as Qadamar does', () => {
  const bundle: PolicyBundle = load('authzen-todo', 'bundle.json');
  const world: { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] } = load('authzen-todo', 'world.json');
  const out = toCedar(bundle);
  assert.deepEqual(out.unsupported.map((u) => u.rule), FIXED_GAPS);
  const policies = parse(out.policies);
  const graph = indexTuples(world.tuples);
  let compared = 0, allowed = 0;
  for (const subject of world.subjects) for (const resource of world.resources) {
    for (const action of Object.keys(bundle.schema.resourceTypes[resource.type]?.actions ?? {})) {
      const req: Request = { subject, action, resource, context: { network: 'trusted', now: world.now } };
      const gate = evaluate(bundle, req, graph).decision;
      assert.equal(authorize(policies, toCedarRequest(bundle, req)), gate, `${subject.id} ${action} ${resource.type}:${resource.id}`);
      compared++; if (gate) allowed++;
    }
  }
  assert.ok(compared > 100 && allowed > 10 && allowed < compared, `${compared} compared, ${allowed} allowed`);
  assert.equal(oracleErrors.count, 0);
});

test('cedar: toy-domain lists every model it cannot carry, and Cedar never allows less than Qadamar there', () => {
  const bundle: PolicyBundle = load('toy-domain', 'bundle.json');
  const world: { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] } = load('toy-domain', 'world.json');
  const out = toCedar(bundle);
  assert.deepEqual(out.unsupported.map((u) => u.rule).sort(), [...FIXED_GAPS, 'NTK.case', 'CW.case', 'CW.payment', 'SOD.SELF_APPROVAL.payment.approve',
    'SOD.create-vs-approve', 'SOD.create-vs-release', 'ABAC.informant-redaction', 'ABAC.finance-mask'].sort());
  for (const id of ['ABAC.owner-read', 'ABAC.no-export-untrusted', 'ABAC.closed-is-read-only', 'ABAC.no-iban-export', 'RBAC.case_lead']) assert.ok(out.policies.includes(`@id("${id}")`), id);
  assert.match(out.policies, /unless \{ resource\.attrs has "status" && resource\.attrs\["status"\] != "closed" \}/);
  const policies = parse(out.policies);
  const graph = indexTuples(world.tuples);
  let checked = 0;
  for (const subject of world.subjects) for (const resource of world.resources) for (const network of ['trusted', 'untrusted'] as const) {
    for (const action of Object.keys(bundle.schema.resourceTypes[resource.type]?.actions ?? {})) {
      const req: Request = { subject, action, resource, context: { network, now: world.now } };
      let cedarReq: CedarRequest;
      try { cedarReq = toCedarRequest(bundle, req); } catch (err) { assert.ok(err instanceof CedarMappingError); continue; }
      const gate = evaluate(bundle, req, graph);
      const cedar = authorize(policies, cedarReq);
      if (gate.decision) assert.equal(cedar, true, `${subject.id} ${action} ${resource.id}`);
      // a deny made only of exported rules is a Cedar deny too
      else if (gate.rules.every((r) => /^(ABAC|CBAC|RBAC|CORE)\./.test(r))) assert.equal(cedar, false, `${subject.id} ${action} ${resource.id}: ${gate.rules.join()}`);
      checked++;
    }
  }
  assert.ok(checked > 100, `${checked}`);
  assert.equal(oracleErrors.count, 0);
});

test('cedar: rules Cedar cannot express faithfully are listed with the reason, and the rest still exports', () => {
  const base: PolicyBundle = load('authzen-todo', 'bundle.json');
  const rule = (id: string, effect: AbacRule['effect'], when: Expr): AbacRule => ({ id, description: id, effect, resourceTypes: ['todo'], when });
  const cmp = (op: string, left: Operand, right: Operand): Expr => ({ op, left, right }) as Expr;
  const bundle: PolicyBundle = {
    ...base,
    schema: { ...base.schema, resourceTypes: { ...base.schema.resourceTypes, 'my-type': { actions: { can_read_todos: { kind: 'read' } } } } },
    abac: [...base.abac,
      rule('string-order', 'forbid', cmp('lt', { path: 'resource.owner' }, { value: 'm' })),
      rule('float', 'permit', cmp('ge', { path: 'resource.attrs.score' }, { value: 0.5 })),
      rule('action-attr', 'permit', cmp('eq', { path: 'action.kind' }, { value: 'read' })),
      rule('object-literal', 'permit', cmp('eq', { path: 'resource.attrs.meta' }, { value: { a: 1 } })),
      rule('ordered-list', 'forbid', cmp('eq', { path: 'subject.roles' }, { value: ['admin'] })),
      rule('typed-int', 'permit', cmp('eq', { path: 'resource.attrs.x' }, { value: 1 })),
      rule('typed-str', 'permit', cmp('eq', { path: 'resource.attrs.x' }, { value: 'a' })),
      rule('has-only', 'forbid', { op: 'has', path: 'subject.attrs.flagged' }),
      rule('delegator', 'forbid', cmp('eq', { path: 'subject.delegator.id' }, { value: 'x' })),
      rule('needle-path', 'permit', cmp('contains', { path: 'resource.owner' }, { path: 'subject.id' })),
      rule('always-unknown', 'forbid', cmp('in', { value: 'a' }, { path: 'resource.owner' })),
      { id: 'other-type', description: 'scoped to a non-identifier type', effect: 'permit', resourceTypes: ['my-type'], when: { op: 'true' } },
    ],
    rbac: { roles: { ...base.rbac.roles, odd: { grants: [{ resourceType: 'my-type', actions: ['can_read_todos'] }] } } },
  };
  assert.ok(validateBundle(bundle).ok);
  const out = toCedar(bundle);
  const reason = (id: string): string => out.unsupported.find((u) => u.rule === id)?.reason ?? '';
  assert.match(reason('ABAC.string-order'), /no string ordering.*Cedar allows more/);
  assert.match(reason('ABAC.float'), /64-bit integers.*Cedar allows less/);
  assert.match(reason('ABAC.action-attr'), /actions carry no attributes/);
  assert.match(reason('ABAC.object-literal'), /object literals/);
  assert.match(reason('ABAC.ordered-list'), /in order/);
  assert.match(reason('ABAC.typed-int'), /different types/);
  assert.match(reason('ABAC.typed-str'), /different types/);
  assert.match(reason('ABAC.has-only'), /schema cannot declare/);
  assert.match(reason('ABAC.delegator'), /only the request fields/);
  assert.match(reason('ABAC.needle-path'), /literal needle/);
  assert.match(reason('ABAC.always-unknown'), /always UNKNOWN/);
  assert.match(reason('ABAC.other-type'), /not a Cedar identifier/);
  assert.match(reason('RBAC.odd'), /not a Cedar identifier/);
  assert.match(reason('schema.my-type'), /refuses its resources/);
  assert.ok(out.policies.includes('@id("ABAC.owner-todo-write")'));
  assert.ok(!JSON.stringify(out.schema).includes('my-type'));
});

test('cedar: toCedarRequest refuses what has no faithful Cedar form', () => {
  const bundle: PolicyBundle = { ...load('authzen-todo', 'bundle.json') };
  const withRule: PolicyBundle = { ...bundle, abac: [...bundle.abac, { id: 'n', description: 'n', effect: 'forbid', when: { op: 'ge', left: { path: 'resource.attrs.n' }, right: { value: 3 } } }] };
  const subject: Subject = { type: 'user', id: 'u', active: true, roles: ['viewer'], clearance: 0, compartments: [], integrity: 'verified' };
  const resource: Resource = { type: 'todo', id: 't', level: 0, compartments: [], integrity: 'verified', contentClasses: [] };
  const req = (over: Partial<Request> = {}): Request => ({ subject, action: 'can_read_todos', resource, context: { network: 'trusted', now: '2026-11-11T00:00:00Z' }, ...over });
  const refuses = (b: PolicyBundle, r: Request, pattern: RegExp) => assert.throws(() => toCedarRequest(b, r), (e: unknown) => e instanceof CedarMappingError && pattern.test(e.message));
  refuses(bundle, req({ subject: { ...subject, type: 'agent', delegator: subject } }), /delegation/);
  refuses(bundle, req({ subject: { ...subject, clearance: 7 as 0 } }), /malformed/);
  refuses(bundle, req({ action: 'can_read_user' }), /not an action/);
  refuses(bundle, req({ resource: { ...resource, id: '\ud800' } }), /surrogate/);
  refuses(withRule, req({ resource: { ...resource, attrs: { n: '5' } } }), /resource\.attrs\.n is not a Long/);
  refuses(withRule, req({ resource: { ...resource, attrs: { n: 2.5 } } }), /not a Long/);
  refuses(withRule, req({ resource: { ...resource, attrs: [] as unknown as Record<string, Json> } }), /not an object/);
  // undeclared attributes are dropped, null is absent: Qadamar reads both as missing
  const mapped = toCedarRequest(withRule, req({ resource: { ...resource, attrs: { n: null, other: { deep: 1.5 } } } }));
  assert.deepEqual(mapped.entities[1]?.attrs.attrs, {});
});

test('cedar: context export translates guarded device, country, method, risk and IP requirements and lists the rest', () => {
  const base: PolicyBundle = load('authzen-todo', 'bundle.json');
  const bundle: PolicyBundle = { ...base, context: [
    { id: 'expressible', resourceTypes: ['todo'], actions: ['can_read_todos'], minResourceLevel: 0, contentClasses: ['pii'],
      network: 'trusted', countries: ['AE', 'US'], ipRanges: ['10.0.0.0/8', '2001:db8::/32'], device: { managed: true, compliant: true },
      authMethodsAny: ['webauthn', 'otp'], maxRiskScore: 50 },
    { id: 'local-time', actions: ['can_read_todos'], timeWindows: [{ days: [1], from: '09:00', to: '17:00', timeZone: 'Asia/Dubai' }] },
    { id: 'fresh-mfa', actions: ['can_read_todos'], mfaMaxAgeSeconds: 300 },
    { id: 'kind', actionKinds: ['read'], maxRiskScore: 10 },
  ] };
  const out = toCedar(bundle);
  assert.match(out.policies, /@id\("CBAC\.expressible"\)/);
  // isInRange takes an ipaddr, not a string: the range is an ip(...) extension value
  assert.match(out.policies, /context\.ip\.isInRange\(ip\("10\.0\.0\.0\/8"\)\)/);
  assert.match(out.policies, /context\.ip\.isInRange\(ip\("2001:db8::\/32"\)\)/);
  assert.ok(!/isInRange\("/.test(out.policies), 'no string argument to isInRange');
  assert.match(out.policies, /context has device && context\.device has managed/);
  assert.match(out.policies, /context has riskScore && context\.riskScore <= 50/);
  assert.ok(!out.policies.includes('@id("CBAC.local-time")'));
  for (const id of ['CBAC.local-time', 'CBAC.fresh-mfa', 'CBAC.kind']) {
    const gap = out.unsupported.find((item) => item.rule === id);
    assert.match(gap?.reason ?? '', /no faithful Cedar|Cedar allows more/);
  }
  assert.ok(JSON.stringify(out.schema).includes('"type":"Extension","name":"ipaddr"'));
  const subject: Subject = { type: 'user', id: 'u', active: true, roles: ['viewer'], clearance: 0, compartments: [], integrity: 'verified' };
  const resource: Resource = { type: 'todo', id: 't', level: 0, compartments: [], integrity: 'verified', contentClasses: ['pii'] };
  const mapped = toCedarRequest(bundle, { subject, action: 'can_read_todos', resource, context: {
    network: 'trusted', now: '2026-11-11T00:00:00Z', ip: '2001:db8::1', country: 'AE', device: { managed: true, compliant: false },
    authTime: '2026-11-10T23:00:00Z', mfaTime: '2026-11-10T23:30:00Z', authMethods: ['webauthn'], riskScore: 0,
  } });
  // the request's IP is the ipaddr extension value of the JSON entity format, matching the schema's Extension ipaddr
  assert.deepEqual(mapped.context.ip, { __extn: { fn: 'ip', arg: '2001:db8::1' } });
  assert.deepEqual(mapped.context.device, { managed: true, compliant: false });
  assert.deepEqual(mapped.context.authMethods, ['webauthn']);
});

// ---------- differential fuzz: random RBAC / ABAC / CBAC-deny bundles, Qadamar's evaluate against the oracle ----------

type Rng = () => number;
function prng(seed: number): Rng {
  let s = seed >>> 0;
  return () => { s = (s + 0x6d2b79f5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 0x100000000; };
}
const int = (rng: Rng, n: number): number => Math.floor(rng() * n);
const pick = <T>(rng: Rng, xs: readonly T[]): T => xs[int(rng, xs.length)] as T;
const chance = (rng: Rng, p: number): boolean => rng() < p;
const some = <T>(rng: Rng, xs: readonly T[], p = 0.5): T[] => xs.filter(() => chance(rng, p));

type T = 'Long' | 'String' | 'Boolean' | 'Set<String>' | 'Set<Long>';
const PATHS: Readonly<Record<T, readonly string[]>> = {
  Long: ['subject.clearance', 'resource.attrs.n', 'subject.attrs.rank', 'resource.version'],
  String: ['subject.id', 'resource.owner', 'resource.attrs.s', 'subject.attrs.dept', 'context.network', 'resource.attrs.addr.city', 'subject.type', 'context.attrs.zone'],
  Boolean: ['context.attrs.flag', 'subject.active', 'resource.attrs.ok'],
  'Set<String>': ['subject.roles', 'resource.attrs.tags', 'resource.contentClasses', 'subject.attrs.groups'],
  'Set<Long>': ['resource.attrs.nums'],
};
const VALUES = { Long: [-1, 0, 1, 2, 3, 7], String: ['a', 'b', 'u1', 'u2', 'x*y', '', 'trusted', 'untrusted', 'user', 'q"\\\n', 'r1'], Boolean: [true, false] } as const;
const ATTR_PATHS = Object.values(PATHS).flat().filter((p) => p.includes('.attrs.'));
const typeOfPath = (p: string): T => (Object.keys(PATHS) as T[]).find((t) => PATHS[t].includes(p)) as T;
const scalarOf = (t: T): 'Long' | 'String' | 'Boolean' => (t === 'Set<String>' ? 'String' : t === 'Set<Long>' ? 'Long' : t);
const lit = (rng: Rng, t: T): Json => (t.startsWith('Set') ? some(rng, VALUES[scalarOf(t)] as readonly Json[], 0.3) : pick(rng, VALUES[scalarOf(t)] as readonly Json[]));

function comparison(rng: Rng): Expr {
  const operand = (t: T, literalChance = 0.5): Operand => (chance(rng, 0.04) ? { value: null } : chance(rng, literalChance) ? { value: lit(rng, t) } : { path: pick(rng, PATHS[t]) });
  const swap = (op: string, a: Operand, b: Operand): Expr => (chance(rng, 0.5) ? { op, left: a, right: b } : { op, left: b, right: a }) as Expr;
  switch (pick(rng, ['eq', 'ne', 'ord', 'in', 'contains', 'subset'] as const)) {
    case 'eq': case 'ne': { const t = pick(rng, ['Long', 'String', 'Boolean'] as const); return swap(pick(rng, ['eq', 'ne']), { path: pick(rng, PATHS[t]) }, operand(t)); }
    case 'ord': return swap(pick(rng, ['lt', 'le', 'gt', 'ge']), { path: pick(rng, PATHS.Long) }, operand('Long'));
    case 'in': { const t = pick(rng, ['Long', 'String'] as const); return { op: 'in', left: operand(t), right: operand(t === 'Long' ? 'Set<Long>' : 'Set<String>') } as Expr; }
    case 'contains':
      if (chance(rng, 0.3)) return { op: 'contains', left: { path: pick(rng, PATHS.String) }, right: { value: pick(rng, VALUES.String) } } as Expr;
      { const t = pick(rng, ['Set<Long>', 'Set<String>'] as const); return { op: 'contains', left: operand(t, 0.2), right: operand(scalarOf(t)) } as Expr; }
    case 'subset': { const t = pick(rng, ['Set<Long>', 'Set<String>'] as const); return { op: 'subset', left: operand(t), right: operand(t) } as Expr; }
  }
}
function expr(rng: Rng, depth = 0): Expr {
  const r = rng();
  if (depth < 3 && r < 0.25) return { op: pick(rng, ['and', 'or'] as const), args: Array.from({ length: 1 + int(rng, 3) }, () => expr(rng, depth + 1)) };
  if (depth < 3 && r < 0.33) return { op: 'not', arg: expr(rng, depth + 1) };
  if (r < 0.36) return { op: 'true' };
  if (r < 0.45) return { op: 'has', path: pick(rng, Object.values(PATHS).flat()) };
  return comparison(rng);
}

const TYPES = { doc: { actions: { read: { kind: 'read' }, edit: { kind: 'write' }, purge: { kind: 'delete' } } }, folder: { actions: { read: { kind: 'read' }, edit: { kind: 'write' } } } } as const;
const ROLES = ['r0', 'r1', 'r2', 'r3'];

function randomBundle(rng: Rng): PolicyBundle {
  const roles = Object.fromEntries(ROLES.map((r, i) => [r, {
    ...(i > 0 && chance(rng, 0.5) ? { inherits: some(rng, ROLES.slice(0, i)) } : {}),
    grants: Array.from({ length: int(rng, 3) }, () => {
      const t = pick(rng, ['doc', 'folder', '*'] as const);
      return { resourceType: t, actions: chance(rng, 0.15) ? ['*'] : some(rng, t === '*' ? ['read'] : Object.keys(TYPES[t].actions)) };
    }),
  }]));
  // always FALSE: fixes the type of every attribute path, as a real bundle's other rules would
  const typing: AbacRule = { id: 'typing', description: 'types', effect: 'permit', when: { op: 'and', args: [{ op: 'not', arg: { op: 'true' } },
    ...ATTR_PATHS.map((p) => ({ op: typeOfPath(p).startsWith('Set') ? 'subset' : 'eq', left: { path: p }, right: { value: typeOfPath(p).startsWith('Set') ? [...VALUES[scalarOf(typeOfPath(p))]] : lit(rng, typeOfPath(p)) } }) as Expr)] } };
  const abac: AbacRule[] = [typing, ...Array.from({ length: 1 + int(rng, 5) }, (_, i): AbacRule => ({
    id: `a${i}`, description: `a${i}`, effect: chance(rng, 0.1) ? 'obligation' : chance(rng, 0.5) ? 'permit' : 'forbid',
    ...(chance(rng, 0.4) ? { resourceTypes: [pick(rng, ['doc', 'folder'])] } : {}),
    ...(chance(rng, 0.4) ? { actions: [pick(rng, ['read', 'edit', 'purge'])] } : {}),
    when: expr(rng), obligations: { redact: ['x'] },
  }))];
  const abacContent: AbacContentRule[] = Array.from({ length: int(rng, 3) }, (_, i) => ({
    id: `c${i}`, description: `c${i}`, contentClass: pick(rng, ['pii', 'fin']), effect: 'deny' as const,
    ...(chance(rng, 0.5) ? { actions: [pick(rng, ['read', 'edit'])] } : {}), ...(chance(rng, 0.6) ? { unless: expr(rng) } : {}),
  }));
  return {
    name: 'fuzz', schema: { resourceTypes: TYPES, compartments: [] }, rbac: { roles },
    mandatory: { trustedRoles: [], untrustedNetworkMaxLevel: 3, compartmentsRequireTrustedNetwork: true, bibaNoReadDownActions: [] },
    needToKnow: { mode: pick(rng, ['off', 'dry_run'] as const), protect: {}, breakGlassMaxHours: 4, breakGlassNotify: [] },
    abac, abacContent, sod: [], clarkWilson: { tokenTtlSeconds: 15 },
  };
}

/** Missing, null, well typed, or (rarely) mistyped: toCedarRequest must then refuse rather than misdecide. */
function value(rng: Rng, t: T, mistyped: { hit: boolean }): Json | undefined {
  const r = rng();
  if (r < 0.3) return undefined;
  if (r < 0.4) return null;
  if (r < 0.99) return lit(rng, t);
  mistyped.hit = true;
  return pick(rng, [1.5, 'x', 4, true, ['a'], [1], {}, [null]] as Json[]);
}
function attrs(rng: Rng, prefix: string, m: { hit: boolean }): Record<string, Json> | undefined {
  if (chance(rng, 0.1)) return undefined;
  const out: Record<string, Json> = {};
  for (const p of ATTR_PATHS.filter((x) => x.startsWith(`${prefix}.attrs.`))) {
    const [k, sub] = p.slice(prefix.length + 7).split('.') as [string, string?];
    const v = value(rng, typeOfPath(p), m);
    if (v === undefined) continue;
    if (sub) out[k] = chance(rng, 0.15) ? null : { [sub]: v };
    else out[k] = v;
  }
  return out;
}
function randomRequest(rng: Rng, m: { hit: boolean }): Request {
  const type = pick(rng, ['doc', 'folder'] as const);
  const subjectAttrs = attrs(rng, 'subject', m), resourceAttrs = attrs(rng, 'resource', m), contextAttrs = attrs(rng, 'context', m);
  const subject: Subject = { type: pick(rng, ['user', 'service']), id: pick(rng, ['u1', 'u2', 'u3']), active: chance(rng, 0.9), roles: some(rng, [...ROLES, 'ghost'], 0.35),
    clearance: int(rng, 4) as 0, compartments: [], integrity: 'verified', ...(subjectAttrs ? { attrs: subjectAttrs } : {}) };
  const resource: Resource = { type, id: pick(rng, ['d1', 'd2']), level: 0, compartments: [], integrity: 'verified', contentClasses: some(rng, ['pii', 'fin'], 0.3),
    ...(chance(rng, 0.7) ? { owner: pick(rng, ['u1', 'u2']) } : {}), ...(chance(rng, 0.5) ? { version: int(rng, 3) } : {}), ...(resourceAttrs ? { attrs: resourceAttrs } : {}) };
  // sessionLevel 0 keeps BLP satisfied for reads and writes of L0 data whatever the clearance (mandatory is not exported)
  const context: Context = { network: pick(rng, ['trusted', 'untrusted']), now: '2026-11-11T00:00:00Z', sessionLevel: 0, ...(contextAttrs ? { attrs: contextAttrs } : {}) };
  return { subject, action: pick(rng, Object.keys(TYPES[type].actions)), resource, context };
}

test('cedar: differential fuzz, the exported Cedar decides as Qadamar on random RBAC/ABAC/CBAC bundles', () => {
  const runs = Number(process.env.FUZZ_RUNS ?? 300);
  const graph = indexTuples([]);
  let compared = 0, allowed = 0, refused = 0;
  for (let seed = 1; seed <= runs; seed++) {
    const rng = prng(seed * 7919);
    const bundle = randomBundle(rng);
    const valid = validateBundle(bundle);
    assert.ok(valid.ok, `seed ${seed}: ${valid.ok ? '' : valid.errors.join('; ')}`);
    const out = toCedar(bundle);
    const obligations = bundle.abac.filter((r) => r.effect === 'obligation').map((r) => `ABAC.${r.id}`);
    assert.deepEqual(out.unsupported.map((u) => u.rule), [...FIXED_GAPS, ...obligations], `seed ${seed}: ${JSON.stringify(out.unsupported)}`);
    const policies = parse(out.policies);
    for (let n = 0; n < 30; n++) {
      const mistyped = { hit: false };
      const req = randomRequest(rng, mistyped);
      let cedarReq: CedarRequest;
      try { cedarReq = toCedarRequest(bundle, req); } catch (err) {
        assert.ok(err instanceof CedarMappingError && mistyped.hit, `seed ${seed}: refused a well-typed request: ${String(err)}`);
        refused++;
        continue;
      }
      const gate = evaluate(bundle, req, graph);
      assert.equal(authorize(policies, cedarReq), gate.decision, `seed ${seed} request ${n}: Qadamar ${gate.decision} (${gate.rules.join()})\n${JSON.stringify(req)}\n${out.policies}`);
      compared++; if (gate.decision) allowed++;
    }
  }
  assert.equal(oracleErrors.count, 0, 'an exported condition errored in the oracle: a `has` guard is missing');
  assert.ok(compared > runs * 20 && allowed > compared / 20 && allowed < compared * 0.95 && refused > 0, `${compared} compared, ${allowed} allowed, ${refused} refused`);
});

test('cedar: a request carries the role assignments live at context.now; an expired session has no Cedar form', () => {
  const bundle: PolicyBundle = load('toy-domain', 'bundle.json');
  const world: { now: string; subjects: Subject[]; resources: Resource[] } = load('toy-domain', 'world.json');
  const lina = world.subjects.find((s) => s.id === 'lina') as Subject;
  const item = world.resources.find((r) => r.id === 'CASE-18') as Resource;
  const roles = (subject: Subject, now: string) => toCedarRequest(bundle, { subject, action: 'read', resource: item, context: { network: 'trusted', now } }).entities[0]?.parents.map((p) => p.id);
  const assigned = { ...lina, roleAssignments: [{ role: 'viewer', notAfter: world.now }] };
  assert.deepEqual(roles(assigned, world.now), ['viewer']);
  assert.deepEqual(roles(assigned, '2026-11-08T10:00:00.001Z'), []);
  assert.throws(() => toCedarRequest(bundle, { subject: lina, action: 'read', resource: item, context: { network: 'trusted', now: world.now, sessionExpired: true } }), CedarMappingError);
});
