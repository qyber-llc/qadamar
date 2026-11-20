// Condition language (JSON AST) for ABAC rules (including content attributes), with three-valued (Kleene) logic, the same as SQL:
// a comparison over a missing or null value, or over operands of the wrong type, is UNKNOWN; NOT(UNKNOWN) is
// UNKNOWN. The engine then fails closed: a permit needs TRUE, a forbid fires on TRUE or UNKNOWN, an exemption needs
// TRUE. A list filter keeps a row only when its predicate is TRUE, which is exactly SQL's WHERE, so point decisions
// and SQL filters agree.
import type { Expr, Json, Operand } from './types.ts';
import { canonical } from './version.ts';

export type Env = Readonly<Record<'subject' | 'resource' | 'action' | 'context', unknown>>;
export type Tri = boolean | null; // null = UNKNOWN

const ROOTS = new Set(['subject', 'resource', 'action', 'context']);
export const MISSING = Symbol('missing');
type Val = Json | typeof MISSING;

export function resolvePath(env: Partial<Env>, path: string): Val {
  const parts = path.split('.');
  const root = parts[0] ?? '';
  if (!ROOTS.has(root) || !Object.hasOwn(env, root)) return MISSING;
  let cur: unknown = (env as Record<string, unknown>)[root];
  for (const p of parts.slice(1)) {
    if (cur === null || typeof cur !== 'object' || !Object.hasOwn(cur, p)) return MISSING;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur === undefined || cur === null ? MISSING : (cur as Json); // JSON null is SQL NULL: unknown
}

const operand = (env: Partial<Env>, o: Operand): Val => ('path' in o ? resolvePath(env, o.path) : o.value ?? MISSING);

const same = (a: Json, b: Json): boolean => canonical(a) === canonical(b);

// Unicode code-point order, which is UTF-8 byte order and PostgreSQL's COLLATE "C": the SQL filter compiles to it.
// JavaScript's `<` compares UTF-16 code units, which differs when a surrogate pair (U+10000 and above) meets
// U+E000..U+FFFF at the first difference; lifting surrogates above U+E000..U+FFFF there restores code-point order.
const unit = (u: number): number => (u < 0xd800 ? u : u < 0xe000 ? u + 0x2000 : u - 0x800);
export function codePointCompare(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a.charCodeAt(i), y = b.charCodeAt(i);
    if (x !== y) return unit(x) - unit(y);
  }
  return a.length - b.length;
}

function ordered(a: Json, b: Json): number | null {
  if (typeof a === 'number' && typeof b === 'number' && Number.isFinite(a) && Number.isFinite(b)) return a < b ? -1 : a > b ? 1 : 0;
  if (typeof a === 'string' && typeof b === 'string') return codePointCompare(a, b);
  return null;
}

// Operands of the wrong type (a number against a string, an array or an object; `in` over a non-array; `contains`
// on a non-array non-string, or a string with a non-string needle; `subset` of non-arrays) are UNKNOWN, as a missing
// value is: a permit does not grant and a forbid or an obligation fires. `eq` and `ne` stay defined across types
// (structural JSON equality: "1" is not 1), and element tests inside arrays use that equality.
export function compare(op: string, a: Val, b: Val): Tri {
  if (a === MISSING || b === MISSING) return null;
  switch (op) {
    case 'eq': return same(a, b);
    case 'ne': return !same(a, b);
    case 'in': return Array.isArray(b) ? b.some((x) => same(x, a)) : null;
    case 'contains':
      if (Array.isArray(a)) return a.some((x) => same(x, b));
      return typeof a === 'string' && typeof b === 'string' ? a.includes(b) : null;
    case 'subset': return Array.isArray(a) && Array.isArray(b) ? a.every((x) => b.some((y) => same(x, y))) : null;
    default: {
      const c = ordered(a, b);
      if (c === null) return null;
      return op === 'lt' ? c < 0 : op === 'le' ? c <= 0 : op === 'gt' ? c > 0 : op === 'ge' ? c >= 0 : null;
    }
  }
}

const andTri = (xs: readonly Tri[]): Tri => (xs.includes(false) ? false : xs.includes(null) ? null : true);
const orTri = (xs: readonly Tri[]): Tri => (xs.includes(true) ? true : xs.includes(null) ? null : false);
const notTri = (x: Tri): Tri => (x === null ? null : !x);

export function evalTri(expr: Expr, env: Env): Tri {
  switch (expr.op) {
    case 'true': return true;
    case 'unknown': return null;
    case 'and': return andTri(expr.args.map((e) => evalTri(e, env)));
    case 'or': return orTri(expr.args.map((e) => evalTri(e, env)));
    case 'not': return notTri(evalTri(expr.arg, env));
    case 'has': return resolvePath(env, expr.path) !== MISSING;
    default: return compare(expr.op, operand(env, expr.left), operand(env, expr.right));
  }
}

/** TRUE only: what a permit, an exemption or a SQL WHERE needs. */
export const evalExpr = (expr: Expr, env: Env): boolean => evalTri(expr, env) === true;

/** TRUE or UNKNOWN: what fires a forbid or an obligation (fail closed). */
export const mayHold = (expr: Expr, env: Env): boolean => evalTri(expr, env) !== false;

// ---------- partial evaluation: the resource is unknown ----------

export const TRUE: Expr = { op: 'true' };
export const FALSE: Expr = { op: 'not', arg: TRUE };
export const UNKNOWN: Expr = { op: 'unknown' };
export const isTrue = (e: Expr): boolean => e.op === 'true';
export const isFalse = (e: Expr): boolean => e.op === 'not' && e.arg.op === 'true';

const onResource = (o: Operand): boolean => 'path' in o && o.path.startsWith('resource.');

export function and(args: readonly Expr[]): Expr {
  const kept = args.filter((a) => !isTrue(a));
  if (kept.some(isFalse)) return FALSE;
  return kept.length === 0 ? TRUE : kept.length === 1 ? (kept[0] as Expr) : { op: 'and', args: kept };
}

export function or(args: readonly Expr[]): Expr {
  const kept = args.filter((a) => !isFalse(a));
  if (kept.some(isTrue)) return TRUE;
  return kept.length === 0 ? FALSE : kept.length === 1 ? (kept[0] as Expr) : { op: 'or', args: kept };
}

export function not(arg: Expr): Expr {
  if (isTrue(arg)) return FALSE;
  if (isFalse(arg)) return TRUE;
  if (arg.op === 'unknown') return UNKNOWN;
  return arg.op === 'not' ? arg.arg : { op: 'not', arg };
}

/** Resolves a non-resource operand to a literal; keeps a resource operand as a path. */
function bind(env: Omit<Env, 'resource'>, o: Operand): Operand | typeof MISSING {
  if (onResource(o)) return o;
  const v = operand(env, o);
  return v === MISSING ? MISSING : { value: v };
}

/** Substitutes everything but `resource.*`; TRUE / FALSE / UNKNOWN when the resource does not matter. */
export function partial(expr: Expr, env: Omit<Env, 'resource'>): Expr {
  switch (expr.op) {
    case 'true': return TRUE;
    case 'unknown': return UNKNOWN;
    case 'and': return and(expr.args.map((e) => partial(e, env)));
    case 'or': return or(expr.args.map((e) => partial(e, env)));
    case 'not': return not(partial(expr.arg, env));
    case 'has':
      if (expr.path.startsWith('resource.')) return expr;
      return resolvePath(env, expr.path) !== MISSING ? TRUE : FALSE;
    default: {
      const l = bind(env, expr.left);
      const r = bind(env, expr.right);
      if (l === MISSING || r === MISSING) return UNKNOWN;
      if ('value' in l && 'value' in r) {
        const t = compare(expr.op, l.value, r.value);
        return t === null ? UNKNOWN : t ? TRUE : FALSE;
      }
      return { op: expr.op, left: l, right: r };
    }
  }
}
