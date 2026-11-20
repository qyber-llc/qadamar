import { evalTri } from '../../core/src/index.ts';
import type { Expr, Json, Operand } from '../../core/src/index.ts';

type Kind = 'number' | 'text' | 'boolean' | 'text[]' | 'jsonb';
export type Columns = Record<string, string | { column: string; kind?: 'scalar' | 'text[]'; type?: Kind }>;
export interface Sql { text: string; params: unknown[] }

const wellFormed = (v: unknown): boolean => typeof v === 'string' ? !/\p{Cs}/u.test(v)
  : Array.isArray(v) ? v.every(wellFormed) : v !== null && typeof v === 'object' ? Object.entries(v).every(([k, x]) => wellFormed(k) && wellFormed(x)) : true;

/** PostgreSQL residuals preserve core's strict types and three-valued logic. */
export function compile(expr: Expr, columns: Columns): Sql {
  const mapped = new Map(Object.entries(columns).map(([path, spec]) => {
    const column = typeof spec === 'string' ? spec : spec.column;
    if (typeof column !== 'string' || !/^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*){0,2}$/.test(column)) throw new Error('Invalid column identifier');
    if (typeof spec !== 'string' && spec.kind !== undefined && !['scalar', 'text[]'].includes(spec.kind)) throw new Error('Invalid column kind');
    const kind = typeof spec === 'string' ? 'text' : spec.type ?? (spec.kind === 'text[]' ? 'text[]' : 'text');
    if (!['text', 'number', 'boolean', 'text[]', 'jsonb'].includes(kind) || (typeof spec !== 'string' && spec.kind === 'text[]' && kind !== 'text[]')) throw new Error('Invalid column type');
    return [path, { text: column.split('.').map((p) => `"${p}"`).join('.'), kind }] as const;
  }));
  const params: unknown[] = [];
  const column = (path: string) => {
    const found = mapped.get(path);
    if (!found) throw new Error(`Unmapped path: ${path}`);
    return found;
  };
  const kind = (o: Operand): string => 'path' in o ? column(o.path).kind : o.value === null ? 'null' : Array.isArray(o.value) ? o.value.every((v) => typeof v === 'string') ? 'text[]' : 'jsonb' : typeof o.value === 'string' ? 'text' : typeof o.value;
  const cast = (k: string): string => k === 'number[]' ? 'numeric[]' : k === 'number' ? 'numeric' : k === 'object' ? 'jsonb' : k === 'null' ? 'text' : k;
  // Every text comparison is pinned to COLLATE "C" (code-point order, exact equality): core's string semantics,
  // whatever the database or column collation (a linguistic or nondeterministic one disagrees with point decisions).
  const collate = (sql: string, type: string) => (type === 'text' || type === 'text[]' ? `${sql} COLLATE "C"` : sql);
  const operand = (o: Operand, expected?: string): string => {
    if ('path' in o) return collate(column(o.path).text, column(o.path).kind);
    if (Array.isArray(o.value) && o.value.some((v) => v === null || typeof v === 'object')) throw new Error('Invalid array element');
    // an unpaired surrogate is not Unicode: the driver would bind U+FFFD, which orders differently from core's string
    if (!wellFormed(o.value)) throw new Error('Invalid string literal');
    const type = cast(expected ?? kind(o));
    params.push((expected ?? kind(o)) === 'jsonb' || (kind(o) === 'object' && !expected) ? JSON.stringify(o.value) : o.value);
    return collate(`$${params.length}::${type}`, type);
  };
  const array = (o: Operand): boolean => 'path' in o ? column(o.path).kind === 'text[]' : Array.isArray(o.value);
  const textArray = (o: Operand): boolean => array(o) && ('path' in o || (Array.isArray(o.value) && o.value.every((v) => typeof v === 'string')));
  // A jsonb column holds a value whose JSON type may differ per row. Each operator tests jsonb_typeof first and is
  // NULL (UNKNOWN) when the type does not fit, exactly as core's compare(); JSON null is SQL NULL, as a missing value.
  const jsonb = (op: string, c: string, value: Json, colLeft: boolean): string => {
    if (value === null) return 'NULL::boolean';
    const type = `jsonb_typeof(${c})`;
    const when = (test: string, then: string) => `(CASE WHEN ${test} THEN ${then} END)`;
    // aliases are quoted upper case: no allowlisted (lower-case) column identifier can be shadowed by them
    const member = (arr: string, x: string, alias: string) => `EXISTS (SELECT 1 FROM jsonb_array_elements(${arr}) AS "${alias}"("V") WHERE "${alias}"."V" = ${x})`;
    const lit = (k: string) => operand({ value }, k);
    const text = `(${c} #>> '{}') COLLATE "C"`;
    const list = Array.isArray(value);
    if (op === 'eq' || op === 'ne') return when(`${type} <> 'null'`, `${c} ${op === 'eq' ? '=' : '<>'} ${lit('jsonb')}`);
    const ordering: Record<string, string> = { lt: '<', le: '<=', gt: '>', ge: '>=' };
    const sym = ordering[op];
    if (sym !== undefined) {
      if (typeof value !== 'number' && typeof value !== 'string') return 'NULL::boolean';
      const num = typeof value === 'number';
      const x = num ? `(${c})::numeric` : text;
      const y = lit(num ? 'number' : 'text');
      return when(`${type} = '${num ? 'number' : 'string'}'`, colLeft ? `${x} ${sym} ${y}` : `${y} ${sym} ${x}`);
    }
    // the column's value is an element of a literal array: `col in [..]`, `[..] contains col`
    if ((op === 'in' && colLeft) || (op === 'contains' && !colLeft && list)) return list ? when(`${type} <> 'null'`, member(lit('jsonb'), c, 'E')) : 'NULL::boolean';
    if (op === 'in' || op === 'contains') {
      if (op === 'contains' && !colLeft) return typeof value === 'string' ? when(`${type} = 'string'`, `(strpos(${lit('text')}, ${text}) > 0)`) : 'NULL::boolean';
      const inArray = `WHEN 'array' THEN ${member(c, lit('jsonb'), 'E')}`;
      const inString = op === 'contains' && typeof value === 'string' ? ` WHEN 'string' THEN (strpos(${text}, ${lit('text')}) > 0)` : '';
      return `(CASE ${type} ${inArray}${inString} END)`;
    }
    if (op !== 'subset') throw new Error('Unknown operator');
    if (!list) return 'NULL::boolean';
    const [inner, outer] = colLeft ? [c, lit('jsonb')] : [lit('jsonb'), c];
    return when(`${type} = 'array'`, `NOT EXISTS (SELECT 1 FROM jsonb_array_elements(${inner}) AS "E"("V") WHERE NOT ${member(outer, '"E"."V"', 'F')})`);
  };
  const walk = (e: Expr, depth = 0): string => {
    if (depth > 64) throw new Error('Expression too deep');
    if (e.op === 'true') return 'TRUE';
    if (e.op === 'unknown') return 'NULL::boolean';
    if (e.op === 'not') return e.arg.op === 'true' ? 'FALSE' : `(NOT ${walk(e.arg, depth + 1)})`;
    if (e.op === 'and' || e.op === 'or') return e.args.length ? `(${e.args.map((a) => walk(a, depth + 1)).join(e.op === 'and' ? ' AND ' : ' OR ')})` : e.op === 'and' ? 'TRUE' : 'FALSE';
    if (e.op === 'has') return column(e.path).kind === 'jsonb' ? `(${column(e.path).text} IS NOT NULL AND jsonb_typeof(${column(e.path).text}) <> 'null')` : `${column(e.path).text} IS NOT NULL`;
    if (!('left' in e)) throw new Error('Unknown operator');
    for (const o of [e.left, e.right]) if ('value' in o && Array.isArray(o.value) && o.value.some((v) => v === null || typeof v === 'object')) throw new Error('Invalid array element');
    const jl = 'path' in e.left && column(e.left.path).kind === 'jsonb', jr = 'path' in e.right && column(e.right.path).kind === 'jsonb';
    if (jl || jr) {
      const [col, lit] = jl ? [e.left, e.right] : [e.right, e.left];
      if (!('path' in col) || !('value' in lit)) throw new Error('jsonb columns compare with literals only');
      return jsonb(e.op, column(col.path).text, lit.value, jl);
    }
    if (e.op === 'in' && !array(e.right)) throw new Error('in requires array on right');
    if (e.op === 'subset' && (!textArray(e.left) || !textArray(e.right))) throw new Error('subset requires text[]');
    if (e.op === 'contains' && !array(e.left) && (!('value' in e.right) || typeof e.right.value !== 'string')) throw new Error('scalar contains requires string literal');
    if ('value' in e.left && 'value' in e.right) {
      const value = evalTri(e, { subject: {}, resource: {}, action: {}, context: {} });
      return value === null ? 'NULL::boolean' : value ? 'TRUE' : 'FALSE';
    }
    // Filter heterogeneous literal arrays by the strict scalar type before binding.
    if (e.op === 'in' && 'value' in e.right && Array.isArray(e.right.value)) {
      const k = kind(e.left);
      if (!['text', 'number', 'boolean', 'null'].includes(k)) {
        const left = operand(e.left);
        return `(CASE WHEN ${left} IS NULL THEN NULL ELSE FALSE END)`;
      }
      const values = e.right.value.filter((v) => (typeof v === 'string' ? 'text' : typeof v) === k);
      const left = operand(e.left);
      const right = operand({ value: values }, `${k === 'null' ? 'text' : k}[]`);
      return `(CASE WHEN ${left} IS NULL THEN NULL ELSE ${left} = ANY(${right}) END)`;
    }
    if (e.op === 'contains' && 'value' in e.left && Array.isArray(e.left.value) && 'path' in e.right) {
      const k = kind(e.right);
      const right = operand(e.right);
      if (!['text', 'number', 'boolean'].includes(k)) return `(CASE WHEN ${right} IS NULL THEN NULL ELSE FALSE END)`;
      const values = e.left.value.filter((v) => (typeof v === 'string' ? 'text' : typeof v) === k);
      const left = operand({ value: values }, `${k}[]`);
      return `(CASE WHEN ${right} IS NULL THEN NULL ELSE ${right} = ANY(${left}) END)`;
    }
    const lk = kind(e.left), rk = kind(e.right);
    const left = operand(e.left, lk === 'null' ? e.op === 'in' ? 'text' : rk : undefined);
    const right = operand(e.right, rk === 'null' ? e.op === 'contains' && array(e.left) ? 'text' : lk : undefined);
    const missing = `${left} IS NULL OR ${right} IS NULL`;
    // eq/ne across types are defined (FALSE/TRUE); any other operator over mistyped operands is UNKNOWN, as in core
    const mismatch = (value: boolean | null) => `(CASE WHEN ${missing} THEN NULL ELSE ${value === null ? 'NULL::boolean' : value ? 'TRUE' : 'FALSE'} END)`;
    if (e.op === 'in') {
      if (lk !== 'text' && lk !== 'null') return mismatch(false);
      return `(CASE WHEN ${left} IS NULL THEN NULL ELSE ${left} = ANY(array_remove(${right}, NULL)) END)`;
    }
    if (e.op === 'subset') return `(array_remove(${left}, NULL) <@ array_remove(${right}, NULL) AND (array_position(${left}, NULL) IS NULL OR array_position(${right}, NULL) IS NOT NULL))`;
    if (e.op === 'contains') {
      if (array(e.left)) {
        if (rk !== 'text' && rk !== 'null') return mismatch(false);
        return `(CASE WHEN ${missing} THEN NULL ELSE ${right} = ANY(array_remove(${left}, NULL)) END)`;
      }
      return lk === 'text' ? `(strpos(${left}, ${right}) > 0)` : mismatch(null);
    }
    const ops = { eq: '=', ne: '<>', lt: '<', le: '<=', gt: '>', ge: '>=' };
    if (!Object.hasOwn(ops, e.op)) throw new Error('Unknown operator');
    if (lk !== 'null' && rk !== 'null' && (lk !== rk || (!['eq', 'ne'].includes(e.op) && !['number', 'text'].includes(lk)))) return mismatch(e.op === 'eq' ? false : e.op === 'ne' ? true : null);
    return `(${left} ${ops[e.op as keyof typeof ops]} ${right})`;
  };
  return { text: walk(expr), params };
}
