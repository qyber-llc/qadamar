import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { compile } from '../src/index.ts';
import type { Columns } from '../src/index.ts';
import { buildFilter, indexTuples, evalExpr, evalTri, FALSE, TRUE, UNKNOWN } from '../../core/src/index.ts';
import type { Expr, PolicyBundle, Subject, Tuple } from '../../core/src/index.ts';

const columns: Columns = { 'resource.level': { column: 'app.cases.level', type: 'number' }, 'resource.id': 'id', 'resource.owner': 'owner',
  'resource.compartments': { column: 'compartments', kind: 'text[]' },
  'resource.contentClasses': { column: 'classes', kind: 'text[]' }, 'resource.integrity': 'integrity', 'resource.attrs.status': 'status' };
const path = { path: 'resource.level' };
for (const [op, sql] of Object.entries({ eq: '=', ne: '<>', lt: '<', le: '<=', gt: '>', ge: '>=' })) {
  test(`comparison ${op} preserves SQL NULL and binds parameters`, () => {
    const e = { op, left: path, right: { value: 2 } } as Expr;
    assert.deepEqual(compile(e, columns), { text: `("app"."cases"."level" ${sql} $1::numeric)`, params: [2] });
    assert.equal(compile({ op: 'not', arg: e }, columns).text, `(NOT ("app"."cases"."level" ${sql} $1::numeric))`);
  });
}
test('constants, empty boolean sets and nested parameter numbering', () => {
  assert.deepEqual(compile(TRUE, {}), { text: 'TRUE', params: [] });
  assert.deepEqual(compile(FALSE, {}), { text: 'FALSE', params: [] });
  assert.equal(compile({ op: 'and', args: [] }, {}).text, 'TRUE');
  assert.equal(compile({ op: 'or', args: [] }, {}).text, 'FALSE');
  assert.deepEqual(compile({ op: 'and', args: [{ op: 'eq', left: path, right: { value: 1 } },
    { op: 'or', args: [{ op: 'eq', left: path, right: { value: 2 } }, FALSE] }] }, columns), {
    text: '(("app"."cases"."level" = $1::numeric) AND (("app"."cases"."level" = $2::numeric) OR FALSE))', params: [1, 2],
  });
});
test('in binds an array; contains uses a text[] column', () => {
  assert.deepEqual(compile({ op: 'in', left: path, right: { value: [1, 2] } }, columns), {
    text: '(CASE WHEN "app"."cases"."level" IS NULL THEN NULL ELSE "app"."cases"."level" = ANY($1::numeric[]) END)', params: [[1, 2]],
  });
  assert.deepEqual(compile({ op: 'contains', left: { path: 'resource.contentClasses' }, right: { value: 'pii.iban' } }, columns), {
    text: '(CASE WHEN "classes" COLLATE "C" IS NULL OR $1::text COLLATE "C" IS NULL THEN NULL ELSE $1::text COLLATE "C" = ANY(array_remove("classes" COLLATE "C", NULL)) END)', params: ['pii.iban'],
  });
  assert.deepEqual(compile({ op: 'contains', left: { path: 'resource.owner' }, right: { value: "a%'_" } }, columns), {
    text: '(strpos("owner" COLLATE "C", $1::text COLLATE "C") > 0)', params: ["a%'_"],
  });
});
test('subset is typed; has tests absence, not truthiness', () => {
  assert.deepEqual(compile({ op: 'subset', left: { path: 'resource.compartments' }, right: { value: ['ORCHID'] } }, columns), {
    text: '(array_remove("compartments" COLLATE "C", NULL) <@ array_remove($1::text[] COLLATE "C", NULL) AND (array_position("compartments" COLLATE "C", NULL) IS NULL OR array_position($1::text[] COLLATE "C", NULL) IS NOT NULL))', params: [['ORCHID']],
  });
  assert.deepEqual(compile({ op: 'has', path: 'resource.owner' }, columns), { text: '"owner" IS NOT NULL', params: [] });
  assert.throws(() => compile({ op: 'subset', left: path, right: { value: [] } }, columns));
});
test('literal NULL remains parameterized for mapped comparisons', () => {
  for (const op of ['eq', 'ne'] as const) assert.deepEqual(compile({ op, left: path, right: { value: null } }, columns).params, [null]);
  assert.equal(compile({ op: 'eq', left: { value: null }, right: { value: null } }, {}).text, 'NULL::boolean');
});
test('unknown paths and identifier injection fail closed', () => {
  assert.throws(() => compile({ op: 'has', path: 'resource.secret' }, columns), /Unmapped/);
  assert.throws(() => compile({ op: 'eq', left: path, right: { path: 'resource.secret' } }, columns), /Unmapped/);
  for (const column of ['x; DROP TABLE x', 'x"', 'X', 'x..y', 'x.y.z.a', 'x--', 'x y', 'x()', 'x.*', '.x', 'x\n']) {
    assert.throws(() => compile(TRUE, { x: column }), /Invalid/);
  }
  assert.deepEqual(compile({ op: 'eq', left: path, right: { value: "'; DROP TABLE users; --" } }, columns).params, ["'; DROP TABLE users; --"]);
});
test('all toy-domain residuals compile using only bound values and mapped columns', () => {
  const bundle = JSON.parse(readFileSync(new URL('../../../examples/toy-domain/bundle.json', import.meta.url), 'utf8')) as PolicyBundle;
  const world = JSON.parse(readFileSync(new URL('../../../examples/toy-domain/world.json', import.meta.url), 'utf8')) as { subjects: Subject[]; tuples: Tuple[] };
  let count = 0;
  for (const s of world.subjects) for (const [type, def] of Object.entries(bundle.schema.resourceTypes)) {
    for (const action of Object.keys(def.actions)) for (const network of ['trusted', 'untrusted'] as const) {
      const residual = buildFilter(bundle, s, type, action, { now: '2026-11-08T10:00:00Z', network }, indexTuples(world.tuples));
      const sql = compile(residual, columns);
      assert.equal(typeof sql.text, 'string');
      const numbers = [...sql.text.matchAll(/\$(\d+)/g)].map((m) => Number(m[1]));
      assert.deepEqual([...new Set(numbers)].sort((a, b) => a - b), sql.params.map((_, i) => i + 1));
      count++;
    }
  }
  assert.equal(count, 264); // 12 subjects (lina and omar included) x 11 actions x 2 networks
});


test('UNKNOWN and negated literal NULL preserve their boolean type', () => {
  assert.deepEqual(compile(UNKNOWN, {}), { text: 'NULL::boolean', params: [] });
  assert.deepEqual(compile({ op: 'not', arg: UNKNOWN }, {}), { text: '(NOT NULL::boolean)', params: [] });
  assert.equal(compile({ op: 'not', arg: { op: 'eq', left: { value: null }, right: { value: 2 } } }, {}).text, '(NOT NULL::boolean)');
});

test('a forbid over a NULL column drops the row under SQL WHERE semantics', () => {
  const residual: Expr = { op: 'not', arg: { op: 'eq', left: path, right: { value: 2 } } };
  const sql = compile(residual, { 'resource.level': { column: 'level', type: 'number' } });
  assert.equal(sql.text, '(NOT ("level" = $1::numeric))');
  const env = { subject: {}, resource: { level: null }, action: {}, context: {} };
  assert.equal(evalTri(residual, env), null);
  assert.equal(evalExpr(residual, env), false);
  assert.equal(evalExpr({ op: 'has', path: 'resource.level' }, env), false);
  // SQLite executes this standard SQL subset with the same NULL/NOT/WHERE semantics.
  const db = new DatabaseSync(':memory:');
  try {
    db.exec("CREATE TABLE cases (id TEXT, level INTEGER); INSERT INTO cases VALUES ('null-row', NULL), ('forbidden', 2), ('allowed', 1)");
    const value = sql.params[0];
    assert.equal(typeof value, 'number');
    if (typeof value !== 'number') throw new Error('Expected numeric comparison parameter');
    const rows = db.prepare(`SELECT id FROM cases WHERE ${sql.text.replace(/\$([0-9]+)::numeric/g, 'CAST($$$1 AS NUMERIC)')}`).all({ $1: value });
    assert.deepEqual(rows.map((row) => row.id), ['allowed']);
  } finally { db.close(); }
});

test('C3: empty in preserves UNKNOWN for a NULL left operand, including under NOT', () => {
  const expr: Expr = { op: 'not', arg: { op: 'in', left: { path: 'resource.owner' }, right: { value: [] } } };
  const sql = compile(expr, { 'resource.owner': 'owner' });
  assert.match(sql.text, /CASE WHEN "owner" COLLATE "C" IS NULL THEN NULL ELSE "owner" COLLATE "C" = ANY\(\$1::text\[\] COLLATE "C"\) END/);
  const db = new DatabaseSync(':memory:');
  try {
    // Model PostgreSQL's surprising ANY('{}') = FALSE even when the left side is NULL.
    db.function('pg_any', (left, right) => {
      const values = JSON.parse(String(right)) as unknown[];
      return values.length === 0 ? 0 : left === null ? null : Number(values.includes(left));
    });
    db.exec("CREATE TABLE cases (owner TEXT); INSERT INTO cases VALUES (NULL), ('alice')");
    // SQLite's default BINARY collation is byte order, as COLLATE "C"
    const text = sql.text.replaceAll(' COLLATE "C"', '').replace('"owner" = ANY($1::text[])', 'pg_any("owner", $1)');
    const rows = db.prepare(`SELECT owner FROM cases WHERE ${text}`).all({ $1: '[]' });
    assert.deepEqual(rows.map((r) => r.owner), ['alice']);
    assert.equal(evalTri(expr, { subject: {}, resource: { owner: null }, action: {}, context: {} }), null);
  } finally { db.close(); }
});

test('C3: strict column types prevent parameter coercion and preserve UNKNOWN across type mismatches', () => {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('CREATE TABLE cases (level INTEGER); INSERT INTO cases VALUES (2), (NULL)');
    for (const op of ['eq', 'ne', 'lt', 'le', 'gt', 'ge'] as const) for (const value of ['2', 2, true, null]) {
      const expr: Expr = { op, left: { path: 'resource.level' }, right: { value } };
      const sql = compile(expr, { 'resource.level': { column: 'level', type: 'number' } });
      const compatible = sql.text.replace(/\$1::(numeric|text|boolean)/g, (_, type: string) => `CAST($1 AS ${type})`).replace('NULL::boolean', 'NULL');
      const rows = db.prepare(`SELECT ${compatible} AS result FROM cases`).all({ $1: typeof value === 'boolean' ? Number(value) : value });
      assert.deepEqual(rows.map((r) => r.result), [2, null].map((level) => {
        const tri = evalTri(expr, { subject: {}, resource: { level }, action: {}, context: {} });
        return tri === null ? null : Number(tri);
      }), `${op} ${String(value)}: ${sql.text}`);
    }
    assert.match(compile({ op: 'eq', left: { path: 'x' }, right: { value: 2 } }, { x: { column: 'level', type: 'number' } }).text, /\$1::numeric/);
    assert.match(compile({ op: 'eq', left: { path: 'x' }, right: { value: '2' } }, { x: 'level' }).text, /\$1::text/);
  } finally { db.close(); }
});

test('C3: invalid array operands, NULL elements and scalar contains arguments are refused before SQL execution', () => {
  const columns: Columns = { scalar: 'owner', array: { column: 'classes', type: 'text[]' } };
  for (const op of ['in', 'subset'] as const) for (const right of [{ value: 'alice' }, { value: 123 }, { path: 'scalar' }] as const) {
    assert.throws(() => compile({ op, left: { path: op === 'in' ? 'scalar' : 'array' }, right }, columns));
  }
  for (const op of ['in', 'subset', 'contains', 'eq'] as const) assert.throws(() => compile({ op, left: { path: 'array' }, right: { value: ['alice', null] } }, columns));
  for (const right of [{ value: 123 }, { value: true }, { path: 'scalar' }] as const) assert.throws(() => compile({ op: 'contains', left: { path: 'scalar' }, right }, columns));
  const sql = compile({ op: 'in', left: { path: 'scalar' }, right: { path: 'array' } }, columns);
  assert.match(sql.text, /array_remove\("classes" COLLATE "C", NULL\)/);
});

test('C3: mixed array literals preserve strict element types and array columns tolerate NULL members', () => {
  const columns: Columns = { text: 'owner', array: { column: 'classes', type: 'text[]' }, number: { column: 'level', type: 'number' } };
  assert.deepEqual(compile({ op: 'in', left: { path: 'number' }, right: { value: [2, '2', true] } }, columns).params, [[2]]);
  assert.deepEqual(compile({ op: 'in', left: { path: 'text' }, right: { value: [2, '2', true] } }, columns).params, [['2']]);
  assert.deepEqual(compile({ op: 'contains', left: { value: [2, '2', true] }, right: { path: 'text' } }, columns).params, [['2']]);
  assert.match(compile({ op: 'eq', left: { path: 'array' }, right: { value: [2] } }, columns).text, /ELSE FALSE END/);
  assert.match(compile({ op: 'in', left: { path: 'array' }, right: { value: [] } }, columns).text, /CASE WHEN "classes" COLLATE "C" IS NULL THEN NULL ELSE FALSE END/);
  assert.match(compile({ op: 'contains', left: { path: 'array' }, right: { value: null } }, columns).text, /\$1::text COLLATE "C" = ANY/);
  assert.doesNotMatch(compile({ op: 'contains', left: { path: 'array' }, right: { value: null } }, columns).text, /\$1::text\[\]/);
  const subset = compile({ op: 'subset', left: { path: 'array' }, right: { value: [] } }, columns);
  assert.match(subset.text, /array_remove\("classes" COLLATE "C", NULL\)/);
  assert.match(subset.text, /array_position\("classes" COLLATE "C", NULL\) IS NULL/);
});

test('jsonb columns: literals stay bound, a mistyped ordering is NULL, column-to-column comparisons are refused', () => {
  const columns: Columns = { 'resource.attrs.amount': { column: 'amount', type: 'jsonb' }, 'resource.attrs.other': { column: 'other', type: 'jsonb' }, 'resource.owner': 'owner' };
  const amount = { path: 'resource.attrs.amount' };
  const ge = compile({ op: 'ge', left: amount, right: { value: 10000 } }, columns);
  assert.deepEqual(ge, { text: `(CASE WHEN jsonb_typeof("amount") = 'number' THEN ("amount")::numeric >= $1::numeric END)`, params: [10000] });
  const injected = compile({ op: 'eq', left: amount, right: { value: "'; DROP TABLE x; --" } }, columns);
  assert.deepEqual(injected.params, [JSON.stringify("'; DROP TABLE x; --")]);
  assert.equal(compile({ op: 'ge', left: amount, right: { value: true } }, columns).text, 'NULL::boolean');
  assert.equal(compile({ op: 'eq', left: amount, right: { value: null } }, columns).text, 'NULL::boolean');
  assert.match(compile({ op: 'has', path: 'resource.attrs.amount' }, columns).text, /jsonb_typeof\("amount"\) <> 'null'/);
  assert.throws(() => compile({ op: 'eq', left: amount, right: { path: 'resource.attrs.other' } }, columns), /literals only/);
  assert.throws(() => compile({ op: 'eq', left: amount, right: { path: 'resource.owner' } }, columns), /literals only/);
  assert.throws(() => compile(TRUE, { x: { column: 'x', type: 'json' as never } }), /Invalid column type/);
});

test('a forbid over a number column compared with a string literal drops every row instead of keeping them', () => {
  // the declared column type cannot hold the literal's type: ordering is UNKNOWN, so NOT(...) stays UNKNOWN
  const sql = compile({ op: 'not', arg: { op: 'ge', left: path, right: { value: '10000' } } }, columns);
  assert.match(sql.text, /ELSE NULL::boolean END/);
  assert.equal(compile({ op: 'eq', left: path, right: { value: '2' } }, columns).text.includes('ELSE FALSE END'), true);
  assert.equal(compile({ op: 'ne', left: path, right: { value: '2' } }, columns).text.includes('ELSE TRUE END'), true);
  assert.match(compile({ op: 'contains', left: path, right: { value: 'x' } }, columns).text, /ELSE NULL::boolean END/);
});

test('text comparisons are pinned to COLLATE "C"; an unpaired surrogate literal is refused', () => {
  const columns: Columns = { 'resource.owner': 'owner', 'resource.attrs.v': { column: 'v', type: 'jsonb' } };
  assert.equal(compile({ op: 'lt', left: { path: 'resource.owner' }, right: { value: 'b' } }, columns).text, '("owner" COLLATE "C" < $1::text COLLATE "C")');
  assert.match(compile({ op: 'lt', left: { path: 'resource.attrs.v' }, right: { value: 'b' } }, columns).text, /\("v" #>> '{}'\) COLLATE "C" < \$1::text COLLATE "C"/);
  for (const value of ['\uD800', 'a\uDFFF', ['ok', '\uDBFF']]) {
    assert.throws(() => compile({ op: 'eq', left: { path: 'resource.owner' }, right: { value } }, columns), /Invalid string literal/);
    assert.throws(() => compile({ op: 'eq', left: { path: 'resource.attrs.v' }, right: { value } }, columns), /Invalid string literal/);
  }
  assert.doesNotThrow(() => compile({ op: 'eq', left: { path: 'resource.owner' }, right: { value: '\u{1F600}' } }, columns));
});
