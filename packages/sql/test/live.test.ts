import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { compile } from '../src/index.ts';
import type { Columns } from '../src/index.ts';
import { buildFilter, evalTri, evaluate, indexTuples } from '../../core/src/index.ts';
import type { AbacRule, Context, Expr, Json, PolicyBundle, Resource, Subject, Tuple } from '../../core/src/index.ts';

const require = createRequire(new URL('../../pdp-http/package.json', import.meta.url));
const { Client } = require('pg') as typeof import('../../pdp-http/node_modules/@types/pg/index.d.ts');
const load = (file: string) => JSON.parse(readFileSync(new URL(`../../../examples/toy-domain/${file}`, import.meta.url), 'utf8'));
const bundle = load('bundle.json') as PolicyBundle;
const world = load('world.json') as { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] };
const graph = indexTuples(world.tuples);
const databaseUrl = process.env.TEST_DATABASE_URL;
const skip = databaseUrl ? false : 'TEST_DATABASE_URL is not set';

const columns: Columns = {
  'resource.id': 'id',
  'resource.level': { column: 'level', type: 'number' },
  'resource.compartments': { column: 'compartments', kind: 'text[]' },
  'resource.integrity': 'integrity',
  'resource.owner': 'owner',
  'resource.contentClasses': { column: 'content_classes', kind: 'text[]' },
  'resource.attrs.status': 'status',
};

const subjects = world.subjects.map((subject) => {
  const delegatedBy = subject.attrs?.delegatedBy;
  if (typeof delegatedBy !== 'string') return subject;
  const delegator = world.subjects.find((candidate) => candidate.id === delegatedBy);
  if (!delegator) throw new Error(`Missing delegator ${delegatedBy}`);
  return { ...subject, delegator };
});

test('compiled toy-domain filters return exactly the point-allowed resources in PostgreSQL', { skip }, async (t) => {
  const client = new Client({ connectionString: databaseUrl! });
  await client.connect();
  t.after(async () => {
    try { await client.query('DROP TABLE IF EXISTS sql_compiler_live_resources'); }
    finally { await client.end(); }
  });
  await client.query(`CREATE TEMPORARY TABLE sql_compiler_live_resources (
    id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    level NUMERIC NOT NULL,
    compartments TEXT[] NOT NULL,
    integrity TEXT NOT NULL,
    owner TEXT,
    content_classes TEXT[] NOT NULL,
    status TEXT
  )`);
  for (const resource of world.resources) {
    await client.query(
      `INSERT INTO sql_compiler_live_resources
        (id, resource_type, level, compartments, integrity, owner, content_classes, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [resource.id, resource.type, resource.level, [...resource.compartments], resource.integrity,
        resource.owner ?? null, [...(resource.contentClasses ?? [])],
        typeof resource.attrs?.status === 'string' ? resource.attrs.status : null],
    );
  }

  let checked = 0;
  for (const network of ['trusted', 'untrusted'] as const) {
    for (const subject of subjects) {
      for (const [type, definition] of Object.entries(bundle.schema.resourceTypes)) {
        for (const [action, actionDefinition] of Object.entries(definition.actions)) {
          // The residual excludes per-row maker history; give the point oracle the toy payment's maker.
          const context: Context = { now: world.now, network, ...(actionDefinition.requiresSecondPerson ? { makerId: 'grace' } : {}) };
          const residual = buildFilter(bundle, subject, type, action, context, graph);
          const sql = compile(residual, columns);
          const result = await client.query<{ id: string }>(
            `SELECT id FROM sql_compiler_live_resources
             WHERE (${sql.text}) AND resource_type = $${sql.params.length + 1} ORDER BY id`,
            [...sql.params, type],
          );
          const expected = world.resources.filter((resource) => resource.type === type)
            .filter((resource) => evaluate(bundle, { subject, action, resource, context }, graph).decision)
            .map((resource) => resource.id).sort();
          assert.deepEqual(result.rows.map((row) => row.id), expected, `${subject.id} ${type} ${action} ${network}`);
          checked++;
        }
      }
    }
  }
  assert.equal(checked, 264); // 12 subjects (lina and omar included) x 11 actions x 2 networks
});

test('context rules compile to PostgreSQL filters identical to point decisions', { skip }, async (t) => {
  const client = new Client({ connectionString: databaseUrl! });
  await client.connect();
  t.after(async () => { await client.end(); });
  await client.query('CREATE TEMPORARY TABLE sql_compiler_live_context (id TEXT NOT NULL, level NUMERIC NOT NULL, compartments TEXT[] NOT NULL, integrity TEXT NOT NULL, owner TEXT, content_classes TEXT[] NOT NULL, status TEXT)');
  const resources = world.resources.filter((resource) => resource.type === 'case');
  for (const resource of resources) await client.query('INSERT INTO sql_compiler_live_context VALUES ($1, $2, $3, $4, $5, $6, $7)', [resource.id, resource.level,
    [...resource.compartments], resource.integrity, resource.owner ?? null, [...(resource.contentClasses ?? [])], resource.attrs?.status ?? null]);
  const contextual: PolicyBundle = { ...bundle, context: [
    { id: 'risk', resourceTypes: ['case'], actionKinds: ['read'], minResourceLevel: 1, maxRiskScore: 50 },
    { id: 'finance-device', resourceTypes: ['case'], actions: ['read'], contentClasses: ['finance.amount'], device: { managed: true, compliant: true } },
  ] };
  const bob = subjects.find((subject) => subject.id === 'bob')!;
  for (const context of [
    { now: world.now, network: 'trusted', riskScore: 0, device: { managed: true, compliant: true } },
    { now: world.now, network: 'trusted', riskScore: 50, device: { managed: true, compliant: true } },
    { now: world.now, network: 'trusted', riskScore: 51, device: { managed: true, compliant: true } },
    { now: world.now, network: 'trusted', riskScore: 0, device: { managed: true, compliant: false } },
    { now: world.now, network: 'trusted', riskScore: 0 },
  ] as const) {
    const sql = compile(buildFilter(contextual, bob, 'case', 'read', context, graph), columns);
    const result = await client.query<{ id: string }>(`SELECT id FROM sql_compiler_live_context WHERE ${sql.text} ORDER BY id`, sql.params);
    const expected = resources.filter((resource) => evaluate(contextual, { subject: bob, action: 'read', resource, context }, graph).decision).map((resource) => resource.id);
    assert.deepEqual(result.rows.map((row) => row.id), expected, JSON.stringify(context));
  }
});

test('jsonb attributes with mistyped values: the SQL filter keeps exactly the point-allowed rows in PostgreSQL', { skip }, async (t) => {
  const client = new Client({ connectionString: databaseUrl! });
  await client.connect();
  t.after(async () => {
    try { await client.query('DROP TABLE IF EXISTS sql_compiler_live_mistyped'); }
    finally { await client.end(); }
  });
  // every operator family over attributes whose JSON type varies per row, in permits and forbids
  const rule = (id: string, effect: 'permit' | 'forbid', action: string, when: Expr): AbacRule => ({ id, description: id, effect, resourceTypes: ['case'], actions: [action], when });
  const attr = (name: string) => ({ path: `resource.attrs.${name}` });
  const typed: PolicyBundle = { ...bundle, abac: [...bundle.abac,
    rule('big-amount', 'forbid', 'update', { op: 'ge', left: attr('amount'), right: { value: 10000 } }),
    rule('small-amount', 'forbid', 'export', { op: 'lt', left: { value: 'm' }, right: attr('amount') }),
    rule('low-priority', 'permit', 'read', { op: 'le', left: attr('priority'), right: { value: 2 } }),
    rule('secret-tag', 'forbid', 'export', { op: 'contains', left: attr('tags'), right: { value: 'secret' } }),
    rule('north', 'forbid', 'close', { op: 'in', left: { value: 'north' }, right: attr('tags') }),
    rule('known-tags', 'permit', 'update', { op: 'subset', left: attr('tags'), right: { value: ['a', 'b'] } }),
    rule('listed', 'permit', 'read', { op: 'and', args: [{ op: 'in', left: attr('priority'), right: { value: [7, 'seven'] } }, { op: 'ne', left: attr('amount'), right: { value: [5] } }] }),
    rule('known-amount', 'forbid', 'delete', { op: 'not', arg: { op: 'subset', left: { value: [5] }, right: attr('amount') } }),
    rule('word', 'forbid', 'delete', { op: 'contains', left: { value: 'xsecretx' }, right: attr('tags') }),
  ] };
  const values: Json[] = [50000, 5, 2, 7, '50000', '5', 'seven', 'secret', 'north', 'zz', '', [5], [50000], ['secret'], ['a'], ['a', 'b', 'c'],
    ['north'], [], { v: 1 }, true, false, null];
  // one row per (base case, value); the base ids keep the toy need-to-know tuples meaningful for the first copy
  const base = world.resources.filter((r) => r.type === 'case');
  const resources: Resource[] = values.flatMap((v, i) => base.map((r): Resource => ({
    ...r, id: i === 0 ? r.id : `${r.id}-${i}`,
    attrs: { ...r.attrs, amount: v, priority: values[(i + 3) % values.length]!, tags: values[(i + 7) % values.length]! },
  })));
  await client.query('CREATE TEMPORARY TABLE sql_compiler_live_mistyped (id TEXT NOT NULL, level NUMERIC NOT NULL, compartments TEXT[] NOT NULL, integrity TEXT NOT NULL, owner TEXT, content_classes TEXT[] NOT NULL, status TEXT, amount JSONB, priority JSONB, tags JSONB)');
  for (const r of resources) {
    const a = r.attrs ?? {};
    // JSON null is stored as jsonb 'null': the SQL side must treat it as missing, like core
    await client.query('INSERT INTO sql_compiler_live_mistyped VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::jsonb)',
      [r.id, r.level, [...r.compartments], r.integrity, r.owner ?? null, [...(r.contentClasses ?? [])], typeof a.status === 'string' ? a.status : null,
        JSON.stringify(a.amount), JSON.stringify(a.priority), JSON.stringify(a.tags)]);
  }
  const mapping: Columns = { ...columns, 'resource.attrs.amount': { column: 'amount', type: 'jsonb' },
    'resource.attrs.priority': { column: 'priority', type: 'jsonb' }, 'resource.attrs.tags': { column: 'tags', type: 'jsonb' } };
  let checked = 0, kept = 0;
  for (const subject of subjects) for (const action of Object.keys(bundle.schema.resourceTypes.case!.actions)) {
    const context: Context = { now: world.now, network: 'trusted' };
    const sql = compile(buildFilter(typed, subject, 'case', action, context, graph), mapping);
    const result = await client.query<{ id: string }>(`SELECT id FROM sql_compiler_live_mistyped WHERE ${sql.text} ORDER BY id`, sql.params);
    const expected = resources.filter((resource) => evaluate(typed, { subject, action, resource, context }, graph).decision).map((r) => r.id).sort();
    assert.deepEqual(result.rows.map((row) => row.id), expected, `${subject.id} ${action}`);
    checked++; kept += expected.length;
  }
  assert.equal(checked, 60); // 12 subjects x 5 case actions
  assert.ok(kept > 0, 'some rows are allowed, so the equivalence is not vacuous');
  // the fail-open case itself: the string "50000" is not below 10000, so the forbid excludes the row
  const bob = subjects.find((s) => s.id === 'bob')!;
  const sql = compile(buildFilter(typed, bob, 'case', 'update', { now: world.now, network: 'trusted' }, graph), mapping);
  const rows = await client.query<{ id: string }>(`SELECT id FROM sql_compiler_live_mistyped WHERE ${sql.text} AND amount = '"50000"'::jsonb`, sql.params);
  assert.deepEqual(rows.rows, []);
});

test('jsonb operators are three-valued like core compare() for every JSON type, both operand orders', { skip }, async (t) => {
  const client = new Client({ connectionString: databaseUrl! });
  await client.connect();
  t.after(() => client.end());
  // the strings after 'xsecretx' order differently by UTF-16 code units, code points and linguistic collations
  const values: Json[] = [0, 5, 50000, 2.5, '', '5', 'm', 'secret', 'xsecretx', 'M', 'é', '\uE000', '\u{1F600}', 'x\u{10000}', [], [5], ['5'],
    ['secret', 'a'], ['\uE000'], [[5]], { a: 1 }, true, false, null];
  const literals: Json[] = [5, 10000, '5', 'm', 'secret', '\uFFFD', '\u{10000}', 'x\uE000', true, [5], ['secret', 'a', 'b'], ['\u{1F600}'], [], { a: 1 }];
  const ops = ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'in', 'contains', 'subset'] as const;
  const mapping: Columns = { 'resource.attrs.v': { column: 'v', type: 'jsonb' } };
  let checked = 0;
  for (const op of ops) for (const literal of literals) for (const columnLeft of [true, false]) {
    const col = { path: 'resource.attrs.v' }, lit = { value: literal };
    const expr = { op, left: columnLeft ? col : lit, right: columnLeft ? lit : col } as Expr;
    const sql = compile(expr, mapping);
    const rows = values.map((_, i) => `(${i}, $${sql.params.length + i + 1}::jsonb)`).join(', ');
    const result = await client.query<{ r: boolean | null }>(`SELECT ${sql.text} AS r FROM (VALUES ${rows}) AS x(i, v) ORDER BY i`,
      [...sql.params, ...values.map((v) => JSON.stringify(v))]);
    const expected = values.map((v) => evalTri(expr, { subject: {}, resource: { attrs: { v } }, action: {}, context: {} }));
    assert.deepEqual(result.rows.map((row) => row.r), expected, `${op} ${JSON.stringify(literal)} column ${columnLeft ? 'left' : 'right'}: ${sql.text}`);
    checked++;
  }
  assert.equal(checked, ops.length * literals.length * 2);
});

// Strings on which core and a linguistic, case-insensitive or UTF-16 comparison disagree: case and accents (ICU),
// U+E000..U+FFFD against surrogate pairs (UTF-16 code units against code points), multi-letter folds (ß, ss).
const tricky = ['', 'a', 'A', 'b', 'B', 'ab', 'aB', 'Ab', 'á', 'Á', 'ä', 'e', 'é', 'E', 'ß', 'ss', 'z', '\uE000', '\uFFFD',
  '\u{10000}', '\u{1F600}', 'x\uE000', 'x\u{1F600}', 'xa'];
const trickyLists = [[], ['A'], ['a', 'b'], ['á', 'ß'], ['\u{1F600}', 'B'], ['\uE000', 'ss']];
type TextType = 'text' | 'text[]' | 'jsonb';

/** Every operator, both operand orders, every tricky literal: each row's SQL value is core's evalTri for that row. */
async function filterEqualsPoint(client: InstanceType<typeof Client>, columns: Record<string, { decl: string; type: TextType }>): Promise<number> {
  const names = Object.keys(columns);
  const value = (type: TextType, i: number): Json => i === tricky.length ? null
    : type === 'text' ? tricky[i]! : type === 'text[]' || i % 3 === 0 ? trickyLists[i % trickyLists.length]! : tricky[i]!;
  await client.query(`CREATE TEMPORARY TABLE collated (i INT NOT NULL, ${names.map((n) => `${n} ${columns[n]!.decl}`).join(', ')})`);
  for (let i = 0; i <= tricky.length; i++) { // the last row is all NULL
    const row = names.map((n) => columns[n]!.type === 'jsonb' && i < tricky.length ? JSON.stringify(value('jsonb', i)) : value(columns[n]!.type, i));
    await client.query(`INSERT INTO collated VALUES ($1, ${names.map((_, k) => `$${k + 2}`).join(', ')})`, [i, ...row]);
  }
  const ops = ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'in', 'contains', 'subset'] as const;
  let checked = 0;
  for (const n of names) for (const op of ops) for (const literal of [...tricky, ...trickyLists]) for (const columnLeft of [true, false]) {
    const col = { path: `resource.attrs.${n}` }, lit = { value: literal };
    const expr = { op, left: columnLeft ? col : lit, right: columnLeft ? lit : col } as Expr;
    let sql;
    try { sql = compile(expr, { [col.path]: { column: n, type: columns[n]!.type } }); } catch { continue; } // shapes refused with 400
    const result = await client.query<{ r: boolean | null }>(`SELECT ${sql.text} AS r FROM collated ORDER BY i`, sql.params);
    const expected = Array.from({ length: tricky.length + 1 }, (_, i) =>
      evalTri(expr, { subject: {}, resource: { attrs: { [n]: value(columns[n]!.type, i) } }, action: {}, context: {} }));
    assert.deepEqual(result.rows.map((row) => row.r), expected, `${n} ${op} ${JSON.stringify(literal)} column ${columnLeft ? 'left' : 'right'}: ${sql.text}`);
    checked++;
  }
  return checked;
}

test('column collations (ICU, nondeterministic ICU) do not change what the SQL filter keeps', { skip }, async (t) => {
  const client = new Client({ connectionString: databaseUrl! });
  await client.connect();
  t.after(() => client.end()); // the temporary collation and table end with the session
  await client.query(`CREATE COLLATION pg_temp.gate_ci (provider = icu, locale = 'und-u-ks-level2', deterministic = false)`);
  // the collations really disagree with core, so the equivalence is not vacuous
  const probe = await client.query(`SELECT 'a' < 'B' COLLATE "und-x-icu" AS icu, 'a' = 'A' COLLATE pg_temp.gate_ci AS ci`);
  assert.deepEqual(probe.rows[0], { icu: true, ci: true });
  const checked = await filterEqualsPoint(client, {
    icu: { decl: 'TEXT COLLATE "und-x-icu"', type: 'text' }, ci: { decl: 'TEXT COLLATE pg_temp.gate_ci', type: 'text' },
    plain: { decl: 'TEXT', type: 'text' }, icu_list: { decl: 'TEXT[] COLLATE "und-x-icu"', type: 'text[]' },
    ci_list: { decl: 'TEXT[] COLLATE pg_temp.gate_ci', type: 'text[]' }, j: { decl: 'JSONB', type: 'jsonb' },
  });
  assert.equal(checked, 2616); // compiled shapes over 6 columns
});

test('a database whose default collation is ICU does not change what the SQL filter keeps', { skip }, async (t) => {
  const admin = new Client({ connectionString: databaseUrl! });
  await admin.connect();
  const role = await admin.query<{ ok: boolean }>('SELECT rolcreatedb OR rolsuper AS ok FROM pg_roles WHERE rolname = current_user');
  if (!role.rows[0]?.ok) { await admin.end(); t.skip('the test role cannot create a database'); return; }
  const name = `gate_icu_${process.pid}`; // digits only: a safe identifier
  await admin.query(`CREATE DATABASE ${name} TEMPLATE template0 ENCODING 'UTF8' LOCALE 'C' LOCALE_PROVIDER icu ICU_LOCALE 'und'`);
  const url = new URL(databaseUrl!);
  url.pathname = `/${name}`;
  const client = new Client({ connectionString: url.toString() });
  t.after(async () => {
    try { await client.end(); } finally { try { await admin.query(`DROP DATABASE IF EXISTS ${name}`); } finally { await admin.end(); } }
  });
  await client.connect();
  assert.deepEqual((await client.query(`SELECT 'a' < 'B' AS icu`)).rows[0], { icu: true });
  const checked = await filterEqualsPoint(client, { plain: { decl: 'TEXT', type: 'text' }, list: { decl: 'TEXT[]', type: 'text[]' }, j: { decl: 'JSONB', type: 'jsonb' } });
  assert.equal(checked, 1380); // compiled shapes over 3 columns
});
