// Fail-open regression: operands of the wrong type made a comparison FALSE, so a forbid such as
// `resource.attrs.amount ge 10000` did not fire for the string "50000" or an array. They are now UNKNOWN.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { codePointCompare } from '../src/conditions.ts';
import {
  buildFilter, evalExpr, evalTri, evaluate, indexTuples, partial, UNKNOWN,
  type AbacRule, type Context, type Expr, type Json, type PolicyBundle, type Resource, type Subject, type Tuple,
} from '../src/index.ts';

const load = (f: string) => JSON.parse(readFileSync(new URL(`../../../examples/toy-domain/${f}`, import.meta.url), 'utf8'));
const bundle: PolicyBundle = load('bundle.json');
const world: { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] } = load('world.json');
const graph = indexTuples(world.tuples);
const S = (id: string): Subject => world.subjects.find((x) => x.id === id) as Subject;
const R = (id: string): Resource => world.resources.find((x) => x.id === id) as Resource;
const ctx: Context = { network: 'trusted', now: world.now };
const withRules = (...rules: AbacRule[]): PolicyBundle => ({ ...bundle, abac: [...bundle.abac, ...rules] });
const withAttr = (r: Resource, key: string, value: Json): Resource => ({ ...r, attrs: { ...r.attrs, [key]: value } });
const env = { subject: {}, resource: {}, action: {}, context: {} };
const cmp = (op: string, left: Json, right: Json): Expr => ({ op, left: { value: left }, right: { value: right } } as Expr);

const bigAmount: AbacRule = {
  id: 'big-amount', description: 'Large amounts need the payment flow', effect: 'forbid', resourceTypes: ['case'], actions: ['update'],
  when: { op: 'ge', left: { path: 'resource.attrs.amount' }, right: { value: 10000 } },
};

test('a numeric forbid fires on a mistyped amount: string, array, object, boolean', () => {
  const b = withRules(bigAmount);
  const point = (amount: Json) => evaluate(b, { subject: S('bob'), action: 'update', resource: withAttr(R('CASE-14'), 'amount', amount), context: ctx }, graph);
  assert.equal(point(500).decision, true);
  assert.equal(point(50000).decision, false);
  for (const amount of ['50000', '5', [50000], [5], { v: 50000 }, true]) {
    const d = point(amount);
    assert.equal(d.decision, false, JSON.stringify(amount));
    assert.ok(d.rules.includes('ABAC.big-amount'), JSON.stringify(amount));
  }
});

test('a permit over a mistyped attribute does not grant', () => {
  const lowPriority: AbacRule = {
    id: 'low-priority-read', description: 'Anyone reads low priority cases', effect: 'permit', resourceTypes: ['case'], actions: ['read'],
    when: { op: 'lt', left: { path: 'resource.attrs.priority' }, right: { value: 3 } },
  };
  const b = withRules(lowPriority);
  const point = (priority: Json) => evaluate(b, { subject: S('grace'), action: 'read', resource: withAttr(R('CASE-18'), 'priority', priority), context: ctx }, graph).decision;
  assert.equal(point(1), true);
  for (const priority of ['1', [1], { p: 1 }, false]) assert.equal(point(priority), false, JSON.stringify(priority));
});

test('in, contains and subset over mistyped operands are UNKNOWN; eq and ne stay defined', () => {
  assert.equal(evalTri(cmp('in', 'a', 'abc'), env), null);
  assert.equal(evalTri(cmp('in', 'a', { a: 1 }), env), null);
  assert.equal(evalTri(cmp('in', 1, ['1']), env), false); // element equality: defined
  assert.equal(evalTri(cmp('contains', 5, 5), env), null);
  assert.equal(evalTri(cmp('contains', 'abc', 1), env), null);
  assert.equal(evalTri(cmp('contains', { a: 1 }, 'a'), env), null);
  assert.equal(evalTri(cmp('contains', [1, 2], '1'), env), false);
  assert.equal(evalTri(cmp('contains', 'abc', 'b'), env), true);
  assert.equal(evalTri(cmp('subset', 'a', ['a']), env), null);
  assert.equal(evalTri(cmp('subset', ['a'], 'a'), env), null);
  assert.equal(evalTri(cmp('subset', ['a'], ['a', 'b']), env), true);
  for (const op of ['lt', 'le', 'gt', 'ge']) {
    assert.equal(evalTri(cmp(op, '2', 1), env), null, op);
    assert.equal(evalTri(cmp(op, true, false), env), null, op);
    assert.equal(evalTri(cmp(op, [1], [2]), env), null, op);
  }
  assert.equal(evalTri(cmp('eq', '1', 1), env), false);
  assert.equal(evalTri(cmp('ne', '1', 1), env), true);
  // partial evaluation folds a mistyped literal comparison to UNKNOWN, not FALSE
  assert.deepEqual(partial({ op: 'ge', left: { path: 'context.amount' }, right: { value: 10 } }, { subject: {}, action: {}, context: { amount: '50' } }), UNKNOWN);
});

test('the residual drops a row whose mistyped attribute a forbid may match, and agrees with the point decision', () => {
  const b = withRules(bigAmount);
  const residual = buildFilter(b, S('bob'), 'case', 'update', ctx, graph);
  for (const amount of [500, 50000, '50000', '5', [5], { v: 1 }, true, null]) {
    const resource = withAttr(R('CASE-14'), 'amount', amount);
    const point = evaluate(b, { subject: S('bob'), action: 'update', resource, context: ctx }, graph).decision;
    const kept = evalExpr(residual, { subject: S('bob'), resource, action: { name: 'update', kind: 'write' }, context: ctx });
    assert.equal(kept, point, JSON.stringify(amount));
    assert.equal(kept, amount === 500, JSON.stringify(amount));
  }
});

test('strings order by Unicode code point (UTF-8 bytes, PostgreSQL COLLATE "C"), not by UTF-16 code unit', () => {
  // U+E000 < U+10000 by code point, but its UTF-16 unit 0xE000 is above the surrogate 0xD800
  assert.equal(evalExpr(cmp('lt', '\uE000', '\u{10000}'), env), true);
  assert.equal(evalExpr(cmp('gt', 'x\u{1F600}', 'x\uFFFD'), env), true);
  assert.equal(evalExpr(cmp('lt', 'B', 'a'), env), true); // no case folding
  const alphabet = ['a', 'B', '\u00E9', '\uD7FF', '\uE000', '\uFFFD', '\u{10000}', '\u{1F600}', '\u{10FFFF}', ''];
  const word = (n: number) => Array.from({ length: n % 4 }, (_, i) => alphabet[(n * 7 + i * 3) % alphabet.length]).join('');
  for (let i = 0; i < 400; i++) {
    const a = word(i), b = word(i * 13 + 5);
    const bytes = Math.sign(Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')));
    assert.equal(Math.sign(codePointCompare(a, b)), bytes, JSON.stringify([a, b]));
  }
});
