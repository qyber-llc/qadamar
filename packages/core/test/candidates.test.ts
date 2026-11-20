import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  buildFilter, CandidateSet, evalTri, indexTuples, ResourceCandidates, TRUE,
  type Expr, type Integrity, type Json, type Level, type PolicyBundle, type Resource, type Subject, type Tuple,
} from '../src/index.ts';

const load = (f: string) => JSON.parse(readFileSync(new URL(`../../../examples/toy-domain/${f}`, import.meta.url), 'utf8'));
const bundle: PolicyBundle = load('bundle.json');
const world: { now: string; subjects: Subject[]; resources: Resource[]; tuples: Tuple[] } = load('world.json');
const graph = indexTuples(world.tuples);

function listed(set: CandidateSet): number[] {
  const out: number[] = [];
  for (let at = set.next(0); at < set.length; at = set.next(at + 1)) out.push(at);
  return out;
}

test('resource positions equal residual evaluation for every toy subject, action, network and BLP mark', () => {
  const index = new ResourceCandidates(world.resources);
  const agent = { ...world.subjects.find((s) => s.id === 'assistant-1')!, delegator: world.subjects.find((s) => s.id === 'bob')! };
  let checked = 0;
  for (const subject of [...world.subjects, agent]) {
    for (const network of ['trusted', 'untrusted'] as const) {
      for (const context of [{ network, now: world.now }, { network, now: world.now, sessionLevel: 1 as Level, highWater: 3 as Level }]) {
        for (const [type, definition] of Object.entries(bundle.schema.resourceTypes)) {
          for (const [action, def] of Object.entries(definition.actions)) {
            const residual = buildFilter(bundle, subject, type, action, context, graph);
            const actual = new Set(listed(index.match(residual, type)));
            for (const [at, resource] of world.resources.entries()) {
              const expected = resource.type === type && evalTri(residual, { subject, resource, action: { name: action, kind: def.kind }, context }) === true;
              assert.equal(actual.has(at), expected, `${subject.id} ${action} ${resource.id} ${network}`);
              checked++;
            }
          }
        }
      }
    }
  }
  assert.ok(checked > 1000);
});

type Rng = () => number;
function prng(seed: number): Rng {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 0x100000000;
  };
}
const integer = (rng: Rng, max: number): number => Math.floor(rng() * max);
const pick = <T>(rng: Rng, values: readonly T[]): T => values[integer(rng, values.length)]!;
const paths = ['resource.level', 'resource.id', 'resource.owner', 'resource.integrity', 'resource.compartments', 'resource.contentClasses',
  'resource.attrs.status', 'resource.attrs.priority', 'resource.attrs.tags', 'resource.attrs.missing', 'resource.attrs.null'] as const;
const values: readonly Json[] = [0, 1, 2, 3, -1, 1.5, 'open', 'closed', 'verified', '1', '', true, false, null, [], ['ORCHID'],
  ['ORCHID', 'FALCON'], ['open'], ['pii.iban'], { open: 1 }];
const operators = ['eq', 'ne', 'lt', 'le', 'gt', 'ge', 'in', 'contains', 'subset'] as const;
const resources: Resource[] = Array.from({ length: 41 }, (_, i) => ({
  type: i % 7 === 0 ? 'payment' : 'case', id: `R-${i}`, level: i % 4 as Level,
  compartments: i % 3 === 0 ? ['ORCHID'] : i % 3 === 1 ? ['FALCON', 'ORCHID'] : [],
  integrity: ['derived', 'extracted', 'system', 'verified'][i % 4] as Integrity,
  owner: i % 2 ? 'alice' : 'bob', contentClasses: i % 5 === 0 ? ['pii.iban'] : [],
  attrs: {
    status: i % 6 === 0 ? null : i % 2 ? 'open' : 'closed',
    priority: i % 6,
    tags: i % 4 === 0 ? ['pii.iban'] : i % 4 === 1 ? 'pii.iban' : [],
    null: null,
  },
}));

function expression(rng: Rng, depth = 0): Expr {
  if (depth < 4 && rng() < 0.42) {
    const op = pick(rng, ['and', 'or', 'not'] as const);
    return op === 'not' ? { op, arg: expression(rng, depth + 1) }
      : { op, args: Array.from({ length: 1 + integer(rng, 3) }, () => expression(rng, depth + 1)) };
  }
  if (rng() < 0.08) return pick(rng, [TRUE, { op: 'unknown' }]);
  if (rng() < 0.1) return { op: 'has', path: pick(rng, paths) };
  const leftPath = rng() < 0.75;
  const path = { path: pick(rng, paths) };
  const value = { value: pick(rng, values) };
  return { op: pick(rng, operators), left: leftPath ? path : value, right: leftPath ? value : path };
}

test('seeded random predicates preserve TRUE, FALSE and UNKNOWN at every stored position', () => {
  const rng = prng(0xca4d1da7);
  const index = new ResourceCandidates(resources);
  for (let run = 0; run < 1500; run++) {
    const expr = expression(rng);
    const actual = new Set(listed(index.match(expr, 'case')));
    for (const [at, resource] of resources.entries()) {
      const expected = resource.type === 'case' && evalTri(expr, { subject: null, resource, action: null, context: null }) === true;
      assert.equal(actual.has(at), expected, `run=${run} resource=${resource.id} expr=${JSON.stringify(expr)}`);
    }
  }
});

test('bit positions retain stable offsets and empty/all edge cases', () => {
  for (const length of [0, 1, 31, 32, 33, 65]) {
    assert.deepEqual(listed(CandidateSet.empty(length)), []);
    assert.deepEqual(listed(CandidateSet.all(length)), Array.from({ length }, (_, i) => i));
    const selected = Array.from({ length }, (_, i) => i).filter((i) => i % 3 === 1);
    const set = CandidateSet.fromPositions(length, selected);
    assert.deepEqual(listed(set), selected);
    for (const at of selected) assert.equal(set.next(at), at);
  }
});
