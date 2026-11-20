import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  check, indexTuples, patchTupleIndex, knownObjects, knownSubjects,
  type Graph, type PolicyBundle, type Ref, type RelationDef, type Tuple,
} from '../src/index.ts';

const load = (f: string) => JSON.parse(readFileSync(new URL(`../../../examples/toy-domain/${f}`, import.meta.url), 'utf8'));
const bundle: PolicyBundle = load('bundle.json');
const world: { now: string; tuples: Tuple[] } = load('world.json');

function scannedKnownObjects(b: PolicyBundle, graph: Graph,
  type: string, relation: string, subject: Ref, now: string): string[] {
  return (graph.objectsByType.get(type) ?? [])
    .filter((id) => check(b, graph, { type, id }, relation, subject, now).ok);
}

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
const pick = <T>(rng: Rng, values: readonly T[]): T => values[integer(rng, values.length)] as T;
const TYPES = ['case', 'folder', 'payment', 'team', 'user'] as const;
const RELATIONS = ['member', 'allocated', 'delegate', 'granted', 'parent', 'direct_knows', 'knows', 'manager'] as const;
const SUBJECTS: readonly Ref[] = [
  { type: 'user', id: 'u0' }, { type: 'user', id: 'u1' }, { type: 'user', id: 'u2' },
  { type: 'team', id: 't0' }, { type: 'agent', id: 'a0' }, { type: 'user', id: 'case:odd#id' },
];
const IDS: Readonly<Record<string, readonly string[]>> = {
  case: ['c0', 'c1', 'c2', 'c3', 'case:odd#id'],
  folder: ['f0', 'f1', 'f2'],
  payment: ['p0', 'p1'],
  team: ['t0', 't1', 't2', 't3'],
  user: ['u0', 'u1', 'u2', 'u3'],
  agent: ['a0'],
};

const ref = (rng: Rng): Ref => {
  const type = pick(rng, [...TYPES, 'agent']);
  return { type, id: pick(rng, IDS[type]!) };
};

function window(rng: Rng): Pick<Tuple, 'validFrom' | 'validTo' | 'breakGlass'> {
  switch (integer(rng, 9)) {
    case 1: return { validFrom: '2026-11-08T09:00:00Z', validTo: '2026-11-08T11:00:00Z' };
    case 2: return { validFrom: '2026-11-08T10:00:00Z', validTo: '2026-11-08T10:00:00Z' };
    case 3: return { validTo: '2026-11-08T09:59:59Z' };
    case 4: return { validFrom: '2026-11-08T10:00:01Z' };
    case 5: return { validFrom: 'bad', validTo: world.now };
    case 6: return { validFrom: '2026-11-08T09:00:00Z', validTo: '2026-11-08T11:00:00Z', breakGlass: true };
    case 7: return { validFrom: '2026-11-08T08:00:00Z', validTo: '2026-11-08T13:00:00Z', breakGlass: true };
    case 8: return { validFrom: '2026-11-08T09:00:00Z', validTo: '2026-11-08T10:00:00Z', breakGlass: true };
    default: return {};
  }
}

function randomTuple(rng: Rng): Tuple {
  const subjectRelation = integer(rng, 3) === 0 ? pick(rng, ['member', 'manager', 'implicit']) : undefined;
  return {
    object: ref(rng),
    relation: pick(rng, [...RELATIONS, 'implicit']),
    subject: ref(rng),
    ...(subjectRelation === undefined ? {} : { subjectRelation }),
    ...window(rng),
  };
}

function relationsOf(type: string): readonly string[] {
  const declared = type === 'team' || type === 'user'
    ? Object.keys(bundle.schema.subjectRelations?.[type] ?? {})
    : Object.keys(bundle.schema.resourceTypes[type]?.relations ?? {});
  return [...declared, 'implicit'];
}

test('seeded random graphs match the original scan for every subject, type and relation', () => {
  const rng = prng(0x4a1e21a);
  let comparisons = 0;
  for (let run = 0; run < 80; run++) {
    const graph = indexTuples(Array.from({ length: integer(rng, 60) }, () => randomTuple(rng)));
    for (const subject of SUBJECTS) {
      for (const type of TYPES) {
        for (const relation of relationsOf(type)) {
          const expected = scannedKnownObjects(bundle, graph, type, relation, subject, world.now);
          assert.deepEqual(knownObjects(bundle, graph, type, relation, subject, world.now), expected,
            `run=${run} subject=${JSON.stringify(subject)} type=${type} relation=${relation}`);
          comparisons++;
        }
      }
    }
  }
  assert.equal(comparisons, 7200);
});

class CountingMap<K, V> extends Map<K, V> {
  reads = 0;

  override get(key: K): V | undefined {
    this.reads++;
    return super.get(key);
  }
}

function countedGraph(tuples: readonly Tuple[]): { graph: Graph; reads: () => number } {
  const base = indexTuples(tuples);
  const byObject = new CountingMap<string, readonly Tuple[]>(base.byObject);
  const bySubject = new CountingMap<string, readonly Tuple[]>(base.bySubject);
  return { graph: { ...base, byObject, bySubject }, reads: () => byObject.reads + bySubject.reads };
}

test('known-set traversal work does not grow with 10,000 unrelated objects', () => {
  const target: Tuple = {
    object: { type: 'case', id: 'TARGET' }, relation: 'granted', subject: { type: 'user', id: 'bob' },
  };
  const unrelated: Tuple[] = Array.from({ length: 10_000 }, (_, i) => ({
    object: { type: 'case', id: `UNRELATED-${i}` }, relation: 'granted', subject: { type: 'user', id: 'stranger' },
  }));
  const subject = { type: 'user', id: 'bob' };
  const oldLarge = countedGraph([target, ...unrelated]);
  assert.deepEqual(scannedKnownObjects(bundle, oldLarge.graph, 'case', 'knows', subject, world.now), ['TARGET']);
  assert.ok(oldLarge.reads() > 10_000, `old scan made only ${oldLarge.reads()} graph reads`);

  const small = countedGraph([target]);
  const large = countedGraph([target, ...unrelated]);
  assert.deepEqual(knownObjects(bundle, small.graph, 'case', 'knows', subject, world.now), ['TARGET']);
  assert.deepEqual(knownObjects(bundle, large.graph, 'case', 'knows', subject, world.now), ['TARGET']);
  assert.equal(large.reads(), small.reads());
  assert.ok(large.reads() < 50, `reverse traversal made ${large.reads()} graph reads`);
});

test('direct tuples on a computed-only relation do not become candidates', () => {
  const subject = { type: 'user', id: 'bob' };
  const tuples: Tuple[] = Array.from({ length: 10_000 }, (_, i) => ({
    object: { type: 'case', id: `DIRECT-${i}` }, relation: 'knows', subject,
  }));
  const empty = countedGraph([]);
  const large = countedGraph(tuples);
  assert.deepEqual(knownObjects(bundle, empty.graph, 'case', 'knows', subject, world.now), []);
  assert.deepEqual(knownObjects(bundle, large.graph, 'case', 'knows', subject, world.now), []);
  assert.equal(large.reads(), empty.reads());
  assert.ok(large.reads() < 50, `computed-only relation made ${large.reads()} graph reads`);
});

test('reverse discovery stays iterative beyond the point-check hop limit', () => {
  const relations: Record<string, RelationDef> = {};
  for (let i = 0; i < 20_000; i++) relations[`r${i}`] = { union: [{ computed: `r${i + 1}` }] };
  relations.r20000 = { union: [{ this: true }] };
  const caseType = bundle.schema.resourceTypes.case!;
  const deep: PolicyBundle = { ...bundle, schema: { ...bundle.schema, resourceTypes: {
    ...bundle.schema.resourceTypes, case: { ...caseType, relations },
  } } };
  const subject = { type: 'user', id: 'bob' };
  const graph = indexTuples([{
    object: { type: 'case', id: 'DEEP' }, relation: 'r20000', subject,
  }]);
  assert.deepEqual(scannedKnownObjects(deep, graph, 'case', 'r0', subject, world.now), []);
  assert.deepEqual(knownObjects(deep, graph, 'case', 'r0', subject, world.now), []);
});

test('incremental tuple-index changes match a fresh index, including shared labels and removal', () => {
  const userset: Tuple = { object: { type: 'case', id: 'A' }, relation: 'knows', subject: { type: 'team', id: 'T' }, subjectRelation: 'member' };
  const shared: Tuple = { object: { type: 'case', id: 'B' }, relation: 'knows', subject: { type: 'team', id: 'T' }, subjectRelation: 'member' };
  const parent: Tuple = { object: { type: 'case', id: 'C' }, relation: 'parent', subject: { type: 'folder', id: 'F' } };
  const graph = indexTuples([userset, shared]);
  patchTupleIndex(graph, [{ op: 'delete', tuple: userset }, { op: 'put', tuple: parent }]);
  assert.deepEqual(graph, indexTuples([shared, parent]));
  patchTupleIndex(graph, [{ op: 'delete', tuple: shared }, { op: 'delete', tuple: parent }]);
  assert.deepEqual(graph, indexTuples([]));
  patchTupleIndex(graph, [{ op: 'put', tuple: userset }, { op: 'put', tuple: parent }, { op: 'delete', tuple: userset }]);
  assert.deepEqual(graph, indexTuples([parent]));
});


test('known-subject traversal includes every point-wise relation match on seeded random graphs', () => {
  const rng = prng(0x5ab1ec7);
  let checked = 0;
  for (let run = 0; run < 12; run++) {
    const graph = indexTuples(Array.from({ length: integer(rng, 50) }, () => randomTuple(rng)));
    for (const type of TYPES) {
      for (const id of IDS[type]!) {
        for (const relation of relationsOf(type)) {
          const found = knownSubjects(bundle, graph, { type, id }, relation, world.now);
          for (const subject of SUBJECTS) {
            if (check(bundle, graph, { type, id }, relation, subject, world.now).ok) {
              assert.ok(found.has(JSON.stringify([subject.type, subject.id])), `run=${run} ${type}:${id}#${relation} ${subject.type}:${subject.id}`);
            }
            checked++;
          }
        }
      }
    }
  }
  assert.ok(checked > 1000);
  const toyGraph = indexTuples(world.tuples);
  const managers = knownSubjects(bundle, toyGraph, { type: 'case', id: 'CASE-14' }, 'knows', world.now);
  assert.ok(managers.has(JSON.stringify(['user', 'carol'])));
});
