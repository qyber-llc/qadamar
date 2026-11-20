import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { commandLine, intOption, options, random, textOption } from './common.ts';
import type { BenchResource, BenchSubject, BenchTuple } from './common.ts';

const args = options();
const output = resolve(textOption(args, 'output', 'tmp/bench-world'));
const subjectCount = intOption(args, 'subjects', 1000);
const resourceCount = intOption(args, 'resources', 10_000);
const tupleCount = intOption(args, 'tuples', subjectCount);
const seed = intOption(args, 'seed', 20261108, 0);
if (tupleCount > subjectCount * resourceCount) throw new Error('--tuples cannot exceed subjects * resources');

const rng = random(seed);
const subjects: BenchSubject[] = Array.from({ length: subjectCount }, (_, i) => ({
  type: 'user',
  id: `SYN-U${String(i + 1).padStart(6, '0')}`,
  active: true,
  roles: ['investigator'],
  clearance: 3,
  compartments: ['ORCHID', 'FALCON'],
  integrity: 'verified',
  attrs: { name: `Synthetic user ${i + 1}`, unit: 'Synthetic benchmark unit' },
} as BenchSubject));
const resources: BenchResource[] = Array.from({ length: resourceCount }, (_, i) => ({
  type: 'case',
  id: `SYN-C${String(i + 1).padStart(7, '0')}`,
  level: 1 + (i % 3),
  compartments: i % 10 === 0 ? ['ORCHID'] : i % 10 === 1 ? ['FALCON'] : [],
  integrity: 'verified',
  owner: subjects[Math.floor(rng() * subjects.length)]!.id,
  version: 1,
  attrs: { title: `Synthetic case ${i + 1}`, status: 'open' },
  contentClasses: [],
} as BenchResource));

const pairs = new Set<string>();
const tuples: BenchTuple[] = [];
while (tuples.length < tupleCount) {
  const subject = subjects[Math.floor(rng() * subjects.length)]!;
  const resource = resources[Math.floor(rng() * resources.length)]!;
  const key = `${subject.id}\0${resource.id}`;
  if (pairs.has(key)) continue;
  pairs.add(key);
  tuples.push({
    object: { type: 'case', id: resource.id },
    relation: 'allocated',
    subject: { type: 'user', id: subject.id },
    grantedBy: resource.owner,
    reason: 'Synthetic benchmark allocation; not real access data',
  });
}

mkdirSync(output, { recursive: true });
copyFileSync(resolve('examples/toy-domain/bundle.json'), resolve(output, 'bundle.json'));
writeFileSync(resolve(output, 'world.json'), JSON.stringify({
  _note: 'SYNTHETIC BENCHMARK DATA ONLY. All users, cases and relations are generated and fictitious.',
  generator: 'scripts/bench/world.ts',
  seed,
  now: '2026-11-08T10:00:00Z',
  subjects,
  resources,
  tuples,
}, null, 2));
console.log(JSON.stringify({
  command: commandLine(), output, seed,
  subjects: subjects.length, resources: resources.length, tuples: tuples.length,
}, null, 2));
