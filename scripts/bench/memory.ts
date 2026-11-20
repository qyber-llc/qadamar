// Fresh processes keep earlier scenarios' allocator high-water marks out of the next measurement.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { cpus, platform, arch, totalmem } from 'node:os';
import { primeDecisionIndexes, graphOf } from '../../packages/pdp-http/src/decision-index.ts';
import type { State } from '../../packages/pdp-http/src/store.ts';
import { ResourceCandidates } from '../../packages/core/src/candidates.ts';

const sizes = (process.argv[2] ?? '10000,100000,500000').split(',').map(Number);
if (sizes.some((n) => !Number.isSafeInteger(n) || n < 1 || n > 500000)) throw new Error('Sizes must be integers in 1..500000');
if (process.argv[3] !== 'child') {
  console.log(JSON.stringify({ node: process.version, platform: platform(), arch: arch(), cpu: cpus()[0]?.model, totalMemoryBytes: totalmem() }));
  for (const size of sizes) for (const served of [10, 1]) {
    const child = spawnSync(process.execPath, ['--expose-gc', import.meta.filename, String(size), 'child', String(served)], { encoding: 'utf8' });
    if (child.status !== 0) throw new Error(child.stderr || 'Memory scenario failed');
    process.stdout.write(child.stdout);
  }
} else {
  const size = sizes[0]!;
  const served = Number(process.argv[4]);
  const sample = () => { globalThis.gc!(); return process.memoryUsage(); };
  const baseline = sample();
  const worlds: State[] = [];
  const bundle = JSON.parse(readFileSync('examples/toy-domain/bundle.json', 'utf8'));
  for (let tenant = 0; tenant < served; tenant++) {
    const count = Math.floor(size / 10) + (tenant < size % 10 ? 1 : 0);
    worlds.push({ bundle,
      subjects: Array.from({ length: count }, (_, i) => ({ type: 'user', id: `u${i}`, active: true, roles: ['investigator'], clearance: 3, compartments: ['ORCHID'], integrity: 'verified' })),
      resources: Array.from({ length: count }, (_, i) => ({ type: 'case', id: `r${i}`, level: 1, compartments: [], integrity: 'verified', owner: `u${i}`, version: 1, attrs: { status: 'open' } })),
      tuples: Array.from({ length: count }, (_, i) => ({ id: `t${i}`, object: { type: 'case', id: `r${i}` }, relation: 'allocated', subject: { type: 'user', id: `u${i}` } })),
    });
  }
  const loaded = sample();
  const candidates = worlds.map((world) => { primeDecisionIndexes(world); const index = new ResourceCandidates(world.resources); index.match({ op: 'has', path: 'resource.attrs.status' }, 'case'); return index; });
  const indexed = sample();
  const records = worlds.reduce((n, w) => n + w.subjects.length, 0);
  const bitsetBytes = worlds.reduce((n, w) => n + Math.ceil(w.resources.length / 32) * 4, 0);
  console.log(JSON.stringify({ totalPerKind: size, totalTenants: 10, servedTenants: served, loadedPerKind: records,
    baseline, loaded, indexed, indexHeapBytes: indexed.heapUsed - loaded.heapUsed,
    lookupEntries: records * 9, relationObjectKeys: worlds.reduce((n, w) => n + graphOf(w.tuples).byObject.size, 0),
    relationSubjectKeys: worlds.reduce((n, w) => n + graphOf(w.tuples).bySubject.size, 0), tupleReferences: records * 2,
    relationObjectIds: records, candidateIndexes: candidates.length, candidatePositionEntries: records,
    candidateValueGroups: served, candidateTypeBitsetBytes: bitsetBytes, candidatePathBitsetBytes: bitsetBytes * 2 }));
}
