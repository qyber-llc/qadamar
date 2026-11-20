// Affected-set change preview on a generated world. The policy case removes a mask from one classified case; a rule
// edit that genuinely applies to every case still has a world-wide affected set and is not presented as a small preview.
//   node scripts/bench/impact.ts --world=tmp/bench-large --repeats=3
import { mkdtempSync, rmSync } from 'node:fs';
import { cpus, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { contentRules } from '../../packages/core/src/index.ts';
import { Audit } from '../../packages/pdp-http/src/audit.ts';
import { impact } from '../../packages/pdp-http/src/admin/changes.ts';
import { Store, type State, type StoredTuple } from '../../packages/pdp-http/src/store.ts';
import { Tokens } from '../../packages/pdp-http/src/tokens.ts';
import type { Runtime } from '../../packages/pdp-http/src/runtime.ts';
import { commandLine, intOption, options, percentile, textOption } from './common.ts';

const args = options();
const world = resolve(textOption(args, 'world', 'tmp/bench-large'));
const repeats = intOption(args, 'repeats', 3);
const now = '2026-11-08T10:00:00Z';
const dir = mkdtempSync(join(tmpdir(), 'gate-bench-impact-'));
try {
  const store = new Store(dir, world, now);
  const rt: Runtime = { store, audit: new Audit(join(dir, 'audit.jsonl'), () => now), tokens: new Tokens(dir, () => now), now: () => now, started: Date.parse(now), decisions: 0 };
  const allocation = store.state.tuples[0]!;
  store.state = { ...store.state, resources: store.state.resources.map((resource) => resource.id === allocation.object.id ? { ...resource, contentClasses: ['finance.amount'] } : resource) };

  const pair = (subject: string, resource: string): boolean => store.state.tuples.some((tuple) => tuple.subject.id === subject && tuple.object.id === resource);
  let subject = store.state.subjects.at(-1)!; const resource = store.state.resources.find((item) => item.id === allocation.object.id)!;
  for (const candidate of store.state.subjects) if (!pair(candidate.id, resource.id)) { subject = candidate; break; }
  const tuple: StoredTuple = { object: { type: resource.type, id: resource.id }, relation: 'allocated', subject: { type: subject.type, id: subject.id },
    id: 'benchmark-impact', notBefore: now, notAfter: '2026-11-09T10:00:00Z', grantedBy: 'benchmark', reason: 'Synthetic impact benchmark' };
  const singleTuple: State = { ...store.state, tuples: [...store.state.tuples, tuple] };
  const bundle = store.state.bundle;
  const policy: State = { ...store.state, bundle: { ...bundle, abacContent: contentRules(bundle).filter((rule) => rule.id !== 'finance-mask') } };
  const scenarios = [
    { name: 'no-op', after: store.state },
    { name: 'single-tuple', after: singleTuple },
    { name: 'policy-content-rule', after: policy },
  ];
  const reports = scenarios.map(({ name, after }) => {
    const runsMs: number[] = []; let result: ReturnType<typeof impact> | undefined;
    for (let run = 0; run < repeats; run++) {
      const started = performance.now(); result = impact(rt, after); runsMs.push(performance.now() - started);
    }
    runsMs.sort((a, b) => a - b);
    return {
      name, runsMs: runsMs.map((value) => +value.toFixed(3)), medianMs: +percentile(runsMs, 0.5).toFixed(3),
      affectedCells: result!.analysis?.affectedCells, evaluated: result!.evaluated, reasons: result!.analysis?.reasons,
      gained: result!.gained.length, lost: result!.lost.length, obligationsGained: result!.obligationsGained.length, obligationsLost: result!.obligationsLost.length,
    };
  });
  console.log(JSON.stringify({
    command: commandLine(), subjects: store.state.subjects.length, resources: store.state.resources.length, tuples: store.state.tuples.length,
    repeats, machine: { platform: process.platform, arch: process.arch, cpu: cpus()[0]?.model ?? 'unknown', node: process.version }, scenarios: reports,
  }, null, 2));
} finally {
  rmSync(dir, { recursive: true, force: true });
}
