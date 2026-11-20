// The Lean toolchain is third-party code fetched at CI time: it is installed from digest-checked archives and runs in
// a job whose token can only read, which the gate (ci) and the release job (contents: write) wait for. docs/CI.md.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const root = new URL('../../../', import.meta.url);
const read = (path: string): string => readFileSync(new URL(path, root), 'utf8');
/** A workflow's top-level jobs, name -> text. shortcut: indentation-based, enough for these files; a YAML parser if they
 *  grow anchors or flow mappings. */
function jobs(workflow: string): Map<string, string> {
  const body = workflow.slice(workflow.indexOf('\njobs:\n') + 7);
  return new Map([...body.matchAll(/^ {2}([\w-]+):\n((?:(?: {4}.*)?\n)*)/gm)].map((m) => [m[1]!, m[2]!]));
}
const LEAN_STEPS = ['tools/ci/install-lean.sh', 'formal/check.sh', 'lean-differential.test.ts'];

for (const file of ['.github/workflows/ci.yml', '.github/workflows/release.yml']) {
  test(`${file}: the Lean steps run in their own read-only job that every other job needs`, () => {
    const text = read(file);
    assert.doesNotMatch(text.slice(0, text.indexOf('\njobs:\n')), /contents: write/, 'read-only by default');
    const all = jobs(text);
    const lean = [...all].filter(([, job]) => LEAN_STEPS.some((step) => job.includes(step)));
    assert.equal(lean.length, 1, 'one job runs the Lean steps');
    const [name, job] = lean[0]!;
    for (const step of LEAN_STEPS) assert.ok(job.includes(step), `${name} runs ${step}`);
    assert.match(job, /^ {4}permissions:\n {6}contents: read\n/m);
    assert.doesNotMatch(job, /write/);
    assert.ok(all.size > 1);
    // `needs: formal` or a flow list naming it: every other job waits for it directly
    for (const [other, body] of all) if (other !== name) assert.match(body, new RegExp(`^ {4}needs: (?:${name}|\\[(?:[\\w-]+, )*${name}(?:, [\\w-]+)*\\])$`, 'm'), `${other} waits for ${name}`);
  });
}

test('install-lean.sh links the toolchain of formal/lean-toolchain from a digest-checked archive', () => {
  const script = read('tools/ci/install-lean.sh');
  const version = /^lean_version=(\S+)$/m.exec(script)?.[1];
  assert.equal(read('formal/lean-toolchain').trim(), `leanprover/lean4:v${version}`);
  assert.match(script, /"\$home\/bin\/elan" toolchain link "\$toolchain"/, 'lake finds it installed: elan downloads nothing');
  assert.match(script, /shasum -a 256 -c -/);
  // every pinned digest is a SHA-256 or an explicit TODO, which the script refuses to download with
  for (const [, digest] of script.matchAll(/(?:^|\s)(?:lean_)?expected=(\S+) ;;/gm)) assert.match(digest!, /^(?:[0-9a-f]{64}|TODO)$/);
  assert.match(script, /\[\[ \$2 =~ \^\[0-9a-f\]\{64\}\$ \]\] \|\| \{ echo "No SHA-256 pinned/);
});
