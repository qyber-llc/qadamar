import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSummary, replaceBlock } from '../../../scripts/docs/test-summary.ts';

const tap = '# tests 10\n# pass 8\n# fail 0\n# cancelled 0\n# skipped 2\n# todo 0\n';
test('documentation counts come from one complete successful TAP summary', () => {
  assert.deepEqual(parseSummary(tap), { tests: 10, pass: 8, fail: 0, skipped: 2 });
  for (const bad of [tap.replace('# fail 0', '# fail 1'), tap.replace('# cancelled 0', '# cancelled 1'), tap.replace('# todo 0', '# todo 1'), tap.replace('# tests 10', '# tests 11'), tap + '# tests 10\n', '']) {
    assert.throws(() => parseSummary(bad));
  }
});
test('generated documentation replaces only its unique marked block and detects stale counts', () => {
  const original = 'before\n<!-- test-summary:start -->\nstale\n<!-- test-summary:end -->\nafter';
  const counts = parseSummary(tap);
  const next = replaceBlock(original, { packages: counts, console: counts });
  assert.match(next, /^before\n/);
  assert.match(next, /\| Packages \| 10 \|/);
  assert.match(next, /\nafter$/);
  assert.equal(replaceBlock(next, { packages: counts, console: counts }), next);
  assert.notEqual(replaceBlock(next, { packages: { ...counts, tests: 11 }, console: counts }), next);
  for (const bad of ['', original + original, '<!-- test-summary:end --><!-- test-summary:start -->']) assert.throws(() => replaceBlock(bad, { packages: counts, console: counts }));
});
