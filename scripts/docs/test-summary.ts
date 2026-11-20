import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

export interface Counts { tests: number; pass: number; fail: number; skipped: number }

/** Only the final TAP summary counts; diagnostic text and nested subtests do not add to it. */
export function parseSummary(text: string): Counts {
  const count = (key: string): number => {
    const matches = [...text.matchAll(new RegExp(`^# ${key} (\\d+)$`, 'gm'))];
    if (matches.length !== 1) throw new Error(`Expected one TAP ${key} summary`);
    return Number(matches[0]![1]);
  };
  const result = { tests: count('tests'), pass: count('pass'), fail: count('fail'), skipped: count('skipped') };
  if (result.fail || count('cancelled') || count('todo')) throw new Error('Cannot publish counts from an incomplete or failing test run');
  if (result.tests !== result.pass + result.skipped) throw new Error('TAP summary does not balance');
  return result;
}

export function replaceBlock(text: string, counts: { packages: Counts; console: Counts }): string {
  const start = '<!-- test-summary:start -->';
  const end = '<!-- test-summary:end -->';
  if (text.split(start).length !== 2 || text.split(end).length !== 2 || text.indexOf(start) > text.indexOf(end)) {
    throw new Error('README needs exactly one ordered test-summary block');
  }
  const block = `${start}\nMeasured by \`bash tools/ci/checks.sh\` (Node TAP totals, including subtests):\n\n| Suite | Tests |\n|---|---:|\n| Packages | ${counts.packages.tests} |\n| Console unit / markup | ${counts.console.tests} |\n\nPass, skip, coverage, browser and Python results are reported by each CI run; optional tools change skips.\nBrowser totals include route subtests only when Chromium runs. See [QUALITY.md](docs/QUALITY.md).\n${end}`;
  return text.slice(0, text.indexOf(start)) + block + text.slice(text.indexOf(end) + end.length);
}

if (process.argv[1] && resolve(process.argv[1]) === import.meta.filename) {
  const [packagesPath, consolePath, mode] = process.argv.slice(2);
  if (!packagesPath || !consolePath || !['--check', '--write'].includes(mode ?? '')) throw new Error('Usage: test-summary.ts packages.tap console.tap --check|--write');
  const counts = { packages: parseSummary(readFileSync(packagesPath, 'utf8')), console: parseSummary(readFileSync(consolePath, 'utf8')) };
  const path = resolve(import.meta.dirname, '../../README.md');
  const current = readFileSync(path, 'utf8');
  const next = replaceBlock(current, counts);
  if (mode === '--write') writeFileSync(path, next);
  else if (current !== next) throw new Error('README test counts are stale: run bash tools/ci/checks.sh --update-test-counts');
  console.log(`Test counts: packages ${counts.packages.tests} (${counts.packages.pass} passed, ${counts.packages.skipped} skipped); console ${counts.console.tests} (${counts.console.pass} passed)`);
}
