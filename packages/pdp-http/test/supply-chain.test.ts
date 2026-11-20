// Build and deploy inputs that must be pinned by content, not by a name that can be re-pointed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { relative, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../../..');
const read = (file: string): string => readFileSync(resolve(root, file), 'utf8');

test('the image build activates pnpm by version and sha512 hash, never by version alone', () => {
  const dockerfile = read('Dockerfile');
  assert.match(dockerfile, /^ARG PNPM_SHA512=[0-9a-f]{128}$/m);
  const prepares = [...dockerfile.matchAll(/corepack prepare (\S+)/g)].map((m) => m[1]);
  assert.ok(prepares.length >= 2, 'both install stages');
  for (const spec of prepares) assert.equal(spec, 'pnpm@${PNPM_VERSION}+sha512.${PNPM_SHA512}');
});

const k8s = process.env.GATE_K8S_TEST === '1' ? false : 'set GATE_K8S_TEST=1 to render overlays (needs kubectl; no cluster is contacted)';
test('new-tenant.sh refuses a non-local overlay whose images are named by tag, and renders one by digest', { skip: k8s }, (t) => {
  // an overlay outside deploy/k8s/overlays/local*: the base as is, images by tag
  const dir = realpathSync(mkdtempSync(resolve(tmpdir(), 'gate-tag-overlay-')));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(resolve(dir, 'kustomization.yaml'), `resources: [${relative(dir, resolve(root, 'deploy/k8s/base'))}]\n`);
  const run = (overlay: string) => spawnSync('bash', [resolve(root, 'scripts/managed/new-tenant.sh'), 'acme'], {
    env: { ...process.env, OVERLAY: overlay, KUBE_CONTEXT: '', RENDER_ONLY: '1' }, encoding: 'utf8' });
  const tagged = run(dir);
  assert.equal(tagged.status, 1, tagged.stderr);
  assert.match(tagged.stderr, /by digest/);
  const sovereign = run('sovereign-uae');
  assert.equal(sovereign.status, 0, sovereign.stderr);
});
