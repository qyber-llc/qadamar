import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../../..');
const read = (name: string): string => readFileSync(resolve(root, '.github/workflows', name), 'utf8');

test('workflow checkouts do not persist credentials', () => {
  for (const name of ['ci.yml', 'release.yml']) {
    const checkouts = [...read(name).matchAll(/- uses: actions\/checkout@[^\n]+\n        with:\n((?:          .*\n)+)/g)];
    assert.ok(checkouts.length > 0, `${name}: checkouts found`);
    for (const checkout of checkouts) assert.match(checkout[1]!, /^          persist-credentials: false(?: #.*)?$/m, `${name}: credentials are not persisted`);
  }
});

test('every container image the workflows run is pinned by digest', () => {
  let seen = 0;
  for (const name of ['ci.yml', 'release.yml']) {
    const workflow = read(name);
    // images named in env (*_IMAGE), in `image:` / `container:` keys, in `uses: docker://` and directly after `docker run`
    const refs = [
      ...[...workflow.matchAll(/^\s*[A-Z_]*IMAGE:\s*(\S+)\s*$/gm)].map((m) => m[1]!),
      ...[...workflow.matchAll(/^\s*(?:image|container):\s*([^\s{]\S*)\s*$/gm)].map((m) => m[1]!),
      ...[...workflow.matchAll(/uses:\s*docker:\/\/(\S+)/g)].map((m) => m[1]!),
    ];
    for (const ref of refs) {
      seen++;
      assert.match(ref, /^[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}$/, `${name}: ${ref} needs a tag and an @sha256 digest`);
    }
    for (const run of workflow.matchAll(/docker run\b/g)) {
      const command = workflow.slice(run.index, run.index + 200);
      assert.match(command, /"\$[A-Z_]*IMAGE"/, `${name}: docker run names its image through a pinned *_IMAGE variable`);
    }
  }
  assert.ok(seen >= 4, `the Semgrep and Trivy images of both workflows (${seen})`);
});

test('container scans are digest-pinned, socketless and isolated from release permissions', () => {
  const release = read('release.yml');
  const ci = read('ci.yml');
  for (const [name, workflow] of [['release', release], ['ci', ci]] as const) {
    assert.match(workflow, /aquasec\/trivy:0\.67\.2@sha256:[0-9a-f]{64}/, `${name}: pin the scanner tag and digest`);
    assert.doesNotMatch(workflow, /\/var\/run\/docker\.sock/, `${name}: never give the scanner the Docker socket`);
    assert.match(workflow, /docker save --output gate-release\.tar "gate-release:\$\{GITHUB_SHA\}"/, `${name}: export the image for an offline scan`);
    assert.match(workflow, /image\s+--input \/tmp\/gate-release\.tar/, `${name}: scan the tar, not through Docker`);
    assert.match(workflow, /image-scan:\n/, `${name}: a separate scan job`);
  }
  assert.match(release, /test:\n\s+needs: formal\n\s+permissions:\n\s+contents: read/, 'the test job does not need release write permission');
  assert.match(release, /image-scan:\n\s+needs: \[formal, test\]\n\s+permissions:\n\s+contents: read/, 'the scan job is read-only and follows the gate');
  assert.match(release, /release:\n\s+needs: \[formal, image-scan\]\n\s+permissions:\n\s+contents: write/, 'only publishing needs write permission, after the Lean proofs and the scan');
  const publish = release.slice(release.indexOf('\n  release:\n'));
  for (const forbidden of [/install-lean|elan|lake /, /docker/, /semgrep|trivy|gitleaks/i]) {
    assert.doesNotMatch(publish, forbidden, `the write job downloads no toolchain and mounts no Docker socket (${forbidden})`);
  }
  assert.match(ci, /image-scan:\n\s+needs: \[formal, ci\]\n\s+if: needs\.ci\.outputs\.docs_only != 'true'\n\s+permissions:\n\s+contents: read/,
    'CI uses the same read-only scan job and skips docs-only changes');
});

test('container scans cover the ops image used by deployment jobs', () => {
  const jobs = readFileSync(resolve(root, 'deploy/k8s/base/jobs.yaml'), 'utf8');
  assert.match(jobs, /image: gate-ops/);
  for (const name of ['ci.yml', 'release.yml']) {
    const workflow = read(name);
    assert.match(workflow, /docker build --target ops --tag "gate-ops:\$\{GITHUB_SHA\}" \./, `${name}: build the ops target`);
    assert.match(workflow, /bash tools\/ci\/ops-image-drill\.sh "gate-release:\$\{GITHUB_SHA\}" "gate-ops:\$\{GITHUB_SHA\}"/, `${name}: backup and restore drill on the built ops image`);
    assert.match(workflow, /docker save --output gate-ops\.tar "gate-ops:\$\{GITHUB_SHA\}"/, `${name}: export the ops image`);
    const scan = workflow.slice(workflow.indexOf('- name: Ops image vulnerability scan'));
    assert.match(scan, /-v "\$PWD\/gate-ops\.tar:\/tmp\/gate-ops\.tar:ro"/, `${name}: mount only the ops tar`);
    assert.match(scan, /--input \/tmp\/gate-ops\.tar\s+--scanners vuln\s+--severity HIGH,CRITICAL\s+--ignore-unfixed\s+--exit-code 1/, `${name}: scan ops with the release gate`);
  }
});

test('the Lean proofs run in their own read-only job that CI and the release need', () => {
  assert.match(read('release.yml'), /\n  release:\n(?:.*\n)*?      - uses: actions\/checkout@[0-9a-f]{40} # v[\d.]+\n        with:\n          persist-credentials: false\b/,
    'the contents: write job keeps no git credential where pnpm install scripts run (gh uses GH_TOKEN)');
  assert.match(read('release.yml'), /\n  release:\n(?:.*\n)*?.*git merge-base --is-ancestor "\$GITHUB_SHA" origin\/main/,
    'a release ships only a commit main already holds, never a tag pushed on a side branch');
  assert.match(read('release.yml'), /ELAN_HOME="\$RUNNER_TEMP\/elan" bash tools\/ci\/install-lean\.sh/,
    'the release installs a fresh, digest-checked Lean toolchain, never one left on a persistent runner');
  assert.match(readFileSync(resolve(root, 'tools/ci/postgres.sh'), 'utf8'), /ARG POSTGRES_IMAGE=/,
    'the test database runs the digest-pinned image of the Dockerfile, not a moving tag');
  for (const name of ['ci.yml', 'release.yml']) {
    const workflow = read(name);
    assert.match(workflow, /\n  formal:\n(?:    .*\n)*?    permissions:\n      contents: read\n/, `${name}: formal is read-only`);
    const formal = /\n  formal:\n((?:    .*\n|      .*\n|\n)*?)  [a-z-]+:\n/.exec(workflow)?.[1] ?? '';
    assert.match(formal, /bash tools\/ci\/install-lean\.sh/, `${name}: the toolchain is installed in the formal job`);
    assert.match(formal, /LEAN_REQUIRED: '1'/, `${name}: the differential test cannot skip there`);
    assert.doesNotMatch(formal, /contents: write|docker/, `${name}: no write token or Docker in the formal job`);
  }
  assert.match(read('ci.yml'), /\n  ci:\n    needs: formal\n/, 'the CI gate waits for the proofs');
  for (const name of ['ci.yml', 'release.yml']) {
    // two-space job keys, four-space job fields: a stray indent would silently move a key into another job
    const jobs = read(name).slice(read(name).indexOf('\njobs:\n'));
    const keys = [...jobs.matchAll(/^  ([a-z-]+):$/gm)].map((m) => m[1]);
    assert.deepEqual(keys, name === 'ci.yml' ? ['formal', 'ci', 'image-scan'] : ['formal', 'test', 'image-scan', 'release'], `${name} jobs`);
    for (const job of jobs.split(/\n  (?=[a-z-]+:\n)/).slice(1)) {
      const fields = [...job.matchAll(/^    ([a-z-]+):/gm)].map((m) => m[1]);
      assert.equal(new Set(fields).size, fields.length, `${name}: no duplicate key in job ${job.slice(0, job.indexOf(':'))}: ${fields}`);
    }
  }
});

test('browser workflows are required in read-only test jobs with hash-verified tooling', () => {
  const installer = readFileSync(resolve(root, 'tools/ci/install-playwright.ts'), 'utf8');
  const lock = JSON.parse(readFileSync(resolve(root, 'tools/ci/playwright-lock.json'), 'utf8'));
  assert.match(lock.version, /^\d+\.\d+\.\d+$/);
  assert.match(lock.integrity, /^sha512-[A-Za-z0-9+/]{86}==$/);
  assert.match(lock.darwinArm64ExecutableSha256, /^[a-f0-9]{64}$/);
  assert.match(installer, /actual !== expected/);
  assert.match(installer, /Browser downloads without an archive pin are refused/);
  assert.match(installer, /E2E_REQUIRED=1/);
  assert.doesNotMatch(installer, /cli\.js.*install|npx |npm install/);
  assert.ok(installer.indexOf("download(`https://registry.npmjs.org") < installer.indexOf("execFileSync('tar'"));
  assert.ok(installer.indexOf('download(pinned.url') < installer.indexOf("execFileSync('unzip'"));
  for (const name of ['ci.yml', 'release.yml']) {
    const workflow = read(name);
    assert.match(workflow, /node tools\/ci\/install-playwright\.ts/);
    assert.match(workflow, /CI_CHROMIUM_SHA256: \$\{\{ vars\.CI_CHROMIUM_SHA256 \}\}/);
    assert.ok(workflow.indexOf('node tools/ci/install-playwright.ts') < workflow.indexOf('run: bash tools/ci/checks.sh'));
  }
  assert.match(read('ci.yml'), /ci:\n    needs: formal\n    permissions:\n      contents: read/);
  const checks = readFileSync(resolve(root, 'tools/ci/checks.sh'), 'utf8');
  assert.match(checks, /pnpm --filter @product\/admin e2e/);
  assert.match(checks, /node scripts\/docs\/test-summary\.ts/);
  assert.match(checks, /--test-concurrency=4/);
  const docsOnly = readFileSync(resolve(root, 'tools/ci/docs-only.sh'), 'utf8');
  assert.match(docsOnly, /README\.md\) echo docs_only=false/);
  assert.match(docsOnly, /docs\/spec\/\*\) echo docs_only=false/, 'the specification under docs/spec is read by the tests: a change to it runs the gate');
});

test('docs-only changes still run the gate for files it checks', () => {
  const docsOnly = readFileSync(resolve(root, 'tools/ci/docs-only.sh'), 'utf8');
  assert.match(docsOnly, /docs\/CONFIGURATION\.md\|CHANGELOG\.md\) echo docs_only=false/);
});

test('CI browser provisioning rejects unpinned downloads and altered archives', async () => {
  const { browserArchive, verifyArchive } = await import('../../../tools/ci/install-playwright.ts');
  const { createHash } = await import('node:crypto');
  const bytes = Buffer.from('pinned archive fixture');
  for (const [algorithm, encoding] of [['sha256', 'hex'], ['sha512', 'base64']] as const) {
    const digest = createHash(algorithm).update(bytes).digest(encoding);
    assert.doesNotThrow(() => verifyArchive(bytes, algorithm, digest, encoding));
    assert.throws(() => verifyArchive(Buffer.from('tampered archive'), algorithm, digest, encoding), /checksum mismatch/);
  }
  for (const missing of [undefined, '', 'latest', 'A'.repeat(64), '0'.repeat(63)]) assert.throws(() => browserArchive('linux64', missing), /without an archive pin/);
  const pin = 'a'.repeat(64);
  assert.match(browserArchive('linux64', pin).url, /156\.0\.8078\.4\/linux64\/chrome-headless-shell-linux64\.zip$/);
  assert.equal(browserArchive('mac-arm64', pin).checksum, pin);
  assert.throws(() => browserArchive('unknown', pin), /Unsupported/);
});
