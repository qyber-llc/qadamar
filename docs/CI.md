# CI without paying GitHub for runner minutes

- **Where it runs.** `.github/workflows/ci.yml` uses `runs-on: ${{ vars.CI_RUNNER || 'ubuntu-latest' }}`. Unset, every job runs on
  GitHub-hosted Linux. Setting the repository Actions variable **`CI_RUNNER`** to a self-hosted runner label moves the
  jobs there; on a public repository, never do this for pull requests from forks, which would run untrusted code on that machine.
- **When it runs.** Pull requests (opened, updated, reopened, marked ready; drafts skipped), pushes to `main`, and
  manual runs. Pushes to other branches without a PR run nothing. A newer push cancels the running one, except on `main`.
- **What it runs.** The main job: Gitleaks over the whole history (pinned version and SHA-256), then, unless
  only Markdown or `docs/` changed (except README, `docs/CONFIGURATION.md` and CHANGELOG, whose measured content or
  version always runs the gate), `pnpm install --frozen-lockfile` and `tools/ci/checks.sh`: the configuration-table
  check (`scripts/docs/env-table.ts --check`), the Dockerfile copy check, the SBOM generator self-test, the type check,
  the console build, all package tests with source line/branch/function coverage thresholds of 85%/84%/92% against a
  throwaway PostgreSQL 17 (Docker, labelled, 2 CPUs, 1 GiB, removed at the end, nothing else on the Mac touched), the
  admin console unit and markup tests, browser workflows, the checked README test summary, the fuzz tests with 2,000 runs, and the Python SDK tests (`sdks/python`, standard library
  `unittest`, its end-to-end test against the real PDP included). The measured local baseline and the exact coverage command are recorded
  in [QUALITY.md](QUALITY.md); the limits of the markup tests are recorded in [ACCESSIBILITY.md](ACCESSIBILITY.md).
- **Dependency vulnerability scan.** After the install, `pnpm audit --prod --audit-level high` checks the production
  dependency tree of the lockfile (every workspace package's `dependencies`, not the build and test tooling) against
  the npm registry's advisories and fails the job on any high or critical one; moderate and low are printed and pass.
  It runs in `ci.yml` (skipped with the rest when only docs changed) and in `release.yml` before the gate, so no tag is
  packed over a known high/critical advisory. It is a workflow step, not part of `tools/ci/checks.sh`: it needs the
  registry, and `checks.sh` is also what `local.sh` runs on a laptop, which must keep working offline and must not
  fail for an advisory published since the last commit. A new advisory can turn CI red on a pull request that touched
  no dependency: upgrade (or override in `pnpm.overrides`) the affected package in its own commit. Run it by hand with
  the same command. Last local run (2026-11-10, pnpm 12.16.1): "No known vulnerabilities found", also with dev dependencies.
- **SAST (Semgrep).** After the dependency scan, the official
  `semgrep/semgrep:1.95.0@sha256:30e6afa99ebd8e7b4115d4904898108eb4bf77025819e9263f09cf14e6f6e549` container scans the shipped
  TypeScript (`--config p/javascript --config p/typescript --config p/nodejsscan`, the registry rulesets for JavaScript,
  TypeScript and Node.js) and fails the job on any finding of `ERROR` severity (`--severity ERROR --error`); warnings
  are not reported. `.semgrepignore` leaves out tests, browser checks, examples, docs and build output (they hold
  deliberate fake secrets and hostile inputs). Same step in `release.yml`. The image is pinned by tag and SHA-256 digest.
  It downloads the image and the rulesets, so it is a workflow step, not part of `checks.sh` (offline on a laptop). Any
  `ERROR` finding blocks until fixed or justified with a `nosemgrep` comment that names the reason.
- **Formal model (Lean 4), job `formal`.** `tools/ci/install-lean.sh` installs elan 4.2.4 and the Lean toolchain of
  `formal/lean-toolchain` (v4.35.0), each from its release archive pinned by SHA-256; the toolchain is registered with
  `elan toolchain link`, so `lake` never makes elan download an unchecked archive, and a digest not yet pinned stops
  the job. Then `formal/check.sh` builds the model and its proofs and fails on any `sorry` or non-standard axiom, and
  `packages/core/test/lean-differential.test.ts` runs 10,000 cases with `LEAN_REQUIRED=1`. This third-party code runs
  in its own job with `permissions: contents: read`; the `ci` job and, in `release.yml`, the `release` job (the only one
  with `contents: write`) wait for it (`needs: formal`). In `checks.sh` the differential test skips when no toolchain
  is installed. See [spec/FORMAL-MODEL.md](spec/FORMAL-MODEL.md).
- **Container vulnerability scan (Trivy).** After the whole CI gate, a separate `image-scan` job with `contents: read`
  builds the Dockerfile's default runtime target as `gate-release:<commit>` and its `ops` target as `gate-ops:<commit>`,
  exports both with `docker save` and scans the tars with
  `aquasec/trivy:0.67.2@sha256:e2b22eac59c02003d8749f5b8d9bd073b62e30fefaef5b7c8371204e0a4b0c08`.
  The scanner gets only each tar read-only, never `/var/run/docker.sock`; `trivy image --input` needs no daemon access.
  Before the ops scan, `tools/ci/ops-image-drill.sh` runs the built image's own `/opt/gate/backup.sh` and
  `/opt/gate/restore.sh` as its unprivileged user against a throwaway PostgreSQL and requires the same row count in
  every `gate_*` table after the restore (the release image seeds the source database: the ops image ships no server
  code); the job fails if the image cannot back up and restore.
  `ci.yml` skips this job for docs-only changes. `release.yml` makes its publish job (alone holding `contents: write`)
  wait for a successful scan. `--severity HIGH,CRITICAL --ignore-unfixed --exit-code 1` blocks exactly high/critical
  vulnerabilities with a fix available; unfixed advisories are reported but do not block.
  No `.trivyignore` is present: there are no accepted exceptions. If one becomes necessary, add only specific CVE IDs
  with a short justification and review/expiry date, and keep the exception as small and short-lived as possible. The
  scanner image and its vulnerability database need network access, so this is a workflow step, not `checks.sh`; it has
  not been run locally (no image pulls are allowed here), and its first CI run must succeed before a release is packed.
- **Browser checks in the gate.** `checks.sh` runs `pnpm --filter @product/admin e2e`. The read-only CI and release
  test jobs first run `node tools/ci/install-playwright.ts`, which pins the external browser tooling in
  `tools/ci/playwright-lock.json`: Playwright 1.64.1 (SHA-512 archive integrity), Chromium revision 1248 / Chrome for
  Testing 156.0.8078.4. There was no Playwright entry in the workspace lockfile; no workspace dependency is added.
  The installer verifies archives before extracting and never runs Playwright's unpinned browser downloader.
  The macOS arm64 runner may use the existing headless shell whose executable SHA-256 is committed in that lock.
  The Linux x86-64 and macOS arm64 archives (`chrome-headless-shell-linux64.zip`, `-mac-arm64.zip`) are pinned in the
  same lock (`linux64ArchiveSha256`, `macArm64ArchiveSha256`,
  recorded on 2026-11-11 from Google's Chrome for Testing storage over HTTPS; Google publishes no reference digest,
  so the pin fixes the archive as first fetched). A repository variable `CI_CHROMIUM_SHA256` overrides it for another
  runner; a missing pin fails before any browser download.
  The installer exports `PLAYWRIGHT_CORE_PATH`, optional `PLAYWRIGHT_BROWSERS_PATH`, and `E2E_REQUIRED=1` through
  `GITHUB_ENV`. A missing or unlaunchable browser fails CI; local runs report a clear skip and stay offline.
  See [ACCESSIBILITY.md](ACCESSIBILITY.md) for test scope, and [QUALITY.md](QUALITY.md) for generated counts.
- **On a laptop, free.** `bash tools/ci/local.sh` runs the same gate with Docker, no GitHub involved (no dependency scan:
  run `pnpm audit --prod --audit-level high` yourself when online).
- **Releases.** `.github/workflows/release.yml` runs on `v*` tags, on the same runner variable: the same gate, then
  `scripts/release/pack.sh` and `gh release create` ([RELEASE.md](RELEASE.md)). It needs the `gh` CLI on the runner.
- **Runner Mac needs:** Git, Bash, Xcode command line tools, OpenSSL, Docker Desktop running. Node and pnpm are set up
  by the workflow. Keep the runner at one job at a time if it also hosts staging.

This repository is public. CI runs on GitHub-hosted `ubuntu-latest`: no self-hosted runner is registered and
`CI_RUNNER` is not set. Pull requests from forks run with a read-only token and no secrets, and a first-time
contributor's run waits for a maintainer's approval. Do not set `CI_RUNNER` to a self-hosted runner here: pull requests
would then run untrusted code (`pnpm install` and its install scripts, `tools/ci/*.sh`, `docker build`) on the machine
that also holds the release job's `contents: write` token. Keep a self-hosted runner for a private mirror only.
