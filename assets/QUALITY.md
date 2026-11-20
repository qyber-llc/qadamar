# Quality checks

## Current measurements

The [README test summary](../README.md#test-it) is generated from the package and console TAP summaries of
`bash tools/ci/checks.sh`. CI compares that marked block with the run and fails on stale counts. After adding or
removing tests, run `bash tools/ci/checks.sh --update-test-counts` and commit the README change. README changes
run the gate even when every changed file is documentation. This avoids separate totals in this page and CI.md.
The summary generator tests reject missing, duplicated, unbalanced, failed, cancelled and unfinished summaries.

Each CI run reports passed, skipped and failed counts, source coverage, browser results and the Python unittest
summary. Coverage and environment-dependent pass/skip counts are measurements of that run, not a static promise.
The package total includes nested subtests; browser route subtests are discovered only when Chromium launches.
Kubernetes checks need `GATE_K8S_TEST=1` and kubectl; the Lean differential test needs the pinned toolchain.
Backup drills require PostgreSQL client tools (mandatory when CI supplies `PG_TOOLS_CONTAINER`).

The console unit suite checks server-rendered markup, all three translation catalogues, error messages and the QR
encoder. The browser suite uses the real PDP with demo data; it is required in CI and reports a clear local skip
when Chromium cannot start. Scope and remaining human checks: [ACCESSIBILITY.md](ACCESSIBILITY.md).
Fuzzing runs with `FUZZ_RUNS=2000`; `FUZZ_SEED` replays a seed. Impact fuzzing uses `IMPACT_FUZZ_RUNS`.
Performance figures in [PERFORMANCE.md](PERFORMANCE.md) are dated experiments with their workload and conditions;
they are not current CI metrics and should only change after rerunning those benchmarks.

## Coverage gate

The command, run by `tools/ci/checks.sh` (four files at a time limits password-hashing contention in wall-clock expiry tests):

```sh
node --test --test-concurrency=4 --test-reporter=tap --experimental-test-coverage \
  --test-coverage-exclude='packages/*/test/**' \
  --test-coverage-lines=85 \
  --test-coverage-branches=84 \
  --test-coverage-functions=92 \
  packages/*/test/*.test.ts
```

`checks.sh` refuses to run without `TEST_DATABASE_URL`, so the gate always measures with PostgreSQL. The thresholds
(85 / 84 / 92) are enforced against that run; skipped optional tests are reported separately. Source files no test loads are not counted. Coverage is not a
substitute for behavioural assertions, fuzzing or live-database verification.

## What `tools/ci/checks.sh` runs, in order

1. `node scripts/docs/env-table.ts --check`: [CONFIGURATION.md](CONFIGURATION.md) lists exactly the environment
   variables `packages/*/src` and the operations scripts (`scripts/ops`) read, and is up to date.
2. The `Dockerfile` runtime stage copies every package the server imports.
3. `node scripts/release/sbom.ts`: the SBOM generator still parses the lockfile (self-test included).
4. The type check (`tsc`, packages, tests and the docs, release and operations scripts).
5. The console build.
6. The coverage gate above.
7. The admin console tests.
8. Check the generated README totals against the run.
9. Browser workflow and accessibility tests (required in CI).
10. The fuzz test with 2,000 runs.
11. Python SDK unit and end-to-end tests.
