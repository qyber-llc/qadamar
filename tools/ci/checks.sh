#!/usr/bin/env bash
# The gate CI runs, and what `bash tools/ci/local.sh` runs on a laptop for free.
set -euo pipefail
summary_dir=$(mktemp -d)
trap 'rm -rf "$summary_dir"' EXIT
summary_mode=--check
case "${1:-}" in
  '') ;;
  --update-test-counts) summary_mode=--write ;;
  *) echo 'Usage: checks.sh [--update-test-counts]' >&2; exit 1 ;;
esac
# docs/CONFIGURATION.md lists exactly the environment variables packages/*/src reads
node scripts/docs/env-table.ts --check
# the image's runtime stage copies every package the server imports (a missing one only fails when the image starts)
# shortcut: scans direct ../../<pkg>/src imports of the server's packages; extend the list if they import a new package
for pkg in $(grep -rhoE "\.\./\.\./(\.\./)?[a-z-]+/src/" packages/pdp-http/src packages/core/src packages/sql/src | sed -E 's#.*\.\./([a-z-]+)/src/#\1#' | sort -u) pdp-http; do
  grep -q "^COPY packages/$pkg/src " Dockerfile || { echo "Dockerfile runtime stage does not copy packages/$pkg/src" >&2; exit 1; }
done
# base images stay pinned by digest (a tag alone can be re-pointed upstream)
if grep -E '^ARG (NODE|POSTGRES)_IMAGE=' Dockerfile | grep -v '@sha256:[0-9a-f]\{64\}$'; then echo 'Dockerfile base image default without a digest' >&2; exit 1; fi
# one product version: the server, core, sql and console manifests agree with the latest CHANGELOG release
node -e '
const fs = require("fs");
const files = ["packages/pdp-http", "packages/core", "packages/sql", "apps/admin"].map((d) => d + "/package.json");
const versions = files.map((f) => JSON.parse(fs.readFileSync(f, "utf8")).version);
const released = (fs.readFileSync("CHANGELOG.md", "utf8").match(/^## \[(\d+\.\d+\.\d+)\]/m) || [])[1];
if (new Set(versions).size !== 1 || versions[0] !== released) { console.error("version mismatch:", files.map((f, i) => f + "=" + versions[i]).join(" "), "CHANGELOG=" + released); process.exit(1); }
'
# the SBOM generator still parses the lockfile (self-test included)
node scripts/release/sbom.ts > /dev/null
npx tsc -p tsconfig.json
pnpm --filter @product/admin build
: "${TEST_DATABASE_URL:?TEST_DATABASE_URL must point at a throwaway PostgreSQL (tools/ci/postgres.sh start)}"
# When CI supplies the client tools through a container, an unavailable drill is a failure, never a skip.
if [ -n "${PG_TOOLS_CONTAINER:-}" ]; then export BACKUP_TESTS_REQUIRED=1; fi
# packages/core/test/lean-differential.test.ts runs (2,000 cases) wherever lake is found (PATH, ~/.elan/bin, $LAKE) and
# skips otherwise, so this needs no Lean and stays offline; CI installs the pinned toolchain and runs it with
# LEAN_REQUIRED=1 after formal/check.sh (docs/spec/FORMAL-MODEL.md)
# thresholds a little below the measured source coverage without PostgreSQL (docs/QUALITY.md); test files excluded
# Bound password-hashing contention so wall-clock expiry tests also run on busy runners.
node --test --test-concurrency=4 --test-reporter=tap --experimental-test-coverage \
  --test-coverage-exclude='packages/*/test/**' \
  --test-coverage-exclude='examples/*/test/**' \
  --test-coverage-lines=85 \
  --test-coverage-branches=84 \
  --test-coverage-functions=92 \
  packages/*/test/*.test.ts | tee "$summary_dir/packages.tap"
pnpm --filter @product/admin test | tee "$summary_dir/console.tap"
node scripts/docs/test-summary.ts "$summary_dir/packages.tap" "$summary_dir/console.tap" "$summary_mode"
# launch() gives a clear local skip; E2E_REQUIRED=1 makes missing Chromium fatal in CI.
pnpm --filter @product/admin e2e
FUZZ_RUNS=2000 node --test packages/core/test/fuzz.test.ts
# the Python SDK (standard library only, offline): unit tests, RFC 8032 vectors, and its end-to-end run against the real PDP
(cd sdks/python && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests)
