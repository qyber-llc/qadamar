#!/usr/bin/env bash
# The CI gate on this machine, no GitHub involved: throwaway PostgreSQL, checks, cleanup.
set -euo pipefail
cd "$(dirname "$0")/../.."
export CI_DB_KEY="local-$$"
trap 'bash tools/ci/postgres.sh stop' EXIT
TEST_DATABASE_URL=$(bash tools/ci/postgres.sh start)
export TEST_DATABASE_URL
# The ordinary throwaway container has no TLS; only a loopback test database may use this policy.
export DATABASE_TLS=disable
PG_TOOLS_CONTAINER="gate-ci-$(printf '%s' local/qadamar | cksum | cut -d ' ' -f 1)-${CI_DB_KEY}"
export PG_TOOLS_CONTAINER
bash tools/ci/checks.sh
