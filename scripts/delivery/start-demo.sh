#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
if [ ! -f apps/admin/dist/index.html ]; then pnpm --filter @product/admin build; fi
export HOST=127.0.0.1
export PORT="${PORT:-8789}"
export CLOCK='fixed:2026-11-08T10:00:00Z'
export WORLD_DIR=examples/qadamar-demo
export DATA_DIR="${DATA_DIR:-data/runtime/qadamar}"
export RESOURCE_OWNERS='{"ruth":["carol"]}'
exec "${NODE_BIN:-node}" packages/pdp-http/src/main.ts
