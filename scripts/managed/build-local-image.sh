#!/usr/bin/env bash
# Builds gate:local and gate-ops:local for the local overlay (deploy/k8s/overlays/local) WITHOUT network access:
# the console bundle and the server's production dependencies are prepared on this machine from the pnpm store
# (pnpm --offline) and handed to the Dockerfile as named build contexts that replace its `build` and
# `production-dependencies` stages, so neither corepack nor the registry is reached. Base images must already be local.
# The server image is based on POSTGRES_IMAGE plus the node binary (RUNTIME_BASE=runtime-base-postgres): that image
# ships the openssl command the server needs to verify RFC 3161 anchors, and installing it on the node image would need
# the network. Release images are built by the plain Dockerfile (pinned alpine base plus openssl, network), not here.
set -euo pipefail
cd "$(dirname "$0")/../.."
NODE_IMAGE=${NODE_IMAGE:-node:22-bookworm-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d}
POSTGRES_IMAGE=${POSTGRES_IMAGE:-postgres:17@sha256:2d2b8998d31037bf721cfdf764d76ba74171b4fab3431b7f72c27c56ddbdf9e3}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pnpm --filter @product/admin build >/dev/null
mkdir -p "$work/console/app/apps/admin" "$work/deps/app/node_modules" "$work/deps/app/packages/pdp-http"
cp -R apps/admin/dist "$work/console/app/apps/admin/"
pnpm --filter @product/pdp-http deploy --prod --offline "$work/pdp-http" >/dev/null
cp -R "$work/pdp-http/node_modules" "$work/deps/app/packages/pdp-http/"

docker build -q --pull=false --build-arg NODE_IMAGE="$NODE_IMAGE" --build-arg POSTGRES_IMAGE="$POSTGRES_IMAGE" --build-arg RUNTIME_BASE=runtime-base-postgres \
  --build-context build="$work/console" --build-context production-dependencies="$work/deps" -t gate:local . >/dev/null
docker build -q --pull=false --build-arg NODE_IMAGE="$NODE_IMAGE" --build-arg POSTGRES_IMAGE="$POSTGRES_IMAGE" \
  --build-arg OPS_BASE=runtime-base-postgres --target ops -t gate-ops:local . >/dev/null
printf 'Built gate:local and gate-ops:local (base %s, %s).\n' "$NODE_IMAGE" "$POSTGRES_IMAGE"
