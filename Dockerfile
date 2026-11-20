# Base images pinned by digest (multi-arch index digest; tools/ci/checks.sh refuses a default without one).
# To move a base: docker buildx imagetools inspect <image:tag>, then replace the tag and the digest together.
ARG NODE_IMAGE=node:22.20.0-alpine@sha256:dbcedd8aeab47fbc0f4dd4bffa55b7c3c729a707875968d467aaaea42d6225af
ARG PNPM_VERSION=12.16.1
# corepack refuses a pnpm tarball whose sha512 differs (the hash corepack recorded for 12.16.1); change both together.
ARG PNPM_SHA512=091d1dee7927575661b25dab3c2ae31cafc1c54d6b71ed6a6600cf0c1cb10434a447eae14015f1b23e2e6bedeed79df94a932e2164d2832280dce3fb32f656d1
# Node 22.20's bundled corepack predates pnpm 12's layout (bin/pnpm.mjs): a pinned newer corepack activates it.
ARG COREPACK_VERSION=0.36.0
# The ops image (target "ops") must use the same C library as NODE_IMAGE: postgres:17-alpine with the alpine default,
# postgres:17 (Debian) with a Debian node image such as node:22-bookworm-slim.
ARG POSTGRES_IMAGE=postgres:17-alpine@sha256:e5d2edd28b1f8d40a0a6c0c9cdc545b19b56a0d5d88f94bc11a97d970d4700d0
# Base of the server image: runtime-base-node (default: NODE_IMAGE plus the openssl package, network needed) or
# runtime-base-postgres (POSTGRES_IMAGE, which ships openssl, plus the node binary; offline local builds).
ARG RUNTIME_BASE=runtime-base-node
# Base of the ops image: ops-base-slim (default: Alpine NODE_IMAGE plus bash and the PostgreSQL 17 client only, network
# needed) or runtime-base-postgres (the whole POSTGRES_IMAGE plus the node binary; offline local builds).
ARG OPS_BASE=ops-base-slim

FROM ${NODE_IMAGE} AS build
ARG PNPM_VERSION
ARG PNPM_SHA512
ARG COREPACK_VERSION
WORKDIR /app
RUN npm install -g corepack@${COREPACK_VERSION} && corepack enable && corepack prepare pnpm@${PNPM_VERSION}+sha512.${PNPM_SHA512} --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json ./
COPY apps/admin/package.json apps/admin/tsconfig.json apps/admin/vite.config.ts apps/admin/index.html ./apps/admin/
COPY packages/core/package.json ./packages/core/
COPY packages/pdp-http/package.json ./packages/pdp-http/
COPY packages/sql/package.json ./packages/sql/
RUN pnpm install --frozen-lockfile
COPY apps/admin/src ./apps/admin/src
COPY packages/core/src ./packages/core/src
RUN pnpm --filter @product/admin build

FROM ${NODE_IMAGE} AS production-dependencies
ARG PNPM_VERSION
ARG PNPM_SHA512
ARG COREPACK_VERSION
WORKDIR /app
RUN npm install -g corepack@${COREPACK_VERSION} && corepack enable && corepack prepare pnpm@${PNPM_VERSION}+sha512.${PNPM_SHA512} --activate
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
# every workspace manifest, so the frozen lockfile matches; --filter then installs only the server's dependencies
COPY apps/admin/package.json ./apps/admin/
COPY packages/core/package.json ./packages/core/
COPY packages/pdp-http/package.json ./packages/pdp-http/
COPY packages/sql/package.json ./packages/sql/
RUN pnpm install --frozen-lockfile --prod --filter @product/pdp-http...

# Backup and restore tools for the managed offer (deploy/k8s): PostgreSQL client tools plus node, which
# scripts/ops/*.sh use to split connection URLs and to encrypt archives (archive-crypt.ts, BACKUP_ENCRYPTION_KEY).
# Build with --target ops; the default target stays the server below.
FROM ${NODE_IMAGE} AS node-binary
FROM ${POSTGRES_IMAGE} AS runtime-base-postgres
COPY --from=node-binary /usr/local/bin/node /usr/local/bin/node
ENTRYPOINT []
# Slim ops base: no PostgreSQL server, no LLVM, no gosu, only what scripts/ops/*.sh call (bash, pg_dump, pg_restore,
# psql) beside node; the bundled package managers go, as in the server image.
FROM ${NODE_IMAGE} AS ops-base-slim
RUN command -v apk >/dev/null || { echo 'ops-base-slim needs an Alpine NODE_IMAGE; offline builds: OPS_BASE=runtime-base-postgres' >&2; exit 1; }; \
  apk upgrade --no-cache && apk add --no-cache bash postgresql17-client \
  && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg
FROM ${OPS_BASE} AS ops
WORKDIR /app
COPY --from=production-dependencies /app/node_modules ./node_modules
COPY --from=production-dependencies /app/packages/pdp-http/node_modules ./packages/pdp-http/node_modules
COPY package.json ./
COPY packages/core/package.json ./packages/core/
COPY packages/core/src ./packages/core/src
COPY packages/pdp-http/package.json ./packages/pdp-http/
COPY packages/pdp-http/src ./packages/pdp-http/src
COPY scripts/ops/audit-retention.ts scripts/ops/database-tls.ts scripts/ops/migrate-records.ts scripts/ops/replica-key.ts ./scripts/ops/
COPY scripts/ops/backup.sh scripts/ops/restore.sh scripts/ops/archive-crypt.ts /opt/gate/
# backup.sh and restore.sh run these beside themselves; node resolves the links, so their ../../packages imports land in /app
RUN ln -s /app/scripts/ops/migrate-records.ts /app/scripts/ops/database-tls.ts /opt/gate/
# The image scan blocks on fixable HIGH/CRITICAL findings: alpine packages go to their fixed versions (network; the
# Debian base of the offline local build is left as is), and the base's gosu goes (nothing here uses it: UID 1000).
# apk upgrade is deliberate: the digest-pinned base can lag behind OS fixes, so two builds of one commit may differ in
# OS package versions (the scan, not the digest, is the gate for them).
RUN if command -v apk >/dev/null; then apk upgrade --no-cache; fi; rm -f /usr/local/bin/gosu
USER 1000:1000

# The server runs `openssl ts -verify` on every RFC 3161 anchor (TSA_CA_FILE, required in production); the node
# images do not ship the openssl command.
# The server needs only the node binary: the bundled package managers (npm, corepack, yarn) and their dependencies
# are removed, and the OS packages are brought to their fixed versions (the release image scan blocks on fixable
# HIGH/CRITICAL findings).
FROM ${NODE_IMAGE} AS runtime-base-node
RUN if command -v apk >/dev/null; then apk upgrade --no-cache && apk add --no-cache openssl; \
    else apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends openssl \
      && rm -rf /var/lib/apt/lists/*; fi \
  && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg

FROM ${RUNTIME_BASE} AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8787 \
    DATA_DIR=/var/lib/gate \
    WORLD_DIR=/app/examples/toy-domain
COPY --from=production-dependencies /app/node_modules ./node_modules
COPY --from=production-dependencies /app/packages/pdp-http/node_modules ./packages/pdp-http/node_modules
COPY package.json ./
COPY packages/core/package.json ./packages/core/
COPY packages/core/src ./packages/core/src
COPY packages/pdp-http/package.json ./packages/pdp-http/
COPY packages/pdp-http/src ./packages/pdp-http/src
# pdp.ts imports the SQL compiler (/x/v1/filter); without it the server cannot start
COPY packages/sql/package.json ./packages/sql/
COPY packages/sql/src ./packages/sql/src
COPY examples/toy-domain ./examples/toy-domain
COPY --from=build /app/apps/admin/dist ./apps/admin/dist
# the only writable path: the root filesystem can be mounted read-only (docker run --read-only, compose read_only)
RUN mkdir -p /var/lib/gate && chown 1000:1000 /var/lib/gate && chmod 700 /var/lib/gate
# UID 1000: the node user of the node images (the PostgreSQL-based local image has no user of that name)
USER 1000:1000
EXPOSE 8787
VOLUME ["/var/lib/gate"]
STOPSIGNAL SIGTERM
# liveness only; a standby opens no port until it takes over, so it reports unhealthy while it waits
HEALTHCHECK --interval=15s --timeout=6s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 8787) + '/healthz', { signal: AbortSignal.timeout(5000) }).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"
CMD ["node", "packages/pdp-http/src/main.ts"]
