#!/usr/bin/env bash
# Throwaway PostgreSQL 17 for the tests on the CI runner. Only resources carrying this repository's label are removed:
# the runner Mac may host other containers (staging), never touched here.
set -euo pipefail
if [ "$(uname -s)" = Darwin ]; then export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"; fi
repo="${GITHUB_REPOSITORY:-local/qadamar}"
key="${CI_DB_KEY:-local}"
owner="qadamar.ci=$repo"
name="gate-ci-$(printf '%s' "$repo" | cksum | cut -d ' ' -f 1)-${key}"
case "${1:-}" in
  start)
    # the digest-pinned image of the Dockerfile, never the moving tag
    image=$(sed -n 's/^ARG POSTGRES_IMAGE=//p' "$(dirname "$0")/../../Dockerfile")
    [[ "$image" =~ ^postgres:[^@]+@sha256:[0-9a-f]{64}$ ]] || { echo 'No digest-pinned POSTGRES_IMAGE in the Dockerfile' >&2; exit 1; }
    password=$(openssl rand -hex 16)
    docker run -d --rm --name "$name" --label "$owner" --cpus=2 --memory=1g -p 127.0.0.1::5432 \
      -e POSTGRES_USER=gate -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB=gate "$image" >/dev/null
    for ((i=0; i<60; i++)); do
      docker exec "$name" pg_isready -h 127.0.0.1 -U gate -d gate >/dev/null 2>&1 && break
      sleep 1
    done
    docker exec "$name" pg_isready -h 127.0.0.1 -U gate -d gate >/dev/null || { docker logs "$name"; exit 1; }
    port=$(docker port "$name" 5432/tcp); port=${port##*:}
    [[ "$port" =~ ^[0-9]+$ ]] || { echo 'Invalid PostgreSQL port' >&2; exit 1; }
    url="postgres://gate:${password}@127.0.0.1:${port}/gate"
    # the backup/restore drill runs pg_dump and pg_restore inside this same container (no client tools needed on the runner)
    if [ -n "${GITHUB_ENV:-}" ]; then echo "::add-mask::$password"; { echo "TEST_DATABASE_URL=$url"; echo "DATABASE_TLS=disable"; echo "PG_TOOLS_CONTAINER=$name"; } >> "$GITHUB_ENV"; else echo "$url"; fi
    ;;
  stop)
    if docker container inspect "$name" >/dev/null 2>&1; then
      actual=$(docker inspect --format '{{ index .Config.Labels "qadamar.ci" }}' "$name")
      [ "$actual" = "$repo" ] || { echo 'Container not owned by this repository; left alone' >&2; exit 1; }
      docker rm -fv "$name" >/dev/null
    fi
    ;;
  *) echo 'Usage: postgres.sh start|stop' >&2; exit 2 ;;
esac
