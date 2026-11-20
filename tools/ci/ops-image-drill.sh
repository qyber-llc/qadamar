#!/usr/bin/env bash
# Backup and restore drill inside the built ops image: the scripts and tools deployment jobs really run (uid 1000,
# /opt/gate, the image's own pg client and node), against a throwaway PostgreSQL that is removed afterwards.
# The release image seeds the source database: the ops image deliberately ships no server code.
set -euo pipefail
release="${1:?Usage: ops-image-drill.sh <release image> <ops image>}"
ops="${2:?Usage: ops-image-drill.sh <release image> <ops image>}"
cd "$(dirname "$0")/../.."
export CI_DB_KEY="ops-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-$$}"
env_file=$(mktemp)
trap 'rm -f "$env_file"; bash tools/ci/postgres.sh stop' EXIT
# postgres.sh reports through a GITHUB_ENV file and masks the password in the job log; a private file keeps the
# database out of later steps, and outside Actions the mask line would only print the password
if [ -n "${GITHUB_ACTIONS:-}" ]; then GITHUB_ENV="$env_file" bash tools/ci/postgres.sh start
else GITHUB_ENV="$env_file" bash tools/ci/postgres.sh start >/dev/null; fi
url=$(grep '^TEST_DATABASE_URL=' "$env_file"); url=${url#*=}
name=$(grep '^PG_TOOLS_CONTAINER=' "$env_file"); name=${name#*=}
# the drill shares the database container's network, so the server is at its own port there
export ADMIN_URL="${url%@*}@127.0.0.1:5432/gate"
export SOURCE_URL="${ADMIN_URL%/*}/gate_drill_source"
docker exec "$name" psql -U gate -d gate -q -v ON_ERROR_STOP=1 -c 'CREATE DATABASE gate_drill_source'
# a first start creates the schema and seeds the demo records; its output is shown only when it fails
if ! seed=$(docker run --rm --pull=never --entrypoint node --network "container:$name" -e SOURCE_URL -e DATABASE_TLS=disable \
  "$release" --input-type=module -e "
    import { mkdtempSync } from 'node:fs';
    import { randomBytes } from 'node:crypto';
    import { createServer } from '/app/packages/pdp-http/src/server.ts';
    const server = createServer({ port: 0, dataDir: mkdtempSync('/tmp/gate-drill-'), databaseUrl: process.env.SOURCE_URL, signingKeySeal: randomBytes(32).toString('base64url') });
    await server.listen();
    await server.close();" 2>&1); then echo "$seed" >&2; exit 1; fi
drill=$(cat <<'DRILL'
set -euo pipefail
dir=$(mktemp -d)
BACKUP_ENCRYPTION_KEY=$(node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))")
export BACKUP_ENCRYPTION_KEY MAINTENANCE_DATABASE_URL="$ADMIN_URL" BACKUP_FILE="$dir/gate.dump"
restored_url="${ADMIN_URL%/*}/gate_drill_restored"
counts() {
  psql "$1" -At -v ON_ERROR_STOP=1 -c "SELECT format('SELECT %L, count(*) FROM %I;', tablename, tablename) FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'gate\_%' ORDER BY 1" | psql "$1" -At -v ON_ERROR_STOP=1
}
before=$(counts "$SOURCE_URL")
grep -qE '\|[1-9]' <<<"$before" || { echo 'The source database has no rows: the drill would prove nothing' >&2; exit 1; }
DATABASE_URL="$SOURCE_URL" /opt/gate/backup.sh
# restore.sh creates its target database itself
DATABASE_URL="$restored_url" /opt/gate/restore.sh
after=$(counts "$restored_url")
[ "$before" = "$after" ] || { echo 'Row counts differ after restore (source, then restored):' >&2; printf '%s\n--\n%s\n' "$before" "$after" >&2; exit 1; }
echo "Ops image drill passed: $(grep -c . <<<"$before") tables restored with matching row counts"
DRILL
)
docker run --rm --pull=never --entrypoint bash --network "container:$name" -e ADMIN_URL -e SOURCE_URL -e DATABASE_TLS=disable "$ops" -c "$drill"
