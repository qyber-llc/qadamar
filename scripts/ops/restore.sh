#!/usr/bin/env bash
set -euo pipefail
umask 077

TABLES=(gate_doc gate_audit gate_audit_meta gate_anchor gate_audit_segment gate_subject_identity gate_sync gate_token gate_performed gate_session gate_blp_mark gate_blp_session gate_retired gate_subject gate_resource gate_tuple gate_state_change gate_rate_limit)
# Tables an archive taken before they existed lacks (gate_session and gate_blp_mark arrived in 0.5.0, gate_retired
# after it, the audit integrity/privacy tables and per-record state after 0.6.0). Sessions, marks, the retired log, seals
# and subject mappings are restored empty, from the DDL below (the same statements as SCHEMA in
# packages/pdp-http/src/postgres-schema.ts; k8s.test.ts compares them): an old archive has no seals or subject mappings.
# Shared rate buckets are disposable too. The record tables are created and populated from the old state document by
# migrate-records.ts below. Every other table stays required.
OPTIONAL=(gate_audit_segment gate_subject_identity gate_session gate_blp_mark gate_blp_session gate_retired gate_subject gate_resource gate_tuple gate_state_change gate_rate_limit)
missing_optional=()
# exactly SESSION_TABLE and SESSION_POLICY of packages/pdp-http/src/postgres-schema.ts (k8s.test.ts checks it)
SESSION_DDL='CREATE TABLE IF NOT EXISTS gate_session (id text PRIMARY KEY, body text NOT NULL, method text NOT NULL, oidc_sub text, oidc_sid text, created bigint NOT NULL, touched bigint NOT NULL);
CREATE INDEX IF NOT EXISTS gate_session_touched ON gate_session (touched);
ALTER TABLE gate_session ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_session FORCE ROW LEVEL SECURITY;
CREATE POLICY gate_session_rw ON gate_session FOR ALL TO PUBLIC USING (true) WITH CHECK (true);'

optional_ddl() {
  case $1 in
    gate_audit_segment) printf '%s' 'CREATE TABLE IF NOT EXISTS gate_audit_segment (node text NOT NULL, seq bigint NOT NULL CHECK (seq > 0), body text NOT NULL, PRIMARY KEY (node, seq)); ALTER TABLE gate_audit_segment ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_audit_segment FORCE ROW LEVEL SECURITY; CREATE POLICY gate_audit_segment_read ON gate_audit_segment FOR SELECT TO PUBLIC USING (true); CREATE POLICY gate_audit_segment_append ON gate_audit_segment FOR INSERT TO PUBLIC WITH CHECK (true); CREATE POLICY gate_audit_segment_rekey ON gate_audit_segment FOR UPDATE TO PUBLIC USING (true) WITH CHECK (true);' ;;
    gate_subject_identity) printf '%s' 'CREATE TABLE IF NOT EXISTS gate_subject_identity (pseudonym text PRIMARY KEY, id text NOT NULL UNIQUE, key text NOT NULL); ALTER TABLE gate_subject_identity ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_subject_identity FORCE ROW LEVEL SECURITY; CREATE POLICY gate_subject_identity_rw ON gate_subject_identity FOR ALL TO PUBLIC USING (true) WITH CHECK (true);' ;;
    gate_session) printf '%s' "$SESSION_DDL" ;;
    gate_blp_mark) printf '%s' 'CREATE TABLE IF NOT EXISTS gate_blp_mark (session text NOT NULL, subject text NOT NULL, level int NOT NULL CHECK (level BETWEEN 0 AND 3), started bigint NOT NULL, seen bigint NOT NULL, PRIMARY KEY (session, subject)); ALTER TABLE gate_blp_mark ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_blp_mark FORCE ROW LEVEL SECURITY; CREATE POLICY gate_blp_mark_rw ON gate_blp_mark FOR ALL TO PUBLIC USING (true) WITH CHECK (true);' ;;
    gate_blp_session) printf '%s' 'CREATE TABLE IF NOT EXISTS gate_blp_session (sid text PRIMARY KEY, pep text NOT NULL, subject text NOT NULL, body text NOT NULL, seen bigint NOT NULL, exp bigint NOT NULL); CREATE INDEX IF NOT EXISTS gate_blp_session_subject ON gate_blp_session (pep, subject); CREATE INDEX IF NOT EXISTS gate_blp_session_seen ON gate_blp_session (seen); CREATE INDEX IF NOT EXISTS gate_blp_session_exp ON gate_blp_session (exp); ALTER TABLE gate_blp_session ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_blp_session FORCE ROW LEVEL SECURITY; CREATE POLICY gate_blp_session_rw ON gate_blp_session FOR ALL TO PUBLIC USING (true) WITH CHECK (true);' ;;
    gate_retired) printf '%s' 'CREATE TABLE IF NOT EXISTS gate_retired (type text NOT NULL, id text NOT NULL, version bigint NOT NULL, retired_at text NOT NULL, node text NOT NULL, PRIMARY KEY (type, id, version)); ALTER TABLE gate_retired ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_retired FORCE ROW LEVEL SECURITY; CREATE POLICY gate_retired_read ON gate_retired FOR SELECT TO PUBLIC USING (true); CREATE POLICY gate_retired_append ON gate_retired FOR INSERT TO PUBLIC WITH CHECK (true);' ;;
    gate_rate_limit) printf '%s' 'CREATE TABLE IF NOT EXISTS gate_rate_limit (key text PRIMARY KEY, tokens double precision NOT NULL, at double precision NOT NULL, leased double precision NOT NULL); ALTER TABLE gate_rate_limit ENABLE ROW LEVEL SECURITY; ALTER TABLE gate_rate_limit FORCE ROW LEVEL SECURITY; CREATE POLICY gate_rate_limit_rw ON gate_rate_limit FOR ALL TO PUBLIC USING (true) WITH CHECK (true);' ;;
    gate_subject|gate_resource|gate_tuple|gate_state_change) printf '' ;;
    *) return 1 ;;
  esac
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Required command is missing: %s\n' "$1" >&2
    exit 1
  fi
}

validate_archive() {
  local archive=$1
  local listing table
  if ! listing=$(pg_restore --list "$archive"); then
    printf 'Restore refused: invalid PostgreSQL custom archive.\n' >&2
    return 1
  fi
  local schema data
  for table in "${TABLES[@]}"; do
    local has_schema=0 has_data=0
    grep -Eq "[[:space:]]TABLE[[:space:]]+public[[:space:]]+${table}[[:space:]]" <<<"$listing" && has_schema=1
    grep -Eq "[[:space:]]TABLE DATA[[:space:]]+public[[:space:]]+${table}[[:space:]]" <<<"$listing" && has_data=1
    if [[ $has_schema == 0 && $has_data == 0 ]] && [[ " ${OPTIONAL[*]} " == *" $table "* ]]; then
      missing_optional+=("$table")
    elif [[ $has_schema == 0 || $has_data == 0 ]]; then
      printf 'Restore refused: archive is missing schema or data for %s.\n' "$table" >&2
      return 1
    fi
  done
}

database_name() {
  node -e '
    try {
      const url = new URL(process.argv[1]);
      if (url.protocol !== "postgresql:" && url.protocol !== "postgres:") throw new Error();
      if (!/^\/[^/]+$/.test(url.pathname)) throw new Error();
      const name = decodeURIComponent(url.pathname.slice(1));
      if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(name)) throw new Error();
      process.stdout.write(name);
    } catch {
      console.error("DATABASE_URL must contain one simple PostgreSQL database name (letters, digits and underscores).");
      process.exit(1);
    }
  ' "$1"
}

# $1 is a URL already stripped of its password
maintenance_url() {
  node -e '
    try {
      const url = new URL(process.argv[1]);
      if (url.protocol !== "postgresql:" && url.protocol !== "postgres:") throw new Error();
      url.pathname = "/postgres";
      process.stdout.write(url.toString());
    } catch {
      console.error("DATABASE_URL is not a valid PostgreSQL URL.");
      process.exit(1);
    }
  ' "$1"
}

# Splits the PostgreSQL URL held in the named variable into a URL without its password and the password, NUL-separated
# on stdout. The URL reaches node through the environment: no secret ever appears in a process argument list (`ps`).
split_url() {
  GATE_URL_VARIABLE=$1 node -e '
    const name = process.env.GATE_URL_VARIABLE;
    try {
      const url = new URL(process.env[name] ?? "");
      if (url.protocol !== "postgresql:" && url.protocol !== "postgres:") throw new Error();
      let password = decodeURIComponent(url.password);
      if (url.searchParams.has("password")) { password = url.searchParams.get("password"); url.searchParams.delete("password"); }
      url.password = "";
      process.stdout.write(`${url}\0${password}\0`);
    } catch {
      console.error(`${name} is not a valid PostgreSQL URL.`);
      process.exit(1);
    }
  '
}

# Runs a client tool with the password in PGPASSWORD (the environment, not the arguments) when there is one.
with_password() {
  local password=$1
  shift
  if [[ -n $password ]]; then PGPASSWORD=$password "$@"; else "$@"; fi
}

for command in pg_restore createdb dropdb psql node grep mktemp; do
  require_command "$command"
done
crypt="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/archive-crypt.ts"
record_migration="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/migrate-records.ts"
database_tls="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/database-tls.ts"

: "${DATABASE_URL:?Set DATABASE_URL to the fresh target without enabling shell tracing}"
: "${BACKUP_FILE:?Set BACKUP_FILE to an archive written by backup.sh}"
# reaches archive-crypt.ts through the environment only, like the database password
: "${BACKUP_ENCRYPTION_KEY:?Set BACKUP_ENCRYPTION_KEY to the key the archive was encrypted with, without enabling shell tracing}"
if [[ ! -f $BACKUP_FILE || -L $BACKUP_FILE || ! -r $BACKUP_FILE || ! -s $BACKUP_FILE ]]; then
  printf 'BACKUP_FILE must be a readable, non-empty regular file and not a symbolic link.\n' >&2
  exit 1
fi

created=0 plain_dir=''
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n $plain_dir ]]; then
    rm -rf "$plain_dir"
  fi
  if (( created == 1 && status != 0 )); then
    if ! with_password "$maintenance_password" dropdb --maintenance-db="$maintenance" "$database" >/dev/null 2>&1; then
      printf 'Restore failed and the newly created database could not be removed; remove only that throwaway target after inspection.\n' >&2
    else
      printf 'Restore failed; the newly created target database was removed.\n' >&2
    fi
  fi
  exit "$status"
}
trap cleanup EXIT

# decrypted into a private temporary directory; the authentication tag is checked before anything reaches the database
plain_dir=$(mktemp -d)
plain="$plain_dir/gate.dump"
if ! node "$crypt" decrypt "$BACKUP_FILE" "$plain"; then
  printf 'Restore refused: the archive did not decrypt and authenticate (wrong BACKUP_ENCRYPTION_KEY, or a damaged or tampered file).\n' >&2
  exit 1
fi
validate_archive "$plain"

{ IFS= read -r -d '' target_url && IFS= read -r -d '' target_password; } < <(split_url DATABASE_URL) || exit 1
database=$(database_name "$target_url")
if [[ -n ${MAINTENANCE_DATABASE_URL:-} ]]; then
  { IFS= read -r -d '' maintenance && IFS= read -r -d '' maintenance_password; } < <(split_url MAINTENANCE_DATABASE_URL) || exit 1
else
  maintenance=$(maintenance_url "$target_url")
  maintenance_password=$target_password
fi

{ IFS= read -r -d '' PGSSLMODE && IFS= read -r -d '' PGSSLROOTCERT && IFS= read -r -d '' PGSSLCERT && IFS= read -r -d '' PGSSLKEY; } < <(node "$database_tls") || exit 1
export PGSSLMODE PGSSLROOTCERT PGSSLCERT PGSSLKEY
with_password "$maintenance_password" createdb --maintenance-db="$maintenance" "$database"
created=1

actual=$(with_password "$target_password" psql --dbname="$target_url" --no-psqlrc --tuples-only --no-align --quiet --set=ON_ERROR_STOP=1 --command='SELECT current_database()')
if [[ $actual != "$database" ]]; then
  printf 'Restore refused: target URL resolved to a different database.\n' >&2
  exit 1
fi

# the whole archive, not --table: that would drop the keys, indexes and row-level security policies; backup.sh already holds only gate_* tables
with_password "$target_password" pg_restore \
  --dbname="$target_url" \
  --format=custom \
  --exit-on-error \
  --single-transaction \
  --no-owner \
  --no-privileges \
  "$plain"

# one psql --command per table: a multi-statement command runs as one transaction
for table in ${missing_optional[@]+"${missing_optional[@]}"}; do
  if [[ $table == gate_subject || $table == gate_resource || $table == gate_tuple || $table == gate_state_change ]]; then
    printf 'The archive predates %s: the record migration will create it.\n' "$table"
    continue
  fi
  with_password "$target_password" psql --dbname="$target_url" --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --command="$(optional_ddl "$table")"
  printf 'The archive predates %s: created empty.\n' "$table"
done

# Current archives are a no-op here. A 0.6.0-or-older archive gets the new schema and its document imported atomically.
DATABASE_URL="$target_url" with_password "$target_password" node "$record_migration"

for table in "${TABLES[@]}"; do
  present=$(with_password "$target_password" psql --dbname="$target_url" --no-psqlrc --tuples-only --no-align --quiet --set=ON_ERROR_STOP=1 \
    --command="SELECT to_regclass('public.${table}') IS NOT NULL")
  if [[ $present != t ]]; then
    printf 'Restore validation failed: missing table %s.\n' "$table" >&2
    exit 1
  fi
done

created=0
printf 'Restore completed; all gate tables are present. Start Qadamar and verify state and the audit chain before admitting traffic.\n'
