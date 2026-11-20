#!/usr/bin/env bash
set -euo pipefail
umask 077

TABLES=(gate_doc gate_audit gate_audit_meta gate_anchor gate_audit_segment gate_subject_identity gate_sync gate_token gate_performed gate_session gate_blp_mark gate_blp_session gate_retired gate_subject gate_resource gate_tuple gate_state_change gate_rate_limit)

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
    printf 'Backup validation failed: invalid PostgreSQL custom archive.\n' >&2
    return 1
  fi
  for table in "${TABLES[@]}"; do
    if ! grep -Eq "[[:space:]]TABLE[[:space:]]+public[[:space:]]+${table}[[:space:]]" <<<"$listing" ||
       ! grep -Eq "[[:space:]]TABLE DATA[[:space:]]+public[[:space:]]+${table}[[:space:]]" <<<"$listing"; then
      printf 'Backup validation failed: missing schema or data for %s.\n' "$table" >&2
      return 1
    fi
  done
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

for command in pg_dump pg_restore grep mktemp node; do
  require_command "$command"
done
crypt="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/archive-crypt.ts"
database_tls="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/database-tls.ts"

: "${DATABASE_URL:?Set DATABASE_URL without enabling shell tracing}"
{ IFS= read -r -d '' source_url && IFS= read -r -d '' source_password; } < <(split_url DATABASE_URL) || exit 1
{ IFS= read -r -d '' PGSSLMODE && IFS= read -r -d '' PGSSLROOTCERT && IFS= read -r -d '' PGSSLCERT && IFS= read -r -d '' PGSSLKEY; } < <(node "$database_tls") || exit 1
export PGSSLMODE PGSSLROOTCERT PGSSLCERT PGSSLKEY
: "${BACKUP_FILE:?Set BACKUP_FILE to a new absolute archive path}"
# reaches archive-crypt.ts through the environment only, like the database password
: "${BACKUP_ENCRYPTION_KEY:?Set BACKUP_ENCRYPTION_KEY from the secret store without enabling shell tracing}"

if [[ $BACKUP_FILE != /* ]]; then
  printf 'BACKUP_FILE must be an absolute path.\n' >&2
  exit 1
fi
if [[ -e $BACKUP_FILE || -L $BACKUP_FILE ]]; then
  printf 'BACKUP_FILE already exists; refusing to overwrite it.\n' >&2
  exit 1
fi
if [[ ! -d ${BACKUP_FILE%/*} ]]; then
  printf 'The backup directory does not exist.\n' >&2
  exit 1
fi

plain_dir='' stage=''
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n $plain_dir ]]; then
    rm -rf "$plain_dir"
  fi
  if [[ -n $stage ]]; then
    rm -rf "$stage"
  fi
  exit "$status"
}
trap cleanup EXIT

# the plaintext stays in a private temporary directory, never next to BACKUP_FILE (which may be synced off-site)
plain_dir=$(mktemp -d)
plain="$plain_dir/gate.dump"
with_password "$source_password" pg_dump \
  --format=custom \
  --no-owner \
  --no-acl \
  --file="$plain" \
  --table=public.gate_doc \
  --table=public.gate_audit \
  --table=public.gate_audit_meta \
  --table=public.gate_anchor \
  --table=public.gate_audit_segment \
  --table=public.gate_subject_identity \
  --table=public.gate_sync \
  --table=public.gate_token \
  --table=public.gate_performed \
  --table=public.gate_session \
  --table=public.gate_blp_mark \
  --table=public.gate_blp_session \
  --table=public.gate_retired \
  --table=public.gate_subject \
  --table=public.gate_resource \
  --table=public.gate_tuple \
  --table=public.gate_state_change \
  --table=public.gate_rate_limit \
  "$source_url"

if [[ ! -s $plain ]]; then
  printf 'Backup validation failed: the archive is empty.\n' >&2
  exit 1
fi
validate_archive "$plain"
# encrypted (AES-256-GCM, mode 600) on the target's file system, then linked: BACKUP_FILE appears complete or not at all
stage=$(mktemp -d "${BACKUP_FILE}.tmp.XXXXXX")
node "$crypt" encrypt "$plain" "$stage/archive"
ln "$stage/archive" "$BACKUP_FILE"
printf 'Backup created, validated and encrypted: %s\n' "$BACKUP_FILE"
