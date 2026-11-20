#!/usr/bin/env bash
# Deletes one tenant: its namespace, and with it the Qadamar pods, Secrets (signing keys included), the in-cluster
# database and the backup volume of the local overlay. Irreversible. A cloud's managed database and off-site backups
# are not touched: retire them under the customer's retention terms.
# Usage: scripts/managed/delete-tenant.sh <tenant> --yes   (KUBE_CONTEXT, default orbstack)
set -euo pipefail
tenant=${1:-}
if [[ ! $tenant =~ ^[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$ || ${2:-} != --yes ]]; then
  printf 'Usage: %s <tenant> --yes   (deletes namespace gate-<tenant> and everything in it)\n' "$0" >&2
  exit 2
fi
context=${KUBE_CONTEXT:-orbstack}
kubectl --context "$context" delete namespace "gate-$tenant" --wait=true --timeout=300s
printf 'Tenant %s deleted (namespace gate-%s).\n' "$tenant" "$tenant"
