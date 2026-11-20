#!/usr/bin/env bash
# Upgrades one tenant to the images and manifests of this checkout (docs/MANAGED-OFFER.md §6), the way docs/DEPLOY.md
# requires for a schema change: stop every Qadamar node, run the schema and the grants as the OWNER role (Job
# gate-migrate, deleted first because a Job is immutable and an old completed one would satisfy the wait), then start
# the new nodes. new-tenant.sh does the apply, creates the Secrets a newer version added (kept when present, e.g.
# gate-backup) and waits for the ready pod(s). The pods are recreated even when the image tag is unchanged (local
# overlay: gate:local), so they always run the image present now. Prints names and timings, never a secret value.
# Usage: scripts/managed/upgrade-tenant.sh <tenant>   (KUBE_CONTEXT, default orbstack; OVERLAY as for new-tenant.sh)
set -euo pipefail
cd "$(dirname "$0")/../.."
tenant=${1:-}
[[ $tenant =~ ^[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$ ]] || { printf 'Usage: %s <tenant>\n' "$0" >&2; exit 2; }
# a cloud overlay without KUBE_CONTEXT only renders (new-tenant.sh): never scale down a tenant that would not come back
case ${OVERLAY:-local} in
  local|local-cluster|*/overlays/local|*/overlays/local-cluster) ;;
  *) [[ -n ${KUBE_CONTEXT:-} ]] || { printf 'Set KUBE_CONTEXT to upgrade a tenant on overlay %s\n' "$OVERLAY" >&2; exit 2; } ;;
esac
k() { kubectl --context "${KUBE_CONTEXT:-orbstack}" -n "gate-$tenant" "$@"; }
# the tenant must exist: a Deployment (active/standby) or a StatefulSet (cluster mode)
workload=$(k get statefulset gate -o name 2>/dev/null || k get deployment gate -o name)
started=$(node -p 'Date.now()')
k scale "$workload" --replicas=0 >/dev/null
k wait --for=delete pod -l app.kubernetes.io/component=server --timeout=120s >/dev/null 2>&1 || true
[[ -z $(k get pods -l app.kubernetes.io/component=server -o name) ]] || { printf 'Qadamar pods still running after 120 s\n' >&2; exit 1; }
k delete job gate-migrate --ignore-not-found >/dev/null
bash scripts/managed/new-tenant.sh "$tenant"
printf 'Upgrade of %s: no serving node for %ss (stop, migration as owner, start).\n' "$tenant" "$(node -p "((Date.now() - $started) / 1000).toFixed(1)")"
