#!/usr/bin/env bash
# Creates or completes one Qadamar tenant: namespace gate-<tenant> (Pod Security "restricted"), generated
# secrets, the overlay, the schema migration, then waits for exactly one ready (active) pod and stores the one-time
# initial credentials of the first start in a Secret. Prints names and the elapsed time, never a secret value.
# Idempotent: existing Secrets are kept, because regenerating them would lock the tenant out of its own database and
# of its sealed signing keys.
#
# Usage: scripts/managed/new-tenant.sh <tenant>
#   KUBE_CONTEXT  kubectl context (default orbstack for the local overlays). A cloud overlay without KUBE_CONTEXT, or
#                 RENDER_ONLY=1, only renders: the tenant's manifests on stdout, no cluster contacted, nothing applied.
#   OVERLAY       kustomize overlay directory, or the name of one under deploy/k8s/overlays (default local). With any
#                 other overlay, create the Secrets first from the cloud's database, secret store, IdP and TSA
#                 (docs/MANAGED-OFFER.md §5); apply is refused while the render still holds placeholders
#                 (example.invalid hosts, all-zero image digests, RFC 5737 documentation address ranges), and both
#                 render and apply are refused while an image is named by tag rather than by digest.
#   WORLD         directory with the tenant's own world.json and bundle.json, seeded on the first start (ConfigMap
#                 gate-world mounted at WORLD_DIR=/etc/gate/world). Required for a new tenant on any other overlay,
#                 unless that overlay sets WORLD_DIR itself: production refuses the image's demo world (docs/DEPLOY.md §5).
set -euo pipefail
umask 077
cd "$(dirname "$0")/../.."
tenant=${1:-}
if [[ ! $tenant =~ ^[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?$ ]]; then
  printf 'Usage: %s <tenant>  (lowercase letters, digits and dashes, at most 30 characters)\n' "$0" >&2
  exit 2
fi
started=$(node -p 'Date.now()')
overlay=${OVERLAY:-local}
[[ $overlay == */* ]] || overlay=deploy/k8s/overlays/$overlay # a bare name: one of this repository's overlays
overlay=$(cd "$overlay" && pwd -P)
ns="gate-$tenant"
local_test=0
[[ $overlay == */overlays/local || $overlay == */overlays/local-cluster ]] && local_test=1
render_only=${RENDER_ONLY:-0}
(( !local_test )) && [[ -z ${KUBE_CONTEXT:-} ]] && render_only=1
context=${KUBE_CONTEXT:-orbstack}
work=$(cd "$(mktemp -d)" && pwd -P) # physical paths: kustomize resolves symlinks
trap 'rm -rf "$work"' EXIT

k() { kubectl --context "$context" -n "$ns" "$@"; }
has_secret() { k get secret "$1" >/dev/null 2>&1; }
secret_value() { k get secret "$1" -o "jsonpath={.data.$2}" | base64 -d; }
hex() { openssl rand -hex "$1"; }

if (( !render_only )); then
# 1. namespace
kubectl --context "$context" get namespace "$ns" >/dev/null 2>&1 || kubectl --context "$context" create namespace "$ns" --save-config >/dev/null
kubectl --context "$context" label --overwrite namespace "$ns" pod-security.kubernetes.io/enforce=restricted \
  app.kubernetes.io/part-of=qadamar "qadamar.example/tenant=$tenant" >/dev/null

# 2. secrets, written to mode-600 files in a private temporary directory, never on a command line
required=(gate-env gate-db-admin gate-backup gate-oidc gate-tsa gate-break-glass)
# the sovereign overlay also requires the database CA (base mounts it optionally) and the pods' own certificate, and runs decision replicas
[[ $overlay == */overlays/sovereign-uae ]] && required+=(gate-postgres-tls gate-pod-tls gate-tls gate-replica gate-replica-keys)
if (( !local_test )); then
  for name in "${required[@]}"; do
    has_secret "$name" || { printf 'Create the Secret %s in %s first (docs/MANAGED-OFFER.md §5).\n' "$name" "$ns" >&2; exit 1; }
  done
else
  if ! has_secret gate-postgres; then
    printf 'POSTGRES_PASSWORD=%s\nGATE_OWNER_PASSWORD=%s\nGATE_APP_PASSWORD=%s\nGATE_BACKUP_PASSWORD=%s\n' \
      "$(hex 24)" "$(hex 24)" "$(hex 24)" "$(hex 24)" > "$work/postgres.env"
    k create secret generic gate-postgres --from-env-file="$work/postgres.env" >/dev/null
  fi
  if ! has_secret gate-env; then
    printf 'DATABASE_URL=postgresql://gate_app:%s@postgres:5432/gate\nSIGNING_KEY_SEAL=%s\nMETRICS_TOKEN=%s\n' \
      "$(secret_value gate-postgres GATE_APP_PASSWORD)" "$(hex 32)" "$(hex 32)" > "$work/gate.env"
    k create secret generic gate-env --from-env-file="$work/gate.env" >/dev/null
  fi
  if ! has_secret gate-db-admin; then
    printf 'OWNER_DATABASE_URL=postgresql://gate_owner:%s@postgres:5432/gate\nBACKUP_DATABASE_URL=postgresql://gate_backup:%s@postgres:5432/gate\n' \
      "$(secret_value gate-postgres GATE_OWNER_PASSWORD)" "$(secret_value gate-postgres GATE_BACKUP_PASSWORD)" > "$work/admin.env"
    k create secret generic gate-db-admin --from-env-file="$work/admin.env" >/dev/null
  fi
  put() { k create secret "$@" --save-config --dry-run=client -o yaml | k apply -f - >/dev/null; }
  # TEST ONLY: a throwaway CA and the certificates of Qadamar, the test IdP, TSA and webhook (test-services.yaml)
  # (gate-tsa is written last: when it exists, the whole set does)
  if ! has_secret gate-tsa; then
    mkdir "$work/pki"
    bash scripts/managed/local-test-pki.sh "$work/pki" "$ns"
    put tls gate-tls --cert="$work/pki/gate.crt" --key="$work/pki/gate.key"
    put generic gate-postgres-tls --from-literal=DATABASE_TLS_CA_FILE=/etc/gate/postgres/ca.crt --from-file=ca.crt="$work/pki/ca.crt"
    put tls gate-postgres-server --cert="$work/pki/postgres.crt" --key="$work/pki/postgres.key"
    put tls test-services-tls --cert="$work/pki/services.crt" --key="$work/pki/services.key"
    put generic test-tsa-signer --from-file="$work/pki/tsa.crt" --from-file="$work/pki/tsa.key"
    put generic gate-tsa --from-literal=TSA_URL=https://test-tsa/tsa --from-literal=TSA_CA_FILE=/etc/gate/tsa/ca.pem \
      --from-literal=ANCHOR_INTERVAL=60 --from-file=ca.pem="$work/pki/ca.crt"
  fi
  # Upgrades from before database TLS have gate-tsa already: backfill only the matched database CA and server certificate.
  if ! has_secret gate-postgres-tls || ! has_secret gate-postgres-server; then
    mkdir "$work/postgres-pki"
    bash scripts/managed/local-test-pki.sh "$work/postgres-pki" "$ns"
    put generic gate-postgres-tls --from-literal=DATABASE_TLS_CA_FILE=/etc/gate/postgres/ca.crt --from-file=ca.crt="$work/postgres-pki/ca.crt"
    put tls gate-postgres-server --cert="$work/postgres-pki/postgres.crt" --key="$work/postgres-pki/postgres.key"
  fi
  if ! has_secret gate-oidc; then
    printf 'OIDC_ISSUER=https://test-idp\nOIDC_CLIENT_ID=gate-console\nOIDC_CLIENT_SECRET=%s\nOIDC_ROLE_CLAIM=roles\nOIDC_ID_CLAIM=preferred_username\n' \
      "$(hex 32)" > "$work/oidc.env"
    k create secret generic gate-oidc --from-env-file="$work/oidc.env" >/dev/null
  fi
  if ! has_secret gate-backup; then
    # 32 random bytes as 64 hex characters (scripts/ops/archive-crypt.ts); a real tenant escrows it outside the cluster
    printf 'BACKUP_ENCRYPTION_KEY=%s\n' "$(hex 32)" > "$work/backup.env"
    k create secret generic gate-backup --from-env-file="$work/backup.env" >/dev/null
  fi
  if ! has_secret gate-break-glass; then
    printf 'BREAK_GLASS_WEBHOOK=https://test-webhook/notices\nBREAK_GLASS_WEBHOOK_SECRET=%s\n' "$(hex 32)" > "$work/break-glass.env"
    k create secret generic gate-break-glass --from-env-file="$work/break-glass.env" >/dev/null
  fi
fi
fi # render_only

# 3. manifests for this namespace: everything but the server first, so the owner migrates before the service role connects
mkdir "$work/tenant"
world_yaml=''
if [[ -n ${WORLD:-} ]]; then
  for f in world.json bundle.json; do
    [[ -f $WORLD/$f ]] || { printf 'WORLD=%s has no %s\n' "$WORLD" "$f" >&2; exit 2; }
    cp "$WORLD/$f" "$work/tenant/$f"
  done
  if (( !local_test )) && [[ $(node -p 'JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")).demo === true' "$work/tenant/world.json") == true ]]; then
    printf 'WORLD=%s is marked "demo": true, which a production tenant refuses to seed from\n' "$WORLD" >&2; exit 2
  fi
  # the world as a ConfigMap (hash-suffixed, so a change rolls the pods), mounted read-only where WORLD_DIR points
  world_yaml=$(cat <<'YAML'
configMapGenerator:
  - {name: gate-world, files: [world.json, bundle.json]}
  - {name: gate-config, behavior: merge, literals: [WORLD_DIR=/etc/gate/world]}
patches:
  - target: {kind: Deployment|StatefulSet, name: gate}
    patch: |-
      apiVersion: apps/v1
      kind: Deployment
      metadata: {name: gate}
      spec:
        template:
          spec:
            containers:
              - name: gate
                volumeMounts: [{name: world, mountPath: /etc/gate/world, readOnly: true}]
            volumes: [{name: world, configMap: {name: gate-world}}]
YAML
)
fi
# kustomize refuses absolute resource paths
relative=$(node -p 'require("node:path").relative(process.argv[1], process.argv[2])' "$work/tenant" "$overlay")
cat > "$work/tenant/kustomization.yaml" <<YAML
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: $ns
resources: ["$relative"]
labels:
  - pairs: {qadamar.example/tenant: "$tenant"}
$world_yaml
YAML
kubectl kustomize "$work/tenant" > "$work/tenant.yaml"
# a tag can be re-pointed: outside the local test overlays every image is named by digest, rendered or applied
if (( !local_test )) && grep -E '^ *(- )?image: ' "$work/tenant.yaml" | grep -vq '@sha256:[0-9a-f]\{64\}'; then
  printf 'Overlay %s names an image by tag: name every image by digest (images: digest: sha256:...).\n' "${overlay#"$PWD"/}" >&2
  exit 1
fi
if (( render_only )); then
  # Secrets are referenced, never rendered: the output holds no secret value
  cat "$work/tenant.yaml"
  printf 'Rendered tenant %s (namespace %s, overlay %s) without a cluster; nothing applied. Set KUBE_CONTEXT to apply.\n' \
    "$tenant" "$ns" "${overlay#"$PWD"/}" >&2
  exit 0
fi
# the documentation ranges (RFC 5737) stand in for TRUSTED_PROXIES and the egress rules: left in, the real ingress is
# not trusted and the database, IdP and TSA stay unreachable
placeholders='example\.invalid|@sha256:0{64}|(^|[^0-9.])(192\.0\.2|198\.51\.100|203\.0\.113)\.[0-9]'
# TLS settings in a database URL (libpq and node-postgres names): Qadamar takes them from DATABASE_TLS* only
url_tls='[?&](ssl|sslmode|sslcert|sslkey|sslrootcert|sslpassword)='
if (( !local_test )); then
  if grep -qE "$placeholders" "$work/tenant.yaml"; then
    printf 'Overlay %s still holds placeholders (example.invalid hosts, all-zero image digests or the documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24): replace every PARAMETER first.\n' "${overlay#"$PWD"/}" >&2
    exit 1
  fi
  if [[ $overlay == */overlays/sovereign-uae ]]; then
    # one TLS policy for every PostgreSQL client (server, migration, backup.sh, restore.sh): DATABASE_TLS=verify-full and
    # the pinned CA of Secret gate-postgres-tls at /etc/gate/postgres/ca.crt; a URL carrying TLS parameters is refused
    # by Qadamar and the ops scripts, so refuse it here first (values are read, never printed)
    grep -qE '^  DATABASE_TLS: verify-full$' "$work/tenant.yaml" \
      || { printf 'Overlay %s must set DATABASE_TLS=verify-full (docs/MANAGED-OFFER.md §12).\n' "${overlay#"$PWD"/}" >&2; exit 1; }
    for pair in gate-env:DATABASE_URL gate-db-admin:OWNER_DATABASE_URL gate-db-admin:BACKUP_DATABASE_URL; do
      value=$(secret_value "${pair%%:*}" "${pair#*:}")
      if [[ -z $value || $value =~ $url_tls ]]; then
        printf 'Secret %s key %s must be set, without TLS parameters: DATABASE_TLS and Secret gate-postgres-tls decide (docs/MANAGED-OFFER.md §12).\n' "${pair%%:*}" "${pair#*:}" >&2
        exit 1
      fi
    done
    value=$(secret_value gate-postgres-tls 'ca\.crt')
    if [[ $(secret_value gate-postgres-tls DATABASE_TLS_CA_FILE) != /etc/gate/postgres/ca.crt || $value != *'BEGIN CERTIFICATE'* ]]; then
      printf 'Secret gate-postgres-tls must hold ca.crt (the CA of the managed PostgreSQL) and DATABASE_TLS_CA_FILE=/etc/gate/postgres/ca.crt (docs/MANAGED-OFFER.md §12).\n' >&2
      exit 1
    fi
    unset value
  fi
fi
# a first production start refuses the image's demo world: fail now rather than after 180 s of a crash-looping pod
# (a tenant whose server workload exists has stored state and never reads WORLD_DIR again)
if (( !local_test )) && ! grep -qE '^  (WORLD_DIR: |ALLOW_DEMO_WORLD: "true")' "$work/tenant.yaml" \
  && ! k get deployment/gate statefulset/gate --ignore-not-found -o name | grep -q .; then
  printf 'New tenant %s has no world of its own: set WORLD=<dir with world.json and bundle.json> (docs/MANAGED-OFFER.md §5).\n' "$tenant" >&2
  exit 1
fi
kubectl --context "$context" apply -f "$work/tenant.yaml" -l 'app.kubernetes.io/component!=server' >/dev/null
if (( local_test )); then k rollout status statefulset/postgres --timeout=300s >/dev/null; fi
k wait --for=condition=complete job/gate-migrate --timeout=300s >/dev/null
kubectl --context "$context" apply -f "$work/tenant.yaml" >/dev/null
# cluster mode runs the nodes as a StatefulSet (stable GATE_NODE_IDs), active/standby as a Deployment: switching mode
# removes the other one, which apply alone would leave running
if grep -q '^kind: StatefulSet$' <(awk '/^kind:/{k=$0} /^  name: gate$/{print k}' "$work/tenant.yaml"); then
  k delete deployment gate --ignore-not-found >/dev/null; workload=statefulset/gate
else
  k delete statefulset gate --ignore-not-found >/dev/null; workload=deployment/gate
fi

# 4. one ready pod: the active node (the standby opens no port and is never ready, by design); in cluster mode
# (GATE_CLUSTER=true, overlays/local-cluster) every pod decides and is ready
want=1
grep -q 'GATE_CLUSTER: "true"' "$work/tenant.yaml" && want=$(k get "$workload" -o jsonpath='{.spec.replicas}')
active=''
for _ in $(seq 1 180); do
  active=$(k get pods -l app.kubernetes.io/component=server \
    -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' | awk '$2 == "True" { print $1 }')
  [[ $(printf '%s' "$active" | grep -c .) == "$want" ]] && break
  active=''
  sleep 1
done
[[ -n $active ]] || { printf 'Not %s ready Qadamar pod(s) after 180 s; see: kubectl --context %s -n %s logs %s\n' "$want" "$context" "$ns" "$workload" >&2; exit 1; }
elapsed=$(node -p "((Date.now() - $started) / 1000).toFixed(1)")
pods=$(k get pods -l app.kubernetes.io/component=server -o jsonpath='{.items[*].metadata.name}')

# 5. the first start wrote the bootstrap PEP key (and demo password accounts) to the active pod's DATA_DIR only, for
# INITIAL_CREDENTIALS_TTL_SECONDS (1 h): keep them in a Secret for the hand-over, piped, never printed
if ! has_secret gate-initial-credentials; then
  # the node that bootstrapped the state wrote it (in cluster mode, any of the ready pods)
  for pod in $active; do
    k exec "$pod" -c gate -- cat /var/lib/gate/INITIAL-CREDENTIALS.txt > "$work/initial.json" 2>/dev/null && [[ -s $work/initial.json ]] && break
  done
  if [[ -s $work/initial.json ]]; then
    k create secret generic gate-initial-credentials --from-file=initial-credentials.json="$work/initial.json" >/dev/null
  else
    printf 'note: no INITIAL-CREDENTIALS.txt on %s (already handed over or expired); Secret gate-initial-credentials not created\n' "$active" >&2
  fi
fi

printf 'Tenant %s ready in namespace %s in %ss (context %s, overlay %s, GATE_PROFILE=%s).\n' "$tenant" "$ns" "$elapsed" "$context" \
  "${overlay#"$PWD"/}" "$(k get "$workload" -o jsonpath='{.spec.template.spec.containers[0].envFrom[0].configMapRef.name}' | xargs -I{} kubectl --context "$context" -n "$ns" get configmap {} -o 'jsonpath={.data.GATE_PROFILE}')"
printf 'Ready pod(s): %s (pods: %s)\n' "$(printf '%s ' $active)" "$pods"
printf 'Secrets (values not shown): %s%s\n' "${required[*]} gate-initial-credentials" "$( (( local_test )) && printf ' gate-postgres gate-tls test-services-tls test-tsa-signer (TEST ONLY)')"
printf 'The bootstrap PEP key is in Secret gate-initial-credentials: hand it over, have the customer create its own PEP credentials and revoke "bootstrap", then delete the Secret.\n'
(( local_test )) && printf 'Local access: kubectl --context %s -n %s port-forward svc/gate 18787:8787, then https://localhost:18787 (test CA: Secret gate-tsa, ca.pem)\n' "$context" "$ns"
exit 0
