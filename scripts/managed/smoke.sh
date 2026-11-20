#!/usr/bin/env bash
# End-to-end check of one tenant of the local overlay in GATE_PROFILE=production, through kubectl port-forward:
#  1. the active node (one ready endpoint), production profile, https with the tenant's certificate, probes, metrics;
#  2. PEP evaluation with the tenant's key; console sign-in through the test IdP: refused without MFA, accepted with it;
#     the audit chain verified; the client address in the sign-in audit row;
#  3. break-glass: an emergency opened by an access admin reaches the test webhook as a verified signed notice;
#  4. anchoring: an RFC 3161 anchor of the audit head by the test TSA, its token verified OFFLINE here with openssl
#     against the test CA, its hash equal to the audit row it anchors;
#  5. FAILOVER twice (graceful delete, then forced kill of the active pod) with timings, a decision token issued just
#     before each failover consumed after it, the audit chain re-verified;
#  6. COLD START of both pods (rollout restart): production-profile startup time, no active node meanwhile;
#  7. BACKUP (the CronJob run once as a Job); 8. RESTORE DRILL into a fresh database, granted like gate-migrate does,
#     served by a throwaway production-profile Qadamar node as the service role.
# A tenant in cluster mode (GATE_CLUSTER=true, overlays/local-cluster) gets its own checks instead: both pods ready
# and deciding under stable names, the admin plane through either pod (followers forward to the leader), a token consumed
# once across nodes, leader loss, the restarted node continuing its audit chain, a rolling restart.
# Prints measurements and PASS/FAIL lines, never a secret: secrets go from the Secrets into shell variables and reach
# curl and node through pipes or files in a private temporary directory, never through arguments.
# Usage: scripts/managed/smoke.sh <tenant>   (KUBE_CONTEXT, default orbstack; SMOKE_IDP_PORT, default 18443)
set -euo pipefail
umask 077
cd "$(dirname "$0")/../.."
tenant=${1:?Usage: smoke.sh <tenant>}
context=${KUBE_CONTEXT:-orbstack}
ns="gate-$tenant"
idp_port=${SMOKE_IDP_PORT:-18443}
work=$(mktemp -d)
pf='' idp_pf=''
stamp=$(date -u +%Y%m%d%H%M%S)
restore_db="gate_restore_$stamp"

k() { kubectl --context "$context" -n "$ns" "$@"; }
cleanup() {
  status=$?
  # best effort: a failed run must not hold PDP sessions (per-subject cap) or leave its scoped PEP credential active
  if [[ -n ${pf:-} && -d ${work:-} ]]; then (close_sessions; revoke_scoped_pep) >/dev/null 2>&1 || true; fi
  for p in $pf $idp_pf; do kill "$p" 2>/dev/null || true; done
  k delete pod -l qadamar.example/smoke=restore-drill --ignore-not-found --wait=false >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }
now_ms() { node -p 'Date.now()'; }
seconds() { node -p "((($2) - ($1)) / 1000).toFixed(1)"; }
# reads JSON on stdin, prints the JavaScript expression $1 evaluated with the document as v
field() { node -e 'let s="";process.stdin.on("data",(d)=>s+=d).on("end",()=>{const v=JSON.parse(s);process.stdout.write(String(new Function("v","return ("+process.argv[1]+")")(v)))})' "$1"; }
# reads a decision token on stdin, prints the consume request for action $1 on the demo payment
token_body() { node -e 'let s="";process.stdin.on("data",(d)=>s+=d).on("end",()=>process.stdout.write(JSON.stringify({token:s,action:{name:process.argv[1]},resource:{type:"payment",id:"PAY-3"},resourceVersion:4})))' "$1"; }
secret() { k get secret "$1" -o "jsonpath={.data.$2}" | base64 -d; }
ready_pods() {
  k get pods -l app.kubernetes.io/component=server \
    -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.conditions[?(@.type=="Ready")].status}{" "}{.metadata.deletionTimestamp}{"\n"}{end}' |
    awk '$2 == "True" && $3 == "" { print $1 }'
}
running_pods() {
  k get pods -l app.kubernetes.io/component=server --field-selector=status.phase=Running \
    -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.deletionTimestamp}{"\n"}{end}' | awk 'NF == 1' | grep -c . || true
}
# endpoints behind the Service, one "pod ready" line each
endpoints() {
  k get endpointslices -l kubernetes.io/service-name=gate \
    -o jsonpath='{range .items[*].endpoints[*]}{.targetRef.name}{" "}{.conditions.ready}{"\n"}{end}'
}
ready_endpoint() { endpoints | awk '$2 == "true" { print $1 }'; }
forward() { # (re)starts the port-forward to pod $1; a port-forward that dies while connecting is retried
  local attempt
  for attempt in 1 2 3; do
    if [[ -n $pf ]]; then kill "$pf" 2>/dev/null || true; wait "$pf" 2>/dev/null || true; pf=''; fi
    # kubectl itself in the background, not the k function: $! must be kubectl, or kill leaves it holding the port
    kubectl --context "$context" -n "$ns" port-forward "pod/$1" "$port:8787" >"$work/port-forward.log" 2>&1 &
    pf=$!
    for _ in $(seq 1 100); do
      # only once this kubectl listens: a stale listener on the port would answer for another pod
      grep -q '^Forwarding from' "$work/port-forward.log" && curl -fsS --cacert "$work/ca.pem" -o /dev/null "$base/healthz" 2>/dev/null && return 0
      kill -0 "$pf" 2>/dev/null || break
      sleep 0.1
    done
    printf 'note: port-forward to %s, attempt %s: %s\n' "$1" "$attempt" "$(tr '\n' ' ' <"$work/port-forward.log")" >&2
  done
  fail "port-forward to $1"
}
# http METHOD PATH [BODY]: status code on stdout, body in $work/body; Authorization from $auth, Cookie and CSRF from $cookie/$csrf
http() {
  { if [[ -n ${auth:-} ]]; then printf 'Authorization: Bearer %s\n' "$auth"; fi
    if [[ -n ${cookie:-} ]]; then printf 'Cookie: %s\n' "$cookie"; fi
    if [[ -n ${csrf:-} ]]; then printf 'X-CSRF-Token: %s\n' "$csrf"; fi; } >"$work/headers"
  if [[ $# -ge 3 ]]; then
    printf '%s' "$3" | curl -sS --cacert "$work/ca.pem" -X "$1" -H @"$work/headers" -H 'Content-Type: application/json' --data-binary @- -o "$work/body" -w '%{http_code}' "$base$2"
  else
    curl -sS --cacert "$work/ca.pem" -X "$1" -H @"$work/headers" -o "$work/body" -w '%{http_code}' "$base$2"
  fi
}
header() { grep -i "^$1:" "$2" | head -n 1 | sed 's/^[^:]*: *//' | tr -d '\r'; }
# Console sign-in through the test IdP, as a browser does it: Qadamar -> IdP (login_hint = the test user) -> Qadamar callback.
# sso USER [MFA 1|0]: sets $cookie (sid) and $csrf, or $sso_error to the error Qadamar redirected to.
sso() {
  local location state_cookie
  cookie='' csrf='' sso_error=''
  curl -sS --cacert "$work/ca.pem" -D "$work/h1" -o /dev/null "$base/admin/v1/oidc/login"
  location=$(header location "$work/h1"); state_cookie=$(header set-cookie "$work/h1" | sed 's/;.*//')
  [[ $location == https://test-idp/authorize\?* && $state_cookie == __Host-gate_oidc=* ]] || fail "sign-in did not redirect to the test IdP"
  curl -sS --cacert "$work/ca.pem" --connect-to "test-idp:443:127.0.0.1:$idp_port" -D "$work/h2" -o /dev/null \
    "$location&login_hint=$1&test_mfa=${2:-1}"
  location=$(header location "$work/h2")
  [[ $location == "$base/admin/v1/oidc/callback?"* ]] || fail "the test IdP did not redirect back to Qadamar"
  printf 'Cookie: %s\n' "$state_cookie" >"$work/headers"
  curl -sS --cacert "$work/ca.pem" -H @"$work/headers" -D "$work/h3" -o /dev/null "$location"
  location=$(header location "$work/h3")
  if [[ $location == /\?sso_error=* ]]; then sso_error=${location#/?sso_error=}; return 0; fi
  cookie=$(grep -i '^set-cookie: sid=' "$work/h3" | head -n 1 | sed 's/^[^:]*: *//; s/;.*//' | tr -d '\r')
  [[ $location == / && -n $cookie ]] || fail "sign-in as $1 did not open a session ($location)"
  [[ $(auth='' csrf='' http GET /admin/v1/session) == 200 ]] || fail "session of $1"
  csrf=$(field 'v.csrfToken' <"$work/body")
}
verify_audit() { # prints the chain length; fails unless verified (uses $cookie)
  local code
  code=$(auth='' http GET /admin/v1/audit/verify)
  [[ $code == 200 && $(field 'v.verified' <"$work/body") == true ]] || fail "audit verify: $code $(cat "$work/body")"
  field 'v.length' <"$work/body"
}
scoped_pep() { # prints the secret of a smoke PEP credential scoped to assert context.network=trusted (production gives
  # bootstrap the empty scope); created once by lina (security officer), revoked by revoke_scoped_pep
  if [[ ! -s $work/scoped-pep ]]; then
    local id
    sso lina
    # a run killed before its cleanup leaves its credential active: revoke those first
    [[ $(auth='' http GET /admin/v1/pep-credentials) == 200 ]] || fail "list PEP credentials: $(head -c 300 "$work/body")"
    for id in $(field 'v.items.filter((c) => c.name.startsWith("smoke-") && !c.revoked).map((c) => c.id).join(" ")' <"$work/body"); do
      [[ $(auth='' http POST "/admin/v1/pep-credentials/$id/revoke" '{}') == 200 ]] || fail "revoke the leftover smoke PEP credential $id: $(head -c 300 "$work/body")"
    done
    [[ $(auth='' http POST /admin/v1/pep-credentials "{\"name\":\"smoke-$(date +%s)\",\"contextScopes\":[{\"signal\":\"network\",\"networks\":[\"trusted\"]}]}") == 201 ]] ||
      fail "create a scoped PEP credential: $(head -c 300 "$work/body")"
    field 'v.credential.id' <"$work/body" >"$work/scoped-pep-id"
    field 'v.secret' <"$work/body" >"$work/scoped-pep"
  fi
  cat "$work/scoped-pep"
}
close_sessions() { # closes every PDP session this run opened
  local file
  for file in "$work"/session-*; do
    [[ -f $file && $file != *.key ]] || continue
    [[ $(auth=$(cat "$file.key") cookie='' csrf='' http POST /x/v1/sessions/close "{\"token\":\"$(cat "$file")\"}") == 200 ]] || fail "close PDP session: $(head -c 300 "$work/body")"
    rm -f "$file" "$file.key"
  done
}
revoke_scoped_pep() {
  [[ -s $work/scoped-pep-id ]] || return 0
  sso lina
  [[ $(auth='' http POST "/admin/v1/pep-credentials/$(cat "$work/scoped-pep-id")/revoke" '{}') == 200 ]] || fail "revoke the smoke PEP credential: $(head -c 300 "$work/body")"
  rm -f "$work/scoped-pep-id"
}
pep_for() { # body; the bootstrap key, or the scoped one when the body asserts a network
  if [[ $1 == *'"network"'* ]]; then scoped_pep; else printf '%s' "$pep"; fi
}
with_session() { # body; prints it with "sessionId":"smoke" swapped for a PDP session token of its subject (opened once, reused)
  local subject file key
  subject=$(printf '%s' "$1" | field 'v.subject.id')
  key=$(pep_for "$1") || exit 1
  file="$work/session-$subject-${key%%.*}-$(printf '%s' "$key" | cut -d. -f2)"
  if [[ ! -s $file ]]; then
    [[ $(auth=$key cookie='' csrf='' http POST /x/v1/sessions "{\"subject\":{\"type\":\"user\",\"id\":\"$subject\"}}") == 201 ]] ||
      fail "open a PDP session for $subject: $(head -c 300 "$work/body")"
    field 'v.token' <"$work/body" >"$file"
    printf '%s' "$key" >"$file.key"
  fi
  printf '%s' "${1/\"sessionId\":\"smoke\"/\"sessionToken\":\"$(cat "$file")\"}"
}
evaluate() { # body; prints the decision token (may be empty), fails unless allowed
  local code body
  body=$(with_session "$1") || exit 1
  code=$(auth=$(pep_for "$1") cookie='' csrf='' http POST /access/v1/evaluation "$body")
  [[ $code == 200 && $(field 'v.decision' <"$work/body") == true ]] || fail "evaluation $1: $code $(head -c 300 "$work/body")"
  field 'v.context.decision_token ?? ""' <"$work/body"
}
consume() { # token action; prints the status code. The PEP that consumes is the one that asked: the scoped key
  auth=$(scoped_pep) cookie='' csrf='' http POST /x/v1/tokens/consume "$(printf '%s' "$1" | token_body "$2")"
}
create_body='{"subject":{"type":"user","id":"grace"},"action":{"name":"create"},"resource":{"type":"payment","id":"PAY-3"},"context":{"network":"trusted","sessionId":"smoke"}}'
approve_body='{"subject":{"type":"user","id":"henry"},"action":{"name":"approve"},"resource":{"type":"payment","id":"PAY-3"},"context":{"network":"trusted","sessionId":"smoke"}}'

printf 'Smoke test of tenant %s (namespace %s, context %s)\n' "$tenant" "$ns" "$context"
# active/standby runs a Deployment, cluster mode a StatefulSet (stable node ids)
workload=$(k get statefulset gate -o name 2>/dev/null || k get deployment gate -o name)
config=$(k get "$workload" -o jsonpath='{.spec.template.spec.containers[0].envFrom[0].configMapRef.name}')
k get configmap "$config" -o json >"$work/config.json"
origin=$(field 'v.data.PUBLIC_ORIGIN' <"$work/config.json")
[[ $(field 'v.data.GATE_PROFILE' <"$work/config.json") == production && $(field 'v.data.CLOCK ?? ""' <"$work/config.json") == '' ]] ||
  fail "the tenant does not run GATE_PROFILE=production without a pinned clock"
[[ $origin =~ ^https://localhost:([0-9]+)$ ]] || fail "PUBLIC_ORIGIN must be https://localhost:<port> in the local overlay, got $origin"
port=${BASH_REMATCH[1]}
base="https://localhost:$port"
secret gate-tsa 'ca\.pem' >"$work/ca.pem" # the tenant's TEST CA (public certificate)
pep=$(secret gate-initial-credentials 'initial-credentials\.json' | field 'v.pepApiKey')
metrics_token=$(secret gate-env METRICS_TOKEN)
for p in "$port" "$idp_port"; do
  (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && fail "local port $p is already in use (a leftover kubectl port-forward?)"
done
kubectl --context "$context" -n "$ns" port-forward svc/test-idp "$idp_port:443" >"$work/idp-forward.log" 2>&1 &
idp_pf=$!

# ---------------------------------------------------------------- cluster mode (GATE_CLUSTER=true): its own checks, then exit
if [[ $(field 'v.data.GATE_CLUSTER ?? ""' <"$work/config.json") == true ]]; then
  read_body='{"subject":{"type":"user","id":"bob"},"action":{"name":"read"},"resource":{"type":"case","id":"CASE-14"},"context":{"sessionId":"smoke"}}'
  pods=$(ready_pods)
  [[ $(printf '%s\n' "$pods" | grep -c .) == 2 && $(running_pods) == 2 ]] || fail "cluster: expected 2 running and 2 ready pods, got: $(printf '%s ' $pods)"
  [[ $(endpoints | awk '$2 == "true"' | grep -c .) == 2 ]] || fail "cluster: the Service must route to both pods: $(endpoints | tr '\n' ',')"
  pass "cluster: 2 pods running and ready ($(printf '%s ' $pods)); the Service has 2 ready endpoints"
  leader='' follower='' auth='' cookie='' csrf=''
  for pod in $pods; do
    [[ $pod =~ ^gate-[0-9]+$ ]] || fail "cluster: pods must be the StatefulSet's stable names gate-<n>, got $pod"
    forward "$pod"
    [[ $(http GET /readyz) == 200 && $(field 'v.node' <"$work/body") == "$pod" ]] || fail "cluster: /readyz on $pod: $(cat "$work/body")"
    evaluate "$read_body" >/dev/null
    if [[ $(http GET /leaderz) == 200 ]]; then leader=$pod; else follower=$pod; fi
    # through either pod the admin plane answers as the leader does: no session yet, 401 (a follower forwards it)
    [[ $(http GET /admin/v1/session) == 401 && $(field 'v.error' <"$work/body") == unauthenticated ]] || fail "cluster: /admin through $pod: $(cat "$work/body")"
  done
  [[ -n $leader && -n $follower ]] || fail "cluster: expected one leader and one follower (leader '$leader', follower '$follower')"
  advertised="https://$leader.gate-nodes.$ns.svc:8787"
  pass "cluster: both pods decide (PEP evaluation 200 on each, GATE_NODE_ID = /readyz node = stable pod name); leader $leader (/leaderz 200); /admin answers 401 through both"
  # a request that already made a hop is never forwarded again: the 409 fallback names the leader's internal address;
  # the leader refuses a hop header it cannot verify
  forward "$follower"
  code=$(curl -sS --cacert "$work/ca.pem" -H 'X-Qadamar-Hop: v1.0.forged.x.x.x' -o "$work/body" -w '%{http_code}' "$base/admin/v1/session")
  [[ $code == 409 && $(field 'v.error' <"$work/body") == not_leader && $(field 'v.leader' <"$work/body") == "$advertised" ]] || fail "cluster: hopped request on $follower: $code $(cat "$work/body")"
  forward "$leader"
  code=$(curl -sS --cacert "$work/ca.pem" -H 'X-Qadamar-Hop: v1.0.forged.x.x.x' -o "$work/body" -w '%{http_code}' "$base/admin/v1/session")
  [[ $code == 401 ]] || fail "cluster: a forged hop must be refused by the leader, got $code"
  pass "cluster: loop guard (hopped request on the follower: 409 not_leader naming $advertised) and forged hop refused by the leader (401)"
  # the whole console flow through the follower: OIDC sign-in with MFA (state cookie, redirects), session, CSRF write, audit
  forward "$follower"
  sso sam
  length=$(verify_audit)
  # sign-out is a CSRF-checked write: cookie and X-CSRF-Token reach the leader intact, and the session is gone after it
  [[ $(auth='' http DELETE /admin/v1/session) == 204 && $(auth='' csrf='' http GET /admin/v1/session) == 401 ]] || fail "cluster: sign-out through $follower: $(cat "$work/body")"
  pass "cluster: OIDC sign-in with MFA, session, audit verify and CSRF-checked sign-out through the follower $follower, forwarded to the leader (length $length)"
  forward "$leader"
  sso sam
  length=$(verify_audit)
  pass "cluster: the same on the leader (length $length)"
  forward "$follower"
  token=$(evaluate "$create_body")
  [[ -n $token ]] || fail "cluster: certified action create returned no decision token"
  forward "$leader"
  code=$(consume "$token" create)
  [[ $code == 200 && $(field 'v.ok' <"$work/body") == true ]] || fail "cluster: token issued by $follower, consumed on $leader: $code"
  forward "$follower"
  [[ $(consume "$token" create) == 409 ]] || fail "cluster: the token consumed on the leader must be refused on the follower"
  pass "cluster: a decision token issued by the follower was consumed on the leader and refused on reuse (409) on the follower: consumed once across nodes"
  # leader loss: the follower keeps deciding and takes the lead
  t0=$(now_ms)
  k delete pod "$leader" --wait=false >/dev/null
  decisions=0 failures=0 led=''
  for _ in $(seq 1 300); do
    code=$(auth=$pep http POST /access/v1/evaluation "$(with_session "$read_body")"); decisions=$((decisions + 1))
    [[ $code == 200 ]] || failures=$((failures + 1))
    if [[ $(http GET /leaderz) == 200 ]]; then led=$(now_ms); break; fi
    sleep 0.1
  done
  [[ -n $led ]] || fail "cluster: $follower did not take the lead within 30 s of deleting $leader"
  lead_s=$(seconds "$t0" "$led")
  (( failures == 0 )) || fail "cluster: $failures of $decisions decisions failed on $follower while the leader stopped"
  sso sam
  length=$(verify_audit)
  pass "cluster: leader $leader deleted; $follower decided throughout ($decisions decisions, 0 failed) and led after ${lead_s}s; sign-in and audit verify on it, length $length"
  for _ in $(seq 1 240); do [[ $(ready_pods | grep -c .) == 2 ]] && break; sleep 0.5; done
  [[ $(ready_pods | grep -c .) == 2 && $(ready_pods | grep -cx "$leader") == 1 ]] || fail "cluster: the StatefulSet did not bring $leader back ready"
  # the restarted node has the same GATE_NODE_ID and continues its own audit chain: its first row predates the restart,
  # and a decision it takes now is a later row of that chain; the audit still verifies (admin through the new follower)
  forward "$leader"
  evaluate "$read_body" >/dev/null
  sso sam
  code=$(auth='' http GET "/admin/v1/audit?cursor=$leader:0&limit=1")
  [[ $code == 200 && $(field 'v.items[0].node' <"$work/body") == "$leader" ]] || fail "cluster: chain $leader: $code $(cat "$work/body")"
  first=$(field 'Date.parse(v.items[0].ts)' <"$work/body")
  (( first < t0 )) || fail "cluster: the chain of $leader must start before its restart"
  length2=$(verify_audit)
  (( length2 > length )) || fail "cluster: audit length must grow after the restarted node decided ($length -> $length2)"
  pass "cluster: $leader came back under the same name and continued its audit chain (first row before the restart); audit verified through the follower, length $length2"
  t0=$(now_ms)
  k rollout restart statefulset/gate >/dev/null
  k rollout status statefulset/gate --timeout=300s >/dev/null || fail "cluster: rollout restart did not complete"
  rollout_s=$(seconds "$t0" "$(now_ms)")
  [[ $(ready_pods | sort | tr '\n' ' ') == "$(printf '%s\n' $pods | sort | tr '\n' ' ')" ]] || fail "cluster: after the rollout, the same 2 pod names must be ready"
  pass "cluster: rolling restart (one pod at a time) completed in ${rollout_s}s; the same node ids are ready again"
  printf '\nSummary for tenant %s (GATE_PROFILE=production, GATE_CLUSTER=true)\n' "$tenant"
  printf '  2 deciding pods (stable ids %s), admin through either pod (followers forward to the leader); token consumed once across nodes\n' "$(printf '%s ' $pods)"
  printf '  leader loss: follower decided throughout (%s decisions, 0 failed), led after %ss\n' "$decisions" "$lead_s"
  printf '  restarted node continued its audit chain; rolling restart completed in %ss\n' "$rollout_s"
  close_sessions; revoke_scoped_pep
  exit 0
fi

# ---------------------------------------------------------------- 1. the active node, production profile
active=$(ready_pods)
[[ $(printf '%s\n' "$active" | grep -c .) == 1 ]] || fail "expected exactly one ready pod, got: $active"
[[ $(running_pods) == 2 ]] || fail "expected 2 running Qadamar pods, got $(running_pods)"
[[ $(endpoints | awk '$2 == "true"' | grep -c .) == 1 && $(ready_endpoint) == "$active" ]] ||
  fail "the Service must route to the active pod only: $(endpoints | tr '\n' ',')"
pass "2 pods running, 1 ready ($active); the Service has exactly one ready endpoint, the active pod"
k logs "$active" -c gate | grep -q '^PDP listening at https://' || fail "the active node does not serve https"
pass "GATE_PROFILE=production, no pinned clock: every production check passed at start (OIDC+MFA, TSA, webhook, database role, seal, metrics token, SOD_HISTORY=server); serving https"
forward "$active"
auth='' cookie='' csrf=''
[[ $(http GET /healthz) == 200 ]] || fail /healthz
[[ $(http GET /readyz) == 200 && $(field 'v.active' <"$work/body") == true ]] || fail "/readyz $(cat "$work/body")"
curl -sS -o /dev/null "$base/healthz" 2>/dev/null && fail "the certificate must not verify without the tenant's test CA"
pass "https with the tenant's certificate (verified against its test CA only); /healthz 200, /readyz 200 (active, audit verified)"
[[ $(http GET /metrics) == 401 ]] || fail "/metrics without the token must be 401"
code=$(auth=$metrics_token http GET /metrics)
[[ $code == 200 ]] && grep -q '^gate_active_node 1$' "$work/body" || fail "/metrics with the token: $code"
pass "/metrics 401 without the token, 200 with it (gate_active_node 1)"

# ---------------------------------------------------------------- 2. PEP and console sign-in through the IdP
code=$(http POST /access/v1/evaluation '{"subject":{"type":"user","id":"bob"},"action":{"name":"read"},"resource":{"type":"case","id":"CASE-14"}}')
[[ $code == 401 ]] || fail "evaluation without the PEP key must be 401, got $code"
evaluate '{"subject":{"type":"user","id":"bob"},"action":{"name":"read"},"resource":{"type":"case","id":"CASE-14"},"context":{"sessionId":"smoke"}}' >/dev/null
grace_approves='{"subject":{"type":"user","id":"grace"},"action":{"name":"approve"},"resource":{"type":"payment","id":"PAY-3"},"context":{"network":"trusted","sessionId":"smoke"}}'
[[ $(auth=$pep cookie='' csrf='' http POST /access/v1/evaluation "$grace_approves") == 403 && $(field 'v.error' <"$work/body") == context_claim_forbidden ]] ||
  fail "the unscoped bootstrap key must not assert context.network: $(head -c 300 "$work/body")"
[[ $(auth=$(scoped_pep) cookie='' csrf='' http POST /access/v1/evaluation "$(with_session "$grace_approves")") == 200 &&
  $(field 'v.decision' <"$work/body") == false ]] || fail "the maker approving her own payment must be denied: $(head -c 300 "$work/body")"
pass "PEP evaluation with the tenant's key (401 without it) and a PDP session token; the unscoped bootstrap key may not assert context.network (403); maker-checker denies grace approving her own payment (SOD_HISTORY=server)"
[[ $(http POST /admin/v1/session '{"username":"sam","password":"x"}') == 403 ]] || fail "password sign-in must be off with OIDC"
for _ in $(seq 1 50); do curl -sS -o /dev/null --cacert "$work/ca.pem" --connect-to "test-idp:443:127.0.0.1:$idp_port" https://test-idp/jwks 2>/dev/null && break; sleep 0.1; done
sso sam 0
[[ $sso_error == mfa_required && -z $cookie ]] || fail "a sign-in without MFA must be refused (got '${sso_error}')"
sso sam
[[ -z $sso_error ]] || fail "sign-in as sam: $sso_error"
length=$(verify_audit)
[[ $(auth='' http GET "/admin/v1/audit?type=session&cursor=$((length - 3))&limit=3") == 200 ]] || fail "audit list"
[[ $(field 'v.items.filter((r) => r.action === "login" && r.actor === "sam" && r.effect === "allow").at(-1)?.details?.client' <"$work/body") == 127.0.0.1 ]] ||
  fail "the sign-in audit row must carry the client address"
pass "password sign-in off (403); OIDC sign-in without MFA refused (mfa_required); sam (auditor) signed in through the test IdP with MFA; audit verified, length $length; sign-in row records client 127.0.0.1"

# ---------------------------------------------------------------- 3. break-glass notice to the webhook
close_break_glass() { # noor (second security officer: neither opener amira nor an earlier opener lina) revokes and reviews
  # dan's emergencies on CASE-12 (one per pair at a time). With OIDC no access_admin fallback exists, so one officer is not enough.
  local id pick='.filter((e) => e.subjectId === "dan" && e.resourceId === "CASE-12").map((e) => e.id).join(" ")'
  sso noor
  [[ $(auth='' http GET /admin/v1/break-glass) == 200 ]] || fail "break-glass list: $(head -c 300 "$work/body")"
  for id in $(field "v.active$pick" <"$work/body"); do
    [[ $(auth='' http POST "/admin/v1/break-glass/$id/revoke" '{"reason":"Smoke test: close the emergency"}') == 200 ]] || fail "break-glass revoke $id: $(head -c 300 "$work/body")"
  done
  [[ $(auth='' http GET /admin/v1/break-glass) == 200 ]] || fail "break-glass list: $(head -c 300 "$work/body")"
  for id in $(field "v.toReview$pick" <"$work/body"); do
    [[ $(auth='' http POST "/admin/v1/break-glass/$id/review" '{"outcome":"justified","note":"Smoke test of the break-glass review"}') == 200 ]] ||
      fail "break-glass review $id: $(head -c 300 "$work/body")"
  done
}
close_break_glass # an earlier run that stopped half-way leaves the pair pending (409 break_glass_pending)
sso amira
code=$(auth='' http POST /admin/v1/break-glass '{"subjectId":"dan","resourceId":"CASE-12","reason":"Smoke test of the break-glass notice to the receiver","hours":1}')
[[ $code == 201 ]] || fail "break-glass open: $code $(cat "$work/body")"
emergency=$(field 'v.id' <"$work/body")
for _ in $(seq 1 100); do
  k logs deploy/test-webhook | grep -q "^verified notice opened emergency=$emergency " && break
  sleep 0.2
done
k logs deploy/test-webhook | grep -q "^verified notice opened emergency=$emergency " || fail "the webhook did not receive a verified notice for $emergency"
close_break_glass
pass "break-glass opened by amira (access admin, MFA); the signed notice reached the in-cluster receiver and its HMAC verified; revoked and reviewed by noor (a second security officer)"

# ---------------------------------------------------------------- 4. anchoring with the test TSA, verified offline
sso sam
target=$(verify_audit)
t0=$(now_ms)
anchor=''
for _ in $(seq 1 75); do # ANCHOR_INTERVAL is 60 s
  [[ $(auth='' http GET /admin/v1/audit/anchors) == 200 ]] || fail "anchors"
  [[ $(field 'v.lastError ?? ""' <"$work/body") == '' ]] || fail "anchoring error: $(field 'v.lastError' <"$work/body")"
  if [[ $(field "v.items.length > 0 && v.items.at(-1).seq >= $target" <"$work/body") == true ]]; then anchor=$(field 'JSON.stringify(v.items.at(-1))' <"$work/body"); break; fi
  sleep 2
done
[[ -n $anchor ]] || fail "no anchor of the audit head within 150 s"
anchor_s=$(seconds "$t0" "$(now_ms)")
seq=$(printf '%s' "$anchor" | field 'v.seq'); hash=$(printf '%s' "$anchor" | field 'v.hash')
printf '%s' "$anchor" | field 'v.token' | base64 -d >"$work/anchor.tst"
openssl ts -verify -digest "$hash" -in "$work/anchor.tst" -token_in -CAfile "$work/ca.pem" 2>/dev/null | grep -q '^Verification: OK$' ||
  fail "the anchor token does not verify offline against the test CA"
openssl ts -verify -digest "$(printf '0%.0s' $(seq 1 64))" -in "$work/anchor.tst" -token_in -CAfile "$work/ca.pem" >/dev/null 2>&1 &&
  fail "the anchor token must not verify for another hash"
[[ $(auth='' http GET "/admin/v1/audit?cursor=$((seq - 1))&limit=1") == 200 && $(field 'v.items[0].hash' <"$work/body") == "$hash" ]] ||
  fail "the anchored hash is not the hash of audit row $seq"
pass "audit head anchored by the test TSA (seq $seq, $(printf '%s' "$anchor" | field 'v.genTime'), waited ${anchor_s}s); token verified offline with openssl against the test CA, refused for another hash; hash = audit row $seq"

# ---------------------------------------------------------------- 5. failover
results=()
for mode in graceful forced; do
  if [[ $mode == graceful ]]; then token=$(evaluate "$create_body") action=create
  else token=$(evaluate "$approve_body") action=approve; fi
  [[ -n $token ]] || fail "certified action $action returned no decision token"
  old=$active
  t0=$(now_ms)
  if [[ $mode == graceful ]]; then k delete pod "$old" --wait=false >/dev/null
  else k delete pod "$old" --grace-period=0 --force --wait=false >/dev/null 2>&1; fi
  active=''
  for _ in $(seq 1 600); do
    candidate=$(ready_pods | grep -vx "$old" || true)
    if [[ -n $candidate ]] && ready_endpoint | grep -qx "$candidate"; then active=$candidate; break; fi
    sleep 0.1
  done
  t_ready=$(now_ms)
  [[ -n $active ]] || fail "$mode failover: no other pod became ready"
  forward "$active"
  [[ $(auth='' cookie='' csrf='' http GET /readyz) == 200 ]] || fail "$mode failover: /readyz on $active"
  t_answer=$(now_ms)
  ready_s=$(seconds "$t0" "$t_ready"); answer_s=$(seconds "$t0" "$t_answer")
  code=$(consume "$token" "$action")
  consumed_s=$(seconds "$t0" "$(now_ms)")
  [[ $code == 200 && $(field 'v.ok' <"$work/body") == true ]] || fail "$mode failover: token consume ($action): $code $(cat "$work/body")"
  sso sam
  new_length=$(verify_audit)
  (( new_length >= length )) || fail "$mode failover: audit length went from $length to $new_length"
  length=$new_length
  pass "$mode failover $old -> $active: Service endpoint ready after ${ready_s}s, answering after ${answer_s}s; $action token issued before it consumed ${consumed_s}s after the delete (TTL 15 s, real clock); audit verified, length $length"
  results+=("$mode failover: endpoint ready ${ready_s}s, node answering ${answer_s}s, token consumed ${consumed_s}s after the delete")
  for _ in $(seq 1 240); do [[ $(running_pods) == 2 ]] && break; sleep 0.5; done # the replacement standby
  [[ $(running_pods) == 2 ]] || fail "$mode failover: the Deployment did not bring back a second pod"
done
code=$(consume "$token" approve)
[[ $code == 409 ]] || fail "a consumed token must be refused on reuse, got $code"
pass "reusing a consumed decision token after the failovers is refused (409); standby replaced after each failover"

# ---------------------------------------------------------------- 6. cold start of both pods (upgrade path)
old_pods=$(k get pods -l app.kubernetes.io/component=server -o jsonpath='{.items[*].metadata.name}')
t0=$(now_ms)
k rollout restart deployment/gate >/dev/null
active=''
for _ in $(seq 1 1200); do
  candidate=$(ready_pods | grep -vxF -f <(printf '%s\n' $old_pods) || true)
  if [[ -n $candidate ]] && [[ $(ready_endpoint) == "$candidate" ]]; then active=$candidate; break; fi
  sleep 0.1
done
[[ -n $active ]] || fail "rollout restart: no new pod became ready"
cold_s=$(seconds "$t0" "$(now_ms)")
forward "$active"
sso sam
length=$(verify_audit)
pass "rollout restart (both pods replaced, production checks rerun): new active pod $active ready ${cold_s}s after the restart; audit verified, length $length"
for _ in $(seq 1 240); do [[ $(running_pods) == 2 ]] && break; sleep 0.5; done

# ---------------------------------------------------------------- 7. backup
auth=$metrics_token cookie='' csrf='' http GET /metrics >/dev/null
backup_length=$(awk '$1 == "gate_audit_length" { print $2 }' "$work/body")
job="gate-backup-smoke-$stamp"
t0=$(now_ms)
k create job --from=cronjob/gate-backup "$job" >/dev/null
for _ in $(seq 1 600); do
  state=$(k get job "$job" -o jsonpath='{.status.succeeded}/{.status.failed}')
  [[ $state == 1/* ]] && break
  if [[ $state == */[1-9]* ]]; then k logs "job/$job" >&2 || true; fail "backup job failed"; fi
  sleep 0.5
done
backup_s=$(seconds "$t0" "$(now_ms)")
archive=$(k logs "job/$job" | sed -n 's/^Backup created, validated and encrypted: //p')
[[ $archive == /backups/gate-*.dump.gcm ]] || fail "backup job did not report a validated archive"
pass "backup CronJob run once as Job $job in ${backup_s}s: $archive (audit length $backup_length at backup time)"

# ---------------------------------------------------------------- 8. restore drill
ops_image=$(k get cronjob gate-backup -o jsonpath='{.spec.jobTemplate.spec.template.spec.containers[0].image}')
pull=$(k get cronjob gate-backup -o jsonpath='{.spec.jobTemplate.spec.template.spec.containers[0].imagePullPolicy}')
restricted='{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"privileged":false,"capabilities":{"drop":["ALL"]}}'
podsec='{"runAsNonRoot":true,"runAsUser":1000,"runAsGroup":1000,"fsGroup":1000,"seccompProfile":{"type":"RuntimeDefault"}}'
labels='{"app.kubernetes.io/name":"gate","app.kubernetes.io/component":"restore","qadamar.example/smoke":"restore-drill"}'
resources='{"requests":{"cpu":"50m","memory":"96Mi"},"limits":{"cpu":"1","memory":"512Mi"}}'
owner_env='{"name":"OWNER_DATABASE_URL","valueFrom":{"secretKeyRef":{"name":"gate-db-admin","key":"OWNER_DATABASE_URL"}}}'
# restore.sh as the owner, then the grants gate-migrate gives (role names from the migration Job)
service_role=$(k get job gate-migrate -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="SERVICE_ROLE")].value}')
backup_role=$(k get job gate-migrate -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="BACKUP_ROLE")].value}')
# the same statements as serviceGrants and backupGrants (packages/pdp-http/src/postgres-schema.ts; k8s.test.ts compares them)
grants="GRANT SELECT, INSERT, UPDATE ON gate_doc, gate_audit_meta TO $service_role; GRANT SELECT, INSERT ON gate_audit, gate_anchor, gate_performed, gate_retired, gate_state_change TO $service_role; GRANT SELECT ON gate_audit_segment TO $service_role; GRANT SELECT, INSERT, UPDATE, DELETE ON gate_subject_identity TO $service_role; GRANT SELECT, UPDATE ON gate_sync TO $service_role; GRANT SELECT, INSERT, UPDATE, DELETE ON gate_token, gate_session, gate_blp_mark, gate_blp_session, gate_subject, gate_resource, gate_tuple, gate_rate_limit TO $service_role; GRANT SELECT ON gate_doc, gate_audit, gate_audit_meta, gate_anchor, gate_audit_segment, gate_subject_identity, gate_sync, gate_token, gate_performed, gate_session, gate_blp_mark, gate_blp_session, gate_retired, gate_subject, gate_resource, gate_tuple, gate_state_change, gate_rate_limit TO $backup_role;"
key_env='{"name":"BACKUP_ENCRYPTION_KEY","valueFrom":{"secretKeyRef":{"name":"gate-backup","key":"BACKUP_ENCRYPTION_KEY"}}}'
t0=$(now_ms)
k apply -f - >/dev/null <<JSON
{"apiVersion":"v1","kind":"Pod","metadata":{"name":"gate-restore-$stamp","labels":$labels},
 "spec":{"restartPolicy":"Never","automountServiceAccountToken":false,"enableServiceLinks":false,"securityContext":$podsec,
  "containers":[{"name":"restore","image":"$ops_image","imagePullPolicy":"$pull","securityContext":$restricted,"resources":$resources,
   "env":[$owner_env,$key_env,{"name":"BACKUP_FILE","value":"$archive"},{"name":"RESTORE_DB","value":"$restore_db"},{"name":"GRANTS","value":"$grants"},{"name":"GATE_PROFILE","value":"production"},{"name":"DATABASE_TLS","value":"verify-full"},{"name":"DATABASE_TLS_CA_FILE","value":"/etc/gate/postgres/ca.crt"}],
   "command":["bash","-c","set -euo pipefail; export PGSSLMODE=verify-full PGSSLROOTCERT=/etc/gate/postgres/ca.crt; echo \"archive bytes: \$(stat -c %s \"\$BACKUP_FILE\")\"; echo \"archive header: \$(head -c 6 \"\$BACKUP_FILE\")\"; export DATABASE_URL=\"\${OWNER_DATABASE_URL%/*}/\$RESTORE_DB\"; if MAINTENANCE_DATABASE_URL=\"\${OWNER_DATABASE_URL%/*}/postgres\" BACKUP_ENCRYPTION_KEY=\$(od -An -N32 -tx1 /dev/urandom | tr -d ' \\n') bash /opt/gate/restore.sh 2>/tmp/wrong-key.log; then echo 'wrong key accepted'; exit 1; fi; grep -q 'did not decrypt' /tmp/wrong-key.log && echo 'Wrong key refused'; MAINTENANCE_DATABASE_URL=\"\${OWNER_DATABASE_URL%/*}/postgres\" bash /opt/gate/restore.sh; echo \"gate tables restored: \$(psql -v ON_ERROR_STOP=1 -qtA \"\$DATABASE_URL\" -c \"SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'gate%'\")\"; echo \"gate tables in the source: \$(psql -v ON_ERROR_STOP=1 -qtA \"\$OWNER_DATABASE_URL\" -c \"SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'gate%'\")\"; psql -v ON_ERROR_STOP=1 -q \"\$DATABASE_URL\" -c \"\$GRANTS\"; echo 'Grants applied'"],
   "volumeMounts":[{"name":"backups","mountPath":"/backups","readOnly":true},{"name":"tmp","mountPath":"/tmp"},{"name":"postgres-tls","mountPath":"/etc/gate/postgres","readOnly":true}]}],
  "volumes":[{"name":"backups","persistentVolumeClaim":{"claimName":"gate-backups","readOnly":true}},{"name":"tmp","emptyDir":{"medium":"Memory","sizeLimit":"16Mi"}},{"name":"postgres-tls","secret":{"secretName":"gate-postgres-tls","defaultMode":0440}}]}}
JSON
for _ in $(seq 1 600); do
  phase=$(k get pod "gate-restore-$stamp" -o jsonpath='{.status.phase}')
  [[ $phase == Succeeded ]] && break
  if [[ $phase == Failed ]]; then k logs "gate-restore-$stamp" >&2 || true; fail "restore failed"; fi
  sleep 0.5
done
restore_s=$(seconds "$t0" "$(now_ms)")
k logs "gate-restore-$stamp" >"$work/restore.log"
tables=$(sed -n 's/^gate tables restored: //p' "$work/restore.log")
[[ -n $tables && $tables -gt 0 && $tables == $(sed -n 's/^gate tables in the source: //p' "$work/restore.log") ]] ||
  fail "the restored database must hold every gate table of the source: $(grep '^gate tables' "$work/restore.log" | tr '\n' ' ')"
archive_bytes=$(sed -n 's/^archive bytes: //p' "$work/restore.log")
grep -q '^Restore completed' "$work/restore.log" && grep -q '^Grants applied' "$work/restore.log" || fail "restore.sh or the grants did not complete"
[[ $(sed -n 's/^archive header: //p' "$work/restore.log") == GATEBK ]] || fail "the archive is not in the encrypted format (GATEBK header)"
grep -q '^Wrong key refused' "$work/restore.log" || fail "restore.sh must refuse the archive under another key"
pass "archive encrypted at rest (GATEBK, AES-256-GCM), refused under a random key before any database was created; decrypted ($archive_bytes bytes) and restored with all $tables gate tables of the source by restore.sh into the fresh database $restore_db and the service/backup grants in ${restore_s}s"

# a throwaway Qadamar node on the restored database: the Deployment's own pod (production profile, service role), with
# DATABASE_URL pointed at the restored database and labels the Service does not select (advisory locks are per database)
t1=$(now_ms)
k get deployment gate -o json | node -e '
let s = ""; process.stdin.on("data", (d) => s += d).on("end", () => {
  const [name, db, labels] = process.argv.slice(1);
  const spec = JSON.parse(s).spec.template.spec;
  const gate = spec.containers[0];
  gate.env.push({ name: "RESTORE_DB", value: db });
  gate.command = ["sh", "-c", "export DATABASE_URL=\"${DATABASE_URL%/*}/$RESTORE_DB\"; exec node packages/pdp-http/src/main.ts"];
  delete gate.livenessProbe; delete gate.startupProbe;
  delete spec.topologySpreadConstraints;
  process.stdout.write(JSON.stringify({ apiVersion: "v1", kind: "Pod", metadata: { name, labels: JSON.parse(labels) },
    spec: { ...spec, restartPolicy: "Never" } }));
});' "gate-restore-check-$stamp" "$restore_db" "$labels" | k apply -f - >/dev/null
if ! k wait --for=condition=Ready "pod/gate-restore-check-$stamp" --timeout=180s >/dev/null; then
  k logs "gate-restore-check-$stamp" >&2 || true
  fail "Qadamar on the restored database never became ready"
fi
check_s=$(seconds "$t1" "$(now_ms)")
total_s=$(seconds "$t0" "$(now_ms)")
forward "gate-restore-check-$stamp"
[[ $(auth='' cookie='' csrf='' http GET /readyz) == 200 && $(field 'v.active' <"$work/body") == true ]] || fail "/readyz on the restored node"
auth=$metrics_token cookie='' csrf='' http GET /metrics >/dev/null
restored_length=$(awk '$1 == "gate_audit_length" { print $2 }' "$work/body")
(( restored_length >= backup_length )) || fail "restored chain length $restored_length < $backup_length at backup time"
pass "production-profile Qadamar (service role) on the restored database ready in ${check_s}s (restore start to ready ${total_s}s); /readyz verified the audit chain, length $restored_length (backup: $backup_length)"
kill "$pf" 2>/dev/null || true; wait "$pf" 2>/dev/null || true; pf=''
k delete pod "gate-restore-check-$stamp" "gate-restore-$stamp" --wait=true >/dev/null
k exec postgres-0 -c postgres -- sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" dropdb -h 127.0.0.1 -U postgres --force "$1"' sh "$restore_db" 2>/dev/null ||
  printf 'note: could not drop the drill database %s (not the local overlay?); drop it by hand\n' "$restore_db"

forward "$(ready_pods)" # the drill closed the forward to the tenant
close_sessions; revoke_scoped_pep
printf '\nSummary for tenant %s (GATE_PROFILE=production)\n' "$tenant"
for line in "${results[@]}"; do printf '  %s\n' "$line"; done
printf '  cold start of both pods (rollout restart): new active node ready %ss\n' "$cold_s"
printf '  anchoring: anchor of the head after %ss (ANCHOR_INTERVAL 60 s), token verified offline\n' "$anchor_s"
printf '  backup: %ss, archive %s bytes, audit length %s\n' "$backup_s" "$archive_bytes" "$backup_length"
printf '  restore drill: restore.sh + grants %ss, Qadamar on the restored database ready %ss later, %ss in all, chain verified\n' "$restore_s" "$check_s" "$total_s"
printf 'Timings come from kubectl polling (~0.1-0.3 s) on one laptop: indicative, not SLOs.\n'
