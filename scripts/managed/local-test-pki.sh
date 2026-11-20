#!/usr/bin/env bash
# LOCAL OVERLAY ONLY. Writes a throwaway test PKI for one tenant into an empty directory: a test CA (ca.crt; its key is
# deleted once the four certificates are signed), the TLS certificate Qadamar serves at https://localhost:18787
# (gate.crt/gate.key), the TLS certificates of PostgreSQL and the test IdP, TSA and webhook (services.crt/services.key) and the
# time-stamp signer of the test TSA (tsa.crt/tsa.key, extended key usage timeStamping). new-tenant.sh stores them in
# Secrets and deletes the directory. A customer tenant uses the customer's certificates, IdP and TSA instead.
# Usage: scripts/managed/local-test-pki.sh <empty directory> <namespace>
set -euo pipefail
umask 077
dir=${1:?Usage: local-test-pki.sh <empty directory> <namespace>}
ns=${2:?Usage: local-test-pki.sh <empty directory> <namespace>}
cd "$dir"
[[ -z $(ls -A) ]] || { printf 'The directory must be empty.\n' >&2; exit 2; }
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
# leaf <name> <subject CN> <extensions>
leaf() {
  key "$1.key"
  openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null
  printf '%s\n' "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -sha256 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
  rm -f "$1.csr" "$1.ext"
}
key ca.key
openssl req -x509 -new -key ca.key -days 30 -sha256 -subj "/CN=Qadamar local TEST CA ($ns)" -out ca.crt \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null
tls='basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth'
leaf gate "gate.$ns (test)" "$tls
subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:gate,DNS:gate.$ns.svc,DNS:*.gate-nodes.$ns.svc"
leaf postgres "postgres.$ns (test)" "$tls
subjectAltName=DNS:postgres,DNS:postgres.$ns.svc"
leaf services "test services $ns" "$tls
subjectAltName=DNS:test-idp,DNS:test-tsa,DNS:test-webhook,DNS:test-idp.$ns.svc,DNS:test-tsa.$ns.svc,DNS:test-webhook.$ns.svc"
leaf tsa "Qadamar local TEST TSA ($ns)" 'basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping'
rm -f ca.key ca.srl
chmod 600 ./*.key
