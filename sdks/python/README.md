# Qadamar Python SDK

The PEP SDK for backends and PEPs written in Python: the contract of the TypeScript SDK (`packages/sdk`) with
Python names. Python 3.9 or later, standard library only (no runtime dependency, no `cryptography`).

- `PepClient`: PDP sessions (`open_session`, `close_session`), evaluation, batch evaluations, the three searches, explain,
  the SQL filter, decision-token consumption and outcome reports, decision assertions (`evaluate_asserted`, `assert_list`)
  and resource registration. Every answer
  is checked against its exact shape; anything unexpected raises (fail closed).
- `enforce()`: applies `fieldAllowlist`, `redact` and `maskClasses` to a copy of a JSON record, and refuses a deny,
  an unknown obligation key, `notify`, a `decisionToken` unless `decision_token_consumed=True` acknowledges `consume_token`, or a content class it cannot locate.
- `AssertionVerifier`: the backend side of the gateway's `gate-assertion` header (docs/API.md 2.0.2), with Ed25519
  verified in pure Python.

## Install

From a checkout of the repository (it is not published to an index):

```sh
pip install ./sdks/python          # or: pip install -e ./sdks/python
```

Without installing, put `sdks/python` on `PYTHONPATH`. Building the wheel needs `setuptools` (pip fetches it unless it
is already installed); the installed package needs nothing.

## A PEP

```python
import os
from qadamar import AccessDeniedError, PepClient

pdp = PepClient("https://pdp.internal", os.environ["GATE_PEP_KEY"], timeout=5)
session = pdp.open_session({"type": "user", "id": "bob"})
request = {"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"},
           "resource": {"type": "case", "id": "CASE-14"},
           "context": {"network": "trusted", "sessionToken": session["token"]}}

try:
    record = pdp.enforce(request, load_case("CASE-14"))   # evaluate, then apply the obligations to a copy
except AccessDeniedError:
    ...  # answer 403; nothing of the record is released
finally:
    pdp.close_session(session["token"])
```

`pdp.evaluate(request)` returns the decision itself (`{"decision", "context": {"rules", "reasons", "obligations",
"policy_version", "would_deny", "decision_token"?}}`); `enforce(decision, record)` is also a module-level function.
Requests and answers are plain dicts with the field names of docs/API.md (`qadamar.types` describes them for
type checkers). `ca_file=` names a CA bundle for a PDP certificate outside the system trust store. Production requires
`sessionToken`; raw `sessionId` remains only as deprecated demo compatibility. Open tokens for one subject and credential
share their high-water mark, so opening another cannot reset it.

A certified command (Clark-Wilson) consumes its decision token, runs, then reports what became of it:

```python
decision = pdp.evaluate({"subject": {"type": "user", "id": "henry"}, "action": {"name": "approve"},
                         "resource": {"type": "payment", "id": "PAY-3"}, "context": {"network": "trusted"}})
token = decision["context"]["decision_token"]
reservation = pdp.consume_token({"token": token, "action": "approve", "resource": {"type": "payment", "id": "PAY-3"},
                                 "resourceVersion": 4})["reservation"]
ran = approve_payment("PAY-3")
pdp.report_outcome({"reservation": reservation, "outcome": "completed" if ran else "failed"})
```

The application that owns records registers them with a credential bound to their types:

```python
app = PepClient("https://pdp.internal", os.environ["GATE_CASE_APP_KEY"])
app.register_resource({"type": "case", "id": "CASE-100", "level": 1, "compartments": [], "integrity": "system",
                       "contentClasses": [], "owner": "carol"})
app.sync_resources({"resources": records, "retire": [{"type": "case", "id": "CASE-7"}]})   # up to 1000, all or nothing
page = app.list_resources({"type": "case", "limit": 1000})   # pass page["next_cursor"] back until it is ""
app.retire_resource({"type": "case", "id": "CASE-100"})
```

Other methods: `evaluate_batch`, `search_resources`, `search_subjects`, `search_actions`, `explain`, `filter`,
`evaluate_asserted`, `assert_list`.

## A backend behind the gateway

The gateway forwards every request with a `gate-assertion` header signed by the PDP. The backend verifies it and reads
who, what and which item from the verified claims, never from caller-controlled headers:

```python
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from qadamar import ASSERTION_HEADER, AssertionVerifier, GateAssertionError, status_for

verifier = AssertionVerifier("https://pdp.internal/.well-known/jwks.json", audience="http://10.0.0.5:8080")

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.rfile.read(int(self.headers.get("content-length") or 0))  # bound it first
        try:
            claims = verifier.verify(self.command, self.path, body, self.headers.get(ASSERTION_HEADER))
        except GateAssertionError as error:
            self.send_response(status_for(error))   # 401, or 503 when the JWKS or the replay store is unavailable
            self.end_headers()
            return
        ...  # claims["sub"], claims["act"], claims["res"], claims["did"]

ThreadingHTTPServer(("10.0.0.5", 8080), Handler).serve_forever()
```

`path` must be the raw request target, path and query exactly as received (`self.path` in `http.server`; under WSGI
use the server's raw target such as `RAW_URI` or `REQUEST_URI`, not a path rebuilt from `PATH_INFO`). A path that
differs fails closed with `assertion_mismatch`.

Options: `clock_skew_seconds` (0..60, default 5), `jwks_cache_seconds` (10..86400, default 300; an unknown `kid`
refetches at most every 10 s), `timeout` (seconds), `ca_file`, `replay_store`. Each nonce is accepted once, by default
within this process (`MemoryReplayStore`). Several processes or replicas must share one store: any object with
`spend(nonce, expires_at) -> bool` doing an atomic check-and-set (True the first time). With redis-py:

```python
class RedisReplayStore:
    def spend(self, nonce, expires_at):
        ttl_ms = max(1000, int(expires_at * 1000 - time.time() * 1000))
        return redis.set(f"gate:nonce:{nonce}", "1", nx=True, px=ttl_ms) is True
```

A store that raises fails the request closed (503).

## Errors

`PepError` (`code`, `message`) and its subclasses: `PdpHttpError` (`status`, `code` from the PDP's `error` field,
`retry_after`), `PdpResponseError` (`invalid_response`), `PdpNetworkError` (`network_error`, `request_timeout`),
`AccessDeniedError`, `ObligationError`, and `GateAssertionError` (`assertion_missing`, `assertion_invalid`,
`assertion_expired`, `assertion_mismatch`, `assertion_replayed`, `assertion_key_unknown`, `jwks_unavailable`,
`replay_store_unavailable`). A request the SDK refuses before sending raises `PepError` with `invalid_request`.
Messages never carry the API key or record content.

## Differences from the TypeScript SDK

- Python names (`evaluate_batch`, `consume_token`, `retry_after`, ...); requests and answers are dicts with the wire
  field names. `AssertionError` is `GateAssertionError`, so it never shadows Python's built-in.
- `explain()` is added (`POST /x/v1/explain`; its answer is validated too).
- No abort signal. `timeout` bounds the request: it is checked between reads, each read bounded by the socket timeout.
- No `withGateAssertion` middleware or example backend: Python frameworks differ, so `verify()` plus `status_for()`
  is the API (above).
- HTTP redirects are not followed (a 3xx is a `PdpHttpError`) and proxy environment variables are ignored, so the
  bearer key only ever goes to `base_url`. TLS uses the system trust store, or `ca_file`.
- Ed25519 is the RFC 8032 section 6 reference algorithm in Python (`qadamar.ed25519`, verification only). It
  is **not constant-time**; that is acceptable because verification handles public data only (key, message,
  signature), so timing reveals nothing secret. A verification takes a few milliseconds.

## Tests

```sh
cd sdks/python && python3 -m unittest discover -s tests
```

Unit tests, the RFC 8032 section 7.1 vectors (TEST 1, 2, 3 and SHA(abc)), and an end-to-end run that starts the real
PDP (`node packages/pdp-http/src/main.ts`, demo profile, 127.0.0.1, a temporary `DATA_DIR`); that one is skipped when
`node` is not on the `PATH`. `tools/ci/checks.sh` (and so `tools/ci/local.sh`) runs them.
