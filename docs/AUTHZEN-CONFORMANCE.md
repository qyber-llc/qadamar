# AuthZEN external vector conformance

## Scope and provenance

Qadamar replays the OpenID AuthZEN working group's **Todo interoperability decision vectors**, not merely requests derived
from Qadamar's own tests. The vectors were copied unmodified from `interop/authzen-todo-backend/test` in
`https://github.com/openid/authzen` at commit **`05dc553`** (downloaded 2026-11-06). Their MIT licence and exact source
paths are retained in `packages/pdp-http/test/authzen-official/README.md`.

This is local, reproducible interoperability evidence, **not OpenID certification**. The certification scenario at
`certification/authorization-api-1_0-scenario.md` was reviewed when scoping the suite; this run covers the separate Todo
interop decision corpora and does not claim completion of that certification harness, its HTTPS checks, or its search and
discovery levels.

## Result

Command run on Node.js 22.23.3:

```bash
node --test packages/pdp-http/test/authzen-official.test.ts
```

The test itself prints `AUTHZEN_OFFICIAL total=163 passed=163 skipped=0 failed=0`.

| Vector file | Evaluation vectors | Batch vectors | Passed | Skipped | Failed |
|---|---:|---:|---:|---:|---:|
| `decisions.json` (legacy) | 40 | 0 | 40 | 0 | 0 |
| `decisions-authorization-api-1_0-00.json` | 40 | 0 | 40 | 0 | 0 |
| `decisions-authorization-api-1_0-01.json` | 40 | 0 | 40 | 0 | 0 |
| `decisions-authorization-api-1_0-02.json` | 40 | 3 | 43 | 0 | 0 |
| **Total** | **160** | **3** | **163** | **0** | **0** |

There are no skipped vectors and therefore no missing-capability exclusions. No PDP implementation change was required.

## How the replay works

`packages/pdp-http/test/authzen-official.test.ts` starts the real PDP server on an ephemeral loopback port with
`examples/authzen-todo` as its world. It reads the generated PEP credential, then sends every vector over HTTP to the
same `/access/v1/evaluation` or `/access/v1/evaluations` endpoint and with the same JSON request body as the upstream
`runner.ts`. It requires HTTP 200 and compares the expected decision values. Optional response `context` objects are not
part of that comparison; AuthZEN permits them and the official vectors specify decisions, not explanation contents. Every
vector is an individual `node:test` subtest, so a failure names its source file, array index, endpoint, request, expected
value, actual value, and HTTP response.

The example implements the scenario's five users and `viewer`, `editor`, `admin`, and `evil_genius` roles. Both encoded
subject IDs and legacy email aliases are present. Todo ownership is resolved from Qadamar's `world.json`; request
`properties.ownerID` and the legacy `ownerID` field remain untrusted and are ignored. This preserves Qadamar's rule that the
PDP, not the caller, supplies security attributes while producing the decisions required by the vectors.

To run the example manually, use a separate data directory so it does not replace the demo state:

```bash
DATA_DIR=data/authzen-todo WORLD_DIR=examples/authzen-todo \
  CLOCK=fixed:2026-11-08T10:00:00Z node packages/pdp-http/src/main.ts
```
