# Integrate a policy enforcement point

A PEP authenticates the end user, asks Qadamar for decisions, and releases data or executes commands only after enforcing every obligation. Use the TypeScript SDK for application code, the enforcing gateway for JSON HTTP APIs, residual SQL for list queries, decision-token consumption for certified commands, and decision assertions so that a backend accepts only requests the PDP decided.

## On this page

- [Create and protect a PEP credential](#create-and-protect-a-pep-credential)
- [Evaluate with the TypeScript SDK](#evaluate-with-the-typescript-sdk)
- [Apply obligations to records](#apply-obligations-to-records)
- [Search and filter lists](#search-and-filter-lists)
- [Compile a PostgreSQL list filter](#compile-a-postgresql-list-filter)
- [Consume certified-command tokens](#consume-certified-command-tokens)
- [Register the records your application owns](#register-the-records-your-application-owns)
- [Deploy the enforcing gateway](#deploy-the-enforcing-gateway)
- [Verify decision assertions in the backend](#verify-decision-assertions-in-the-backend)
- [Handle failures closed](#handle-failures-closed)

For runnable PostgreSQL replay protection and SQL filtering followed by row/action checks, see
[Integration safety examples](integration-safety.md).

## Create and protect a PEP credential

A security officer creates credentials in **Credentials and keys → PEP credentials**. Use a distinct credential per PEP and store its one-time secret in the PEP's secret manager. Send it only as:

```http
Authorization: Bearer pep.<credential-id>.<random>
```

The PDP API accepts only bearer-authenticated POST requests under `/access/`, `/x/`, and `/xacml/v3/authorize`. Do not use the PEP credential as an end-user identity, put it in a browser application, or send it in a URL. Rotate with an overlap and revoke the shared `bootstrap` credential after every PEP has its own secret.

If the bundle lists a type in `clarkWilson.requirePepBinding`, certified commands on that type are allowed only for subjects whose type is in the calling credential's `subjectTypes`; otherwise the decision denies with `CW.SUBJECT_NOT_AUTHENTICATED`. The security officer sets `subjectTypes` when creating the credential through the API; see [Manage PEP credentials](security-officer.md#manage-pep-credentials). The binding also applies at token consumption.

Rate limits apply per client address and per credential, 120 requests per minute by default. The client address is the socket address, or the `X-Forwarded-For` client when the connection comes from an address in `TRUSTED_PROXIES`. Sources: `packages/pdp-http/src/auth.ts`, `packages/pdp-http/src/router.ts`, `packages/pdp-http/src/proxy.ts`, `packages/core/src/procedures.ts`.

## Evaluate with the TypeScript SDK

The workspace-private `@product/sdk` package exports `PepClient` and `createPepClient`. Node 22.18 or later runs its TypeScript source directly. Construct the client with the PDP origin and PEP secret:

```ts
import { PepClient } from '@product/sdk';

const pdp = new PepClient({
  baseUrl: 'http://127.0.0.1:8787',
  apiKey: process.env.PEP_API_KEY!,
  timeoutMs: 10_000,
});

const evaluation = await pdp.evaluate({
  subject: { type: 'user', id: 'bob' },
  action: { name: 'read' },
  resource: { type: 'case', id: 'CASE-14' },
  context: { network: 'trusted' },
});

if (!evaluation.decision) {
  throw new Error(`Denied: ${evaluation.context.rules.join(', ')}`);
}
```

The SDK sets the JSON headers and bearer credential, validates every response shape, and defaults to a 10-second timeout. Pass `{ signal }` as the second argument to cancel a call. `PdpClient` is an alias of `PepClient`.

When the bundle has CBAC (context) rules, add the required current assertions to `context`: `ip`, upper-case `country`,
`device: { id?, managed, compliant }`, `networkSensorId` when a network sensor signs evidence, ISO-8601
`authTime`/`mfaTime`, `authMethods`, and integer `riskScore`. The TypeScript and Python SDK request types expose all of
them. A malformed value receives HTTP 400; a missing required signal denies with `CBAC.SIGNAL_MISSING`. Your credential's
`contextScopes` must list each signal you send; an out-of-scope signal or constrained value receives audited 403
`context_claim_forbidden`, never silent removal. Where a scope requires attestation, put the MDM/sensor's compact JWS in
`context.attestations.<signal>`. It binds the exact value, subject `sub`, PDP session `sid` when a session token is used,
device/network source `src`, your credential id, configured audience, attester key and a maximum five-minute lifetime.
Reuse is valid only for that same subject, session and source; missing or mismatched evidence receives 403
`invalid_context_attestation`. See the exact header and claims in [API](../../API.md#2-pdp-api-authzen-authorization-api-10--extensions).
Re-evaluate each request and never reuse a decision for a different context. `CBAC.MFA_STALE` is the step-up MFA signal. When your session layer knows the user's session has expired, send
`context.sessionExpired: true`: the request denies with `CBAC.SESSION_EXPIRED` (a `false` changes nothing; the PDP also
sets it itself when the BLP mark of `context.sessionId` has passed its 15-minute idle or 8-hour absolute expiry).

For batches, use `evaluateBatch`. The outer subject, action, resource, and context are merged into each partial evaluation. Choose `execute_all`, `deny_on_first_deny`, or `permit_on_first_permit`; the server stops early only for the two short-circuit semantics. A batch can contain at most 1,000 evaluations and costs one rate-limit token per evaluation.

```ts
const batch = await pdp.evaluateBatch({
  subject: { type: 'user', id: 'bob' },
  action: { name: 'read' },
  context: { network: 'trusted' },
  evaluations: [
    { resource: { type: 'case', id: 'CASE-14' } },
    { resource: { type: 'case', id: 'CASE-11' } },
  ],
  options: { evaluations_semantic: 'execute_all' },
});
```

Sources: `packages/sdk/src/client.ts`, `packages/sdk/src/types.ts`, `packages/pdp-http/src/pdp.ts`.

## Apply obligations to records

For a read decision, `pdp.enforce(request, record)` evaluates and then applies the obligations to a deep clone. You can also call `enforce(evaluation, record)` yourself. It throws `AccessDeniedError` on deny and `ObligationError` when the record or obligations cannot be handled safely.

```ts
import { enforce, AccessDeniedError, ObligationError } from '@product/sdk';

try {
  const releasable = enforce(evaluation, {
    title: 'Procurement irregularities',
    informant_name: 'Example',
    content: [
      { class: 'finance.amount', text: '1000' },
      { class: 'plain', text: 'Review the supplier history.' },
    ],
  });
  // Return releasable, never the original record.
} catch (error) {
  if (error instanceof AccessDeniedError || error instanceof ObligationError) {
    // Return an authorization-safe refusal and release no record.
  }
}
```

`fieldAllowlist` retains only dotted paths, `redact` sets listed paths to `null`, and `maskClasses` replaces matching fragment text with `[MASKED]`. The record must contain plain JSON values. Masking requires every requested class to occur in `record.content`; arbitrary strings are not scanned.

The SDK rejects `notify` obligations because it has no notification channel. Use the gateway's `notify` hook or implement and successfully complete notification before release in a custom PEP. Sources: `packages/sdk/src/enforce.ts`, `packages/sdk/src/errors.ts`.

## Search and filter lists

Use `searchResources` for resource ids a subject can access, `searchSubjects` for subjects that can access a resource, and `searchActions` for actions allowed on one subject-resource pair. Search results contain identifiers, not record bodies.

Resource and subject searches support pages of 1–1,000, default 100. Continue until `next_token` is empty:

```ts
let token = '';
do {
  const page = await pdp.searchResources({
    subject: { type: 'user', id: 'bob' },
    action: { name: 'read' },
    resource: { type: 'case' },
    context: { network: 'trusted' },
    page: { limit: 100, token },
  });
  for (const resource of page.results) {
    // Load and authorize the actual record before releasing it.
  }
  token = page.page.next_token;
} while (token);
```

The token is an opaque position in the original stored array, not a count of allowed results or a position in the filtered set. Do not construct it yourself. Resource search uses indexed residuals and subject search uses shared relation reachability to prune candidates, including for two-person and SoD actions; every survivor still receives a full point decision. Only those point decisions are audited. Sources: `packages/sdk/src/client.ts`, `packages/pdp-http/src/pdp.ts`, `packages/core/src/candidates.ts`, `packages/core/src/filter.ts`.

## Compile a PostgreSQL list filter

`pdp.filter` returns a residual expression and a parameterized PostgreSQL `WHERE` fragment. Declare every `resource.*` path the residual can read, with its real column and type. Built-in fields have fixed required types: level is `number`, compartments and content classes are `text[]`, and id, type, owner, and integrity are `text`.

```ts
const { sql } = await pdp.filter({
  subject: { type: 'user', id: 'bob' },
  action: { name: 'read' },
  resource: { type: 'case' },
  context: { network: 'trusted' },
  dialect: 'postgres',
  columns: {
    'resource.id': { column: 'id', type: 'text' },
    'resource.type': { column: 'resource_type', type: 'text' },
    'resource.level': { column: 'level', type: 'number' },
    'resource.compartments': { column: 'compartments', type: 'text[]' },
    'resource.contentClasses': { column: 'content_classes', type: 'text[]' },
    'resource.owner': { column: 'owner_id', type: 'text' },
    'resource.integrity': { column: 'integrity', type: 'text' },
    'resource.attrs.status': { column: 'status', type: 'text' },
  },
});

const result = await db.query(
  `SELECT id, title, status FROM cases WHERE ${sql.text}`,
  sql.params,
);
```

`sql.text` is an expression, not a complete statement. Column identifiers allow one to three dot-separated lowercase SQL identifier parts; values become bound parameters. A missing mapping or a mistyped built-in returns 400 rather than risking a wrong filter.

The residual does not carry obligations, the two-person rule, or separation-of-duty history. Re-check each row before applying obligations or executing such an action. The residual does include classification, compartments, eligibility, need-to-know ids, forbids, content denials, constrained-command restrictions, and resource-only IVPs. A database RLS backstop is **Not available**.

Sources: `packages/core/src/filter.ts`, `packages/sql/src/index.ts`, `packages/pdp-http/src/pdp.ts`.

## Consume certified-command tokens

For a certified command, an allowed evaluation contains both `obligations.decisionToken` and the signed `context.decision_token`. Consume it before executing the command:

```ts
const obligation = evaluation.context.obligations.decisionToken;
const token = evaluation.context.decision_token;

if (obligation && token) {
  await pdp.consumeToken({
    token,
    action: { name: 'approve' },
    resource: { type: 'payment', id: 'PAY-3' },
    resourceVersion: obligation.resourceVersion,
    ...(obligation.postState
      ? { attrs: { status: 'approved', amount: 1000 } }
      : {}),
  });
}

// Only now call the protected application's approve operation.
```

`enforce()` refuses a decision that carries `obligations.decisionToken` unless you acknowledge the consumption, so a PEP cannot skip the single-use check by calling only `enforce()`:

```ts
const releasable = enforce(evaluation, record, { decisionTokenConsumed: true });
```

The token binds the subject, action, resource, resource version, and policy version. The PDP verifies its signature, server-side single-use record, lifetime, and current decision, re-decided for the consuming credential's PEP binding. With `postState: true`, `attrs` is required: it is merged over current attributes for IVP checks and checked by the command's input validators. If the bundle declares input validators for the command, also send the command's input as `context.input` in the evaluation request. A 409 `conflict` means do not execute; a failed or missing post-state leaves the token unconsumed for a corrected retry while it remains valid.

Do not substitute offline JWS verification for consumption: that would skip single-use and current-state enforcement. Successful consumption records performed-action history used by SoD. Sources: `packages/pdp-http/src/tokens.ts`, `packages/pdp-http/src/pdp.ts`, `packages/pdp-http/src/runtime.ts`.

## Register the records your application owns

Qadamar decides only on resources it knows: a record your application creates after deployment is `CORE.UNKNOWN_ID` (denied) until it is registered. Ask a security officer for a PEP credential created with `resourceTypes` listing your types; a credential without it, `bootstrap` included, cannot register anything. Register in the same unit of work that creates the record, before you ask for decisions on it, and retire it when you delete it.

```ts
const app = createPepClient({ baseUrl: process.env.GATE_URL!, apiKey: process.env.GATE_CASE_APP_KEY! });

await app.registerResource({
  type: 'case', id: 'CASE-100', level: 1, compartments: [], integrity: 'system',
  contentClasses: [], // the content scan result: required, empty when scanned and clean
  owner: 'carol', parent: { type: 'folder', id: 'FOLDER-A' }, attrs: { status: 'open' },
});
const result = await app.syncResources({ resources: changed, retire: deleted }); // at most 1,000, all or nothing
await app.retireResource({ type: 'case', id: 'CASE-99' });
```

New records, raised levels, added compartments or content classes, edits of attributes no policy rule reads, and retirements apply at once. A lowered level, a removed compartment or content class, a changed integrity, owner or parent, a change to an attribute a rule reads, or the retirement of a constrained item comes back with status `proposed` and a `changeId` (HTTP 202): the stored labels stay as they were until an approver who did not issue your credential approves it in the console. Sending the same record again is `unchanged`, and the same pending proposal is not queued twice. To reconcile, page `listResources({ type, cursor })` and diff it against your table. An existing item of a constrained type is refused with `409 certified_command_required`: change it with its certified command and token consumption. Details: docs/API.md §2.2.

## Deploy the enforcing gateway

The workspace-private `@product/gateway` package provides a reverse-proxy PEP for JSON HTTP APIs. Declare every route; undeclared routes return 404 and are never proxied. Routes match in order, first match wins: list a literal path such as `/cases/export` before `/cases/:id`. The gateway refuses to start when an earlier route matches every request of a later one.

```ts
import { createGateway } from '@product/gateway';
import { PepClient } from '@product/sdk';

const gateway = createGateway({
  upstream: 'http://10.0.0.5:8080',
  pdp: new PepClient({ baseUrl: process.env.PDP_URL!, apiKey: process.env.PEP_API_KEY! }),
  routes: [
    {
      method: 'GET', path: '/cases', resourceType: 'case', action: 'read',
      list: { items: 'items', idField: 'id' },
    },
    {
      method: 'GET', path: '/cases/:id', resourceType: 'case', action: 'read',
      query: ['fields'], headers: ['x-request-id'],
    },
    {
      method: 'POST', path: '/payments/:id/approve', resourceType: 'payment', action: 'approve',
      postState: 'body',
    },
  ],
  authenticate: async (req) => authenticateEndUserWithYourIdentityLayer(req),
  attestContext: async (context, req) => attestRequiredSignalsWithYourMdmOrSensor(context),
  trustedNetworks: ['10.0.0.0/8'],
  notify: async ({ recipients, subject, resource, action, policyVersion }) => {
    await deliverNotification({ recipients, subject, resource, action, policyVersion });
  },
});

await gateway.listen(8443, '0.0.0.0');
```

Replace `authenticateEndUserWithYourIdentityLayer`, `attestRequiredSignalsWithYourMdmOrSensor`, and `deliverNotification` with real deployment functions. The attestation hook receives the fully resolved context, including socket-derived IP/network, and returns only the JWS values required by the credential scopes. The gateway trusts only its `authenticate` result and socket-address CIDRs; it does not trust identity or forwarded-for headers. For CBAC (context) rules, `ip` always comes from the socket and `authTime`, `mfaTime`, `authMethods`, device posture, country and risk come from the returned authenticated `Caller` session when known. Client headers cannot override them.

For single resources, it asks for an asserted decision before forwarding, consumes a certified token, calls the upstream with the `gate-assertion` header, and applies response obligations. On a `postState: "body"` route, the request body is sent as `context.input` and as the post-state `attrs`. For list routes, it first asks for a list assertion; when no item of the type can be released, it answers an empty list without calling the upstream. Otherwise it calls the upstream, decides the returned items in one batch of at most 1,000, drops denied items, applies each allowed item's obligations, and removes sibling fields such as totals and cursors. List routes must be GET.

The gateway allowlists request headers and query parameters, refuses method overrides, strips hop-by-hop headers, bounds bodies and the upstream deadline, and refuses upstream error bodies. HTTPS upstreams, GraphQL, and SQL-filter list enforcement are **Not available**. The upstream must be a plain HTTP origin on a private link, and it should verify the `gate-assertion` header on every request.

Sources: `packages/gateway/src/gateway.ts`, `packages/gateway/src/routes.ts`, `packages/gateway/src/headers.ts`.

## Verify decision assertions in the backend

A decision assertion proves to the backend that the PDP allowed exactly this subject, action, and resource for exactly this request. The PDP signs it with the decision-token keyring; the PEP never holds a signing key, and a deny gets no assertion. The enforcing gateway requests one for every forwarded request and sends it in the `gate-assertion` header. A custom PEP can request one with the SDK:

- `pdp.evaluateAsserted(request)` calls `POST /x/v1/assertions/evaluation`: an evaluation plus, on allow, `assertion`.
- `pdp.assertList(request)` calls `POST /x/v1/assertions/list` for a list request on a resource type. It returns `decision`, `policy_version`, and, when the subject may act on some item of the type, `assertion`. The PEP must still decide each item before releasing it.

Both take a `request` binding: `audience` (the backend origin, at most 256 characters), `method` (1–16 uppercase letters), `path` (the path with query, starting with `/`, at most 2,048 characters), and `bodySha256` (the base64url SHA-256 of the body, 43 characters). An invalid binding returns 400.

The assertion is a compact EdDSA JWS with header `typ: "gate-assertion+jwt"`. Its claims are `sub`, `act`, `res` (no `id` for a list), `did` (the decision id, also in the PDP audit row as `details.decisionId`), `pv`, `aud`, `htm`, `htp`, `bsh`, `iat`, `exp`, and `nonce`. It lives at most 30 seconds.

In a Node backend, wrap the handler with `withGateAssertion` and an `AssertionVerifier`:

```ts
import { createServer } from 'node:http';
import { AssertionVerifier, withGateAssertion } from '@product/sdk';

const verifier = new AssertionVerifier({
  jwksUrl: 'https://pdp.internal/.well-known/jwks.json',
  audience: 'http://10.0.0.5:8080', // exactly the gateway's upstream origin
});

createServer(withGateAssertion(verifier, (req, res, { claims, body }) => {
  // Use claims.sub, claims.act, and claims.res, never caller-supplied identity headers.
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({ subject: claims.sub, resource: claims.res }));
})).listen(8080);
```

`packages/sdk/src/example-backend.ts` is a runnable version that reads `GATE_JWKS_URL`, `GATE_AUDIENCE`, and `PORT`.

The verifier checks the signature, `typ`, lifetime, audience, method, path with query, and body digest, and accepts each `nonce` once while the assertion lives. The replay cache is held in memory by each `AssertionVerifier` instance unless you pass `replayStore`: a backend with several processes or replicas must pass one shared store (an atomic check-and-set such as Redis `SET NX PX` or a PostgreSQL unique insert; examples in docs/API.md §2.0.2), or each process accepts the same assertion once. It reads public Ed25519 keys from the JWKS, keeps them for `jwksCacheSeconds` (default 300, range 10–86400), and refetches at most every 10 seconds when it meets an unknown `kid`, so signing-key rotation needs no backend change. `clockSkewSeconds` defaults to 5 (range 0–60).

`withGateAssertion` reads the body up to `maxBodyBytes` (default 1 MiB) and runs the handler only after verification. Otherwise it answers 401 with `assertion_missing`, `assertion_invalid`, `assertion_key_unknown`, `assertion_expired`, `assertion_mismatch`, or `assertion_replayed`, 503 with `jwks_unavailable`, or 413 with `payload_too_large`. Sources: `packages/sdk/src/assertion.ts`, `packages/sdk/src/example-backend.ts`, `packages/sdk/src/client.ts`, `packages/pdp-http/src/pdp.ts`, `packages/pdp-http/src/tokens.ts`, `packages/gateway/src/gateway.ts`.

## Handle failures closed

The SDK exposes specific errors:

- `PdpHttpError`: PDP HTTP status, sanitized error code, and optional `retryAfter`.
- `PdpNetworkError`: `request_timeout`, `request_aborted`, or `network_error`.
- `PdpResponseError`: malformed or unsupported PDP response.
- `AccessDeniedError`: deny during `enforce`.
- `ObligationError`: unsafe or unsupported record obligations.

Do not retry a denied evaluation as though it were a transport failure. Honor `Retry-After` for 429, and treat an unreachable PDP or unenforceable response as a refusal, not an allow.

In cluster mode, every node answers PDP requests. A node that has not confirmed the shared state within its staleness bound answers 503 `unavailable`; retry the request on another node. The SDK and the gateway do not retry by themselves, so put the PDP nodes behind a load balancer or retry in your PEP. `GET /leaderz` matters only for routing the admin plane; PEPs do not need it. The gateway maps PDP failures to 503 `pdp_unavailable`, malformed decisions to 502 `unenforceable_decision`, and unenforceable obligations to 502 `obligation_unenforceable`.

Sources: `packages/sdk/src/errors.ts`, `packages/sdk/src/client.ts`, `packages/gateway/src/gateway.ts`, `packages/pdp-http/src/router.ts`.

## Related pages

- [Understand obligations](../concepts/policy-and-content.md)
- [Understand decision tokens and SoD](../concepts/integrity-and-separation.md)
- [Manage PEP credentials and keys](security-officer.md)
- [Read API errors and limits](../reference/error-codes.md)
