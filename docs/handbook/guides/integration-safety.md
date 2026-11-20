# Enforce safely across backend replicas and SQL lists

The runnable examples live in [`examples/integration-safety`](../../../examples/integration-safety).
They use the existing SDK, core, SQL compiler and PostgreSQL driver, with no added dependency.
Run `node --test examples/integration-safety/test/safety.test.ts` with `TEST_DATABASE_URL` pointing to a throwaway
PostgreSQL database and `DATABASE_TLS=disable` for that local database. The normal CI suite includes these tests.

## Share assertion replay protection

Every backend instance that accepts the same audience must spend nonces in one shared atomic store. Separate
`MemoryReplayStore` objects accept the same assertion once per process. Never implement spend as SELECT followed by
INSERT; competing instances can both see an unused nonce.

[`postgres-replay.ts`](../../../examples/integration-safety/postgres-replay.ts) implements the SDK's existing
`ReplayStore.spend(nonce, expiresAt)` contract with INSERT ON CONFLICT and an expiry-guarded update. The unique key
is `(backend, nonce)`; use the exact audience as `backend` on every replica, and keep the database durable across
backend restarts. Errors propagate so the verifier answers `replay_store_unavailable` (503), with no handler call.
The SDK supplies expiry including its clock skew; retain the nonce through that second. Synchronise database and
backend clocks. The race test uses independent verifier instances and database connections: only one accepts.

Provision the exported `replaySchema` once as the schema owner. Give the backend role only SELECT, INSERT, UPDATE,
and DELETE on that table. Use a normal `pg.Pool` from the existing dependency at your backend's composition point:

```ts
import pg from 'pg';
import { AssertionVerifier, withGateAssertion } from '../../../packages/sdk/src/index.ts';
import { PostgresReplayStore } from '../../../examples/integration-safety/postgres-replay.ts';

const pool = new pg.Pool(databaseConfig); // credentials come from your secret manager
const replayStore = new PostgresReplayStore(pool, audience);
const verifier = new AssertionVerifier({ jwksUrl, audience, replayStore });
const handler = withGateAssertion(verifier, applicationHandler);
// Schedule replayStore.prune() periodically, outside the request path.
```

The names `databaseConfig`, `audience`, `jwksUrl`, and `applicationHandler` are application configuration or code;
keep the listener private and verify the assertion before any application handler. The reference module accepts a
query interface so it does not add a driver dependency to the SDK. A Redis implementation must provide equivalent
atomic SET NX with a TTL through `expiresAt`; storage failure must throw rather than return success.

## Filter SQL candidates, then enforce each row

[`filtered-backend.ts`](../../../examples/integration-safety/filtered-backend.ts) compiles `buildFilter` into bound
PostgreSQL parameters and selects candidates with `WHERE (...) IS TRUE`. Column mappings are application-owned;
unmapped policy paths throw and must fail closed. The shipped `bundle.json` defines the review policy used by the test. The example table has `id`, `level`, `compartments`, `integrity`,
`content_classes` (authoritative scan results, including an empty array for scanned-clean records), `maker`,
`prior_actions`, `title`, and `secret`. The test creates this schema locally.

The backend then evaluates **every row for the requested action** using authoritative per-row maker and prior-action
history. It drops denied rows and calls the SDK's `enforce` before releasing the projection. The example strips
caller-supplied history claims; it cannot use SQL membership as authority for two-person review or separation of
duty. Obligations also require a point decision even when `filterDecides` is true. Notification or unsupported
obligations fail closed through `enforce`; supply a notification-capable PEP when your policy requires them.

The PostgreSQL test includes a row excluded by classification in SQL, candidates denied for self-review, unknown
maker and conflicting history, and an allowed row whose secret is redacted. It also proves that a notification
obligation cannot silently pass through this example.

Use a transaction and lock rows/history against concurrent changes until the protected operation completes. The
example's `FOR SHARE` assumes maker/history are stored on that locked row; normalised history needs its own locking
and a consistent policy/subject/context snapshot. Always obtain identity and signals from authenticated sources.
This function only returns data: it refuses certified-command token obligations. To execute a write, acquire the
appropriate write locks, re-evaluate the actual row/action, consume its decision token when required, enforce all
obligations, and atomically commit the application change with its authoritative history. Qadamar and application
transactions remain separate; design recovery for a consumed token whose application commit fails.

See [Integrate a PEP](integrator.md), [API §2](../../API.md), and [Architecture](../../ARCHITECTURE.md).
