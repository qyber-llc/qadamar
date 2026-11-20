# Backend integration safety

- `postgres-replay.ts`: a shared, atomic SDK `ReplayStore` with PostgreSQL expiry cleanup.
- `filtered-backend.ts`: generated SQL candidates followed by per-row history checks and SDK obligation enforcement.
- `bundle.json`: the example review policy, also checked against the policy schema.
- `test/safety.test.ts`: real PostgreSQL race and filtering tests, included by the normal CI suite.

See the [handbook walkthrough](../../docs/handbook/guides/integration-safety.md) for schema, wiring, transaction
assumptions and deployment. Run with the supplied throwaway `TEST_DATABASE_URL` (never print it):

```sh
DATABASE_TLS=disable node --test examples/integration-safety/test/safety.test.ts
```
