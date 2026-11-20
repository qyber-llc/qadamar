# ADR 0002: Minimal dependencies

This ADR records the decision to keep the engine and enforcement libraries dependency-free and the PDP’s runtime dependency surface small, rather than claim that the entire repository has no dependencies. The actual policy is minimal, explicit dependencies with Node.js standard-library implementations where practical.

## On this page

- [Status](#status)
- [Context](#context)
- [Decision](#decision)
- [Consequences](#consequences)
- [Alternatives](#alternatives)
- [Evidence](#evidence)

## Status

Accepted through the initial implementation and retained in v0.3.0 and in the code at commit b09bc44 (after 0.3.0). The v0.2.0 PostgreSQL work added `pg`; the console has always used its declared React and Vite toolchain. The work after 0.3.0 (cluster mode, decision assertions, encrypted backups, the SBOM generator) added no runtime dependency: `packages/pdp-http/package.json` still lists only `pg` 8.23.1, and `packages/core`, `sql`, `sdk`, and `gateway` list none.

## Context

Sovereign and air-gapped deployments benefit from a small installation and audit surface. Authorization code also needs careful control of parsing, cryptography, HTTP, and expression evaluation. However, “no dependencies” would be inaccurate for the complete product: the PDP needs a PostgreSQL driver, and the browser console uses React with a Vite build.

The requirement is therefore to minimise third-party runtime code, not to replace mature tools for every task.

## Decision

- Implement `packages/core`, `packages/sql`, `packages/sdk`, and `packages/gateway` using TypeScript and Node.js standard-library APIs only.
- Limit the PDP’s direct runtime dependency to `pg` 8.23.1.
- Use Node’s built-in cryptography, HTTP/HTTPS, test runner, and direct TypeScript execution rather than additional runtime frameworks.
- Implement the JSON condition evaluator, RFC 3161 request/reply handling, TOTP, OTLP/HTTP JSON exporter, decision-assertion verifier, backup-archive encryption, and CycloneDX SBOM generator in product code.
- Keep React 19 and Vite 8 confined to the declared console application and build toolchain. Serve the compiled console as static assets.
- Pin direct versions in package manifests and the workspace lockfile. Do not infer support for uninstalled libraries.

## Consequences

### Positive

- Installation and offline deployment require few server runtime packages.
- Core behavior is deterministic and independent of third-party framework lifecycle.
- The SDK and gateway are easy to embed in a Node.js 22.18+ enforcement service.
- There are fewer transitive server dependencies to monitor and approve.

### Negative and operational

- Product code owns more protocol and security details, including DER parsing, OIDC checks, and OTLP export. These need specialist review and conformance testing.
- Node.js and browser toolchain upgrades remain operational work; the policy does not eliminate supply-chain risk.
- The console still has a substantial development dependency tree, and the server has the `pg` dependency tree.
- Standard-library-only choices limit some integrations. For example, the tracing exporter has no SDK-provided authentication, metrics, or sampler feature set.

## Alternatives

- **A full web and policy framework:** not chosen; it would increase the runtime and upgrade surface for limited current need.
- **Literal zero dependencies across the repository:** rejected as inaccurate and counterproductive for PostgreSQL and the React console.
- **A third-party OpenTelemetry SDK, TOTP library, JOSE library, and RFC 3161 client:** not added; the product implements only the required subsets and documents their limits.

## Evidence

- Root engine requirement and scripts: `package.json`.
- PDP dependency: `packages/pdp-http/package.json`.
- Console dependencies: `apps/admin/package.json`.
- Dependency-free core exports: `packages/core/src/index.ts`.
- Standard-library HTTP gateway: `packages/gateway/src/gateway.ts`.
- Standard-library cryptography and protocols: `packages/pdp-http/src/tokens.ts`, `oidc.ts`, `totp.ts`, `anchor.ts`, and `tracing.ts`; `packages/sdk/src/assertion.ts`; `scripts/ops/archive-crypt.ts`; `scripts/release/sbom.ts`.
- Lockfile: `pnpm-lock.yaml`.

## Related pages

- [Architecture overview](../overview.md)
- [ADR 0004: Hash-chained audit with RFC 3161](0004-hash-chain-rfc3161.md)
- [ADR 0007: JSON condition AST](0007-json-condition-ast.md)
