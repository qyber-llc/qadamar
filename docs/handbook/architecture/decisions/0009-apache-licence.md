# ADR 0009: Apache License 2.0

## Status

Accepted on 2026-11-20 for the open-source release.

## Context

The repository needs an explicit grant of rights so that users know what they may do with the code. Security tooling in this space (OPA, Cedar, Apache Ranger) is commonly distributed under permissive licences with a patent grant.

## Decision

- Distribute Qadamar under the Apache License, Version 2.0 (`LICENSE`), with a `NOTICE` file.
- Mark workspace packages `Apache-2.0` where the field is used.
- Keep third-party attribution and licence information in `THIRD-PARTY-NOTICES.md`; dependency licences are unchanged.

## Consequences

- Anyone may use, modify and redistribute the code, including commercially, under the licence's conditions (notice retention, stated changes).
- The licence includes an express patent grant from contributors, and terminates it for anyone who sues over patents in the work.
- Contributions are accepted under the same licence (section 5 of the licence).

## Alternatives

- AGPL-3.0: protects against closed hosted forks but slows adoption in enterprises.
- MIT: simpler, but with no explicit patent grant.
