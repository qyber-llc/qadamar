# ADR 0005: Server-derived separation of duty

This ADR records the decision to derive maker and conflicting-action history from Qadamar’s persisted certified-token consumption rather than trust PEP assertions alone. Production requires this server-history mode because the compatibility mode can be bypassed by an inaccurate PEP.

## On this page

- [Status](#status)
- [Context](#context)
- [Decision](#decision)
- [Consequences](#consequences)
- [Alternatives](#alternatives)
- [Evidence](#evidence)

## Status

Accepted in commit `925876a` on 2026-11-10. Impact previews were aligned with real history in `7498fc4`; v0.3.0 commit `6cd36fb` makes `SOD_HISTORY=server` mandatory in production. In commit `b09bc44` (after 0.3.0), PostgreSQL mode stores new performed actions in the `gate_performed` table so every cluster node reads the same history ([ADR 0011](0011-cluster-mode.md)).

## Context

Two-person and conflicting-action rules need to know who performed earlier actions on the same resource. A PEP can supply `makerId` and `priorActions`, but a buggy or malicious PEP can omit them. Server history must also handle agents acting for people, so an action counts for the performer and every delegator.

The server can observe successful decision-token consumption, but not the protected application’s subsequent database commit. That distinction limits what the history proves.

## Decision

- On successful certified-token consumption, persist subject, resource, action, time, and delegation chain as a performed action.
- On every decision, union recorded actions for the subject and delegation chain into `context.priorActions`; caller entries can add but not remove recorded history.
- Derive the resource maker from the first recorded certified action and its `onBehalfOf` chain. A contradictory caller maker denies with `SOD.MAKER_MISMATCH`.
- Support `SOD_HISTORY=caller` for compatibility: when the server has no history, caller input is trusted.
- Support `SOD_HISTORY=server`: for actions constrained by `requiresSecondPerson` or an SoD rule, remove caller `makerId` and `priorActions` before deriving server history. With no history, the two-person check fails closed with `SOD.MAKER_UNKNOWN`.
- Require `server` in the production profile. Impact analysis still evaluates maker variants so it may over-report but must not under-report a change.

## Consequences

### Positive

- A PEP cannot erase recorded conflicts or substitute a different maker after history exists.
- The first two-person action must follow an earlier certified action that establishes a maker.
- Delegation inherits the history of the people acted for, preventing delegation from resetting SoD.
- Impact previews and real decisions use the same history derivation.

### Negative and operational

- Existing resources need a valid performed-action history before two-person actions can succeed in server mode. Bootstrapping requires an initial certified action that does not itself require a second person.
- History grows with certified actions. File mode stores it in the state document; PostgreSQL mode appends new entries to `gate_performed`. It is indexed by resource in memory, not retained as a separate business ledger.
- Token consumption occurs before the gateway forwards the command. An upstream failure can leave a performed action whose business effect did not commit.
- Caller mode remains the default outside production for compatibility and is not safe against an untrusted PEP.

## Alternatives

- **Trust caller history everywhere:** rejected for production because omission defeats the control.
- **Query the application’s business log:** not implemented; there is no standard adapter or transaction protocol for it.
- **Distributed SoD service:** not needed. In cluster mode performed actions are shared through `gate_performed`, numbered under the `gate_sync` row lock so every node applies them in commit order. External writes would still need a redesign.

## Evidence

- Server history and maker derivation: `packages/pdp-http/src/runtime.ts`.
- Token consumption and history persistence: `packages/pdp-http/src/pdp.ts`; shared rows in `packages/pdp-http/src/postgres.ts` (`gate_performed`).
- Core SoD checks: `packages/core/src/evaluate.ts`.
- Production requirement: `packages/pdp-http/src/profile.ts`.
- History-aware impact preview: `packages/pdp-http/src/admin/changes.ts`.
- History commits: `925876a`, `7498fc4`, and `6cd36fb`.

## Related pages

- [Decision engine](../decision-engine.md)
- [Integration](../integration.md)
- [ADR 0001: Fixed evaluation pipeline](0001-fixed-evaluation-pipeline.md)
- [Well-Architected review](../well-architected-review.md)
