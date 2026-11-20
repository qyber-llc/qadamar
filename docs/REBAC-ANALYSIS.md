# ReBAC analysis — should the product add relationship-based access control?

Status: **decided and built.** Draft 1 for owner review (2026-11-07); the recommendation (options B and C of §5) is
implemented, option D is not (§8).

> **Answer in one line: yes to ReBAC as a model, no to a separate graph database for now.** Relations become
> first-class, declared data in the engine, resolved where they live and pushed down into SQL. A small tuple table
> holds the relations no application owns (grants, shares, delegations). A SpiceDB/OpenFGA adapter comes only when
> one of the criteria in §6 is met.

## 1. The question

ReBAC derives permissions from a graph of relations ("Alice is a member of team T; T is allocated to project P;
members of teams allocated to P may read P"). Google's Zanzibar paper made the model popular: relation tuples,
userset rewrites and *zookies* for consistency ([Zanzibar, USENIX ATC '19][zanzibar]). SpiceDB ([docs][spicedb]) and
OpenFGA, a CNCF incubating project since late 2025 ([CNCF][openfga-cncf]), are the open-source implementations.

Our engine is attribute-based: the subject carries computed attributes, the resource carries its own, and rules
compare them. The question is whether the product should store and evaluate relations as a first-class graph.

## 2. The pattern: relationships computed in SQL

"A reason to know this record" is a relationship check. An application can compute, once per request, the set of
records a subject has a reason to know, pass it to the policy as a subject attribute, and let a pure rule read it.
Typical relations, as a tuple would write them:

| "Reason to know" | Relation, as a tuple would write it | Where it typically lives |
|---|---|---|
| Team field | `project:P#pm@person:X` (deputy, tech lead, sponsor, ...) | columns of the record |
| Live allocation | `project:P#allocated@person:X`, valid while `to_date ≥ today` | an allocations table |
| Engagement owner | `project:P#engagement_owner@person:X` | an engagements table |
| Client account | `client:C#account_owner@person:X`; `project:P#client@client:C` | clients table and a foreign key |
| Reporting line | `person:Y#manager@person:X`, transitive (recursive CTE, cycle-safe, bounded depth) | a manager column |
| Approved grant | `project:P#granted@user:U`, with an expiry | a grants table |
| Break-glass | same, short-lived, administrators only, never past clearance or compartments | a grants table |
| Portfolio seat | `org:main#executive@person:X`, plus their direct reports | settings and people |

The same pattern covers inheritance: a child record can inherit its root record's rule, and a document can follow
its parent item's rule. Grants can name a person, a group or a role.

Such an application needs relationships but **does not need a graph store** for them when:

- every relation is a row in the **same Postgres database** as the protected data;
- the "known set" becomes one SQL predicate. It is **pushed down** into list queries and can be mirrored by a
  row-level-security backstop;
- the decision is taken on **current state**: the backend re-decides on the locked row, so a revocation takes effect
  on the next request.

This is a design pattern, not a claim of production proof; this analysis does not rely on a named reference
deployment. The weakness of the pattern, when hand-written, is that the relations are **hard-coded SQL** in one
place, not declared as data. That is the real problem for the product, and it is a modelling problem rather than a
storage one.

## 3. Benefits of first-class ReBAC

1. **Domain independence.** Declared relations (`relation allocated: person` with a source) replace hand-written SQL.
   This is what lets another application reuse the engine with its own policies.
2. **Hierarchies and inheritance.** Org charts, folder trees, parent/child records and group nesting are natural.
3. **Sharing and delegation.** "Share this deal with that co-investor", "delegate my approvals for two weeks", and
   external organisations as subjects. Sovereign funds will ask for this.
4. **Reverse queries for the admin console.** "Who can see Y?" and "what can X see?" are graph traversals. The
   simulator and access reviews need them.
5. **Market expectation.** Oso, Permit.io, SpiceDB and OpenFGA all advertise ReBAC ([Oso][oso], [Permit][permit]),
   so buyers will check for it.

## 4. Costs and risks

| Cost | Detail | Severity for our buyers |
|---|---|---|
| **Consistency (new-enemy problem)** | With a separate relation store and caches, a removed member can still read. Zanzibar solves it with zookies; SpiceDB with per-request consistency and ZedTokens, whose default `minimize_latency` "can open a window" ([SpiceDB consistency][spicedb-cons]). OpenFGA has no zookie equivalent yet; it says it is considering one ([OpenFGA consistency][openfga-cons]). | **High.** The guarantee of deciding on current state (the locked row) would be weakened unless every write path carries tokens. |
| **Two sources of truth** | Allocations, teams and org chart live in the application or HR system. A graph store needs them copied and kept in sync; a failed sync means wrong access, open or closed. | **High** for an external store, none if relations are read in place. |
| **SQL pushdown** | An external graph filters lists by returning IDs first. SpiceDB's guidance: LookupResources for sets under ~10,000 resources, CheckBulkPermissions per page beyond, and Materialize (early access, Dedicated plan only) for a local denormalised copy ([list endpoints][spicedb-list]). Our predicate is one `EXISTS` in the query, with counts and pagination intact. | **High** for large lists and RLS. |
| **Mandatory models are not relations** | Clearance, compartments, Biba levels and the network condition are attributes with lattice semantics. In SpiceDB they would become caveats (CEL on relations); a check missing context returns "conditional" ([caveats][spicedb-caveats]). Mixing makes "a share lifts a classification" a modelling mistake waiting to happen. | **High.** Non-negotiable invariant: *a relation can only supply a reason to know; it never lifts a level, a compartment or the network condition.* Break-glass style grants must follow the same rule. |
| **Explainability** | "Why can I see this?" becomes a path of 3–4 hops instead of a rule id. | Medium; it can be solved by returning the path. |
| **Operations** | A new stateful component (HA, backup, audit, upgrades). With SpiceDB/OpenFGA, a third-party dependency to assess (security, licence, maintenance). | Medium; high for air-gapped deployments. |

## 5. Options

| Option | What it means | Consistency | Pushdown | MAC (BLP, Biba) | Sharing / external orgs | Ops |
|---|---|---|---|---|---|---|
| **A. No ReBAC** | Keep relations as hand-written attribute computation per domain. | Strong | Yes | Intact | Ad hoc | None |
| **B. ReBAC as attribute source** | Relations are **declared in the policy model** (name, subject type, object type, source query or table, validity, transitivity bound). The engine resolves them where the data lives and compiles them to SQL `EXISTS` predicates and to the subject's known sets. | Strong (same DB, same transaction) | Yes | Intact: relations feed `reason_to_know` only | Within the app's DB | Low |
| **C. Embedded relation store** | B, plus a tuple table in the product's own database for relations **no application owns**: grants, shares, delegations, managed groups, external parties. | Strong if the protected app uses the same Postgres; otherwise needs versions/tokens | Yes in the same DB; IDs otherwise | Intact if C stays a reason source | Yes | Medium |
| **D. Integrate SpiceDB / OpenFGA** | An adapter: the external graph answers "related?", the engine still applies MAC and ABAC on top. | Token discipline required | IDs (≤ ~10k) or Materialize | Intact only if the graph never decides alone | Strongest | High |

## 6. Recommendation

**Add ReBAC as a model now (option B, with the small tuple store of C for product-owned relations); keep a separate
graph store (D) as an optional adapter behind explicit criteria.**

- **B** is the pattern of §2, generalised: an application's reasons to know become declared relations of a policy
  pack rather than hand-written SQL. Exit test: identical decisions on a recorded corpus.
- **C-lite** formalises relations an application typically stores in its own tables (grants, managed groups,
  assignments). One generic table `(object, relation, subject, valid_from, valid_to, granted_by,
  reason, approval_id)` with the existing invariants: no self-grant, two-person approval, expiry, audit.
- **The relation layer sits under the mandatory models, never beside them.** Decision order stays: inactive → RBAC
  eligibility → clearance / compartments / network / Biba → relation-based reason to know → ABAC record rules
  (including content attributes) → CBAC (context-based, Zero Trust). Any deny wins.
- **Explain returns the relation path** ("allocated to P until 2026-12-31", "reports to the PM of P"), never a
  hidden node.

**Criteria to add option D (the SpiceDB/OpenFGA adapter)**, any one of:

1. A customer's relations live **outside** the protected application's database and must be shared across several
   applications (cross-app sharing, a group directory the IdP cannot express).
2. A subject's known set routinely exceeds what a per-request set can carry. Measure it on the second backend;
   SpiceDB's own threshold for ID lists is ~10,000.
3. **User-defined, unbounded hierarchies** (nested folders, nested groups), deeper than a bounded recursive query
   handles within the latency budget.
4. A buyer **mandates** a Zanzibar-style store or OpenFGA as an enterprise standard.

Until one of these is met, D adds the consistency and pushdown costs of §4 without a benefit our first buyers need.

## 7. Open points for the owner

1. ~~Agree that **relations never lift a classification**~~ Done: written in [ARCHITECTURE.md](ARCHITECTURE.md) and a
   theorem of the Lean model (`mandatory_before_tenant_policy`).
2. Whether external organisations as subjects (co-investors, subcontractors) are in the **first pilot's scope**:
   that decides whether C-lite must ship with sharing UI in the MVP.
3. Whether a ReBAC tick-box matters for the first buyers enough to build the D adapter early regardless of the
   criteria (a commercial call, not a technical one).

## 8. What is built (version 0.12.2)

- **Declared relations** per resource type in the policy bundle (`relations`), each a union of rewrites: a direct or
  userset tuple (`this`), another relation on the same object (`computed`), a relation on the object's parent
  (`fromParent`) and a bounded reporting line (`viaReports`, `maxDepth`). Types: `RelationDef` in
  `packages/core/src/types.ts`.
- **Zanzibar-style evaluation in the engine** over an in-memory tuple graph (`packages/core/src/relations.ts`, at most 32
  hops). Every positive answer carries the path that produced it, for explain. Known sets for lists and search come
  from reverse traversal.
- **Tuple store** (option C): tuples live in the product's own PostgreSQL (`gate_tuple`) and are managed through
  `/admin/v1/tuples` with a grant window (`notBefore` / `notAfter`), the grantor and a reason; break-glass tuples and
  access reviews (`/admin/v1/reviews`) use the same store.
- **The invariant holds**: a relation supplies a reason to know at the need-to-know stage only and never lifts a
  classification or compartment.
- **Not built**: the SpiceDB / OpenFGA adapter (option D). The criteria of §6 still decide when it comes.

[zanzibar]: https://www.usenix.org/conference/atc19/presentation/pang
[spicedb]: https://authzed.com/docs/spicedb/getting-started/discovering-spicedb
[spicedb-cons]: https://authzed.com/docs/spicedb/concepts/consistency
[spicedb-caveats]: https://authzed.com/docs/spicedb/concepts/caveats
[spicedb-list]: https://authzed.com/docs/spicedb/modeling/protecting-a-list-endpoint
[openfga-cncf]: https://www.cncf.io/blog/2025/11/11/openfga-becomes-a-cncf-incubating-project/
[openfga-cons]: https://openfga.dev/docs/interacting/consistency
[oso]: https://www.osohq.com/docs
[permit]: https://docs.permit.io/
