// Core contract of the access engine. Pure data: every input is JSON, every decision is reproducible from
// (bundle, request, graph). The evaluation order is fixed by the core (docs/ARCHITECTURE.md §3.2).

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

/** Bell-LaPadula classification: L0 public, L1 internal, L2 confidential, L3 secret. */
export type Level = 0 | 1 | 2 | 3;

/** Biba integrity, low to high. */
export type Integrity = 'derived' | 'extracted' | 'system' | 'verified';

export type ActionKind = 'read' | 'write' | 'delete' | 'approve' | 'execute';

export interface Ref {
  readonly type: string;
  readonly id: string;
}

export interface RoleAssignment {
  readonly role: string;
  readonly notBefore?: string;
  readonly notAfter?: string;
}

export interface Subject extends Ref {
  /** type: user, service, agent (AI), external */
  readonly active: boolean;
  readonly roles: readonly string[];
  /** Time-bounded additions to the unconditional role names above, evaluated against context.now. */
  readonly roleAssignments?: readonly RoleAssignment[];
  readonly clearance: Level;
  readonly compartments: readonly string[];
  /** Biba level of what this subject writes. A human command is 'verified'; an AI agent is 'derived'. */
  readonly integrity: Integrity;
  readonly attrs?: Readonly<Record<string, Json>>;
  /** An agent acting for a person: every mandatory and need-to-know check must also pass for the delegator. */
  readonly delegator?: Subject;
}

export interface Resource extends Ref {
  readonly level: Level;
  readonly compartments: readonly string[];
  readonly integrity: Integrity;
  readonly owner?: string;
  readonly parent?: Ref;
  /** Monotonic version, bound into Clark-Wilson decision tokens. */
  readonly version?: number;
  /** Closed content classes detected in the resource (CBAC), e.g. "pii.iban", "finance.amount". */
  readonly contentClasses?: readonly string[];
  readonly attrs?: Readonly<Record<string, Json>>;
}

export interface Context {
  readonly network: 'trusted' | 'untrusted';
  /** ISO-8601 instant of the decision, supplied by the caller so the engine stays pure. */
  readonly now: string;
  /** Zero Trust signals asserted by the authenticated PEP; the PDP validates their shape, not their provenance. */
  readonly ip?: string;
  readonly country?: string;
  readonly device?: { readonly managed: boolean; readonly compliant: boolean };
  readonly authTime?: string;
  readonly mfaTime?: string;
  readonly authMethods?: readonly string[];
  readonly riskScore?: number;
  /** BLP session level: a subject may work below its clearance. Defaults to the clearance. */
  readonly sessionLevel?: Level;
  /** Server-derived scope of the subject's working session (from a verified PDP token, or a legacy PEP id in demo).
   *  Reads raise a server-side high-water mark that later writes of the session cannot go below. */
  readonly sessionId?: string;
  /** Server-derived: the session's high-water mark, the highest level the subject read in it. */
  readonly highWater?: Level;
  /** Server-derived (BLP_SESSION_REQUIRED): writes by a cleared subject and reads above L0 need a session. */
  readonly sessionRequired?: boolean;
  /** Server-derived: the named session is known to have passed its idle or absolute expiry. */
  readonly sessionExpired?: boolean;
  /** Two-person rule: the caller's claim about the maker of the object being approved. */
  readonly makerId?: string;
  /** Server-derived maker; when present, it overrides makerId and a contradictory claim denies. */
  readonly serverMakerId?: string;
  /** Actions this subject and its delegation chain already performed on this resource (separation of duty). */
  readonly priorActions?: readonly string[];
  /** Server-derived: transformation procedures with a certification record (Clark-Wilson C2), for requireCertification.
   *  `fingerprint`: the procedureFingerprint the record certified; a record counts only while it is the current one. */
  readonly certified?: readonly { readonly resourceType: string; readonly action: string; readonly by?: readonly string[]; readonly fingerprint?: string }[];
  /** Server-derived: subject types the calling PEP credential is bound to (Clark-Wilson E3, requirePepBinding). */
  readonly pepSubjectTypes?: readonly string[];
  /** Clark-Wilson C5: the unconstrained input the certified command takes (the request body), checked by inputValidators. */
  readonly input?: Readonly<Record<string, Json>>;
  readonly attrs?: Readonly<Record<string, Json>>;
}

export interface Request {
  readonly subject: Subject;
  readonly action: string;
  readonly resource: Resource;
  readonly context: Context;
}

// ---------- relations (ReBAC, Zanzibar-style tuples) ----------

/** object#relation@subject, or object#relation@group#member when subjectRelation is set (a userset). */
export interface Tuple {
  readonly object: Ref;
  readonly relation: string;
  readonly subject: Ref;
  readonly subjectRelation?: string;
  readonly validFrom?: string;
  readonly validTo?: string;
  /** Canonical CBAC grant window; validFrom/validTo remain readable for existing records. */
  readonly notBefore?: string;
  readonly notAfter?: string;
  /** Emergency access: a reason to know only, capped in hours by the bundle, notified and reviewed. */
  readonly breakGlass?: boolean;
  readonly grantedBy?: string;
  readonly reason?: string;
}

/** One way to satisfy a relation on an object type. */
export type RelationRewrite =
  | { readonly this: true } // a direct tuple (or a userset tuple)
  | { readonly computed: string } // another relation on the same object
  | { readonly fromParent: { readonly relation: string; readonly then: string } } // object's parent, then a relation on it
  | { readonly viaReports: { readonly managerRelation: string; readonly then: string; readonly maxDepth: number } };

export interface RelationDef {
  readonly union: readonly RelationRewrite[];
}

// ---------- conditions (ABAC, including content attributes, as a JSON AST: plan B of ARCHITECTURE.md §3.4) ----------

export type Operand = { readonly path: string } | { readonly value: Json };

export type Expr =
  // in: left is an element of the right array; contains: left array (or string) contains right; subset: left array ⊆ right array
  | { readonly op: 'eq' | 'ne' | 'lt' | 'le' | 'gt' | 'ge' | 'in' | 'contains' | 'subset'; readonly left: Operand; readonly right: Operand }
  | { readonly op: 'has'; readonly path: string }
  | { readonly op: 'and' | 'or'; readonly args: readonly Expr[] }
  | { readonly op: 'not'; readonly arg: Expr }
  | { readonly op: 'true' }
  /** Produced by partial evaluation only: a comparison over a missing subject or context value (SQL NULL). */
  | { readonly op: 'unknown' };

export interface Obligations {
  /** Fields the caller may see; undefined = all. Intersected across rules. */
  readonly fieldAllowlist?: readonly string[];
  /** Fields replaced by null. Unioned. */
  readonly redact: readonly string[];
  /** Content classes masked in text (ABAC on content attributes). Unioned. */
  readonly maskClasses: readonly string[];
  /** Who must be notified (break-glass, sensitive reads). Unioned. */
  readonly notify: readonly string[];
  /** Clark-Wilson: a single-use, short-lived token the PEP must present to execute a certified command. */
  /** postState: the type has IVPs, so consumption must carry the item's state as the command will commit it. */
  readonly decisionToken?: { readonly ttlSeconds: number; readonly resourceVersion: number | null; readonly postState?: true };
}

export interface AbacRule {
  readonly id: string;
  readonly description: string;
  /** permit = eligibility beyond the role matrix (never past the mandatory models); forbid = deny; obligation = adds obligations. */
  readonly effect: 'permit' | 'forbid' | 'obligation';
  readonly resourceTypes?: readonly string[];
  readonly actions?: readonly string[];
  readonly when: Expr;
  readonly obligations?: Partial<Omit<Obligations, 'decisionToken'>>;
}

export interface AbacContentRule {
  readonly id: string;
  readonly description: string;
  readonly contentClass: string;
  /** deny: the action is refused; mask: the class is masked in text; redact: the listed fields are removed. */
  readonly effect: 'deny' | 'mask' | 'redact';
  readonly fields?: readonly string[];
  readonly actions?: readonly string[];
  /** The rule does not apply when this holds (e.g. the subject holds a finance role). */
  readonly unless?: Expr;
}

export interface SodRule {
  readonly id: string;
  readonly description: string;
  /** A subject who performed one of these on a resource may not perform another of them on it. */
  readonly conflicting: readonly string[];
}

export interface ContextTimeWindow {
  /** ISO weekday: 1 Monday through 7 Sunday. An overnight window belongs to its starting day. */
  readonly days: readonly number[];
  readonly from: string;
  readonly to: string;
  readonly timeZone: string;
}

/** Request-level Zero Trust requirements. Every matched requirement must be TRUE; a missing signal is UNKNOWN and denies. */
export interface ContextRule {
  readonly id: string;
  readonly description?: string;
  readonly resourceTypes?: readonly string[];
  readonly actions?: readonly string[];
  readonly actionKinds?: readonly ActionKind[];
  readonly minResourceLevel?: Level;
  readonly contentClasses?: readonly string[];
  readonly network?: 'trusted';
  readonly countries?: readonly string[];
  readonly ipRanges?: readonly string[];
  readonly timeWindows?: readonly ContextTimeWindow[];
  readonly device?: { readonly managed?: boolean; readonly compliant?: boolean };
  readonly mfaMaxAgeSeconds?: number;
  readonly authMaxAgeSeconds?: number;
  readonly authMethodsAny?: readonly string[];
  readonly maxRiskScore?: number;
}

export interface ActionDef {
  readonly kind: ActionKind;
  /** Clark-Wilson transformation procedure: a certified command, the only way to change a constrained item. */
  readonly certified?: boolean;
  /** Two-person rule: the maker of the object may not perform this action. */
  readonly requiresSecondPerson?: boolean;
}

export interface ResourceTypeDef {
  readonly actions: Readonly<Record<string, ActionDef>>;
  readonly relations?: Readonly<Record<string, RelationDef>>;
  /** Clark-Wilson constrained data item: changed only through certified actions. */
  readonly constrained?: boolean;
  /** Resource attributes (names under resource.attrs) whose change through PEP resource registration needs a second
   *  person, in addition to every attribute a rule of the bundle reads. */
  readonly governedAttributes?: readonly string[];
}

export interface PolicyBundle {
  readonly name: string;
  readonly schema: {
    readonly resourceTypes: Readonly<Record<string, ResourceTypeDef>>;
    /** Relations on subject-side types (e.g. user#manager, team#member). */
    readonly subjectRelations?: Readonly<Record<string, Readonly<Record<string, RelationDef>>>>;
    readonly compartments: readonly string[];
  };
  readonly rbac: {
    readonly roles: Readonly<Record<string, {
      readonly inherits?: readonly string[];
      readonly grants: readonly { readonly resourceType: string; readonly actions: readonly string[] }[];
    }>>;
  };
  readonly mandatory: {
    /** Roles allowed to write below their session level (BLP trusted subjects, e.g. a declassification officer). */
    readonly trustedRoles: readonly string[];
    readonly untrustedNetworkMaxLevel: Level;
    readonly compartmentsRequireTrustedNetwork: boolean;
    /** Actions that must not consume lower-integrity data (Biba no-read-down), e.g. approve. */
    readonly bibaNoReadDownActions: readonly string[];
    /** `actions` (default) uses only the list; `reads` covers every read-kind action; `all` covers every action. */
    readonly bibaNoReadDownScope?: 'actions' | 'reads' | 'all';
  };
  readonly needToKnow: {
    readonly mode: 'off' | 'dry_run' | 'enforce';
    /** Resource types protected by need-to-know, with the relation that gives a reason to know. */
    readonly protect: Readonly<Record<string, { readonly relation: string; readonly minLevel?: Level }>>;
    readonly breakGlassMaxHours: number;
    readonly breakGlassNotify: readonly string[];
  };
  readonly abac: readonly AbacRule[];
  /** ABAC on content attributes (mask, redact, deny). */
  readonly abacContent?: readonly AbacContentRule[];
  /** Deprecated compatibility input for content-attribute rules; validateBundle normalizes it to abacContent. */
  readonly cbac?: readonly AbacContentRule[];
  /** CBAC (context-based, Zero Trust) rules; optional for bundles written before them, absent means none. */
  readonly context?: readonly ContextRule[];
  readonly sod: readonly SodRule[];
  readonly clarkWilson: {
    readonly tokenTtlSeconds: number;
    /** Integrity verification procedures: when absent or empty, Clark-Wilson decisions are exactly those without IVPs. */
    readonly ivps?: readonly IvpDef[];
    /** Constrained types whose certified actions run only with a certification record (CW.NOT_CERTIFIED otherwise).
     *  Absent or empty: certification records are evidence only. */
    readonly requireCertification?: readonly string[];
    /** C5: declarative validators of the input of certified commands, run at decision and on the post-state at consumption. */
    readonly inputValidators?: readonly InputValidatorDef[];
    /** E3: constrained types whose certified commands are decided only for a subject whose type the calling PEP
     *  credential is bound to (CW.SUBJECT_NOT_AUTHENTICATED otherwise). */
    readonly requirePepBinding?: readonly string[];
  };
}

/** One input field: its JSON type and bounds. A field not declared by the validator fails it (closed schema). */
export interface InputFieldRule {
  readonly type: 'string' | 'number' | 'integer' | 'boolean';
  readonly required?: boolean;
  readonly enum?: readonly (string | number | boolean)[];
  readonly min?: number;
  readonly max?: number;
  readonly maxLength?: number;
}
/** Clark-Wilson C5: what a certified command accepts as input on these types. It holds only when every rule holds. */
export interface InputValidatorDef {
  readonly id: string;
  readonly description: string;
  readonly resourceTypes: readonly string[];
  readonly actions: readonly string[];
  readonly fields: Readonly<Record<string, InputFieldRule>>;
}

/** Clark-Wilson IVP: a declared predicate over a constrained data item (resource.* paths only). It holds only when TRUE. */
export interface IvpDef {
  readonly id: string;
  readonly description: string;
  /** Constrained resource types this check applies to. */
  readonly resourceTypes: readonly string[];
  readonly check: Expr;
}

// ---------- decisions ----------

export type StageName =
  | 'inactive' | 'rbac' | 'mandatory' | 'delegation' | 'need_to_know' | 'abac' | 'cbac' | 'clark_wilson' | 'sod' | 'engine';

export interface TraceStep {
  readonly stage: StageName;
  readonly rule: string;
  readonly outcome: 'pass' | 'deny' | 'would_deny' | 'skip' | 'obligation';
  readonly reason: string;
  /** For a relation-based pass: the path that gave the reason to know. */
  readonly path?: readonly string[];
  /** Context traces carry the policy rule, requirement and asserted value behind the reason code. */
  readonly policyRule?: string;
  readonly requirement?: string;
  readonly observed?: Json;
  /** ABAC on content attributes, inside the abac stage rather than the CBAC (Zero Trust) stage. */
  readonly kind?: 'content';
}

export interface Decision {
  readonly decision: boolean;
  /** Ids of the denying rules (deny) or of the eligibility and reason-to-know basis (allow). */
  readonly rules: readonly string[];
  readonly reasons: readonly string[];
  readonly obligations: Obligations;
  readonly trace: readonly TraceStep[];
  /** Rules that would deny once need-to-know is enforced (dry run). */
  readonly wouldDeny: readonly string[];
  readonly policyVersion: string;
}
