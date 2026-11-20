// Core engine types matching packages/core/src/types.ts.

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export type Level = 0 | 1 | 2 | 3;

export type Integrity = 'derived' | 'extracted' | 'system' | 'verified';

export type ActionKind = 'read' | 'write' | 'delete' | 'approve' | 'execute';

export interface Ref {
  readonly type: string;
  readonly id: string;
}

/** CBAC grant duration on a role, both bounds inclusive. */
export interface RoleAssignment {
  readonly role: string;
  readonly notBefore?: string;
  readonly notAfter?: string;
}

export interface Tuple {
  readonly object: Ref;
  readonly relation: string;
  readonly subject: Ref;
  readonly subjectRelation?: string;
  /** CBAC grant window, both bounds inclusive; validFrom/validTo are the names of records written before it. */
  readonly notBefore?: string;
  readonly notAfter?: string;
  readonly validFrom?: string;
  readonly validTo?: string;
  readonly breakGlass?: boolean;
  readonly grantedBy?: string;
  readonly reason?: string;
}

export type RelationRewrite =
  | { readonly this: true }
  | { readonly computed: string }
  | { readonly fromParent: { readonly relation: string; readonly then: string } }
  | { readonly viaReports: { readonly managerRelation: string; readonly then: string; readonly maxDepth: number } };

export interface RelationDef {
  readonly union: readonly RelationRewrite[];
}

export type Operand = { readonly path: string } | { readonly value: Json };

export type BinaryOp = 'eq' | 'ne' | 'lt' | 'le' | 'gt' | 'ge' | 'in' | 'contains' | 'subset';

export type Expr =
  | { readonly op: BinaryOp; readonly left: Operand; readonly right: Operand }
  | { readonly op: 'has'; readonly path: string }
  | { readonly op: 'and' | 'or'; readonly args: readonly Expr[] }
  | { readonly op: 'not'; readonly arg: Expr }
  | { readonly op: 'true' };

export interface Obligations {
  readonly fieldAllowlist?: readonly string[];
  readonly redact: readonly string[];
  readonly maskClasses: readonly string[];
  readonly notify: readonly string[];
  readonly decisionToken?: { readonly ttlSeconds: number; readonly resourceVersion: number | null };
}

export interface AbacRule {
  readonly id: string;
  readonly description: string;
  readonly effect: 'permit' | 'forbid' | 'obligation';
  readonly resourceTypes?: readonly string[];
  readonly actions?: readonly string[];
  readonly when: Expr;
  readonly obligations?: Partial<Omit<Obligations, 'decisionToken'>>;
}

/** ABAC on content attributes (mask, redact, deny). */
export interface AbacContentRule {
  readonly id: string;
  readonly description: string;
  readonly contentClass: string;
  readonly effect: 'deny' | 'mask' | 'redact';
  readonly fields?: readonly string[];
  readonly actions?: readonly string[];
  readonly unless?: Expr;
}

export interface SodRule {
  readonly id: string;
  readonly description: string;
  readonly conflicting: readonly string[];
}

export interface Context {
  readonly network: 'trusted' | 'untrusted';
  readonly now: string;
  readonly ip?: string;
  readonly country?: string;
  readonly device?: { readonly managed: boolean; readonly compliant: boolean };
  readonly authTime?: string;
  readonly mfaTime?: string;
  readonly authMethods?: readonly string[];
  readonly riskScore?: number;
  readonly sessionLevel?: Level;
  readonly sessionId?: string;
  readonly highWater?: Level;
  readonly sessionRequired?: boolean;
  readonly sessionExpired?: boolean;
  readonly makerId?: string;
  readonly serverMakerId?: string;
  readonly priorActions?: readonly string[];
}

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
  readonly timeWindows?: readonly { readonly days: readonly number[]; readonly from: string; readonly to: string; readonly timeZone: string }[];
  readonly device?: { readonly managed?: boolean; readonly compliant?: boolean };
  readonly mfaMaxAgeSeconds?: number;
  readonly authMaxAgeSeconds?: number;
  readonly authMethodsAny?: readonly string[];
  readonly maxRiskScore?: number;
}

export interface ActionDef {
  readonly kind: ActionKind;
  readonly certified?: boolean;
  readonly requiresSecondPerson?: boolean;
}

export interface ResourceTypeDef {
  readonly actions: Readonly<Record<string, ActionDef>>;
  readonly relations?: Readonly<Record<string, RelationDef>>;
  readonly constrained?: boolean;
}

export interface PolicyBundle {
  readonly name: string;
  readonly schema: {
    readonly resourceTypes: Readonly<Record<string, ResourceTypeDef>>;
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
    readonly trustedRoles: readonly string[];
    readonly untrustedNetworkMaxLevel: Level;
    readonly compartmentsRequireTrustedNetwork: boolean;
    readonly bibaNoReadDownActions: readonly string[];
    readonly bibaNoReadDownScope?: 'actions' | 'reads' | 'all';
  };
  readonly needToKnow: {
    readonly mode: 'off' | 'dry_run' | 'enforce';
    readonly protect: Readonly<Record<string, { readonly relation: string; readonly minLevel?: Level }>>;
    readonly breakGlassMaxHours: number;
    readonly breakGlassNotify: readonly string[];
  };
  readonly abac: readonly AbacRule[];
  readonly abacContent?: readonly AbacContentRule[];
  /** Deprecated name of abacContent, read for one version (DEPRECATED_CBAC_FIELD). */
  readonly cbac?: readonly AbacContentRule[];
  /** CBAC (context-based, Zero Trust) rules. */
  readonly context?: readonly ContextRule[];
  readonly sod: readonly SodRule[];
  readonly clarkWilson: { readonly tokenTtlSeconds: number };
}

export type StageName =
  | 'inactive' | 'rbac' | 'mandatory' | 'delegation' | 'need_to_know' | 'abac' | 'cbac' | 'clark_wilson' | 'sod' | 'engine';

export interface TraceStep {
  readonly stage: StageName;
  readonly rule: string;
  readonly outcome: 'pass' | 'deny' | 'would_deny' | 'skip' | 'obligation';
  readonly reason: string;
  readonly path?: readonly string[];
  readonly policyRule?: string;
  readonly requirement?: string;
  readonly observed?: Json;
  /** 'content': ABAC on content attributes, inside the abac stage. */
  readonly kind?: 'content';
}

export interface Decision {
  readonly decision: boolean;
  readonly rules: readonly string[];
  readonly reasons: readonly string[];
  readonly obligations: Obligations;
  readonly trace: readonly TraceStep[];
  readonly wouldDeny: readonly string[];
  readonly policyVersion: string;
}

/** The content-attribute rules of a bundle, whichever field holds them (a stored bundle may still use cbac). */
export const contentRules = (b: PolicyBundle): readonly AbacContentRule[] => [...(b.abacContent ?? []), ...(b.cbac ?? [])];

/** A tuple's grant window, new names first. */
export const windowOf = (t: Tuple): { from?: string; to?: string } => ({ from: t.notBefore ?? t.validFrom, to: t.notAfter ?? t.validTo });
