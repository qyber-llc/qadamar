import Qadamar.Cond
/-!
# Policy bundles (the modelled part of `PolicyBundle` in packages/core/src/types.ts)

A bundle is taken well-typed: rule effects are from their closed sets, every field has its declared type. A bundle
outside these types is rejected by the JSON reader (`Qadamar.Json`), where TypeScript would deny with
`ENGINE.RULE_ERROR` or reject it in `validateBundle`.
-/
namespace Qadamar

inductive Kind where
  | read | write | delete | approve | execute
  deriving DecidableEq, Repr

/-- Every kind but read changes state. -/
def Kind.isWrite : Kind → Bool
  | .read => false
  | _ => true

def Kind.name : Kind → String
  | .read => "read" | .write => "write" | .delete => "delete" | .approve => "approve" | .execute => "execute"

structure ActionDef where
  kind : Kind
  certified : Bool
  requiresSecondPerson : Bool
  deriving Repr

structure TypeDef where
  actions : List (String × ActionDef)
  constrained : Bool
  deriving Repr

structure Grant where
  resourceType : String
  actions : List String
  deriving Repr

structure Role where
  inherits : List String
  grants : List Grant
  deriving Repr

inductive BibaNoReadDownScope where
  | actions | reads | all
  deriving DecidableEq, Repr

structure Mandatory where
  trustedRoles : List String
  untrustedNetworkMaxLevel : Nat
  compartmentsRequireTrustedNetwork : Bool
  bibaNoReadDownActions : List String
  bibaNoReadDownScope : BibaNoReadDownScope
  deriving Repr

inductive NtkMode where
  | off | dryRun | enforce
  deriving DecidableEq, Repr

structure Protect where
  relation : String
  minLevel : Nat
  deriving Repr

structure NeedToKnow where
  mode : NtkMode
  protect : List (String × Protect)
  breakGlassNotify : List String
  deriving Repr

structure Token where
  ttlSeconds : Val
  resourceVersion : Val
  postState : Bool
  deriving Repr

/-- Partial obligations, as one rule contributes them (`Partial<Obligations>`); also the merged result. -/
structure Obl where
  fieldAllowlist : Option (List String) := none
  redact : List String := []
  maskClasses : List String := []
  notify : List String := []
  decisionToken : Option Token := none
  deriving Repr

inductive AbacEffect where
  | permit | forbid | obligation
  deriving DecidableEq, Repr

structure AbacRule where
  id : String
  effect : AbacEffect
  resourceTypes : Option (List String)
  actions : Option (List String)
  when : Expr
  obligations : Obl
  deriving Repr

/-- ABAC on content attributes (bundle field `abacContent`, legacy `cbac`): mask, redact or deny by content class. -/
inductive ContentEffect where
  | deny | mask | redact
  deriving DecidableEq, Repr

structure ContentRule where
  id : String
  contentClass : String
  effect : ContentEffect
  fields : List String
  actions : Option (List String)
  «unless» : Option Expr
  deriving Repr

/-- A CBAC (context-based, Zero Trust) rule: a selector and its requirements, in the order of `contextChecks`
    (context.ts). The requirements whose predicate the model does not compute (CIDR membership, IANA local-time
    windows, authentication ages) are flags here; their outcome comes from the oracle (`Qadamar.Eval`). -/
structure ContextRule where
  id : String
  resourceTypes : Option (List String)
  actions : Option (List String)
  actionKinds : Option (List Kind)
  minResourceLevel : Option Nat
  contentClasses : Option (List String)
  network : Bool
  countries : Option (List String)
  ipRanges : Bool
  timeWindows : Bool
  deviceManaged : Option Bool
  deviceCompliant : Option Bool
  mfaMaxAge : Bool
  authMaxAge : Bool
  authMethodsAny : Option (List String)
  maxRiskScore : Option Nat
  deriving Repr

structure SodRule where
  id : String
  conflicting : List String
  deriving Repr

structure Ivp where
  id : String
  resourceTypes : List String
  check : Expr
  deriving Repr

inductive FieldType where
  | string | number | integer | boolean
  deriving DecidableEq, Repr

structure FieldRule where
  type : FieldType
  required : Bool
  enum : Option (List Val)
  min : Option Num
  max : Option Num
  maxLength : Option Nat
  deriving Repr

structure Validator where
  id : String
  resourceTypes : List String
  actions : List String
  fields : List (String × FieldRule)
  deriving Repr

structure ClarkWilson where
  tokenTtlSeconds : Val
  ivps : List Ivp
  requireCertification : List String
  inputValidators : List Validator
  requirePepBinding : List String
  deriving Repr

structure Bundle where
  resourceTypes : List (String × TypeDef)
  roles : List (String × Role)
  mandatory : Mandatory
  needToKnow : NeedToKnow
  abac : List AbacRule
  /-- `contentRules(bundle)`: `abacContent`, then the legacy `cbac` list. -/
  content : List ContentRule
  context : List ContextRule
  sod : List SodRule
  clarkWilson : ClarkWilson
  deriving Repr

def lookup (k : String) (xs : List (String × α)) : Option α := (xs.find? (·.1 == k)).map (·.2)

end Qadamar
