import Lean.Data.Json
import Qadamar.Eval
/-!
# JSON input and output of the executable model (not part of the proofs)

Reads a bundle into the typed `Bundle` of `Qadamar.Policy`, rejecting what the model does not cover; converts requests
to `Val`; prints decisions. Uses only `Lean.Data.Json` from the Lean distribution.
-/
namespace Qadamar

partial def ofJson : Lean.Json → Val
  | .null => .null
  | .bool b => .bool b
  | .num n => .num (Num.norm n.mantissa n.exponent)
  | .str s => .str s
  | .arr xs => .arr (xs.toList.map ofJson)
  | .obj kvs => .obj (kvs.foldr (init := []) fun k v acc => (k, ofJson v) :: acc)

partial def toJson : Val → Lean.Json
  | .null => .null
  | .bool b => .bool b
  | .num n => .num ⟨n.mantissa, n.exponent⟩
  | .str s => .str s
  | .arr xs => .arr (xs.map toJson).toArray
  | .obj kvs => Lean.Json.mkObj (kvs.map fun (k, v) => (k, toJson v))

abbrev P := Except String

def need (v : Val) (k : String) : P Val :=
  match v.field? k with
  | some x => pure x
  | none => throw s!"missing {k}"

def str (v : Val) : P String :=
  match v with
  | .str s => pure s
  | _ => throw "expected a string"

def strs (v : Val) : P (List String) :=
  match v.asStrList? with
  | some xs => pure xs
  | none => throw "expected a list of strings"

def optStrs (v : Val) (k : String) : P (Option (List String)) :=
  match v.field? k with
  | none => pure none
  | some x => some <$> strs x

def optBool (v : Val) (k : String) (dflt : Bool) : P Bool :=
  match v.field? k with
  | none => pure dflt
  | some (.bool b) => pure b
  | some _ => throw s!"{k} must be a boolean"

def level (v : Val) : P Nat :=
  match isLevel? v with
  | some n => pure n
  | none => throw "expected a level 0..3"

def entries (v : Val) : P (List (String × Val)) :=
  match v with
  | .obj kvs => pure kvs
  | _ => throw "expected an object"

def list (v : Val) : P (List Val) :=
  match v with
  | .arr xs => pure xs
  | _ => throw "expected a list"

def operandOf (v : Val) : P Operand :=
  match v.field? "path", v.field? "value" with
  | some (.str p), _ => pure (.path p)
  | some _, _ => throw "operand path must be a string"
  | none, some x => pure (.value x)
  | none, none => throw "operand without path or value"

partial def exprOf (v : Val) : P Expr := do
  let op ← str (← need v "op")
  match op with
  | "true" => pure .tru
  | "unknown" => pure .unk
  | "and" => .and <$> ((← list (← need v "args")).mapM exprOf)
  | "or" => .or <$> ((← list (← need v "args")).mapM exprOf)
  | "not" => .not <$> exprOf (← need v "arg")
  | "has" => .has <$> str (← need v "path")
  | _ =>
    let cop ← match op with
      | "eq" => pure CmpOp.eq | "ne" => pure .ne | "lt" => pure .lt | "le" => pure .le | "gt" => pure .gt
      | "ge" => pure .ge | "in" => pure .in_ | "contains" => pure .contains | "subset" => pure .subset
      | o => throw s!"unknown operator {o}"
    pure (.cmp cop (← operandOf (← need v "left")) (← operandOf (← need v "right")))

def kindOf : String → P Kind
  | "read" => pure .read | "write" => pure .write | "delete" => pure .delete
  | "approve" => pure .approve | "execute" => pure .execute
  | k => throw s!"unknown action kind {k}"

def typeDefOf (v : Val) : P TypeDef := do
  let actions ← (← entries (← need v "actions")).mapM fun (n, a) => do
    pure (n, { kind := ← kindOf (← str (← need a "kind")), certified := ← optBool a "certified" false,
               requiresSecondPerson := ← optBool a "requiresSecondPerson" false : ActionDef })
  pure { actions, constrained := ← optBool v "constrained" false }

def roleOf (v : Val) : P Role := do
  let grants ← (← list (← need v "grants")).mapM fun g => do
    pure { resourceType := ← str (← need g "resourceType"), actions := ← strs (← need g "actions") : Grant }
  pure { inherits := (← optStrs v "inherits").getD [], grants }

def oblOf (v : Val) : P Obl := do
  if v.has "decisionToken" then throw "rule obligations cannot carry a decision token"
  pure { fieldAllowlist := ← optStrs v "fieldAllowlist", redact := (← optStrs v "redact").getD [],
         maskClasses := (← optStrs v "maskClasses").getD [], notify := (← optStrs v "notify").getD [] }

def abacOf (v : Val) : P AbacRule := do
  let effect ← match ← str (← need v "effect") with
    | "permit" => pure AbacEffect.permit | "forbid" => pure .forbid | "obligation" => pure .obligation
    | e => throw s!"unknown ABAC effect {e}"
  pure { id := ← str (← need v "id"), effect, resourceTypes := ← optStrs v "resourceTypes",
         actions := ← optStrs v "actions", when := ← exprOf (← need v "when"),
         obligations := ← match v.field? "obligations" with | none => pure {} | some o => oblOf o }

def contentOf (v : Val) : P ContentRule := do
  let effect ← match ← str (← need v "effect") with
    | "deny" => pure ContentEffect.deny | "mask" => pure .mask | "redact" => pure .redact
    | e => throw s!"unknown content-rule effect {e}"
  pure { id := ← str (← need v "id"), contentClass := ← str (← need v "contentClass"), effect,
         fields := (← optStrs v "fields").getD [], actions := ← optStrs v "actions",
         «unless» := ← match v.field? "unless" with | none => pure none | some e => some <$> exprOf e }

def optList (v : Val) (k : String) : P (List Val) :=
  match v.field? k with
  | none => pure []
  | some x => list x

def contextOf (v : Val) : P ContextRule := do
  let kinds ← match v.field? "actionKinds" with
    | none => pure none
    | some ks => some <$> (← strs ks).mapM kindOf
  let minResourceLevel ← match v.field? "minResourceLevel" with | none => pure none | some l => some <$> level l
  let network ← match v.field? "network" with
    | none => pure false
    | some (.str "trusted") => pure true
    | some _ => throw "context network must be trusted"
  let device ← match v.field? "device" with
    | none => pure (none, none)
    | some d => do
      let b (k : String) : P (Option Bool) := match d.field? k with
        | none => pure none | some (.bool x) => pure (some x) | some _ => throw s!"device.{k} must be a boolean"
      pure (← b "managed", ← b "compliant")
  let maxRiskScore ← match v.field? "maxRiskScore" with
    | none => pure none
    | some (.num n) => if n.isInt && 0 ≤ n.mantissa && n.mantissa ≤ 100 then pure (some n.mantissa.toNat) else throw "maxRiskScore"
    | some _ => throw "maxRiskScore"
  let r : ContextRule := {
    id := ← str (← need v "id"), resourceTypes := ← optStrs v "resourceTypes", actions := ← optStrs v "actions",
    actionKinds := kinds, minResourceLevel, contentClasses := ← optStrs v "contentClasses", network,
    countries := ← optStrs v "countries", ipRanges := v.has "ipRanges", timeWindows := v.has "timeWindows",
    deviceManaged := device.1, deviceCompliant := device.2, mfaMaxAge := v.has "mfaMaxAgeSeconds",
    authMaxAge := v.has "authMaxAgeSeconds", authMethodsAny := ← optStrs v "authMethodsAny", maxRiskScore }
  -- a rule without a requirement is a rule error in TypeScript (and refused by validateBundle): outside the model
  unless r.network || r.countries.isSome || r.ipRanges || r.timeWindows || r.deviceManaged.isSome ||
      r.deviceCompliant.isSome || r.mfaMaxAge || r.authMaxAge || r.authMethodsAny.isSome || r.maxRiskScore.isSome do
    throw s!"context rule {r.id} has no requirement"
  pure r

def num (v : Val) : P Num :=
  match v with
  | .num n => pure n
  | _ => throw "expected a number"

def fieldRuleOf (v : Val) : P FieldRule := do
  let type ← match ← str (← need v "type") with
    | "string" => pure FieldType.string | "number" => pure .number | "integer" => pure .integer
    | "boolean" => pure .boolean | t => throw s!"unknown field type {t}"
  pure { type, required := ← optBool v "required" false,
         enum := ← match v.field? "enum" with | none => pure none | some e => some <$> list e,
         min := ← match v.field? "min" with | none => pure none | some x => some <$> num x,
         max := ← match v.field? "max" with | none => pure none | some x => some <$> num x,
         maxLength := ← match v.field? "maxLength" with
           | none => pure none
           | some (.num n) => if n.isInt && n.mantissa ≥ 0 then pure (some n.mantissa.toNat) else throw "maxLength"
           | some _ => throw "maxLength" }

def bibaScopeOf (v : Val) : P BibaNoReadDownScope :=
  match v.field? "bibaNoReadDownScope" with
  | none => pure .actions
  | some (.str "actions") => pure .actions
  | some (.str "reads") => pure .reads
  | some (.str "all") => pure .all
  | some _ => throw "bibaNoReadDownScope must be actions, reads or all"

def bundleOf (v : Val) : P Bundle := do
  let schema ← need v "schema"
  let resourceTypes ← (← entries (← need schema "resourceTypes")).mapM fun (n, t) => do pure (n, ← typeDefOf t)
  let roles ← (← entries (← need (← need v "rbac") "roles")).mapM fun (n, r) => do pure (n, ← roleOf r)
  let m ← need v "mandatory"
  let mandatory : Mandatory := {
    trustedRoles := ← strs (← need m "trustedRoles"),
    untrustedNetworkMaxLevel := ← level (← need m "untrustedNetworkMaxLevel"),
    compartmentsRequireTrustedNetwork := ← optBool m "compartmentsRequireTrustedNetwork" true,
    bibaNoReadDownActions := ← strs (← need m "bibaNoReadDownActions"),
    bibaNoReadDownScope := ← bibaScopeOf m }
  let nk ← need v "needToKnow"
  let mode ← match ← str (← need nk "mode") with
    | "off" => pure NtkMode.off | "dry_run" => pure .dryRun | "enforce" => pure .enforce
    | x => throw s!"unknown need-to-know mode {x}"
  let protect ← (← entries (← need nk "protect")).mapM fun (n, p) => do
    pure (n, { relation := ← str (← need p "relation"),
               minLevel := ← match p.field? "minLevel" with | none => pure 0 | some l => level l : Protect })
  let needToKnow : NeedToKnow := { mode, protect, breakGlassNotify := ← strs (← need nk "breakGlassNotify") }
  let cw ← need v "clarkWilson"
  let ivps ← match cw.field? "ivps" with
    | none => pure []
    | some xs => (← list xs).mapM fun i => do
        pure { id := ← str (← need i "id"), resourceTypes := ← strs (← need i "resourceTypes"),
               check := ← exprOf (← need i "check") : Ivp }
  let inputValidators ← match cw.field? "inputValidators" with
    | none => pure []
    | some xs => (← list xs).mapM fun x => do
        pure { id := ← str (← need x "id"), resourceTypes := ← strs (← need x "resourceTypes"),
               actions := ← strs (← need x "actions"),
               fields := ← (← entries (← need x "fields")).mapM fun (n, f) => do pure (n, ← fieldRuleOf f) : Validator }
  let clarkWilson : ClarkWilson := {
    tokenTtlSeconds := .num (← num (← need cw "tokenTtlSeconds")), ivps,
    requireCertification := (← optStrs cw "requireCertification").getD [], inputValidators,
    requirePepBinding := (← optStrs cw "requirePepBinding").getD [] }
  pure { resourceTypes, roles, mandatory, needToKnow, clarkWilson,
         abac := ← (← list (← need v "abac")).mapM abacOf,
         content := ← ((← optList v "abacContent") ++ (← optList v "cbac")).mapM contentOf,
         context := ← (← optList v "context").mapM contextOf,
         sod := ← (← list (← need v "sod")).mapM fun s => do
           pure { id := ← str (← need s "id"), conflicting := ← strs (← need s "conflicting") : SodRule } }

def oracleOf (v : Val) : P Oracle := do
  let ntk ← match v.field? "ntk" with
    | none => pure []
    | some xs => (← list xs).mapM fun
        | .null => pure (default : NtkResult)
        | r => do pure { ok := ← optBool r "ok" false, breakGlass := ← optBool r "breakGlass" false : NtkResult }
  -- roleLive: per principal, [{ role, notBefore?, notAfter?, live }]; ctxOk: per context rule, { <requirement>: bool }
  let roleLive ← (← optList v "roleLive").mapM fun xs => do
    (← list xs).mapM fun x => do
      match parseAssignment x with
      | some a => pure (a, ← optBool x "live" false)
      | none => throw "roleLive entries are role assignments"
  let ctxOk ← (← optList v "ctxOk").mapM entries
  pure { ntk := fun i => ntk.getD i default, fingerprintCurrent := ← optBool v "fingerprintCurrent" false,
         signalsValid := ← optBool v "signalsValid" false,
         roleLive := fun i a => (((roleLive.getD i []).find? (·.1 == a)).map (·.2)).getD false,
         ctxOk := fun j k => match lookup k (ctxOk.getD j []) with | some (.bool b) => b | _ => false }

def strArr (xs : List String) : Lean.Json := .arr (xs.map Lean.Json.str).toArray

def oblJson (o : Obl) : Lean.Json :=
  Lean.Json.mkObj <|
    (match o.fieldAllowlist with | some xs => [("fieldAllowlist", strArr xs)] | none => []) ++
    [("redact", strArr o.redact), ("maskClasses", strArr o.maskClasses), ("notify", strArr o.notify)] ++
    (match o.decisionToken with
     | some t => [("decisionToken", Lean.Json.mkObj <|
         [("ttlSeconds", toJson t.ttlSeconds), ("resourceVersion", toJson t.resourceVersion)] ++
         (if t.postState then [("postState", Lean.Json.bool true)] else []))]
     | none => [])

def decisionJson (d : Decision) : Lean.Json :=
  Lean.Json.mkObj [("decision", .bool d.decision), ("rules", strArr d.rules),
    ("obligations", oblJson d.obligations), ("wouldDeny", strArr d.wouldDeny)]

/-- One input line: `{ "bundle": …, "cases": [{ "request": …, "oracle": … }] }`; one output line per input line. -/
def runLine (line : String) : Lean.Json :=
  let res : P Lean.Json := do
    let j ← Lean.Json.parse line
    let v := ofJson j
    let b ← bundleOf (← need v "bundle")
    let cases ← list (← need v "cases")
    let out ← cases.mapM fun c => do
      pure (decisionJson (evaluate b (← need c "request") (← oracleOf (← need c "oracle"))))
    pure (Lean.Json.mkObj [("results", .arr out.toArray)])
  match res with
  | .ok j => j
  | .error e => Lean.Json.mkObj [("error", .str e)]

end Qadamar
