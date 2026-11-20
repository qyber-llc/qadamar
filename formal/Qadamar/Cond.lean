import Qadamar.Value
/-!
# The condition language with three-valued (Kleene) logic

Mirrors `packages/core/src/conditions.ts`: `resolvePath`, `compare` (0.7.0: a mistyped operand is UNKNOWN;
0.8.2: strings in code-point order), `evalTri`, `evalExpr` (TRUE only) and `mayHold` (TRUE or UNKNOWN).
`Tri` is `Option Bool`: `none` is UNKNOWN (SQL NULL).
-/
namespace Qadamar

abbrev Tri := Option Bool

inductive CmpOp where
  | eq | ne | lt | le | gt | ge | in_ | contains | subset
  deriving DecidableEq, Repr

inductive Operand where
  | path (p : String)
  | value (v : Val)
  deriving Repr, Inhabited

inductive Expr where
  | cmp (op : CmpOp) (left right : Operand)
  | has (path : String)
  | and (args : List Expr)
  | or (args : List Expr)
  | not (arg : Expr)
  | tru
  | unk
  deriving Repr, Inhabited

def roots : List String := ["subject", "resource", "action", "context"]

/-- `resolvePath`: `none` is MISSING (absent, not an own property, or JSON null). -/
def resolvePath (env : Val) (path : String) : Option Val :=
  match path.splitOn "." with
  | [] => none
  | root :: rest =>
    if !roots.contains root then none else
    match rest.foldl (fun cur p => cur.bind (·.getField p)) (env.field? root) with
    | some .null => none
    | r => r

def operand (env : Val) : Operand → Option Val
  | .path p => resolvePath env p
  | .value .null => none
  | .value v => some v

def same (a b : Val) : Bool := Val.beq a b

/-- `ordered`: numbers numerically, strings in code-point order, anything else is not ordered. -/
def ordered : Val → Val → Option Ordering
  | .num a, .num b => some (Num.cmp a b)
  | .str a, .str b => some (cpCompare a b)
  | _, _ => none

def compareVals (op : CmpOp) (a b : Val) : Tri :=
  match op with
  | .eq => some (same a b)
  | .ne => some (!same a b)
  | .in_ => match b with
    | .arr ys => some (ys.any (same · a))
    | _ => none
  | .contains => match a, b with
    | .arr xs, _ => some (xs.any (same · b))
    | .str x, .str y => some (strIncludes x y)
    | _, _ => none
  | .subset => match a, b with
    | .arr xs, .arr ys => some (xs.all fun x => ys.any (same x ·))
    | _, _ => none
  | .lt => (ordered a b).map (· == .lt)
  | .le => (ordered a b).map (· != .gt)
  | .gt => (ordered a b).map (· == .gt)
  | .ge => (ordered a b).map (· != .lt)

/-- `compare`: a MISSING operand is UNKNOWN. -/
def compareOpt (op : CmpOp) : Option Val → Option Val → Tri
  | some a, some b => compareVals op a b
  | _, _ => none

def andTri (xs : List Tri) : Tri :=
  if xs.contains (some false) then some false else if xs.contains none then none else some true

def orTri (xs : List Tri) : Tri :=
  if xs.contains (some true) then some true else if xs.contains none then none else some false

def notTri : Tri → Tri
  | none => none
  | some b => some (!b)

mutual
def evalTri (env : Val) : Expr → Tri
  | .tru => some true
  | .unk => none
  | .and args => andTri (evalAll env args)
  | .or args => orTri (evalAll env args)
  | .not e => notTri (evalTri env e)
  | .has p => some (resolvePath env p).isSome
  | .cmp op l r => compareOpt op (operand env l) (operand env r)

def evalAll (env : Val) : List Expr → List Tri
  | [] => []
  | e :: es => evalTri env e :: evalAll env es
end

/-- TRUE only: what a permit, an exemption (CBAC `unless`) and an IVP need. -/
def evalExpr (env : Val) (e : Expr) : Bool := evalTri env e == some true

/-- TRUE or UNKNOWN: what fires a forbid or an obligation (fail closed). -/
def mayHold (env : Val) (e : Expr) : Bool := evalTri env e != some false

theorem mayHold_of_unknown {env : Val} {e : Expr} (h : evalTri env e = none) : mayHold env e = true := by
  simp [mayHold, h]

theorem not_evalExpr_of_unknown {env : Val} {e : Expr} (h : evalTri env e = none) : evalExpr env e = false := by
  simp [evalExpr, h]

end Qadamar
