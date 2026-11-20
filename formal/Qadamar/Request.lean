import Qadamar.Value
/-!
# Requests and their validation

Mirrors `packages/core/src/request.ts`. `parseRequest` returns `none` exactly when `requestErrors` is non-empty, and
otherwise the typed view the pipeline reads. The raw JSON of the subject, resource and context is kept: conditions
resolve paths into it.

`context.now` is accepted iff `validInstant` accepts it: a full date and time with an explicit `Z` or offset, on a real
calendar day. Every number in the subject, resource and context must lie within ±(2^53 - 1) once read as a double.
-/
namespace Qadamar

inductive Integrity where
  | derived | extracted | system | verified
  deriving DecidableEq, Repr

def Integrity.rank : Integrity → Nat
  | .derived => 0 | .extracted => 1 | .system => 2 | .verified => 3

def Integrity.parse? : Val → Option Integrity
  | .str "derived" => some .derived
  | .str "extracted" => some .extracted
  | .str "system" => some .system
  | .str "verified" => some .verified
  | _ => none

/-- A time-bound role (`roleAssignments` on a subject, CBAC grant duration). Whether `now` lies in its window is an
    input of the model (`Oracle.roleLive`); the instants themselves are not parsed. -/
structure RoleAssignment where
  role : String
  notBefore : Option String
  notAfter : Option String
  deriving DecidableEq, Repr

/-- One principal: the subject, or a person it acts for. `raw` is its JSON (with its own delegator inside). -/
structure Principal where
  type : String
  id : String
  active : Bool
  roles : List String
  assignments : List RoleAssignment
  clearance : Nat
  compartments : List String
  integrity : Integrity
  raw : Val
  deriving Repr

structure Resource where
  type : String
  id : String
  level : Nat
  compartments : List String
  integrity : Integrity
  contentClasses : List String
  /-- `version ?? null`, as bound into the decision token. -/
  version : Val
  raw : Val
  deriving Repr

structure CertRecord where
  resourceType : String
  action : String
  by_ : List String
  deriving Repr

structure Device where
  managed : Bool
  compliant : Bool
  deriving Repr

structure Context where
  trusted : Bool
  sessionLevel : Option Nat
  sessionId : Option String
  highWater : Option Nat
  sessionRequired : Bool
  makerId : Option String
  serverMakerId : Option String
  priorActions : List String
  certified : List CertRecord
  pepSubjectTypes : List String
  input : Option Val
  /-- `sessionExpired === true`: the PDP or the PEP knows the session ended (CBAC.SESSION_EXPIRED). -/
  sessionExpired : Bool
  /-- Zero Trust signals, as asserted by the PEP; their grammar (IP literal, ISO country, instants, method names) is
      checked by `Oracle.signalsValid`, their shape here. -/
  ip : Option String
  country : Option String
  device : Option Device
  authTime : Option String
  mfaTime : Option String
  authMethods : Option (List String)
  riskScore : Option Nat
  raw : Val
  deriving Repr

structure Req where
  /-- The subject, then each person it acts for (`principals` in request.ts). -/
  chain : List Principal
  action : String
  resource : Resource
  context : Context
  deriving Repr

def maxDelegationDepth : Nat := 4

def isId? : Val → Option String
  | .str s => if 0 < utf16Length s && utf16Length s ≤ 256 then some s else none
  | _ => none

def isLevel? : Val → Option Nat
  | .num n => if n.exponent == 0 && 0 ≤ n.mantissa && n.mantissa ≤ 3 then some n.mantissa.toNat else none
  | _ => none

/-- An optional field: absent is fine, present must parse. -/
def optField (v : Val) (k : String) (p : Val → Option α) : Option (Option α) :=
  match v.field? k with
  | none => some none
  | some x => (p x).map some

/-! ## `validInstant` (context.ts): `YYYY-MM-DDTHH:mm:ss[.fffffffff](Z|±hh:mm)` on a real calendar day -/

def digitsN : Nat → List Char → Option (Nat × List Char)
  | 0, cs => some (0, cs)
  | n + 1, c :: cs =>
    if c.isDigit then (digitsN n cs).map fun (v, r) => ((c.toNat - '0'.toNat) * 10 ^ n + v, r) else none
  | _ + 1, [] => none

def inRange (lo hi : Nat) : Option (Nat × List Char) → Option (List Char)
  | some (v, r) => if lo ≤ v && v ≤ hi then some r else none
  | none => none

def leapYear (y : Nat) : Bool := y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)

def monthDays (y m : Nat) : Nat :=
  if m == 2 then (if leapYear y then 29 else 28) else if m == 4 || m == 6 || m == 9 || m == 11 then 30 else 31

/-- `Z`, or an offset `±hh:mm` that `Date.parse` accepts (hh ≤ 23, mm ≤ 59). No zone is refused: a zone-less instant
    would be read in the host's local time. -/
def isoZone : List Char → Bool
  | ['Z'] => true
  | s :: cs => (s == '+' || s == '-') &&
      match inRange 0 23 (digitsN 2 cs) with
      | some (':' :: r) => inRange 0 59 (digitsN 2 r) == some []
      | _ => false
  | [] => false

/-- An optional fraction of 1 to 9 digits, then the zone. -/
def isoFraction : List Char → Bool
  | '.' :: cs =>
    let n := (cs.takeWhile Char.isDigit).length
    1 ≤ n && n ≤ 9 && isoZone (cs.drop n)
  | cs => isoZone cs

def isoTime : List Char → Bool
  | 'T' :: cs =>
    match inRange 0 23 (digitsN 2 cs) with
    | some (':' :: r) =>
      match inRange 0 59 (digitsN 2 r) with
      | some (':' :: r2) =>
        match inRange 0 59 (digitsN 2 r2) with
        | some r3 => isoFraction r3
        | none => false
      | _ => false
    | _ => false
  | _ => false

/-- `validInstant`. Years 0-99 are refused there too: `Date.UTC` maps them onto 1900-1999, so its calendar check fails. -/
def isoInstant (s : String) : Bool :=
  match digitsN 4 s.toList with
  | some (y, '-' :: m) =>
    match digitsN 2 m with
    | some (mo, '-' :: d) =>
      match digitsN 2 d with
      | some (day, r) => 100 ≤ y && 1 ≤ mo && mo ≤ 12 && 1 ≤ day && day ≤ monthDays y mo && isoTime r
      | none => false
    | _ => false
  | _ => false

/-! ## Numbers the conditions read: within ±(2^53 - 1) as a double

A decimal rounds to a double of magnitude 2^53 or more iff its magnitude is at least 2^53 - 1/2 (the tie goes to the
even 2^53), so the test is exact on any JSON text. -/

def Num.unsafe (n : Num) : Bool := (2 ^ 54 - 1) * 10 ^ n.exponent ≤ 2 * n.mantissa.natAbs

mutual
/-- `!hasUnsafeNumber(v)` in request.ts. -/
def Val.safeNums : Val → Bool
  | .num n => !n.unsafe
  | .arr xs => Val.safeNumsList xs
  | .obj kvs => Val.safeNumsObj kvs
  | _ => true

def Val.safeNumsList : List Val → Bool
  | [] => true
  | x :: xs => Val.safeNums x && Val.safeNumsList xs

def Val.safeNumsObj : List (String × Val) → Bool
  | [] => true
  | (_, x) :: xs => Val.safeNums x && Val.safeNumsObj xs
end

/-! ## Parsing = validation -/

def parseAssignment (v : Val) : Option RoleAssignment := do
  guard v.isObj
  let role ← (v.field? "role").bind isId?
  let notBefore ← optField v "notBefore" Val.asStr?
  let notAfter ← optField v "notAfter" Val.asStr?
  pure { role, notBefore, notAfter }

def parsePrincipal (v : Val) : Option Principal := do
  guard v.isObj
  let type ← (v.field? "type").bind isId?
  let id ← (v.field? "id").bind isId?
  let active ← match v.field? "active" with | some (.bool b) => some b | _ => none
  let roles ← (v.field? "roles").bind Val.asStrList?
  let assignments ← optField v "roleAssignments" fun | .arr xs => xs.mapM parseAssignment | _ => none
  let clearance ← (v.field? "clearance").bind isLevel?
  let compartments ← (v.field? "compartments").bind Val.asStrList?
  let integrity ← (v.field? "integrity").bind Integrity.parse?
  pure { type, id, active, roles, assignments := assignments.getD [], clearance, compartments, integrity, raw := v }

/-- `subjectErrors` from `depth` on, with the chain (`principals`): `none` on any error. `fuel` bounds the recursion
    (a chain longer than `maxDelegationDepth` is an error before the fuel runs out). -/
def parseChain : (fuel depth : Nat) → Val → Option (List Principal)
  | 0, _, _ => none
  | fuel + 1, depth, v => do
    let p ← parsePrincipal v
    -- an agent must carry the person it acts for (`!s.delegator`: absent or falsy)
    guard !(p.type == "agent" && !((v.field? "delegator").map Val.truthy).getD false)
    match v.field? "delegator" with
    | none => pure [p]
    | some dv => if depth ≥ maxDelegationDepth then none else (parseChain fuel (depth + 1) dv).map (p :: ·)

def parseResource (v : Val) : Option Resource := do
  guard v.isObj
  let type ← (v.field? "type").bind isId?
  let id ← (v.field? "id").bind isId?
  let level ← (v.field? "level").bind isLevel?
  let compartments ← (v.field? "compartments").bind Val.asStrList?
  let integrity ← (v.field? "integrity").bind Integrity.parse?
  let contentClasses ← (v.field? "contentClasses").bind Val.asStrList?
  let version ← match v.field? "version" with
    | none => some Val.null
    | some (.num n) => if n.isInt then some (Val.num n) else none
    | some _ => none
  pure { type, id, level, compartments, integrity, contentClasses, version, raw := v }

def parseCert (v : Val) : Option CertRecord := do
  guard v.isObj
  let resourceType ← (v.field? "resourceType").bind isId?
  let action ← (v.field? "action").bind isId?
  let by_ ← optField v "by" Val.asStrList?
  let _ ← optField v "fingerprint" Val.asStr?
  pure { resourceType, action, by_ := by_.getD [] }

def parseContext (v : Val) : Option Context := do
  guard v.isObj
  let trusted ← match v.field? "network" with
    | some (.str "trusted") => some true
    | some (.str "untrusted") => some false
    | _ => none
  guard ((v.field? "now").bind Val.asStr? |>.map isoInstant |>.getD false)
  let sessionLevel ← optField v "sessionLevel" isLevel?
  let sessionId ← optField v "sessionId" isId?
  let highWater ← optField v "highWater" isLevel?
  let sessionRequired ← optField v "sessionRequired" fun | .bool b => some b | _ => none
  let makerId ← optField v "makerId" isId?
  let serverMakerId ← optField v "serverMakerId" isId?
  let priorActions ← optField v "priorActions" Val.asStrList?
  let certified ← optField v "certified" fun | .arr xs => xs.mapM parseCert | _ => none
  let pepSubjectTypes ← optField v "pepSubjectTypes" Val.asStrList?
  let input ← optField v "input" fun x => if x.isObj then some x else none
  let sessionExpired ← optField v "sessionExpired" fun | .bool b => some b | _ => none
  let ip ← optField v "ip" Val.asStr?
  let country ← optField v "country" Val.asStr?
  let device ← optField v "device" fun d => do
    let managed ← match d.field? "managed" with | some (.bool b) => some b | _ => none
    let compliant ← match d.field? "compliant" with | some (.bool b) => some b | _ => none
    pure { managed, compliant : Device }
  let authTime ← optField v "authTime" Val.asStr?
  let mfaTime ← optField v "mfaTime" Val.asStr?
  let authMethods ← optField v "authMethods" Val.asStrList?
  let riskScore ← optField v "riskScore" fun
    | .num n => if n.isInt && 0 ≤ n.mantissa && n.mantissa ≤ 100 then some n.mantissa.toNat else none
    | _ => none
  pure { trusted, sessionLevel, sessionId, highWater, sessionRequired := sessionRequired.getD false,
         makerId, serverMakerId, priorActions := priorActions.getD [], certified := certified.getD [],
         pepSubjectTypes := pepSubjectTypes.getD [], input, sessionExpired := sessionExpired.getD false, ip, country,
         device, authTime, mfaTime, authMethods, riskScore, raw := v }

/-- `requestErrors(req).length === 0`, with the typed request. -/
def parseRequest (v : Val) : Option Req := do
  guard v.isObj
  let chain ← (v.field? "subject").bind (parseChain (maxDelegationDepth + 1) 0)
  let resource ← (v.field? "resource").bind parseResource
  let action ← (v.field? "action").bind isId?
  let context ← (v.field? "context").bind parseContext
  guard (["subject", "resource", "context"].all fun k => ((v.field? k).map Val.safeNums).getD true)
  pure { chain, action, resource, context }

end Qadamar
