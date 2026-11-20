/-!
# JSON values, as the TypeScript engine sees them after `JSON.parse`

Mirrors `packages/core/src/conditions.ts` (values, `canonical` equality, code-point string order) and the parts of
JavaScript the engine relies on (UTF-16 lengths, array own properties).

Numbers are exact decimals `mantissa * 10^-exponent`, normalised so that structural equality is numeric equality.
JavaScript holds IEEE doubles: the two agree on every number whose shortest decimal form is what the JSON carries
(what `JSON.stringify` emits), which is how the differential test transports them.
-/
namespace Qadamar

/-- An exact decimal, normalised: no trailing zero in the mantissa while the exponent is positive. -/
structure Num where
  mantissa : Int
  exponent : Nat
  deriving DecidableEq, Repr, Inhabited

def Num.norm : Int → Nat → Num
  | m, 0 => ⟨m, 0⟩
  | m, e + 1 => if m % 10 == 0 then Num.norm (m / 10) e else ⟨m, e + 1⟩

def Num.ofNat (n : Nat) : Num := ⟨n, 0⟩

/-- Numeric order, exact. -/
def Num.cmp (a b : Num) : Ordering :=
  compare (a.mantissa * 10 ^ b.exponent) (b.mantissa * 10 ^ a.exponent)

def Num.isInt (n : Num) : Bool := n.exponent == 0

/-- A JSON value. Object keys are unique and sorted (canonical form), so structural equality is JSON equality. -/
inductive Val where
  | null
  | bool (b : Bool)
  | num (n : Num)
  | str (s : String)
  | arr (xs : List Val)
  | obj (kvs : List (String × Val))
  deriving Repr, Inhabited

mutual
/-- `canonical(a) === canonical(b)` in conditions.ts: structural JSON equality. -/
def Val.beq : Val → Val → Bool
  | .null, .null => true
  | .bool a, .bool b => a == b
  | .num a, .num b => a == b
  | .str a, .str b => a == b
  | .arr xs, .arr ys => Val.beqList xs ys
  | .obj xs, .obj ys => Val.beqObj xs ys
  | _, _ => false

def Val.beqList : List Val → List Val → Bool
  | [], [] => true
  | x :: xs, y :: ys => Val.beq x y && Val.beqList xs ys
  | _, _ => false

def Val.beqObj : List (String × Val) → List (String × Val) → Bool
  | [], [] => true
  | (k, x) :: xs, (k', y) :: ys => k == k' && Val.beq x y && Val.beqObj xs ys
  | _, _ => false
end

/-- JavaScript `String.prototype.length`: UTF-16 code units. -/
def utf16Length (s : String) : Nat :=
  s.foldl (fun n c => n + if c.val.toNat > 0xFFFF then 2 else 1) 0

/-- The UTF-16 code units of a character. -/
def utf16Units (c : Char) : List Nat :=
  let v := c.val.toNat
  if v > 0xFFFF then [0xD800 + (v - 0x10000) / 0x400, 0xDC00 + (v - 0x10000) % 0x400] else [v]

def lexNat : List Nat → List Nat → Ordering
  | [], [] => .eq
  | [], _ :: _ => .lt
  | _ :: _, [] => .gt
  | x :: xs, y :: ys => if x < y then .lt else if y < x then .gt else lexNat xs ys

/-- Unicode code-point order (conditions.ts `codePointCompare`, PostgreSQL `COLLATE "C"`). -/
def cpCompare (a b : String) : Ordering :=
  lexNat (a.toList.map (·.val.toNat)) (b.toList.map (·.val.toNat))

/-- JavaScript's default `Array.prototype.sort` order on strings: UTF-16 code units. -/
def utf16Le (a b : String) : Bool :=
  lexNat (a.toList.flatMap utf16Units) (b.toList.flatMap utf16Units) != .gt

/-- `needle` occurs in the haystack (`a.includes(b)`; for well-formed strings the same in code points as in UTF-16). -/
def listInfix (needle : List Char) : List Char → Bool
  | [] => needle.isEmpty
  | h :: t => needle.isPrefixOf (h :: t) || listInfix needle t

def strIncludes (a b : String) : Bool := listInfix b.toList a.toList

/-- A canonical array index property name ("0", "1", ...; not "01"). -/
def arrayIndex (k : String) : Option Nat :=
  let cs := k.toList
  if cs.isEmpty || !cs.all Char.isDigit || (cs.length > 1 && cs.head? == some '0') then none else some k.toNat!

/-- An own property of a non-null object (arrays included: their indices and `length`), as `Object.hasOwn`. -/
def Val.getField : Val → String → Option Val
  | .obj kvs, k => (kvs.find? (·.1 == k)).map (·.2)
  | .arr xs, k => if k == "length" then some (.num (Num.ofNat xs.length)) else (arrayIndex k).bind (xs[·]?)
  | _, _ => none

/-- An own property of a JSON object (a record, never an array): request fields and bundle sections. -/
def Val.field? : Val → String → Option Val
  | .obj kvs, k => (kvs.find? (·.1 == k)).map (·.2)
  | _, _ => none

def Val.has (v : Val) (k : String) : Bool := (v.field? k).isSome

def Val.isObj : Val → Bool
  | .obj _ => true
  | _ => false

def Val.asStr? : Val → Option String
  | .str s => some s
  | _ => none

def Val.asStrList? : Val → Option (List String)
  | .arr xs => xs.mapM Val.asStr?
  | _ => none

/-- JavaScript truthiness of a JSON value. -/
def Val.truthy : Val → Bool
  | .null => false
  | .bool b => b
  | .num n => n.mantissa != 0
  | .str s => !s.isEmpty
  | _ => true

end Qadamar
