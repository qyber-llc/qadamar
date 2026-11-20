import Qadamar.Request
import Qadamar.Policy
/-!
# The decision pipeline

Mirrors `packages/core/src/evaluate.ts` (and `mandatory.ts`, `procedures.ts`, `integrity.ts`): validation, declared
action, inactive principals, then for every principal of the delegation chain eligibility (RBAC, ABAC permit),
mandatory controls (BLP with session level and high-water mark, compartments, network cap, Biba), need-to-know, ABAC
forbid / obligation, ABAC on content attributes; then once CBAC (context-based, Zero Trust), Clark-Wilson and separation
of duty. Any deny wins. Every principal is evaluated with its live roles: its unconditional roles and the role
assignments live at `context.now` (`withLiveRoles`), in RBAC, ABAC conditions and the trusted-role exemption alike.

Parts are abstracted by an `Oracle`, and every theorem holds for every oracle:
* the ReBAC relation check of need-to-know (`check` in relations.ts: tuple graph, rewrites, grant windows, break-glass);
* whether a certification record's fingerprint is the current one (`procedureFingerprint`, a SHA-256 of the bundle);
* whether `context.now` lies in a role assignment's [notBefore, notAfter] window (instant arithmetic);
* the outcome of the CBAC requirements that need instant, CIDR or IANA time-zone arithmetic (`ipRanges`,
  `timeWindows`, `mfaMaxAgeSeconds`, `authMaxAgeSeconds`) when their signal is present; an absent signal is decided
  by the model (it denies);
* the grammar of the context signals and of the role-assignment instants (`contextSignalErrors`).

Each stage returns an `Out`: its denials, its allow basis, its obligations and its dry-run would-denies, in the order
the TypeScript run pushes them; the pipeline concatenates them, which keeps each list in the TypeScript order.
-/
namespace Qadamar

/-! ## Oracle -/

structure NtkResult where
  ok : Bool
  breakGlass : Bool
  deriving Repr, Inhabited

structure Oracle where
  /-- The relation check for principal `i` of the chain (0 = the subject). -/
  ntk : Nat → NtkResult
  /-- Some certification record of (type, action) carries the current procedure fingerprint. -/
  fingerprintCurrent : Bool
  /-- No context signal or role-assignment window is ill-formed (IP literal, ISO country, instants, method names). -/
  signalsValid : Bool
  /-- Principal `i`'s assignment is live at `context.now` (`windowState(a, now) === 'live'`). -/
  roleLive : Nat → RoleAssignment → Bool
  /-- The predicate of an abstracted requirement (by name) of context rule `j`, its signal being present. -/
  ctxOk : Nat → String → Bool

/-! ## Helpers -/

/-- `[...new Set(xs)]`: first occurrences, in order. -/
def dedup : List String → List String
  | [] => []
  | x :: xs => x :: (dedup xs).filter (· != x)

def union (a b : List String) : List String := dedup (a ++ b)

/-- `List.map` with the index, from `n`. -/
def mapI (f : Nat → α → β) : Nat → List α → List β
  | _, [] => []
  | i, a :: as => f i a :: mapI f (i + 1) as

theorem mem_mapI {f : Nat → α → β} {a : α} : ∀ {n : Nat} {as : List α}, a ∈ as → ∃ i, f i a ∈ mapI f n as
  | n, x :: xs, h => by
    cases h with
    | head => exact ⟨n, List.mem_cons_self⟩
    | tail _ h' =>
      obtain ⟨i, hi⟩ := mem_mapI (f := f) (n := n + 1) h'
      exact ⟨i, List.mem_cons_of_mem _ hi⟩

theorem mapI_zero_head {f : Nat → α → β} {a : α} {as : List α} : f 0 a ∈ mapI f 0 (a :: as) := List.mem_cons_self

structure Out where
  denies : List String := []
  basis : List String := []
  obls : List Obl := []
  wouldDeny : List String := []

def Out.append (a b : Out) : Out :=
  ⟨a.denies ++ b.denies, a.basis ++ b.basis, a.obls ++ b.obls, a.wouldDeny ++ b.wouldDeny⟩

def Out.cat : List Out → Out
  | [] => {}
  | o :: os => o.append (Out.cat os)

theorem Out.cat_denies : ∀ os : List Out, (Out.cat os).denies = (os.map Out.denies).flatten
  | [] => rfl
  | o :: os => by simp [Out.cat, Out.append, Out.cat_denies os]

theorem Out.cat_obls : ∀ os : List Out, (Out.cat os).obls = (os.map Out.obls).flatten
  | [] => rfl
  | o :: os => by simp [Out.cat, Out.append, Out.cat_obls os]

/-- A denial anywhere in a concatenation is a denial of the whole. -/
theorem Out.cat_denies_ne_nil {os : List Out} {o : Out} (ho : o ∈ os) (h : o.denies ≠ []) :
    (Out.cat os).denies ≠ [] := by
  rw [Out.cat_denies]
  intro hnil
  rw [List.flatten_eq_nil_iff] at hnil
  exact h (hnil _ (List.mem_map_of_mem ho))

/-! ## Live roles (CBAC grant duration) -/

/-- `liveRoles`: the unconditional roles, then the assignments live now, first occurrences kept. -/
def liveRolesOf (o : Oracle) (i : Nat) (p : Principal) : List String :=
  dedup (p.roles ++ (p.assignments.filter (o.roleLive i)).map (·.role))

def setField (v : Val) (k : String) (x : Val) : Val :=
  match v with
  | .obj kvs => .obj (kvs.map fun kv => if kv.1 == k then (kv.1, x) else kv)
  | v => v

/-- `withLiveRoles` on the chain from principal `i`: each principal and its JSON (conditions read `subject.roles`, and
    a delegator through `subject.delegator`) carry its live roles. -/
def liveChain (o : Oracle) : Nat → List Principal → List Principal
  | _, [] => []
  | i, p :: ps =>
    let rest := liveChain o (i + 1) ps
    let rs := liveRolesOf o i p
    let raw := setField p.raw "roles" (.arr (rs.map .str))
    { p with roles := rs, raw := match rest with | q :: _ => setField raw "delegator" q.raw | [] => raw } :: rest

/-- The request the pipeline decides: valid (`requestErrors` empty), with live roles. -/
def prepare (v : Val) (o : Oracle) : Option Req := do
  let req ← parseRequest v
  guard o.signalsValid
  pure { req with chain := liveChain o 0 req.chain }

/-! ## RBAC -/

def hasRole (b : Bundle) (r : String) : Bool := (lookup r b.roles).isSome
def inheritsOf (b : Bundle) (r : String) : List String := ((lookup r b.roles).map (·.inherits)).getD []

def closure (b : Bundle) : Nat → List String → List String → List String
  | 0, _, seen => seen
  | _, [], seen => seen
  | f + 1, r :: rest, seen =>
    if seen.contains r || !hasRole b r then closure b f rest seen else closure b f (inheritsOf b r ++ rest) (r :: seen)

/-- Roles with their inherited roles, cycle-safe, sorted as `Array.prototype.sort` does (`expandRoles`). -/
def expandRoles (b : Bundle) (roles : List String) : List String :=
  (closure b (roles.length + (b.roles.map (·.2.inherits.length)).sum + 1) roles []).mergeSort utf16Le

def roleGrants (b : Bundle) (role type action : String) : Bool :=
  match lookup role b.roles with
  | some r => r.grants.any fun g =>
      (g.resourceType == type || g.resourceType == "*") && (g.actions.contains action || g.actions.contains "*")
  | none => false

def rbacGrant (b : Bundle) (p : Principal) (type action : String) : Option String :=
  (expandRoles b p.roles).find? (roleGrants b · type action)

def actionDef (b : Bundle) (type action : String) : Option ActionDef :=
  (lookup type b.resourceTypes).bind fun t => lookup action t.actions

def appliesTo (types actions : Option (List String)) (type action : String) : Bool :=
  (types.map (·.contains type)).getD true && (actions.map (·.contains action)).getD true

/-! ## Mandatory controls (mandatory.ts) -/

/-- The level the caller asks to work at: its clearance, or a lower session level it chose. -/
def requestedLevel (p : Principal) (c : Context) : Nat := min (c.sessionLevel.getD p.clearance) p.clearance
/-- The working level: raised by the session's high-water mark, never above the clearance. -/
def sessionOf (p : Principal) (c : Context) : Nat := min (max (requestedLevel p c) (c.highWater.getD 0)) p.clearance
/-- The lowest level a write may target: the requested level, raised by what the session already read. -/
def writeFloor (p : Principal) (c : Context) : Nat := max (requestedLevel p c) (c.highWater.getD 0)
def sessionMissing (p : Principal) (c : Context) (k : Kind) (level : Nat) : Bool :=
  c.sessionRequired && c.sessionId.isNone && (if k.isWrite then decide (p.clearance > 0) else decide (level > 0))
def trustedSubject (m : Mandatory) (p : Principal) : Bool := p.roles.any (m.trustedRoles.contains ·)

def blpRead (p : Principal) (r : Resource) (c : Context) : List String :=
  if sessionOf p c < r.level then ["BLP.NO_READ_UP"] else []
def compartments (p : Principal) (r : Resource) : List String :=
  if r.compartments.any (fun x => !p.compartments.contains x) then ["MAC.COMPARTMENT"] else []
def network (m : Mandatory) (r : Resource) (c : Context) : List String :=
  if c.trusted then [] else
    (if m.untrustedNetworkMaxLevel < r.level then ["NET.UNTRUSTED_LEVEL"] else []) ++
    (if m.compartmentsRequireTrustedNetwork && !r.compartments.isEmpty then ["NET.UNTRUSTED_COMPARTMENT"] else [])
def sessionRule (p : Principal) (r : Resource) (k : Kind) (c : Context) : List String :=
  if sessionMissing p c k r.level then ["BLP.SESSION_REQUIRED"] else []
def blpWrite (m : Mandatory) (p : Principal) (r : Resource) (c : Context) : List String :=
  if r.level < requestedLevel p c && !trustedSubject m p then ["BLP.NO_WRITE_DOWN"]
  else if r.level < writeFloor p c && !trustedSubject m p then ["BLP.HIGH_WATER"] else []
def bibaWrite (p : Principal) (r : Resource) : List String :=
  if p.integrity.rank < r.integrity.rank then ["BIBA.NO_WRITE_UP"] else []
def bibaNoReadDownRequired (m : Mandatory) (action : String) (k : Kind) : Bool :=
  match m.bibaNoReadDownScope with
  | .actions => m.bibaNoReadDownActions.contains action
  | .reads => k == .read
  | .all => true

def bibaRead (m : Mandatory) (p : Principal) (r : Resource) (action : String) (k : Kind) : List String :=
  if bibaNoReadDownRequired m action k && r.integrity.rank < p.integrity.rank then ["BIBA.NO_READ_DOWN"] else []

/-- `mandatoryFindings`: a function of the mandatory section of the bundle and the request only. -/
def mandatoryFindings (m : Mandatory) (p : Principal) (r : Resource) (action : String) (k : Kind) (c : Context) :
    List String :=
  blpRead p r c ++ compartments p r ++ network m r c ++ sessionRule p r k c ++
  (if k.isWrite then blpWrite m p r c ++ bibaWrite p r else []) ++ bibaRead m p r action k

/-! ## Stages -/

def prefixOf (i : Nat) : String := if i == 0 then "" else "DELEGATION."

/-- The condition environment of one principal: `{ subject, resource, action: { name, kind }, context }`. -/
def envOf (req : Req) (d : ActionDef) (p : Principal) : Val :=
  .obj [("action", .obj [("kind", .str d.kind.name), ("name", .str req.action)]), ("context", req.context.raw),
        ("resource", req.resource.raw), ("subject", p.raw)]

/-- The permit that grants eligibility: the first applicable one whose condition is TRUE. -/
def grantingPermit (b : Bundle) (req : Req) (env : Val) : Option AbacRule :=
  b.abac.find? fun r => r.effect == .permit && appliesTo r.resourceTypes r.actions req.resource.type req.action &&
    evalExpr env r.when

def eligibility (b : Bundle) (req : Req) (env : Val) (p : Principal) (pre : String) : Out :=
  match rbacGrant b p req.resource.type req.action with
  | some role => { basis := [pre ++ "RBAC." ++ role] }
  | none =>
    match grantingPermit b req env with
    | some r => { basis := [pre ++ "ABAC." ++ r.id] }
    | none => { denies := [pre ++ "RBAC.NOT_ELIGIBLE"] }

def mandatoryStage (b : Bundle) (req : Req) (d : ActionDef) (i : Nat) (p : Principal) : Out :=
  { denies := (mandatoryFindings b.mandatory p req.resource req.action d.kind req.context).map (prefixOf i ++ ·) }

def needToKnow (b : Bundle) (req : Req) (o : Oracle) (i : Nat) : Out :=
  let nk := b.needToKnow
  let pre := prefixOf i
  match lookup req.resource.type nk.protect with
  | none => {}
  | some pr =>
    if nk.mode == .off || req.resource.level < pr.minLevel then {} else
    let r := o.ntk i
    if r.ok then
      { basis := [pre ++ "NTK." ++ pr.relation],
        obls := if r.breakGlass then [{ notify := nk.breakGlassNotify }] else [] }
    else if nk.mode == .dryRun then { wouldDeny := [pre ++ "NTK.NO_REASON"] }
    else { denies := [pre ++ "NTK.NO_REASON"] }

/-- One ABAC rule in the forbid / obligation pass: it fires on TRUE or UNKNOWN (`mayHold`). -/
def abacRule (env : Val) (type action pre : String) (r : AbacRule) : Out :=
  if r.effect == .permit || !appliesTo r.resourceTypes r.actions type action || !mayHold env r.when then {}
  else if r.effect == .forbid then { denies := [pre ++ "ABAC." ++ r.id] }
  else { obls := [r.obligations] }

def abacStage (b : Bundle) (req : Req) (env : Val) (pre : String) : Out :=
  Out.cat (b.abac.map (abacRule env req.resource.type req.action pre))

/-- One rule of ABAC on content attributes; its code names the effect, the rule id goes to the trace. -/
def contentRule (req : Req) (env : Val) (pre : String) (r : ContentRule) : Out :=
  if !req.resource.contentClasses.contains r.contentClass || !((r.actions.map (·.contains req.action)).getD true) then {}
  else if (r.unless.map (evalExpr env)).getD false then {} -- an exemption must hold for certain
  else match r.effect with
    | .deny => { denies := [pre ++ "ABAC.CONTENT_DENY"] }
    | .mask => { obls := [{ maskClasses := [r.contentClass] }] }
    | .redact => { obls := [{ redact := r.fields }] }

def contentStage (b : Bundle) (req : Req) (env : Val) (pre : String) : Out :=
  Out.cat (b.content.map (contentRule req env pre))

/-! ## CBAC: context-based, Zero Trust (context.ts) -/

/-- `contextRuleApplies`: the selector, the minimum level and the content classes (any overlap). -/
def contextApplies (r : ContextRule) (req : Req) (k : Kind) : Bool :=
  (r.resourceTypes.map (·.contains req.resource.type)).getD true && (r.actions.map (·.contains req.action)).getD true &&
  (r.actionKinds.map (·.contains k)).getD true && (r.minResourceLevel.map fun l => decide (l ≤ req.resource.level)).getD true &&
  (r.contentClasses.map fun cs => cs.any (req.resource.contentClasses.contains ·)).getD true

/-- One requirement: TRUE passes; otherwise an absent signal is `CBAC.SIGNAL_MISSING`, a present one its own code. -/
def judge (code : String) (present ok : Bool) : List String :=
  if ok then [] else if present then [code] else ["CBAC.SIGNAL_MISSING"]

/-- `contextChecks`, in its order: the codes of the requirements of rule `j` that are not TRUE. -/
def contextRuleChecks (o : Oracle) (j : Nat) (r : ContextRule) (c : Context) : List String :=
  (if r.network then judge "CBAC.NETWORK" true c.trusted else []) ++
  (match r.countries with
   | some cs => judge "CBAC.COUNTRY" c.country.isSome ((c.country.map cs.contains).getD false)
   | none => []) ++
  (if r.ipRanges then judge "CBAC.IP_RANGE" c.ip.isSome (c.ip.isSome && o.ctxOk j "ipRanges") else []) ++
  (if r.timeWindows then judge "CBAC.TIME_WINDOW" true (o.ctxOk j "timeWindows") else []) ++
  (match r.deviceManaged with
   | some m => judge "CBAC.DEVICE_UNMANAGED" c.device.isSome ((c.device.map (·.managed == m)).getD false)
   | none => []) ++
  (match r.deviceCompliant with
   | some m => judge "CBAC.DEVICE_NONCOMPLIANT" c.device.isSome ((c.device.map (·.compliant == m)).getD false)
   | none => []) ++
  (if r.mfaMaxAge then judge "CBAC.MFA_STALE" c.mfaTime.isSome (c.mfaTime.isSome && o.ctxOk j "mfaMaxAgeSeconds") else []) ++
  (if r.authMaxAge then judge "CBAC.AUTH_STALE" c.authTime.isSome (c.authTime.isSome && o.ctxOk j "authMaxAgeSeconds") else []) ++
  (match r.authMethodsAny with
   | some ms => judge "CBAC.AUTH_METHOD" c.authMethods.isSome ((c.authMethods.map fun xs => ms.any (xs.contains ·)).getD false)
   | none => []) ++
  (match r.maxRiskScore with
   | some m => judge "CBAC.RISK" c.riskScore.isSome ((c.riskScore.map fun x => decide (x ≤ m)).getD false)
   | none => [])

/-- `situational`: a known-expired session, then every matched rule; request-level, so once for the whole chain. -/
def contextStage (b : Bundle) (req : Req) (d : ActionDef) (o : Oracle) : Out :=
  { denies := (if req.context.sessionExpired then ["CBAC.SESSION_EXPIRED"] else []) ++
      (mapI (fun j r => if contextApplies r req d.kind then contextRuleChecks o j r req.context else []) 0 b.context).flatten }

/-! ## Clark-Wilson and separation of duty -/

def ivpsFor (b : Bundle) (type : String) : List Ivp := b.clarkWilson.ivps.filter (·.resourceTypes.contains type)
def validatorsFor (b : Bundle) (type action : String) : List Validator :=
  b.clarkWilson.inputValidators.filter fun v => v.resourceTypes.contains type && v.actions.contains action
def postStateRequired (b : Bundle) (type action : String) (constrained : Bool) : Bool :=
  (constrained && !(ivpsFor b type).isEmpty) || !(validatorsFor b type action).isEmpty

def fieldOk (r : FieldRule) (v : Val) : Bool :=
  let typed := match r.type, v with
    | .string, .str _ => true
    | .boolean, .bool _ => true
    | .number, .num _ => true
    | .integer, .num n => n.isInt
    | _, _ => false
  typed && (r.enum.map (·.any (Val.beq · v))).getD true &&
  (match v with
   | .num n => (r.min.map (Num.cmp n · != .lt)).getD true && (r.max.map (Num.cmp n · != .gt)).getD true
   | .str s => (r.maxLength.map fun m => decide (s.length ≤ m)).getD true
   | _ => true)

def failedValidators (vs : List Validator) (input : Val) : List String :=
  match input with
  | .obj kvs => (vs.filter fun v => kvs.any (fun kv => (lookup kv.1 v.fields).isNone) ||
      v.fields.any fun f => match lookup f.1 kvs with
        | some x => !fieldOk f.2 x
        | none => f.2.required).map (·.id)
  | _ => vs.map (·.id)

def procedureFindings (b : Bundle) (req : Req) : List String :=
  let type := req.resource.type
  let c := req.context
  let vs := validatorsFor b type req.action
  (if vs.isEmpty then [] else match c.input with
    | none => ["CW.INPUT_REQUIRED"]
    | some i => (failedValidators vs i).map ("CW.INPUT." ++ ·)) ++
  (if b.clarkWilson.requirePepBinding.contains type &&
      !((req.chain.head?.map fun s => c.pepSubjectTypes.contains s.type).getD false)
    then ["CW.SUBJECT_NOT_AUTHENTICATED"] else []) ++
  (let certifiers := (c.certified.filter fun x => x.resourceType == type && x.action == req.action).flatMap (·.by_)
   if req.chain.any (certifiers.contains ·.id) then ["CW.CERTIFIER_EXECUTES"] else [])

def certificationGap (b : Bundle) (req : Req) (o : Oracle) : List String :=
  if !b.clarkWilson.requireCertification.contains req.resource.type then []
  else if !req.context.certified.any (fun x => x.resourceType == req.resource.type && x.action == req.action)
    then ["CW.NOT_CERTIFIED"]
  else if o.fingerprintCurrent then [] else ["CW.CERTIFICATION_STALE"]

def ivpEnv (r : Resource) : Val :=
  .obj [("action", .null), ("context", .null), ("resource", r.raw), ("subject", .null)]

def cwSod (b : Bundle) (req : Req) (d : ActionDef) (o : Oracle) : Out :=
  let type := req.resource.type
  let c := req.context
  let constrained := ((lookup type b.resourceTypes).map (·.constrained)).getD false
  let tok : Token := ⟨b.clarkWilson.tokenTtlSeconds, req.resource.version,
    postStateRequired b type req.action constrained⟩
  let token : Obl := { decisionToken := some tok }
  Out.cat [
    if constrained && d.kind.isWrite && !d.certified then { denies := ["CW.UNCERTIFIED_TP"] } else {},
    if d.certified then { obls := [token], denies := procedureFindings b req } else {},
    if constrained && d.certified then
      { denies := (certificationGap b req o ++
          ((ivpsFor b type).filter (fun i => !evalExpr (ivpEnv req.resource) i.check)).map ("CW.IVP." ++ ·.id)) }
    else {},
    if (match c.serverMakerId, c.makerId with | some s, some m => s != m | _, _ => false)
      then { denies := ["SOD.MAKER_MISMATCH"] } else {},
    if d.requiresSecondPerson then
      match c.serverMakerId <|> c.makerId with
      | none => { denies := ["SOD.MAKER_UNKNOWN"] }
      | some m => if req.chain.any (·.id == m) then { denies := ["SOD.SELF_APPROVAL"] } else {}
    else {},
    { denies := ((b.sod.filter fun r => r.conflicting.contains req.action &&
        c.priorActions.any fun a => a != req.action && r.conflicting.contains a).map ("SOD." ++ ·.id)) }]

/-! ## The pipeline and the decision -/

def pipelineOut (b : Bundle) (req : Req) (d : ActionDef) (o : Oracle) : Out :=
  Out.cat [
    Out.cat (mapI (fun i p => eligibility b req (envOf req d p) p (prefixOf i)) 0 req.chain),
    Out.cat (mapI (mandatoryStage b req d) 0 req.chain),
    Out.cat (mapI (fun i _ => needToKnow b req o i) 0 req.chain),
    Out.cat (mapI (fun i p => abacStage b req (envOf req d p) (prefixOf i)) 0 req.chain),
    Out.cat (mapI (fun i p => contentStage b req (envOf req d p) (prefixOf i)) 0 req.chain),
    contextStage b req d o,
    cwSod b req d o]

def mergeObl (a b : Obl) : Obl :=
  { fieldAllowlist := match b.fieldAllowlist, a.fieldAllowlist with
      | none, x => x
      | some y, none => some y
      | some y, some x => some (x.filter y.contains),
    redact := union a.redact b.redact,
    maskClasses := union a.maskClasses b.maskClasses,
    notify := union a.notify b.notify,
    decisionToken := b.decisionToken <|> a.decisionToken }

structure Decision where
  decision : Bool
  /-- Denying rule ids (deny), or the eligibility and reason-to-know basis (allow). -/
  rules : List String
  obligations : Obl
  wouldDeny : List String

def denyWith (rules : List String) : Decision :=
  { decision := false, rules, obligations := {}, wouldDeny := [] }

def finish (out : Out) : Decision :=
  if out.denies.isEmpty then
    { decision := true, rules := dedup out.basis, obligations := out.obls.foldl mergeObl {}, wouldDeny := out.wouldDeny }
  else
    -- a denied request carries no obligations: nothing is released
    { decision := false, rules := dedup out.denies, obligations := {}, wouldDeny := out.wouldDeny }

def firstInactive (chain : List Principal) : Option Nat := chain.findIdx? (!·.active)

/-- `evaluate` in evaluate.ts, on the request as JSON. -/
def evaluate (b : Bundle) (v : Val) (o : Oracle) : Decision :=
  match prepare v o with
  | none => denyWith ["ENGINE.MALFORMED_REQUEST"]
  | some req =>
    match actionDef b req.resource.type req.action with
    | none => denyWith ["SCHEMA.UNKNOWN_ACTION"]
    | some d =>
      match firstInactive req.chain with
      | some 0 => denyWith ["CORE.INACTIVE"]
      | some _ => denyWith ["DELEGATION.INACTIVE"]
      | none => finish (pipelineOut b req d o)

end Qadamar
