import Qadamar.Eval
/-!
# Mechanised properties of the decision model

Every theorem quantifies over all bundles, requests and oracles (so over every outcome of the relation check), and
uses no axiom beyond Lean's standard ones (`propext`, `Classical.choice`, `Quot.sound`); `CheckAxioms.lean` prints
them and the CI fails on anything else, `sorryAx` included.
-/
namespace Qadamar

/-! ## Shape of a decision -/

theorem finish_decision (out : Out) : (finish out).decision = out.denies.isEmpty := by
  unfold finish; split <;> simp_all

theorem finish_obligations (out : Out) (h : (finish out).decision = false) : (finish out).obligations = {} := by
  unfold finish at *; split <;> simp_all

/-- Every evaluation ends in an early denial or in `finish` of the pipeline. -/
theorem evaluate_shape (b : Bundle) (v : Val) (o : Oracle) :
    (∃ rs, evaluate b v o = denyWith rs) ∨ (∃ out, evaluate b v o = finish out) := by
  unfold evaluate
  split
  · exact .inl ⟨_, rfl⟩
  · split
    · exact .inl ⟨_, rfl⟩
    · split
      · exact .inl ⟨_, rfl⟩
      · exact .inl ⟨_, rfl⟩
      · exact .inr ⟨_, rfl⟩

/-- An allow comes only from a valid request, a declared action, an active chain and a pipeline without denials. -/
theorem allow_inv {b : Bundle} {v : Val} {o : Oracle} (h : (evaluate b v o).decision = true) :
    ∃ req d, prepare v o = some req ∧ actionDef b req.resource.type req.action = some d ∧
      firstInactive req.chain = none ∧ (pipelineOut b req d o).denies = [] := by
  unfold evaluate at h
  split at h
  · simp [denyWith] at h
  · rename_i req hr
    split at h
    · simp [denyWith] at h
    · rename_i d hd
      split at h
      · simp [denyWith] at h
      · simp [denyWith] at h
      · rename_i hi
        rw [finish_decision] at h
        exact ⟨req, d, hr, hd, hi, by simpa using h⟩

/-! ## Determinism -/

/-- The decision is a function of the bundle, the request and the relation oracle: equal inputs, equal decisions. -/
theorem deterministic {b b' : Bundle} {v v' : Val} {o o' : Oracle} (hb : b = b') (hv : v = v') (ho : o = o') :
    evaluate b v o = evaluate b' v' o' := by
  subst hb hv ho; rfl

/-! ## Malformed requests deny -/

theorem malformed_denies (b : Bundle) (o : Oracle) {v : Val} (h : parseRequest v = none) :
    evaluate b v o = denyWith ["ENGINE.MALFORMED_REQUEST"] := by
  simp [evaluate, prepare, h]

/-- An ill-formed context signal or role-assignment window makes the request malformed: deny. -/
theorem malformed_signals_deny (b : Bundle) {o : Oracle} (v : Val) (h : o.signalsValid = false) :
    evaluate b v o = denyWith ["ENGINE.MALFORMED_REQUEST"] := by
  have : prepare v o = none := by
    unfold prepare
    cases parseRequest v <;> simp [h, guard, failure]
  simp [evaluate, this]

theorem malformed_decision (b : Bundle) (o : Oracle) {v : Val} (h : parseRequest v = none) :
    (evaluate b v o).decision = false := by
  rw [malformed_denies b o h]; rfl

theorem undeclared_action_denies {b : Bundle} {o : Oracle} {v : Val} {req : Req} (hr : prepare v o = some req)
    (h : actionDef b req.resource.type req.action = none) : evaluate b v o = denyWith ["SCHEMA.UNKNOWN_ACTION"] := by
  simp [evaluate, hr, h]

/-! ## Deny wins -/

/-- Any denial of any stage, for any principal, denies the request, whatever grants or permits also hold. -/
theorem deny_wins {b : Bundle} {v : Val} {o : Oracle} {req : Req} {d : ActionDef}
    (hr : prepare v o = some req) (hd : actionDef b req.resource.type req.action = some d)
    (h : (pipelineOut b req d o).denies ≠ []) : (evaluate b v o).decision = false := by
  cases hdec : (evaluate b v o).decision
  · rfl
  · obtain ⟨req', d', hr', hd', _, hn⟩ := allow_inv hdec
    rw [hr] at hr'
    cases hr'
    rw [hd] at hd'
    cases hd'
    exact absurd hn h

/-- A stage of the pipeline that denies, denies the request. -/
theorem stage_denies {b : Bundle} {v : Val} {o : Oracle} {req : Req} {d : ActionDef} {s : Out}
    (hr : prepare v o = some req) (hd : actionDef b req.resource.type req.action = some d)
    (hs : s ∈ [Out.cat (mapI (fun i p => eligibility b req (envOf req d p) p (prefixOf i)) 0 req.chain),
               Out.cat (mapI (mandatoryStage b req d) 0 req.chain),
               Out.cat (mapI (fun i _ => needToKnow b req o i) 0 req.chain),
               Out.cat (mapI (fun i p => abacStage b req (envOf req d p) (prefixOf i)) 0 req.chain),
               Out.cat (mapI (fun i p => contentStage b req (envOf req d p) (prefixOf i)) 0 req.chain),
               contextStage b req d o,
               cwSod b req d o])
    (h : s.denies ≠ []) : (evaluate b v o).decision = false :=
  deny_wins hr hd (Out.cat_denies_ne_nil hs h)

/-- A forbid that applies and whose condition is TRUE or UNKNOWN for any principal of the chain denies. -/
theorem forbid_denies {b : Bundle} {v : Val} {o : Oracle} {req : Req} {d : ActionDef} {p : Principal} {r : AbacRule}
    (hr : prepare v o = some req) (hd : actionDef b req.resource.type req.action = some d)
    (hp : p ∈ req.chain) (hrule : r ∈ b.abac) (heff : r.effect = .forbid)
    (happ : appliesTo r.resourceTypes r.actions req.resource.type req.action = true)
    (hmay : mayHold (envOf req d p) r.when = true) : (evaluate b v o).decision = false := by
  obtain ⟨i, hi⟩ := mem_mapI (f := fun i p => abacStage b req (envOf req d p) (prefixOf i)) (n := 0) hp
  refine stage_denies hr hd (s := Out.cat (mapI (fun i p => abacStage b req (envOf req d p) (prefixOf i)) 0 req.chain))
    (by simp) (Out.cat_denies_ne_nil hi ?_)
  refine Out.cat_denies_ne_nil (o := abacRule (envOf req d p) req.resource.type req.action (prefixOf i) r)
    (List.mem_map_of_mem hrule) ?_
  simp [abacRule, heff, happ, hmay]

/-- Deny wins over permits: adding any permit rules and replacing every role leaves a firing forbid a denial. -/
theorem forbid_denies_whatever_permits {b : Bundle} {v : Val} {o : Oracle} {req : Req} {d : ActionDef}
    {p : Principal} {r : AbacRule} (permits : List AbacRule) (roles : List (String × Role))
    (hr : prepare v o = some req) (hd : actionDef b req.resource.type req.action = some d)
    (hp : p ∈ req.chain) (hrule : r ∈ b.abac) (heff : r.effect = .forbid)
    (happ : appliesTo r.resourceTypes r.actions req.resource.type req.action = true)
    (hmay : mayHold (envOf req d p) r.when = true) :
    (evaluate { b with abac := b.abac ++ permits, roles := roles } v o).decision = false :=
  forbid_denies (b := { b with abac := b.abac ++ permits, roles := roles }) hr hd hp
    (List.mem_append_left _ hrule) heff happ hmay

/-- An ABAC content-attribute deny applies unless its exemption is TRUE: an exemption that is FALSE or UNKNOWN does not
    lift it. -/
theorem abac_content_deny_denies {b : Bundle} {v : Val} {o : Oracle} {req : Req} {d : ActionDef} {p : Principal}
    {r : ContentRule} (hr : prepare v o = some req) (hd : actionDef b req.resource.type req.action = some d)
    (hp : p ∈ req.chain) (hrule : r ∈ b.content) (heff : r.effect = .deny)
    (hclass : req.resource.contentClasses.contains r.contentClass = true)
    (hact : (r.actions.map (·.contains req.action)).getD true = true)
    (hexempt : (r.unless.map (evalExpr (envOf req d p))).getD false = false) : (evaluate b v o).decision = false := by
  obtain ⟨i, hi⟩ := mem_mapI (f := fun i p => contentStage b req (envOf req d p) (prefixOf i)) (n := 0) hp
  refine stage_denies hr hd (s := Out.cat (mapI (fun i p => contentStage b req (envOf req d p) (prefixOf i)) 0 req.chain))
    (by simp) (Out.cat_denies_ne_nil hi ?_)
  refine Out.cat_denies_ne_nil (o := contentRule req (envOf req d p) (prefixOf i) r) (List.mem_map_of_mem hrule) ?_
  simp only [contentRule, hclass, hact, hexempt, heff, Bool.not_true, Bool.or_self, Bool.false_eq_true, ↓reduceIte]
  simp

/-! ## CBAC: context-based, Zero Trust -/

theorem mapI_getElem {f : Nat → α → β} : ∀ {n : Nat} {as : List α} {j : Nat} {a : α},
    as[j]? = some a → f (n + j) a ∈ mapI f n as
  | _, [], _, _, h => by simp at h
  | n, x :: xs, 0, a, h => by
    simp only [List.getElem?_cons_zero, Option.some.injEq] at h
    subst h
    exact List.mem_cons_self
  | n, x :: xs, j + 1, a, h => by
    have hm := mapI_getElem (f := f) (n := n + 1) (as := xs) (j := j) (by simpa using h)
    rw [show n + (j + 1) = n + 1 + j by omega]
    exact List.mem_cons_of_mem _ hm

/-- A matched context rule with an unsatisfied requirement makes the CBAC stage deny. -/
theorem context_stage_denies {b : Bundle} {req : Req} {d : ActionDef} {o : Oracle} {j : Nat} {r : ContextRule}
    (hj : b.context[j]? = some r) (happ : contextApplies r req d.kind = true)
    (hc : contextRuleChecks o j r req.context ≠ []) : (contextStage b req d o).denies ≠ [] := by
  have hm := mapI_getElem
    (f := fun j r => if contextApplies r req d.kind then contextRuleChecks o j r req.context else []) (n := 0) hj
  simp only [Nat.zero_add] at hm
  simp only [contextStage]
  intro h
  rw [List.append_eq_nil_iff, List.flatten_eq_nil_iff] at h
  have := h.2 _ hm
  simp only [happ, ↓reduceIte] at this
  exact hc this

/-- Deny wins: a matched CBAC rule with a requirement that is not TRUE denies, whatever roles, grants and permits the
    bundle holds (the stage runs whatever the earlier ones allowed). -/
theorem cbac_deny_denies {b : Bundle} {v : Val} {o : Oracle} {req : Req} {d : ActionDef} {j : Nat} {r : ContextRule}
    (hr : prepare v o = some req) (hd : actionDef b req.resource.type req.action = some d)
    (hj : b.context[j]? = some r) (happ : contextApplies r req d.kind = true)
    (hc : contextRuleChecks o j r req.context ≠ []) : (evaluate b v o).decision = false :=
  stage_denies hr hd (s := contextStage b req d o) (by simp) (context_stage_denies hj happ hc)

/-- A required signal the request does not carry. -/
def missingSignal (r : ContextRule) (c : Context) : Prop :=
  (r.countries.isSome ∧ c.country = none) ∨ (r.ipRanges = true ∧ c.ip = none) ∨
  ((r.deviceManaged.isSome ∨ r.deviceCompliant.isSome) ∧ c.device = none) ∨ (r.mfaMaxAge = true ∧ c.mfaTime = none) ∨
  (r.authMaxAge = true ∧ c.authTime = none) ∨ (r.authMethodsAny.isSome ∧ c.authMethods = none) ∨
  (r.maxRiskScore.isSome ∧ c.riskScore = none)

/-- A missing signal is UNKNOWN, never a pass: whatever the oracle answers, the rule reports `CBAC.SIGNAL_MISSING`. -/
theorem missing_signal_reported (o : Oracle) (j : Nat) {r : ContextRule} {c : Context} (h : missingSignal r c) :
    "CBAC.SIGNAL_MISSING" ∈ contextRuleChecks o j r c := by
  unfold missingSignal at h
  rcases h with ⟨hs, hn⟩ | ⟨hs, hn⟩ | ⟨hs | hs, hn⟩ | ⟨hs, hn⟩ | ⟨hs, hn⟩ | ⟨hs, hn⟩ | ⟨hs, hn⟩
  · obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp hs
    simp [contextRuleChecks, judge, hx, hn]
  · simp [contextRuleChecks, judge, hs, hn]
  · obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp hs
    simp [contextRuleChecks, judge, hx, hn]
  · obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp hs
    simp [contextRuleChecks, judge, hx, hn]
  · simp [contextRuleChecks, judge, hs, hn]
  · simp [contextRuleChecks, judge, hs, hn]
  · obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp hs
    simp [contextRuleChecks, judge, hx, hn]
  · obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp hs
    simp [contextRuleChecks, judge, hx, hn]

/-- Zero Trust: a matched context rule whose required signal is absent denies, for every outcome of the abstracted
    requirements and whatever else the bundle grants. -/
theorem cbac_missing_signal_denies {b : Bundle} {v : Val} {o : Oracle} {req : Req} {d : ActionDef} {r : ContextRule}
    (hr : prepare v o = some req) (hd : actionDef b req.resource.type req.action = some d)
    (hrule : r ∈ b.context) (happ : contextApplies r req d.kind = true) (hmiss : missingSignal r req.context) :
    (evaluate b v o).decision = false := by
  obtain ⟨j, hj⟩ := List.mem_iff_getElem?.mp hrule
  exact cbac_deny_denies hr hd hj happ (List.ne_nil_of_mem (missing_signal_reported o j hmiss))

/-- A session the PDP or the PEP knows to be expired is refused, whatever the rest of the request. -/
theorem session_expired_denies {b : Bundle} {v : Val} {o : Oracle} {req : Req} {d : ActionDef}
    (hr : prepare v o = some req) (hd : actionDef b req.resource.type req.action = some d)
    (hx : req.context.sessionExpired = true) : (evaluate b v o).decision = false :=
  stage_denies hr hd (s := contextStage b req d o) (by simp) (by simp [contextStage, hx])

/-! ## CBAC grant duration: a grant outside its window does not exist for the request -/

theorem filter_erase_of_false [DecidableEq α] {f : α → Bool} {a : α} (h : f a = false) :
    ∀ l : List α, (l.erase a).filter f = l.filter f
  | [] => rfl
  | x :: xs => by
    by_cases hx : x = a
    · subst hx; simp [h]
    · have hb : (x == a) = false := by simpa using hx
      simp [List.erase_cons, hb, List.filter_cons, filter_erase_of_false h xs]

theorem mem_dedup {x : String} : ∀ {l : List String}, x ∈ l → x ∈ dedup l
  | y :: ys, h => by
    by_cases hx : x = y
    · subst hx; exact List.mem_cons_self
    · have hm : x ∈ ys := by simpa [hx] using h
      exact List.mem_cons_of_mem _ (List.mem_filter.mpr ⟨mem_dedup hm, by simpa using hx⟩)

/-- An assignment outside its window grants nothing: the principal's live roles, its RBAC eligibility and its
    trusted-role exemption are those it would have without the assignment. (Relation tuples outside their window are
    dropped by the relation check, which the oracle abstracts.) -/
theorem expired_grant_not_eligible (o : Oracle) (i : Nat) (p : Principal) {a : RoleAssignment}
    (h : o.roleLive i a = false) :
    liveRolesOf o i { p with assignments := p.assignments.erase a } = liveRolesOf o i p ∧
    (∀ (b : Bundle) (type action : String),
      rbacGrant b { p with roles := liveRolesOf o i { p with assignments := p.assignments.erase a } } type action =
      rbacGrant b { p with roles := liveRolesOf o i p } type action) ∧
    (∀ m : Mandatory, trustedSubject m { p with roles := liveRolesOf o i { p with assignments := p.assignments.erase a } } =
      trustedSubject m { p with roles := liveRolesOf o i p }) := by
  have he : liveRolesOf o i { p with assignments := p.assignments.erase a } = liveRolesOf o i p := by
    simp only [liveRolesOf, filter_erase_of_false h]
  exact ⟨he, fun _ _ _ => by rw [he], fun _ => by rw [he]⟩

/-- A live assignment is a role like any other. -/
theorem live_assignment_is_a_role (o : Oracle) (i : Nat) (p : Principal) {a : RoleAssignment}
    (ha : a ∈ p.assignments) (hl : o.roleLive i a = true) : a.role ∈ liveRolesOf o i p :=
  mem_dedup (List.mem_append_right _ (List.mem_map_of_mem (List.mem_filter.mpr ⟨ha, hl⟩)))

/-- The pipeline decides every principal of the chain with its live roles. -/
theorem live_chain_roles (o : Oracle) : ∀ (i : Nat) (ps : List Principal) (k : Nat),
    (liveChain o i ps)[k]?.map (·.roles) = ps[k]?.map (liveRolesOf o (i + k))
  | _, [], _ => rfl
  | i, p :: ps, 0 => by simp [liveChain]
  | i, p :: ps, k + 1 => by
    simp only [liveChain, List.getElem?_cons_succ]
    rw [live_chain_roles o (i + 1) ps k, show i + 1 + k = i + (k + 1) by omega]

/-! ## Unknown is deny for forbids, and never a grant -/

/-- A forbid whose condition is UNKNOWN (a missing or mistyped attribute) denies. -/
theorem unknown_forbid_denies {b : Bundle} {v : Val} {o : Oracle} {req : Req} {d : ActionDef} {p : Principal}
    {r : AbacRule} (hr : prepare v o = some req) (hd : actionDef b req.resource.type req.action = some d)
    (hp : p ∈ req.chain) (hrule : r ∈ b.abac) (heff : r.effect = .forbid)
    (happ : appliesTo r.resourceTypes r.actions req.resource.type req.action = true)
    (hunk : evalTri (envOf req d p) r.when = none) : (evaluate b v o).decision = false :=
  forbid_denies hr hd hp hrule heff happ (mayHold_of_unknown hunk)

/-- The permit that grants eligibility is a permit of the bundle whose condition is TRUE. -/
theorem grantingPermit_sound {b : Bundle} {req : Req} {env : Val} {r : AbacRule}
    (h : grantingPermit b req env = some r) : r ∈ b.abac ∧ r.effect = .permit ∧ evalTri env r.when = some true := by
  unfold grantingPermit at h
  have hp := List.find?_some h
  have hm := List.mem_of_find?_eq_some h
  simp only [Bool.and_eq_true, beq_iff_eq] at hp
  exact ⟨hm, hp.1.1, by simpa [evalExpr] using hp.2⟩

/-- A permit whose condition is UNKNOWN does not grant. -/
theorem unknown_permit_does_not_grant {b : Bundle} {req : Req} {env : Val} {r : AbacRule}
    (hunk : evalTri env r.when = none) : grantingPermit b req env ≠ some r := by
  intro h
  have := (grantingPermit_sound h).2.2
  rw [hunk] at this
  cases this

/-- Without a role grant, a principal whose applicable permits are all FALSE or UNKNOWN is not eligible: deny. -/
theorem no_true_permit_denies {b : Bundle} {v : Val} {o : Oracle} {req : Req} {d : ActionDef} {p : Principal}
    (hr : prepare v o = some req) (hd : actionDef b req.resource.type req.action = some d) (hp : p ∈ req.chain)
    (hrbac : rbacGrant b p req.resource.type req.action = none)
    (hperm : ∀ r ∈ b.abac, r.effect = .permit → appliesTo r.resourceTypes r.actions req.resource.type req.action = true →
      evalTri (envOf req d p) r.when ≠ some true) : (evaluate b v o).decision = false := by
  have hg : grantingPermit b req (envOf req d p) = none := by
    unfold grantingPermit
    rw [List.find?_eq_none]
    intro r hr' hc
    simp only [Bool.and_eq_true, beq_iff_eq] at hc
    exact hperm r hr' hc.1.1 hc.1.2 (by simpa [evalExpr] using hc.2)
  obtain ⟨i, hi⟩ := mem_mapI (f := fun i p => eligibility b req (envOf req d p) p (prefixOf i)) (n := 0) hp
  refine stage_denies hr hd
    (s := Out.cat (mapI (fun i p => eligibility b req (envOf req d p) p (prefixOf i)) 0 req.chain))
    (by simp) (Out.cat_denies_ne_nil hi ?_)
  simp [eligibility, hrbac, hg]

/-! ## Mandatory controls come before tenant policy -/

/-- Mandatory findings for any principal deny. -/
theorem mandatory_denies {b : Bundle} {v : Val} {o : Oracle} {req : Req} {d : ActionDef} {p : Principal}
    (hr : prepare v o = some req) (hd : actionDef b req.resource.type req.action = some d) (hp : p ∈ req.chain)
    (hm : mandatoryFindings b.mandatory p req.resource req.action d.kind req.context ≠ []) :
    (evaluate b v o).decision = false := by
  obtain ⟨i, hi⟩ := mem_mapI (f := mandatoryStage b req d) (n := 0) hp
  refine stage_denies hr hd (s := Out.cat (mapI (mandatoryStage b req d) 0 req.chain)) (by simp)
    (Out.cat_denies_ne_nil hi ?_)
  simpa [mandatoryStage] using hm

/-- No tenant rule turns a mandatory denial into an allow: for every bundle with the same mandatory section and the
    same kind of action — whatever its roles, grants, permits, forbids, content and context rules, need-to-know
    settings — and for every outcome of the relation check, the request (with its principals' live roles) is denied. -/
theorem mandatory_before_tenant_policy (m : Mandatory) {v : Val} {req : Req} {p : Principal} (hp : p ∈ req.chain)
    (k : Kind) (hm : mandatoryFindings m p req.resource req.action k req.context ≠ []) :
    ∀ (b : Bundle) (o : Oracle) (d : ActionDef), b.mandatory = m → prepare v o = some req →
      actionDef b req.resource.type req.action = some d → d.kind = k → (evaluate b v o).decision = false := by
  intro b o d hb hr hd hk
  subst hb hk
  exact mandatory_denies hr hd hp hm

/-- The mandatory findings read a principal's roles only through "holds a trusted role": adding roles that are not
    trusted (any tenant role) changes nothing. -/
theorem mandatory_untrusted_roles_irrelevant (m : Mandatory) (p : Principal) (r : Resource) (a : String) (k : Kind)
    (c : Context) (extra : List String) (hx : extra.all (fun x => !m.trustedRoles.contains x) = true) :
    mandatoryFindings m { p with roles := p.roles ++ extra } r a k c = mandatoryFindings m p r a k c := by
  have ht : trustedSubject m { p with roles := p.roles ++ extra } = trustedSubject m p := by
    simp only [trustedSubject, List.any_append]
    have : extra.any (m.trustedRoles.contains ·) = false := by
      simp only [List.all_eq_true, Bool.not_eq_true'] at hx
      simpa [List.any_eq_false] using hx
    rw [this, Bool.or_false]
  simp only [mandatoryFindings, blpWrite, ht]
  rfl

theorem no_read_up {m : Mandatory} {p : Principal} {r : Resource} {a : String} {k : Kind} {c : Context}
    (h : sessionOf p c < r.level) : "BLP.NO_READ_UP" ∈ mandatoryFindings m p r a k c := by
  simp [mandatoryFindings, blpRead, h]

theorem compartment_required {m : Mandatory} {p : Principal} {r : Resource} {a : String} {k : Kind} {c : Context}
    {x : String} (hx : x ∈ r.compartments) (hn : x ∉ p.compartments) :
    "MAC.COMPARTMENT" ∈ mandatoryFindings m p r a k c := by
  have hex : ∃ y, y ∈ r.compartments ∧ ¬y ∈ p.compartments := ⟨x, hx, hn⟩
  simp [mandatoryFindings, compartments, hex]

theorem network_cap {m : Mandatory} {p : Principal} {r : Resource} {a : String} {k : Kind} {c : Context}
    (ht : c.trusted = false) (h : m.untrustedNetworkMaxLevel < r.level) :
    "NET.UNTRUSTED_LEVEL" ∈ mandatoryFindings m p r a k c := by
  simp [mandatoryFindings, network, ht, h]

theorem no_write_down {m : Mandatory} {p : Principal} {r : Resource} {a : String} {k : Kind} {c : Context}
    (hw : k.isWrite = true) (h : r.level < requestedLevel p c) (ht : trustedSubject m p = false) :
    "BLP.NO_WRITE_DOWN" ∈ mandatoryFindings m p r a k c := by
  simp [mandatoryFindings, blpWrite, hw, h, ht]

/-- High-water: an untrusted write below a level the session already read is denied (as BLP.NO_WRITE_DOWN when it is
    also below the requested level, BLP.HIGH_WATER otherwise), whatever session level the caller asks for. -/
theorem high_water {m : Mandatory} {p : Principal} {r : Resource} {a : String} {k : Kind} {c : Context}
    (hw : k.isWrite = true) (h : r.level < c.highWater.getD 0) (ht : trustedSubject m p = false) :
    "BLP.NO_WRITE_DOWN" ∈ mandatoryFindings m p r a k c ∨ "BLP.HIGH_WATER" ∈ mandatoryFindings m p r a k c := by
  by_cases hl : r.level < requestedLevel p c
  · exact .inl (no_write_down hw hl ht)
  · have hf : r.level < writeFloor p c := Nat.lt_of_lt_of_le h (Nat.le_max_right _ _)
    exact .inr (by simp [mandatoryFindings, blpWrite, hw, hl, hf, ht])

theorem biba_no_write_up {m : Mandatory} {p : Principal} {r : Resource} {a : String} {k : Kind} {c : Context}
    (hw : k.isWrite = true) (h : p.integrity.rank < r.integrity.rank) :
    "BIBA.NO_WRITE_UP" ∈ mandatoryFindings m p r a k c := by
  simp [mandatoryFindings, bibaWrite, hw, h]

theorem biba_no_read_down {m : Mandatory} {p : Principal} {r : Resource} {a : String} {k : Kind} {c : Context}
    (ha : bibaNoReadDownRequired m a k = true) (h : r.integrity.rank < p.integrity.rank) :
    "BIBA.NO_READ_DOWN" ∈ mandatoryFindings m p r a k c := by
  simp [mandatoryFindings, bibaRead, ha, h]

/-- The `reads` scope applies no-read-down to an action because its kind is read, regardless of its name. -/
theorem biba_no_read_down_reads {m : Mandatory} {p : Principal} {r : Resource} {a : String} {k : Kind} {c : Context}
    (hs : m.bibaNoReadDownScope = .reads) (hk : k = .read) (h : r.integrity.rank < p.integrity.rank) :
    "BIBA.NO_READ_DOWN" ∈ mandatoryFindings m p r a k c :=
  biba_no_read_down (by simp [bibaNoReadDownRequired, hs, hk]) h

/-- The `all` scope applies no-read-down to every action kind, in addition to no-write-up for writes. -/
theorem biba_no_read_down_all {m : Mandatory} {p : Principal} {r : Resource} {a : String} {k : Kind} {c : Context}
    (hs : m.bibaNoReadDownScope = .all) (h : r.integrity.rank < p.integrity.rank) :
    "BIBA.NO_READ_DOWN" ∈ mandatoryFindings m p r a k c :=
  biba_no_read_down (by simp [bibaNoReadDownRequired, hs]) h

/-- The working level never exceeds the clearance, whatever session level or high-water mark the context carries. -/
theorem sessionOf_le_clearance (p : Principal) (c : Context) : sessionOf p c ≤ p.clearance :=
  Nat.min_le_right _ _

/-! ## Obligations are only released on allow -/

theorem obligations_only_on_allow (b : Bundle) (v : Val) (o : Oracle) (h : (evaluate b v o).decision = false) :
    (evaluate b v o).obligations = {} := by
  rcases evaluate_shape b v o with ⟨rs, he⟩ | ⟨out, he⟩
  · rw [he]; rfl
  · rw [he] at h ⊢; exact finish_obligations out h

end Qadamar
