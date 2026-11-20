#!/usr/bin/env bash
# Builds the Lean model, its proofs and the gate-model executable, then checks the proofs: no `sorry` anywhere, and no
# axiom beyond Lean's standard three (propext, Classical.choice, Quot.sound). docs/spec/FORMAL-MODEL.md.
set -euo pipefail
cd "$(dirname "$0")"
if grep -rnw --include='*.lean' sorry .  --exclude-dir=.lake; then echo 'formal/: sorry is not allowed' >&2; exit 1; fi
# A declared axiom would never reach the #print axioms list of CheckAxioms.lean unless a listed theorem used it.
if grep -rnE --include='*.lean' '^\s*(private\s+|noncomputable\s+)*axiom\s' . --exclude-dir=.lake; then echo 'formal/: axiom declarations are not allowed' >&2; exit 1; fi
log=$(lake build 2>&1) || { echo "$log" >&2; exit 1; }
if grep -q "sorry" <<<"$log"; then echo "$log" >&2; echo 'formal/: a declaration uses sorry' >&2; exit 1; fi
axioms=$(lake env lean CheckAxioms.lean 2>&1)
echo "$axioms"
# Lean wraps long axiom lists over several lines: join them before matching the brackets.
bad=$(tr '\n' ' ' <<<"$axioms" | grep -oE '\[[^]]*\]' | tr -d '[] ' | tr ',' '\n' | grep -v '^$' | grep -vxE 'propext|Classical\.choice|Quot\.sound' || true)
if [ -n "$bad" ]; then echo "formal/: non-standard axioms: $bad" >&2; exit 1; fi
echo "formal/: model, proofs and gate-model built; no sorry, standard axioms only"
