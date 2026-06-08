/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * THE COMPLETENESS INVARIANT — the CI teeth (the binary-startup teeth are the package-level
 * mustCoverAllActions() init-panic in handler.go). This test FAILS `go test` (= fails CI) if
 * any generatable action lacks a native handler, if a handler is an orphan, if the action
 * order drifts, or if the feasibility gate does not evaluate every action. Full real-time
 * coverage is thus a build/CI-enforced theorem, not an assumption. (HONEST: this is not a
 * compile error — `go build` still produces a binary; the init-panic makes it die on start.)
 */

package actuator

import (
	"testing"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/model"
)

// TestCompletenessForward — every generatable action has a registered native handler.
func TestCompletenessForward(t *testing.T) {
	if missing := MissingHandlers(); len(missing) > 0 {
		t.Fatalf("COMPLETENESS VIOLATION: generatable actions have no native handler: %v", missing)
	}
	// Belt-and-suspenders: each is actually dispatchable.
	for _, a := range actionset.GeneratableActions() {
		if _, ok := HandlerRegistry.Get(string(a)); !ok {
			t.Fatalf("COMPLETENESS VIOLATION: action %q not in HandlerRegistry", a)
		}
	}
}

// TestCompletenessSymmetric — no orphan handler (a dead hand hiding a typo). Allowed:
// generatable actions + the declared-only ActionDisable.
func TestCompletenessSymmetric(t *testing.T) {
	if orphans := OrphanHandlers(); len(orphans) > 0 {
		t.Fatalf("ORPHAN HANDLERS (registered but not generatable/declared): %v", orphans)
	}
}

// TestActionOrderDeterminism — MutatingActions must list ActionRotate before
// ActionQuarantine so the engine's strict-`>` net-benefit tie-break stays byte-identical
// to the pre-P-ACTUATOR baseline (the 1.62x + P3 + lead-demo parity rides this order).
func TestActionOrderDeterminism(t *testing.T) {
	idx := map[model.Action]int{}
	for i, a := range model.MutatingActions {
		idx[a] = i
	}
	r, okR := idx[model.ActionRotate]
	q, okQ := idx[model.ActionQuarantine]
	if !okR || !okQ {
		t.Fatalf("MutatingActions must contain rotate and quarantine; got %v", model.MutatingActions)
	}
	if r >= q {
		t.Fatalf("determinism: ActionRotate (idx %d) must precede ActionQuarantine (idx %d) in MutatingActions", r, q)
	}
	// ActionDisable must NOT be generatable (declared-only).
	if _, ok := idx[model.ActionDisable]; ok {
		t.Fatalf("ActionDisable must be EXCLUDED from MutatingActions (declared-not-implemented), but it is present")
	}
}

// TestFeasibilityReachability — the feasibility gate evaluates EVERY generatable action
// (returns a verdict without panicking), so "real-time safety for every action type" is
// reachable per action (the emit-boundary re-gate keys on Move{Action} uniformly).
func TestFeasibilityReachability(t *testing.T) {
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}}
	pol := model.Policy{}
	for _, a := range actionset.GeneratableActions() {
		_ = feasibility.Evaluate(view, model.Move{Action: a}, pol) // must not panic
	}
}
