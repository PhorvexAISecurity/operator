package feasibility

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// M-23 — per-action exposure clocks. These pin the three legs and the D1–D3 decisions:
// a TOTAL exposureVarFor over a clocked variable set (completeness), each pod-alive action
// throttled against its OWN clock, the emit-intent burst guard (min over observed+intent),
// and fail-OPEN on an absent clock (never-actuated pod is not deadlocked).

func liveVarSet() map[string]bool {
	s := map[string]bool{}
	for _, v := range model.LiveExposureVariables {
		s[v] = true
	}
	return s
}

// viewClocks builds a view with arbitrary observed and intent clocks.
func viewClocks(observed, intent map[string]time.Duration) *model.WorkloadView {
	return &model.WorkloadView{
		Pod:                model.Pod{Namespace: "ns", Name: "p", UID: "u1"},
		ExposureByVariable: observed,
		IntentByVariable:   intent,
	}
}

// TestExposureVarForCompleteness is the M-23 wiring tripwire (D1): because the runtime Check
// fail-OPENs an unclocked variable, the fail-CLOSED guarantee lives here — every generatable
// action MUST map to a variable that is actually clocked (∈ LiveExposureVariables). A new
// MutatingActions member with no exposure decision, or a typo'd variable, fails the build.
func TestExposureVarForCompleteness(t *testing.T) {
	live := liveVarSet()
	for _, a := range model.MutatingActions {
		v := ExposureVarFor(a)
		if v == "" {
			t.Errorf("action %q has no exposure variable (add an ExposureVarFor arm; pod-replacing => VarPodIdentity)", a)
			continue
		}
		if !live[v] {
			t.Errorf("action %q maps to %q which is NOT clocked (not in model.LiveExposureVariables) — a mapped-but-unclocked variable fail-OPENs forever", a, v)
		}
	}
}

// TestExposureFingerprintsCoversClockedVars closes the loop: a fully-marked pod emits EXACTLY
// LiveExposureVariables (so every mapped variable can actually be observed), and an unmarked pod
// absent-skips the per-action epochs (leaving only the always-present identity/session).
func TestExposureFingerprintsCoversClockedVars(t *testing.T) {
	full := model.Pod{
		UID: "u1", Node: "n1", SessionEpoch: "s",
		QuarantineEpoch: "1", RouteKeyEpoch: "2", IdentityEpoch: "3",
		AdapterEpoch: "4", DrainEpoch: "5", GuardrailEpoch: "6",
	}
	fp := model.ExposureFingerprints(full)
	live := liveVarSet()
	if len(fp) != len(live) {
		t.Fatalf("fully-marked pod emitted %d fingerprints, want %d (== LiveExposureVariables)", len(fp), len(live))
	}
	for v := range fp {
		if !live[v] {
			t.Errorf("ExposureFingerprints emitted %q which is not in LiveExposureVariables", v)
		}
	}
	// Absent-skip: a never-actuated pod carries only the always-present two.
	bare := model.ExposureFingerprints(model.Pod{UID: "u1", Node: "n1", SessionEpoch: "s"})
	if len(bare) != 2 {
		t.Fatalf("unmarked pod emitted %d fingerprints, want 2 (podIdentity/session); absent epochs must be skipped, not seeded", len(bare))
	}
}

// TestPerActionClockThrottles proves each pod-alive action reads the clock its OWN handler resets:
// 20s after that variable moved it is vetoed; 16m after, feasible. On the OLD code (default ->
// podIdentity) every one of these read podIdentity and passed — this is ticket test (a)'s RED.
func TestPerActionClockThrottles(t *testing.T) {
	pol := model.Policy{AntiOverRotationWindow: 15 * time.Minute}
	for _, a := range []model.Action{
		model.ActionQuarantine, model.ActionEndpointRotate, model.ActionRouteRotate,
		model.ActionIdentityRotate, model.ActionAdapterRotate, model.ActionRequestDrain,
		model.ActionGuardrailRotate,
	} {
		v := ExposureVarFor(a)
		// podIdentity is ancient (the bug's clock); only the action's own variable is fresh.
		inWindow := viewClocks(map[string]time.Duration{model.VarPodIdentity: 10 * time.Hour, v: 20 * time.Second}, nil)
		if got := (antiOverRotation{}).Check(inWindow, model.Move{Action: a}, pol); got.Feasible {
			t.Errorf("%q 20s after its %q clock reset was allowed (old bug: read podIdentity=10h)", a, v)
		}
		elapsed := viewClocks(map[string]time.Duration{model.VarPodIdentity: 10 * time.Hour, v: 16 * time.Minute}, nil)
		if got := (antiOverRotation{}).Check(elapsed, model.Move{Action: a}, pol); !got.Feasible {
			t.Errorf("%q 16m after its %q clock reset must be allowed: %s", a, v, got.Reason)
		}
	}
}

// TestPodAliveActionReadsOwnClockNotPodIdentity is the sharpest statement of the M-23 bug and its
// fix (ticket test a): a pod alive for 10h but guardrail-rotated 20s ago must be BLOCKED. The old
// code read podIdentity (10h > window) and allowed it — the re-fire-every-tick defect. The view
// hardcodes both clocks (it does NOT key off ExposureVarFor), so reverting the guardrail mapping
// back to podIdentity flips this test red.
func TestPodAliveActionReadsOwnClockNotPodIdentity(t *testing.T) {
	pol := model.Policy{AntiOverRotationWindow: 15 * time.Minute}
	view := viewClocks(map[string]time.Duration{
		model.VarPodIdentity:    10 * time.Hour,   // pod itself is ancient
		model.VarGuardrailEpoch: 20 * time.Second, // but guardrail was rotated 20s ago
	}, nil)
	if got := (antiOverRotation{}).Check(view, model.Move{Action: model.ActionGuardrailRotate}, pol); got.Feasible {
		t.Fatalf("guardrail-rotate 20s after its own epoch was allowed — the guard read podIdentity (10h), the M-23 bug")
	}
}

// TestIntentClosesBurstHole is ticket test (c) + the D3 sign guard: the observed clock is stale
// (the *-epoch marker hasn't been re-observed yet) but an emit intent was stamped 20s ago, so the
// second emit is vetoed. With the D3 regression (max instead of min) the stale 10h would win and
// the burst would slip through — this test catches that.
func TestIntentClosesBurstHole(t *testing.T) {
	pol := model.Policy{AntiOverRotationWindow: 15 * time.Minute}
	a := model.ActionGuardrailRotate
	v := ExposureVarFor(a)
	view := viewClocks(
		map[string]time.Duration{v: 10 * time.Hour},   // observed: not yet caught up
		map[string]time.Duration{v: 20 * time.Second}, // intent: emitted 20s ago
	)
	if got := (antiOverRotation{}).Check(view, model.Move{Action: a}, pol); got.Feasible {
		t.Fatalf("a second %q 20s after emission (intent) was allowed — the cross-tick burst hole is open (or max/min is inverted)", a)
	}
	// After the window, both observed and intent are old -> feasible again.
	elapsed := viewClocks(
		map[string]time.Duration{v: 10 * time.Hour},
		map[string]time.Duration{v: 16 * time.Minute},
	)
	if got := (antiOverRotation{}).Check(elapsed, model.Move{Action: a}, pol); !got.Feasible {
		t.Fatalf("%q 16m after emission must be allowed: %s", a, got.Reason)
	}
}

// TestFailOpenBootstrap is the D1 guard: a never-actuated pod has no clock for the action's
// variable (its *-epoch marker doesn't exist yet). Fail-CLOSED would deadlock the FIRST actuation
// (which is what writes the marker); the guard must fail-OPEN.
func TestFailOpenBootstrap(t *testing.T) {
	pol := model.Policy{AntiOverRotationWindow: 15 * time.Minute}
	// Only podIdentity is clocked; the governed actions' own variables are absent.
	view := viewClocks(map[string]time.Duration{model.VarPodIdentity: 10 * time.Hour}, nil)
	for _, a := range []model.Action{
		model.ActionQuarantine, model.ActionEndpointRotate, model.ActionIdentityRotate,
		model.ActionAdapterRotate, model.ActionRequestDrain, model.ActionGuardrailRotate,
	} {
		if got := (antiOverRotation{}).Check(view, model.Move{Action: a}, pol); !got.Feasible {
			t.Errorf("first %q on a never-actuated pod was DEADLOCKED (%s); it must fail-open so the actuation that creates the marker can run", a, got.Reason)
		}
	}
}
