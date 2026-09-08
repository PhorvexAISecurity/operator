package feasibility

import (
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// proactive_cadence_test.go — M-28 (proactive cadence cap).
//
// The cap floors EVIDENCE-LESS (hygiene) motion to Policy.ProactiveFloor (T_cad), while leaving
// evidence-driven motion at the short reactive AntiOverRotationWindow that anti-over-rotation governs.
// Live defect: with zero SecurityEvents, kv-reset flushed the vLLM prefix cache every ~100-110s
// (= AntiOverRotationWindow) forever. These exercise the SPLIT via the full feasibility.Evaluate
// registry, so the behavioral cases are RED on base (the cap absent → Evaluate returns feasible).

// window (reactive, short) < the age we test < floor (proactive, long): the gap the cap closes.
const (
	testWindow = 100 * time.Second
	testFloor  = 15 * time.Minute
	testAge    = 110 * time.Second // past the reactive window, inside the proactive floor
)

func capPolicy() model.Policy {
	return model.Policy{AntiOverRotationWindow: testWindow, ProactiveFloor: testFloor}
}

// capView builds a one-pod view with a session/podIdentity clock and an event-evidence verdict.
func capView(hasEventEvidence bool, session, podIdentity time.Duration) *model.WorkloadView {
	return &model.WorkloadView{
		// ModelID makes it an inference pod so ai-context-required (which sorts before the cap)
		// passes kv-reset — isolating the proactive-cadence cap as the acting law.
		Pod:              model.Pod{Namespace: "vllm", Name: "vllm-1", UID: "u1", ModelID: "vllm-qwen"},
		HasEventEvidence: hasEventEvidence,
		ExposureByVariable: map[string]time.Duration{
			model.VarSession:     session,
			model.VarPodIdentity: podIdentity,
		},
	}
}

// (a) RED: no evidence, kv-reset past the reactive window but inside the floor → VETO. On base the
// cap is absent, so Evaluate passes anti-over-rotation (110s > 100s window) and returns feasible —
// the churn. This test FAILS on base and passes with the cap.
func TestCapVetoesEvidenceLessHygieneWithinFloor(t *testing.T) {
	v := capView(false, testAge, 10*time.Hour)
	got := Evaluate(v, model.Move{Action: model.ActionKVReset}, capPolicy())
	if got.Feasible {
		t.Fatalf("evidence-less kv-reset %s after the last flush (window=%s, floor=%s) was allowed — "+
			"the proactive-cadence cap must floor hygiene motion to T_cad. This is the ~110s vLLM churn.",
			testAge, testWindow, testFloor)
	}
	if !strings.HasPrefix(got.Reason, "proactive-cadence:") {
		t.Fatalf("blocked, but by %q — want the proactive-cadence cap (anti-over-rotation should have "+
			"passed at %s > %s window)", got.Reason, testAge, testWindow)
	}
}

// (b) Hygiene RESUMES at the floor: no evidence, past ProactiveFloor → feasible (M-118: with
// detectors silent the brain keeps moving, just at T_cad).
func TestCapAllowsHygieneAtFloor(t *testing.T) {
	v := capView(false, testFloor+time.Second, 10*time.Hour)
	if got := Evaluate(v, model.Move{Action: model.ActionKVReset}, capPolicy()); !got.Feasible {
		t.Fatalf("evidence-less kv-reset %s after the last flush (floor=%s) must be allowed — the cap "+
			"SLOWS hygiene, it does not stop it (M-118): %s", testFloor+time.Second, testFloor, got.Reason)
	}
}

// (c) POSITIVE CONTROL (P4): WITH a trusted recent event, the same within-floor move is feasible —
// the reactive path is untouched, so a real response still lands within one tick.
func TestCapUntouchedByReactivePath(t *testing.T) {
	v := capView(true, testAge, 10*time.Hour) // HasEventEvidence=true, same 110s age as (a)
	if got := Evaluate(v, model.Move{Action: model.ActionKVReset}, capPolicy()); !got.Feasible {
		t.Fatalf("with event evidence, kv-reset %s after the last flush must stay feasible (reactive "+
			"cadence, anti-over-rotation only) — the cap must not touch the event path: %s", testAge, got.Reason)
	}
}

// (h) GAP GUARD (reviewer, 2026-09-07): a pod that is aiClassified / SuspectAdapter-flagged but has
// NO trusted recent event MUST still be capped. Keying the cap on the broad HasEvidence (which fires
// on physics/topology AI classification a healthy event-less GPU server carries) would fail-open on
// exactly the physics-pinned model-theft churn pod. HasEventEvidence excludes those, so it is capped.
func TestCapFiresWhenOnlyPhysicsClassifiedNoEvent(t *testing.T) {
	v := capView(false, testAge, 10*time.Hour) // HasEventEvidence=false (no event) …
	v.Pod.SuspectAdapter = "unauthorized-lora" // … even though a detector flag / AI signature is set
	got := Evaluate(v, model.Move{Action: model.ActionKVReset}, capPolicy())
	if got.Feasible {
		t.Fatal("cap fail-opened on a pod with an AI signature / suspect adapter but NO trusted event — " +
			"this is the physics-pinned churn pod the cap MUST throttle (reviewer gap #1)")
	}
	if !strings.HasPrefix(got.Reason, "proactive-cadence:") {
		t.Fatalf("blocked by %q; want the proactive-cadence cap", got.Reason)
	}
}

// (d) The cap is ACTION-GENERAL, not kv-special: a pod-replacing action reads its OWN clock
// (VarPodIdentity via ExposureVarFor) and is capped the same way when evidence-less within the floor.
func TestCapIsActionGeneral(t *testing.T) {
	// podIdentity within the floor, session long ago; rotate maps to VarPodIdentity.
	v := capView(false, 10*time.Hour, testAge)
	got := Evaluate(v, model.Move{Action: model.ActionRotate}, capPolicy())
	if got.Feasible {
		t.Fatalf("evidence-less rotate %s after the pod was replaced must be capped via its own "+
			"VarPodIdentity clock — the cap is not kv-reset-specific", testAge)
	}
	if !strings.HasPrefix(got.Reason, "proactive-cadence:") {
		t.Fatalf("rotate blocked by %q; want proactive-cadence (anti-over-rotation passes at %s > %s)",
			got.Reason, testAge, testWindow)
	}
}

// Zero floor reproduces base byte-for-byte: an unset ProactiveFloor never caps (a policy built
// without it is unchanged), so the evidence-less within-window churn is NOT introduced by the cap.
func TestCapUnsetFloorIsPassThrough(t *testing.T) {
	v := capView(false, testAge, 10*time.Hour)
	pol := model.Policy{AntiOverRotationWindow: testWindow} // ProactiveFloor unset (0)
	if got := Evaluate(v, model.Move{Action: model.ActionKVReset}, pol); !got.Feasible {
		t.Fatalf("with ProactiveFloor unset the cap must be a no-op (base-identical): %s", got.Reason)
	}
}

// The cap reuses the M-23 clock: mostRecentSince = min(observed, intent). An emit INTENT inside the
// floor caps even when the observed clock is already past it (the cross-tick burst hole M-23 closed).
func TestCapReadsEmitIntentNotJustObserved(t *testing.T) {
	v := capView(false, testFloor+time.Minute, 10*time.Hour) // observed session past the floor
	v.IntentByVariable = map[string]time.Duration{model.VarSession: testAge}
	got := Evaluate(v, model.Move{Action: model.ActionKVReset}, capPolicy())
	if got.Feasible {
		t.Fatalf("a fresh emit intent (%s) inside the floor must cap even though the OBSERVED clock (%s) "+
			"is past it — the cap must read min(observed, intent), not a second clock", testAge, testFloor+time.Minute)
	}
}

// (e) PRESENCE: the cap must be registered. Absent → RED (M-118 lands "fully" only when the cap
// exists). Checked by Name() string so this compiles on base (where it fails: law not registered).
func TestCapRegistered(t *testing.T) {
	if !lawRegistered("proactive-cadence") {
		t.Fatal("the proactive-cadence law is not registered — the cap never runs")
	}
}

// (f) ORDERING pin: Registry.All() is sorted by Name and returns the FIRST veto, so "proactive-cadence"
// MUST sort AFTER "anti-over-rotation" for the reactive (evidence-retention) reason to win when both
// windows apply. A rename that breaks the alphabetical coupling flips reason priority silently.
func TestProactiveCadenceOrdersAfterAntiOverRotation(t *testing.T) {
	iAnti, iCap := -1, -1
	for i, c := range Registry.All() {
		switch c.Name() {
		case "anti-over-rotation":
			iAnti = i
		case "proactive-cadence":
			iCap = i
		}
	}
	if iAnti < 0 || iCap < 0 {
		t.Fatalf("missing a law: anti-over-rotation@%d proactive-cadence@%d", iAnti, iCap)
	}
	if iCap < iAnti {
		t.Fatalf("proactive-cadence (@%d) runs BEFORE anti-over-rotation (@%d): the reactive reason "+
			"would be masked by the hygiene reason inside the reactive window", iCap, iAnti)
	}
}

func lawRegistered(name string) bool {
	for _, c := range Registry.All() {
		if c.Name() == name {
			return true
		}
	}
	return false
}
