/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// coverage_evidence_stamp_test.go — M-28.
//
// The proactive-cadence feasibility cap reads view.HasEventEvidence, but a hard law never sees the
// killchain Assessment. AssembleSet is the wiring: it must mirror assess.HasEventEvidence onto the
// shared view. HasEventEvidence is the EVENT-ONLY, age-weighted subset — a trusted recent event
// bears on the pod — NOT the broad HasEvidence (which also fires on the physics/topology AI
// classification a healthy event-less GPU server carries). Keying the cap on the broad signal would
// fail-open on the physics-pinned churn pod, so this test pins BOTH that a real event stamps true
// AND that a physics-only classification (aiClassified, zero events) stamps FALSE (reviewer gap #1).
func TestAssembleSetStampsHasEventEvidenceOntoView(t *testing.T) {
	e := NewCoverageEngine()
	pol := covPolicy(1)

	withEvent := covView("evt", true, 2*time.Hour, false)
	withEvent.Events = []model.SecurityEventInfo{ // a trusted, recent, targeting event
		{Type: "Anomaly", ThreatLevel: "high", TargetsPod: true, Age: 10 * time.Second},
	}
	clean := covView("clean", true, 2*time.Hour, false) // no event, no physics

	// physics-only model-theft: aiClassified ⇒ broad HasEvidence=true, but ZERO events ⇒
	// HasEventEvidence MUST be false, or the cap fail-opens on the churn pod.
	physicsOnly := covView("physics", true, 2*time.Hour, false)
	physicsOnly.Pod.HasGPU = true
	physicsOnly.Pod.ModelID = "qwen"
	physicsOnly.Physics = model.PhysicsWitness{CoResidency: 1.5, ModelRarity: 1.4, SMOccupancy: 0.9}

	for _, v := range []*model.WorkloadView{withEvent, clean, physicsOnly} {
		if v.HasEventEvidence {
			t.Fatalf("fixture %s pre-stamped; the test would not prove AssembleSet does it", v.Pod.Name)
		}
	}

	_, ctx := e.AssembleSet([]*model.WorkloadView{withEvent, clean, physicsOnly}, pol)

	// NON-VACUOUSNESS pin (K3 P3-2): the physics fixture must genuinely trip the BROAD HasEvidence
	// (aiClassified via the real aiStageFromView), or the HasEventEvidence=false assertion below is
	// vacuous — it would also pass if the fixture simply carried no signal at all, silently vacating
	// the gap-#1 guard. This asserts the exclusion is doing real work.
	if !ctx["ns/physics"].assess.HasEvidence {
		t.Fatal("fixture drift: the physics-only pod no longer trips broad HasEvidence (aiClassified) — " +
			"the HasEventEvidence=false check below would be vacuous; restore a real physics/AI signal")
	}

	if !withEvent.HasEventEvidence {
		t.Error("AssembleSet did not stamp HasEventEvidence=true for a pod with a trusted recent event — " +
			"the cap would wrongly throttle a real response")
	}
	if clean.HasEventEvidence {
		t.Error("AssembleSet stamped HasEventEvidence=true on a clean pod — the cap would never floor its hygiene")
	}
	if physicsOnly.HasEventEvidence {
		t.Error("GAP #1: AssembleSet stamped HasEventEvidence=true on a physics-only (aiClassified, zero-event) " +
			"pod — the cap would fail-open on exactly the physics-pinned churn pod (reviewer 2026-09-07)")
	}
}
