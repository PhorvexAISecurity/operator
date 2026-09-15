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
// bears on the pod — NOT the broad HasEvidence (which also includes contextual AI classification).
// This test pins BOTH that a real event stamps true AND that a supported telemetry-only
// classification (aiClassified, zero events) stamps FALSE (reviewer gap #1).
func TestAssembleSetStampsHasEventEvidenceOntoView(t *testing.T) {
	e := NewCoverageEngine()
	pol := covPolicy(1)

	withEvent := covView("evt", true, 2*time.Hour, false)
	withEvent.Events = []model.SecurityEventInfo{ // a trusted, recent, targeting event
		{Type: "Anomaly", ThreatLevel: "high", TargetsPod: true, Age: 10 * time.Second},
	}
	clean := covView("clean", true, 2*time.Hour, false) // no event, no physics

	// Telemetry-only LLM-jacking: aiClassified ⇒ broad HasEvidence=true, but ZERO events ⇒
	// HasEventEvidence MUST be false.
	physicsOnly := covView("physics", true, 2*time.Hour, false)
	physicsOnly.Pod.EndpointPath = "/v1"
	physicsOnly.Telemetry.GPUUtil = model.PresentSignal(0.9, "dcgm")

	for _, v := range []*model.WorkloadView{withEvent, clean, physicsOnly} {
		if v.HasEventEvidence {
			t.Fatalf("fixture %s pre-stamped; the test would not prove AssembleSet does it", v.Pod.Name)
		}
	}

	_, ctx := e.AssembleSet([]*model.WorkloadView{withEvent, clean, physicsOnly}, pol)

	// NON-VACUOUSNESS pin (K3 P3-2): the telemetry fixture must genuinely trip broad HasEvidence
	// (aiClassified via the real supported LLM-jacking arm), or the assertion below is
	// vacuous — it would also pass if the fixture simply carried no signal at all, silently vacating
	// the gap-#1 guard. This asserts the exclusion is doing real work.
	if !ctx["ns/physics"].assess.HasEvidence {
		t.Fatal("fixture drift: the telemetry-only pod no longer trips broad HasEvidence (aiClassified)")
	}

	if !withEvent.HasEventEvidence {
		t.Error("AssembleSet did not stamp HasEventEvidence=true for a pod with a trusted recent event — " +
			"the cap would wrongly throttle a real response")
	}
	if clean.HasEventEvidence {
		t.Error("AssembleSet stamped HasEventEvidence=true on a clean pod — the cap would never floor its hygiene")
	}
	if physicsOnly.HasEventEvidence {
		t.Error("GAP #1: AssembleSet stamped HasEventEvidence=true on a telemetry-only AI classification with zero events")
	}
}
