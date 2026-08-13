package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// fixedThreatContext isolates the ctxprov scalar from the raw SecurityEvents that
// the kill-chain model consumes. This makes the PHORVEXSEC-58 boundary explicit:
// ThreatPosture is audit context in P1; event severity reaches targeting through
// killchain.Assess -> P(hold)/stage urgency -> fact weights.
type fixedThreatContext struct {
	postureByPod map[string]float64
}

func (fixedThreatContext) Name() string { return "fixed-threat-context" }

func (c fixedThreatContext) Context(v *model.WorkloadView, _ model.Policy) model.ContextSignals {
	return model.ContextSignals{
		AssetValue:    1,
		Phase:         v.Phase,
		ThreatPosture: c.postureByPod[v.Pod.Name],
		SLOHeadroom:   1,
	}
}

func selectedPod(ds []model.Decision) string {
	for _, d := range ds {
		if d.Selected {
			return d.Pod
		}
	}
	return ""
}

func TestEventSeverityDrivesP1WithoutThreatPostureScalar(t *testing.T) {
	low := covView("low-first", false, 10*time.Minute, false)
	critical := covView("critical-second", false, 10*time.Minute, false)
	low.Events = []model.SecurityEventInfo{{Type: "generic-alert", ThreatLevel: "low", TargetsPod: true}}
	critical.Events = []model.SecurityEventInfo{{Type: "generic-alert", ThreatLevel: "critical", TargetsPod: true}}

	e := NewCoverageEngine()
	e.Context = fixedThreatContext{} // both posture scalars are exactly zero
	got := selectedPod(e.Decide([]*model.WorkloadView{low, critical}, covPolicy(1)))
	if got != critical.Pod.Name {
		t.Fatalf("critical event must win the one-move budget through kill-chain fact weighting; selected %q", got)
	}
}

func TestThreatPostureScalarIsAuditOnlyInP1(t *testing.T) {
	first := covView("first", false, 2*time.Hour, false)
	postureOnly := covView("posture-only-second", false, 2*time.Hour, false)

	e := NewCoverageEngine()
	e.Context = fixedThreatContext{postureByPod: map[string]float64{
		first.Pod.Name:       0,
		postureOnly.Pod.Name: 1,
	}}
	got := selectedPod(e.Decide([]*model.WorkloadView{first, postureOnly}, covPolicy(1)))
	if got != first.Pod.Name {
		t.Fatalf("ctxprov ThreatPosture must not independently reweight P1 targeting; selected %q", got)
	}
}
