/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package killchain

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func kcPolicy() model.Policy {
	return model.Policy{Tenant: "t", ProactiveFloor: time.Hour}
}

func TestHazardRisesWithExposure_PredictiveHorizon(t *testing.T) {
	m := NewModel()
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}}
	floor := 3600.0

	young := m.Assess(v, kcPolicy(), 60, floor) // 1 min dwell
	old := m.Assess(v, kcPolicy(), 3600, floor) // 1 h dwell

	if !(old.Hazard > young.Hazard) {
		t.Errorf("stage-exit hazard must rise with dwell (predictive horizon): young=%.3f old=%.3f", young.Hazard, old.Hazard)
	}
	if !(old.StageUrgency > young.StageUrgency) {
		t.Errorf("stage urgency (current blended with hazard*next) must rise with dwell: young=%.3f old=%.3f", young.StageUrgency, old.StageUrgency)
	}
}

func TestPHoldDampedRightAfterMove(t *testing.T) {
	m := NewModel()
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}}
	fresh := m.Assess(v, kcPolicy(), 1, 3600)  // just moved
	old := m.Assess(v, kcPolicy(), 3600, 3600) // long unmoved
	if fresh.PHold > 0.1 {
		t.Errorf("P(hold) must be ~0 right after a wipe, got %.3f", fresh.PHold)
	}
	if !(old.PHold > fresh.PHold) {
		t.Errorf("P(hold) must recover/accrue with exposure: fresh=%.3f old=%.3f", fresh.PHold, old.PHold)
	}
}

func TestNeighborEventProjectsLateral(t *testing.T) {
	m := NewModel()
	v := &model.WorkloadView{
		Pod: model.Pod{Namespace: "ns", Name: "p"},
		Events: []model.SecurityEventInfo{
			{Type: "panic", ThreatLevel: "critical", TargetsPod: false, Age: time.Minute}, // a compromised NEIGHBOR
		},
	}
	a := m.Assess(v, kcPolicy(), 600, 3600)
	if a.LateralUrgency <= 0 {
		t.Errorf("a compromised neighbor must raise lateral urgency (about-to-pivot-here), got %.3f", a.LateralUrgency)
	}
	if a.NextStage != StageLateral {
		t.Errorf("neighbor pressure should forward-project NextStage=lateral, got %s", a.NextStageName)
	}
}

func TestPolicySojournAndShapeOverridesReachHazardModel(t *testing.T) {
	m := NewModel()
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}}
	basePolicy := kcPolicy()
	baseline := m.Assess(v, basePolicy, 60, 3600)
	override := basePolicy
	override.KillChainSojournScaleSeconds = map[string]float64{"recon": 60}
	override.KillChainShape = 1
	got := m.Assess(v, override, 60, 3600)

	if got.Hazard <= baseline.Hazard || got.Hazard < 0.63 || got.Hazard > 0.64 {
		t.Fatalf("override did not reach Weibull hazard: baseline=%v override=%v", baseline.Hazard, got.Hazard)
	}
	if m.SojournScale[StageRecon] != 1800 || m.Shape != 2 {
		t.Fatalf("per-policy override mutated shared model defaults: scale=%v shape=%v", m.SojournScale[StageRecon], m.Shape)
	}
}

func TestConjugateMemoryAccumulates(t *testing.T) {
	mem := NewConjugateMemory()
	before := mem.PriorMean("tenantX")
	for i := 0; i < 20; i++ {
		mem.Observe("tenantX", 1.0) // repeated held-evidence
	}
	after := mem.PriorMean("tenantX")
	if !(after > before) {
		t.Errorf("conjugate memory must raise the per-tenant prior with held-evidence: before=%.3f after=%.3f", before, after)
	}
}
