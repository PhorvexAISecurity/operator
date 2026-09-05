/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package killchain

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/r6security/phoenix/api/v1beta1"
)

func m025Policy() model.Policy { return model.Policy{Tenant: "t", ProactiveFloor: time.Hour} }

// TestMaxByConsequence_MergeRule is the unit-level merge rule (M-25). Rank is consequence(),
// which is NOT ordinal-monotonic (gpu-side-channel ordinal 5 = 0.15 < persist ordinal 2 = 0.6),
// so the merge MUST use consequence, not the raw ordinal.
func TestMaxByConsequence_MergeRule(t *testing.T) {
	// (a) persist (0.6) vs gpu-side-channel (0.15) => persist (no downgrade).
	if got := maxByConsequence(StagePersist, StageGPUSideChannel); got != StagePersist {
		t.Errorf("(a) max(persist, gpu-side-channel) = %s, want persist", got)
	}
	// (b) recon (0.1) vs model-theft (0.9) => model-theft (escalation preserved).
	if got := maxByConsequence(StageRecon, StageModelTheft); got != StageModelTheft {
		t.Errorf("(b) max(recon, model-theft) = %s, want model-theft", got)
	}
	// ties keep a (the event-incorporating current stage): llm-jacking(0.6) vs persist(0.6) => a.
	if got := maxByConsequence(StagePersist, StageLLMJacking); got != StagePersist {
		t.Errorf("tie must keep a (persist), got %s", got)
	}
}

// (e) rank completeness: every declared stage has a name and a consequence rank, so the merge is
// total. A new stage without a rank would surface here.
func TestConsequenceRankCompleteness(t *testing.T) {
	for s := StageRecon; s <= StagePromptInjectPersist; s++ {
		if s.String() == "unknown" {
			t.Errorf("stage ordinal %d has no name — rank table incomplete", int(s))
		}
		if c := consequence(s); c < minConsequence || c > 1 {
			t.Errorf("stage %s consequence %.3f out of [%.2f,1] — no valid rank", s, c, minConsequence)
		}
	}
}

// TestAssess_M025_NoDowngrade is the RED->GREEN anchor (ticket (a)): a persist-class event on a
// co-resident GPU pod (arm (2) => gpu-side-channel) must keep the persist stage, not be
// downgraded to the AI/topology stage. OLD code (stage = ai) returned gpu-side-channel.
func TestAssess_M025_NoDowngrade(t *testing.T) {
	m := NewModel()
	v := &model.WorkloadView{
		Pod:     model.Pod{Namespace: "ns", Name: "p", HasGPU: true, Ready: true, Age: time.Hour},
		Physics: model.PhysicsWitness{GPUPresent: true, CoResidency: 2, ModelRarity: 1.2, SMOccupancy: 0}, // arm (2), not (1)
		Events:  []model.SecurityEventInfo{{Type: v1beta1.TypePanic, ThreatLevel: "high", TargetsPod: true, Age: time.Minute}},
	}
	a := m.Assess(v, m025Policy(), 600, 3600)
	if a.StageName != "persist" {
		t.Fatalf("(a) merged stage = %q, want persist (detector floor must not be downgraded by topology)", a.StageName)
	}
	if a.EventStageName != "persist" || a.AIStageName != "gpu-side-channel" {
		t.Errorf("record must attribute both inputs: event=%q ai=%q (want persist / gpu-side-channel)", a.EventStageName, a.AIStageName)
	}
	if a.StageMergeRule != "max-consequence" {
		t.Errorf("merge rule = %q, want max-consequence", a.StageMergeRule)
	}
}

// (b) escalation preserved: a model-theft AI stage (0.9) raises a recon base.
func TestAssess_M025_EscalationPreserved(t *testing.T) {
	m := NewModel()
	v := &model.WorkloadView{
		Pod:     model.Pod{Namespace: "ns", Name: "p", HasGPU: true, Ready: true, Age: time.Hour},
		Physics: model.PhysicsWitness{GPUPresent: true, CoResidency: 2, ModelRarity: 1.5, SMOccupancy: 0.9, SMSource: "DCGM_FI_PROF_SM_ACTIVE"}, // arm (1)
	}
	a := m.Assess(v, m025Policy(), 600, 3600)
	if a.StageName != "model-theft" {
		t.Fatalf("(b) merged stage = %q, want model-theft (escalation must be preserved)", a.StageName)
	}
}

// (c) no events: merged == the AI stage (unchanged until M-26 gates arm (1)).
func TestAssess_M025_NoEventsIsAIStage(t *testing.T) {
	m := NewModel()
	v := &model.WorkloadView{
		Pod:     model.Pod{Namespace: "ns", Name: "p", HasGPU: true, Ready: true, Age: time.Hour},
		Physics: model.PhysicsWitness{GPUPresent: true, CoResidency: 2, ModelRarity: 1.2, SMOccupancy: 0}, // arm (2)
	}
	a := m.Assess(v, m025Policy(), 600, 3600)
	if a.StageName != "gpu-side-channel" {
		t.Errorf("(c) no events: merged = %q, want gpu-side-channel (AI stage, arm (1) still fires — M-26 territory)", a.StageName)
	}
}

// (d) AI arm silent (non-AI workload): merged == the event stage.
func TestAssess_M025_SilentAIIsEventStage(t *testing.T) {
	m := NewModel()
	v := &model.WorkloadView{
		Pod:    model.Pod{Namespace: "ns", Name: "p", Ready: true, Age: time.Hour}, // no GPU, no ModelID => aiStageFromView false
		Events: []model.SecurityEventInfo{{Type: v1beta1.TypePanic, ThreatLevel: "high", TargetsPod: true, Age: time.Minute}},
	}
	a := m.Assess(v, m025Policy(), 600, 3600)
	if a.StageName != "persist" {
		t.Errorf("(d) silent AI: merged = %q, want persist (event stage)", a.StageName)
	}
	if a.AIStageName != "" {
		t.Errorf("silent AI must record ai=\"\", got %q", a.AIStageName)
	}
}
