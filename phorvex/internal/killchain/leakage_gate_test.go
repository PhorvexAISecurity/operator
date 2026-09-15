/*
 * Phorvex — T1-A regression lock for the model-theft leakage gate (hazard.go:246/:249 @ 016361c).
 *
 * This file must COMPILE on the pre-fix build and be RED at the named assertion there
 * (FIX_LOOP §4 "red before green — and red for the right reason"). It therefore uses only
 * API that exists before the fix: Assess, NeutralPhysics, the Stage constants. Record-field
 * assertions (leakage / SMSource in the decision record) live in a separate file that ships
 * WITH the fix, because a test that fails to compile is red while testing nothing.
 */

package killchain

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/r6security/phoenix/api/v1beta1"
)

// gpuView builds the minimal AI workload that satisfies every conjunct of arm (1) EXCEPT the
// leakage term, so each test isolates exactly the term under test:
//
//	HasGPU (pod)  ·  CoResidency > 1  ·  ModelRarity > 1.3  ·  ModelID set (AI classification)
func gpuView(sm, vram float64, smSource string) *model.WorkloadView {
	ph := model.NeutralPhysics()
	ph.GPUPresent = true
	ph.CoResidency = 1.25 // two namespaces on the node: 1 + (2-1)/4 (platform.go:169)
	ph.ModelRarity = 2.0  // two distinct models, 1-of-2 each (platform.go:164)
	ph.SMOccupancy = sm
	ph.VRAMFraction = vram
	ph.SMSource = smSource
	return &model.WorkloadView{
		Pod:     model.Pod{Namespace: "t", Name: "vllm-a", HasGPU: true, ModelID: "qwen2.5-0.5b"},
		Physics: ph,
	}
}

// Fixture (a) — the live observation from bus 084 / VALIDATION_REPORT:1655:
// VRAMFraction = 0.9931 (14,990/15,094 MiB), SMOccupancy = 0, SMSource = "" (honest-absent on a
// T4 without DCP profiling). A loaded, IDLE model server.
//
// PRE-FIX: leakage = 0 + 0.9931 = 0.9931 > 0.8 → arm (1) → StageModelTheft. (RED here.)
// POST-M150: namespace dispersion cannot activate either GPU threat stage.
func TestLeakageGate_LoadedIdleIsNotTheft(t *testing.T) {
	m := NewModel()
	a := m.Assess(gpuView(0, 0.9931, ""), ctxPolicy(), 60, 3600)
	if a.AIClassified || a.Stage != StageRecon {
		t.Fatalf("namespace dispersion must not classify a loaded-idle GPU attack; got stage=%s ai=%v", a.StageName, a.AIClassified)
	}
}

// Activity remains recorded, but without a validated target/device-bound detector it cannot turn
// a namespace count into model-theft evidence.
func TestLeakageGate_ActivityAloneIsNotTheft(t *testing.T) {
	m := NewModel()
	a := m.Assess(gpuView(0.85, 0.9931, "DCGM_FI_PROF_SM_ACTIVE"), ctxPolicy(), 60, 3600)
	if a.Stage == StageModelTheft || a.Stage == StageGPUSideChannel || a.AIClassified {
		t.Fatalf("activity plus namespace dispersion must not infer a GPU attack, got %s", a.StageName)
	}
}

// Fixture (c) — the boundary: SM exactly at the threshold must NOT fire (gate is strict >).
// Same on both builds when VRAM = 0; guards against anyone "fixing" 0.8 → 0.79 in passing
// (ticket trap: do not lower the threshold).
func TestLeakageGate_ThresholdIsStrict(t *testing.T) {
	m := NewModel()
	a := m.Assess(gpuView(0.80, 0, "DCGM_FI_PROF_SM_ACTIVE"), ctxPolicy(), 60, 3600)
	if a.Stage == StageModelTheft {
		t.Fatalf("leakage == 0.8 must not satisfy a strict > 0.8 gate; got model-theft")
	}
}

// Fixture (d) — allocation must contribute at NO weight (ticket trap: "do not add VRAMFraction
// back with a smaller weight"). SM just under threshold + VRAM saturated must not tip the gate
// post-fix. PRE-FIX this reads theft (0.79 + 1.0 > 0.8) → RED here too.
func TestLeakageGate_AllocationCarriesNoWeight(t *testing.T) {
	m := NewModel()
	a := m.Assess(gpuView(0.79, 1.0, "DCGM_FI_PROF_SM_ACTIVE"), ctxPolicy(), 60, 3600)
	if a.Stage == StageModelTheft {
		t.Fatalf("T1-A regression: VRAM allocation tipped an under-threshold SM reading into model-theft (stage=%s)", a.StageName)
	}
}

// A trusted persist-class event remains a positive AI control: prompt persistence is supported
// even though namespace-only GPU threat inference is unavailable.
func TestLeakageGate_LivePersistEventOnTwoModelFleet_NoDowngrade(t *testing.T) {
	m := NewModel()
	v := gpuView(0, 0.9931, "") // bus-084 physics, on a 2-model / 2-namespace topology
	v.Events = []model.SecurityEventInfo{{Type: v1beta1.TypePanic, ThreatLevel: "high", TargetsPod: true}}
	a := m.Assess(v, ctxPolicy(), 60, 3600)
	if a.Stage == StageModelTheft {
		t.Fatalf("T1-A regression: residency + a live event still reads model-theft (stage=%s)", a.StageName)
	}
	if a.Stage != StagePromptInjectPersist {
		t.Fatalf("a live persist event on a model server must classify prompt persistence; merged stage = %s "+
			"(event=%s ai=%s rule=%s)", a.StageName, a.EventStageName, a.AIStageName, a.StageMergeRule)
	}
	if !a.HasEvidence {
		t.Fatalf("a live Panic event must keep HasEvidence true regardless of stage")
	}
}
