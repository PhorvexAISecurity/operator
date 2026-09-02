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
// POST-FIX: leakage = SMOccupancy = 0 → arm (1) skipped → arm (2) → StageGPUSideChannel.
func TestLeakageGate_LoadedIdleIsNotTheft(t *testing.T) {
	m := NewModel()
	a := m.Assess(gpuView(0, 0.9931, ""), ctxPolicy(), 60, 3600)
	if !a.AIClassified {
		t.Fatalf("fixture must be AI-classified (HasGPU + ModelID); got generic chain")
	}
	if a.Stage == StageModelTheft {
		t.Fatalf("T1-A regression: a loaded-idle GPU (VRAM=0.9931, SM=0) reads model-theft — "+
			"residency alone satisfied the leakage gate; got stage=%s", a.StageName)
	}
	if a.Stage != StageGPUSideChannel {
		t.Fatalf("loaded-idle co-resident rare model must fall through to gpu-side-channel, got %s", a.StageName)
	}
}

// Fixture (b) — POSITIVE CONTROL: an extraction-shaped load, SMOccupancy sustained ≥ 0.8 with a
// real profiling source. Must read model-theft on BOTH builds (pre-fix: 0.85+0.99 > 0.8;
// post-fix: 0.85 > 0.8). This proves the rig can still detect theft after the term is dropped;
// it is NOT a red-before-green test and the ticket's "both fail on current code" is wrong for
// this fixture — dropping a non-negative term can only ever lower leakage.
func TestLeakageGate_ExtractionLoadIsTheft_PositiveControl(t *testing.T) {
	m := NewModel()
	a := m.Assess(gpuView(0.85, 0.9931, "DCGM_FI_PROF_SM_ACTIVE"), ctxPolicy(), 60, 3600)
	if a.Stage != StageModelTheft {
		t.Fatalf("positive control: sustained SM occupancy 0.85 must read model-theft, got %s", a.StageName)
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

// Fixture (e) — K3 02-critique B.1: the DECLARED downgrade this fix unmasks. On a ≥2-model
// topology, a GPU pod with a LIVE persist-class event (Panic, high) — detector evidence implying
// the persist stage (consequence 0.6) — reads:
//
//	PRE-FIX:  arm (1) fires on residency alone → model-theft (0.9). The inflation masked the
//	          arm ordering entirely.
//	POST-FIX: arm (1) is dark (SM unmeasured); arm (2) side-channel (0.15) is checked BEFORE
//	          arm (3) prompt-inject-persist and Assess overwrites the event stage with a bare
//	          `=` (hazard.go:291-293) → gpu-side-channel, BELOW the event-implied stage.
//
// This is M-25's override surface, unchanged in kind, direction now deflation instead of
// inflation. Declared in 01-proposal §4 / 03-decision; the re-ordering is M-25's fix, not
// T1-A's (one issue per cycle). This test pins the declared post-fix behavior so that when M-25
// lands, its diff flips exactly this assertion and nothing else here.
func TestLeakageGate_LivePersistEventOnTwoModelFleet_DeclaredDowngrade(t *testing.T) {
	m := NewModel()
	v := gpuView(0, 0.9931, "") // bus-084 physics, on a 2-model / 2-namespace topology
	v.Events = []model.SecurityEventInfo{{Type: v1beta1.TypePanic, ThreatLevel: "high", TargetsPod: true}}
	a := m.Assess(v, ctxPolicy(), 60, 3600)
	if a.Stage == StageModelTheft {
		t.Fatalf("T1-A regression: residency + a live event still reads model-theft (stage=%s)", a.StageName)
	}
	if a.Stage != StageGPUSideChannel {
		t.Fatalf("declared post-fix stage for GPU pod + live persist event on a 2-model fleet is gpu-side-channel "+
			"(M-25 override, deflation direction); got %s — if this is persist-class, M-25 has landed and this pin must be retired", a.StageName)
	}
	if !a.HasEvidence {
		t.Fatalf("a live Panic event must keep HasEvidence true regardless of stage")
	}
}
