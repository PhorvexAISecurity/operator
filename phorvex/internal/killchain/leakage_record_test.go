/*
 * Phorvex — T1-A: the recorded gate input. Ships WITH the fix (references Assessment.Leakage,
 * which does not exist pre-fix), so it is deliberately separate from leakage_gate_test.go —
 * the red-before-green lock must compile on the pre-fix build.
 */

package killchain

import "testing"

// The value the trace records must be the value the gate tested — and that value must be
// activity only. Three cases pin the semantics:
//
//	measured activity → Leakage == SMOccupancy exactly (VRAM contributes nothing)
//	honest-absent     → Leakage == 0 with SMSource == "" (unmeasured, not idle)
//	saturated VRAM    → still 0 (the allocation term is gone, not down-weighted)
func TestLeakageRecord_MatchesGateInput(t *testing.T) {
	m := NewModel()
	cases := []struct {
		name     string
		sm, vram float64
		source   string
		want     float64
	}{
		{"measured activity, VRAM ignored", 0.85, 0.9931, "DCGM_FI_PROF_SM_ACTIVE", 0.85},
		{"honest-absent SM reads as 0, not as VRAM", 0, 0.9931, "", 0},
		{"saturated VRAM adds nothing at any weight", 0.30, 1.0, "DCGM_FI_PROF_SM_ACTIVE", 0.30},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := m.Assess(gpuView(c.sm, c.vram, c.source), ctxPolicy(), 60, 3600)
			if a.Leakage != c.want {
				t.Fatalf("Assessment.Leakage = %v, want %v (sm=%v vram=%v source=%q)", a.Leakage, c.want, c.sm, c.vram, c.source)
			}
			if a.Leakage != leakageOf(gpuView(c.sm, c.vram, c.source).Physics) {
				t.Fatalf("recorded Leakage diverged from the gate helper — two sources of truth")
			}
		})
	}
}

// Non-AI workloads must be byte-identical to before: Leakage is recorded (0) but the generic
// chain is untouched. Guards the honest-absent contract at the top of aiStageFromView.
func TestLeakageRecord_GenericChainUnchanged(t *testing.T) {
	m := NewModel()
	v := gpuView(0.99, 0.99, "DCGM_FI_PROF_SM_ACTIVE")
	v.Pod.HasGPU, v.Pod.ModelID = false, "" // not an AI workload
	a := m.Assess(v, ctxPolicy(), 60, 3600)
	if a.AIClassified {
		t.Fatalf("non-AI pod must not be AI-classified regardless of physics")
	}
	if a.Stage == StageModelTheft || a.Stage == StageGPUSideChannel {
		t.Fatalf("non-AI pod reached an AI GPU stage: %s", a.StageName)
	}
}
