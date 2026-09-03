/*
 * Phorvex — T1-A: the decision trace carries the model-theft gate's ACTIVITY input, with
 * honest-absent semantics. Ships with the fix (references Inputs.Leakage).
 */

package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func TestDecisionTraceRecordsLeakageWithHonestAbsence(t *testing.T) {
	// honest-absent: SMOccupancy unmeasured (SMSource == "") must NOT serialize as a measured 0,
	// even with VRAM saturated — the exact live shape from bus 084.
	view := covView("leak", true, 2*time.Hour, false)
	view.Physics.GPUPresent = true
	view.Physics.VRAMFraction, view.Physics.VRAMPresent = 0.9931, true
	view.Physics.SMOccupancy, view.Physics.SMSource = 0, ""
	trace := fixedTraceEngine().Decide([]*model.WorkloadView{view}, decisionTracePolicy(1, true))[0].Trace
	if trace == nil {
		t.Fatal("trace missing")
	}
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	if trace.Inputs.Leakage.Present {
		t.Fatalf("unmeasured SM occupancy serialized as a measured leakage: %+v", trace.Inputs.Leakage)
	}
	// The builder honours VRAMPresent when the witness carries it. LIVE, this flag is dark until
	// M-152 lands: stampGPU (platform/adapters.go:19-29) never copies VRAMPresent across the
	// adapter seam, so real records show vramFraction {present:false} even with DCGM flowing.
	// This assertion is about the builder, not the seam.
	if !trace.Inputs.VRAMFraction.Present {
		t.Fatalf("VRAMFraction lost presence; the trace must still show residency beside the gate input")
	}

	// measured: Leakage == SMOccupancy exactly, VRAM contributes nothing.
	view.Physics.SMOccupancy, view.Physics.SMSource = 0.85, "DCGM_FI_PROF_SM_ACTIVE"
	measured := fixedTraceEngine().Decide([]*model.WorkloadView{view}, decisionTracePolicy(1, true))[0].Trace
	if !measured.Inputs.Leakage.Present || measured.Inputs.Leakage.Value != 0.85 {
		t.Fatalf("measured leakage = %+v, want present 0.85 (SM only; VRAM=0.9931 must not add)", measured.Inputs.Leakage)
	}
	// canonical form keeps the field (it is registered in Canonical(), not silently dropped)
	if c := measured.Canonical(); !c.Inputs.Leakage.Present || c.Inputs.Leakage.Value != 0.85 {
		t.Fatalf("Canonical() dropped or altered leakage: %+v", c.Inputs.Leakage)
	}
}
