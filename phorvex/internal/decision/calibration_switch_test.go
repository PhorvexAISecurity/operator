package decision

import (
	"testing"
)

// calibration_switch_test.go — PHVX-2 / PHORVEXSEC-84, the engine side of the off-switch.
//
// The RLS is PER TENANT and the buckets are created lazily, so a switch applied only to the buckets
// that happen to exist would silently miss the next tenant the engine sees.

func TestFreezeAppliesToTenantsCreatedLater(t *testing.T) {
	e := NewCoverageEngine()
	early := e.costFor("tenant-a") // exists before the switch is thrown
	e.SetCostCalibrationFrozen(true)
	late := e.costFor("tenant-b") // first seen AFTER

	if !early.RLS.Frozen() {
		t.Error("an existing tenant bucket was not frozen")
	}
	if !late.RLS.Frozen() {
		t.Error("a tenant first seen after the freeze started learning behind the operator's back — " +
			"the flag must be remembered and applied when a bucket is created")
	}
	if !e.CostCalibrationFrozen() {
		t.Error("the engine must report the state for audit")
	}
}

// TestFreezeIsIdempotent matters because the switch is evaluated EVERY tick. Freezing reverts theta,
// so a non-idempotent implementation would wipe calibration once per tick forever once unfrozen and
// re-frozen, and — worse — re-applying "frozen" every tick would keep resetting an already-frozen
// learner, hiding whether it was ever unfrozen.
func TestFreezeIsIdempotent(t *testing.T) {
	e := NewCoverageEngine()
	c := e.costFor("t")
	f, y := probeObs()
	for i := 0; i < 50; i++ {
		c.RLS.Update(f, y)
	}
	e.SetCostCalibrationFrozen(false) // already false: must NOT revert the learned theta
	if !c.RLS.Primed() {
		t.Fatal("setting the switch to its current value must be a no-op; it discarded the calibration")
	}
	e.SetCostCalibrationFrozen(true)
	e.SetCostCalibrationFrozen(true) // repeated every tick
	if !c.RLS.Frozen() {
		t.Error("repeated freezes must leave the learner frozen")
	}
}

func probeObs() ([6]float64, float64) {
	var f [6]float64
	f[0], f[2], f[4] = 1, 1, 1
	return f, 0.05
}
