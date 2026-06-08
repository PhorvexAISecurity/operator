package adaptive

import (
	"math"
	"testing"
)

func TestLearnerEstimatesPeriodicInterval(t *testing.T) {
	l := NewLearner()
	// A perfectly periodic 6s cadence across two trials.
	l.ObserveRotations([]float64{100, 106, 112, 118})
	l.ObserveRotations([]float64{200, 206, 212})
	est := l.EstimatedInterval()
	if math.Abs(est-6) > 0.001 {
		t.Fatalf("estimated interval want ~6 got %v", est)
	}
	if reg := l.GapRegularity(); reg < 0.99 {
		t.Fatalf("periodic cadence should be highly regular, got %v", reg)
	}
}

func TestLearnerRandomIsIrregular(t *testing.T) {
	l := NewLearner()
	// Memoryless-looking gaps: high variance => low regularity.
	l.ObserveRotations([]float64{0, 1, 12, 13, 30, 31, 60})
	if reg := l.GapRegularity(); reg > 0.6 {
		t.Fatalf("irregular cadence should have low regularity, got %v", reg)
	}
}

func TestPlanDelayZeroWithoutLearning(t *testing.T) {
	l := NewLearner()
	if d := l.PlanDelaySeconds(0); d != 0 {
		t.Fatalf("no learned rhythm => strike now (delay 0), got %v", d)
	}
}

func TestPlanDelayBoundedByInterval(t *testing.T) {
	l := NewLearner()
	l.ObserveRotations([]float64{0, 10, 20, 30})
	d := l.PlanDelaySeconds(3)
	if d < 0 || d > 10 {
		t.Fatalf("planned delay must be in [0, est=10], got %v", d)
	}
}

func TestObservationsCounted(t *testing.T) {
	l := NewLearner()
	l.ObserveRotations([]float64{1, 2, 3})
	if l.Observations() != 3 {
		t.Fatalf("observations want 3 got %d", l.Observations())
	}
}
