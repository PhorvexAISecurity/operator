package physics

import (
	"github.com/phorvex/phorvex/internal/model"
	"math"
	"testing"
)

// Kept compatible with pre-M115 SHA 5fe1c8e for actual old-code negative controls.
func TestM115HistoricalPresentOnlyDenominator(t *testing.T) {
	v := &model.WorkloadView{Telemetry: model.Telemetry{ConnCount: model.PresentSignal(300, "fixture"), ReqRate: model.PresentSignal(1, "fixture")}}
	if got := (littlesLaw{}).Residual(v, model.Policy{}); math.Abs(got-1) > 1e-9 {
		t.Fatalf("one present magnitude=1: got %g, want 1", got)
	}
}
func TestM115HistoricalQueueUnitDependence(t *testing.T) {
	run := func(rate float64) float64 {
		return (littlesLaw{}).Residual(&model.WorkloadView{Telemetry: model.Telemetry{QueueDepth: model.PresentSignal(10, "fixture"), ReqRate: model.PresentSignal(rate, "fixture")}}, model.Policy{})
	}
	a, b := run(5), run(300)
	if a != b || a != 0 {
		t.Fatalf("disabled count-minus-rate: per-second=%g per-minute=%g, want both 0", a, b)
	}
}
