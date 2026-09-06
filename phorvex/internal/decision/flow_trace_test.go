package decision

import (
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/physics"
)

// PHORVEXSEC-198 / M-115: the decision trace carries the flow basis record — inputs, window,
// units, expected, signed residual, magnitude, presence, reason and every component.
func TestTraceRecordsFlowBasis(t *testing.T) {
	// M-115 conformance round: the flow residual is now per-class activated, so this fixture
	// activates its own namespace; every other class records absent/class-not-activated.
	prevClasses := physics.ActivatedFlowClasses()
	t.Cleanup(func() { physics.ConfigureFlowActivation(prevClasses) })
	physics.ConfigureFlowActivation([]string{"ns"})
	pol := covPolicy(2)
	pol.TraceEnabled = true
	e := NewCoverageEngine()
	e.Now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	served := covView("served", true, 2*time.Hour, false)
	served.Telemetry.InFlightMean = model.PresentSignal(15, "prom")
	served.Telemetry.CompletionRate = model.PresentSignal(5, "prom")
	served.Telemetry.MeanSojournSec = model.PresentSignal(1, "prom")
	plain := covView("plain", true, 2*time.Hour, false)
	for _, d := range e.Decide([]*model.WorkloadView{served, plain}, pol) {
		f := d.Trace.Inputs.Flow
		switch d.Pod {
		case "served":
			if !f.Present || f.Basis != "littles-law" || math.Abs(f.Residual.Value-0.5) > 1e-9 || !f.Residual.Present || f.Expected.Value != 5 || f.WStatistic != "mean-sojourn" || f.Window != "5m" {
				t.Fatalf("served flow record = %+v", f)
			}
		case "plain":
			if f.Present || f.Basis != "absent" || f.Reason != "mean-sojourn-unavailable" || f.Residual.Present {
				t.Fatalf("plain flow record = %+v, want absent with reason", f)
			}
		}
		if len(f.Components) != 5 {
			t.Fatalf("%s: components = %d, want 5", d.Pod, len(f.Components))
		}
	}
}
