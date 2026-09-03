package decision

import (
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// PHORVEXSEC-199 / M-111 end to end: a NaN physics multiplier on one asset leaves every
// numeric decision field finite, records factsAbsentReason on that asset, and does not touch
// the other asset. Old code: NaN CoveredWeight/gain and undefined selection.
func TestDecideRecordsAbsentFactsInsteadOfNaN(t *testing.T) {
	poisoned := covView("poisoned", true, 2*time.Hour, false)
	poisoned.Physics.ImageRarity = math.NaN()
	healthy := covView("healthy", true, 2*time.Hour, false)
	// The shipped UCW profile is the one that reads physics (dispersion); the standard profile
	// never touches ImageRarity, so the poison must go through ucw-recon to reach a weight.
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon not registered")
	}
	e := NewCoverageEngine()
	e.Recon = profile
	pol := covPolicy(2)
	pol.TraceEnabled = true
	decs := e.Decide([]*model.WorkloadView{poisoned, healthy}, pol)
	var sawPoisoned, sawHealthy bool
	for _, d := range decs {
		for name, val := range map[string]float64{"coverageValue": d.CoverageValue, "coveredWeight": d.CoveredWeight, "net": d.Net, "cost": d.Cost, "perDollar": d.PerDollar} {
			if math.IsNaN(val) || math.IsInf(val, 0) {
				t.Fatalf("%s/%s %s = %v (old behaviour: NaN propagated)", d.Pod, d.Action, name, val)
			}
		}
		if d.Trace == nil {
			continue
		}
		switch d.Pod {
		case "poisoned":
			sawPoisoned = true
			if d.Trace.Inputs.FactsAbsentReason != "non-finite-input: dispersion" || d.Trace.Inputs.DispersionMult.Present {
				t.Fatalf("poisoned trace inputs = %+v, want factsAbsentReason and absent dispersionMult", d.Trace.Inputs)
			}
			if d.Selected || d.Action != model.ActionNoop {
				t.Fatalf("poisoned asset must not be selectable: %s selected=%v", d.Action, d.Selected)
			}
		case "healthy":
			sawHealthy = true
			if d.Trace.Inputs.FactsAbsentReason != "" {
				t.Fatalf("healthy asset carries an absent reason: %q", d.Trace.Inputs.FactsAbsentReason)
			}
		}
	}
	if !sawPoisoned || !sawHealthy {
		t.Fatalf("traces missing: poisoned=%v healthy=%v", sawPoisoned, sawHealthy)
	}
}
