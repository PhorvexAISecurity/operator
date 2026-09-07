/*
 * Phorvex — NaN PROPERTY TEST at the Decide() boundary.
 *
 * The cost-layer unit tests prove sat()/satRLS()/Predict() are NaN-safe in isolation. This test
 * asserts the property that actually matters in production: NO cost reaching a DECISION is ever
 * NaN or Inf, no matter what the telemetry looks like.
 *
 * Why the boundary matters. A NaN cost does not crash the engine — it corrupts it silently. The
 * greedy selector compares `gain > best`, and every comparison against NaN is false, so a poisoned
 * candidate is never selected and the tick degrades to noop while REPORTING a normal decision. The
 * safety laws run before cost, so nothing unsafe happens; effectiveness just quietly stops. That is
 * the worst failure mode this engine has, and it is invisible without this assertion.
 *
 * This test FAILS on the unguarded code (NaN telemetry -> NaN Cost/Net on the emitted decision)
 * and passes once the clamps and the ingest boundary reject non-finite values.
 */

package decision

import (
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// poisonValues are every non-finite (and one negative) value a real telemetry source can produce.
// Prometheus serves the literal string "NaN" for 0/0 and for a stale series, and ParseFloat
// accepts "NaN"/"Inf" without error, so these are reachable inputs and not synthetic paranoia.
var poisonValues = []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1, 0}

func poisonedView(ns, name string, v float64, gpu bool, phase model.WorkloadPhase) *model.WorkloadView {
	return &model.WorkloadView{
		Pod: model.Pod{
			Namespace: ns, Name: name, UID: name + "-uid",
			Ready: true, Age: 30 * time.Minute, HasGPU: gpu,
			Labels: map[string]string{"app": name},
		},
		Phase: phase,
		Telemetry: model.Telemetry{
			ReqRate: telSigNP(v), ConnCount: telSigNP(v),
		},
		BlastRadius:        0.5,
		ExposureByVariable: map[string]time.Duration{"podIdentity": 20 * time.Minute, "nodePlacement": 20 * time.Minute},
	}
}

func nanPolicy() model.Policy {
	return model.Policy{
		Tenant: "t", Mode: "active",
		NormSparsity: 0.4, FlowDisruption: 0.6,
		Lambda: 0.5, MaxMovesPerTick: 2,
	}
}

// TestDecideNeverEmitsNonFiniteCost is the property: for every poisoned telemetry value, on every
// engine, every emitted decision carries finite Cost / value / Net / CHi-derived numbers.
func TestDecideNeverEmitsNonFiniteCost(t *testing.T) {
	pol := nanPolicy()
	for _, v := range poisonValues {
		for _, gpu := range []bool{false, true} {
			for _, phase := range []model.WorkloadPhase{"", model.PhaseColdStarting, model.PhaseWarm, model.PhaseIdle} {
				views := []*model.WorkloadView{
					poisonedView("ns", "a", v, gpu, phase),
					poisonedView("ns", "b", v, !gpu, phase),
				}
				for _, tc := range []struct {
					name string
					dec  []model.Decision
				}{
					{"CoverageEngine", NewCoverageEngine().Decide(views, pol)},
				} {
					for _, d := range tc.dec {
						check := func(field string, x float64) {
							if math.IsNaN(x) || math.IsInf(x, 0) {
								t.Errorf("%s: telemetry=%v gpu=%v phase=%q -> decision %s/%s action=%s has non-finite %s = %v",
									tc.name, v, gpu, phase, d.Namespace, d.Pod, d.Action, field, x)
							}
						}
						check("Cost", d.Cost)
						check("CoverageValue", d.CoverageValue)
						check("ThreatRisk", d.ThreatRisk)
						check("Net", d.Net)
						check("AssetValue", d.AssetValue)
						check("BlastRadius", d.BlastRadius)
						check("BlindCost", d.BlindCost)
					}
				}
			}
		}
	}
}

// TestDecideStaysSelectableUnderPoisonedTelemetry is the SECOND half of the property, and the one
// that captures the real damage: a NaN cost does not merely look ugly in the audit, it makes the
// greedy comparison `gain > best` false forever, so the engine silently stops acting. With a
// genuinely actionable view, poisoned telemetry must NOT change whether a move is selected.
func TestDecideStaysSelectableUnderPoisonedTelemetry(t *testing.T) {
	pol := nanPolicy()
	// a clean baseline: overdue exposure on a plain pod => the engine should select something
	clean := poisonedView("ns", "a", 0, false, model.PhaseWarm)
	clean.Telemetry = model.Telemetry{} // no telemetry at all
	baseline := NewCoverageEngine().Decide([]*model.WorkloadView{clean}, pol)
	wantSelected := 0
	for _, d := range baseline {
		if d.Selected {
			wantSelected++
		}
	}

	for _, v := range []float64{math.NaN(), math.Inf(1)} {
		poisoned := poisonedView("ns", "a", v, false, model.PhaseWarm)
		got := NewCoverageEngine().Decide([]*model.WorkloadView{poisoned}, pol)
		gotSelected := 0
		for _, d := range got {
			if d.Selected {
				gotSelected++
			}
			if math.IsNaN(d.Cost) || math.IsInf(d.Cost, 0) {
				t.Fatalf("telemetry=%v: emitted a non-finite Cost (%v) — the selector's gain>best is now always false", v, d.Cost)
			}
		}
		if gotSelected != wantSelected {
			t.Errorf("telemetry=%v changed selection: %d selected vs %d on clean telemetry — poisoned input must be neutral, not silencing",
				v, gotSelected, wantSelected)
		}
	}
}

// telSigNP mirrors ingest typing for the poison fuzz: non-finite => State=Error, else Present.
func telSigNP(v float64) model.Signal {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return model.Signal{Value: v, State: model.Error}
	}
	return model.PresentSignal(v, "test")
}
