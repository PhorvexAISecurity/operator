package physics

import (
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// flow_residual_test.go — PHORVEXSEC-198 / M-115 (M_115_MATH_RULING.md Q2–Q10).

func flowTel(L, lam, W float64) model.Telemetry {
	return model.Telemetry{
		InFlightMean:   model.PresentSignal(L, "prom"),
		CompletionRate: model.PresentSignal(lam, "prom"),
		MeanSojournSec: model.PresentSignal(W, "prom"),
	}
}

// Predicted-output vector: the six numeric cases to 1e-9, plus the two absent cases.
func TestFlowResidualMatchesRulingVector(t *testing.T) {
	cases := []struct {
		L, lam, W float64
		r         float64
	}{
		{10, 5, 2, 0}, {15, 5, 1, 0.5}, {5, 5, 3, -0.5}, {5, 0, 2, 1}, {0, 5, 2, -1}, {0, 0, 2, 0},
	}
	for _, c := range cases {
		fr := FlowResidual(flowTel(c.L, c.lam, c.W))
		if !fr.Present || fr.Basis != FlowBasisLittle || math.Abs(fr.Residual-c.r) > 1e-9 || math.Abs(fr.Expected-c.lam*c.W) > 1e-9 || math.Abs(fr.Magnitude-math.Abs(c.r)) > 1e-9 {
			t.Fatalf("L=%v λ=%v W=%v → %+v, ruling says r=%v", c.L, c.lam, c.W, fr, c.r)
		}
	}
	// W unavailable → absent; percentile-only latency (P99Ms) is not W → absent.
	noW := model.Telemetry{InFlightMean: model.PresentSignal(10, "prom"), CompletionRate: model.PresentSignal(5, "prom")}
	if fr := FlowResidual(noW); fr.Present || fr.Basis != FlowBasisAbsent || fr.Reason != "mean-sojourn-unavailable" {
		t.Fatalf("W unavailable → %+v, want absent/mean-sojourn-unavailable", fr)
	}
	noW.P99Ms = model.PresentSignal(950, "prom")
	if fr := FlowResidual(noW); fr.Present || fr.Reason != "mean-sojourn-unavailable" {
		t.Fatalf("p99-only latency must not stand in for W: %+v", fr)
	}
	stale := flowTel(10, 5, 2)
	stale.MeanSojournSec.State = model.Stale
	if fr := FlowResidual(stale); fr.Present {
		t.Fatalf("stale W must be absent: %+v", fr)
	}
}

// Unit invariance (P-DIMENSIONS): reciprocal conversion of λ and W leaves E and r unchanged.
func TestFlowResidualUnitInvariance(t *testing.T) {
	a := FlowResidual(flowTel(15, 5, 1))        // req/s, s
	b := FlowResidual(flowTel(15, 0.005, 1000)) // req/ms, ms
	if math.Abs(a.Expected-b.Expected) > 1e-9 || math.Abs(a.Residual-b.Residual) > 1e-9 || a.Expected != 5 {
		t.Fatalf("unit conversion changed the result: %+v vs %+v", a, b)
	}
}

// Antisymmetry, exact agreement, symmetric saturation, monotonicity, boundedness, finiteness.
func TestFlowResidualProperties(t *testing.T) {
	for _, L := range []float64{0, 0.5, 1, 7, 100} {
		for _, E := range []float64{0, 0.5, 1, 7, 100} {
			r1 := FlowResidual(flowTel(L, E, 1)).Residual // E = λ·1
			r2 := FlowResidual(flowTel(E, L, 1)).Residual
			if math.Abs(r1+r2) > 1e-12 {
				t.Fatalf("antisymmetry broken at L=%v E=%v: %v vs %v", L, E, r1, r2)
			}
			if r1 < -1 || r1 > 1 || !finite(r1) {
				t.Fatalf("range/finite broken at L=%v E=%v: %v", L, E, r1)
			}
			if L == E && r1 != 0 {
				t.Fatalf("exact agreement L=E=%v must give 0, got %v", L, r1)
			}
		}
	}
	if FlowResidual(flowTel(3, 0, 5)).Residual != 1 || FlowResidual(flowTel(0, 3, 5)).Residual != -1 {
		t.Fatal("symmetric saturation broken")
	}
	// monotone: r non-decreasing in L, non-increasing in E
	prev := -2.0
	for L := 0.0; L <= 20; L += 0.5 {
		r := FlowResidual(flowTel(L, 2, 2)).Residual
		if r < prev-1e-12 {
			t.Fatalf("not monotone in L at %v", L)
		}
		prev = r
	}
	prev = 2.0
	for E := 0.0; E <= 20; E += 0.5 {
		r := FlowResidual(flowTel(4, E, 1)).Residual
		if r > prev+1e-12 {
			t.Fatalf("not monotone in E at %v", E)
		}
		prev = r
	}
	for _, bad := range []float64{math.NaN(), math.Inf(1), -1} {
		if fr := FlowResidual(flowTel(bad, 5, 2)); fr.Present || fr.Reason == "" {
			t.Fatalf("invalid L=%v must be absent with a reason: %+v", bad, fr)
		}
	}
}

// Aggregation (Q8/Q9): present-only denominator, measured zero counts, no signed cancellation.
func TestAggregatePresentOnly(t *testing.T) {
	c := func(m float64) Component { return Component{Present: true, Magnitude: m} }
	absent := Component{Reason: "x"}
	if a, ok := Aggregate([]Component{c(1), c(0.5), absent, absent}); !ok || math.Abs(a-0.75) > 1e-12 {
		t.Fatalf("{1,0.5,absent,absent} → %v (old code: 0.375 by ÷4)", a)
	}
	if a, ok := Aggregate([]Component{c(1), c(0), absent}); !ok || math.Abs(a-0.5) > 1e-12 {
		t.Fatalf("measured zero must stay in the denominator: %v", a)
	}
	// magnitudes of r=+1 and r=−1 both count as 1: no cancellation
	if a, ok := Aggregate([]Component{c(math.Abs(1.0)), c(math.Abs(-1.0))}); !ok || a != 1 {
		t.Fatalf("no-cancellation broken: %v", a)
	}
	if _, ok := Aggregate([]Component{absent, absent}); ok {
		t.Fatal("all-absent must be absent, not 0-present")
	}
}

// Dilution (old-fails): one present component reads its own magnitude, not 0.7·x + 0.3·x/4.
func TestResidualNoDilutionByAbsentComponents(t *testing.T) {
	tel := model.Telemetry{ConnCount: model.PresentSignal(300, "cadvisor"), ReqRate: model.PresentSignal(1, "prom")} // fan-out saturates at 1
	got := (littlesLaw{}).Residual(&model.WorkloadView{Telemetry: tel}, model.Policy{})
	if math.Abs(got-1.0) > 1e-12 {
		t.Fatalf("lone present component = %.4f, want 1.0 (old code: 0.775 from the ÷4 mean blend)", got)
	}
	cs := Components(&model.WorkloadView{Telemetry: tel})
	present := 0
	for _, c := range cs {
		if c.Present {
			present++
		}
	}
	if present != 1 {
		t.Fatalf("present components = %d, want 1 (others absent, not measured zero): %+v", present, cs)
	}
}

// Unit dependence (old-fails): the same physical situation in different units gives the same
// aggregate; the old queue term flipped from 0.298 to 0 when the rate was expressed per minute.
func TestResidualFlowTermIsUnitInvariantEndToEnd(t *testing.T) {
	// The flow term is per-class gated since the M-115 conformance round, so the fixture
	// activates its own class; unit invariance is a property of the ruled mathematics, not of
	// the gate.
	prev := ActivatedFlowClasses()
	t.Cleanup(func() { ConfigureFlowActivation(prev) })
	ConfigureFlowActivation([]string{"ns"})
	view := func(t model.Telemetry) *model.WorkloadView {
		return &model.WorkloadView{Pod: model.Pod{Namespace: "ns"}, Telemetry: t}
	}
	a := (littlesLaw{}).Residual(view(flowTel(15, 5, 1)), model.Policy{})
	b := (littlesLaw{}).Residual(view(flowTel(15, 300, 1.0/60)), model.Policy{}) // per minute
	if math.Abs(a-b) > 1e-9 || math.Abs(a-0.5) > 1e-9 {
		t.Fatalf("aggregate differs across units: %v vs %v (want 0.5 both)", a, b)
	}
}
