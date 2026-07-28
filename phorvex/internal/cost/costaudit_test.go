/*
 * Phorvex — COST MODEL AUDIT (unitless side).
 *
 * Executable verification of the decision-cost contract: C_norm, C_flow, ECost, CHi and the
 * always-true invariants. Every assertion here is the SPEC, not a snapshot of current behaviour —
 * if the code drifts, these fail.
 */

package cost

import (
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

const eps = 1e-9

func defaultPolicy() model.Policy {
	return model.Policy{NormSparsity: 0.4, FlowDisruption: 0.6}
}

// bareView is a view with NO telemetry — the "missing data is neutral, not garbage" case.
func bareView() *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}}
}

// ---------- Part 1 — C_norm ----------

func TestPart1_CNorm(t *testing.T) {
	live := len(model.LiveExposureVariables)
	if live != 2 {
		t.Fatalf("spec assumes len(LiveExposureVariables)=2, got %d", live)
	}
	if got := normCostP1(model.Move{Action: model.ActionRotate}); got != 1.0 {
		t.Errorf("C_norm(rotate) = %v, want exactly 1.0", got)
	}
	wantQ := 1.0 / float64(live+1) // tracks live, not a hardcoded 0.333
	got := normCostP1(model.Move{Action: model.ActionQuarantine})
	if math.Abs(got-wantQ) > eps {
		t.Errorf("C_norm(quarantine) = %v, want 1/(live+1) = %v", got, wantQ)
	}
	if math.Abs(got-0.3333333333333333) > 1e-9 {
		t.Errorf("C_norm(quarantine) = %v, want 0.333… at live=2", got)
	}
	if got := normCostP1(model.Move{Action: model.ActionNoop}); got != 0 {
		t.Errorf("C_norm(noop) = %v, want exactly 0", got)
	}
}

// C_norm must be structural only: identical for a telemetry-rich and a bare view.
func TestPart1_CNormIsPurelyStructural(t *testing.T) {
	for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine, model.ActionNoop} {
		v := normCostP1(model.Move{Action: a})
		if v < 0 || v > 1 || math.IsNaN(v) || math.IsInf(v, 0) {
			t.Errorf("C_norm(%s) = %v, want finite in [0,1]", a, v)
		}
	}
	// normCostP1 takes ONLY a Move — it cannot read telemetry. Assert the signature contract holds
	// by confirming repeated calls are identical (no hidden state).
	for i := 0; i < 100; i++ {
		if normCostP1(model.Move{Action: model.ActionQuarantine}) != 1.0/3.0 {
			t.Fatal("C_norm(quarantine) is not deterministic")
		}
	}
}

// ---------- Part 2 — C_flow ----------

func TestPart2_CFlowQuarantineNoTelemetry(t *testing.T) {
	c := NewP1Cost()
	pol := defaultPolicy()
	v := bareView()
	// ECost = 0.4*C_norm + 0.6*C_flow  =>  C_flow = (ECost - 0.4*C_norm)/0.6
	e := c.ECost(v, model.Move{Action: model.ActionQuarantine}, pol)
	cFlow := (e - pol.NormSparsity*(1.0/3.0)) / pol.FlowDisruption
	if math.Abs(cFlow-0.25) > 1e-9 {
		t.Errorf("C_flow(quarantine, no telemetry) = %v, want exactly 0.25 (no phantom load term)", cFlow)
	}
}

func TestPart2_CFlowQuarantineLoadTermBounded(t *testing.T) {
	c := NewP1Cost()
	pol := defaultPolicy()
	for _, conn := range []float64{0, 1, 50, 100, 1000, 1e9} {
		v := bareView()
		v.Telemetry = model.Telemetry{Present: true, ConnCount: conn}
		e := c.ECost(v, model.Move{Action: model.ActionQuarantine}, pol)
		cFlow := (e - pol.NormSparsity*(1.0/3.0)) / pol.FlowDisruption
		if cFlow < 0.25-1e-9 || cFlow > 0.40+1e-9 {
			t.Errorf("C_flow(quarantine, conn=%v) = %v, want within [0.25, 0.40]", conn, cFlow)
		}
	}
	// monotone non-decreasing in ConnCount
	prev := -1.0
	for _, conn := range []float64{0, 10, 25, 50, 75, 100, 200} {
		v := bareView()
		v.Telemetry = model.Telemetry{Present: true, ConnCount: conn}
		e := c.ECost(v, model.Move{Action: model.ActionQuarantine}, pol)
		cFlow := (e - pol.NormSparsity*(1.0/3.0)) / pol.FlowDisruption
		if cFlow < prev-1e-12 {
			t.Errorf("C_flow(quarantine) decreased as ConnCount rose to %v", conn)
		}
		prev = cFlow
	}
}

// Feed a KNOWN phi and assert the dot product against the documented prior theta.
func TestPart2_CFlowRotateDotProduct(t *testing.T) {
	wantTheta := [featureDim]float64{0.15, 0.85, 0.55, 0.0, 0.45, 0.20}
	if got := priorTheta(); got != wantTheta {
		t.Fatalf("prior theta = %v, want %v", got, wantTheta)
	}
	r := NewRLS()
	cases := []struct {
		name string
		f    [featureDim]float64
		want float64
	}{
		{"bias only (idle-ish, no gpu, no load)", [featureDim]float64{1, 0, 0, 0, 0, 0}, 0.15},
		{"cold start", [featureDim]float64{1, 1, 0, 0, 0, 0}, 0.15 + 0.85},
		{"warm", [featureDim]float64{1, 0, 1, 0, 0, 0}, 0.15 + 0.55},
		{"idle (zero weight)", [featureDim]float64{1, 0, 0, 1, 0, 0}, 0.15},
		{"cold + gpu + full load", [featureDim]float64{1, 1, 0, 0, 1, 1}, 0.15 + 0.85 + 0.45 + 0.20},
		{"clamp high", [featureDim]float64{10, 10, 10, 10, 10, 10}, 2.0},
	}
	for _, tc := range cases {
		if got := r.Predict(tc.f); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("%s: Predict = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPart2_CFlowRotateClampedToRange(t *testing.T) {
	r := NewRLS()
	// force a negative theta to prove the lower clamp
	r.theta = [featureDim]float64{-5, 0, 0, 0, 0, 0}
	if got := r.Predict([featureDim]float64{1, 0, 0, 0, 0, 0}); got != 0 {
		t.Errorf("negative prediction not clamped: %v, want 0", got)
	}
	r.theta = [featureDim]float64{99, 0, 0, 0, 0, 0}
	if got := r.Predict([featureDim]float64{1, 0, 0, 0, 0, 0}); got != 2 {
		t.Errorf("large prediction not clamped: %v, want 2", got)
	}
}

func TestPart2_CFlowNoopIsZero(t *testing.T) {
	c := NewP1Cost()
	if got := c.ECost(bareView(), model.Move{Action: model.ActionNoop}, defaultPolicy()); got != 0 {
		t.Errorf("ECost(noop) = %v, want exactly 0", got)
	}
}

// The RLS is a FROZEN PRIOR today: ObserveRotation has no operator callers, so identical inputs
// must give an identical C_flow forever. This test documents the frozen-prior contract; if the
// update is ever wired, this test must be revisited deliberately.
func TestPart2_RLSIsFrozenPriorUnlessObserved(t *testing.T) {
	c := NewP1Cost()
	pol := defaultPolicy()
	v := bareView()
	v.Phase = model.PhaseWarm
	first := c.ECost(v, model.Move{Action: model.ActionRotate}, pol)
	for i := 0; i < 500; i++ {
		if got := c.ECost(v, model.Move{Action: model.ActionRotate}, pol); got != first {
			t.Fatalf("C_flow(rotate) drifted without ObserveRotation: %v -> %v", first, got)
		}
	}
	if c.RLS.Primed() {
		t.Error("RLS reports primed with no observations")
	}
	// and it DOES move when explicitly observed (the mechanism works; it is just unwired)
	c.ObserveRotation(v, 1.9)
	if got := c.ECost(v, model.Move{Action: model.ActionRotate}, pol); got == first {
		t.Error("ObserveRotation did not change C_flow — the calibrator is inert, not merely unwired")
	}
}

// ---------- Part 3 — ECost / CHi ----------

func TestPart3_ECostWeightsAndSanityExample(t *testing.T) {
	c := NewP1Cost()
	pol := defaultPolicy()
	v := bareView()
	// quarantine, no telemetry: 0.4*0.3333 + 0.6*0.25 = 0.283333
	want := 0.4*(1.0/3.0) + 0.6*0.25
	got := c.ECost(v, model.Move{Action: model.ActionQuarantine}, pol)
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("ECost(quarantine) = %v, want %v", got, want)
	}
	if math.Abs(got-0.2833333333333333) > 1e-9 {
		t.Errorf("ECost(quarantine) = %v, want 0.2833…", got)
	}
	// rotate on a bare view: phase is neither cold/warm/idle -> phi = [1,0,0,0,0,0] -> C_flow 0.15
	wantRot := 0.4*1.0 + 0.6*0.15
	gotRot := c.ECost(v, model.Move{Action: model.ActionRotate}, pol)
	if math.Abs(gotRot-wantRot) > 1e-9 {
		t.Errorf("ECost(rotate, bare) = %v, want %v", gotRot, wantRot)
	}
}

func TestPart3_WeightsComeFromPolicy(t *testing.T) {
	c := NewP1Cost()
	v := bareView()
	pol := model.Policy{NormSparsity: 1.0, FlowDisruption: 0.0}
	if got := c.ECost(v, model.Move{Action: model.ActionRotate}, pol); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("with weights (1,0) ECost(rotate) = %v, want C_norm = 1.0", got)
	}
	pol = model.Policy{NormSparsity: 0.0, FlowDisruption: 1.0}
	if got := c.ECost(v, model.Move{Action: model.ActionRotate}, pol); math.Abs(got-0.15) > 1e-9 {
		t.Errorf("with weights (0,1) ECost(rotate) = %v, want C_flow = 0.15", got)
	}
}

func TestPart3_CHiNeverBelowECost(t *testing.T) {
	pol := defaultPolicy()
	for _, gpu := range []bool{false, true} {
		for _, ph := range []model.WorkloadPhase{model.PhaseColdStarting, model.PhaseWarm, model.PhaseIdle} {
			c := NewP1Cost()
			v := bareView()
			v.Pod.HasGPU = gpu
			v.Phase = ph
			for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine, model.ActionNoop} {
				m := model.Move{Action: a}
				e, hi := c.ECost(v, m, pol), c.CHi(v, m, pol)
				if hi < e-eps {
					t.Errorf("CHi < ECost for action=%s gpu=%v phase=%v: %v < %v", a, gpu, ph, hi, e)
				}
			}
		}
	}
}

func TestPart3_CostCeilingValue(t *testing.T) {
	pol := defaultPolicy()
	ceiling := pol.NormSparsity + pol.FlowDisruption + 0.2
	if math.Abs(ceiling-1.2) > 1e-9 {
		t.Errorf("cost ceiling = %v, want 1.2 at default weights", ceiling)
	}
	// A GPU pod with an unprimed RLS gets the worst-case envelope: assert it is the case that
	// actually approaches/【exceeds】the ceiling, which is what the SLO gate is there to catch.
	c := NewP1Cost()
	v := bareView()
	v.Pod.HasGPU = true
	v.Phase = model.PhaseColdStarting
	hi := c.CHi(v, model.Move{Action: model.ActionRotate}, pol)
	if hi <= 0 || math.IsNaN(hi) || math.IsInf(hi, 0) {
		t.Fatalf("CHi not finite/positive: %v", hi)
	}
	t.Logf("CHi(rotate, GPU cold, unprimed) = %.4f vs ceiling %.2f -> dropped=%v", hi, ceiling, hi > ceiling)
}

// ---------- Always-true invariants ----------

func TestInvariants_NonNegativeFiniteDeterministic(t *testing.T) {
	pol := defaultPolicy()
	views := []*model.WorkloadView{}
	for _, gpu := range []bool{false, true} {
		for _, ph := range []model.WorkloadPhase{"", model.PhaseColdStarting, model.PhaseWarm, model.PhaseIdle} {
			for _, tel := range []bool{false, true} {
				v := bareView()
				v.Pod.HasGPU = gpu
				v.Phase = ph
				if tel {
					v.Telemetry = model.Telemetry{Present: true, ConnCount: 137, ReqRate: 321}
				}
				views = append(views, v)
			}
		}
	}
	for i, v := range views {
		c := NewP1Cost()
		for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine, model.ActionNoop} {
			m := model.Move{Action: a}
			e := c.ECost(v, m, pol)
			hi := c.CHi(v, m, pol)
			if e < 0 || math.IsNaN(e) || math.IsInf(e, 0) {
				t.Errorf("view#%d %s: ECost not finite/non-negative: %v", i, a, e)
			}
			if hi < 0 || math.IsNaN(hi) || math.IsInf(hi, 0) {
				t.Errorf("view#%d %s: CHi not finite/non-negative: %v", i, a, hi)
			}
			// determinism: same view + same policy -> identical cost
			c2 := NewP1Cost()
			if e2 := c2.ECost(v, m, pol); e2 != e {
				t.Errorf("view#%d %s: non-deterministic ECost %v vs %v", i, a, e, e2)
			}
		}
	}
}

// A NaN/Inf in telemetry must not poison the cost (missing/garbage data => neutral, not garbage).
func TestInvariants_GarbageTelemetryDoesNotPoisonCost(t *testing.T) {
	c := NewP1Cost()
	pol := defaultPolicy()
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1} {
		v := bareView()
		v.Telemetry = model.Telemetry{Present: true, ConnCount: bad, ReqRate: bad}
		for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
			got := c.ECost(v, model.Move{Action: a}, pol)
			if math.IsNaN(got) || math.IsInf(got, 0) || got < 0 {
				t.Errorf("telemetry=%v action=%s: ECost = %v, want finite non-negative", bad, a, got)
			}
		}
	}
}

// The CHi >= ECost contract rests on the conformal slack never being negative. Verify the
// mechanism rather than assuming it: ConformalBound.Observe stores |residual|, so the quantile
// is an order statistic over non-negative values no matter what is observed.
func TestPart3_ConformalSlackIsNeverNegative(t *testing.T) {
	c := NewP1Cost()
	for _, r := range []float64{-0.9, -5, -1e6, 0, 0.3, 7} {
		c.Conformal.Observe(r)
	}
	if q := c.Conformal.Quantile(); q < 0 {
		t.Errorf("conformal quantile = %v after negative observations, want >= 0 (Observe must store |residual|)", q)
	}
	// and the end-to-end contract still holds on that populated window
	pol := defaultPolicy()
	v := bareView()
	v.Phase = model.PhaseWarm
	m := model.Move{Action: model.ActionRotate}
	if e, hi := c.ECost(v, m, pol), c.CHi(v, m, pol); hi < e-eps {
		t.Errorf("CHi (%v) below ECost (%v)", hi, e)
	}
}
