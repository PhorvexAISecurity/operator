/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package cost

import (
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func TestRLSConvergesToObservedCost(t *testing.T) {
	r := NewRLS()
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}, Phase: model.PhaseIdle}
	f := Features(v)
	// True idle-rotation flow cost is, say, 0.05 (cheap); feed it repeatedly.
	for i := 0; i < 50; i++ {
		r.Update(f, 0.05)
	}
	got := r.Predict(f)
	if math.Abs(got-0.05) > 0.05 {
		t.Errorf("RLS should converge toward the observed 0.05, got %.3f", got)
	}
	if !r.Primed() {
		t.Errorf("RLS should report primed after observations")
	}
}

func TestCalibratorsRejectNonFiniteObservations(t *testing.T) {
	r := NewRLS()
	before := r.theta
	f := [featureDim]float64{1, 0, 0, 0, 0, 0}
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		r.Update(f, bad)
	}
	f[0] = math.NaN()
	r.Update(f, 0.5)
	if r.theta != before || r.Primed() || r.Updates() != 0 {
		t.Fatalf("non-finite observation poisoned RLS: before=%v after=%v", before, r.theta)
	}

	b := NewConformalBound()
	b.Observe(math.NaN())
	b.Observe(math.Inf(1))
	if len(b.residuals) != 0 || b.Quantile() != ColdStartSlack {
		t.Fatalf("non-finite residual poisoned conformal bound: %+v", b.residuals)
	}
}

func TestComponentsExactlyRecomposeECost(t *testing.T) {
	c := NewP1Cost()
	pol := model.Policy{NormSparsity: 0.4, FlowDisruption: 0.6}
	view := &model.WorkloadView{
		Pod:       model.Pod{HasGPU: true},
		Phase:     model.PhaseWarm,
		Telemetry: model.Telemetry{ReqRate: model.PresentSignal(100, "test"), ConnCount: model.PresentSignal(40, "test")},
	}
	actions := append([]model.Action{model.ActionNoop}, model.MutatingActions...)
	for _, action := range actions {
		move := model.Move{Action: action}
		got := c.Components(view, move, pol)
		wantFlow := 0.0
		if action != model.ActionNoop {
			wantFlow = c.actionFlow(view, action)
		}
		if math.Abs(got.Flow-wantFlow) > 1e-12 {
			t.Fatalf("%s components flow=%v actionFlow=%v", action, got.Flow, wantFlow)
		}
		if math.Abs(got.Total-(pol.NormSparsity*got.Norm+pol.FlowDisruption*got.Flow)) > 1e-12 {
			t.Fatalf("%s components do not recompose: %+v", action, got)
		}
	}
}

func TestNormalizeReadyDelayUsesDeclaredRecoveryRange(t *testing.T) {
	cases := []struct {
		name  string
		delay time.Duration
		want  float64
	}{
		{name: "zero", delay: 0, want: 0},
		{name: "idle end", delay: 60 * time.Second, want: 0.15},
		{name: "reference", delay: ReadyDelayReference, want: 1},
		{name: "model maximum", delay: 2 * ReadyDelayReference, want: 2},
		{name: "clamped", delay: 3 * ReadyDelayReference, want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeReadyDelay(tc.delay); math.Abs(got-tc.want) > 1e-12 {
				t.Fatalf("NormalizeReadyDelay(%s) = %v, want %v", tc.delay, got, tc.want)
			}
		})
	}
}

func TestDualLambdaRespondsToBudgetPressure(t *testing.T) {
	d := NewDualSolver()
	start := d.Lambda()
	// Demand far exceeds budget => lambda must RISE (moves are scarce).
	for i := 0; i < 20; i++ {
		d.Step(10, 2, 2)
	}
	high := d.Lambda()
	if !(high > start) {
		t.Errorf("lambda must rise under over-demand: start=%.3f high=%.3f", start, high)
	}
	// Slack (demand < budget) => lambda must FALL.
	for i := 0; i < 200; i++ {
		d.Step(0, 0, 5)
	}
	low := d.Lambda()
	if !(low < high) {
		t.Errorf("lambda must fall under budget slack: high=%.3f low=%.3f", high, low)
	}
	if low < 0 {
		t.Errorf("lambda must stay non-negative, got %.3f", low)
	}
}

func TestCHiPrunesUncalibratedGPURotate(t *testing.T) {
	c := NewP1Cost()
	pol := model.Policy{NormSparsity: 0.4, FlowDisruption: 0.6}
	ceiling := EffectiveCostCeiling(pol)

	telemetry := model.Telemetry{ReqRate: model.PresentSignal(0, "fixture")}
	gpu := &model.WorkloadView{Pod: model.Pod{HasGPU: true}, Phase: model.PhaseWarm, Telemetry: telemetry}
	cpu := &model.WorkloadView{Pod: model.Pod{}, Phase: model.PhaseWarm, Telemetry: telemetry}
	rot := model.Move{Action: model.ActionRotate}

	if chi := c.CHi(gpu, rot, pol); chi <= ceiling {
		t.Errorf("uncalibrated GPU rotate CHi (%.3f) should EXCEED ceiling (%.3f) with the conservative default envelope", chi, ceiling)
	}
	if chi := c.CHi(cpu, rot, pol); chi > ceiling {
		t.Errorf("non-GPU rotate CHi (%.3f) should be within ceiling (%.3f)", chi, ceiling)
	}
	// Quarantine is always within the ceiling (the safe fallback).
	if chi := c.CHi(gpu, model.Move{Action: model.ActionQuarantine}, pol); chi > ceiling {
		t.Errorf("GPU quarantine CHi (%.3f) should be within ceiling (%.3f)", chi, ceiling)
	}
}

func TestConformalColdStartSlack(t *testing.T) {
	c := NewConformalBound()
	if q := c.Quantile(); q != ColdStartSlack {
		t.Errorf("cold-start conformal slack should be %.2f, got %.3f", ColdStartSlack, q)
	}
	if c.Calibrated() {
		t.Errorf("conformal bound should not report calibrated with zero residuals")
	}
}

func TestMeasuredT4GPUEnvelopeConfiguresCHi(t *testing.T) {
	original := GPUEnvelopeMax()
	t.Cleanup(func() { _ = ConfigureGPUEnvelopeMax(original) })

	if math.Abs(MeasuredT4GPUEnvelopeMax-0.2925) > 1e-12 {
		t.Fatalf("T4 envelope must be 117s/400s = 0.2925, got %.12f", MeasuredT4GPUEnvelopeMax)
	}
	if err := ConfigureGPUEnvelopeMax(MeasuredT4GPUEnvelopeMax); err != nil {
		t.Fatal(err)
	}
	c := NewP1Cost()
	pol := model.Policy{FlowDisruption: 1}
	view := &model.WorkloadView{Pod: model.Pod{HasGPU: true}, Phase: model.PhaseWarm,
		Telemetry: model.Telemetry{ReqRate: model.PresentSignal(0, "fixture")}}
	move := model.Move{Action: model.ActionRotate}
	if delta := c.CHi(view, move, pol) - c.ECost(view, move, pol); math.Abs(delta-MeasuredT4GPUEnvelopeMax) > 1e-12 {
		t.Errorf("GPU CHi slack = %.12f, want measured envelope %.12f", delta, MeasuredT4GPUEnvelopeMax)
	}

	before := GPUEnvelopeMax()
	if err := ConfigureGPUEnvelopeMax(math.NaN()); err == nil {
		t.Fatal("NaN GPU envelope must be rejected")
	}
	if GPUEnvelopeMax() != before {
		t.Fatal("invalid calibration changed the active GPU envelope")
	}
}

func TestConformalBoundIsOneSidedAndGatedOnCalibration(t *testing.T) {
	b := NewConformalBound()
	b.Observe(-0.7)
	if b.residuals[0] != 0 {
		t.Fatalf("over-prediction stored as %v, want 0 (one-sided upper bound)", b.residuals[0])
	}
	for len(b.residuals) < ConformalMinimumSamples-1 {
		b.Observe(5)
	}
	if b.Calibrated() || b.Quantile() != ColdStartSlack {
		t.Fatalf("uncalibrated window (n=%d) replaced the cold-start slack: q=%v", len(b.residuals), b.Quantile())
	}

	b = NewConformalBound()
	for i := 1; i <= ConformalMinimumSamples; i++ {
		b.Observe(float64(i) / 100)
	}
	// Finite-sample split-conformal rank ceil((20+1)*0.9) = 19 -> the 19th smallest.
	if got := b.Quantile(); math.Abs(got-0.19) > 1e-12 {
		t.Fatalf("calibrated quantile = %v, want 0.19", got)
	}
}

// Staging regression (2026-10-26): a rotation that was Ready in ~1 s (C_flow 0.0025
// against a Warm prior of ~0.7) widened the conformal slack 0.1 -> 0.70 and pushed
// rotate C_hi past demo-api-defense's 1.2 SLO ceiling. New residuals only come from
// executed rotations, so rotate stayed excluded for that owner.
func TestFastRotationDoesNotLockRotateOutOfSLO(t *testing.T) {
	const costCeiling = 1.2 // demo-api-defense slo.costCeiling
	pol := model.Policy{NormSparsity: 0.4, FlowDisruption: 0.6}
	view := &model.WorkloadView{
		Pod:       model.Pod{Namespace: "phorvex-staging-demo", Name: "demo-api"},
		Phase:     model.PhaseWarm,
		Telemetry: model.Telemetry{ReqRate: model.PresentSignal(5, "test")},
	}
	rotate := model.Move{Action: model.ActionRotate}
	c := NewP1Cost()

	if before := c.Evaluation(view, rotate, pol); before.CHi > costCeiling {
		t.Fatalf("cold-start rotate CHi = %v, want <= %v", before.CHi, costCeiling)
	}
	c.ObserveRotation(view, 0.0025)
	after := c.Evaluation(view, rotate, pol)
	if after.CHi > costCeiling {
		t.Fatalf("one fast rotation locked rotate out: CHi = %v > ceiling %v (q=%v)", after.CHi, costCeiling, c.Conformal.Quantile())
	}
	if q, _ := c.ConformalQuantile(); q != ColdStartSlack {
		t.Fatalf("conformal slack after one sample = %v, want cold-start %v", q, ColdStartSlack)
	}
	for i := 0; i < 2*ConformalMinimumSamples; i++ {
		c.ObserveRotation(view, 0.0025)
		if got := c.Evaluation(view, rotate, pol); got.CHi > costCeiling {
			t.Fatalf("rotation %d locked rotate out: CHi = %v > ceiling %v", i+2, got.CHi, costCeiling)
		}
	}
}
