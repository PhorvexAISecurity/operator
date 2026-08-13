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

func TestComponentsExactlyRecomposeECost(t *testing.T) {
	c := NewP1Cost()
	pol := model.Policy{NormSparsity: 0.4, FlowDisruption: 0.6}
	view := &model.WorkloadView{
		Pod:       model.Pod{HasGPU: true},
		Phase:     model.PhaseWarm,
		Telemetry: model.Telemetry{Present: true, ReqRate: 100, ConnCount: 40},
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
	ceiling := pol.NormSparsity + pol.FlowDisruption + 0.2

	gpu := &model.WorkloadView{Pod: model.Pod{HasGPU: true}, Phase: model.PhaseWarm}
	cpu := &model.WorkloadView{Pod: model.Pod{}, Phase: model.PhaseWarm}
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
	view := &model.WorkloadView{Pod: model.Pod{HasGPU: true}}
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
