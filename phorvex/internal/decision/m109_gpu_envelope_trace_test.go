package decision

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/model"
)

func m109TraceRow(t *testing.T, trace *model.DecisionTraceV2, excluded bool) *model.DecisionCandidateV2 {
	t.Helper()
	for i := range trace.Candidates {
		row := &trace.Candidates[i]
		if row.Action == string(model.ActionRotate) && (row.ExistingExclusionReason != "") == excluded {
			return row
		}
	}
	t.Fatalf("rotate row with excluded=%t missing: %+v", excluded, trace.Candidates)
	return nil
}

func m109RequireTraceClose(t *testing.T, label string, got, want float64) {
	t.Helper()
	if math.IsNaN(got) || math.IsInf(got, 0) || math.IsNaN(want) || math.IsInf(want, 0) || math.Abs(got-want) > 1e-12 {
		t.Fatalf("%s = %.15g, want %.15g", label, got, want)
	}
}

func TestM109GeneratorGateAndTraceRetainExactGPUEnvelopeProvenance(t *testing.T) {
	previousEnvelope := cost.GPUEnvelopeMax()
	t.Cleanup(func() {
		if err := cost.ConfigureGPUEnvelopeMax(previousEnvelope); err != nil {
			t.Errorf("restore GPU envelope: %v", err)
		}
	})
	if err := cost.ConfigureGPUEnvelopeMax(1); err != nil {
		t.Fatal(err)
	}

	newFixture := func(t *testing.T, residual float64, observations int) (*CoverageEngine, *model.WorkloadView, model.Policy, cost.P1Evaluation) {
		t.Helper()
		e := fixedTraceEngine()
		pol := decisionTracePolicy(1, true)
		pol.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
		gpu := covView("m109-gpu", true, 2*time.Hour, false)
		gpu.Pod.HasGPU = true
		cpu := covView("m109-cpu-observation", true, 2*time.Hour, false)
		cpu.Pod.HasGPU = false
		bucket := e.costFor(pol.Owner(), pol.Lambda)
		for i := 0; i < observations; i++ {
			measured := bucket.RLS.Predict(cost.Features(cpu)) + residual
			e.ObserveRotation(pol.Owner(), cpu, measured)
		}
		if !bucket.RLS.Primed() || bucket.RLS.Updates() != observations {
			t.Fatalf("actual owner bucket did not consume CPU observation: primed=%t updates=%d", bucket.RLS.Primed(), bucket.RLS.Updates())
		}
		evaluation := bucket.Evaluation(gpu, model.Move{Action: model.ActionRotate}, pol)
		return e, gpu, pol, evaluation
	}

	t.Run("included row", func(t *testing.T) {
		e, gpu, pol, evaluation := newFixture(t, 0, 1)
		pol.CostCeiling = 100
		decision := e.Decide([]*model.WorkloadView{gpu}, pol)[0]
		if decision.Trace == nil {
			t.Fatal("trace missing")
		}
		if err := decision.Trace.Validate(); err != nil {
			t.Fatal(err)
		}
		if !decision.Trace.Inputs.Primed {
			t.Fatal("trace hid the generic RLS primed state")
		}
		row := m109TraceRow(t, decision.Trace, false)
		if !row.SLOGateResult.Present || !row.SLOGateResult.Value {
			t.Fatalf("included rotate did not record a passing SLO gate: %+v", row.SLOGateResult)
		}
		if !row.GPUEnvelopeApplied.Present || !row.GPUEnvelopeApplied.Value || !row.GPUEnvelopeSlack.Present {
			t.Fatalf("included rotate lost evaluation envelope provenance: %+v", row)
		}
		m109RequireTraceClose(t, "included expected cost", row.ExpectedCost.Value, evaluation.Total)
		m109RequireTraceClose(t, "included robust cost", row.CostHigh.Value, evaluation.CHi)
		m109RequireTraceClose(t, "included envelope slack", row.GPUEnvelopeSlack.Value, evaluation.GPUEnvelopeSlack)
	})

	t.Run("SLO-excluded row", func(t *testing.T) {
		e, gpu, pol, evaluation := newFixture(t, 0, 1)
		quantile, ok := e.costFor(pol.Owner()).ConformalQuantile()
		if !ok {
			t.Fatal("generic conformal quantile unavailable")
		}
		genericHigh := evaluation.Total + quantile
		pol.CostCeiling = (genericHigh + evaluation.CHi) / 2
		if !(genericHigh < pol.CostCeiling && pol.CostCeiling < evaluation.CHi) {
			t.Fatalf("floor-driven gate fixture is not discriminating: genericHigh=%g ceiling=%g configuredHigh=%g", genericHigh, pol.CostCeiling, evaluation.CHi)
		}
		decision := e.Decide([]*model.WorkloadView{gpu}, pol)[0]
		if decision.Trace == nil {
			t.Fatal("trace missing")
		}
		if err := decision.Trace.Validate(); err != nil {
			t.Fatal(err)
		}
		row := m109TraceRow(t, decision.Trace, true)
		if !row.SLOGateResult.Present || row.SLOGateResult.Value {
			t.Fatalf("excluded rotate did not record a failing SLO gate: %+v", row.SLOGateResult)
		}
		if !strings.HasPrefix(row.ExistingExclusionReason, "conformal-slo:") {
			t.Fatalf("floor-driven exclusion reason = %q, want conformal-slo", row.ExistingExclusionReason)
		}
		if !row.GPUEnvelopeApplied.Present || !row.GPUEnvelopeApplied.Value || !row.GPUEnvelopeSlack.Present {
			t.Fatalf("SLO-excluded rotate lost evaluation envelope provenance: %+v", row)
		}
		m109RequireTraceClose(t, "excluded expected cost", row.ExpectedCost.Value, evaluation.Total)
		m109RequireTraceClose(t, "excluded robust cost", row.CostHigh.Value, evaluation.CHi)
		m109RequireTraceClose(t, "excluded envelope slack", row.GPUEnvelopeSlack.Value, evaluation.GPUEnvelopeSlack)
	})

	t.Run("larger generic uncertainty", func(t *testing.T) {
		// The generic slack replaces the cold-start value only once the window is calibrated.
		e, gpu, pol, evaluation := newFixture(t, 0.8, cost.ConformalMinimumSamples)
		pol.CostCeiling = 100
		decision := e.Decide([]*model.WorkloadView{gpu}, pol)[0]
		if decision.Trace == nil {
			t.Fatal("trace missing")
		}
		if err := decision.Trace.Validate(); err != nil {
			t.Fatal(err)
		}
		row := m109TraceRow(t, decision.Trace, false)
		if !row.ConformalQuantile.Present || !row.GPUEnvelopeApplied.Present || !row.GPUEnvelopeApplied.Value || !row.GPUEnvelopeSlack.Present {
			t.Fatalf("rotate row lacks uncertainty terms: %+v", row)
		}
		m109RequireTraceClose(t, "generic quantile", row.ConformalQuantile.Value, 0.8)
		m109RequireTraceClose(t, "configured floor", row.GPUEnvelopeSlack.Value, 0.6)
		m109RequireTraceClose(t, "larger uncertainty CHi", row.CostHigh.Value-row.ExpectedCost.Value, 0.8)
		m109RequireTraceClose(t, "evaluation CHi", row.CostHigh.Value, evaluation.CHi)
	})
}
