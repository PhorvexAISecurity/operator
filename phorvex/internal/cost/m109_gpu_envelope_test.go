package cost

import (
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func configureM109GPUEnvelope(t *testing.T, value float64) {
	t.Helper()
	previous := GPUEnvelopeMax()
	t.Cleanup(func() {
		if err := ConfigureGPUEnvelopeMax(previous); err != nil {
			t.Errorf("restore GPU envelope: %v", err)
		}
	})
	if err := ConfigureGPUEnvelopeMax(value); err != nil {
		t.Fatal(err)
	}
}

func m109Views() (cpu, gpu *model.WorkloadView) {
	telemetry := model.Telemetry{ReqRate: model.PresentSignal(0, "m109-control")}
	cpu = &model.WorkloadView{Pod: model.Pod{HasGPU: false}, Phase: model.PhaseWarm, Telemetry: telemetry}
	gpu = &model.WorkloadView{Pod: model.Pod{HasGPU: true}, Phase: model.PhaseWarm, Telemetry: telemetry}
	return cpu, gpu
}

func requireM109Close(t *testing.T, label string, got, want float64) {
	t.Helper()
	if math.IsNaN(got) || math.IsInf(got, 0) || math.IsNaN(want) || math.IsInf(want, 0) || math.Abs(got-want) > 1e-12 {
		t.Fatalf("%s = %.15g, want %.15g", label, got, want)
	}
}

func TestM109GPUEnvelopeSurvivesUnrelatedGenericCalibration(t *testing.T) {
	configureM109GPUEnvelope(t, 1)
	c := NewP1Cost()
	pol := model.Policy{NormSparsity: 0.4, FlowDisruption: 0.6}
	cpu, gpu := m109Views()
	rotate := model.Move{Action: model.ActionRotate}

	before := c.Evaluation(gpu, rotate, pol)
	c.ObserveRotation(cpu, c.RLS.Predict(Features(cpu)))
	if !c.RLS.Primed() || c.RLS.Updates() != 1 {
		t.Fatalf("CPU observation did not prime the generic learner: primed=%t updates=%d", c.RLS.Primed(), c.RLS.Updates())
	}
	if c.Conformal.Calibrated() {
		t.Fatal("one generic residual unexpectedly reported calibrated")
	}
	requireM109Close(t, "uncalibrated quantile keeps the cold-start slack", c.Conformal.Quantile(), ColdStartSlack)

	after := c.Evaluation(gpu, rotate, pol)
	requireM109Close(t, "GPU expected cost after zero innovation", after.Total, before.Total)
	if !after.GPUEnvelopeApplied {
		t.Fatal("generic RLS priming withdrew the configured GPU envelope")
	}
	requireM109Close(t, "GPU envelope provenance", after.GPUEnvelopeSlack, 0.6)
	requireM109Close(t, "GPU robust slack", after.CHi-after.Total, 0.6)

	cpuEval := c.Evaluation(cpu, rotate, pol)
	if cpuEval.GPUEnvelopeApplied || cpuEval.GPUEnvelopeSlack != 0 {
		t.Fatalf("CPU rotate acquired GPU envelope provenance: %+v", cpuEval)
	}
	requireM109Close(t, "CPU robust slack", cpuEval.CHi-cpuEval.Total, ColdStartSlack)

	for c.RLS.Updates() < 20 {
		c.ObserveRotation(cpu, c.RLS.Predict(Features(cpu)))
	}
	if !c.Conformal.Calibrated() || c.RLS.Updates() != 20 {
		t.Fatalf("generic readiness did not advance independently: calibrated=%t updates=%d", c.Conformal.Calibrated(), c.RLS.Updates())
	}
	requireM109Close(t, "calibrated zero-residual quantile", c.Conformal.Quantile(), 0)
	calibrated := c.Evaluation(gpu, rotate, pol)
	if !calibrated.GPUEnvelopeApplied {
		t.Fatal("generic conformal calibration withdrew the configured GPU envelope")
	}
	requireM109Close(t, "calibrated GPU envelope provenance", calibrated.GPUEnvelopeSlack, 0.6)
	requireM109Close(t, "calibrated GPU robust slack", calibrated.CHi-calibrated.Total, 0.6)
}

func TestM109GenericUncertaintyAndMeanLearningRemainLive(t *testing.T) {
	configureM109GPUEnvelope(t, 1)
	pol := model.Policy{NormSparsity: 0.4, FlowDisruption: 0.6}
	cpu, gpu := m109Views()
	rotate := model.Move{Action: model.ActionRotate}

	largeResidual := NewP1Cost()
	for !largeResidual.Conformal.Calibrated() {
		prediction := largeResidual.RLS.Predict(Features(cpu))
		largeResidual.ObserveRotation(cpu, prediction+0.8)
	}
	eval := largeResidual.Evaluation(gpu, rotate, pol)
	if !eval.GPUEnvelopeApplied {
		t.Fatal("larger generic uncertainty hid the configured GPU envelope provenance")
	}
	requireM109Close(t, "generic conformal quantile", largeResidual.Conformal.Quantile(), 0.8)
	requireM109Close(t, "configured GPU floor", eval.GPUEnvelopeSlack, 0.6)
	requireM109Close(t, "larger generic uncertainty", eval.CHi-eval.Total, 0.8)

	learnedMean := NewP1Cost()
	before := learnedMean.Evaluation(gpu, rotate, pol)
	cpuPrediction := learnedMean.RLS.Predict(Features(cpu))
	learnedMean.ObserveRotation(cpu, cpuPrediction+0.2)
	after := learnedMean.Evaluation(gpu, rotate, pol)
	if after.Total == before.Total {
		t.Fatalf("nonzero CPU innovation did not update the shared expected mean: before=%g after=%g", before.Total, after.Total)
	}
	if !after.GPUEnvelopeApplied {
		t.Fatal("expected-mean learning withdrew the configured GPU floor")
	}
	requireM109Close(t, "floor after mean learning", after.GPUEnvelopeSlack, 0.6)
}

func TestM109GPUObservationConfigurationAndActionScope(t *testing.T) {
	configureM109GPUEnvelope(t, 0.25)
	c := NewP1Cost()
	pol := model.Policy{NormSparsity: 0.4, FlowDisruption: 0.6}
	cpu, gpu := m109Views()
	rotate := model.Move{Action: model.ActionRotate}

	c.ObserveRotation(gpu, c.RLS.Predict(Features(gpu)))
	eval := c.Evaluation(gpu, rotate, pol)
	if !eval.GPUEnvelopeApplied {
		t.Fatal("a GPU-shaped observation withdrew the configured envelope")
	}
	requireM109Close(t, "configured 0.25 envelope", eval.GPUEnvelopeSlack, 0.15)
	requireM109Close(t, "GPU-observed robust slack", eval.CHi-eval.Total, 0.15)

	for _, tc := range []struct {
		name string
		view *model.WorkloadView
		move model.Move
	}{
		{name: "CPU rotate", view: cpu, move: rotate},
		{name: "GPU quarantine", view: gpu, move: model.Move{Action: model.ActionQuarantine}},
		{name: "GPU MIG rebind", view: gpu, move: model.Move{Action: model.ActionMIGRebind}},
		{name: "GPU noop", view: gpu, move: model.Move{Action: model.ActionNoop}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := c.Evaluation(tc.view, tc.move, pol)
			if got.GPUEnvelopeApplied || got.GPUEnvelopeSlack != 0 {
				t.Fatalf("out-of-scope action acquired GPU envelope provenance: %+v", got)
			}
			if tc.move.Action != model.ActionRotate && tc.move.Action != model.ActionMIGRebind {
				requireM109Close(t, "non-rotate robust cost", got.CHi, got.Total)
			}
			if tc.move.Action == model.ActionMIGRebind && (!got.FlowUncertaintyApplied || got.CHi < got.Total) {
				t.Fatalf("MIG lower-bound proxy lost unsupported-regime provenance: %+v", got)
			}
		})
	}

	nanGPU := *gpu
	nanGPU.Telemetry.ReqRate = model.Signal{Value: math.NaN(), State: model.Error}
	nanEval := c.Evaluation(&nanGPU, rotate, pol)
	if nanEval.UnactionableCategory != UnactionableNaNCategory || nanEval.GPUEnvelopeApplied || nanEval.GPUEnvelopeSlack != 0 {
		t.Fatalf("early NaN refusal acquired GPU envelope provenance: %+v", nanEval)
	}
}
