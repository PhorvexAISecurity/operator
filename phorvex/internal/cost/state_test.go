package cost

import (
	"math"
	"reflect"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func trainedBucket(t *testing.T) *P1Cost {
	t.Helper()
	c := NewP1CostWithLambda(0.45)
	view := &model.WorkloadView{Phase: model.PhaseWarm}
	view.Telemetry.ReqRate = model.PresentSignal(120, "test")
	for i := 0; i < 7; i++ {
		c.ObserveRotation(view, 0.3+0.05*float64(i))
	}
	c.Dual.Step(5, 1, 1)
	return c
}

func TestP1CostStateRoundTripIsExact(t *testing.T) {
	src := trainedBucket(t)
	restored, err := RestoreP1Cost(src.State())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(src.State(), restored.State()) {
		t.Fatalf("state changed across export/restore:\nsrc=%+v\ngot=%+v", src.State(), restored.State())
	}
	view := &model.WorkloadView{Phase: model.PhaseWarm}
	view.Telemetry.ReqRate = model.PresentSignal(80, "test")
	for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine, model.ActionKVReset} {
		pol := model.Policy{NormSparsity: 0.4, FlowDisruption: 0.6}
		if got, want := restored.Evaluation(view, model.Move{Action: a}, pol), src.Evaluation(view, model.Move{Action: a}, pol); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s evaluation differs after restore:\nwant=%+v\ngot=%+v", a, want, got)
		}
	}
	if restored.Dual.Lambda() != src.Dual.Lambda() {
		t.Fatalf("lambda %v != %v", restored.Dual.Lambda(), src.Dual.Lambda())
	}
}

func TestExportIsACopyNotAnAlias(t *testing.T) {
	src := trainedBucket(t)
	st := src.State()
	st.Conformal.Residuals[0] = 99
	if src.Conformal.State().Residuals[0] == 99 {
		t.Fatal("exported residual window aliases the live window")
	}
	restored, err := RestoreP1Cost(src.State())
	if err != nil {
		t.Fatal(err)
	}
	restored.Conformal.Observe(1.5)
	if len(src.Conformal.State().Residuals) == len(restored.Conformal.State().Residuals) {
		t.Fatal("restored window aliases the source window")
	}
}

func TestRestoreRejectsCorruptState(t *testing.T) {
	good := trainedBucket(t).State()
	cases := map[string]func(*P1CostState){
		"nan theta":        func(s *P1CostState) { s.RLS.Theta[2] = math.NaN() },
		"inf covariance":   func(s *P1CostState) { s.RLS.P[1][1] = math.Inf(1) },
		"forgetting zero":  func(s *P1CostState) { s.RLS.FF = 0 },
		"negative updates": func(s *P1CostState) { s.RLS.Updates = -1 },
		"window overflow":  func(s *P1CostState) { s.Conformal.Cap = 1 },
		"alpha one":        func(s *P1CostState) { s.Conformal.Alpha = 1 },
		"negative residual": func(s *P1CostState) {
			s.Conformal.Residuals = append([]float64(nil), s.Conformal.Residuals...)
			s.Conformal.Residuals[0] = -0.1
		},
		"lambda above max": func(s *P1CostState) { s.Dual.RuntimeLegacy = s.Dual.Max + 1 },
		"nan step":         func(s *P1CostState) { s.Dual.Step = math.NaN() },
	}
	for name, mutate := range cases {
		s := good
		s.Conformal.Residuals = append([]float64(nil), good.Conformal.Residuals...)
		mutate(&s)
		if _, err := RestoreP1Cost(s); err == nil {
			t.Errorf("%s: corrupt state restored without error", name)
		}
	}
}
