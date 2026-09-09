package physics

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestM115LargeFiniteAndScale(t *testing.T) {
	// Contract §6: adding finite L and E must not silently overflow to infinity.
	for _, scale := range []float64{1, 1e-200, 1e200, 8e307} {
		fr := FlowResidual(flowTel(2*scale, scale, 1))
		if !fr.Present || math.Abs(fr.Residual-1.0/3) > 1e-9 {
			t.Fatalf("scale=%g: %+v, want present r=1/3", scale, fr)
		}
	}
}

func TestM115InvalidInputsSerializeAsAbsent(t *testing.T) {
	for _, bad := range []float64{-1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		for column := 0; column < 3; column++ {
			vals := []float64{10, 5, 2}
			vals[column] = bad
			fr := FlowResidual(flowTel(vals[0], vals[1], vals[2]))
			if fr.Present || fr.Reason == "" {
				t.Fatalf("column=%d bad=%v: %+v", column, bad, fr)
			}
			if _, err := json.Marshal(fr); err != nil {
				t.Fatal(err)
			}
		}
	}
	fr := FlowResidual(flowTel(1, math.MaxFloat64, 2))
	if fr.Present || fr.Reason != "non-finite-expected" {
		t.Fatalf("overflowing product: %+v", fr)
	}
	fr = FlowResidual(flowTel(1, 1e-300, 1e-300))
	if fr.Present || fr.Reason != "underflow-expected" {
		t.Fatalf("underflowing product must not become a measured zero: %+v", fr)
	}
	for column := 0; column < 3; column++ {
		tel := flowTel(10, 5, 2)
		signals := []*model.Signal{&tel.InFlightMean, &tel.CompletionRate, &tel.MeanSojournSec}
		signals[column].State = model.Stale
		if FlowResidual(tel).Present {
			t.Fatalf("stale column %d accepted", column)
		}
	}
}

func TestM115MeasuredZeroAggregate(t *testing.T) {
	a, present := Aggregate([]Component{{Present: true, Magnitude: 0}, {Reason: "absent"}})
	if !present || a != 0 {
		t.Fatalf("{0,absent}: %g %v", a, present)
	}
}
