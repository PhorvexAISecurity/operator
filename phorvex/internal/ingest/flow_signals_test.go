package ingest

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// PHORVEXSEC-198 / M-115: the three flow inputs are typed signals with their own slots and
// never count as app-level activity for PhaseOf.
func TestFlowSignalsAssignedAndNotAppLevel(t *testing.T) {
	var tel model.Telemetry
	assignSignal(&tel, SigInFlightMean, model.PresentSignal(0.4, "prom"))
	assignSignal(&tel, SigCompletionRate, model.PresentSignal(0.03, "prom"))
	assignSignal(&tel, SigMeanSojournSec, model.PresentSignal(0.97, "prom"))
	if !tel.InFlightMean.Usable() || !tel.CompletionRate.Usable() || !tel.MeanSojournSec.Usable() {
		t.Fatalf("flow signals not assigned: %+v", tel)
	}
	if tel.AppLevelPresent() {
		t.Fatal("flow inputs must not make a pod app-level present (PhaseOf unchanged)")
	}
	for _, sig := range []string{SigInFlightMean, SigCompletionRate, SigMeanSojournSec} {
		if _, ok := DefaultPromQueries()[sig]; !ok {
			t.Fatalf("no query registered for %s", sig)
		}
	}
}
