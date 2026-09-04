/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package physics

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func t1cView(t model.Telemetry) *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}, Telemetry: t}
}

// TestLittlesLaw_NoPhantomFanoutOnUninstrumentedPod is the T1-C phantom-fan-out fix (K3 §A.3 #13).
// A pod with REAL cAdvisor connections but NO app-level request rate must not fabricate a
// "lateral probing / C2" fan-out residual. Pre-T1-C, ConnCount>0 with ReqRate absent-as-zero
// produced fanout = clamp01((Conn-0)/(0+20)) > 0 and fed it to live selection.
func TestLittlesLaw_NoPhantomFanoutOnUninstrumentedPod(t *testing.T) {
	// 300 real connections, request rate ABSENT (uninstrumented app).
	tel := model.Telemetry{ConnCount: model.PresentSignal(300, "cadvisor")}
	if got := (littlesLaw{}).Residual(t1cView(tel), model.Policy{}); got != 0 {
		t.Errorf("uninstrumented pod (conns present, reqRate absent) fabricated residual %.4f, want 0 (no phantom fan-out)", got)
	}
}

// Control: when BOTH connections and request rate are measured, the fan-out term still works —
// the fix gates on presence, it does not delete the physics.
func TestLittlesLaw_FanoutStillFiresWhenBothMeasured(t *testing.T) {
	tel := model.Telemetry{
		ConnCount: model.PresentSignal(300, "cadvisor"),
		ReqRate:   model.PresentSignal(1, "prom"), // tiny arrival, huge fan-out
	}
	if got := (littlesLaw{}).Residual(t1cView(tel), model.Policy{}); got <= 0 {
		t.Errorf("measured conn>>reqRate must still raise the fan-out residual, got %.4f", got)
	}
}

// Fully-absent telemetry yields an honest-zero residual (never invented).
func TestLittlesLaw_AbsentTelemetryIsZero(t *testing.T) {
	if got := (littlesLaw{}).Residual(t1cView(model.Telemetry{}), model.Policy{}); got != 0 {
		t.Errorf("absent telemetry must give residual 0, got %.4f", got)
	}
}
