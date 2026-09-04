/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ingest

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func t1cReadyPod() model.Pod {
	return model.Pod{Namespace: "ns", Name: "p", UID: "u", Ready: true, Age: time.Hour}
}

// TestPhaseOf_UninstrumentedIsWarmNotIdle is the T1-C RED->GREEN anchor (ticket test (a) / M-142).
// A Ready pod that exports ONLY universal cAdvisor metrics (real connections, no app-level
// ReqRate/GPUUtil/QueueDepth/TokensPerSec) must be Warm, never Idle. Pre-T1-C PhaseOf gated on
// any-signal presence and returned Idle here — pricing rotate at the idle rate fleet-wide.
func TestPhaseOf_UninstrumentedIsWarmNotIdle(t *testing.T) {
	tel := model.Telemetry{ConnCount: model.PresentSignal(42, "cadvisor")} // cAdvisor only
	if tel.AppLevelPresent() {
		t.Fatal("cAdvisor-only telemetry must not count as app-level presence")
	}
	if got := PhaseOf(t1cReadyPod(), tel); got != model.PhaseWarm {
		t.Errorf("uninstrumented Ready pod: PhaseOf = %q, want Warm (M-142: absence must not route to Idle)", got)
	}
	if got := PhaseReasonOf(t1cReadyPod(), tel); got != PhaseReasonWarmNoApp {
		t.Errorf("phaseReason = %q, want %q", got, PhaseReasonWarmNoApp)
	}
}

// (b) A measured idle app signal (ReqRate present, ~0) routes to Idle.
func TestPhaseOf_MeasuredIdleIsIdle(t *testing.T) {
	tel := model.Telemetry{ReqRate: model.PresentSignal(0, "prom")}
	if got := PhaseOf(t1cReadyPod(), tel); got != model.PhaseIdle {
		t.Errorf("measured-idle pod: PhaseOf = %q, want Idle", got)
	}
	if got := PhaseReasonOf(t1cReadyPod(), tel); got != PhaseReasonIdleMeasured {
		t.Errorf("phaseReason = %q, want %q", got, PhaseReasonIdleMeasured)
	}
}

// (c) A measured serving app signal (ReqRate > 0.001) is not Idle (Warm, reason busy-measured).
func TestPhaseOf_MeasuredBusyIsNotIdle(t *testing.T) {
	tel := model.Telemetry{ReqRate: model.PresentSignal(5, "prom")}
	if got := PhaseOf(t1cReadyPod(), tel); got == model.PhaseIdle {
		t.Errorf("measured-busy pod must not be Idle, got %q", got)
	}
	if got := PhaseReasonOf(t1cReadyPod(), tel); got != PhaseReasonBusyMeasured {
		t.Errorf("phaseReason = %q, want %q", got, PhaseReasonBusyMeasured)
	}
}

// A measured-idle GPU pod stays Idle only when GPUUtil is a usable low reading; a busy GPU
// (present, high) must not be Idle even with ReqRate ~0.
func TestPhaseOf_BusyGPUNotIdle(t *testing.T) {
	tel := model.Telemetry{ReqRate: model.PresentSignal(0, "prom"), GPUUtil: model.PresentSignal(0.9, "dcgm")}
	if got := PhaseOf(t1cReadyPod(), tel); got == model.PhaseIdle {
		t.Errorf("busy-GPU pod must not be Idle, got %q", got)
	}
}
