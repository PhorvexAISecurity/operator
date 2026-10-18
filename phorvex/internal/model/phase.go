package model

import (
	"math"
	"time"
)

// Phase reason strings recorded alongside the phase. The Warm enum covers measured activity,
// absence and uncertain app telemetry; the reason disambiguates them.
const (
	PhaseReasonColdStart     = "coldstart"
	PhaseReasonUnknown       = "unknown"
	PhaseReasonDraining      = "draining"
	PhaseReasonIdleMeasured  = "idle-measured"
	PhaseReasonWarmNoApp     = "warm-no-app-signal"
	PhaseReasonWarmUncertain = "warm-uncertain-app-signal"
	PhaseReasonBusyMeasured  = "busy-measured"
)

// ClassifyPhase derives the cost-relevant workload phase from pod status and telemetry, with
// the auditable reason for the verdict. It is the SINGLE decision tree behind the phase and its
// recorded reason, so the two can never drift (K3 P3 F3).
func ClassifyPhase(p Pod, t Telemetry) (WorkloadPhase, string) {
	if p.Phase == "Succeeded" || p.Phase == "Failed" {
		return PhaseDraining, PhaseReasonDraining
	}
	if !p.Ready {
		// Young + not ready => still warming; older + not ready => unknown/unhealthy.
		if p.Age < 2*time.Minute {
			return PhaseColdStarting, PhaseReasonColdStart
		}
		return PhaseUnknown, PhaseReasonUnknown
	}
	if appActivityUncertain(t) {
		// Stale/error and invalid Present samples are unknown, not measured zero. They cannot
		// support the cheap Idle classification even when request rate is otherwise low.
		return PhaseWarm, PhaseReasonWarmUncertain
	}
	if !t.AppLevelPresent() {
		// Ready, no APP-LEVEL signal: assume warm (rotating costs the warm-load). Keyed on
		// AppLevelPresent (not any-signal), so a pod exporting only universal cAdvisor metrics
		// stays Warm for its whole life instead of collapsing to Idle — the M-142 fix.
		return PhaseWarm, PhaseReasonWarmNoApp
	}
	if appActivityMeasured(t) {
		return PhaseWarm, PhaseReasonBusyMeasured
	}
	if !t.ReqRate.Usable() {
		// Optional zero-valued signals do not prove the request path is idle. This is distinct
		// from the no-app fallback above: some app telemetry exists, but it is insufficient to
		// establish measured inactivity.
		return PhaseWarm, PhaseReasonWarmUncertain
	}
	return PhaseIdle, PhaseReasonIdleMeasured
}

// appActivityUncertain identifies application activity inputs that cannot be interpreted as
// measured inactivity. Absent optional signals are allowed; explicit Stale/Error and invalid
// Present values are not. Prometheus normally types non-finite samples as Error, while the
// finite check also protects direct/internal Telemetry producers.
func appActivityUncertain(t Telemetry) bool {
	for _, s := range []Signal{t.ReqRate, t.GPUUtil, t.QueueDepth, t.TokensPerSec} {
		switch s.State {
		case Absent:
			continue
		case Present:
			if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) || s.Value < 0 {
				return true
			}
		default:
			return true
		}
	}
	return false
}

// appActivityMeasured applies only the existing request/GPU thresholds. Queue depth and token
// throughput have no calibrated phase thresholds, so any positive measured value conservatively
// vetoes Idle without assigning a new cost or phase vocabulary.
func appActivityMeasured(t Telemetry) bool {
	return (t.ReqRate.Usable() && t.ReqRate.Value > 0.001) ||
		(t.GPUUtil.Usable() && t.GPUUtil.Value > 0.01) ||
		(t.QueueDepth.Usable() && t.QueueDepth.Value > 0) ||
		(t.TokensPerSec.Usable() && t.TokensPerSec.Value > 0)
}
