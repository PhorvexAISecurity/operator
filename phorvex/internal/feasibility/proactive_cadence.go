/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package feasibility

import (
	"fmt"

	"github.com/phorvex/phorvex/internal/model"
)

// proactiveCadence caps EVIDENCE-LESS (hygiene) motion to the long proactive cadence
// (Policy.ProactiveFloor == T1-B's T_cad), leaving evidence-driven motion at the short
// reactive cadence that anti-over-rotation governs (M-28).
//
// The problem it closes (register M-28, 🔴 LIVE 2026-08-20/21): after M-23, kv-reset reads its
// own VarSession clock and the ONLY per-action brake on it is anti-over-rotation — the
// forensic/evidence-retention guard sized to the SHORT AntiOverRotationWindow. With the physics-only
// arm pinning stage=model-theft and ZERO SecurityEvents, the brain flushed the vLLM prefix cache
// every ~100-110 s forever (= that window), a self-inflicted availability tax. Two cadences were
// conflated: the reactive window (right for responding to evidence) governed even with NO evidence,
// where the proactive floor (hygiene) belongs.
//
// The split (P-BELIEF): no-evidence motion is hygiene → floored at ProactiveFloor; evidence-driven
// motion is reactive → untouched here (anti-over-rotation still applies). The two never share a clock.
//
// It does NOT stop hygiene motion (P-M118 / M-118 is the intended zero-day posture: detectors silent,
// the brain keeps moving) — it only SLOWS evidence-less motion to T_cad. It picks NO new value:
// T_cad == the existing ProactiveFloor.
type proactiveCadence struct{}

// Name sorts AFTER "anti-over-rotation" in the by-name-sorted Registry.All(), so when a move is
// inside BOTH the reactive window and the proactive floor, the reactive (evidence-retention) reason
// surfaces first (first-veto-wins). TestProactiveCadenceOrdering pins this alphabetical coupling.
func (proactiveCadence) Name() string { return "proactive-cadence" }

func (proactiveCadence) Check(view *model.WorkloadView, move model.Move, pol model.Policy) Verdict {
	// Reactive path: with a trusted, recent EVENT bearing on this pod (M-28 HasEventEvidence —
	// the event-only, age-weighted subset, NOT the broad HasEvidence that also fires on the
	// physics/topology AI classification a healthy event-less GPU server carries), the move is a
	// response, not hygiene — leave the cadence to anti-over-rotation. This is the positive
	// control (P4). Keying on the broad HasEvidence would fail-open on the physics-pinned churn
	// pod (model-theft/LLM-jacking with zero events) — the exact pod this cap must throttle.
	if view.HasEventEvidence {
		return feasible
	}
	// An unset floor reproduces base byte-for-byte (no cap): a policy built without ProactiveFloor
	// is unchanged.
	if pol.ProactiveFloor <= 0 {
		return feasible
	}
	v := ExposureVarFor(move.Action) // reuse the M-23 action→clock map (no second clock)
	since, ok := mostRecentSince(view, v)
	if !ok {
		// FAIL-OPEN (as anti-over-rotation does): the pod has no clock for this variable yet — it
		// was never actuated, so there is no churn to cap and the FIRST hygiene move must be allowed
		// (else hygiene never starts — P-M118). An ungoverned action ("" from ExposureVarFor) also
		// lands here and is never capped. A mapped-but-unclocked variable is a wiring bug caught at
		// build time by M-23's completeness test, not by a runtime veto.
		return feasible
	}
	if since < pol.ProactiveFloor {
		return Verdict{Feasible: false, Reason: fmt.Sprintf(
			"proactive-cadence: %s hygiene-reset %s ago < floor=%s (no evidence)",
			v, since.Round(1e9), pol.ProactiveFloor)}
	}
	return feasible
}

func init() {
	Registry.Register(proactiveCadence{})
}
