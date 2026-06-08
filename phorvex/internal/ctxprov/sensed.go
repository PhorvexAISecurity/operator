/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ctxprov

import (
	"github.com/phorvex/phorvex/internal/model"
	"github.com/r6security/phoenix/api/v1beta1"
)

// sensed is the DEFAULT ContextProvider (PRD §4.2 five sensed signals):
//
//  1. AssetValue — labels (data-class map) + mounted-secret count + blast-radius
//     graph score. Sets cost_if_compromised / consequence weighting (R6 has none).
//  2. Phase — already derived during ingest; passed through.
//  3. ThreatPosture — recent event severity for this pod + neighbors (boosts risk).
//  4. Exposure — time-since-last-move vs the proactive floor (boosts risk over time).
//  5. SLOHeadroom — remaining latency/availability budget (hard limit on disruption).
type sensed struct{}

func (sensed) Name() string { return "sensed-context" }

func (sensed) Context(view *model.WorkloadView, pol model.Policy) model.ContextSignals {
	// (1) Asset value.
	asset := 0.0
	if pol.AssetWeightFromLabels != nil {
		asset = pol.AssetWeightFromLabels(view.Pod.Labels)
	}
	asset += pol.WeightSecrets * float64(len(view.Pod.MountedSecrets))
	if pol.BlastRadiusFromGraph {
		asset += view.BlastRadius // graph score already normalized [0,1]
	}
	// P-CONTEXT live-beta Tier-1: lift value toward the infection frontier (a pod
	// adjacent to a known-infected neighbor). Honest-absent (0 -> 1.0) at empty-I, so
	// the 1.62x gate + ucw nil-data tie reproduce exactly.
	if view.InfectionFrontier > 1 {
		asset *= view.InfectionFrontier
	}

	// (3) Threat posture: max severity among events on this pod (full weight) and on
	// neighbors (discounted), age-decayed over the proactive-floor horizon.
	posture := 0.0
	for _, e := range view.Events {
		rank := v1beta1.ThreatLevelRank(e.ThreatLevel)
		if rank < 0 {
			rank = 0
		}
		sev := float64(rank) / 4.0
		decay := 1.0
		if pol.ProactiveFloor > 0 {
			decay = 1.0 - clampC(e.Age.Seconds()/pol.ProactiveFloor.Seconds(), 0, 1)
		}
		w := sev * decay
		if !e.TargetsPod {
			w *= 0.4
		}
		if w > posture {
			posture = w
		}
	}

	// (4) Exposure pressure from the pod-identity clock vs the proactive floor.
	exposure := 0.0
	if since, ok := view.ExposureByVariable[model.VarPodIdentity]; ok && pol.ProactiveFloor > 0 {
		exposure = clampC(since.Seconds()/pol.ProactiveFloor.Seconds(), 0, 1)
	}

	// (5) SLO headroom (1 = full headroom). Derived from p99 vs ceiling when known.
	headroom := 1.0
	if pol.P99Ms > 0 && view.Telemetry.Present && view.Telemetry.P99Ms > 0 {
		headroom = clampC(1.0-view.Telemetry.P99Ms/float64(pol.P99Ms), 0, 1)
	}

	return model.ContextSignals{
		AssetValue:    asset,
		Phase:         view.Phase,
		ThreatPosture: posture,
		Exposure:      exposure,
		SLOHeadroom:   headroom,
	}
}

func clampC(x, lo, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

func init() { Registry.Register(sensed{}) }
