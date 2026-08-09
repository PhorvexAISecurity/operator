/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ctxprov

import (
	"sort"
	"sync"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/r6security/phoenix/api/v1beta1"
)

// threatRankUnknown is the rank assigned to a threat level outside the canonical vocabulary
// (v1beta1.ThreatLevelRank returns -1). It is deliberately MEDIUM (2 of 4): unknown means we do
// not know how severe the event is, so treating it as `info` (the previous behaviour) hides real
// threats, while treating it as `critical` would let a single mislabelled event dominate a tenant.
const threatRankUnknown = 2

// unknownThreatLevels records every out-of-vocabulary threat level seen, so an operator can find
// and map it instead of silently living with a degraded signal. Deduplicated — a detector emitting
// the same bad level every tick must not flood the log.
var unknownThreatLevels sync.Map

// unknownThreatLevel notes an out-of-vocabulary level. Exposed for the metric/report path; the
// dedupe means the caller can invoke it on every event without cost.
func unknownThreatLevel(level string) {
	unknownThreatLevels.LoadOrStore(level, struct{}{})
}

// UnknownThreatLevelsSeen returns the out-of-vocabulary threat levels observed so far, sorted.
// A non-empty result is an operator-visible signal that the detector vocabulary needs extending —
// every one of these events is being scored at the `threatRankUnknown` fallback, not its real
// severity.
func UnknownThreatLevelsSeen() []string {
	var out []string
	unknownThreatLevels.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok {
			out = append(out, s)
		}
		return true
	})
	sort.Strings(out)
	return out
}

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
			// FAIL-CLOSED. An UNKNOWN threat level is not a harmless one. This used to clamp to 0,
			// which is exactly `info` — so a detector emitting a severity outside our vocabulary
			// ("severe", "warning", a localised string, a new Falco/CrowdStrike level) was scored as
			// the LOWEST possible threat and the event effectively disappeared. Unknown ≠ benign:
			// we cannot tell how bad it is, so we must not assume the best case.
			//
			// Mapped to MEDIUM rather than critical on purpose: unknown means uncertain, and
			// unconditionally maximising would let one mislabelled event dominate the posture of a
			// whole tenant. Medium is the honest midpoint — high enough that a real threat is not
			// silently dropped, low enough that a vocabulary gap is not an amplifier.
			rank = threatRankUnknown
			unknownThreatLevel(e.ThreatLevel)
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
