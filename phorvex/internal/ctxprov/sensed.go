/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ctxprov

import (
	"sort"
	"sync"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/r6security/phoenix/api/v1beta1"
)

// threatRankUnknown is the rank assigned to a threat level outside the canonical vocabulary
// (v1beta1.ThreatLevelRank returns -1). It is deliberately MEDIUM (2 of 4): unknown means we do
// not know how severe the event is, so treating it as `info` (the previous behaviour) hides real
// threats, while treating it as `critical` would let a single mislabelled event dominate a tenant.
const threatRankUnknown = 2

// unknownThreatLevels records out-of-vocabulary values. All access is protected by the mutex so
// the size check and insertion are one operation; a Load/check/LoadOrStore sequence can exceed the
// budget when several event streams discover distinct values concurrently.
var unknownThreatLevels = struct {
	sync.Mutex
	seen      map[string]struct{}
	truncated bool
}{seen: map[string]struct{}{}}

// unknownThreatLevelBudget caps how many DISTINCT out-of-vocabulary levels are retained.
//
// This map is keyed on a string that arrives from OUTSIDE the operator — a SecurityEvent's
// ThreatLevel — and the whole reason this code path exists is that the value is not from a fixed
// vocabulary. An unbounded map keyed on unvalidated input is a memory leak waiting for a
// misconfigured detector, and a growth primitive for anything that can author SecurityEvents. The
// operator is long-lived and never resets this, so it would only ever grow.
//
// The cap is diagnostic, not defensive: 32 distinct levels is far more than a real detector
// vocabulary, so hitting it means something is generating garbage — which is itself the signal, and
// is why unknownThreatLevelsTruncated exists rather than the overflow being dropped silently.
const unknownThreatLevelBudget = 32

// unknownThreatLevel notes an out-of-vocabulary level. Exposed for the metric/report path; the
// dedupe means the caller can invoke it on every event without cost.
func unknownThreatLevel(level string) {
	unknownThreatLevels.Lock()
	defer unknownThreatLevels.Unlock()
	if _, loaded := unknownThreatLevels.seen[level]; loaded {
		return // already recorded; no growth, no counter churn
	}
	if len(unknownThreatLevels.seen) >= unknownThreatLevelBudget {
		unknownThreatLevels.truncated = true
		return
	}
	unknownThreatLevels.seen[level] = struct{}{}
}

// UnknownThreatLevelsTruncated reports that MORE distinct out-of-vocabulary levels were seen than
// the budget retains. A true here is a stronger signal than the list itself: the detector is not
// merely using an unmapped level, it is emitting unbounded variety.
func UnknownThreatLevelsTruncated() bool {
	unknownThreatLevels.Lock()
	defer unknownThreatLevels.Unlock()
	return unknownThreatLevels.truncated
}

// UnknownThreatLevelsSeen returns the out-of-vocabulary threat levels observed so far, sorted.
// A non-empty result is an operator-visible signal that the detector vocabulary needs extending —
// every one of these events is being scored at the `threatRankUnknown` fallback, not its real
// severity.
func UnknownThreatLevelsSeen() []string {
	unknownThreatLevels.Lock()
	defer unknownThreatLevels.Unlock()
	out := make([]string, 0, len(unknownThreatLevels.seen))
	for level := range unknownThreatLevels.seen {
		out = append(out, level)
	}
	sort.Strings(out)
	return out
}

// sensed is the DEFAULT ContextProvider (PRD §4.2 five sensed signals):
//
//  1. AssetValue — labels (data-class map) + mounted-secret count + blast-radius
//     graph score. Sets cost_if_compromised / consequence weighting (R6 has none).
//  2. Phase — already derived during ingest; passed through.
//  3. ThreatPosture — recent event severity for this pod + neighbors, recorded for
//     audit/explainability. P1 targeting consumes the raw events through kill-chain
//     P(hold)/stage urgency; this derived scalar is not applied a second time.
//  4. Exposure — time-since-last-move vs the proactive floor (boosts risk over time).
//  5. SLOHeadroom — remaining latency/availability budget (hard limit on disruption).
type sensed struct{}

func (sensed) Name() string { return "sensed-context" }

func (sensed) Context(view *model.WorkloadView, pol model.Policy) model.ContextSignals {
	// (1) Asset value.
	asset := pol.AssetWeights.Weight(view.Pod.Labels)
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
		// The credential vector is meaningful only for the current, independently
		// observed Pod-bound API token. Keep this context scalar on the same
		// admission boundary as recon and kill-chain; other event types retain
		// their established handling.
		if e.Type == model.AttackVectorPodBoundAPIAuth &&
			!model.PodBoundAPIAuthEventEligible(e, view.Pod, pol.EffectiveEventAgeHorizon()) {
			continue
		}
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
		// One aging function for both halves of belief (M-27): the same linear
		// w = 1 − clamp01(age/τ_ev) the kill-chain evidence sum now uses. The inherited
		// one-hour τ_ev is independent of cadence and remains uncalibrated.
		decay := 0.0
		if !e.TimestampMissing {
			decay = model.EventAgeWeight(e.Age, eventAgeHorizonCtx(pol))
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

	// (5) SLO headroom (1 = full headroom), derived from p99 vs ceiling ONLY when the
	// latency signal is a usable measurement. Absent/stale/errored ⇒ gate SKIPPED: headroom
	// stays fully permissive (never blocks a move, P-NO-FREEZE) and headroomKnown=false so the
	// record reports sloGate=skipped and the metric counts it — no silent full-headroom 1.0 (B-3).
	headroom := 1.0
	headroomKnown := false
	if pol.P99Ms > 0 && view.Telemetry.P99Ms.Usable() && view.Telemetry.P99Ms.Value > 0 {
		headroom = clampC(1.0-view.Telemetry.P99Ms.Value/float64(pol.P99Ms), 0, 1)
		headroomKnown = true
	}

	return model.ContextSignals{
		AssetValue:       asset,
		Phase:            view.Phase,
		ThreatPosture:    posture,
		Exposure:         exposure,
		SLOHeadroom:      headroom,
		SLOHeadroomKnown: headroomKnown,
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

// eventAgeHorizonCtx shares the one effective rule with every event consumer.
func eventAgeHorizonCtx(pol model.Policy) time.Duration {
	return pol.EffectiveEventAgeHorizon()
}
