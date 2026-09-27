/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package slo carries the SLO cost model's data-free halves: per-action impact
// classification and the ledger of disruption Phorvex itself caused. The gate
// that divides an impact by remaining budget is deliberately not implemented;
// the cluster does not yet retain the service-wide SLO history it requires.
package slo

import (
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// BoundStatus is a proof status, not a confidence level.
type BoundStatus string

const (
	// StatusZero means replica loss is structurally impossible on every shipped
	// execution path. No duration estimate is needed because the multiplier is 0.
	StatusZero BoundStatus = "zero"
	// StatusBounded means every replica-losing success, failure, timeout and
	// rollback phase has an enforced deadline and bounded safe recovery.
	StatusBounded BoundStatus = "bounded"
	// StatusUnknown means at least one contributing path lacks such a deadline or
	// recovery guarantee. Unknown must never be serialized as a numeric zero.
	StatusUnknown BoundStatus = "unknown"
)

// Bound classifies one action's unavailable-replica impact.
//
// A finite positive bound is valid only when it comes from enforced action and
// safe-recovery deadlines. ObservedMaxRecovery is deliberately separate: a
// historical maximum can validate a proposed contract, but cannot create one.
type Bound struct {
	Action                 model.Action
	Status                 BoundStatus
	MaxUnavailableReplicas int
	MaxUnavailableDuration time.Duration
	MaxReplicaSeconds      float64
	Evidence               string
	MissingBound           string

	ObservedMaxRecovery time.Duration
	ObservedEvidence    string
}

// ReplicaSeconds returns a numeric value only for a proven zero or finite bound.
// The boolean prevents unknown from being confused with a completed zero.
func (b Bound) ReplicaSeconds() (float64, bool) {
	switch b.Status {
	case StatusZero:
		return 0, true
	case StatusBounded:
		if b.MaxUnavailableReplicas < 0 || b.MaxUnavailableDuration <= 0 {
			return 0, false
		}
		if b.MaxReplicaSeconds > 0 {
			return b.MaxReplicaSeconds, true
		}
		return float64(b.MaxUnavailableReplicas) * b.MaxUnavailableDuration.Seconds(), true
	default:
		return 0, false
	}
}

const vLLMObservedReplacementRecovery = 117 * time.Second

func zero(action model.Action, evidence string) Bound {
	return Bound{Action: action, Status: StatusZero, Evidence: evidence}
}

func unknown(action model.Action, maxReplicas int, missing string) Bound {
	// maxReplicas < 0 means the action can alter a shared serving path and no
	// finite per-request replica-loss cardinality has been proven.
	return Bound{
		Action: action, Status: StatusUnknown, MaxUnavailableReplicas: maxReplicas,
		MissingBound: missing,
	}
}

// classifications is an explicit proof registry. It intentionally does not infer
// zero from the availability-floor predicate: that predicate is a selection guard,
// not a success/failure/rollback phase proof. Actions that alter serving paths or
// run arbitrary payloads remain unknown until their complete contracts are bounded.
var classifications = map[model.Action]Bound{
	model.ActionNoop: zero(model.ActionNoop,
		"no-op has no mutation path and cannot reduce a Ready serving replica"),
	model.ActionIdentityRotate: zero(model.ActionIdentityRotate,
		"metadata-only identity epoch update; it does not change pod UID, IP, token, readiness, or routing"),
	model.ActionRouteRotate: unknown(model.ActionRouteRotate, -1,
		"Service route cutover and rollback preserve a controller membership floor but have no enforced safe-return or network data-plane deadline"),
	model.ActionDisable: zero(model.ActionDisable,
		"declared-not-implemented handler always returns emitted=false and has no mutation path"),

	model.ActionRotate: unknown(model.ActionRotate, 1,
		"Delete/replacement has no enforced end-to-end deadline and no bounded rollback or safe-recovery deadline"),
	model.ActionQuarantine: unknown(model.ActionQuarantine, 1,
		"detachment persists until a separate rollback; neither quarantine duration nor safe recovery has an enforced deadline"),
	model.ActionDebugger: unknown(model.ActionDebugger, 1,
		"ephemeral diagnostic payload has no bounded operating range, completion deadline, or rollback"),
	model.ActionCustomInject: unknown(model.ActionCustomInject, 1,
		"operator-supplied ephemeral payload has no bounded operating range, completion deadline, or rollback"),
	model.ActionWarmSwap: unknown(model.ActionWarmSwap, 1,
		"warm-up, cutover, retire, failure and rollback paths do not all have enforced safe-return deadlines"),
	model.ActionMIGRebind: unknown(model.ActionMIGRebind, 1,
		"MIG allocation, cutover and rollback paths do not all have enforced safe-return deadlines"),
	model.ActionKVReset: unknown(model.ActionKVReset, 1,
		"serving-stack cache flush has no enforced safe-state/readiness recovery contract after timeout or failure"),
	model.ActionEndpointRotate: unknown(model.ActionEndpointRotate, -1,
		"Service re-key/cutover and rollback paths do not have enforced safe-return deadlines"),
	model.ActionModelShardReplace: unknown(model.ActionModelShardReplace, -1,
		"shard warm-up, cutover, retirement and rollback paths lack complete enforced safe-return deadlines"),
	model.ActionAdapterRotate: unknown(model.ActionAdapterRotate, 1,
		"adapter unload/load can leave the served adapter unavailable and rollback has no enforced safe-return deadline"),
	model.ActionRequestDrain: unknown(model.ActionRequestDrain, 1,
		"drain removes serving capacity and re-admission/rollback has no enforced safe-return deadline"),
	model.ActionGuardrailRotate: unknown(model.ActionGuardrailRotate, -1,
		"guardrail cutover and rollback do not have enforced safe-return deadlines"),
	model.ActionKVMigrateInvalidate: unknown(model.ActionKVMigrateInvalidate, -1,
		"distributed invalidate/migration and recovery paths do not have enforced safe-return deadlines"),
	model.ActionSensitiveOutputPolicyActivate: unknown(model.ActionSensitiveOutputPolicyActivate, -1,
		"response-field policy activation and rollback have no calibrated safe-return deadline"),
	model.ActionVoiceMemoryNoteRevoke: unknown(model.ActionVoiceMemoryNoteRevoke, -1,
		"voice memory quarantine and projection readback have no calibrated safe-return deadline"),
	model.ActionVoiceRefundPairDeny: unknown(model.ActionVoiceRefundPairDeny, -1,
		"voice refund pair denial and projection readback have no calibrated safe-return deadline"),
	model.ActionLiteLLMClientRevoke: unknown(model.ActionLiteLLMClientRevoke, -1,
		"owned client-channel denial and gateway readback have no calibrated safe-return deadline"),
}

func init() {
	b := classifications[model.ActionRotate]
	b.ObservedMaxRecovery = vLLMObservedReplacementRecovery
	b.ObservedEvidence = "worst observed vLLM replacement recovery on the EKS T4 fleet; validation evidence only"
	classifications[model.ActionRotate] = b
}

// Classify returns the proof status and provenance for a known action.
func Classify(action model.Action) (Bound, bool) {
	b, ok := classifications[action]
	return b, ok
}

// BoundFor returns only a proven finite bound. An unknown action returns false;
// callers needing its missing-proof explanation should use Classify.
func BoundFor(action model.Action) (Bound, bool) {
	b, ok := Classify(action)
	if !ok || b.Status == StatusUnknown {
		return Bound{}, false
	}
	return b, true
}

// Bounded reports whether the action has a proven zero or finite bound.
func Bounded(action model.Action) bool {
	_, ok := BoundFor(action)
	return ok
}

// Unknown lists enabled actions whose deterministic proof is incomplete.
func Unknown(enabled []model.Action) []model.Action {
	var out []model.Action
	for _, action := range enabled {
		b, ok := Classify(action)
		if !ok || b.Status == StatusUnknown {
			out = append(out, action)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Unmeasured is retained for source compatibility. The corrected specification
// is broader than measurement: an observed maximum still leaves an action unknown.
func Unmeasured(enabled []model.Action) []model.Action { return Unknown(enabled) }

// AvailabilityBound is service-specific because the same replica loss can be a
// positive disruption with zero availability breach when sufficient headroom exists.
type AvailabilityBound struct {
	Status      BoundStatus
	MaxDuration time.Duration
	Evidence    string
}

// AvailabilityFor classifies breach time against a service's current Ready floor.
// readyReplicas and minAvailableReplicas must be non-negative observations.
func AvailabilityFor(action model.Action, readyReplicas, minAvailableReplicas int) AvailabilityBound {
	b, ok := Classify(action)
	if !ok || readyReplicas < 0 || minAvailableReplicas < 0 {
		return AvailabilityBound{Status: StatusUnknown, Evidence: "action or service Ready-floor input is unavailable"}
	}
	if b.Status == StatusZero {
		return AvailabilityBound{Status: StatusZero, Evidence: "action has zero replica disruption"}
	}
	if b.MaxUnavailableReplicas > 0 && readyReplicas-b.MaxUnavailableReplicas >= minAvailableReplicas {
		return AvailabilityBound{Status: StatusZero, Evidence: "declared maximum replica loss preserves minAvailableReplicas"}
	}
	if b.Status == StatusBounded {
		return AvailabilityBound{Status: StatusBounded, MaxDuration: b.MaxUnavailableDuration,
			Evidence: "replica-loss path is bounded and can cross minAvailableReplicas"}
	}
	return AvailabilityBound{Status: StatusUnknown, Evidence: b.MissingBound}
}

// LostRequestBound is intentionally separate from replica-seconds. It returns no
// numeric value for unknown disruption and therefore cannot launder unknown to 0.
func LostRequestBound(b Bound, maxRequestsPerSec float64) (float64, bool) {
	replicaSeconds, ok := b.ReplicaSeconds()
	if !ok {
		return 0, false
	}
	if b.Status == StatusZero {
		return 0, true
	}
	_ = replicaSeconds // establishes that the finite bound passed validation above
	return maxRequestsPerSec * b.MaxUnavailableDuration.Seconds(), true
}
