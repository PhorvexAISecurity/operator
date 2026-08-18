/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package slo carries the SLO cost model's two data-free halves: the per-action
// deterministic disruption bound, and the ledger of disruption Phorvex itself
// caused. Both are computable today. The gate that divides one by a remaining
// budget is NOT here — it needs SLO history the cluster does not yet record.
package slo

import (
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/model"
)

// Bound is the deterministic worst case for one action, in unavailable
// replica-seconds:
//
//	bound = MaxUnavailableReplicas * MaxUnavailableDuration
//
// Deterministic, not probabilistic. A percentile — even p99 with a margin on top
// — still lets a fraction of cases through, and a hard gate that a fraction of
// cases can cross is not a hard gate. The bound is the worst case inside the
// operating range, so nothing may exceed it.
//
// If the replica count moves during the action the true cost is the area under
// the curve; the product is its rectangular envelope and always at least as
// large, which is the direction a bound has to err.
//
// Load is deliberately absent. Multiplying by requests-per-second would produce
// lost requests, not replica-seconds — a different quantity in different units.
// Load belongs to the lost-request and lost-token bounds (see LostRequestBound),
// not to this one.
type Bound struct {
	Action model.Action

	// MaxUnavailableReplicas is how many Ready serving replicas this action can
	// take out of rotation at once. Zero for in-process actions, which is exact
	// rather than optimistic: they keep the pod Ready.
	MaxUnavailableReplicas int

	// MaxUnavailableDuration is the worst RECOVERY time observed for this action,
	// never an assumed or invented figure. Zero when MaxUnavailableReplicas is
	// zero, since nothing goes unavailable and there is nothing to wait for.
	MaxUnavailableDuration time.Duration

	// Evidence records where the numbers came from, so a bound can be audited
	// without archaeology. Every registered bound has one.
	Evidence string
}

// ReplicaSeconds is the bound in the unit the disruption budget is stated in.
func (b Bound) ReplicaSeconds() float64 {
	return float64(b.MaxUnavailableReplicas) * b.MaxUnavailableDuration.Seconds()
}

// vLLMWorstReplacementRecovery is the only worst-case recovery Phorvex has
// actually MEASURED: 117s from replacement to Ready, the worst observed vLLM
// replacement on the production EKS Tesla T4 fleet, against the 400s documented
// warm-load scale. It is the same measurement the GPUEnvelopeMax=0.2925
// calibration was derived from.
//
// It bounds `rotate`, which is the action that measurement describes. It is NOT
// silently reused for other replica-removing actions: a recovery time measured
// on one action is evidence about that action.
const vLLMWorstReplacementRecovery = 117 * time.Second

// bounds is the registry. An action is listed only when its numbers are derived
// or measured; an action absent from here is UNBOUNDED, and an unbounded action
// is blocked rather than guessed at.
var bounds = map[model.Action]Bound{
	model.ActionNoop: {
		Action:                 model.ActionNoop,
		MaxUnavailableReplicas: 0,
		Evidence:               "no-op: touches nothing, so it can remove no replica",
	},
	model.ActionRotate: {
		Action:                 model.ActionRotate,
		MaxUnavailableReplicas: 1,
		MaxUnavailableDuration: vLLMWorstReplacementRecovery,
		Evidence: "one replica per move (feasibility.RemovesReadyReplica); duration = worst " +
			"observed vLLM replacement recovery on the production EKS T4 fleet, 117s to Ready",
	},
}

// BoundFor returns the deterministic bound for an action, and whether one exists.
//
// The false return is the load-bearing one. It means no bound could be
// established, and per the agreed model that action is then blocked for the
// service rather than admitted on an assumption. Callers must not substitute a
// default: a made-up bound is worse than a blocked action, because it is a hard
// gate that silently is not one.
func BoundFor(a model.Action) (Bound, bool) {
	if b, ok := bounds[a]; ok {
		return b, true
	}
	// Actions that remove no Ready replica are bounded at exactly zero
	// replica-seconds, and that needs no measurement — it follows from what the
	// action does. kv-reset keeps the pod alive and Ready, warm-swap cuts over to
	// an already-Ready shadow, and the identity/route/endpoint rotations change
	// configuration rather than replica count. Blocking those for want of a
	// stopwatch reading would forbid exactly the gentle in-process defense that
	// suits a single-replica inference server best.
	if !feasibility.RemovesReadyReplica(a) {
		return Bound{
			Action:                 a,
			MaxUnavailableReplicas: 0,
			Evidence: "in-process action: keeps the pod Ready, so it removes no serving " +
				"replica and its disruption bound is exactly zero (feasibility.RemovesReadyReplica)",
		}, true
	}
	// Removes a replica, and nobody has measured how long it stays removed.
	return Bound{}, false
}

// Bounded reports whether the action may run under the disruption model at all.
func Bounded(a model.Action) bool {
	_, ok := BoundFor(a)
	return ok
}

// Unmeasured lists the actions that remove a Ready replica but have no measured
// recovery time, sorted for a stable read. These are the actions the model blocks
// today, and the list is the work queue for closing that: each entry needs a
// measured worst-case recovery, not an estimate.
func Unmeasured(enabled []model.Action) []model.Action {
	var out []model.Action
	for _, a := range enabled {
		if !Bounded(a) {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// LostRequestBound is the separate, differently-dimensioned bound that DOES take
// load: the requests a service could lose while an action holds replicas out,
// as maxRequestsPerSec * outage duration.
//
// It is kept apart from Bound on purpose. Folding load into the replica-seconds
// figure would add quantities in different units and produce a number that means
// nothing. Callers that want a request-loss ceiling ask for it explicitly.
//
// This is the worst case in which the outage is total for its duration. A service
// whose surviving replicas absorb the traffic loses fewer requests than this, and
// never more — which is the direction a bound must err. The same shape gives the
// token ceiling for an inference workload: maxTokensPerSec * degradation duration.
func LostRequestBound(b Bound, maxRequestsPerSec float64) float64 {
	if b.MaxUnavailableReplicas == 0 {
		return 0
	}
	return maxRequestsPerSec * b.MaxUnavailableDuration.Seconds()
}
