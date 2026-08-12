/*
 * Phorvex — action-specific P1 flow-cost shapes (PHVX-9c / PHORVEXSEC-92).
 */

package cost

import "github.com/phorvex/phorvex/internal/model"

type flowFamily uint8

const (
	flowUnknown flowFamily = iota
	flowNone
	flowRespawn
	flowQuarantine
	flowCutover
	flowServingState
	flowLightweight
)

// These are dimensionless disruption-loss priors, NOT fabricated durations and
// NOT conversions to replacement PodReady seconds.
//
// [ESTIMATE-UNVALIDATED] Replace cutover and serving-state values with per-action
// measurements as the fleet makes them observable (PHVX-9d starts with kv-reset
// TTFT). The ordering is deliberate: a live serving-state refresh is cheaper than
// route drain/reconvergence, which is cheaper than a full respawn prior.
const (
	estimatedCutoverBase      = 0.10
	estimatedCutoverLoadSpan  = 0.15
	estimatedServingStateBase = 0.05
	estimatedServingLoadSpan  = 0.10
	estimatedLightweightFlow  = 0.02
	unknownActionFlowMax      = 2.00
)

// flowFamilyForAction is the single exhaustive routing table. New mutating
// actions must be classified explicitly: the completeness test fails, and the
// runtime fallback uses the conservative maximum instead of silently inheriting
// the rotation-trained RLS.
func flowFamilyForAction(action model.Action) flowFamily {
	switch action {
	case model.ActionNoop:
		return flowNone
	case model.ActionRotate, model.ActionMIGRebind:
		return flowRespawn
	case model.ActionQuarantine:
		return flowQuarantine
	case model.ActionWarmSwap, model.ActionModelShardReplace,
		model.ActionEndpointRotate, model.ActionRequestDrain:
		return flowCutover
	case model.ActionKVReset, model.ActionKVMigrateInvalidate,
		model.ActionAdapterRotate, model.ActionGuardrailRotate:
		return flowServingState
	case model.ActionIdentityRotate, model.ActionRouteRotate,
		model.ActionDebugger, model.ActionCustomInject:
		return flowLightweight
	default:
		return flowUnknown
	}
}

func (c *P1Cost) actionFlow(view *model.WorkloadView, action model.Action) float64 {
	switch flowFamilyForAction(action) {
	case flowNone:
		return 0
	case flowRespawn:
		// Calibrated only from measured replacement PodReady delay. For mig-rebind
		// this is explicitly a lower-bound proxy until repartition timing exists.
		return c.RLS.Predict(Features(view))
	case flowQuarantine:
		flow := 0.25
		if view.Telemetry.Present {
			flow += 0.15 * sat(view.Telemetry.ConnCount/100.0)
		}
		return flow
	case flowCutover:
		return estimatedCutoverBase + estimatedCutoverLoadSpan*servingLoadPressure(view)
	case flowServingState:
		return estimatedServingStateBase + estimatedServingLoadSpan*servingLoadPressure(view)
	case flowLightweight:
		return estimatedLightweightFlow
	default:
		return unknownActionFlowMax
	}
}

// servingLoadPressure is a bounded, dimensionless pressure signal. It does not
// pretend that an aborted-request count is a PodReady duration: request and
// connection counts are normalized within their own model family and only shape
// the unvalidated disruption-loss prior.
func servingLoadPressure(view *model.WorkloadView) float64 {
	if view == nil || !view.Telemetry.Present {
		return 0
	}
	req := sat(view.Telemetry.ReqRate / 200.0)
	conn := sat(view.Telemetry.ConnCount / 100.0)
	return maxf(req, conn)
}
