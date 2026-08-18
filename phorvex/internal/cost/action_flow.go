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
	flowKVResetMeasured
	flowServingState
	flowLightweight
)

// These are dimensionless disruption-loss priors, NOT fabricated durations and
// NOT conversions to replacement PodReady seconds.
//
// [ESTIMATE-UNVALIDATED] Cutover and the remaining serving-state values need their
// own per-action measurements as the fleet makes them observable. kv-reset is no
// longer in that bucket: PHVX-9d measured its paired TTFT penalty on the live AWS
// vLLM endpoint and records the raw samples under benchmarks/kv-reset-ttft.
const (
	estimatedCutoverBase      = 0.10
	estimatedCutoverLoadSpan  = 0.15
	estimatedServingStateBase = 0.05
	estimatedServingLoadSpan  = 0.10
	estimatedLightweightFlow  = 0.02
	unknownActionFlowMax      = 2.00

	// Twenty paired samples on Qwen2.5-7B-Instruct-AWQ/vLLM 0.7.3 measured an
	// idle cached median TTFT of 325.196 ms and first-post-reset median TTFT of
	// 1811.871 ms. The paired median penalty was 1486.686 ms (95% bootstrap CI
	// 1484.418–1494.930 ms; 20/20 positive). C_flow is a dimensionless disruption
	// loss, so encode the measured fraction of post-reset TTFT spent on the reset
	// penalty, not raw milliseconds in a mixed-unit objective.
	measuredKVResetCachedTTFTMilliseconds    = 325.196398422122
	measuredKVResetPostResetTTFTMilliseconds = 1811.8705251254141
	measuredKVResetTTFTPenaltyFraction       = (measuredKVResetPostResetTTFTMilliseconds - measuredKVResetCachedTTFTMilliseconds) / measuredKVResetPostResetTTFTMilliseconds
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
	case model.ActionKVReset:
		return flowKVResetMeasured
	case model.ActionKVMigrateInvalidate, model.ActionAdapterRotate, model.ActionGuardrailRotate:
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
	case flowKVResetMeasured:
		return measuredKVResetTTFTPenaltyFraction
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
