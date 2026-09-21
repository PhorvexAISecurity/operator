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

// RespawnFlowRegime identifies the input/action support behind one learned
// respawn estimate. It is deliberately independent of the RLS feature vector:
// changing this classification must not migrate or reset learned owner state.
type RespawnFlowRegime string

const (
	RespawnFlowMeasuredLoad  RespawnFlowRegime = "measured-load"
	RespawnFlowMissingLoad   RespawnFlowRegime = "missing-load"
	RespawnFlowDrainingPhase RespawnFlowRegime = "draining-phase"
	RespawnFlowUnknownPhase  RespawnFlowRegime = "unknown-phase"
	RespawnFlowMIGProxy      RespawnFlowRegime = "mig-proxy"
)

type respawnFlowEstimate struct {
	PredictedMean      float64
	Effective          float64
	Regime             RespawnFlowRegime
	ConservativeFloor  float64
	FloorApplied       bool
	UncertaintyBound   float64
	UncertaintyApplied bool
}

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
	unknownActionFlowMax      = model.CFlowMaximum
	quarantineBase            = 0.25
	quarantineConnectionSpan  = 0.15
	requestRateNormalizer     = 200.0
	connectionCountNormalizer = 100.0

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
		return c.respawnFlow(view, action).Effective
	case flowQuarantine:
		flow := quarantineBase
		// cAdvisor ConnCount is infra-universal; gate on its own usability, not any-signal.
		if view.Telemetry.ConnCount.Usable() {
			flow += quarantineConnectionSpan * sat(view.Telemetry.ConnCount.Value/connectionCountNormalizer)
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

// respawnFlow preserves the six-dimensional RLS prediction as the learned mean,
// then applies source-owned policy floors only where the action or current inputs
// are unsupported. The robust upper bound is consumed by P1Cost.Evaluation; it is
// not folded into the mean and never becomes a training label.
func (c *P1Cost) respawnFlow(view *model.WorkloadView, action model.Action) respawnFlowEstimate {
	predicted := c.RLS.Predict(Features(view))
	estimate := respawnFlowEstimate{PredictedMean: predicted, Effective: predicted}

	phase := model.PhaseUnknown
	reqRateUsable := false
	if view != nil {
		phase = view.Phase
		reqRateUsable = view.Telemetry.ReqRate.Usable()
	}
	knownPhase := false
	for _, candidate := range model.AllWorkloadPhases {
		if phase == candidate {
			knownPhase = true
			break
		}
	}

	switch {
	case action == model.ActionMIGRebind:
		estimate.Regime = RespawnFlowMIGProxy
	case !knownPhase || phase == model.PhaseUnknown:
		estimate.Regime = RespawnFlowUnknownPhase
	case phase == model.PhaseDraining:
		estimate.Regime = RespawnFlowDrainingPhase
	case !reqRateUsable:
		estimate.Regime = RespawnFlowMissingLoad
	default:
		estimate.Regime = RespawnFlowMeasuredLoad
	}

	// MIG is always an unsupported proxy, but it still receives the same phase/load
	// point floor as a rotate so an unsupported action cannot bypass input uncertainty.
	switch {
	case !knownPhase || phase == model.PhaseUnknown:
		estimate.ConservativeFloor = phaseEncoding(model.PhaseUnknown).switchPrior
		estimate.FloorApplied = true
	case phase == model.PhaseDraining:
		estimate.ConservativeFloor = phaseEncoding(model.PhaseDraining).switchPrior
		estimate.FloorApplied = true
	case !reqRateUsable:
		estimate.ConservativeFloor = phaseEncoding(phase).switchPrior
		estimate.FloorApplied = true
	}
	if estimate.FloorApplied && estimate.Effective < estimate.ConservativeFloor {
		estimate.Effective = estimate.ConservativeFloor
	}
	if estimate.Regime != RespawnFlowMeasuredLoad {
		estimate.UncertaintyBound = unknownActionFlowMax
		estimate.UncertaintyApplied = true
	}
	return estimate
}

// servingLoadPressure is a bounded, dimensionless pressure signal. It does not
// pretend that an aborted-request count is a PodReady duration: request and
// connection counts are normalized within their own model family and only shape
// the unvalidated disruption-loss prior.
func servingLoadPressure(view *model.WorkloadView) float64 {
	if view == nil {
		return 0
	}
	// Per-signal gates: an absent app signal contributes 0 pressure, never a measured zero.
	req, conn := 0.0, 0.0
	if view.Telemetry.ReqRate.Usable() {
		req = sat(view.Telemetry.ReqRate.Value / requestRateNormalizer)
	}
	if view.Telemetry.ConnCount.Usable() {
		conn = sat(view.Telemetry.ConnCount.Value / connectionCountNormalizer)
	}
	return maxf(req, conn)
}
