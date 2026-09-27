/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package cost

import (
	"math"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	// DefaultCostCeiling is the single imported default used by production and
	// tests. See model.DefaultCostCeiling for the policy contract.
	DefaultCostCeiling = model.DefaultCostCeiling

	// NaNFailConservativeCost is the largest finite float. A NaN-bearing cost
	// evaluation is also excluded by category before optimization, so this value is
	// defense in depth for callers that ask ECost/CHi directly.
	NaNFailConservativeCost = math.MaxFloat64

	// UnactionableNaNCategory is deliberately distinct from ordinary infeasibility:
	// the former means a fixable data failure, the latter means the safety laws are
	// working with valid data.
	UnactionableNaNCategory = "unactionable due to NaN"
)

// EffectiveCostCeiling preserves explicit positive policy values and gives
// directly-constructed test/benchmark policies the same default as CRD-backed
// policies. NaN is intentionally not defaulted: Evaluation must surface it.
func EffectiveCostCeiling(pol model.Policy) float64 {
	if pol.CostCeiling == 0 {
		return DefaultCostCeiling
	}
	return pol.CostCeiling
}

// P1Cost is the assembled P1 cost model: C = normSparsity*C_norm + flowDisruption*
// C_flow. Respawn C_flow is calibrated from completed live rotations; cutover,
// serving-state, quarantine and lightweight mutations have separate action-specific
// shapes so rotation latency is never applied across incompatible units. Both
// components and their weights are dimensionless; ECost is not dollars. The legacy
// lambda controller multiplies ECost but is not certified as an exact move-budget
// dual. CHi is the conformal robust upper bound used by the HARD SLO gate. It is a
// stateful object (the RLS, conformal window and lambda state persist across ticks) owned by
// the decision engine.
type P1Cost struct {
	RLS       *RLS
	Conformal *ConformalBound
	Dual      *DualSolver
}

// P1Components is the exact decomposition used by the current objective-cost
// model. It is exported for empirical cost validation so a benchmark can record
// the model inputs without reimplementing (and potentially drifting from) ECost.
// State/GPU/availability are intentionally not separate additive terms: actionFlow
// incorporates the action-relevant serving/load signals, while state and availability
// remain hard feasibility constraints.
type P1Components struct {
	Norm  float64 `json:"c_norm"`
	Flow  float64 `json:"c_flow"`
	Total float64 `json:"total"`
}

// P1Evaluation carries the point and robust costs plus the fail-conservative
// category needed by candidate generation and audit. GPUEnvelopeApplied means the
// configured term participated in the robust maximum; it does not imply that the
// term dominated or that GPU behavior is empirically calibrated. NaNFeature is the
// precise input that made the action unactionable.
type P1Evaluation struct {
	P1Components
	CHi                       float64           `json:"chi"`
	FlowPredictedMean         float64           `json:"flow_predicted_mean"`
	FlowRegime                RespawnFlowRegime `json:"flow_regime,omitempty"`
	FlowConservativeFloor     float64           `json:"flow_conservative_floor"`
	FlowFloorApplied          bool              `json:"flow_floor_applied"`
	FlowUncertaintyBound      float64           `json:"flow_uncertainty_bound"`
	FlowUncertaintyApplied    bool              `json:"flow_uncertainty_applied"`
	FlowUncertaintySlack      float64           `json:"flow_uncertainty_slack"`
	ConformalWindowReady      bool              `json:"conformal_window_ready"`
	ConformalRegimeApplicable bool              `json:"conformal_regime_applicable"`
	GPUEnvelopeApplied        bool              `json:"gpu_envelope_applied"`
	GPUEnvelopeSlack          float64           `json:"gpu_envelope_slack"`
	UnactionableCategory      string            `json:"unactionable_category,omitempty"`
	NaNFeature                string            `json:"nan_feature,omitempty"`
}

// NewP1Cost constructs the P1 cost model seeded at the P0-equivalent prior.
func NewP1Cost() *P1Cost {
	return NewP1CostWithLambda(DefaultLambdaSeed)
}

// NewP1CostWithLambda constructs an isolated tenant cost bucket whose legacy
// runtime lambda starts from the tenant policy's configured seed.
func NewP1CostWithLambda(lambdaSeed float64) *P1Cost {
	return &P1Cost{RLS: NewRLS(), Conformal: NewConformalBound(), Dual: NewDualSolverWithSeed(lambdaSeed)}
}

// Structural components make the quarantine denominator reproducible. The first
// two are historical structural dimensions, not a count of live clocks (M-30).
// Node-placement exposure is declared-only; this fixed rubric does not read its
// clock. Keep the three-element denominator unchanged by clock cleanup.
const structuralNetworkIsolation = "network-isolation"

const (
	NormCostMetadataMutation     = 0.10
	NormCostPartialIdentity      = 0.15
	NormCostStateReset           = 0.20
	NormCostServingConfiguration = 0.25
	NormCostServiceRekey         = 0.35
	NormCostWorkloadReplacement  = 1.00
	NormCostSharedDeviceMutation = 1.25
)

var structuralComponents = []string{
	model.VarPodIdentity,
	model.VarNodePlacement,
	structuralNetworkIsolation,
}

// normCostP1 is the provisional C_norm rubric in logical pod-replacement units:
//
//	0.10 minimal local metadata mutation
//	0.15 partial identity metadata mutation
//	0.20 in-process state/config reset
//	0.25 computation-affecting serving configuration
//	0.35 effective Service/network re-key
//	1.00 one logical workload replacement
//	1.25 replacement plus shared device mutation [PROVISIONAL-UNVALIDATED]
//
// Every generatable mutating action is positive. Service and group context come
// from the view: endpoint-rotate earns 0.35 only when it can mutate a declared
// route Service, and model-shard-replace is additive over affected ranks.
func normCostP1(view *model.WorkloadView, move model.Move) float64 {
	switch move.Action {
	case model.ActionRotate, model.ActionWarmSwap:
		// Both retire one logical serving workload. Warm-swap's lower disruption
		// belongs to C_flow, not C_norm.
		return NormCostWorkloadReplacement
	case model.ActionQuarantine:
		return NormCostWorkloadReplacement / float64(len(structuralComponents))
	case model.ActionMIGRebind:
		return NormCostSharedDeviceMutation
	case model.ActionModelShardReplace:
		parallelSize := 1
		if view != nil && view.Pod.ParallelSize > parallelSize {
			parallelSize = view.Pod.ParallelSize
		}
		return float64(parallelSize)
	case model.ActionEndpointRotate:
		if view != nil && view.Pod.RouteServiceReady {
			return NormCostServiceRekey
		}
		return NormCostMetadataMutation
	case model.ActionAdapterRotate, model.ActionSensitiveOutputPolicyActivate, model.ActionVoiceMemoryNoteRevoke, model.ActionVoiceRefundPairDeny, model.ActionVoiceOutputPolicyActivate, model.ActionLiteLLMClientRevoke:
		return NormCostServingConfiguration
	case model.ActionKVReset, model.ActionKVMigrateInvalidate, model.ActionGuardrailRotate:
		return NormCostStateReset
	case model.ActionIdentityRotate:
		return NormCostPartialIdentity
	case model.ActionRouteRotate, model.ActionDebugger, model.ActionCustomInject, model.ActionRequestDrain:
		return NormCostMetadataMutation
	default:
		return 0
	}
}

func (c *P1Cost) components(view *model.WorkloadView, move model.Move, pol model.Policy) P1Components {
	components, _ := c.componentsWithRespawn(view, move, pol)
	return components
}

func (c *P1Cost) componentsWithRespawn(view *model.WorkloadView, move model.Move, pol model.Policy) (P1Components, respawnFlowEstimate) {
	if move.Action == model.ActionNoop {
		return P1Components{}, respawnFlowEstimate{}
	}
	cNorm := normCostP1(view, move)
	var respawn respawnFlowEstimate
	cFlow := 0.0
	if flowFamilyForAction(move.Action) == flowRespawn {
		respawn = c.respawnFlow(view, move.Action)
		cFlow = respawn.Effective
	} else {
		cFlow = c.actionFlow(view, move.Action)
	}
	return P1Components{
		Norm:  cNorm,
		Flow:  cFlow,
		Total: pol.NormSparsity*cNorm + pol.FlowDisruption*cFlow,
	}, respawn
}

// Evaluation computes the cost once and carries any NaN classification to the
// generator. This check happens before the low-level clamps, so missing telemetry
// cannot be silently reinterpreted as a cheap action.
func (c *P1Cost) Evaluation(view *model.WorkloadView, move model.Move, pol model.Policy) P1Evaluation {
	if move.Action == model.ActionNoop {
		return P1Evaluation{}
	}
	if feature := c.nanFeature(view, move, pol); feature != "" {
		return P1Evaluation{
			P1Components:         P1Components{Total: NaNFailConservativeCost},
			CHi:                  NaNFailConservativeCost,
			UnactionableCategory: UnactionableNaNCategory,
			NaNFeature:           feature,
		}
	}
	components, respawn := c.componentsWithRespawn(view, move, pol)
	chi := components.Total
	windowReady := c.Conformal != nil && c.Conformal.Calibrated()
	conformalApplicable := move.Action == model.ActionRotate && respawn.Regime == RespawnFlowMeasuredLoad
	envelopeApplied := false
	envelopeSlack := 0.0
	regimeSlack := 0.0
	if move.Action == model.ActionRotate {
		slack := c.Conformal.Quantile()
		if slack < 0 {
			slack = 0
		}
		if view != nil && view.Pod.HasGPU {
			envelopeApplied = true
			envelopeSlack = pol.FlowDisruption * GPUEnvelopeMax()
			slack = maxf(slack, envelopeSlack)
		}
		chi += slack
	}
	if respawn.UncertaintyApplied {
		regimeSlack = pol.FlowDisruption * maxf(0, respawn.UncertaintyBound-components.Flow)
		chi = maxf(chi, components.Total+regimeSlack)
	}
	if math.IsNaN(components.Norm) || math.IsNaN(components.Flow) ||
		math.IsNaN(components.Total) || math.IsNaN(chi) {
		return P1Evaluation{
			P1Components:         P1Components{Total: NaNFailConservativeCost},
			CHi:                  NaNFailConservativeCost,
			UnactionableCategory: UnactionableNaNCategory,
			NaNFeature:           "derived-cost",
		}
	}
	return P1Evaluation{
		P1Components:              components,
		CHi:                       chi,
		FlowPredictedMean:         respawn.PredictedMean,
		FlowRegime:                respawn.Regime,
		FlowConservativeFloor:     respawn.ConservativeFloor,
		FlowFloorApplied:          respawn.FloorApplied,
		FlowUncertaintyBound:      respawn.UncertaintyBound,
		FlowUncertaintyApplied:    respawn.UncertaintyApplied,
		FlowUncertaintySlack:      regimeSlack,
		ConformalWindowReady:      windowReady,
		ConformalRegimeApplicable: conformalApplicable,
		GPUEnvelopeApplied:        envelopeApplied,
		GPUEnvelopeSlack:          envelopeSlack,
	}
}

// Components returns the exact current-model terms and weighted total for a move.
func (c *P1Cost) Components(view *model.WorkloadView, move model.Move, pol model.Policy) P1Components {
	return c.Evaluation(view, move, pol).P1Components
}

// ECost is the expected (objective) cost of a move: the calibrated point estimate.
func (c *P1Cost) ECost(view *model.WorkloadView, move model.Move, pol model.Policy) float64 {
	return c.Evaluation(view, move, pol).Total
}

// T0-C read-only accessors for the decision trace. None of them mutates model
// state (Quantile sorts a copy); Observe is never reachable through them.

// Name returns the cost-model identity constant — the same value the registry
// stub reports — so the trace records the model, not a hard-coded string.
func (c *P1Cost) Name() string { return P1CostModelName }

// ConformalQuantile returns the post-clamp slack the CHi path applies for a
// rotate (Quantile() clamped at 0, exactly as Evaluation uses it). ok is false
// when no conformal bound exists.
func (c *P1Cost) ConformalQuantile() (q float64, ok bool) {
	if c == nil || c.Conformal == nil {
		return 0, false
	}
	q = c.Conformal.Quantile()
	if q < 0 {
		q = 0
	}
	return q, true
}

// ConformalCalibrated reports whether the bound holds enough residuals for a
// measured (non-cold-start) quantile. ok is false when no bound exists.
func (c *P1Cost) ConformalCalibrated() (calibrated, ok bool) {
	if c == nil || c.Conformal == nil {
		return false, false
	}
	return c.Conformal.Calibrated(), true
}

// CHi is the conformal robust UPPER bound used by the hard SLO/feasibility gate. For a
// rotate it adds generic conformal slack on top of E[C]. For GPU rotates, the larger
// of that slack and the configured GPU envelope minimum applies; CPU rotates use only
// the generic slack. Generic RLS or conformal observations do not establish GPU-specific
// support and cannot withdraw the configured minimum. Deployments without an explicit
// value retain the conservative default rather than fabricating a measurement.
func (c *P1Cost) CHi(view *model.WorkloadView, move model.Move, pol model.Policy) float64 {
	return c.Evaluation(view, move, pol).CHi
}

// nanFeature returns the precise action-relevant NaN input. It intentionally does
// not reject an unrelated telemetry field for an action that never reads it.
func (c *P1Cost) nanFeature(view *model.WorkloadView, move model.Move, pol model.Policy) string {
	if math.IsNaN(pol.NormSparsity) || math.IsInf(pol.NormSparsity, 0) || pol.NormSparsity < 0 {
		return "policy.normSparsity"
	}
	if math.IsNaN(pol.FlowDisruption) || math.IsInf(pol.FlowDisruption, 0) || pol.FlowDisruption < 0 {
		return "policy.flowDisruption"
	}
	if math.IsNaN(pol.CostCeiling) || math.IsInf(pol.CostCeiling, 0) || pol.CostCeiling < 0 {
		return "policy.costCeiling"
	}
	if c.RLS != nil && c.RLS.hasNaNParameter() && flowFamilyForAction(move.Action) == flowRespawn {
		return "rls.parameter"
	}
	if view == nil {
		return ""
	}
	// A non-finite telemetry sample is typed State==Error at ingest (M-111 ingest-side);
	// an absent signal is not unactionable, it just takes its fallback.
	switch flowFamilyForAction(move.Action) {
	case flowRespawn:
		if view.Telemetry.ReqRate.State == model.Error {
			return "telemetry.reqRate"
		}
	case flowQuarantine:
		if view.Telemetry.ConnCount.State == model.Error {
			return "telemetry.connCount"
		}
	case flowCutover, flowServingState:
		if view.Telemetry.ReqRate.State == model.Error {
			return "telemetry.reqRate"
		}
		if view.Telemetry.ConnCount.State == model.Error {
			return "telemetry.connCount"
		}
	}
	return ""
}

// ObserveRotation folds a measured rotation disruption into the calibrators (offline
// cadence). measuredFlow is the normalized time-to-Ready of the replacement. The live
// runner calls this only after an emitted rotation is matched to a new Ready pod UID;
// a recovery still missing at the model maximum is recorded as right-censored C_flow=2.
// Dry-run and emitted-but-unexecuted rotations remain honest no-ops.
func (c *P1Cost) ObserveRotation(view *model.WorkloadView, measuredFlow float64) {
	f := Features(view)
	pred := c.RLS.Predict(f)
	c.Conformal.Observe(measuredFlow - pred)
	c.RLS.Update(f, measuredFlow)
}

// ReadyDelayReference is the existing declared upper end of the 60-400 second
// GPU/LLM warm-load range used by the flow-cost prior. A 400-second recovery maps
// to C_flow=1; slower recoveries remain distinguishable up to the RLS model's
// documented maximum of 2.
const ReadyDelayReference = 400 * time.Second

// NormalizeReadyDelay maps a measured replacement Ready delay into the same [0,2]
// domain as RLS.Predict. It contains no workload guess: the input is the Kubernetes
// PodReady transition observed after the emitted rotation.
func NormalizeReadyDelay(delay time.Duration) float64 {
	if delay <= 0 {
		return 0
	}
	x := float64(delay) / float64(ReadyDelayReference)
	if x > 2 {
		return 2
	}
	return x
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// --- modularity: register a CostModel wrapper so "add a cost model = one file" holds.
// The wrapper is stateless (a fresh P1Cost per call returns the PRIOR estimate); the
// stateful calibrating instance is owned by the engine. This entry just proves the P1
// cost is a registered, swappable CostModel.
// P1CostModelName is the single source of the cost-model identity string,
// reported by both the registry stub and the decision trace.
const P1CostModelName = "rls-dual-conformal"

type p1CostModel struct{}

func (p1CostModel) Name() string { return P1CostModelName }
func (p1CostModel) Switching(view *model.WorkloadView, move model.Move, pol model.Policy) float64 {
	return NewP1Cost().ECost(view, move, pol)
}

func init() { Registry.Register(p1CostModel{}) }
