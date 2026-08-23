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
// shapes so rotation latency is never applied across incompatible units. Lambda is
// the dual-descent shadow-price, and CHi is the
// conformal robust upper bound used by the HARD SLO gate. It is a
// stateful object (the RLS, conformal window and dual persist across ticks) owned by
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
// category needed by candidate generation and audit. NaNFeature is the precise
// input that made the action unactionable.
type P1Evaluation struct {
	P1Components
	CHi                  float64 `json:"chi"`
	UnactionableCategory string  `json:"unactionable_category,omitempty"`
	NaNFeature           string  `json:"nan_feature,omitempty"`
}

// NewP1Cost constructs the P1 cost model seeded at the P0-equivalent prior.
func NewP1Cost() *P1Cost {
	return NewP1CostWithLambda(DefaultLambdaSeed)
}

// NewP1CostWithLambda constructs an isolated tenant cost bucket whose adaptive
// dual price starts from the tenant policy's lambda value.
func NewP1CostWithLambda(lambdaSeed float64) *P1Cost {
	return &P1Cost{RLS: NewRLS(), Conformal: NewConformalBound(), Dual: NewDualSolverWithSeed(lambdaSeed)}
}

// Structural components make the quarantine denominator reproducible. The first
// two are the live exposure clocks; network isolation is the third component that
// the historical 1/(live+1) anchor was counting but had never named.
const structuralNetworkIsolation = "network-isolation"

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
		return 1.0
	case model.ActionQuarantine:
		return 1.0 / float64(len(structuralComponents))
	case model.ActionMIGRebind:
		return 1.25
	case model.ActionModelShardReplace:
		parallelSize := 1
		if view != nil && view.Pod.ParallelSize > parallelSize {
			parallelSize = view.Pod.ParallelSize
		}
		return float64(parallelSize)
	case model.ActionEndpointRotate:
		if view != nil && view.Pod.RouteServiceReady {
			return 0.35
		}
		return 0.10
	case model.ActionAdapterRotate:
		return 0.25
	case model.ActionKVReset, model.ActionKVMigrateInvalidate, model.ActionGuardrailRotate:
		return 0.20
	case model.ActionIdentityRotate:
		return 0.15
	case model.ActionRouteRotate, model.ActionDebugger, model.ActionCustomInject, model.ActionRequestDrain:
		return 0.10
	default:
		return 0
	}
}

func (c *P1Cost) components(view *model.WorkloadView, move model.Move, pol model.Policy) P1Components {
	if move.Action == model.ActionNoop {
		return P1Components{}
	}
	cNorm := normCostP1(view, move)
	cFlow := c.actionFlow(view, move.Action)
	return P1Components{
		Norm:  cNorm,
		Flow:  cFlow,
		Total: pol.NormSparsity*cNorm + pol.FlowDisruption*cFlow,
	}
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
	components := c.components(view, move, pol)
	chi := components.Total
	if move.Action == model.ActionRotate {
		slack := c.Conformal.Quantile()
		if slack < 0 {
			slack = 0
		}
		if view != nil && view.Pod.HasGPU && !c.RLS.Primed() {
			slack = maxf(slack, pol.FlowDisruption*GPUEnvelopeMax())
		}
		chi += slack
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
	return P1Evaluation{P1Components: components, CHi: chi}
}

// Components returns the exact current-model terms and weighted total for a move.
func (c *P1Cost) Components(view *model.WorkloadView, move model.Move, pol model.Policy) P1Components {
	return c.Evaluation(view, move, pol).P1Components
}

// ECost is the expected (objective) cost of a move: the calibrated point estimate.
func (c *P1Cost) ECost(view *model.WorkloadView, move model.Move, pol model.Policy) float64 {
	return c.Evaluation(view, move, pol).Total
}

// CHi is the conformal robust UPPER bound used by the hard SLO/feasibility gate. For a
// rotate it adds the conformal slack on top of E[C]; for an unprimed GPU pod the
// configured hardware-measured reload/warm-up envelope dominates. Deployments without
// a calibration retain the conservative default rather than fabricating a measurement.
func (c *P1Cost) CHi(view *model.WorkloadView, move model.Move, pol model.Policy) float64 {
	return c.Evaluation(view, move, pol).CHi
}

// nanFeature returns the precise action-relevant NaN input. It intentionally does
// not reject an unrelated telemetry field for an action that never reads it.
func (c *P1Cost) nanFeature(view *model.WorkloadView, move model.Move, pol model.Policy) string {
	if math.IsNaN(pol.NormSparsity) {
		return "policy.normSparsity"
	}
	if math.IsNaN(pol.FlowDisruption) {
		return "policy.flowDisruption"
	}
	if math.IsNaN(pol.CostCeiling) {
		return "policy.costCeiling"
	}
	if c.RLS != nil && c.RLS.hasNaNParameter() && flowFamilyForAction(move.Action) == flowRespawn {
		return "rls.parameter"
	}
	if view == nil || !view.Telemetry.Present {
		return ""
	}
	switch flowFamilyForAction(move.Action) {
	case flowRespawn:
		if math.IsNaN(view.Telemetry.ReqRate) {
			return "telemetry.reqRate"
		}
	case flowQuarantine:
		if math.IsNaN(view.Telemetry.ConnCount) {
			return "telemetry.connCount"
		}
	case flowCutover, flowServingState:
		if math.IsNaN(view.Telemetry.ReqRate) {
			return "telemetry.reqRate"
		}
		if math.IsNaN(view.Telemetry.ConnCount) {
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
type p1CostModel struct{}

func (p1CostModel) Name() string { return "rls-dual-conformal" }
func (p1CostModel) Switching(view *model.WorkloadView, move model.Move, pol model.Policy) float64 {
	return NewP1Cost().ECost(view, move, pol)
}

func init() { Registry.Register(p1CostModel{}) }
