/*
 * Phorvex — versioned, deterministic decision-reconstruction trace (PX-T0-001).
 */

package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

const (
	// DecisionTraceSchemaV2 is independent of the enclosing audit-record version.
	DecisionTraceSchemaV2 = "phorvex.decision-trace.v2"
	// DecisionTraceSchemaV3 adds the complete decision path (T0-C): the per-action
	// status array, CHi reconstruction terms, round semantics, and the dispatch
	// outcome. V2 records remain readable: Validate branches on the version.
	DecisionTraceSchemaV3 = "phorvex.decision-trace.v3"
	// TraceNotAvailable is the explicit, honest value for a string input the running
	// build cannot expose. Numeric inputs use OptionalFloat/OptionalInt instead.
	TraceNotAvailable = "notAvailable"
	// CostRepresentationWeightedDimensionlessV1 names the current weighted
	// objective score. It is not a dollar representation.
	CostRepresentationWeightedDimensionlessV1 = "weighted_dimensionless_v1"
	// CFlowUnitDimensionlessDisruptionLoss is the formal current CFlow unit.
	CFlowUnitDimensionlessDisruptionLoss = "confirmed_dimensionless_disruption_loss"
	// SelectorStrictPositiveGain is the exact P1 production comparator.
	SelectorStrictPositiveGain = "strict_gain_positive"
	SelectorM99Containment     = "m99_bounded_full_containment"
)

// T0-C: the closed per-action status vocabulary (the ticket's ten values). Exactly one
// row per model.MutatingActions member is recorded, in canonical order.
const (
	ActionStatusNotEnabled      = "not-enabled"
	ActionStatusNoCover         = "no-cover"
	ActionStatusInfeasible      = "infeasible"
	ActionStatusConformalSLO    = "conformal-slo"
	ActionStatusPricedOut       = "priced-out"
	ActionStatusBudgetExhausted = "budget-exhausted"
	ActionStatusCandidate       = "candidate"
	ActionStatusSelected        = "selected"
	ActionStatusNotEvaluated    = "not-evaluated-by-current-model"
	ActionStatusNotInstallable  = "not-installable" // T1-E: the action is absent from the installed CRD action enum
	ActionStatusIneligible      = "ineligible"      // T1-E: excluded by the capability gate (no-rbac / capability-unsupported)
)

// T0-C: the closed exclusion-kind vocabulary (B.3) — the structural cause, kept
// distinct from the ticket's status so a data-quality failure never reads as
// ordinary infeasibility (p1cost.go's deliberate distinction).
const (
	ExclusionNone         = "none"
	ExclusionNotEnabled   = "not-enabled"
	ExclusionReconCover   = "recon-cover"
	ExclusionFeasibility  = "feasibility"
	ExclusionCostNaN      = "cost-nan"
	ExclusionSLOGate      = "slo-gate"
	ExclusionReactiveOnly = "reactive-only"
	ExclusionSelection    = "selection"
	// T1-E capability-gate kinds (evaluated before scoring). no-cover reuses
	// ExclusionReconCover; these three are the genuinely new causes.
	ExclusionNotInstallable = "not-installable"
	ExclusionNoRBAC         = "no-rbac"
	ExclusionCapability     = "capability-unsupported"
	ExclusionActionFailure  = "action-failure-cooldown"
	ExclusionOperatorOptOut = "operator-opt-out"
)

// T0-C: the closed dispatch-outcome vocabulary. The runner stamps it after the
// actuation attempt, before the audit record is written.
const (
	DispatchNotAttempted = "not-attempted"
	DispatchEmitted      = "emitted"
	DispatchEmittedFalse = "emitted-false"
	DispatchError        = "dispatch-error"
)

// DecisionActionStatusV3 is one canonical action's outcome for this asset (T0-C R-2):
// every MutatingActions member gets exactly one row, so "the action was never
// considered" is recorded, not absent. Reason carries the existing pipeline string
// verbatim (redacted); Scored reports whether the greedy loop evaluated a marginal.
type DecisionActionStatusV3 struct {
	Action        string `json:"action"`
	Status        string `json:"status"`
	ExclusionKind string `json:"exclusionKind"`
	Reason        string `json:"reason,omitempty"`
	Scored        bool   `json:"scored"`
	// RBACUnknown (T1-E): the capability gate's SSAR errored for this candidate, so its
	// RBAC could not be confirmed this tick. The action is NOT excluded (fail-open,
	// P-NO-FREEZE) — this flags that the eligibility is provisional. Never set on an
	// excluded row.
	RBACUnknown bool `json:"rbacUnknown,omitempty"`
}

// DecisionClocksV3 are T1-B's separated belief clocks (all seconds). Equal on a
// non-transitioning pod with all horizons = ProactiveFloor (byte-identical era).
type DecisionClocksV3 struct {
	PodAgeSec                float64       `json:"podAgeSeconds"`
	SinceIdentityChangeSec   float64       `json:"sinceIdentityChangeSeconds"`
	InStageSec               float64       `json:"inStageSeconds"`
	SinceEvidence            OptionalFloat `json:"sinceEvidenceSeconds"`
	EventAgeHorizonSec       float64       `json:"eventAgeHorizonSeconds"`
	ExposurePressureScaleSec float64       `json:"exposurePressureScaleSeconds"`
}

// DecisionFlowV3 records the M-115 Little's-law residual and its basis, plus every physics
// residual component's presence, so a flow-derived anomaly traces to its inputs.
type DecisionFlowV3 struct {
	Present    bool          `json:"present"`
	Basis      string        `json:"basis"`            // littles-law | absent
	Reason     string        `json:"reason,omitempty"` // absence/invalid reason
	InFlight   OptionalFloat `json:"inFlight"`         // L, requests (time-average)
	ReqRate    OptionalFloat `json:"reqRate"`          // lambda, requests/second (completion rate)
	W          OptionalFloat `json:"w"`                // mean sojourn, seconds
	WStatistic string        `json:"wStatistic"`       // mean-sojourn
	Units      string        `json:"units"`
	Window     string        `json:"window"`
	Expected   OptionalFloat `json:"expected"`  // lambda*W
	Residual   OptionalFloat `json:"residual"`  // signed, [-1,1]
	Magnitude  OptionalFloat `json:"magnitude"` // |residual|, [0,1]
	AgeSec     float64       `json:"ageSeconds"`
	// Components lists every physics residual component with presence and magnitude; the
	// aggregate is the mean magnitude over the present ones (absent ones are excluded).
	Components []DecisionFlowComponentV3 `json:"components"`
	Aggregate  OptionalFloat             `json:"aggregate"`
}

type DecisionFlowComponentV3 struct {
	Name      string        `json:"name"`
	Present   bool          `json:"present"`
	Magnitude OptionalFloat `json:"magnitude"`
	Reason    string        `json:"reason,omitempty"`
}

// DecisionSignalStateV3 is one telemetry signal's presence as the record sees it (M-113):
// state, the reason it is not a fresh measurement, and the source. A measured 0 is
// present with no reason; query-failed and no-series are two different absences.
type DecisionSignalStateV3 struct {
	Signal string `json:"signal"`
	State  string `json:"state"` // present | stale | error | absent
	Reason string `json:"reason,omitempty"`
	Src    string `json:"src,omitempty"`
}

// DecisionPCIeV3 records the PCIe utilisation inputs (M-114): the measured RX+TX byte-rate is
// divided by a DISCOVERED capacity; the record names the capacity, its source and the link.
type DecisionPCIeV3 struct {
	Present        bool          `json:"present"`
	Measured       OptionalFloat `json:"measuredBytesPerSec"`
	Capacity       OptionalFloat `json:"capacityBytesPerSec"`
	CapacitySource string        `json:"capacitySource"` // dcgm-link | class-config | absent
	Gen            int           `json:"gen,omitempty"`
	Width          int           `json:"width,omitempty"`
	Utilization    OptionalFloat `json:"utilization"`
	Reason         string        `json:"reason,omitempty"`
}

// OptionalFloat distinguishes an observed zero from an unavailable measurement.
type OptionalFloat struct {
	Present bool    `json:"present"`
	Value   float64 `json:"value"`
}

// OptionalInt distinguishes an observed zero from an unavailable integer.
type OptionalInt struct {
	Present bool `json:"present"`
	Value   int  `json:"value"`
}

// OptionalBool distinguishes false from a check the current model did not run.
type OptionalBool struct {
	Present bool `json:"present"`
	Value   bool `json:"value"`
}

// DecisionModelInputsV2 is the exact current per-asset input surface exposed to
// the decision path. Every potentially absent measurement carries presence.
type DecisionModelInputsV2 struct {
	Phase string `json:"phase"`
	// PhaseReason distinguishes idle-measured|warm-no-app-signal|warm-uncertain-app-signal|
	// busy-measured|coldstart|draining|unknown, so absence and uncertain app evidence are
	// auditable rather than mislabeled as measured serving.
	PhaseReason string `json:"phaseReason,omitempty"`

	RequestRate     OptionalFloat `json:"requestRate"`
	ConnectionCount OptionalFloat `json:"connectionCount"`
	GPUUtilization  OptionalFloat `json:"gpuUtilization"`
	SMOccupancy     OptionalFloat `json:"smOccupancy"`
	VRAMFraction    OptionalFloat `json:"vramFraction"`
	// Leakage is the model-theft gate's ACTIVITY input as actually tested (T1-A): SMOccupancy
	// only, never allocation. Present iff SMOccupancy was measured (SMSource != ""), so an
	// honest-absent scrape is recorded as absent rather than as an idle GPU.
	Leakage           OptionalFloat `json:"leakage"`
	ImageRarity       OptionalFloat `json:"imageRarity"`
	ModelRarity       OptionalFloat `json:"modelRarity"`
	CoResidency       OptionalFloat `json:"coResidency"`
	CoResidencyBasis  string        `json:"coResidencyBasis,omitempty"`
	EPSS              OptionalFloat `json:"epss"`                        // RAW exploit probability [0,1] (M-104; was the multiplier before)
	CVSS              OptionalFloat `json:"cvss"`                        // raw base severity [0,10]
	EPSSMultiplier    OptionalFloat `json:"epssMultiplier"`              // 1 + epss·(cvss/10) ∈ [1,2]; present only for a usable pair
	EPSSReason        string        `json:"epssReason,omitempty"`        // absent | non-finite | invalid-domain
	EPSSBasis         string        `json:"epssBasis,omitempty"`         // exact | repo-fallback | miss (M-141)
	EPSSCachedDigest  string        `json:"epssCachedDigest,omitempty"`  // cache key that supplied the value
	EPSSRunningDigest string        `json:"epssRunningDigest,omitempty"` // the pod's running ImageID
	EPSSScanTS        string        `json:"epssScanTS,omitempty"`        // feed-run time the pair (CVE scan + EPSS score) was produced = EPSS as-of; a matched digest with an old scanTS is a stale pair
	PhysicsScanned    bool          `json:"physicsScanned"`
	DispersionMult    OptionalFloat `json:"dispersionMult"`
	// FactsAbsentReason is set when a non-finite belief/physics input meant no fact was
	// minted for this asset (M-111): the weights are absent, not zero and not NaN.
	FactsAbsentReason string `json:"factsAbsentReason,omitempty"`
	// Flow is the M-115 Little's-law residual basis record.
	Flow DecisionFlowV3 `json:"flow"`
	// TelemetryStates lists every telemetry signal's state/reason/src (M-113 record fields).
	TelemetryStates   []DecisionSignalStateV3 `json:"telemetryStates,omitempty"`
	DispersionCap     OptionalFloat           `json:"dispersionCap"`
	Primed            bool                    `json:"primed"`
	BetaMean          OptionalFloat           `json:"betaMean"`
	PHold             OptionalFloat           `json:"pHold"`
	Stage             string                  `json:"stage"`
	StageHazard       OptionalFloat           `json:"stageHazard"`
	StageUrgency      OptionalFloat           `json:"stageUrgency"`
	ThreatPosture     OptionalFloat           `json:"threatPosture"`
	ExposureVariable  string                  `json:"exposureVariable"`
	ExposureSeconds   OptionalFloat           `json:"exposureSeconds"`
	ProactiveFloorSec float64                 `json:"proactiveFloorSeconds"`
	// PCIe (M-114): the LinkBandwidth denominator and where it came from.
	PCIe DecisionPCIeV3 `json:"pcie"`
	// CostCalibratorTenant names the tenant whose calibrator bucket priced every cost in this
	// record, BlindCost included (M-110 site 1); BlindCostSource says whether the blind cost
	// came from that calibrator ("tenant-calibrator") or the stateful maximum ("stateful-max").
	CostCalibratorTenant string  `json:"costCalibratorTenant,omitempty"`
	BlindCostSource      string  `json:"blindCostSource,omitempty"`
	AntiOverRotateSec    float64 `json:"antiOverRotationWindowSeconds"`
	// Clocks (T1-B): the separated CLOCK->BELIEF time inputs, so a reader can see which clock
	// fed the dwell Weibull vs the pHold pressure. Additive under v3; no schema bump.
	Clocks DecisionClocksV3 `json:"clocks"`
	// T0-C: the three horizon/headroom inputs the envelope already carried (log.go)
	// lifted into the trace with presence. ProjectedNextStageSec is present iff a
	// next stage was projected (NextStage != "").
	SLOHeadroom           OptionalFloat `json:"sloHeadroom"`
	NextStage             string        `json:"nextStage"`
	ProjectedNextStageSec OptionalFloat `json:"projectedNextStageSec"`
}

// DecisionFactV2 is one fact presented to the current optimizer. Decomposition
// terms remain explicitly unavailable when the recon implementation exposes only
// the final weight; the trace never reverse-engineers or fabricates them.
type DecisionFactV2 struct {
	FactKey                string        `json:"factKey"`
	FactType               string        `json:"factType"`
	FinalWeight            float64       `json:"finalWeight"`
	CoveredBeforeDecision  bool          `json:"coveredBeforeDecision"`
	SourceComponent        string        `json:"sourceComponent"`
	AssetValue             OptionalFloat `json:"assetValue"`
	PHoldContribution      OptionalFloat `json:"pHoldContribution"`
	UrgencyContribution    OptionalFloat `json:"urgencyContribution"`
	DispersionContribution OptionalFloat `json:"dispersionContribution"`
	RelativeWeight         OptionalFloat `json:"relativeWeight"`
	// T0-C: CoveringActions lists every canonical action whose declared cover
	// includes this fact (all actions, not only policy-enabled ones — a fact's
	// cover set is a property of the fact). CoveredRound is the 1-based greedy
	// round in which a selected move first covered this fact (absent = never
	// covered this tick); CoveredBeforeDecision is DERIVED from it
	// (coveredRound < evaluationRound), recorded computed, not asserted.
	// DecompositionAvailable names the honest absence of the four decomposition
	// terms above instead of leaving their absence unexplained.
	CoveringActions        []string                   `json:"coveringActions"`
	DecompositionAvailable bool                       `json:"decompositionAvailable"`
	CoveredRound           OptionalInt                `json:"coveredRound"`
	SteeredBy              *VectorSteeringAttribution `json:"steeredBy,omitempty"`
}

// DecisionCandidateV2 records either a generated feasible candidate or an
// action excluded by an existing current-model gate. Optional values say exactly
// which calculations were reached before an exclusion.
type DecisionCandidateV2 struct {
	Existential  *ExistentialCandidate `json:"existential,omitempty"`
	Action       string                `json:"action"`
	CandidateKey string                `json:"candidateKey"`
	CoverKeys    []string              `json:"coverKeys"`
	TieBreakRank int                   `json:"tieBreakRank"`

	GrossFullValue     OptionalFloat `json:"grossFullValue"`
	MarginalCoverage   OptionalFloat `json:"marginalCoverage"`
	Provenance         OptionalFloat `json:"provenance"`
	CNorm              OptionalFloat `json:"cNorm"`
	CFlow              OptionalFloat `json:"cFlow"`
	ExpectedCost       OptionalFloat `json:"expectedCost"`
	CostHigh           OptionalFloat `json:"costHigh"`
	LambdaContribution OptionalFloat `json:"lambdaContribution"`
	NetGain            OptionalFloat `json:"netGain"`
	Feasible           OptionalBool  `json:"feasible"`
	Selected           bool          `json:"selected"`

	// T0-C CHi reconstruction terms (B.1). Present exactly where the cost path
	// computed them: rotate rows carry ConformalQuantile (the post-clamp slack
	// used in the max) and ConformalCalibrated (measured vs cold-start);
	// GPUEnvelopeApplied is present wherever cost ran (false for non-rotate);
	// GPUEnvelopeSlack is present iff the envelope branch fired. NaN-category
	// rows carry none of the four (the fail-closed return never computes slack).
	// Law: CostHigh = ExpectedCost + (action==rotate ? max(quantile, applied?slack:0) : 0).
	ConformalQuantile   OptionalFloat `json:"conformalQuantile"`
	ConformalCalibrated OptionalBool  `json:"conformalCalibrated"`
	GPUEnvelopeApplied  OptionalBool  `json:"gpuEnvelopeApplied"`
	GPUEnvelopeSlack    OptionalFloat `json:"gpuEnvelopeSlack"`
	// SLOGateResult is present/true for generated candidates (they passed the
	// conformal SLO gate), present/false for conformal-slo exclusions, absent
	// for rows excluded upstream of the gate. SelectionRound is per-candidate,
	// present iff this candidate was selected.
	SLOGateResult  OptionalBool `json:"sloGateResult"`
	SelectionRound OptionalInt  `json:"selectionRound"`

	ExistingExclusionReason     string `json:"existingExclusionReason,omitempty"`
	SelectionReason             string `json:"selectionReason"`
	NotClassifiedByCurrentModel bool   `json:"notClassifiedByCurrentModel"`
	// RBACUnknown (T1-E): the capability gate's SSAR errored for this candidate, so its
	// RBAC could not be confirmed this tick; it was NOT excluded (fail-open). Carried
	// through to the per-action status row.
	RBACUnknown bool `json:"rbacUnknown,omitempty"`
}

// DecisionDualUpdateV2 records one legacy runtime-controller transition.
// Demand, spent and budget are unit move/asset-slot counts.
type DecisionDualUpdateV2 struct {
	Applied         bool    `json:"applied"`
	Demand          int     `json:"demand"`
	Spent           int     `json:"spent"`
	Budget          int     `json:"budget"`
	RawExcess       int     `json:"rawExcess"`
	EffectiveExcess int     `json:"effectiveExcess"`
	LambdaBefore    float64 `json:"lambdaBefore"`
	LambdaAfter     float64 `json:"lambdaAfter"`
	UpdateReason    string  `json:"updateReason"`
}

// DecisionTraceV2 is the nested structured audit contract for one asset outcome.
// Candidate/fact arrays are canonicalized during JSON serialization.
type DecisionTraceV2 struct {
	Existential    *ExistentialDecision `json:"existential,omitempty"`
	SchemaVersion  string               `json:"schemaVersion"`
	DecisionID     string               `json:"decisionID"`
	TickID         string               `json:"tickID"`
	Timestamp      string               `json:"timestamp"`
	BrainImage     string               `json:"brainImage"`
	GitSHA         string               `json:"gitSHA"`
	DecisionEngine string               `json:"decisionEngine"`
	// PolicyActionVocabulary records the one CRD observation used by this tick's
	// installability witness. Unknown reads preserve historical identity only.
	PolicyActionVocabulary *PolicyActionVocabularyObservation `json:"policyActionVocabulary,omitempty"`

	PolicyNamespace string `json:"policyNamespace"`
	PolicyName      string `json:"policyName"`
	PolicyUID       string `json:"policyUID"`
	TenantName      string `json:"tenantName"`
	AssetNamespace  string `json:"assetNamespace"`
	AssetName       string `json:"assetName"`
	AssetUID        string `json:"assetUID"`

	Budget               int     `json:"budget"`
	CandidateDemand      int     `json:"candidateDemand"`
	MovesSpent           int     `json:"movesSpent"`
	DryRun               bool    `json:"dryRun"`
	DryRunCause          string  `json:"dryRunCause,omitempty"`
	ActuationBrakeCause  string  `json:"actuationBrakeCause,omitempty"`
	KillSwitchEngaged    bool    `json:"killSwitchEngaged"`
	KillSwitchCause      string  `json:"killSwitchCause,omitempty"`
	LambdaConfiguredSeed float64 `json:"lambdaConfiguredSeed"`
	LambdaRuntime        float64 `json:"lambdaRuntime"`
	// The two fields above remain as wire-compatible aliases for existing readers.
	// [M-140] Ownership metadata, captured when the economic unit was CREATED and stable
	// for its life. LambdaConfiguredSeed above re-reads the current policy spec every tick,
	// so it moves on a PATCH that reseeds nothing; LambdaSeedConsumed is the value actually
	// handed to the dual solver, and BucketCreatedAt/CreationEvent show a recreate really
	// did construct a new unit. Emitted even on ticks with no selected decisions.
	OwnerKey                  string               `json:"ownerKey"`
	OwnerKeyKind              string               `json:"ownerKeyKind"`
	LambdaSeedConsumed        float64              `json:"lambdaSeedConsumed"`
	BucketCreatedAt           string               `json:"bucketCreatedAt"`
	BucketCreationEvent       uint64               `json:"bucketCreationEvent"`
	LambdaConfiguredPolicy    float64              `json:"lambdaConfiguredPolicy"`
	LambdaRuntimeLegacy       float64              `json:"lambdaRuntimeLegacy"`
	SelectorComparator        string               `json:"selectorComparator"`
	NormWeight                float64              `json:"normWeight"`
	FlowWeight                float64              `json:"flowWeight"`
	CFlowUnitStatus           string               `json:"cFlowUnitStatus"`
	CostRepresentationVersion string               `json:"costRepresentationVersion"`
	DualUpdate                DecisionDualUpdateV2 `json:"dualUpdate"`
	// T0-C: CostCeiling is the EFFECTIVE conformal SLO ceiling the generator
	// enforced (post-defaulting, not the raw policy field); CostModelVersion is
	// the cost model's own Name(); EvaluationRound is the 1-based greedy round
	// whose marginal this record carries (the selection round for the selected
	// asset, the last executed round otherwise).
	CostCeiling      float64 `json:"costCeiling"`
	CostModelVersion string  `json:"costModelVersion"`
	EvaluationRound  int     `json:"evaluationRound"`

	Inputs     DecisionModelInputsV2 `json:"inputs"`
	Facts      []DecisionFactV2      `json:"facts"`
	Candidates []DecisionCandidateV2 `json:"candidates"`

	// T0-C: ActionStatus carries exactly one row per model.MutatingActions member
	// in canonical order (R-2: the complete action accounting, including actions
	// the current model never considered). DispatchOutcome/DispatchReason are
	// stamped by the runner after the actuation attempt, before the audit write.
	ActionStatus    []DecisionActionStatusV3 `json:"actionStatus"`
	DispatchOutcome string                   `json:"dispatchOutcome"`
	DispatchReason  string                   `json:"dispatchReason,omitempty"`

	SelectedAction       string      `json:"selectedAction"`
	SelectedCandidateKey string      `json:"selectedCandidateKey,omitempty"`
	SelectionRound       OptionalInt `json:"selectionRound"`
	TieBreakReason       string      `json:"tieBreakReason"`
	NoopReason           string      `json:"noopReason,omitempty"`
}

// PolicyActionVocabularyObservation is additive capability evidence for a
// retained decision. Known=false never establishes that an action was installed.
type PolicyActionVocabularyObservation struct {
	Known           bool   `json:"known"`
	UID             string `json:"uid,omitempty"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
	ObservedAt      string `json:"observedAt,omitempty"`
	AttemptedAt     string `json:"attemptedAt,omitempty"`
	Error           string `json:"error,omitempty"`
}

var (
	authorizationPattern = regexp.MustCompile(`(?i)\bauthorization\s*[:=]\s*[^\r\n]+`)
	bearerPattern        = regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]+`)
	secretKVPattern      = regexp.MustCompile(`(?i)\b(x-api-key|api[_-]?key|password|passwd|token|credential)\s*[:=]\s*[^\s,;]+`)
	uriUserInfoPattern   = regexp.MustCompile(`://[^/@\s]+:[^/@\s]+@`)
)

func redactTraceString(s string) string {
	s = authorizationPattern.ReplaceAllString(s, "Authorization:[REDACTED]")
	s = bearerPattern.ReplaceAllString(s, "Bearer [REDACTED]")
	s = uriUserInfoPattern.ReplaceAllString(s, "://[REDACTED]@")
	return secretKVPattern.ReplaceAllStringFunc(s, func(match string) string {
		if i := strings.IndexAny(match, ":="); i >= 0 {
			return strings.TrimSpace(match[:i]) + string(match[i]) + "[REDACTED]"
		}
		return "[REDACTED]"
	})
}

func cleanOptional(v OptionalFloat) OptionalFloat {
	if !v.Present || math.IsNaN(v.Value) || math.IsInf(v.Value, 0) {
		return OptionalFloat{Present: false}
	}
	return v
}

// Canonical returns a redacted, deterministically ordered deep copy. It never
// mutates the trace attached to the decision or any optimizer input.
// The schema version is set at construction and is NOT rewritten here: a legacy
// v2 record read from disk re-marshals as v2 (rollback-honest), and a v3 record
// stays v3. (Pre-T0-C this line forced V2; forcing V3 would mislabel legacy
// records that lack the v3 arrays.)
func (t DecisionTraceV2) Canonical() DecisionTraceV2 {
	out := t
	out.DecisionID = redactTraceString(out.DecisionID)
	out.TickID = redactTraceString(out.TickID)
	out.Timestamp = redactTraceString(out.Timestamp)
	out.BrainImage = redactTraceString(out.BrainImage)
	out.GitSHA = redactTraceString(out.GitSHA)
	out.DecisionEngine = redactTraceString(out.DecisionEngine)
	out.PolicyNamespace = redactTraceString(out.PolicyNamespace)
	out.PolicyName = redactTraceString(out.PolicyName)
	out.PolicyUID = redactTraceString(out.PolicyUID)
	out.TenantName = redactTraceString(out.TenantName)
	out.AssetNamespace = redactTraceString(out.AssetNamespace)
	out.AssetName = redactTraceString(out.AssetName)
	out.AssetUID = redactTraceString(out.AssetUID)
	out.SelectedAction = redactTraceString(out.SelectedAction)
	out.SelectedCandidateKey = redactTraceString(out.SelectedCandidateKey)
	out.TieBreakReason = redactTraceString(out.TieBreakReason)
	out.NoopReason = redactTraceString(out.NoopReason)
	out.SelectorComparator = redactTraceString(out.SelectorComparator)
	out.CFlowUnitStatus = redactTraceString(out.CFlowUnitStatus)
	out.CostRepresentationVersion = redactTraceString(out.CostRepresentationVersion)
	out.DualUpdate.UpdateReason = redactTraceString(out.DualUpdate.UpdateReason)
	out.CostModelVersion = redactTraceString(out.CostModelVersion)
	out.DispatchOutcome = redactTraceString(out.DispatchOutcome)
	out.DispatchReason = redactTraceString(out.DispatchReason)

	out.Inputs.Phase = redactTraceString(out.Inputs.Phase)
	out.Inputs.Stage = redactTraceString(out.Inputs.Stage)
	out.Inputs.ExposureVariable = redactTraceString(out.Inputs.ExposureVariable)
	out.Inputs.RequestRate = cleanOptional(out.Inputs.RequestRate)
	out.Inputs.ConnectionCount = cleanOptional(out.Inputs.ConnectionCount)
	out.Inputs.GPUUtilization = cleanOptional(out.Inputs.GPUUtilization)
	out.Inputs.SMOccupancy = cleanOptional(out.Inputs.SMOccupancy)
	out.Inputs.VRAMFraction = cleanOptional(out.Inputs.VRAMFraction)
	out.Inputs.Leakage = cleanOptional(out.Inputs.Leakage)
	out.Inputs.ImageRarity = cleanOptional(out.Inputs.ImageRarity)
	out.Inputs.ModelRarity = cleanOptional(out.Inputs.ModelRarity)
	out.Inputs.CoResidency = cleanOptional(out.Inputs.CoResidency)
	out.Inputs.EPSS = cleanOptional(out.Inputs.EPSS)
	out.Inputs.CVSS = cleanOptional(out.Inputs.CVSS)
	out.Inputs.EPSSMultiplier = cleanOptional(out.Inputs.EPSSMultiplier)
	out.Inputs.DispersionMult = cleanOptional(out.Inputs.DispersionMult)
	out.Inputs.DispersionCap = cleanOptional(out.Inputs.DispersionCap)
	out.Inputs.BetaMean = cleanOptional(out.Inputs.BetaMean)
	out.Inputs.PHold = cleanOptional(out.Inputs.PHold)
	out.Inputs.StageHazard = cleanOptional(out.Inputs.StageHazard)
	out.Inputs.StageUrgency = cleanOptional(out.Inputs.StageUrgency)
	out.Inputs.ThreatPosture = cleanOptional(out.Inputs.ThreatPosture)
	out.Inputs.ExposureSeconds = cleanOptional(out.Inputs.ExposureSeconds)
	out.Inputs.Clocks.SinceEvidence = cleanOptional(out.Inputs.Clocks.SinceEvidence)
	out.Inputs.NextStage = redactTraceString(out.Inputs.NextStage)
	out.Inputs.SLOHeadroom = cleanOptional(out.Inputs.SLOHeadroom)
	out.Inputs.ProjectedNextStageSec = cleanOptional(out.Inputs.ProjectedNextStageSec)

	out.Facts = append([]DecisionFactV2(nil), t.Facts...)
	for i := range out.Facts {
		f := &out.Facts[i]
		f.FactKey = redactTraceString(f.FactKey)
		f.FactType = redactTraceString(f.FactType)
		f.SourceComponent = redactTraceString(f.SourceComponent)
		f.AssetValue = cleanOptional(f.AssetValue)
		f.PHoldContribution = cleanOptional(f.PHoldContribution)
		f.UrgencyContribution = cleanOptional(f.UrgencyContribution)
		f.DispersionContribution = cleanOptional(f.DispersionContribution)
		f.RelativeWeight = cleanOptional(f.RelativeWeight)
		if f.SteeredBy != nil {
			steering := *f.SteeredBy
			steering.RuleType = redactTraceString(steering.RuleType)
			steering.Events = append([]VectorSteeringEvent(nil), steering.Events...)
			for j := range steering.Events {
				e := &steering.Events[j]
				e.EventName = redactTraceString(e.EventName)
				e.EventUID = redactTraceString(e.EventUID)
				e.RuleType = redactTraceString(e.RuleType)
				e.DeclaredSource = redactTraceString(e.DeclaredSource)
				e.TrustVerdict = redactTraceString(e.TrustVerdict)
				e.CreatorIdentity = redactTraceString(e.CreatorIdentity)
			}
			sort.Slice(steering.Events, func(i, j int) bool {
				a, b := steering.Events[i], steering.Events[j]
				return vectorSteeringEventKey(a) < vectorSteeringEventKey(b)
			})
			unique := steering.Events[:0]
			for _, event := range steering.Events {
				if len(unique) == 0 || vectorSteeringEventKey(unique[len(unique)-1]) != vectorSteeringEventKey(event) {
					unique = append(unique, event)
				}
			}
			steering.Events = unique
			f.SteeredBy = &steering
		}
		f.CoveringActions = append([]string(nil), f.CoveringActions...)
		for j := range f.CoveringActions {
			f.CoveringActions[j] = redactTraceString(f.CoveringActions[j])
		}
		sort.SliceStable(f.CoveringActions, func(a, b int) bool {
			return canonicalActionRank(f.CoveringActions[a]) < canonicalActionRank(f.CoveringActions[b])
		})
	}
	sort.SliceStable(out.Facts, func(i, j int) bool { return out.Facts[i].FactKey < out.Facts[j].FactKey })

	out.Candidates = append([]DecisionCandidateV2(nil), t.Candidates...)
	for i := range out.Candidates {
		c := &out.Candidates[i]
		c.Action = redactTraceString(c.Action)
		c.CandidateKey = redactTraceString(c.CandidateKey)
		c.ExistingExclusionReason = redactTraceString(c.ExistingExclusionReason)
		c.SelectionReason = redactTraceString(c.SelectionReason)
		c.CoverKeys = append([]string(nil), c.CoverKeys...)
		for j := range c.CoverKeys {
			c.CoverKeys[j] = redactTraceString(c.CoverKeys[j])
		}
		sort.Strings(c.CoverKeys)
		c.GrossFullValue = cleanOptional(c.GrossFullValue)
		c.MarginalCoverage = cleanOptional(c.MarginalCoverage)
		c.Provenance = cleanOptional(c.Provenance)
		c.CNorm = cleanOptional(c.CNorm)
		c.CFlow = cleanOptional(c.CFlow)
		c.ExpectedCost = cleanOptional(c.ExpectedCost)
		c.CostHigh = cleanOptional(c.CostHigh)
		c.LambdaContribution = cleanOptional(c.LambdaContribution)
		c.NetGain = cleanOptional(c.NetGain)
		c.ConformalQuantile = cleanOptional(c.ConformalQuantile)
		c.GPUEnvelopeSlack = cleanOptional(c.GPUEnvelopeSlack)
	}

	out.ActionStatus = append([]DecisionActionStatusV3(nil), t.ActionStatus...)
	for i := range out.ActionStatus {
		row := &out.ActionStatus[i]
		row.Action = redactTraceString(row.Action)
		row.Status = redactTraceString(row.Status)
		row.ExclusionKind = redactTraceString(row.ExclusionKind)
		row.Reason = redactTraceString(row.Reason)
	}
	sort.SliceStable(out.ActionStatus, func(i, j int) bool {
		return canonicalActionRank(out.ActionStatus[i].Action) < canonicalActionRank(out.ActionStatus[j].Action)
	})
	sort.SliceStable(out.Candidates, func(i, j int) bool {
		assetKey := func(candidateKey string) string {
			if at := strings.LastIndex(candidateKey, "|"); at >= 0 {
				return candidateKey[:at]
			}
			return candidateKey
		}
		leftAsset, rightAsset := assetKey(out.Candidates[i].CandidateKey), assetKey(out.Candidates[j].CandidateKey)
		if leftAsset != rightAsset {
			return leftAsset < rightAsset
		}
		leftRank, rightRank := canonicalActionRank(out.Candidates[i].Action), canonicalActionRank(out.Candidates[j].Action)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return out.Candidates[i].CandidateKey < out.Candidates[j].CandidateKey
	})
	return out
}

func vectorSteeringEventKey(e VectorSteeringEvent) string {
	return e.EventName + "\x00" + e.EventUID + "\x00" + e.RuleType + "\x00" + e.DeclaredSource + "\x00" + e.TrustVerdict + "\x00" + e.CreatorIdentity
}

func canonicalActionRank(action string) int {
	for i, a := range MutatingActions {
		if string(a) == action {
			return i
		}
	}
	return len(MutatingActions)
}

// MarshalJSON makes every wire record canonical and redacted by construction.
func (t DecisionTraceV2) MarshalJSON() ([]byte, error) {
	type alias DecisionTraceV2
	canonical := t.Canonical()
	return json.Marshal(alias(canonical))
}

// Validate checks the version/build identity and selection-reference invariants.
// It accepts both V2 (legacy/rollback records, pre-T0-C checks only) and V3
// (full reconstructability invariants). NOTE (T0-C, B.6.7): Validate has no
// non-test caller — it is a test-time contract, not a runtime guard; the
// production reconstruction check lives in the independent validator.
func (t DecisionTraceV2) Validate() error {
	if t.SchemaVersion != DecisionTraceSchemaV2 && t.SchemaVersion != DecisionTraceSchemaV3 {
		return fmt.Errorf("schemaVersion %q", t.SchemaVersion)
	}
	isV3 := t.SchemaVersion == DecisionTraceSchemaV3
	finite := func(values ...float64) bool {
		for _, value := range values {
			if math.IsNaN(value) || math.IsInf(value, 0) {
				return false
			}
		}
		return true
	}
	if !finite(t.LambdaConfiguredSeed, t.LambdaRuntime, t.LambdaConfiguredPolicy,
		t.LambdaRuntimeLegacy, t.NormWeight, t.FlowWeight,
		t.DualUpdate.LambdaBefore, t.DualUpdate.LambdaAfter) {
		return errors.New("trace contains non-finite controller or cost values")
	}
	for _, candidate := range t.Candidates {
		values := []OptionalFloat{candidate.GrossFullValue, candidate.MarginalCoverage,
			candidate.Provenance, candidate.CNorm, candidate.CFlow, candidate.ExpectedCost,
			candidate.CostHigh, candidate.LambdaContribution, candidate.NetGain}
		for _, value := range values {
			if value.Present && !finite(value.Value) {
				return fmt.Errorf("candidate %q contains a non-finite value", candidate.CandidateKey)
			}
		}
	}
	for _, fact := range t.Facts {
		if fact.SteeredBy == nil {
			continue
		}
		if !finite(fact.SteeredBy.AppliedMultiplier) || fact.SteeredBy.AppliedMultiplier <= 0 ||
			fact.SteeredBy.RuleType == "" || len(fact.SteeredBy.Events) == 0 {
			return fmt.Errorf("fact %q contains invalid steering attribution", fact.FactKey)
		}
		for _, event := range fact.SteeredBy.Events {
			if event.RuleType != fact.SteeredBy.RuleType {
				return fmt.Errorf("fact %q steering event rule %q disagrees with %q", fact.FactKey, event.RuleType, fact.SteeredBy.RuleType)
			}
		}
	}
	t = t.Canonical()
	if t.BrainImage == "" || t.GitSHA == "" {
		return errors.New("brainImage and gitSHA are mandatory")
	}
	if t.DecisionID == "" || t.TickID == "" || t.PolicyUID == "" || t.AssetUID == "" {
		return errors.New("decision, tick, policy and asset identities are mandatory")
	}
	seen := map[string]bool{}
	factsSeen := map[string]bool{}
	for _, fact := range t.Facts {
		if fact.FactKey == "" || factsSeen[fact.FactKey] {
			return fmt.Errorf("fact key is empty or duplicated: %q", fact.FactKey)
		}
		factsSeen[fact.FactKey] = true
	}
	selected := 0
	selectedKey := ""
	for _, c := range t.Candidates {
		if c.CandidateKey == "" || seen[c.CandidateKey] {
			return fmt.Errorf("candidate key is empty or duplicated: %q", c.CandidateKey)
		}
		seen[c.CandidateKey] = true
		if c.Selected {
			selected++
			selectedKey = c.CandidateKey
		}
		if c.NetGain.Present && c.MarginalCoverage.Present && c.Provenance.Present &&
			c.LambdaContribution.Present {
			want := c.MarginalCoverage.Value*c.Provenance.Value - c.LambdaContribution.Value
			if math.Abs(want-c.NetGain.Value) > 1e-9 {
				return fmt.Errorf("candidate %q net gain is not reconstructable", c.CandidateKey)
			}
		}
		if t.CostRepresentationVersion != "" && c.CNorm.Present && c.CFlow.Present && c.ExpectedCost.Present {
			want := t.NormWeight*c.CNorm.Value + t.FlowWeight*c.CFlow.Value
			if math.Abs(want-c.ExpectedCost.Value) > 1e-9 {
				return fmt.Errorf("candidate %q expected cost is not reconstructable", c.CandidateKey)
			}
		}
	}
	// Empty representation identifies pre-T0-B V2 records and remains readable
	// during rollback. New records carry and validate the complete semantics.
	if t.CostRepresentationVersion != "" {
		if t.CostRepresentationVersion != CostRepresentationWeightedDimensionlessV1 ||
			t.CFlowUnitStatus != CFlowUnitDimensionlessDisruptionLoss ||
			(t.SelectorComparator != SelectorStrictPositiveGain && t.SelectorComparator != SelectorM99Containment) {
			return errors.New("unknown cost representation, CFlow unit, or selector comparator")
		}
		if t.LambdaConfiguredPolicy != t.LambdaConfiguredSeed || t.LambdaRuntimeLegacy != t.LambdaRuntime {
			return errors.New("legacy lambda aliases disagree with explicit semantics")
		}
		if t.DualUpdate.Demand != t.CandidateDemand || t.DualUpdate.Spent != t.MovesSpent ||
			t.DualUpdate.Budget != t.Budget || t.DualUpdate.RawExcess != t.CandidateDemand-t.Budget ||
			t.DualUpdate.LambdaBefore != t.LambdaRuntimeLegacy || t.DualUpdate.UpdateReason == "" {
			return errors.New("dual update is not reconstructable from trace inputs")
		}
	} else if isV3 {
		return errors.New("v3 trace must carry the cost representation semantics")
	}
	if isV3 {
		if err := t.validateV3(); err != nil {
			return err
		}
	}
	if t.SelectedAction == string(ActionNoop) {
		if selected != 0 || t.SelectedCandidateKey != "" || t.NoopReason == "" {
			return errors.New("noop trace has a selected candidate or no noop reason")
		}
		return nil
	}
	if selected != 1 || t.SelectedCandidateKey == "" || selectedKey != t.SelectedCandidateKey {
		return errors.New("selected trace must reference exactly one recorded candidate")
	}
	return nil
}

// validateV3 enforces the T0-C reconstructability invariants. It runs on the
// canonical copy from Validate, after the version-agnostic checks.
func (t DecisionTraceV2) validateV3() error {
	// (0) Trace-level v3 fields the reconstruction laws depend on are mandatory.
	if t.CostModelVersion == "" {
		return errors.New("v3 trace has no costModelVersion")
	}
	if math.IsNaN(t.CostCeiling) || math.IsInf(t.CostCeiling, 0) || t.CostCeiling <= 0 {
		return fmt.Errorf("v3 trace costCeiling %g is not a positive finite ceiling", t.CostCeiling)
	}
	// (1) The action accounting is complete: exactly one row per canonical
	// mutating action, in canonical order, from the closed vocabularies.
	if len(t.ActionStatus) != len(MutatingActions) {
		return fmt.Errorf("actionStatus carries %d rows, want exactly %d (one per MutatingActions member)",
			len(t.ActionStatus), len(MutatingActions))
	}
	statusOK := map[string]bool{
		ActionStatusNotEnabled: true, ActionStatusNoCover: true, ActionStatusInfeasible: true,
		ActionStatusConformalSLO: true, ActionStatusPricedOut: true, ActionStatusBudgetExhausted: true,
		ActionStatusCandidate: true, ActionStatusSelected: true, ActionStatusNotEvaluated: true,
		ActionStatusNotInstallable: true, ActionStatusIneligible: true,
	}
	kindOK := map[string]bool{
		ExclusionNone: true, ExclusionNotEnabled: true, ExclusionReconCover: true,
		ExclusionFeasibility: true, ExclusionCostNaN: true, ExclusionSLOGate: true,
		ExclusionReactiveOnly: true, ExclusionSelection: true,
		ExclusionNotInstallable: true, ExclusionNoRBAC: true, ExclusionCapability: true, ExclusionActionFailure: true,
		ExclusionOperatorOptOut: true,
	}
	selectedRows := 0
	for i, row := range t.ActionStatus {
		if row.Action != string(MutatingActions[i]) {
			return fmt.Errorf("actionStatus[%d] = %q, canonical order wants %q", i, row.Action, MutatingActions[i])
		}
		if !statusOK[row.Status] {
			return fmt.Errorf("actionStatus[%d] status %q is outside the closed vocabulary", i, row.Status)
		}
		if !kindOK[row.ExclusionKind] {
			return fmt.Errorf("actionStatus[%d] exclusionKind %q is outside the closed vocabulary", i, row.ExclusionKind)
		}
		// (2) status/kind consistency: a selected row carries no exclusion; a
		// data-quality exclusion always reads infeasible (never collapsed).
		if row.Status == ActionStatusSelected {
			selectedRows++
			if row.ExclusionKind != ExclusionNone {
				return fmt.Errorf("actionStatus[%d] selected but exclusionKind=%q", i, row.ExclusionKind)
			}
		}
		if row.ExclusionKind == ExclusionCostNaN && row.Status != ActionStatusInfeasible {
			return fmt.Errorf("actionStatus[%d] cost-nan must read status=infeasible, got %q", i, row.Status)
		}
		// T1-E: not-installable / ineligible are now emitted by the capability gate;
		// enforce status↔kind consistency instead of rejecting them outright.
		if row.Status == ActionStatusNotInstallable && row.ExclusionKind != ExclusionNotInstallable {
			return fmt.Errorf("actionStatus[%d] not-installable must read exclusionKind=not-installable, got %q", i, row.ExclusionKind)
		}
		if row.Status == ActionStatusIneligible &&
			row.ExclusionKind != ExclusionNoRBAC && row.ExclusionKind != ExclusionCapability && row.ExclusionKind != ExclusionActionFailure && row.ExclusionKind != ExclusionOperatorOptOut {
			return fmt.Errorf("actionStatus[%d] ineligible must read a recognized eligibility exclusion, got %q", i, row.ExclusionKind)
		}
	}
	if t.SelectedAction == string(ActionNoop) && selectedRows != 0 {
		return errors.New("noop trace has a selected actionStatus row")
	}
	if t.SelectedAction != string(ActionNoop) {
		if selectedRows != 1 {
			return fmt.Errorf("selected trace has %d selected actionStatus rows, want 1", selectedRows)
		}
		rank := canonicalActionRank(t.SelectedAction)
		if rank >= len(t.ActionStatus) {
			return fmt.Errorf("selected action %q is not a canonical mutating action", t.SelectedAction)
		}
		if t.ActionStatus[rank].Status != ActionStatusSelected {
			return fmt.Errorf("selected action %q is not the selected actionStatus row", t.SelectedAction)
		}
	}

	// (3) One asset per record: every candidate key's asset prefix is this asset.
	asset := t.AssetNamespace + "/" + t.AssetName
	for _, c := range t.Candidates {
		key := c.CandidateKey
		if at := strings.LastIndex(key, "|"); at >= 0 {
			key = key[:at]
		}
		if key != asset {
			return fmt.Errorf("candidate %q does not belong to this record's asset %q", c.CandidateKey, asset)
		}
	}

	// (4) CHi reconstruction law (B.1): CostHigh = ExpectedCost + slack, where
	// slack = max(conformalQuantile, gpuEnvelopeSlack if applied) for rotate and
	// 0 otherwise. Rows without a computed CostHigh (NaN, pre-cost exclusions)
	// are outside the law — and must carry none of the slack terms.
	for _, c := range t.Candidates {
		if !c.CostHigh.Present || !c.ExpectedCost.Present {
			if c.ConformalQuantile.Present || c.GPUEnvelopeSlack.Present {
				return fmt.Errorf("candidate %q carries slack terms without a computed cost", c.CandidateKey)
			}
			continue
		}
		want := c.ExpectedCost.Value
		if c.Action == string(ActionRotate) {
			if !c.ConformalQuantile.Present {
				return fmt.Errorf("candidate %q is a costed rotate without the conformal quantile", c.CandidateKey)
			}
			slack := c.ConformalQuantile.Value
			if c.GPUEnvelopeApplied.Present && c.GPUEnvelopeApplied.Value {
				if !c.GPUEnvelopeSlack.Present {
					return fmt.Errorf("candidate %q applied the GPU envelope without recording its value", c.CandidateKey)
				}
				if c.GPUEnvelopeSlack.Value > slack {
					slack = c.GPUEnvelopeSlack.Value
				}
			}
			want += slack
		} else if c.ConformalQuantile.Present || (c.GPUEnvelopeApplied.Present && c.GPUEnvelopeApplied.Value) {
			return fmt.Errorf("candidate %q is non-rotate but carries rotate slack terms", c.CandidateKey)
		}
		if math.Abs(want-c.CostHigh.Value) > 1e-9 {
			return fmt.Errorf("candidate %q cost high is not reconstructable (want %g, got %g)",
				c.CandidateKey, want, c.CostHigh.Value)
		}
	}

	// (5) coveredBeforeDecision is derived, not asserted: coveredRound present
	// and strictly before the record's evaluation round.
	factByKey := map[string]*DecisionFactV2{}
	for i := range t.Facts {
		f := &t.Facts[i]
		want := f.CoveredRound.Present && f.CoveredRound.Value < t.EvaluationRound
		if f.CoveredBeforeDecision != want {
			return fmt.Errorf("fact %q coveredBeforeDecision=%t contradicts coveredRound=%+v at evaluationRound=%d",
				f.FactKey, f.CoveredBeforeDecision, f.CoveredRound, t.EvaluationRound)
		}
		factByKey[f.FactKey] = f
	}

	// (6) Marginal law: the recorded marginal is the sum of final weights over
	// cover keys not covered before the evaluation round.
	for _, c := range t.Candidates {
		if !c.MarginalCoverage.Present {
			continue
		}
		sum := 0.0
		for _, k := range c.CoverKeys {
			f, ok := factByKey[k]
			if !ok {
				return fmt.Errorf("candidate %q covers fact %q that has no recorded fact row", c.CandidateKey, k)
			}
			if !f.CoveredBeforeDecision {
				sum += f.FinalWeight
			}
		}
		if math.Abs(sum-c.MarginalCoverage.Value) > 1e-9 {
			return fmt.Errorf("candidate %q marginal coverage is not reconstructable (want %g, got %g)",
				c.CandidateKey, sum, c.MarginalCoverage.Value)
		}
	}

	// (7) Dispatch outcome from the closed vocabulary, always recorded.
	switch t.DispatchOutcome {
	case DispatchNotAttempted, DispatchEmitted, DispatchEmittedFalse, DispatchError:
	default:
		return fmt.Errorf("dispatchOutcome %q is outside the closed vocabulary", t.DispatchOutcome)
	}
	return nil
}
