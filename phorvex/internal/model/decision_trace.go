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
)

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

	RequestRate     OptionalFloat `json:"requestRate"`
	ConnectionCount OptionalFloat `json:"connectionCount"`
	GPUUtilization  OptionalFloat `json:"gpuUtilization"`
	SMOccupancy     OptionalFloat `json:"smOccupancy"`
	VRAMFraction    OptionalFloat `json:"vramFraction"`
	// Leakage is the model-theft gate's ACTIVITY input as actually tested (T1-A): SMOccupancy
	// only, never allocation. Present iff SMOccupancy was measured (SMSource != ""), so an
	// honest-absent scrape is recorded as absent rather than as an idle GPU.
	Leakage        OptionalFloat `json:"leakage"`
	ImageRarity    OptionalFloat `json:"imageRarity"`
	ModelRarity    OptionalFloat `json:"modelRarity"`
	CoResidency    OptionalFloat `json:"coResidency"`
	EPSS           OptionalFloat `json:"epss"`
	CVSS           OptionalFloat `json:"cvss"`
	PhysicsScanned bool          `json:"physicsScanned"`
	DispersionMult OptionalFloat `json:"dispersionMult"`
	// FactsAbsentReason is set when a non-finite belief/physics input meant no fact was
	// minted for this asset (M-111): the weights are absent, not zero and not NaN.
	FactsAbsentReason string        `json:"factsAbsentReason,omitempty"`
	DispersionCap     OptionalFloat `json:"dispersionCap"`
	Primed            bool          `json:"primed"`
	BetaMean          OptionalFloat `json:"betaMean"`
	PHold             OptionalFloat `json:"pHold"`
	Stage             string        `json:"stage"`
	StageHazard       OptionalFloat `json:"stageHazard"`
	StageUrgency      OptionalFloat `json:"stageUrgency"`
	ThreatPosture     OptionalFloat `json:"threatPosture"`
	ExposureVariable  string        `json:"exposureVariable"`
	ExposureSeconds   OptionalFloat `json:"exposureSeconds"`
	ProactiveFloorSec float64       `json:"proactiveFloorSeconds"`
	AntiOverRotateSec float64       `json:"antiOverRotationWindowSeconds"`
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
}

// DecisionCandidateV2 records either a generated feasible candidate or an
// action excluded by an existing current-model gate. Optional values say exactly
// which calculations were reached before an exclusion.
type DecisionCandidateV2 struct {
	Action       string   `json:"action"`
	CandidateKey string   `json:"candidateKey"`
	CoverKeys    []string `json:"coverKeys"`
	TieBreakRank int      `json:"tieBreakRank"`

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

	ExistingExclusionReason     string `json:"existingExclusionReason,omitempty"`
	SelectionReason             string `json:"selectionReason"`
	NotClassifiedByCurrentModel bool   `json:"notClassifiedByCurrentModel"`
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
	SchemaVersion  string `json:"schemaVersion"`
	DecisionID     string `json:"decisionID"`
	TickID         string `json:"tickID"`
	Timestamp      string `json:"timestamp"`
	BrainImage     string `json:"brainImage"`
	GitSHA         string `json:"gitSHA"`
	DecisionEngine string `json:"decisionEngine"`

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
	KillSwitchEngaged    bool    `json:"killSwitchEngaged"`
	LambdaConfiguredSeed float64 `json:"lambdaConfiguredSeed"`
	LambdaRuntime        float64 `json:"lambdaRuntime"`
	// The two fields above remain as wire-compatible aliases for existing readers.
	LambdaConfiguredPolicy    float64              `json:"lambdaConfiguredPolicy"`
	LambdaRuntimeLegacy       float64              `json:"lambdaRuntimeLegacy"`
	SelectorComparator        string               `json:"selectorComparator"`
	NormWeight                float64              `json:"normWeight"`
	FlowWeight                float64              `json:"flowWeight"`
	CFlowUnitStatus           string               `json:"cFlowUnitStatus"`
	CostRepresentationVersion string               `json:"costRepresentationVersion"`
	DualUpdate                DecisionDualUpdateV2 `json:"dualUpdate"`

	Inputs     DecisionModelInputsV2 `json:"inputs"`
	Facts      []DecisionFactV2      `json:"facts"`
	Candidates []DecisionCandidateV2 `json:"candidates"`

	SelectedAction       string      `json:"selectedAction"`
	SelectedCandidateKey string      `json:"selectedCandidateKey,omitempty"`
	SelectionRound       OptionalInt `json:"selectionRound"`
	TieBreakReason       string      `json:"tieBreakReason"`
	NoopReason           string      `json:"noopReason,omitempty"`
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
func (t DecisionTraceV2) Canonical() DecisionTraceV2 {
	out := t
	out.SchemaVersion = DecisionTraceSchemaV2
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
	out.Inputs.DispersionMult = cleanOptional(out.Inputs.DispersionMult)
	out.Inputs.DispersionCap = cleanOptional(out.Inputs.DispersionCap)
	out.Inputs.BetaMean = cleanOptional(out.Inputs.BetaMean)
	out.Inputs.PHold = cleanOptional(out.Inputs.PHold)
	out.Inputs.StageHazard = cleanOptional(out.Inputs.StageHazard)
	out.Inputs.StageUrgency = cleanOptional(out.Inputs.StageUrgency)
	out.Inputs.ThreatPosture = cleanOptional(out.Inputs.ThreatPosture)
	out.Inputs.ExposureSeconds = cleanOptional(out.Inputs.ExposureSeconds)

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
	}
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
func (t DecisionTraceV2) Validate() error {
	if t.SchemaVersion != DecisionTraceSchemaV2 {
		return fmt.Errorf("schemaVersion %q", t.SchemaVersion)
	}
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
			t.SelectorComparator != SelectorStrictPositiveGain {
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
