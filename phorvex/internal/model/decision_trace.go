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

	RequestRate       OptionalFloat `json:"requestRate"`
	ConnectionCount   OptionalFloat `json:"connectionCount"`
	GPUUtilization    OptionalFloat `json:"gpuUtilization"`
	SMOccupancy       OptionalFloat `json:"smOccupancy"`
	VRAMFraction      OptionalFloat `json:"vramFraction"`
	ImageRarity       OptionalFloat `json:"imageRarity"`
	ModelRarity       OptionalFloat `json:"modelRarity"`
	CoResidency       OptionalFloat `json:"coResidency"`
	EPSS              OptionalFloat `json:"epss"`
	CVSS              OptionalFloat `json:"cvss"`
	PhysicsScanned    bool          `json:"physicsScanned"`
	DispersionMult    OptionalFloat `json:"dispersionMult"`
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

	MarginalCoverage   OptionalFloat `json:"marginalCoverage"`
	Provenance         OptionalFloat `json:"provenance"`
	ExpectedCost       OptionalFloat `json:"expectedCost"`
	CostHigh           OptionalFloat `json:"costHigh"`
	LambdaContribution OptionalFloat `json:"lambdaContribution"`
	NetGain            OptionalFloat `json:"netGain"`
	Feasible           OptionalBool  `json:"feasible"`
	Selected           bool          `json:"selected"`

	ExistingExclusionReason     string `json:"existingExclusionReason,omitempty"`
	NotClassifiedByCurrentModel bool   `json:"notClassifiedByCurrentModel"`
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

	out.Inputs.Phase = redactTraceString(out.Inputs.Phase)
	out.Inputs.Stage = redactTraceString(out.Inputs.Stage)
	out.Inputs.ExposureVariable = redactTraceString(out.Inputs.ExposureVariable)
	out.Inputs.RequestRate = cleanOptional(out.Inputs.RequestRate)
	out.Inputs.ConnectionCount = cleanOptional(out.Inputs.ConnectionCount)
	out.Inputs.GPUUtilization = cleanOptional(out.Inputs.GPUUtilization)
	out.Inputs.SMOccupancy = cleanOptional(out.Inputs.SMOccupancy)
	out.Inputs.VRAMFraction = cleanOptional(out.Inputs.VRAMFraction)
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
		c.CoverKeys = append([]string(nil), c.CoverKeys...)
		for j := range c.CoverKeys {
			c.CoverKeys[j] = redactTraceString(c.CoverKeys[j])
		}
		sort.Strings(c.CoverKeys)
		c.MarginalCoverage = cleanOptional(c.MarginalCoverage)
		c.Provenance = cleanOptional(c.Provenance)
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
