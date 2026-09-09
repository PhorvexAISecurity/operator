package model

import (
	"encoding/json"
	"time"
)

// ProtectedOutcome is the M99 scoped detector assertion. It is carried inside an
// authenticated SecurityEvent, never inferred from fact weights or severity.
// RequiredKeys are prevention requirements, not new action grants.
type ProtectedOutcome struct {
	ID               string   `json:"id"`
	PolicyUID        string   `json:"policyUID"`
	DecisionAsset    string   `json:"decisionAsset"`
	DecisionAssetUID string   `json:"decisionAssetUID"`
	ProtectedAsset   string   `json:"protectedAsset"`
	Version          string   `json:"version"`
	Portion          string   `json:"portion"`
	Property         string   `json:"property"`
	Outcome          string   `json:"outcome"`
	Recovery         string   `json:"recovery"`
	ClassBasis       string   `json:"classBasis"`
	ScopeBasis       string   `json:"scopeBasis"`
	LossState        string   `json:"lossState"`
	StateBasis       string   `json:"stateBasis"`
	RequiredKeys     []string `json:"requiredKeys"`
	MappingBasis     string   `json:"mappingBasis"`
	MappingComplete  bool     `json:"mappingComplete"`
}

type OutcomeEvidence struct {
	EventTrust             string           `json:"eventTrust"`
	CreatorIdentity        string           `json:"creatorIdentity"`
	EventCreatedAt         time.Time        `json:"eventCreatedAt"`
	EventAgeSeconds        float64          `json:"eventAgeSeconds"`
	EvidenceHorizonSeconds float64          `json:"evidenceHorizonSeconds"`
	TimestampPresent       bool             `json:"timestampPresent"`
	BoundaryEnforced       bool             `json:"boundaryEnforced"`
	Outcome                ProtectedOutcome `json:"outcome"`
	Event                  string           `json:"event"`
	Class                  string           `json:"class"`
	TrustedEvidence        bool             `json:"trustedEvidence"`
	Qualified              bool             `json:"qualified"`
	Reasons                []string         `json:"reasons,omitempty"`
}

type ExistentialCandidate struct {
	SLOExcluded       bool     `json:"sloExcluded"`
	Action            Action   `json:"action"`
	GenerationRank    int      `json:"generationRank"`
	Present           bool     `json:"present"`
	TrustedEvidence   bool     `json:"trustedEvidence"`
	Contains          bool     `json:"contains"`
	ConstraintApplied bool     `json:"constraintApplied"`
	Order             string   `json:"order"`
	MayBreachSLO      bool     `json:"mayBreachSLO"`
	SLORelaxed        bool     `json:"sloRelaxed"`
	MissingKeys       []string `json:"missingKeys,omitempty"`
	Reasons           []string `json:"reasons,omitempty"`
}

// ExistentialDecision is the PHORVEXSEC-208 interim M117 result. Contains means
// certified candidate cover, never successful execution or reversal of past loss.
type ExistentialDecision struct {
	TrustBoundaryReady  bool                   `json:"trustBoundaryReady"`
	TrustBoundaryReason string                 `json:"trustBoundaryReason"`
	TrustBoundarySince  time.Time              `json:"trustBoundarySince"`
	Present             bool                   `json:"present"`
	TrustedEvidence     bool                   `json:"trustedEvidence"`
	ConstraintApplied   bool                   `json:"constraintApplied"`
	MayBreachSLO        bool                   `json:"mayBreachSLO"`
	Order               string                 `json:"order"`
	Result              string                 `json:"result"`
	EffectStatus        string                 `json:"effectStatus"`
	RemainingBudget     int                    `json:"remainingBudget"`
	Evidence            []OutcomeEvidence      `json:"evidence"`
	Candidates          []ExistentialCandidate `json:"candidates"`
	Reasons             []string               `json:"reasons,omitempty"`
	PrioritySelections  []string               `json:"prioritySelections,omitempty"`
}

func OutcomeClass(r ProtectedOutcome) string {
	if r.ClassBasis == "" {
		return "unresolved"
	}
	switch r.Outcome {
	case "unauthorized-disclosure":
		return "irreversible-catastrophic"
	case "destruction-corruption", "control-integrity-loss":
		if r.Recovery == "no-trustworthy-recovery" {
			return "irreversible-catastrophic"
		}
		if r.Recovery == "trusted-rebuild-restore" {
			return "reversible-costly"
		}
	case "service-disruption", "revocable-access", "replacement-reset":
		if r.Recovery == "trusted-rebuild-restore" || r.Recovery == "revocable" {
			return "reversible-costly"
		}
	}
	return "unresolved"
}

// ExistentialInventory retains policy-level scope gaps even when no workload is
// selected, so an unmappable exposure cannot masquerade as an empty inventory.
type ExistentialInventory struct {
	PolicyUID     string             `json:"policyUID"`
	ScopeComplete bool               `json:"scopeComplete"`
	Records       []OutcomeAssertion `json:"records"`
	Reasons       []string           `json:"reasons,omitempty"`
}

// Detector-supplied descriptions obey the same credential redaction boundary as
// other decision traces. Work on a serialization copy, never optimizer inputs.
func marshalOutcomeRedacted(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	if err = json.Unmarshal(b, &tree); err != nil {
		return nil, err
	}
	var clean func(any) any
	clean = func(value any) any {
		switch x := value.(type) {
		case string:
			return redactTraceString(x)
		case []any:
			for i := range x {
				x[i] = clean(x[i])
			}
		case map[string]any:
			for k, v := range x {
				x[k] = clean(v)
			}
		}
		return value
	}
	return json.Marshal(clean(tree))
}

func (d ExistentialDecision) MarshalJSON() ([]byte, error) {
	type plain ExistentialDecision
	return marshalOutcomeRedacted(plain(d))
}
func (d ExistentialCandidate) MarshalJSON() ([]byte, error) {
	type plain ExistentialCandidate
	return marshalOutcomeRedacted(plain(d))
}
func (d ExistentialInventory) MarshalJSON() ([]byte, error) {
	type plain ExistentialInventory
	return marshalOutcomeRedacted(plain(d))
}

// OutcomeAssertion is raw policy inventory, before per-asset trust qualification.
type OutcomeAssertion struct {
	Event      string           `json:"event"`
	EventTrust string           `json:"eventTrust"`
	Outcome    ProtectedOutcome `json:"outcome"`
	Reasons    []string         `json:"reasons,omitempty"`
}
