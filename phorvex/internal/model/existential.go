package model

import (
	"encoding/json"
	"slices"
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

// AssessOutcomes reads the full authenticated-event inventory, before projection
// through FactWeights. Conflicting records are retained, never last-writer-wins.
func AssessOutcomes(v *WorkloadView, p Policy) *ExistentialDecision {
	d := &ExistentialDecision{TrustBoundaryReady: p.TrustBoundaryReady, TrustBoundaryReason: p.TrustBoundaryReason, TrustBoundarySince: p.TrustBoundarySince, Result: "inactive", EffectStatus: "not-attempted", MayBreachSLO: p.MayBreachSLO, Order: "baseline"}
	key := v.Pod.Namespace + "/" + v.Pod.Name
	horizon := p.EffectiveEventAgeHorizon()
	for _, ev := range v.OutcomeEvents {
		if ev.TargetBindingReason != "" {
			continue
		}
		if ev.OutcomeParseError != "" {
			d.Reasons = append(d.Reasons, ev.OutcomeParseError)
		}
		for _, r := range ev.Outcomes {
			// Another policy's inventory cannot constrain this one.
			if r.PolicyUID != "" && r.PolicyUID != p.PolicyUID {
				continue
			}
			if r.DecisionAsset != "" && r.DecisionAsset != key && p.DecisionAssets[r.DecisionAsset] != "" {
				continue
			}
			e := OutcomeEvidence{Outcome: r, Event: ev.Name, Class: OutcomeClass(r), EventTrust: ev.Trust, CreatorIdentity: ev.CreatorIdentity, EventCreatedAt: ev.CreatedAt, EventAgeSeconds: ev.Age.Seconds(), EvidenceHorizonSeconds: horizon.Seconds(), TimestampPresent: !ev.TimestampMissing}
			scope := r.ID != "" && r.PolicyUID != "" && r.PolicyUID == p.PolicyUID && r.DecisionAsset == key && r.DecisionAssetUID != "" && r.DecisionAssetUID == v.Pod.UID && r.ProtectedAsset != "" && r.Version != "" && r.Portion != "" && r.Property != "" && r.ScopeBasis != ""
			relevant := scope && slices.Contains(ev.ResolvedTargets, key)
			e.TrustedEvidence = relevant && ev.Trust == "trusted" && ev.CreatorIdentity != "" && !ev.TimestampMissing && EventAgeWeight(ev.Age, horizon) > 0
			if !scope {
				e.Reasons = append(e.Reasons, "scope-unresolved")
				d.Reasons = append(d.Reasons, "scope-unresolved:"+r.ID)
			}
			if !e.TrustedEvidence {
				e.Reasons = append(e.Reasons, "no-valid-scoped-trusted-support")
			}
			boundaryValid := p.TrustBoundaryReady && (p.TrustBoundarySince.IsZero() || !ev.CreatedAt.Before(p.TrustBoundarySince))
			e.BoundaryEnforced = boundaryValid
			e.TrustedEvidence = e.TrustedEvidence && boundaryValid
			if !boundaryValid {
				e.Reasons = append(e.Reasons, "m94-boundary-not-ready-or-event-predates-enforcement:"+p.TrustBoundaryReason)
			}
			if e.Class == "unresolved" {
				e.Reasons = append(e.Reasons, "class-unresolved")
			}
			if (r.LossState != "at-risk" && r.LossState != "already-lost") || r.StateBasis == "" {
				e.Reasons = append(e.Reasons, "loss-state-unknown")
			}
			e.Qualified = scope && e.TrustedEvidence && boundaryValid && e.Class == "irreversible-catastrophic" && r.LossState == "at-risk" && r.StateBasis != ""
			d.Evidence = append(d.Evidence, e)
			d.TrustedEvidence = d.TrustedEvidence || e.TrustedEvidence
			d.Present = d.Present || e.Qualified
		}
	}
	d.Present = false
	for i := range d.Evidence {
		risk := &d.Evidence[i]
		if !risk.Qualified {
			continue
		}
		for _, other := range d.Evidence {
			if other.TrustedEvidence && other.BoundaryEnforced && other.Class == "irreversible-catastrophic" && other.Outcome.LossState == "already-lost" && other.Outcome.StateBasis != "" && sameOutcomeScope(risk.Outcome, other.Outcome) {
				risk.Qualified = false
				risk.Reasons = append(risk.Reasons, "accepted-established-loss-no-prevention-credit")
				break
			}
		}
		d.Present = d.Present || risk.Qualified
	}
	d.ConstraintApplied = d.Present
	if d.Present {
		d.Order = "existential>λ"
		if p.MayBreachSLO {
			d.Order = "existential>SLO>λ"
		}
	}
	return d
}

func sameOutcomeScope(a, b ProtectedOutcome) bool {
	return a.PolicyUID == b.PolicyUID && a.ProtectedAsset == b.ProtectedAsset && a.Version == b.Version && a.Portion == b.Portion && a.Property == b.Property && a.Outcome == b.Outcome
}

// HasQualifiedOutcome reports whether v carries a qualified M99 outcome. The
// dispatcher retains an unavailable capability checker as a veto specifically for
// it, without changing the ordinary fail-open path.
func HasQualifiedOutcome(v *WorkloadView, p Policy) bool {
	return AssessOutcomes(v, p).Present
}
