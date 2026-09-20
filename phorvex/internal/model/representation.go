package model

import (
	"math"
)

// RepresentationState is reporting-only. Its safe zero value is unknown.
// M-99 may reference these definitions, but M-100 adds no selection constraint.
type RepresentationState uint8

const (
	RepresentationUnknown RepresentationState = iota
	RepresentationAtRisk
	RepresentationAlreadyLost
)

func (s RepresentationState) MarshalJSON() ([]byte, error) {
	switch s {
	case RepresentationAtRisk:
		return []byte(`"at-risk"`), nil
	case RepresentationAlreadyLost:
		return []byte(`"already-lost"`), nil
	default:
		return []byte(`"unknown"`), nil
	}
}

func (s *RepresentationState) UnmarshalJSON(b []byte) error {
	*s = RepresentationUnknown
	switch string(b) {
	case `"at-risk"`:
		*s = RepresentationAtRisk
	case `"already-lost"`:
		*s = RepresentationAlreadyLost
	}
	return nil
}

// ProtectedScope identifies an assertion, not just a pod or a fact kind.
type ProtectedScope struct {
	Tenant   string `json:"tenant"`
	Asset    string `json:"asset"`
	Version  string `json:"version"`
	Property string `json:"property"`
}

type RepresentationAmount struct {
	Present bool     `json:"present"`
	Value   *float64 `json:"value"`
	Reason  string   `json:"reason,omitempty"`
}

type RepresentationFact struct {
	Key                 string         `json:"key"` // original recon key; Tenant provides qualification
	Kind                string         `json:"kind"`
	Scope               ProtectedScope `json:"scope"`
	RuleVersion         string         `json:"ruleVersion"`
	ObservationRef      string         `json:"observationRef"`
	ReversibleCondition string         `json:"reversibleCondition"`
	Reason              string         `json:"reason,omitempty"`
	Actionability       []string       `json:"actionability"`
}

// LossWitness is an already-bound evidence record supplied by a trusted adapter,
// not a SecurityEvent/source string. Nonempty references are necessary, not a
// substitute for independent review of the referenced event-to-outcome rule.
type LossWitness struct {
	Scope                           ProtectedScope `json:"scope"`
	EventRef                        string         `json:"eventRef"`
	EventTime                       string         `json:"eventTime"`
	IngestionTime                   string         `json:"ingestionTime"`
	AuthenticatedIdentity           string         `json:"authenticatedIdentity"`
	TrustAtIngestionRef             string         `json:"trustAtIngestionRef"`
	RuleVersion                     string         `json:"ruleVersion"`
	PayloadPredicateRef             string         `json:"payloadPredicateRef"`
	CompletedUnauthorizedOutcomeRef string         `json:"completedUnauthorizedOutcomeRef"`
	IrreversibilitySemantics        string         `json:"irreversibilitySemantics"`
	ClassificationRef               string         `json:"classificationRef"`
}

type RetainedLoss struct {
	ID        string         `json:"id"`
	Scope     ProtectedScope `json:"scope"`
	Witnesses []LossWitness  `json:"witnesses"`
}

type RepresentationGap struct {
	Scope  ProtectedScope `json:"scope"`
	Kind   string         `json:"kind"`
	Reason string         `json:"reason"`
}

type RepresentationWeights struct {
	SnapshotRef   string             `json:"snapshotRef"`
	Basis         string             `json:"basis"`
	ProvenanceRef string             `json:"provenanceRef"`
	InvalidValues map[string]string  `json:"invalidValues"`
	Values        map[string]float64 `json:"values"` // QualifiedRepresentationKey keys
}

type RepresentationCovers struct {
	SnapshotRef string     `json:"snapshotRef"`
	Available   bool       `json:"available"`
	Sets        [][]string `json:"sets"` // QualifiedRepresentationKey keys, one per action
}

// RepresentationSnapshot is a frozen, replayable reporting input. The runner
// copies source bindings before actuation and appends dispatch evidence afterward. It must
// never be passed back into the optimizer. Claim retains record-time metadata.
type RepresentationSnapshot struct {
	Ref                    string                `json:"ref"`
	Scope                  ProtectedScope        `json:"scope"`
	Aggregation            string                `json:"aggregation"` // per-decision or fleet-union
	PopulationVersion      string                `json:"populationVersion"`
	InventoryComplete      bool                  `json:"inventoryComplete"`
	ClassificationComplete bool                  `json:"classificationComplete"`
	Claim                  *ClaimScope           `json:"claim"`
	DetectorBasis          string                `json:"detectorBasis"`
	CapabilityStatus       string                `json:"capabilityStatus"`
	CapabilityVersion      string                `json:"capabilityVersion"`
	UnresolvedEntries      []RepresentationGap   `json:"unresolvedEntries"`
	UnknownKinds           []RepresentationGap   `json:"unknownKinds"`
	Facts                  []RepresentationFact  `json:"facts"`
	Weights                RepresentationWeights `json:"weights"`
	ActionBasis            string                `json:"actionBasis"`
	Covers                 RepresentationCovers  `json:"covers"`
	Candidates             RepresentationCovers  `json:"candidates"`
	HistoryStatus          string                `json:"historyStatus"`
	LossMappingVersion     string                `json:"lossMappingVersion"`
	DispatchEvidence       string                `json:"dispatchEvidence"`
	LossAssessment         string                `json:"lossAssessment"`
	History                []RetainedLoss        `json:"history"`
	Witnesses              []LossWitness         `json:"witnesses"`
	Limitations            []string              `json:"limitations"`
}

type ReportedFact struct {
	RepresentationFact
	State    RepresentationState `json:"state"`
	LossRefs []string            `json:"lossRefs"`
}

type RepresentationCoverage struct {
	Unit               string               `json:"unit"`
	Covered            RepresentationAmount `json:"covered"`
	Representable      RepresentationAmount `json:"representable"`
	Coverable          RepresentationAmount `json:"coverable"`
	Share              RepresentationAmount `json:"share"`
	KnownAtRisk        int                  `json:"knownAtRisk"`
	KnownLostEntries   int                  `json:"knownLostEntries"`
	KnownUnknown       int                  `json:"knownUnknown"`
	RequiredSetCovered *bool                `json:"requiredSetCovered"`
}

type RepresentationAsset struct {
	Scope      ProtectedScope      `json:"scope"`
	Primary    RepresentationState `json:"primary"`
	AtRiskKeys []string            `json:"atRiskKeys"`
	LossRefs   []string            `json:"lossRefs"`
	Unresolved []string            `json:"unresolved"`
}

type Representation struct {
	Version            string                 `json:"version"`
	Snapshot           RepresentationSnapshot `json:"snapshot"`
	CoverageShare      RepresentationCoverage `json:"coverageShare"`
	FactStates         []ReportedFact         `json:"factStates"`
	AlreadyLost        []RetainedLoss         `json:"alreadyLost"`
	KnownLossCount     int                    `json:"knownLossCount"` // recorded losses, never actual total loss
	LossHistoryStatus  string                 `json:"lossHistoryStatus"`
	LossAssessment     string                 `json:"lossAssessment"`
	UnknownEntries     []RepresentationGap    `json:"unknownEntries"`
	UnknownKinds       []RepresentationGap    `json:"unknownKinds"`
	UncoverableEntries []string               `json:"uncoverableEntries"`
	AssetState         []RepresentationAsset  `json:"assetState"`
	OutOfBand          string                 `json:"outOfBand"`
	EffectEvidence     string                 `json:"effectEvidence"`
	Note               string                 `json:"note"`
}

// Redacted canonicalizes reporting payloads with the existing M99 credential
// redactor before report identities are constructed. A redacted protected scope
// cannot establish a positive classification. Original evidence belongs in the
// authenticated source archive; this audit stores safe references only.
func (s RepresentationSnapshot) Redacted() RepresentationSnapshot {
	s, _ = s.withoutCredentialKeys()
	for _, value := range s.Weights.Values {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return RepresentationSnapshot{Limitations: []string{"invalid-reporting-input"}}
		}
	}
	out := cloneRepresentationSnapshot(s, true)
	for i, f := range s.Facts {
		if f.Scope != out.Facts[i].Scope {
			out.Facts[i].Reason = "redacted-scope-binding-unavailable"
			out.ClassificationComplete = false
		}
	}
	for i, w := range s.Witnesses {
		if w.Scope != out.Witnesses[i].Scope {
			out.Witnesses[i].TrustAtIngestionRef = ""
		}
	}
	for i, l := range s.History {
		if l.Scope != out.History[i].Scope {
			out.HistoryStatus = "partial"
		}
	}
	return out
}

// MarshalJSON also protects callers persisting an externally decoded report.
func (r Representation) MarshalJSON() ([]byte, error) {
	_, raw, err := MarshalOwnedRedactedRepresentation(&r)
	return raw, err
}

// The existing redactor cleans JSON values, not map keys. Drop sensitive keys
// rather than replacing them: two different credentials must never merge.
func (s RepresentationSnapshot) withoutCredentialKeys() (RepresentationSnapshot, bool) {
	removed := false
	values := make(map[string]float64, len(s.Weights.Values))
	for k, v := range s.Weights.Values {
		if redactTraceString(k) != k {
			removed = true
			continue
		}
		values[k] = v
	}
	invalid := make(map[string]string, len(s.Weights.InvalidValues))
	for k, v := range s.Weights.InvalidValues {
		if redactTraceString(k) != k {
			removed = true
			continue
		}
		invalid[k] = v
	}
	s.Weights.Values = values
	s.Weights.InvalidValues = invalid
	if removed {
		s.Limitations = append(append([]string{}, s.Limitations...), "credential-bearing-weight-key-removed")
	}
	return s, removed
}
