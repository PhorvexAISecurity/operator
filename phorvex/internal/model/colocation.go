package model

import "time"

// ColocationAssessment is an observational record, NEVER a numerical FactWeight.
// Keep it out of Decision/DecisionTrace to preserve the existing decision payload.
type ColocationAssessment struct {
	SchemaVersion           string                     `json:"schemaVersion"`
	Kind                    string                     `json:"kind"`
	DecisionID              string                     `json:"decisionID"`
	TickID                  string                     `json:"tickID"`
	GitSHA                  string                     `json:"gitSHA"`
	BrainImage              string                     `json:"brainImage"`
	SnapshotTime            time.Time                  `json:"snapshotTime"`
	Tenant                  string                     `json:"tenant"`
	PolicyUID               string                     `json:"policyUID"`
	PolicyKey               string                     `json:"policyKey"`
	IdentityBasis           string                     `json:"identityBasis"`
	PeerPolicies            []string                   `json:"peerPolicies"`
	PodKey                  string                     `json:"podKey"`
	PodUID                  string                     `json:"podUID"`
	Node                    string                     `json:"node"`
	Fact                    string                     `json:"fact"`
	State                   string                     `json:"state"`
	Reason                  string                     `json:"reason"`
	ObservabilityBasis      string                     `json:"observabilityBasis"`
	ThreatModel             string                     `json:"threatModel"`
	PodInventoryComplete    bool                       `json:"podInventoryComplete"`
	PolicyInventoryComplete bool                       `json:"policyInventoryComplete"`
	EventInventoryComplete  bool                       `json:"eventInventoryComplete"`
	Neighbors               []ColocationNeighbor       `json:"neighbors"`
	Witnesses               []string                   `json:"witnesses"`
	Weight                  UnresolvedColocationWeight `json:"weight"`
	EffectiveContribution   float64                    `json:"effective_contribution"`
	ScoringAdmitted         bool                       `json:"scoring_admitted"`
	ScoringReason           string                     `json:"scoringReason"`
	CoverEnabled            bool                       `json:"coverEnabled"`
	CoverCondition          string                     `json:"coverCondition"`
	CoverReason             string                     `json:"coverReason"`
	Prerequisites           []string                   `json:"prerequisites"`
	PredictedCover          bool                       `json:"predictedCover"`
	ConfirmedInvalidation   bool                       `json:"confirmedInvalidation"`
	ExecutionOutcome        string                     `json:"executionOutcome"`
	EventAgeBinding         string                     `json:"eventAgeBinding"`
}

type UnresolvedColocationWeight struct {
	Status string   `json:"status"`
	Value  *float64 `json:"value"`
}

type ColocationNeighbor struct {
	PodKey                    string            `json:"podKey"`
	PodUID                    string            `json:"podUID"`
	Node                      string            `json:"node"`
	Class                     string            `json:"class"`
	Reason                    string            `json:"reason"`
	Policies                  []string          `json:"policies"`
	OwnerKind                 string            `json:"ownerKind"`
	NamespaceTrustDeclaration string            `json:"namespaceTrustDeclaration"`
	Events                    []ColocationEvent `json:"events"`
}

type ColocationEvent struct {
	Name       string  `json:"name"`
	Source     string  `json:"source"`
	Target     string  `json:"target"`
	AgeSeconds float64 `json:"ageSeconds"`
	AgePresent bool    `json:"agePresent"`
	Trust      string  `json:"trust"`
	Override   string  `json:"override"`
}
