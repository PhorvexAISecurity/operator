package model

import "time"

const (
	CompletedDisclosureSchemaV1    = "phorvex.completed-disclosure.v1"
	CompletedDisclosureRuleType    = "PhorvexCompletedDisclosure"
	CompletedDisclosureSource      = "phorvex-loss-observer"
	CompletedDisclosureClass       = "unauthorized-synthetic"
	CompletedDisclosureDescription = "synthetic completed-disclosure observation; payload contains digests only"
	AdmittedLossSchemaV1           = "phorvex.admitted-loss.v1"
)

// ObjectIdentity is an immutable Kubernetes object identity. Name is retained
// for audit, while UID is the authority used for joins.
type ObjectIdentity struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

type DecisionAssetIdentity struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	TargetUID string `json:"targetUID"`
}

type DisclosureClassification struct {
	RuleVersion      string `json:"ruleVersion"`
	RuleDigest       string `json:"ruleDigest"`
	ObserverClass    string `json:"observerClass"`
	ObserverIdentity string `json:"observerIdentity"`
}

type DisclosureObservation struct {
	StartedAt      time.Time `json:"startedAt"`
	CompletedAt    time.Time `json:"completedAt"`
	StatusCode     int       `json:"statusCode"`
	ExpectedBytes  int64     `json:"expectedBytes"`
	ObservedBytes  int64     `json:"observedBytes"`
	ReachedEOF     bool      `json:"reachedEOF"`
	ExpectedSHA256 string    `json:"expectedSHA256"`
	ObservedSHA256 string    `json:"observedSHA256"`
}

// CompletedDisclosureV1 is the only M100 producer payload. It contains no
// canary bytes; the two digests and exact completed response are its evidence.
type CompletedDisclosureV1 struct {
	SchemaVersion       string                   `json:"schemaVersion"`
	EvidenceID          string                   `json:"evidenceID"`
	PolicyEpoch         PolicyEpoch              `json:"policyEpoch"`
	DecisionAsset       DecisionAssetIdentity    `json:"decisionAsset"`
	ImmediateController ObjectIdentity           `json:"immediateController"`
	StableWorkloadOwner ObjectIdentity           `json:"stableWorkloadOwner"`
	ProtectedScope      ProtectedScope           `json:"protectedScope"`
	Classification      DisclosureClassification `json:"classification"`
	Observation         DisclosureObservation    `json:"observation"`
	Synthetic           bool                     `json:"synthetic"`
}

type SecurityEventIdentity struct {
	Name              string    `json:"name"`
	UID               string    `json:"uid"`
	CreationTimestamp time.Time `json:"creationTimestamp"`
}

type DisclosureTrustBoundary struct {
	ConfigurationUID             string    `json:"configurationUID"`
	ConfigurationResourceVersion string    `json:"configurationResourceVersion"`
	ActivationTime               time.Time `json:"activationTime"`
	ContractVersion              string    `json:"contractVersion"`
}

// AdmittedLossV1 freezes payload, API identity, authenticated creator and the
// exact fail-closed boundary observed during admission to durable history.
type AdmittedLossV1 struct {
	SchemaVersion          string                  `json:"schemaVersion"`
	Disclosure             CompletedDisclosureV1   `json:"disclosure"`
	CanonicalPayloadSHA256 string                  `json:"canonicalPayloadSHA256"`
	SecurityEvent          SecurityEventIdentity   `json:"securityEvent"`
	AuthenticatedCreator   string                  `json:"authenticatedCreator"`
	TrustBoundary          DisclosureTrustBoundary `json:"trustBoundary"`
	IngestedAt             time.Time               `json:"ingestedAt"`
}
