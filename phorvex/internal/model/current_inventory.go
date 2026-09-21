package model

import "time"

const (
	CurrentInventorySchemaV1         = "phorvex.current-protected-inventory.v1"
	CurrentInventoryRuleType         = "PhorvexCurrentProtectedInventory"
	CurrentInventorySource           = "phorvex-current-inventory-observer"
	CurrentInventoryClass            = "configured-synthetic-protected-inventory"
	CurrentInventoryDescription      = "synthetic current protected-version observation; payload contains digests only"
	AdmittedCurrentInventorySchemaV1 = "phorvex.admitted-current-inventory.v1"
	CurrentInventoryRuleVersionV1    = "current-protected-version-v1"
)

type CurrentInventorySourceBinding struct {
	ConfigMap       ObjectIdentity `json:"configMap"`
	ResourceVersion string         `json:"resourceVersion"`
	Key             string         `json:"key"`
	VolumeName      string         `json:"volumeName"`
	ContainerName   string         `json:"containerName"`
	MountPath       string         `json:"mountPath"`
	ProjectedPath   string         `json:"projectedPath"`
	Bytes           int64          `json:"bytes"`
	SHA256          string         `json:"sha256"`
}

type CurrentInventoryClassification struct {
	RuleVersion      string `json:"ruleVersion"`
	RuleDigest       string `json:"ruleDigest"`
	InventoryClass   string `json:"inventoryClass"`
	PossibleOutcome  string `json:"possibleOutcome"`
	ObserverIdentity string `json:"observerIdentity"`
}

type CurrentInventoryObservation struct {
	StartedAt   time.Time `json:"startedAt"`
	CompletedAt time.Time `json:"completedAt"`
	ValidUntil  time.Time `json:"validUntil"`
	StatusCode  int       `json:"statusCode"`
	ManifestEOF bool      `json:"manifestEOF"`
}

type CurrentInventoryV1 struct {
	SchemaVersion       string                         `json:"schemaVersion"`
	EvidenceID          string                         `json:"evidenceID"`
	PolicyEpoch         PolicyEpoch                    `json:"policyEpoch"`
	DecisionAsset       DecisionAssetIdentity          `json:"decisionAsset"`
	ImmediateController ObjectIdentity                 `json:"immediateController"`
	StableWorkloadOwner ObjectIdentity                 `json:"stableWorkloadOwner"`
	ProtectedScope      ProtectedScope                 `json:"protectedScope"`
	SourceBinding       CurrentInventorySourceBinding  `json:"sourceBinding"`
	Classification      CurrentInventoryClassification `json:"classification"`
	Observation         CurrentInventoryObservation    `json:"observation"`
	Synthetic           bool                           `json:"synthetic"`
}

type AdmittedCurrentInventory struct {
	SchemaVersion          string                  `json:"schemaVersion"`
	Inventory              CurrentInventoryV1      `json:"inventory"`
	CanonicalPayloadSHA256 string                  `json:"canonicalPayloadSHA256"`
	SecurityEvent          SecurityEventIdentity   `json:"securityEvent"`
	AdmissionTime          time.Time               `json:"admissionTime"`
	AuthenticatedCreator   string                  `json:"authenticatedCreator"`
	TrustBoundary          DisclosureTrustBoundary `json:"trustBoundary"`
	IngestedAt             time.Time               `json:"ingestedAt"`
}

// CurrentInventoryProvenance is the compact audit join retained on a reported
// fact. The full canonical payload remains in the bounded current ledger.
type CurrentInventoryProvenance struct {
	SchemaVersion            string `json:"schemaVersion"`
	EvidenceID               string `json:"evidenceID"`
	PolicyUID                string `json:"policyUID"`
	PolicyGeneration         int64  `json:"policyGeneration"`
	StableOwnerUID           string `json:"stableOwnerUID"`
	PodUID                   string `json:"podUID"`
	ConfigMapUID             string `json:"configMapUID"`
	ConfigMapResourceVersion string `json:"configMapResourceVersion"`
	CanonicalPayloadSHA256   string `json:"canonicalPayloadSHA256"`
	SecurityEventUID         string `json:"securityEventUID"`
}
