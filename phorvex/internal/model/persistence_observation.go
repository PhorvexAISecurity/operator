package model

import (
	"fmt"
	"time"
	"unicode/utf8"
)

const (
	PersistenceObservationSchemaV1 = "phorvex.persistence-observation.v1"
	PersistenceLearningSchemaV1    = "phorvex.persistence-learning.v1"

	PersistenceHeld     = "held"
	PersistenceRevoked  = "revoked"
	PersistenceUnknown  = "unknown"
	PersistenceCensored = "censored"

	PersistenceDispositionNoProducer = "no-qualified-live-label-producer"
	PersistenceDispositionNoLabel    = "no-qualified-observed-label"
	PersistenceDispositionApplied    = "applied"
	PersistenceDispositionDuplicate  = "duplicate-idempotent"
	PersistenceDispositionConflict   = "evidence-id-conflict"
	PersistenceDispositionSaturated  = "dedup-saturated"
	PersistenceDispositionExpired    = "observation-expired"
	PersistenceDispositionRejected   = "binding-rejected"
	PersistenceDispositionUnresolved = "outcome-unresolved"
)

// PolicyEpoch is the exact active policy identity to which an observation is bound.
type PolicyEpoch struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
}

func (e PolicyEpoch) Owner() string { return OwnerKey(OwnerKindUID, e.UID) }

func (e PolicyEpoch) Validate() error {
	if e.Namespace == "" || e.Name == "" || e.UID == "" || e.Generation <= 0 {
		return fmt.Errorf("policy epoch requires namespace, name, UID, and positive generation")
	}
	if len(e.Namespace) > 253 || len(e.Name) > 253 || len(e.UID) > 253 {
		return fmt.Errorf("policy epoch identity exceeds bounded size")
	}
	if !utf8.ValidString(e.Namespace) || !utf8.ValidString(e.Name) || !utf8.ValidString(e.UID) {
		return fmt.Errorf("policy epoch identity is not valid UTF-8")
	}
	return nil
}

// PersistenceOperationBinding is retained independently by an authoritative
// effect producer. TargetUID is the object on which the operation began; a
// successful revocation remains bound to that old UID after replacement.
type PersistenceOperationBinding struct {
	Policy               PolicyEpoch `json:"policy"`
	OperationID          string      `json:"operationID"`
	TargetUID            string      `json:"targetUID"`
	Capability           string      `json:"capability"`
	Scope                string      `json:"scope"`
	ObservationNotBefore time.Time   `json:"observationNotBefore"`
	ObservationDeadline  time.Time   `json:"observationDeadline"`
}

// PersistenceObservation is a categorical observed outcome. It deliberately
// has no PHold or confidence target: predictions cannot be submitted as labels.
type PersistenceObservation struct {
	SchemaVersion    string      `json:"schemaVersion"`
	Source           string      `json:"source"`
	EvidenceID       string      `json:"evidenceID"`
	Policy           PolicyEpoch `json:"policy"`
	OperationID      string      `json:"operationID"`
	TargetUID        string      `json:"targetUID"`
	Capability       string      `json:"capability"`
	Scope            string      `json:"scope"`
	ObservationStart time.Time   `json:"observationStart"`
	ObservationEnd   time.Time   `json:"observationEnd"`
	Outcome          string      `json:"outcome"`
}

// PersistenceLearningStatus is audit provenance, not an efficacy or
// calibration claim. QualifiedLabels counts raw admitted held/revoked outcomes;
// it is not the effective conjugate pseudo-count mass, which remains capped.
type PersistenceLearningStatus struct {
	SchemaVersion   string       `json:"schemaVersion"`
	Source          string       `json:"source"`
	Disposition     string       `json:"disposition"`
	Policy          *PolicyEpoch `json:"policy,omitempty"`
	EvidenceID      string       `json:"evidenceID,omitempty"`
	Outcome         string       `json:"outcome,omitempty"`
	QualifiedLabels int          `json:"qualifiedLabels"`
	HeldLabels      int          `json:"heldLabels"`
	RevokedLabels   int          `json:"revokedLabels"`
	DedupEntries    int          `json:"dedupEntries"`
	DedupCapacity   int          `json:"dedupCapacity"`
}

func ValidatePersistenceLearningStatus(status *PersistenceLearningStatus) error {
	if status == nil {
		return nil
	}
	if status.SchemaVersion != PersistenceLearningSchemaV1 || status.Source == "" || status.Disposition == "" {
		return fmt.Errorf("persistence learning status lacks schema, source, or disposition")
	}
	if status.Policy != nil {
		if err := status.Policy.Validate(); err != nil {
			return fmt.Errorf("persistence learning policy: %w", err)
		}
	}
	if len(status.Source) > 128 || len(status.EvidenceID) > 253 ||
		!utf8.ValidString(status.Source) || !utf8.ValidString(status.EvidenceID) {
		return fmt.Errorf("persistence learning status identity exceeds bounded size")
	}
	switch status.Disposition {
	case PersistenceDispositionNoProducer, PersistenceDispositionNoLabel,
		PersistenceDispositionApplied, PersistenceDispositionDuplicate,
		PersistenceDispositionConflict, PersistenceDispositionSaturated,
		PersistenceDispositionExpired, PersistenceDispositionRejected,
		PersistenceDispositionUnresolved:
	default:
		return fmt.Errorf("unknown persistence learning disposition %q", status.Disposition)
	}
	if status.Outcome != "" {
		switch status.Outcome {
		case PersistenceHeld, PersistenceRevoked, PersistenceUnknown, PersistenceCensored:
		default:
			return fmt.Errorf("unknown persistence learning outcome %q", status.Outcome)
		}
	}
	if status.QualifiedLabels < 0 || status.HeldLabels < 0 || status.RevokedLabels < 0 ||
		status.QualifiedLabels != status.HeldLabels+status.RevokedLabels ||
		status.DedupEntries < 0 || status.DedupCapacity < 0 || status.DedupEntries > status.DedupCapacity ||
		status.DedupEntries != status.QualifiedLabels {
		return fmt.Errorf("persistence learning status counters are contradictory")
	}
	switch status.Disposition {
	case PersistenceDispositionNoProducer:
		if status.Source != "none" || status.QualifiedLabels != 0 {
			return fmt.Errorf("no-producer persistence status carries producer or label state")
		}
	case PersistenceDispositionNoLabel:
		if status.Source == "none" || status.EvidenceID != "" || status.Outcome != "" {
			return fmt.Errorf("no-label persistence status is contradictory")
		}
	default:
		if status.EvidenceID == "" || status.Outcome == "" {
			return fmt.Errorf("persistence disposition %q lacks evidence identity or outcome", status.Disposition)
		}
	}
	if status.Disposition == PersistenceDispositionApplied || status.Disposition == PersistenceDispositionDuplicate ||
		status.Disposition == PersistenceDispositionConflict || status.Disposition == PersistenceDispositionSaturated {
		if status.Outcome != PersistenceHeld && status.Outcome != PersistenceRevoked {
			return fmt.Errorf("persistence disposition %q requires a categorical label", status.Disposition)
		}
	}
	if status.Disposition == PersistenceDispositionUnresolved && status.Outcome != PersistenceUnknown && status.Outcome != PersistenceCensored {
		return fmt.Errorf("unresolved persistence status requires unknown or censored outcome")
	}
	return nil
}
