package console

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const attackCatalogResultSchema = "phorvex.attack-catalogue-result.v1"

const attackCatalogEvidenceSchema = "phorvex.attack-catalogue-evidence.v1"

type AttackCatalogExecutionMode string

const (
	AttackCatalogExecutionActive AttackCatalogExecutionMode = "active"
	AttackCatalogExecutionDryRun AttackCatalogExecutionMode = "dryRun"
)

type AttackCatalogTriggerMode string

const (
	AttackCatalogTriggerReactive          AttackCatalogTriggerMode = "reactive"
	AttackCatalogTriggerProactiveReactive AttackCatalogTriggerMode = "proactive+reactive"
)

func validAttackCatalogModes(execution AttackCatalogExecutionMode, trigger AttackCatalogTriggerMode) bool {
	return (execution == AttackCatalogExecutionActive || execution == AttackCatalogExecutionDryRun) &&
		(trigger == AttackCatalogTriggerReactive || trigger == AttackCatalogTriggerProactiveReactive)
}

type AttackCatalogSignalResult struct {
	CatalogueID string     `json:"catalogueID,omitempty"`
	RunID       string     `json:"runID,omitempty"`
	Family      string     `json:"family,omitempty"`
	Created     bool       `json:"created"`
	Observed    bool       `json:"observed"`
	Name        string     `json:"name,omitempty"`
	UID         string     `json:"uid,omitempty"`
	Creator     string     `json:"creator,omitempty"`
	TargetUID   string     `json:"targetUID,omitempty"`
	CreatedAt   *time.Time `json:"createdAt,omitempty"`
	ObservedAt  *time.Time `json:"observedAt,omitempty"`
}

type AttackCatalogDecisionResult struct {
	CatalogueID     string     `json:"catalogueID,omitempty"`
	RunID           string     `json:"runID,omitempty"`
	Family          string     `json:"family,omitempty"`
	Observed        bool       `json:"observed"`
	ID              string     `json:"id,omitempty"`
	EventUID        string     `json:"eventUID,omitempty"`
	TargetUID       string     `json:"targetUID,omitempty"`
	ObservedAt      *time.Time `json:"observedAt,omitempty"`
	Selected        bool       `json:"selected"`
	Feasible        bool       `json:"feasible"`
	Action          string     `json:"action,omitempty"`
	DispatchOutcome string     `json:"dispatchOutcome,omitempty"`
}

type AttackCatalogActuatorResult struct {
	CatalogueID string `json:"catalogueID,omitempty"`
	RunID       string `json:"runID,omitempty"`
	Family      string `json:"family,omitempty"`
	// ReceiptObserved means the adapter bound an accepted actuator receipt to
	// this exact run. An expected action name is never a receipt.
	ReceiptObserved bool       `json:"receiptObserved"`
	DecisionID      string     `json:"decisionID,omitempty"`
	ReceiptID       string     `json:"receiptID,omitempty"`
	Status          string     `json:"status,omitempty"`
	AcceptedAt      *time.Time `json:"acceptedAt,omitempty"`
	Handler         string     `json:"handler,omitempty"`
	ObjectsTouched  []string   `json:"objectsTouched,omitempty"`
}

type AttackCatalogOracleObservation struct {
	Name       string     `json:"name"`
	Before     any        `json:"before"`
	After      any        `json:"after"`
	Passed     bool       `json:"passed"`
	ObservedAt *time.Time `json:"observed_at"`
}

type AttackCatalogPhysicalResult struct {
	CatalogueID  string                           `json:"catalogueID,omitempty"`
	RunID        string                           `json:"runID,omitempty"`
	Family       string                           `json:"family,omitempty"`
	Kind         string                           `json:"kind,omitempty"`
	Validated    bool                             `json:"validated"`
	ObservedAt   *time.Time                       `json:"observedAt,omitempty"`
	Observations []AttackCatalogOracleObservation `json:"observations,omitempty"`
	Oracle       string                           `json:"oracle,omitempty"`
	Evidence     json.RawMessage                  `json:"evidence,omitempty"`
	// AML.T0012's original typed oracle fields remain stable for existing API
	// clients. Other reviewed adapters use Oracle+Evidence and validate that
	// adapter-owned payload before the shared lifecycle can issue DEFENDED.
	OldServiceAccountUID          string `json:"oldServiceAccountUID,omitempty"`
	NewServiceAccountUID          string `json:"newServiceAccountUID,omitempty"`
	CredentialAuthenticatedBefore bool   `json:"credentialAuthenticatedBefore"`
	CredentialAuthenticatedAfter  bool   `json:"credentialAuthenticatedAfter"`
	PodRetained                   bool   `json:"podRetained"`
	PodUID                        string `json:"podUID,omitempty"`
}

type AttackCatalogCleanupResult struct {
	CatalogueID   string `json:"catalogueID,omitempty"`
	RunID         string `json:"runID,omitempty"`
	Family        string `json:"family,omitempty"`
	Attempted     bool   `json:"attempted"`
	EventDeleted  bool   `json:"eventDeleted"`
	MarkerDeleted bool   `json:"markerDeleted"`
	Verified      bool   `json:"verified"`
	// RetrySafe is the authoritative "no run-owned SecurityEvents/artifacts remain
	// and no active mutation persists" signal. It is strictly weaker than Verified:
	// Verified additionally proves the full family cleanup oracle (e.g. the exact
	// prepare-time fixture identity, pod and ReplicaSet UIDs). RetrySafe only clears
	// the single-active-run retry gate and NEVER contributes to a DEFENDED verdict.
	// An environmental Pod rollout can leave a run RetrySafe but not Verified; a
	// fully Verified cleanup is always RetrySafe (see attackCatalogCleanupRetrySafe).
	RetrySafe   bool            `json:"retrySafe,omitempty"`
	CompletedAt *time.Time      `json:"completedAt,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	Evidence    json.RawMessage `json:"evidence,omitempty"`
}

// attackCatalogCleanupRetrySafe reports whether a prior run left the cluster safe
// to launch against again. Full DEFENDED-grade cleanup (Verified) always implies
// retry-safety; the weaker authoritative RetrySafe signal (run-owned artifacts
// absent, active mutations restored, fixture healthy even after an environmental
// Pod rollout) also clears the retry gate without ever asserting DEFENDED.
func attackCatalogCleanupRetrySafe(c AttackCatalogCleanupResult) bool {
	return c.Verified || c.RetrySafe
}

// AttackCatalogResult keeps every claim stage independent. ExpectedAction is
// metadata, never a substitute for any observed field below. ExecutionMode is
// the policy effect mode; TriggerMode is the policy trigger posture. They are
// deliberately separate concepts.
type AttackCatalogResult struct {
	Schema             string                         `json:"schema"`
	EvidenceSchema     string                         `json:"evidenceSchema,omitempty"`
	CatalogueID        string                         `json:"catalogueID"`
	RunID              string                         `json:"runID"`
	Family             string                         `json:"family,omitempty"`
	Visible            bool                           `json:"visible"`
	Available          bool                           `json:"available"`
	Launched           bool                           `json:"launched"`
	ReactiveOnly       bool                           `json:"reactiveOnly"`
	ExecutionMode      AttackCatalogExecutionMode     `json:"executionMode,omitempty"`
	TriggerMode        AttackCatalogTriggerMode       `json:"triggerMode,omitempty"`
	ExpectedAction     string                         `json:"expectedAction"`
	StartedAt          time.Time                      `json:"startedAt"`
	FinishedAt         time.Time                      `json:"finishedAt"`
	Signal             AttackCatalogSignalResult      `json:"signal"`
	Decision           AttackCatalogDecisionResult    `json:"decision"`
	Actuator           AttackCatalogActuatorResult    `json:"actuator"`
	PhysicalValidation AttackCatalogPhysicalResult    `json:"physicalValidation"`
	Cleanup            AttackCatalogCleanupResult     `json:"cleanup"`
	Postflight         *AttackCatalogPostflightResult `json:"postflight,omitempty"`
	Verdict            string                         `json:"verdict"`
	Reason             string                         `json:"reason"`
	UnsafeToRetry      bool                           `json:"unsafeToRetry"`
}

func (r AttackCatalogResult) genericDefendedRequirements() error {
	if r.Schema != attackCatalogResultSchema || strings.TrimSpace(r.CatalogueID) == "" || r.RunID == "" ||
		!r.Visible || !r.Available || !r.Launched || strings.TrimSpace(r.ExpectedAction) == "" ||
		!validAttackCatalogModes(r.ExecutionMode, r.TriggerMode) || r.ReactiveOnly != (r.TriggerMode == AttackCatalogTriggerReactive) {
		return errors.New("visible, available, launched case with explicit execution and trigger modes required")
	}
	if r.ExecutionMode != AttackCatalogExecutionActive {
		return errors.New("active execution mode required for DEFENDED")
	}
	if !r.Signal.Created || !r.Signal.Observed || r.Signal.Name == "" || r.Signal.UID == "" ||
		r.Signal.Creator == "" || r.Signal.TargetUID == "" {
		return errors.New("exact defensive signal observation required")
	}
	if !r.Decision.Observed || r.Decision.ID == "" || !r.Decision.Selected || !r.Decision.Feasible ||
		r.Decision.Action != r.ExpectedAction || r.Decision.DispatchOutcome != "emitted" {
		return errors.New("selected feasible emitted expected-action decision required")
	}
	if !r.Actuator.ReceiptObserved || strings.TrimSpace(r.Actuator.Handler) == "" {
		return errors.New("accepted actuator receipt required")
	}
	if !r.PhysicalValidation.Validated {
		return errors.New("family-specific physical oracle required")
	}
	if !r.Cleanup.Attempted || !r.Cleanup.Verified || r.UnsafeToRetry {
		return errors.New("verified exact postflight required")
	}
	if r.EvidenceSchema != "" {
		if err := r.releaseEvidenceRequirements(); err != nil {
			return err
		}
	}
	return nil
}

func (r AttackCatalogResult) releaseEvidenceRequirements() error {
	if r.EvidenceSchema != attackCatalogEvidenceSchema || r.Family == "" ||
		r.Signal.CatalogueID != r.CatalogueID || r.Signal.RunID != r.RunID ||
		r.Decision.CatalogueID != r.CatalogueID || r.Decision.RunID != r.RunID ||
		r.Actuator.CatalogueID != r.CatalogueID || r.Actuator.RunID != r.RunID ||
		r.PhysicalValidation.CatalogueID != r.CatalogueID || r.PhysicalValidation.RunID != r.RunID ||
		r.Signal.Family != r.Family || r.Decision.Family != r.Family || r.Actuator.Family != r.Family ||
		r.PhysicalValidation.Family != r.Family || r.Cleanup.CatalogueID != r.CatalogueID || r.Cleanup.RunID != r.RunID ||
		r.Cleanup.Family != r.Family {
		return errors.New("immutable run, catalogue and family stage bindings required")
	}
	if r.Signal.CreatedAt == nil || r.Signal.ObservedAt == nil || r.Decision.ObservedAt == nil ||
		r.Actuator.AcceptedAt == nil || r.PhysicalValidation.ObservedAt == nil || r.Cleanup.CompletedAt == nil ||
		!attackCatalogSignalCreationTimeValid(*r.Signal.CreatedAt, r.StartedAt) ||
		r.Signal.ObservedAt.Before(*r.Signal.CreatedAt) || r.Decision.ObservedAt.Before(*r.Signal.ObservedAt) ||
		r.Actuator.AcceptedAt.Before(*r.Decision.ObservedAt) || r.PhysicalValidation.ObservedAt.Before(*r.Actuator.AcceptedAt) ||
		r.Cleanup.CompletedAt.Before(*r.PhysicalValidation.ObservedAt) {
		return errors.New("trusted monotonic stage timestamps required")
	}
	if r.Decision.EventUID != r.Signal.UID || r.Decision.TargetUID != r.Signal.TargetUID ||
		r.Actuator.DecisionID != r.Decision.ID || r.Actuator.ReceiptID != acceptedAttackCatalogReceiptID(r) ||
		r.Actuator.Status != "accepted" {
		return errors.New("exact signal, decision and accepted-receipt bindings required")
	}
	if r.PhysicalValidation.Kind == "" || len(r.PhysicalValidation.Observations) == 0 {
		return errors.New("structured family physical observations required")
	}
	for _, observation := range r.PhysicalValidation.Observations {
		if observation.Name == "" || !observation.Passed || observation.ObservedAt == nil ||
			observation.ObservedAt.After(*r.PhysicalValidation.ObservedAt) {
			return errors.New("complete typed physical observation entries required")
		}
	}
	if r.Postflight == nil || !r.Postflight.Clean || r.Postflight.CatalogueID != r.CatalogueID ||
		r.Postflight.RunID != r.RunID || r.Postflight.Family != r.Family || r.Postflight.EvidenceKind != "runtime-health" ||
		r.Postflight.InventorySHA256 == "" || r.Postflight.CheckedAt.Before(*r.Cleanup.CompletedAt) ||
		r.FinishedAt.Before(r.Postflight.CheckedAt) {
		return errors.New("separate clean postflight inventory and health proof required")
	}
	digest, err := canonicalJSONSHA256(r.Postflight.Inventory)
	if err != nil || digest != r.Postflight.InventorySHA256 {
		return errors.New("postflight inventory hash does not match its typed payload")
	}
	var inventory attackCatalogPostflightInventory
	if json.Unmarshal(r.Postflight.Inventory, &inventory) != nil || inventory.Schema != attackCatalogPostflightSchema ||
		inventory.CatalogueID != r.CatalogueID || inventory.RunID != r.RunID || inventory.Family != r.Family ||
		!inventory.EventDeleted || !inventory.MarkerDeleted || !inventory.Verified {
		return errors.New("postflight typed inventory is incomplete or rebound")
	}
	return nil
}

// Kubernetes creationTimestamp is serialized at whole-second precision while
// the Console run start retains nanoseconds. A signal launched during the run
// can therefore appear fractionally older than StartedAt. Accept only the same
// UTC second (or later); an object from any earlier second remains stale.
func attackCatalogSignalCreationTimeValid(createdAt, startedAt time.Time) bool {
	return !createdAt.Before(startedAt.Truncate(time.Second))
}

func (r AttackCatalogResult) identityDefendedRequirements() error {
	if r.CatalogueID != "AML.T0012" || r.ExpectedAction != "identity-rotate" {
		return errors.New("AML.T0012 identity-rotation case required")
	}
	if r.Actuator.Handler != "identity-rotate" || len(r.Actuator.ObjectsTouched) == 0 {
		return errors.New("identity-rotate actuator receipt required")
	}
	p := r.PhysicalValidation
	if !p.Validated || p.OldServiceAccountUID == "" || p.NewServiceAccountUID == "" ||
		p.OldServiceAccountUID == p.NewServiceAccountUID || !p.CredentialAuthenticatedBefore ||
		p.CredentialAuthenticatedAfter || !p.PodRetained || p.PodUID == "" {
		return errors.New("ServiceAccount UID, credential invalidation and retained Pod oracle required")
	}
	if !r.Cleanup.EventDeleted || !r.Cleanup.MarkerDeleted {
		return errors.New("AML.T0012 event and marker cleanup required")
	}
	return nil
}

func (r AttackCatalogResult) defendedRequirements(adapter AttackCatalogAdapter) error {
	if err := r.genericDefendedRequirements(); err != nil {
		return err
	}
	if adapter == nil || adapter.CatalogueID() != r.CatalogueID {
		return errors.New("exact registered adapter required")
	}
	return adapter.ValidateDefended(r)
}

func (r AttackCatalogResult) withLegacyRuntimeModes() AttackCatalogResult {
	if r.CatalogueID == "AML.T0012" && r.ExecutionMode == "" && r.TriggerMode == "" {
		r.ExecutionMode = AttackCatalogExecutionActive
		r.TriggerMode = AttackCatalogTriggerProactiveReactive
		if r.ReactiveOnly {
			r.TriggerMode = AttackCatalogTriggerReactive
		}
	}
	return r
}

func (r AttackCatalogResult) Validate() error {
	if r.Schema != attackCatalogResultSchema || strings.TrimSpace(r.CatalogueID) == "" || strings.TrimSpace(r.RunID) == "" ||
		r.StartedAt.IsZero() || r.FinishedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) || r.Reason == "" {
		return errors.New("catalogue result envelope is incomplete")
	}
	if (r.ExecutionMode == "") != (r.TriggerMode == "") {
		return errors.New("catalogue runtime modes are incomplete")
	}
	if r.ExecutionMode != "" && !validAttackCatalogModes(r.ExecutionMode, r.TriggerMode) {
		return errors.New("catalogue runtime modes are invalid")
	}
	if r.Verdict == "DEFENDED" {
		validated := r.withLegacyRuntimeModes()
		// Retained AML.T0012 v1 files predate explicit mode fields. The only
		// reviewed execution mode for that adapter was active; ReactiveOnly
		// preserves its trigger posture. New aggregate records never take this
		// compatibility path and require both fields on disk.
		if err := validated.genericDefendedRequirements(); err != nil {
			return fmt.Errorf("DEFENDED is unsupported: %w", err)
		}
		// Preserve strict validation of retained AML.T0012 v1 artifacts. New
		// families receive their additional validation from their registered
		// adapter when the shared lifecycle writes/reads the aggregate record.
		if r.CatalogueID == "AML.T0012" {
			if err := validated.identityDefendedRequirements(); err != nil {
				return fmt.Errorf("DEFENDED is unsupported: %w", err)
			}
		}
	}
	if r.Verdict != "DEFENDED" && r.Verdict != "NOT_DEFENDED" && r.Verdict != "INCONCLUSIVE" && r.Verdict != "ERROR" {
		return fmt.Errorf("unknown catalogue verdict %q", r.Verdict)
	}
	return nil
}

func (r *AttackCatalogResult) finishVerdict(adapter AttackCatalogAdapter, reason string) {
	r.FinishedAt = time.Now().UTC()
	r.Reason = reason
	if err := r.defendedRequirements(adapter); err == nil {
		r.Verdict = "DEFENDED"
		r.Reason = adapter.DefendedReason()
		return
	}
	// Retry-safety is decoupled from the DEFENDED cleanup oracle: a run whose
	// run-owned artifacts are gone and whose active mutations are restored is safe
	// to retry even if the full oracle (exact prepare-time fixture identity) could
	// not be reproven — e.g. after an unrelated Pod rollout.
	if !attackCatalogCleanupRetrySafe(r.Cleanup) {
		r.UnsafeToRetry = true
	}
	if r.Actuator.ReceiptObserved && !r.PhysicalValidation.Validated {
		r.Verdict = "NOT_DEFENDED"
		return
	}
	if r.Launched {
		r.Verdict = "INCONCLUSIVE"
		return
	}
	r.Verdict = "ERROR"
}
