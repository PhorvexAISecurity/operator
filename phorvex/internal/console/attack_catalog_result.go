package console

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const attackCatalogResultSchema = "phorvex.attack-catalogue-result.v1"

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
	Created   bool   `json:"created"`
	Observed  bool   `json:"observed"`
	Name      string `json:"name,omitempty"`
	UID       string `json:"uid,omitempty"`
	Creator   string `json:"creator,omitempty"`
	TargetUID string `json:"targetUID,omitempty"`
}

type AttackCatalogDecisionResult struct {
	Observed        bool   `json:"observed"`
	ID              string `json:"id,omitempty"`
	Selected        bool   `json:"selected"`
	Feasible        bool   `json:"feasible"`
	Action          string `json:"action,omitempty"`
	DispatchOutcome string `json:"dispatchOutcome,omitempty"`
}

type AttackCatalogActuatorResult struct {
	// ReceiptObserved means the adapter bound an accepted actuator receipt to
	// this exact run. An expected action name is never a receipt.
	ReceiptObserved bool     `json:"receiptObserved"`
	Handler         string   `json:"handler,omitempty"`
	ObjectsTouched  []string `json:"objectsTouched,omitempty"`
}

type AttackCatalogPhysicalResult struct {
	Validated bool            `json:"validated"`
	Oracle    string          `json:"oracle,omitempty"`
	Evidence  json.RawMessage `json:"evidence,omitempty"`
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
	Attempted     bool            `json:"attempted"`
	EventDeleted  bool            `json:"eventDeleted"`
	MarkerDeleted bool            `json:"markerDeleted"`
	Verified      bool            `json:"verified"`
	Reason        string          `json:"reason,omitempty"`
	Evidence      json.RawMessage `json:"evidence,omitempty"`
}

// AttackCatalogResult keeps every claim stage independent. ExpectedAction is
// metadata, never a substitute for any observed field below. ExecutionMode is
// the policy effect mode; TriggerMode is the policy trigger posture. They are
// deliberately separate concepts.
type AttackCatalogResult struct {
	Schema             string                      `json:"schema"`
	CatalogueID        string                      `json:"catalogueID"`
	RunID              string                      `json:"runID"`
	Visible            bool                        `json:"visible"`
	Available          bool                        `json:"available"`
	Launched           bool                        `json:"launched"`
	ReactiveOnly       bool                        `json:"reactiveOnly"`
	ExecutionMode      AttackCatalogExecutionMode  `json:"executionMode,omitempty"`
	TriggerMode        AttackCatalogTriggerMode    `json:"triggerMode,omitempty"`
	ExpectedAction     string                      `json:"expectedAction"`
	StartedAt          time.Time                   `json:"startedAt"`
	FinishedAt         time.Time                   `json:"finishedAt"`
	Signal             AttackCatalogSignalResult   `json:"signal"`
	Decision           AttackCatalogDecisionResult `json:"decision"`
	Actuator           AttackCatalogActuatorResult `json:"actuator"`
	PhysicalValidation AttackCatalogPhysicalResult `json:"physicalValidation"`
	Cleanup            AttackCatalogCleanupResult  `json:"cleanup"`
	Verdict            string                      `json:"verdict"`
	Reason             string                      `json:"reason"`
	UnsafeToRetry      bool                        `json:"unsafeToRetry"`
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
	return nil
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
	if !r.Cleanup.Verified {
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
