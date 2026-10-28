package console

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const attackCatalogResultSchema = "phorvex.attack-catalogue-result.v1"

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
	ReceiptObserved bool     `json:"receiptObserved"`
	Handler         string   `json:"handler,omitempty"`
	ObjectsTouched  []string `json:"objectsTouched,omitempty"`
}

type AttackCatalogPhysicalResult struct {
	Validated                     bool   `json:"validated"`
	OldServiceAccountUID          string `json:"oldServiceAccountUID,omitempty"`
	NewServiceAccountUID          string `json:"newServiceAccountUID,omitempty"`
	CredentialAuthenticatedBefore bool   `json:"credentialAuthenticatedBefore"`
	CredentialAuthenticatedAfter  bool   `json:"credentialAuthenticatedAfter"`
	PodRetained                   bool   `json:"podRetained"`
	PodUID                        string `json:"podUID,omitempty"`
}

type AttackCatalogCleanupResult struct {
	Attempted     bool   `json:"attempted"`
	EventDeleted  bool   `json:"eventDeleted"`
	MarkerDeleted bool   `json:"markerDeleted"`
	Verified      bool   `json:"verified"`
	Reason        string `json:"reason,omitempty"`
}

// AttackCatalogResult keeps every claim stage independent. ExpectedAction is metadata, never a
// substitute for any observed field below.
type AttackCatalogResult struct {
	Schema             string                      `json:"schema"`
	CatalogueID        string                      `json:"catalogueID"`
	RunID              string                      `json:"runID"`
	Visible            bool                        `json:"visible"`
	Available          bool                        `json:"available"`
	Launched           bool                        `json:"launched"`
	ReactiveOnly       bool                        `json:"reactiveOnly"`
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

func (r AttackCatalogResult) defendedRequirements() error {
	if r.Schema != attackCatalogResultSchema || r.CatalogueID != "AML.T0012" || r.RunID == "" ||
		!r.Visible || !r.Available || !r.Launched || r.ExpectedAction != "identity-rotate" {
		return errors.New("visible, available and launched identity-rotation case required")
	}
	if !r.Signal.Created || !r.Signal.Observed || r.Signal.Name == "" || r.Signal.UID == "" ||
		r.Signal.Creator == "" || r.Signal.TargetUID == "" {
		return errors.New("exact defensive signal observation required")
	}
	if !r.Decision.Observed || r.Decision.ID == "" || !r.Decision.Selected || !r.Decision.Feasible ||
		r.Decision.Action != "identity-rotate" || r.Decision.DispatchOutcome != "emitted" {
		return errors.New("selected feasible emitted identity-rotate decision required")
	}
	if !r.Actuator.ReceiptObserved || r.Actuator.Handler != "identity-rotate" || len(r.Actuator.ObjectsTouched) == 0 {
		return errors.New("identity-rotate actuator receipt required")
	}
	p := r.PhysicalValidation
	if !p.Validated || p.OldServiceAccountUID == "" || p.NewServiceAccountUID == "" ||
		p.OldServiceAccountUID == p.NewServiceAccountUID || !p.CredentialAuthenticatedBefore ||
		p.CredentialAuthenticatedAfter || !p.PodRetained || p.PodUID == "" {
		return errors.New("ServiceAccount UID, credential invalidation and retained Pod oracle required")
	}
	if !r.Cleanup.Attempted || !r.Cleanup.EventDeleted || !r.Cleanup.MarkerDeleted || !r.Cleanup.Verified || r.UnsafeToRetry {
		return errors.New("clean exact postflight required")
	}
	return nil
}

func (r AttackCatalogResult) Validate() error {
	if r.Schema != attackCatalogResultSchema || strings.TrimSpace(r.RunID) == "" || r.StartedAt.IsZero() ||
		r.FinishedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) || r.Reason == "" {
		return errors.New("catalogue result envelope is incomplete")
	}
	if r.Verdict == "DEFENDED" {
		if err := r.defendedRequirements(); err != nil {
			return fmt.Errorf("DEFENDED is unsupported: %w", err)
		}
	}
	if r.Verdict != "DEFENDED" && r.Verdict != "NOT_DEFENDED" && r.Verdict != "INCONCLUSIVE" && r.Verdict != "ERROR" {
		return fmt.Errorf("unknown catalogue verdict %q", r.Verdict)
	}
	return nil
}

func (r *AttackCatalogResult) finishVerdict(reason string) {
	r.FinishedAt = time.Now().UTC()
	r.Reason = reason
	if err := r.defendedRequirements(); err == nil {
		r.Verdict = "DEFENDED"
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
