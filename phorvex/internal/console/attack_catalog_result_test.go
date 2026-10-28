package console

import (
	"testing"
	"time"
)

func defendedAttackCatalogResult() AttackCatalogResult {
	now := time.Now().UTC()
	return AttackCatalogResult{Schema: attackCatalogResultSchema, CatalogueID: "AML.T0012", RunID: "cat-1",
		Visible: true, Available: true, Launched: true, ExpectedAction: "identity-rotate", StartedAt: now, FinishedAt: now,
		Signal:             AttackCatalogSignalResult{Created: true, Observed: true, Name: "event", UID: "event-uid", Creator: "creator", TargetUID: "pod-uid"},
		Decision:           AttackCatalogDecisionResult{Observed: true, ID: "decision", Selected: true, Feasible: true, Action: "identity-rotate", DispatchOutcome: "emitted"},
		Actuator:           AttackCatalogActuatorResult{ReceiptObserved: true, Handler: "identity-rotate", ObjectsTouched: []string{"ServiceAccount/ns/sa"}},
		PhysicalValidation: AttackCatalogPhysicalResult{Validated: true, OldServiceAccountUID: "old", NewServiceAccountUID: "new", CredentialAuthenticatedBefore: true, CredentialAuthenticatedAfter: false, PodRetained: true, PodUID: "pod-uid"},
		Cleanup:            AttackCatalogCleanupResult{Attempted: true, EventDeleted: true, MarkerDeleted: true, Verified: true},
		Verdict:            "DEFENDED", Reason: "all exact oracles passed"}
}

func TestAttackCatalogDefendedRequiresEveryIndependentOracle(t *testing.T) {
	base := defendedAttackCatalogResult()
	if err := base.Validate(); err != nil {
		t.Fatalf("complete result rejected: %v", err)
	}
	tests := map[string]func(*AttackCatalogResult){
		"not launched":                   func(r *AttackCatalogResult) { r.Launched = false },
		"event creation only":            func(r *AttackCatalogResult) { r.Signal.Observed = false },
		"decision absent":                func(r *AttackCatalogResult) { r.Decision.Observed = false },
		"decision unselected":            func(r *AttackCatalogResult) { r.Decision.Selected = false },
		"actuator receipt absent":        func(r *AttackCatalogResult) { r.Actuator.ReceiptObserved = false },
		"credential still authenticates": func(r *AttackCatalogResult) { r.PhysicalValidation.CredentialAuthenticatedAfter = true },
		"ServiceAccount did not rotate":  func(r *AttackCatalogResult) { r.PhysicalValidation.NewServiceAccountUID = "old" },
		"Pod not retained":               func(r *AttackCatalogResult) { r.PhysicalValidation.PodRetained = false },
		"cleanup unverified":             func(r *AttackCatalogResult) { r.Cleanup.Verified = false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			got := base
			mutate(&got)
			if err := got.Validate(); err == nil {
				t.Fatal("incomplete result retained DEFENDED")
			}
		})
	}
}
