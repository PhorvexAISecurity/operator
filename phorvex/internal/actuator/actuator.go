/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package actuator is the ACTUATOR interface behind which Phorvex's "hands" live
// (PRD §6 / NFR5): PhoenixActuator (Phase 1, Seam 1 — emit SecurityEvent + maintain
// an AMTD strategy so UNMODIFIED Phoenix performs the move) and NativeActuator
// (Phase 2 — Phorvex actuates directly; STUBBED, deliberately not implemented). The
// decision engine depends ONLY on this interface, so the Phase-2 native path drops
// in without touching the brain.
package actuator

import (
	"context"

	"github.com/phorvex/phorvex/internal/model"
)

// Phorvex-controlled rule vocabulary. Because Phorvex authors BOTH the SecurityEvent
// and the AMTD strategy that matches it, it bypasses Phoenix's brittle exact-match
// problem entirely and drives any action deterministically (PRD §4.3). These rule
// fields are Phorvex-private (Source=PhorvexController) so they never collide with a
// real integrator's events.
const (
	// RuleSource marks an event as authored by Phorvex's controller.
	RuleSource = "PhorvexController"
	// RuleThreatLevel is the canonical level Phorvex emits at (Phoenix vocabulary).
	RuleThreatLevel = "high"
	// RuleTypeRotate is the Phorvex-private rule type mapped to Phoenix Delete.
	RuleTypeRotate = "phorvex.rotate"
	// RuleTypeQuarantine is the Phorvex-private rule type mapped to Phoenix Quarantine.
	RuleTypeQuarantine = "phorvex.quarantine"
)

// TenantTarget describes one tenant's protected workloads for AMTD maintenance.
type TenantTarget struct {
	Tenant         string
	Namespace      string
	MatchLabels    map[string]string // the AMTD PodSelector (guest list)
	EnabledActions map[model.Action]bool
}

// Request is one actuation: perform Action on Namespace/Pod for Tenant.
type Request struct {
	Tenant    string
	Namespace string
	Pod       string
	Action    model.Action
	Reason    string
	Score     float64 // optional anomaly score in [0,1] (<0 = unscored)
}

// Result records what was emitted (used by the audit log + integration proof). The
// Phoenix-path fields (AMTDName/EventName/RuleType/RuleThreatLevel/RuleSource) are empty
// for the native actuator; the neutral fields (Handler/ObjectsTouched/RollbackRef/
// MutationKind) carry native effects. Emitted is the universal success flag the runner
// checks at the actuate boundary, regardless of actuator.
type Result struct {
	Actuator        string
	AMTDName        string
	EventName       string
	RuleType        string
	RuleThreatLevel string
	RuleSource      string
	Emitted         bool

	// --- P-ACTUATOR native-actuator neutral fields ---
	// Handler is the action the native handler enacted (= req.Action).
	Handler string
	// ObjectsTouched lists the cluster objects the handler created/mutated/deleted
	// (for the per-action audit + the live-enactment proof).
	ObjectsTouched []string
	// RollbackRef is an opaque token a Rollbacker uses for compensating undo ("" = none).
	RollbackRef string
	// MutationKind is "reversible" | "irreversible" | "forward-only" | "swap" | "declared".
	MutationKind string
}

// Actuator is the swappable hands behind the brain.
type Actuator interface {
	Name() string
	// EnsurePolicy idempotently maintains the Phoenix-side policy (the AMTD whose
	// strategy maps Phorvex's controlled rules to actions) for one tenant. A no-op
	// for actuators that do not need a standing policy.
	EnsurePolicy(ctx context.Context, target TenantTarget) error
	// Actuate performs the requested move. Implementations MUST be safe to call only
	// in active mode; the decision engine never calls Actuate in dryRun.
	Actuate(ctx context.Context, req Request) (Result, error)
}

// RuleTypeFor maps a Phorvex action to its controlled SecurityEvent rule type.
func RuleTypeFor(a model.Action) string {
	switch a {
	case model.ActionRotate:
		return RuleTypeRotate
	case model.ActionQuarantine:
		return RuleTypeQuarantine
	default:
		return ""
	}
}
