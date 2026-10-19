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

	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/model"
)

// The dispatcher-actuator contract types live in internal/actuatorapi (ADR-0001);
// these aliases keep the actuator's own code unchanged.
type (
	NoEffectRefusal             = actuatorapi.NoEffectRefusal
	NoEffectDisposition         = actuatorapi.NoEffectDisposition
	TenantTarget                = actuatorapi.TenantTarget
	PolicyMaintenanceState      = actuatorapi.PolicyMaintenanceState
	PolicyRouteMaintenance      = actuatorapi.PolicyRouteMaintenance
	PolicyMaintenanceResult     = actuatorapi.PolicyMaintenanceResult
	Request                     = actuatorapi.Request
	ServingSelectionObservation = actuatorapi.ServingSelectionObservation
	Result                      = actuatorapi.Result
	Target                      = actuatorapi.Target
)

const (
	NoEffectUnknown    = actuatorapi.NoEffectUnknown
	NoEffectRefused    = actuatorapi.NoEffectRefused
	NoEffectSatisfied  = actuatorapi.NoEffectSatisfied
	NoEffectReconciled = actuatorapi.NoEffectReconciled
	NoEffectDeclared   = actuatorapi.NoEffectDeclared

	PolicyMaintenanceNotRequired      = actuatorapi.PolicyMaintenanceNotRequired
	PolicyMaintenanceInSync           = actuatorapi.PolicyMaintenanceInSync
	PolicyMaintenanceMissing          = actuatorapi.PolicyMaintenanceMissing
	PolicyMaintenanceDrifted          = actuatorapi.PolicyMaintenanceDrifted
	PolicyMaintenanceRepaired         = actuatorapi.PolicyMaintenanceRepaired
	PolicyMaintenanceUnknown          = actuatorapi.PolicyMaintenanceUnknown
	PolicyMaintenanceOwnershipRefused = actuatorapi.PolicyMaintenanceOwnershipRefused
)

// RefusedWithoutEffect marks err as a positively established pre-mutation refusal.
func RefusedWithoutEffect(err error) error { return actuatorapi.RefusedWithoutEffect(err) }

// IsNoEffectRefusal reports whether err is a NoEffectRefusal.
func IsNoEffectRefusal(err error) bool { return actuatorapi.IsNoEffectRefusal(err) }

// RuleTypeFor maps a Phorvex action to its controlled SecurityEvent rule type.
func RuleTypeFor(a model.Action) string { return actuatorapi.RuleTypeFor(a) }

// StandingPolicyMaintainer separates read-only drift observation from
// mutation-capable reconciliation. The runner uses observation whenever a
// brake or owner guard is unavailable or engaged.
type StandingPolicyMaintainer interface {
	ObserveStandingPolicy(ctx context.Context, target TenantTarget) PolicyMaintenanceResult
	ReconcileStandingPolicy(ctx context.Context, target TenantTarget) PolicyMaintenanceResult
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
	// SupportsAction reports whether the runtime fixtures for action a are present on
	// target t (T1-E capability gate, evaluated BEFORE scoring). ok=false excludes the
	// action with why as the record detail (e.g. "no-guardrail-labels",
	// "transport-unwired"). It answers TARGET-LOCAL predicates only; pool/namespace
	// predicates are the capability layer's job. A stub that cannot yet verify a
	// fixture MUST return ok=true with why prefixed "unverified: " (never a silent
	// false), so an unverified capability can never masquerade as a checked one (P-08).
	SupportsAction(ctx context.Context, a model.Action, t Target) (ok bool, why string)
}

// PolicyBindingLifecycle is the optional owner-lifecycle seam for actuators that
// retain local policy authorization. Manager invokes it only when an exact policy
// UID has reached the serialized lifecycle-drain boundary.
type PolicyBindingLifecycle interface {
	RetirePolicyBinding(policyUID string)
}
