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
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/model"
)

// NoEffectRefusal marks a handler's positively established pre-mutation refusal.
// Callers may consider a different action only when this explicit contract is
// returned and the result carries no effect evidence. Ordinary errors, including
// timeouts and ambiguous API responses, make no such promise.
type NoEffectRefusal struct{ Err error }

func (e NoEffectRefusal) Error() string { return e.Err.Error() }
func (e NoEffectRefusal) Unwrap() error { return e.Err }
func RefusedWithoutEffect(err error) error {
	if err == nil {
		return nil
	}
	return NoEffectRefusal{Err: err}
}
func IsNoEffectRefusal(err error) bool { var e NoEffectRefusal; return errors.As(err, &e) }

// NoEffectDisposition is an actuator's positive statement about a reviewed
// result that emitted no new mutation. Reconciled results may retain protected
// prior-operation references; refused and satisfied results remain clean.
// Empty is deliberately unknown: callers must never infer a refusal from
// Emitted=false, MutationKind, or free-form Note text.
type NoEffectDisposition string

const (
	NoEffectUnknown    NoEffectDisposition = ""
	NoEffectRefused    NoEffectDisposition = "refused"
	NoEffectSatisfied  NoEffectDisposition = "already-satisfied"
	NoEffectReconciled NoEffectDisposition = "reconciled"
	NoEffectDeclared   NoEffectDisposition = "declared-only"
)

// Phorvex-controlled rule vocabulary. Because Phorvex authors BOTH a controlled
// SecurityEvent and the AMTD strategy that matches it, the retained quarantine route
// avoids Phoenix's brittle external-rule matching. These rule
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
	Tenant      string
	Namespace   string
	PolicyName  string
	PolicyUID   string
	Generation  int64
	MatchLabels map[string]string // the AMTD PodSelector (guest list)
	// Selector is the complete policy selector. MatchLabels remains for legacy
	// internal callers; when Selector is supplied it is authoritative.
	Selector       *metav1.LabelSelector
	EnabledActions map[model.Action]bool
	// PolicyOwnerCount is the number of current policy owners for this exact
	// namespace/tenant tuple. More than one makes a shared Phoenix strategy
	// ambiguous and must refuse Phoenix maintenance. Zero is reserved for legacy
	// direct callers without a runner ownership registry.
	PolicyOwnerCount int
}

// PolicyMaintenanceState describes a read-only observation or a completed
// standing-policy reconcile. It never claims that a defense action executed.
type PolicyMaintenanceState string

const (
	PolicyMaintenanceNotRequired      PolicyMaintenanceState = "not-required"
	PolicyMaintenanceInSync           PolicyMaintenanceState = "in-sync"
	PolicyMaintenanceMissing          PolicyMaintenanceState = "missing"
	PolicyMaintenanceDrifted          PolicyMaintenanceState = "drifted"
	PolicyMaintenanceRepaired         PolicyMaintenanceState = "repaired"
	PolicyMaintenanceUnknown          PolicyMaintenanceState = "unknown"
	PolicyMaintenanceOwnershipRefused PolicyMaintenanceState = "ownership-refused"
)

type PolicyRouteMaintenance struct {
	State  PolicyMaintenanceState
	Detail string
}

// PolicyMaintenanceResult is one tick's Phoenix/native standing-policy result.
// Preparation is reusable by selected dispatch in the same tick.
type PolicyMaintenanceResult struct {
	Preparation RoutePreparation
	Phoenix     PolicyRouteMaintenance
	Native      PolicyRouteMaintenance
}

// StandingPolicyMaintainer separates read-only drift observation from
// mutation-capable reconciliation. The runner uses observation whenever a
// brake or owner guard is unavailable or engaged.
type StandingPolicyMaintainer interface {
	ObserveStandingPolicy(ctx context.Context, target TenantTarget) PolicyMaintenanceResult
	ReconcileStandingPolicy(ctx context.Context, target TenantTarget) PolicyMaintenanceResult
}

// Request is one actuation: perform Action on Namespace/Pod for Tenant.
type Request struct {
	AdapterObservation       *model.AdapterObservation         // selection-time detector assertion; runtime rechecks event
	OutputPolicyObservation  *model.SensitiveOutputObservation // selection-time exact response-field authority
	VoiceMemoryObservation   *model.VoiceMemoryObservation     // selection-time exact caller/note digest authority
	VoiceRefundObservation   *model.VoiceRefundObservation     // selection-time asserted caller/order pair authority
	VoiceMCPObservation      *model.VoiceMCPObservation        // selection-time installed Voice/MCP source authority
	VoiceOutputObservation   *model.VoiceOutputObservation     // selection-time observed synthetic output marker
	LiteLLMClientObservation *model.LiteLLMClientObservation   // selection-time owned-client gateway authority
	TargetUID                string                            // Bound identity from the selecting snapshot.
	TargetNamespaceUID       string                            // Bound by the protected quarantine-capacity reservation.
	OperationID              string                            // Stable decision identity for protected quarantine and route operations.
	TickID                   string                            // Real selection tick; protected serving operation IDs are recomputed from it.
	ServingObservation       *ServingSelectionObservation
	PolicyName               string // Selecting PhorvexPolicy identity for recoverable native operations.
	PolicyUID                string
	PolicyGeneration         int64
	// MaxGracePeriodSeconds is the selecting policy's resolved native rotate
	// cap. The native handler re-reads and matches it at the mutation boundary.
	// Zero is invalid and never means force deletion.
	MaxGracePeriodSeconds int64

	Tenant    string
	Namespace string
	Pod       string
	Action    model.Action
	Reason    string
	Score     float64 // genuine anomaly score in [0,1] (<0 = unscored)
	// CoverageValue is an optional raw selection-time sum of recon fact weights.
	// Presence takes precedence over Score, including invalid coverage values.
	CoverageValue *float64
}

// ServingSelectionObservation is the presence-aware metadata snapshot selected
// by the runner. It is compared with a fresh exact-UID Pod before a protected
// serving receipt may dispatch.
type ServingSelectionObservation struct {
	KVReset, KVMigrate, KVLocalEffect, Guardrail model.OwnedValue
}

// Result records observed effect provenance (used by the audit log + integration proof). The
// Phoenix-path fields (AMTDName/EventName/RuleType/RuleThreatLevel/RuleSource) are empty
// for the native actuator; the neutral fields (Handler/ObjectsTouched/RollbackRef/
// MutationKind) carry native effects. Emitted may also accompany an error when an effect
// was confirmed but later bookkeeping failed; completion requires coherent outcome and
// error handling at the runner boundary.
type Result struct {
	Note string
	// NoEffect is set only when a reviewed, non-emitted result positively proves
	// why no new mutation occurred. Contradictory result evidence invalidates it
	// at the runner boundary and leaves the outcome unknown; reconciled results
	// may retain protected references from the prior operation they observed.
	NoEffect NoEffectDisposition

	Actuator  string
	AMTDName  string
	EventName string
	// EventUID is the server-assigned UID of the created SecurityEvent, read from the
	// SAME successful Create response that supplies EventName — no extra read, no extra
	// RBAC (M-18). It is the only identity that distinguishes a recreated same-name
	// object from the original. Empty when the create failed or the actuator has no
	// server-acknowledged object; never synthesized.
	EventUID        string
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
	// MutationKind is "reversible" | "irreversible" | "forward-only" | "swap" | "declared" | "partial".
	MutationKind string
	// GracefulTermination is the exact acknowledged native rotate request. It
	// never claims the old process exited or a replacement became ready.
	GracefulTermination *model.GracefulTerminationReceipt
	DrainOperation      *model.DrainOperationEvidence
}

// Target is the per-asset context the capability gate (T1-E) passes to SupportsAction.
// It carries exactly the TARGET-LOCAL facts an actuator needs to answer "can I run this
// action on THIS pod?" (labels, annotations, node, GPU) — no fleet/pool state, which the
// capability layer precomputes once per tick and checks itself (R1).
type Target struct {
	Namespace      string
	Pod            string
	UID            string
	Labels         map[string]string
	NodeName       string
	HasGPU         bool
	MIGResource    string
	PolicyName     string
	PolicyUID      string
	ServiceAccount string
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
