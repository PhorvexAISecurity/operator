package actuatorapi

import (
	"errors"
	"fmt"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
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

// Request is one actuation: perform Action on Namespace/Pod for Tenant.
type Request struct {
	AdapterObservation        *model.AdapterObservation         // selection-time detector assertion; runtime rechecks event
	OutputPolicyObservation   *model.SensitiveOutputObservation // selection-time exact response-field authority
	VoiceMemoryObservation    *model.VoiceMemoryObservation     // selection-time exact caller/note digest authority
	VoiceRefundObservation    *model.VoiceRefundObservation     // selection-time asserted caller/order pair authority
	VoiceMCPObservation       *model.VoiceMCPObservation        // selection-time installed Voice/MCP source authority
	VoiceAdmissionObservation *model.VoiceAdmissionObservation
	VoiceOutputObservation    *model.VoiceOutputObservation   // selection-time observed synthetic output marker
	LiteLLMClientObservation  *model.LiteLLMClientObservation // selection-time owned-client gateway authority
	CRMRefundObservation      *model.CRMRefundObservation     // selection-time CRM deny-guard + abused-order authority
	EndpointLeaseObservation  *model.EndpointLeaseObservation // selection-time accepted caller lease reuse authority
	// IdentityRotationObservation + PodBoundKubeAPIAuth are the selection-time dedicated-SA
	// theft authority for identity-rotate. The native handler rechecks both against the live
	// cluster (identityAuthority) before any ServiceAccount mutation.
	IdentityRotationObservation *model.IdentityRotationObservation
	PodBoundKubeAPIAuth         *model.PodBoundKubeAPIAuthProjection
	// PersistenceObservation is the selection-time, controller-UID-bound trusted
	// persistence authority for controller-stop. The native handler rechecks it against
	// the live cluster (validateControllerStop) before any owner scale/child deletion.
	PersistenceObservation *model.PersistenceFootholdObservation
	TargetUID              string // Bound identity from the selecting snapshot.
	TargetNamespaceUID     string // Bound by the protected quarantine-capacity reservation.
	OperationID            string // Stable decision identity for protected quarantine and route operations.
	TickID                 string // Real selection tick; protected serving operation IDs are recomputed from it.
	ServingObservation     *ServingSelectionObservation
	PolicyName             string // Selecting PhorvexPolicy identity for recoverable native operations.
	PolicyUID              string
	PolicyGeneration       int64
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
	// ControllerStop is the bounded native absence receipt for controller-stop. It
	// rides the CBOR wire (wire.Encode/Decode) back to the manager unchanged; it
	// records only a bounded no-recreation window, never permanent erasure.
	ControllerStop *model.ControllerStopReceipt
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

// RuleTypeFor maps a Phorvex action to its controlled SecurityEvent rule type.
func RuleTypeFor(a model.Action) string {
	switch a {
	case model.ActionRotate:
		return amtdv1beta1.PhorvexRuleTypeRotate
	case model.ActionQuarantine:
		return amtdv1beta1.PhorvexRuleTypeQuarantine
	default:
		return ""
	}
}

// RoutePreparation is local to one runner preparation call. It cannot retain a
// refusal from another policy, namespace, generation, or tick.
type RoutePreparation struct {
	PhoenixErr     error
	NativeErr      error
	PhoenixSkipped bool
	NativeSkipped  bool
}

// ForAction reports the preparation result for the route backend b dispatches
// this action on. The caller must check it before attempting Actuate. The route
// is backend b's own: a native backend prepares no Phoenix route and needs none.
func (p RoutePreparation) ForAction(b Backend, a model.Action) error {
	if RouteFor(b, a) == BackendPhoenix {
		if p.PhoenixSkipped {
			return fmt.Errorf("Phoenix route was not prepared for action %q", a)
		}
		return p.PhoenixErr
	}
	if p.NativeSkipped {
		return fmt.Errorf("native route was not prepared for action %q", a)
	}
	return p.NativeErr
}

// Backend names an actuator implementation a deployment may select.
type Backend string

const (
	// BackendPhoenix drives UNMODIFIED Phoenix through SecurityEvent + AMTD CRs.
	BackendPhoenix Backend = "phoenix"
	// BackendNative enacts directly through client-go (Phorvex's own hands).
	BackendNative Backend = "native"
	// BackendHybrid routes each action to whichever of the two actually implements it.
	BackendHybrid Backend = "hybrid"
)

// RouteFor reports which backend would actually receive a dispatch of action a under
// backend b. For hybrid it is the SAME predicate HybridActuator.Actuate routes on — never
// a union of both backends and never a fallback to the other one.
func RouteFor(b Backend, a model.Action) Backend {
	if b != BackendHybrid {
		return b
	}
	// Hybrid owns a native client-go path that can enforce the current-policy
	// grace contract. Pure Phoenix cannot, so bounded rotate is routed native.
	if a != model.ActionRotate && a != model.ActionVoiceMemoryNoteRevoke && RuleTypeFor(a) != "" {
		return BackendPhoenix
	}
	return BackendNative
}

// Rejection reasons. These are the SHARED vocabulary: SupportsAction returns them, the
// capability gate records them as its exclusion detail, and the ActionsSupported message
// renders them, so a condition and a decision record can never disagree about why.
const (
	// ReasonBackendUnsupported: the SELECTED backend does not implement the action.
	ReasonBackendUnsupported = "backend-unsupported"
	// ReasonBackendUnavailable: no backend is wired, so nothing can establish support.
	ReasonBackendUnavailable = "backend-unavailable"
	// ReasonTransportUnwired: the backend implements the action but a runtime transport
	// prerequisite is absent (M-79 node-exec). Retained verbatim from the pre-M-21 code.
	ReasonTransportUnwired = "transport-unwired"
	// ReasonParallelGroupUnavailable is the stable capability and dispatch reason for
	// grouped model-shard replacement until a trusted distributed-readiness witness,
	// atomic activation, and controller-owned replenishment protocol exist.
	ReasonParallelGroupUnavailable = "parallel-group-unavailable: distributed readiness, atomic activation and replenishment are unverified"
)

// RecoveryEvent describes one administrative attempt, including refusals and partial effects.
type RecoveryEvent struct {
	Receipt, Kind, Phase, Tenant, PolicyNamespace, PolicyName, PolicyUID, TargetName, TargetUID, Outcome, Effect string
	Err                                                                                                          error
}
