// Package actuatorapi is the contract between the dispatcher and the actuator
// (ADR-0001): what the dispatcher asks the actuator before and while it acts, and
// the values that cross between them. The actuator is the only service that
// writes to workloads; every live re-read before a mutation stays inside it.
// internal/actuatorsvc implements the contract in process, and over gRPC once
// the actuator runs as its own service.
package actuatorapi

import (
	"context"

	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/model"
)

// Actuator is the actuator service as the dispatcher sees it.
type Actuator interface {
	// Backend names the configured backend.
	Backend() Backend
	// RequiredVerbs lists the access the backend needs to dispatch action a.
	RequiredVerbs(a model.Action) []authz.Verb

	// SupportsAction reports whether the runtime fixtures for action a are present
	// on target t. Some answers read the cluster or probe the workload.
	SupportsAction(ctx context.Context, a model.Action, t Target) (ok bool, why string)
	// CapabilityAdvisory reports local configuration posture for a on t. It
	// performs no read.
	CapabilityAdvisory(a model.Action, t Target) string

	// MaintainsStandingPolicy reports whether the backend keeps standing route
	// policy, observed or reconciled every policy tick.
	MaintainsStandingPolicy() bool
	// ObserveStandingPolicy reports route drift without changing anything.
	ObserveStandingPolicy(ctx context.Context, target TenantTarget) PolicyMaintenanceResult
	// ReconcileStandingPolicy repairs route drift.
	ReconcileStandingPolicy(ctx context.Context, target TenantTarget) PolicyMaintenanceResult
	// PrepareRoutes prepares dispatch routes for a backend without standing-policy
	// maintenance. A non-nil error refuses every dispatch of the tick.
	PrepareRoutes(ctx context.Context, target TenantTarget) (RoutePreparation, error)
	// RetirePolicyBinding forgets a removed policy's local authorization and reports
	// whether the backend keeps such bindings.
	RetirePolicyBinding(policyUID string) bool

	// RecoverOperations runs journal-driven operation maintenance. supported is
	// false when the backend keeps no operation journals.
	RecoverOperations(ctx context.Context, globalKill bool) (events []RecoveryEvent, supported bool, err error)
	// QuarantineCapacity reports a namespace's retained-quarantine capacity.
	QuarantineCapacity(ctx context.Context, namespace string) QuarantineCapacity
	// PendingOperation reports whether a protected operation of the given kind is
	// unresolved for the Pod, which fences any other dispatch to it.
	PendingOperation(ctx context.Context, query PendingOperation) (bool, error)

	// Actuate performs one move. invoked is false when the actuator refused it
	// before reaching the backend (for example for quarantine capacity), so no
	// effect can have occurred.
	Actuate(ctx context.Context, req Request) (result Result, invoked bool, err error)
}

// QuarantineCapacity is a namespace's retained-quarantine capacity.
type QuarantineCapacity struct {
	// Configured is false when no namespace bound is configured; nothing else is set.
	Configured bool
	Limit      int
	// Known is false when the inventory could not be read; Reason says why.
	Known  bool
	Used   int
	Reason string
}

// PendingKind names a family of protected operations with its own journal.
type PendingKind string

const (
	PendingEndpointLease  PendingKind = "endpoint-lease"
	PendingLiteLLMClient  PendingKind = "litellm-client"
	PendingVoiceAdmission PendingKind = "voice-admission"
	PendingVoiceOutput    PendingKind = "voice-output"
	PendingOutputPolicy   PendingKind = "output-policy"
)

// PendingOperation asks whether an operation of Kind is unresolved for one Pod.
type PendingOperation struct {
	Kind      PendingKind
	Namespace string
	Pod       string
	PodUID    string
}
