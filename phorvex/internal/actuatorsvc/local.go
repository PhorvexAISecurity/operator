// Package actuatorsvc serves the actuatorapi contract from an actuator backend.
// Local runs in the caller's process; the actuator service's gRPC server serves
// the same adapter, so both paths share one implementation of the contract.
package actuatorsvc

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/model"
)

// Local adapts an actuator backend, its quarantine-capacity ledger and its
// journals to actuatorapi.Actuator. The backend's optional capabilities (standing
// policy, policy bindings, operation recovery, route preparation, advisories)
// are discovered the way the runner discovered them, by interface.
type Local struct {
	// Actuator is the backend that enacts moves. It must not be nil.
	Actuator actuator.Actuator
	// Capacity bounds retained quarantines per namespace; nil means unbounded.
	Capacity *actuator.QuarantineCapacity
	// Reader is the uncached reader the protected-operation journals are read
	// through, in OperatorNamespace.
	Reader            client.Reader
	OperatorNamespace string
	// Access reviews this process's identity, the one the backend acts as; nil
	// reviews nothing.
	Access *authz.Checker
}

var _ actuatorapi.Actuator = (*Local)(nil)

func (l *Local) Backend() actuatorapi.Backend { return actuatorapi.Backend(l.Actuator.Name()) }

// RequiredVerbs follows the backend that dispatches the action. A backend whose
// name is not a production backend (a test double) is treated as hybrid.
func (l *Local) RequiredVerbs(a model.Action) []authz.Verb {
	backend := actuator.BackendHybrid
	for _, candidate := range actuator.Backends() {
		if l.Actuator.Name() == string(candidate) {
			backend = candidate
			break
		}
	}
	return actuator.RequiredVerbsForBackend(backend, a)
}

func (l *Local) SupportsAction(ctx context.Context, a model.Action, t actuatorapi.Target) (bool, string) {
	return l.Actuator.SupportsAction(ctx, a, t)
}

func (l *Local) CapabilityAdvisory(_ context.Context, a model.Action, t actuatorapi.Target) string {
	advisory, ok := l.Actuator.(interface {
		CapabilityAdvisory(model.Action, actuator.Target) string
	})
	if !ok {
		return ""
	}
	return advisory.CapabilityAdvisory(a, t)
}

func (l *Local) ReviewsAccess() bool { return l.Access != nil }

func (l *Local) AccessAllowed(ctx context.Context, namespace string, verbs []authz.Verb) (bool, bool, string) {
	return l.Access.Allowed(ctx, namespace, verbs)
}

func (l *Local) AccessObserved(_ context.Context, namespace string, verbs []authz.Verb) (bool, bool, string) {
	return l.Access.Observed(namespace, verbs)
}

func (l *Local) MaintainsStandingPolicy() bool {
	_, ok := l.Actuator.(actuator.StandingPolicyMaintainer)
	return ok
}

func (l *Local) ObserveStandingPolicy(ctx context.Context, target actuatorapi.TenantTarget) actuatorapi.PolicyMaintenanceResult {
	maintainer, ok := l.Actuator.(actuator.StandingPolicyMaintainer)
	if !ok {
		return actuatorapi.PolicyMaintenanceResult{}
	}
	return maintainer.ObserveStandingPolicy(ctx, target)
}

func (l *Local) ReconcileStandingPolicy(ctx context.Context, target actuatorapi.TenantTarget) actuatorapi.PolicyMaintenanceResult {
	maintainer, ok := l.Actuator.(actuator.StandingPolicyMaintainer)
	if !ok {
		return actuatorapi.PolicyMaintenanceResult{}
	}
	return maintainer.ReconcileStandingPolicy(ctx, target)
}

// PrepareRoutes prepares both routes when the backend can, else maintains its
// policy with EnsurePolicy, whose failure refuses the tick.
func (l *Local) PrepareRoutes(ctx context.Context, target actuatorapi.TenantTarget) (actuatorapi.RoutePreparation, error) {
	if routed, ok := l.Actuator.(interface {
		PrepareRoutes(context.Context, actuator.TenantTarget) actuator.RoutePreparation
	}); ok {
		return routed.PrepareRoutes(ctx, target), nil
	}
	var preparation actuatorapi.RoutePreparation
	err := l.Actuator.EnsurePolicy(ctx, target)
	if l.Actuator.Name() == "native" {
		preparation.NativeErr = err
	} else {
		preparation.PhoenixErr = err
	}
	return preparation, err
}

func (l *Local) RetirePolicyBinding(_ context.Context, policyUID string) (bool, error) {
	lifecycle, ok := l.Actuator.(actuator.PolicyBindingLifecycle)
	if !ok {
		return false, nil
	}
	lifecycle.RetirePolicyBinding(policyUID)
	return true, nil
}

func (l *Local) RecoverOperations(ctx context.Context, globalKill bool) ([]actuatorapi.RecoveryEvent, bool, error) {
	recoverer, ok := l.Actuator.(interface {
		RecoverOperations(context.Context, bool) ([]actuator.RecoveryEvent, error)
	})
	if !ok {
		return nil, false, nil
	}
	events, err := recoverer.RecoverOperations(ctx, globalKill)
	return events, true, err
}

func (l *Local) QuarantineCapacity(ctx context.Context, namespace string) actuatorapi.QuarantineCapacity {
	if l.Capacity == nil {
		return actuatorapi.QuarantineCapacity{}
	}
	out := actuatorapi.QuarantineCapacity{Configured: true, Limit: l.Capacity.Limit()}
	inventory, err := l.Capacity.Inventory(ctx, namespace)
	if err != nil {
		out.Reason = err.Error()
		return out
	}
	out.Known, out.Used = true, inventory.Used
	return out
}

func (l *Local) PendingOperation(ctx context.Context, q actuatorapi.PendingOperation) (bool, error) {
	switch q.Kind {
	case actuatorapi.PendingEndpointLease:
		return actuator.PendingEndpointLeaseOperation(ctx, l.Reader, l.OperatorNamespace, q.Namespace, q.PodUID)
	case actuatorapi.PendingLiteLLMClient:
		return actuator.PendingLiteLLMClientOperation(ctx, l.Reader, l.OperatorNamespace, q.Namespace, q.PodUID)
	case actuatorapi.PendingVoiceAdmission:
		return actuator.PendingVoiceAdmissionOperation(ctx, l.Reader, l.OperatorNamespace, q.Namespace, q.Pod, q.PodUID)
	case actuatorapi.PendingVoiceOutput:
		return actuator.PendingVoiceOutputOperation(ctx, l.Reader, l.OperatorNamespace, q.Namespace, q.Pod, q.PodUID)
	case actuatorapi.PendingOutputPolicy:
		return actuator.PendingOutputPolicyOperation(ctx, l.Reader, l.OperatorNamespace, q.Namespace, q.PodUID)
	}
	// An unknown journal can never be shown clear.
	return true, fmt.Errorf("unknown protected operation kind %q", q.Kind)
}

// Actuate reserves quarantine capacity around the backend when a bound is
// configured; otherwise it calls the backend directly.
func (l *Local) Actuate(ctx context.Context, req actuatorapi.Request) (actuatorapi.Result, bool, error) {
	if l.Capacity != nil {
		res, provenance, err := l.Capacity.ActuateWithProvenance(ctx, l.Actuator, req)
		return res, provenance.BackendInvoked, err
	}
	res, err := l.Actuator.Actuate(ctx, req)
	return res, true, err
}
