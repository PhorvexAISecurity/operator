package runner

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/model"
)

const ConditionStandingPolicy = "StandingPolicy"

type standingPolicyTickStatus struct {
	result          actuatorapi.PolicyMaintenanceResult
	observed        bool
	blockedCause    string
	dispatchAllowed bool
}

func (m *Manager) policyOwnerCount(namespace, tenant string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, candidate := range m.policies {
		if candidate != nil && candidate.namespace == namespace && candidate.tenant == tenant {
			count++
		}
	}
	return count
}

func (m *Manager) policyEntryCurrent(e *policyEntry) bool {
	if e == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	current := m.policies[e.key.String()]
	return current != nil && current.uid == e.uid && current.generation == e.generation &&
		current.namespace == e.namespace && current.tenant == e.tenant
}

func policyMaintenanceTarget(e *policyEntry, pol model.Policy, ownerCount int) actuatorapi.TenantTarget {
	return actuatorapi.TenantTarget{
		Tenant:           pol.Tenant,
		Namespace:        e.namespace,
		PolicyName:       e.key.Name,
		PolicyUID:        e.uid,
		Generation:       e.generation,
		Selector:         e.spec.Selector.DeepCopy(),
		EnabledActions:   pol.EnabledActions,
		PolicyOwnerCount: ownerCount,
	}
}

func (m *Manager) observeStandingPolicy(ctx context.Context, act actuatorapi.Actuator, target actuatorapi.TenantTarget, blockedCause string) standingPolicyTickStatus {
	return standingPolicyTickStatus{
		result:       act.ObserveStandingPolicy(ctx, target),
		observed:     true,
		blockedCause: blockedCause,
	}
}

// maintainStandingPolicy observes every active policy tick, including ticks with no
// selected move or no matching Pod. It reconciles only after fresh policy, namespace
// and global-stop checks. The returned preparation belongs to this exact tick and can
// be reused by selected dispatch without a second route preparation.
func (m *Manager) maintainStandingPolicy(
	ctx context.Context,
	e *policyEntry,
	pol model.Policy,
	admittedOwnerEpoch uint64,
	killState *killSwitchTickState,
	brakeState *actuationBrakeTickState,
) (standingPolicyTickStatus, bool) {
	maintainer := m.actuation()
	if maintainer == nil || !maintainer.MaintainsStandingPolicy() {
		return standingPolicyTickStatus{dispatchAllowed: true}, true
	}
	target := policyMaintenanceTarget(e, pol, m.policyOwnerCount(e.namespace, pol.Tenant))

	if pol.DryRun {
		return m.observeStandingPolicy(ctx, maintainer, target, actuationbrake.PolicyDryRun), true
	}
	if killState == nil {
		return m.observeStandingPolicy(ctx, maintainer, target, "KillSwitchStateUnavailable"), true
	}
	if killState.observation.Engaged {
		return m.observeStandingPolicy(ctx, maintainer, target, string(killState.observation.Cause)), true
	}
	if brakeState == nil {
		return m.observeStandingPolicy(ctx, maintainer, target, actuationbrake.BoundaryReaderUnavailable), true
	}
	if brakeState.namespace.Engaged {
		return m.observeStandingPolicy(ctx, maintainer, target, brakeState.namespace.Cause), true
	}
	if m.KillSwitch == nil {
		return m.observeStandingPolicy(ctx, maintainer, target, "KillSwitchUnavailable"), true
	}

	killObservation := killState.observe(ctx, m.KillSwitch)
	if ctx.Err() != nil {
		return standingPolicyTickStatus{}, false
	}
	if killObservation.Engaged {
		return m.observeStandingPolicy(ctx, maintainer, target, string(killObservation.Cause)), true
	}

	namespaceObservation := brakeState.observeNamespace(ctx, m, e.namespace)
	if ctx.Err() != nil {
		return standingPolicyTickStatus{}, false
	}
	if namespaceObservation.Engaged {
		return m.observeStandingPolicy(ctx, maintainer, target, namespaceObservation.Cause), true
	}

	// BoundaryReader is the uncached authority used at mutation boundaries. A
	// missing/erroring reader may still observe route drift, but may never repair it.
	if m.BoundaryReader == nil {
		return m.observeStandingPolicy(ctx, maintainer, target, actuationbrake.BoundaryReaderUnavailable), true
	}
	timeout := m.ActuationBrakeReadTimeout
	if timeout <= 0 {
		timeout = actuationbrake.DefaultReadTimeout
	}
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var current v1alpha1.PhorvexPolicy
	if err := m.BoundaryReader.Get(readCtx, e.key, &current); err != nil {
		m.Log.Error(err, "standing policy owner read unavailable", "namespace", e.namespace, "policy", e.key.Name)
		observed := m.observeStandingPolicy(ctx, maintainer, target, "PolicyReadUnavailable")
		return observed, true
	}
	if string(current.UID) != e.uid || current.Generation != e.generation || current.DeletionTimestamp != nil ||
		current.EffectiveTenant() != e.tenant || !m.policyEntryCurrent(e) || !m.ownerCurrent(pol.Owner(), admittedOwnerEpoch) {
		// A stale producer neither repairs nor publishes for a successor. The caller
		// exits this tick; updateStatus carries the same UID guard as a final boundary.
		return standingPolicyTickStatus{}, false
	}

	// Rebuild selector/actions from the just-read generation. Equality of UID and
	// generation binds these values to the admitted policy rather than cached state.
	freshEntry := *e
	freshEntry.spec = *current.Spec.DeepCopy()
	freshPolicy := buildPolicy(&freshEntry)
	target = policyMaintenanceTarget(&freshEntry, freshPolicy, m.policyOwnerCount(e.namespace, freshPolicy.Tenant))
	return standingPolicyTickStatus{
		result:          maintainer.ReconcileStandingPolicy(ctx, target),
		observed:        true,
		dispatchAllowed: true,
	}, true
}

func standingPolicyRouteSummary(result actuatorapi.PolicyMaintenanceResult) (states []actuatorapi.PolicyMaintenanceState, detail string) {
	parts := make([]string, 0, 2)
	if result.Phoenix.State != actuatorapi.PolicyMaintenanceNotRequired && result.Phoenix.State != "" {
		states = append(states, result.Phoenix.State)
		parts = append(parts, fmt.Sprintf("Phoenix=%s (%s)", result.Phoenix.State, result.Phoenix.Detail))
	}
	if result.Native.State != actuatorapi.PolicyMaintenanceNotRequired && result.Native.State != "" {
		states = append(states, result.Native.State)
		parts = append(parts, fmt.Sprintf("native=%s (%s)", result.Native.State, result.Native.Detail))
	}
	return states, strings.Join(parts, "; ")
}

func standingPolicyCondition(status *standingPolicyTickStatus, generation int64) metav1.Condition {
	condition := metav1.Condition{
		Type:               ConditionStandingPolicy,
		Status:             metav1.ConditionUnknown,
		Reason:             "NotObserved",
		Message:            "standing route configuration was not observed this tick; no defense effect is claimed",
		ObservedGeneration: generation,
	}
	if status == nil || !status.observed {
		return condition
	}
	states, detail := standingPolicyRouteSummary(status.result)
	if len(states) == 0 {
		condition.Reason = "NoEnabledRoutes"
		condition.Message = "no enabled action route requires a standing policy; no defense effect is claimed"
		return condition
	}
	has := func(want actuatorapi.PolicyMaintenanceState) bool {
		for _, state := range states {
			if state == want {
				return true
			}
		}
		return false
	}
	suffix := "; standing route configuration only; no defense effect is claimed"
	switch {
	case has(actuatorapi.PolicyMaintenanceOwnershipRefused):
		condition.Status, condition.Reason = metav1.ConditionFalse, "OwnershipRefused"
	case has(actuatorapi.PolicyMaintenanceUnknown):
		condition.Status, condition.Reason = metav1.ConditionUnknown, "ObservationUnavailable"
	case status.blockedCause != "" && (has(actuatorapi.PolicyMaintenanceMissing) || has(actuatorapi.PolicyMaintenanceDrifted)):
		condition.Status, condition.Reason = metav1.ConditionFalse, "BrakedWithDrift"
		detail += "; mutation prohibited by " + status.blockedCause
	case has(actuatorapi.PolicyMaintenanceRepaired):
		condition.Status, condition.Reason = metav1.ConditionTrue, "Repaired"
	case has(actuatorapi.PolicyMaintenanceMissing) || has(actuatorapi.PolicyMaintenanceDrifted):
		condition.Status, condition.Reason = metav1.ConditionFalse, "DriftUnrepaired"
	default:
		condition.Status, condition.Reason = metav1.ConditionTrue, "InSync"
		if status.blockedCause != "" {
			detail += "; mutation prohibited by " + status.blockedCause
		}
	}
	condition.Message = detail + suffix
	return condition
}
