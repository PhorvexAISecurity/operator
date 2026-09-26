/*
 * Phorvex — HYBRID actuator (composite hands).
 *
 * The in-cluster operator can only pick ONE actuator, but two tenant classes need
 * DIFFERENT enactment:
 *   - infra workloads (nats, litellm, live-demo) are defended with rotate/quarantine.
 *     Quarantine remains on Phoenix's AMTD CR + SecurityEvent path. Rotate is native
 *     because only that path can bind the current policy's graceful-termination cap;
 *   - AI workloads (vLLM) are defended with AI-native moves (kv-reset, adapter-rotate,
 *     warm-swap, …) that Phoenix does NOT support — it returns "unsupported action" and
 *     the attack LANDS. Those need the native actuator (its own client-go hands: a real
 *     vLLM /reset_prefix_cache flush, adapter eviction, …).
 *
 * The hybrid actuator routes each move by capability: quarantine goes to Phoenix;
 * bounded rotate and the remaining native moves go to native. EnsurePolicy
 * fans out to BOTH so the Phoenix-side AMTD CR is maintained (unchanged for nats) AND the
 * native actuator records its tenant/namespace binding (required before it will Actuate).
 * The brain is unchanged; this only widens Phorvex's hands.
 */

package actuator

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

// HybridActuator dispatches quarantine to the Phoenix adapter and bounded rotate plus
// the remaining native moves to the native actuator.
type HybridActuator struct {
	phoenix *PhoenixActuator
	native  *NativeActuator
}

// NewHybridActuator builds the composite over one client (both sub-actuators share it).
func NewHybridActuator(c client.Client) *HybridActuator {
	return &HybridActuator{
		phoenix: NewPhoenixActuator(c),
		native:  NewNativeActuator(c),
	}
}

func (h *HybridActuator) Name() string { return "hybrid" }

func (h *HybridActuator) PendingOutputPolicyOperation(ctx context.Context, namespace, podUID string) (bool, error) {
	return h.native.PendingOutputPolicyOperation(ctx, namespace, podUID)
}

// ConfigureNativeJournal wires only the native leg. Phoenix actions never enter it.
func (h *HybridActuator) ConfigureNativeJournal(reader client.Reader, namespace string) {
	h.native.Reader = reader
	h.native.JournalNamespace = namespace
}
func (h *HybridActuator) SetAdapterSources(s AdapterSources)          { h.native.SetAdapterSources(s) }
func (h *HybridActuator) SetMIGProfiles(p *MIGProfiles)               { h.native.SetMIGProfiles(p) }
func (h *HybridActuator) SetServingSecurity(c *ServingSecurityConfig) { h.native.SetServingSecurity(c) }

func (h *HybridActuator) RecoverOperations(ctx context.Context, globalKill bool) ([]RecoveryEvent, error) {
	return h.native.recoverOperations(ctx, globalKill, func(a model.Action) bool { return RouteFor(BackendHybrid, a) == BackendNative })
}

// SupportsAction delegates exactly as Actuate does: quarantine to the Phoenix stub;
// every native action (incl. bounded rotate, guardrail-rotate and
// mig-rebind) to the native actuator's real target-local checks — so M-19 and M-79 are
// caught on the production hybrid path, not only on a native-only deployment.
func (h *HybridActuator) SupportsAction(ctx context.Context, a model.Action, t Target) (bool, string) {
	if RouteFor(BackendHybrid, a) == BackendPhoenix {
		return h.phoenix.SupportsAction(ctx, a, t)
	}
	return h.native.SupportsAction(ctx, a, t)
}

func (h *HybridActuator) CapabilityAdvisory(a model.Action, t Target) string {
	if RouteFor(BackendHybrid, a) == BackendPhoenix {
		return ""
	}
	return h.native.CapabilityAdvisory(a, t)
}

// EnsurePolicy maintains BOTH sides: Phoenix's AMTD CR (so quarantine keeps the
// exact CR-driven mechanism) and the native actuator's in-memory tenant binding (which its
// Actuate asserts before enacting an AI move). Phoenix runs first so a CR error surfaces.
func (h *HybridActuator) EnsurePolicy(ctx context.Context, target TenantTarget) error {
	if err := h.phoenix.EnsurePolicy(ctx, target); err != nil {
		return err
	}
	return h.native.EnsurePolicy(ctx, target)
}

// RoutePreparation is local to one runner preparation call. It cannot retain a
// refusal from another policy, namespace, generation, or tick.
type RoutePreparation struct {
	PhoenixErr     error
	NativeErr      error
	PhoenixSkipped bool
	NativeSkipped  bool
}

// ForAction reports the preparation result for the backend that will dispatch
// this action. The caller must check it before attempting Actuate.
func (p RoutePreparation) ForAction(a model.Action) error {
	if RouteFor(BackendHybrid, a) == BackendPhoenix {
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

// PrepareRoutes prepares both backends independently. An unsupported Phoenix
// selector leaves native actions available, while a Phoenix-routed action sees
// the refusal through the preparation result.
func (h *HybridActuator) PrepareRoutes(ctx context.Context, target TenantTarget) RoutePreparation {
	return h.ReconcileStandingPolicy(ctx, target).Preparation
}

func requiredStandingRoutes(target TenantTarget) (phoenix, native bool) {
	// Nil retains the documented default rotate+quarantine set. An explicit
	// policy map remains authoritative, including declared/manual actions outside
	// MutatingActions that still route through the native adapter.
	if target.EnabledActions == nil {
		return true, true // default quarantine uses Phoenix; bounded rotate uses native
	}
	for action, enabled := range target.EnabledActions {
		if !enabled {
			continue
		}
		if RouteFor(BackendHybrid, action) == BackendPhoenix {
			phoenix = true
		} else {
			native = true
		}
	}
	return phoenix, native
}

func initialHybridMaintenance() PolicyMaintenanceResult {
	return PolicyMaintenanceResult{
		Preparation: RoutePreparation{PhoenixSkipped: true, NativeSkipped: true},
		Phoenix:     PolicyRouteMaintenance{State: PolicyMaintenanceNotRequired, Detail: "Phoenix route not required"},
		Native:      PolicyRouteMaintenance{State: PolicyMaintenanceNotRequired, Detail: "native route not required"},
	}
}

// ObserveStandingPolicy checks only the applicable backends and never repairs
// their state. It is safe under dry-run, namespace brake and kill switch.
func (h *HybridActuator) ObserveStandingPolicy(ctx context.Context, target TenantTarget) PolicyMaintenanceResult {
	result := initialHybridMaintenance()
	phoenixRequired, nativeRequired := requiredStandingRoutes(target)
	if phoenixRequired {
		observed := h.phoenix.ObserveStandingPolicy(ctx, target)
		result.Preparation.PhoenixSkipped = false
		result.Preparation.PhoenixErr = observed.Preparation.PhoenixErr
		result.Phoenix = observed.Phoenix
	}
	if nativeRequired {
		observed := h.native.ObserveStandingPolicy(ctx, target)
		result.Preparation.NativeSkipped = false
		result.Preparation.NativeErr = observed.Preparation.NativeErr
		result.Native = observed.Native
	}
	return result
}

// ReconcileStandingPolicy repairs each applicable backend independently so a
// Phoenix refusal cannot suppress a valid native route.
func (h *HybridActuator) ReconcileStandingPolicy(ctx context.Context, target TenantTarget) PolicyMaintenanceResult {
	result := initialHybridMaintenance()
	phoenixRequired, nativeRequired := requiredStandingRoutes(target)
	if phoenixRequired {
		maintained := h.phoenix.ReconcileStandingPolicy(ctx, target)
		result.Preparation.PhoenixSkipped = false
		result.Preparation.PhoenixErr = maintained.Preparation.PhoenixErr
		result.Phoenix = maintained.Phoenix
	}
	if nativeRequired {
		maintained := h.native.ReconcileStandingPolicy(ctx, target)
		result.Preparation.NativeSkipped = false
		result.Preparation.NativeErr = maintained.Preparation.NativeErr
		result.Native = maintained.Native
	}
	return result
}

// Actuate routes quarantine to Phoenix and bounded rotate plus all remaining actions to
// the native actuator's registered handlers.
func (h *HybridActuator) Actuate(ctx context.Context, req Request) (Result, error) {
	if RouteFor(BackendHybrid, req.Action) == BackendPhoenix {
		return h.phoenix.Actuate(ctx, req)
	}
	return h.native.Actuate(ctx, req)
}

// RetirePolicyBinding forwards owner retirement only to the native leg. Phoenix
// has no corresponding in-memory authorization store.
func (h *HybridActuator) RetirePolicyBinding(policyUID string) {
	h.native.RetirePolicyBinding(policyUID)
}

// compile-time guard: the hybrid satisfies the Actuator contract.
var (
	_ Actuator                 = (*HybridActuator)(nil)
	_ PolicyBindingLifecycle   = (*HybridActuator)(nil)
	_ StandingPolicyMaintainer = (*HybridActuator)(nil)
)
