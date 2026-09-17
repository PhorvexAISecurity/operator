/*
 * Phorvex — HYBRID actuator (composite hands).
 *
 * The in-cluster operator can only pick ONE actuator, but two tenant classes need
 * DIFFERENT enactment:
 *   - infra workloads (nats, litellm, live-demo) are defended with rotate/quarantine,
 *     which Phoenix enacts via its AMTD CR + SecurityEvent (the nats quarantine story +
 *     the dashboard's AMTD-CR detection depend on this exact mechanism);
 *   - AI workloads (vLLM) are defended with AI-native moves (kv-reset, adapter-rotate,
 *     warm-swap, …) that Phoenix does NOT support — it returns "unsupported action" and
 *     the attack LANDS. Those need the native actuator (its own client-go hands: a real
 *     vLLM /reset_prefix_cache flush, adapter eviction, …).
 *
 * The hybrid actuator routes each move by capability: if Phoenix can enact the action
 * (RuleTypeFor != ""), Phoenix does it; otherwise the native actuator does. EnsurePolicy
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

// HybridActuator dispatches Phoenix-supported actions (rotate/quarantine) to the Phoenix
// adapter and everything else (the AI-native moves) to the native actuator.
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

// ConfigureNativeJournal wires only the native leg. Phoenix actions never enter it.
func (h *HybridActuator) ConfigureNativeJournal(reader client.Reader, namespace string) {
	h.native.Reader = reader
	h.native.JournalNamespace = namespace
}
func (h *HybridActuator) SetAdapterSources(s AdapterSources)          { h.native.SetAdapterSources(s) }
func (h *HybridActuator) SetMIGProfiles(p *MIGProfiles)               { h.native.SetMIGProfiles(p) }
func (h *HybridActuator) SetServingSecurity(c *ServingSecurityConfig) { h.native.SetServingSecurity(c) }

func (h *HybridActuator) RecoverOperations(ctx context.Context, globalKill bool) ([]RecoveryEvent, error) {
	return h.native.recoverOperations(ctx, globalKill, func(a model.Action) bool { return RuleTypeFor(a) == "" })
}

// SupportsAction delegates exactly as Actuate does: Phoenix-mapped actions (rotate,
// quarantine) to the Phoenix stub; every native action (incl. guardrail-rotate and
// mig-rebind) to the native actuator's real target-local checks — so M-19 and M-79 are
// caught on the production hybrid path, not only on a native-only deployment.
func (h *HybridActuator) SupportsAction(ctx context.Context, a model.Action, t Target) (bool, string) {
	if RuleTypeFor(a) != "" {
		return h.phoenix.SupportsAction(ctx, a, t)
	}
	return h.native.SupportsAction(ctx, a, t)
}

func (h *HybridActuator) CapabilityAdvisory(a model.Action, t Target) string {
	if RuleTypeFor(a) != "" {
		return ""
	}
	return h.native.CapabilityAdvisory(a, t)
}

// EnsurePolicy maintains BOTH sides: Phoenix's AMTD CR (so nats/rotate/quarantine keep the
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
	if RuleTypeFor(a) != "" {
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
	prep := RoutePreparation{PhoenixSkipped: true, NativeSkipped: true}
	for a, enabled := range target.EnabledActions {
		if !enabled {
			continue
		}
		if RuleTypeFor(a) != "" {
			prep.PhoenixSkipped = false
		} else {
			prep.NativeSkipped = false
		}
	}
	if !prep.PhoenixSkipped {
		prep.PhoenixErr = h.phoenix.EnsurePolicy(ctx, target)
	}
	if !prep.NativeSkipped {
		prep.NativeErr = h.native.EnsurePolicy(ctx, target)
	}
	return prep
}

// Actuate routes by capability: an action Phoenix can enact (rotate/quarantine) goes to
// Phoenix (preserving the AMTD path); any other action (kv-reset, adapter-rotate, …) goes
// to the native actuator's registered handler.
func (h *HybridActuator) Actuate(ctx context.Context, req Request) (Result, error) {
	if RuleTypeFor(req.Action) != "" {
		return h.phoenix.Actuate(ctx, req)
	}
	return h.native.Actuate(ctx, req)
}

// compile-time guard: the hybrid satisfies the Actuator contract.
var _ Actuator = (*HybridActuator)(nil)
