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

	"sigs.k8s.io/controller-runtime/pkg/client"
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

// EnsurePolicy maintains BOTH sides: Phoenix's AMTD CR (so nats/rotate/quarantine keep the
// exact CR-driven mechanism) and the native actuator's in-memory tenant binding (which its
// Actuate asserts before enacting an AI move). Phoenix runs first so a CR error surfaces.
func (h *HybridActuator) EnsurePolicy(ctx context.Context, target TenantTarget) error {
	if err := h.phoenix.EnsurePolicy(ctx, target); err != nil {
		return err
	}
	return h.native.EnsurePolicy(ctx, target)
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
