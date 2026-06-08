/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 */

package actuator

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NativeActuator is Phorvex's OWN hands (NFR5: "standalone actuation behind an
// interface"). It writes Pods/NetworkPolicies/Services/EndpointSlices/Secrets/
// ephemeral-containers DIRECTLY via client-go — NO Phoenix CRDs installed — dispatching
// each model.Action to its registered native ActionHandler. It is the native PEER of
// PhoenixActuator (which stays byte-unchanged as the optional SSPL integration adapter);
// a deployment selects one by wiring Manager.Actuator. The brain is unchanged — both
// satisfy the same Actuator interface.
//
// License-clean: this package imports ONLY k8s.io/* + sigs.k8s.io/controller-runtime
// (ZERO Phoenix imports); every handler is authored from the published k8s.io API
// contract (clean-room), so the standalone product IP carries no SSPL-derived Go.
type NativeActuator struct {
	Client client.Client
	// DryRun is a belt-and-suspenders guard (the runner already skips actuation in
	// dry-run); when set, every handler refuses to mutate.
	DryRun bool
}

// NewNativeActuator constructs the native actuator over a controller-runtime client.
func NewNativeActuator(c client.Client) *NativeActuator { return &NativeActuator{Client: c} }

// Name implements Actuator.
func (*NativeActuator) Name() string { return "native" }

// EnsurePolicy pre-stages per-tenant native state where a handler needs it (warm-swap
// pre-stages the warm pool via its handler on first use). The base K8s moves
// (rotate/quarantine/inject/identity/route) need NO standing policy, so this is a no-op
// today — native carries no Phoenix CR. Implements Actuator.
func (n *NativeActuator) EnsurePolicy(_ context.Context, _ TenantTarget) error { return nil }

// Actuate dispatches the move to its native handler. Implements Actuator.
func (n *NativeActuator) Actuate(ctx context.Context, req Request) (Result, error) {
	return dispatch(ctx, EnactCtx{Client: n.Client, DryRun: n.DryRun}, req)
}

// Rollback runs a handler's compensating undo (used by the rollback proof + a future
// saga coordinator). A handler that is not a Rollbacker (forward-only/irreversible)
// returns a no-op nil.
func (n *NativeActuator) Rollback(ctx context.Context, req Request, ref string) error {
	h, ok := HandlerRegistry.Get(string(req.Action))
	if !ok {
		return nil
	}
	if rb, ok := h.(Rollbacker); ok {
		return rb.Rollback(ctx, EnactCtx{Client: n.Client, DryRun: n.DryRun}, req, ref)
	}
	return nil
}

// Compile-time assertions that ALL THREE actuators satisfy the interface (the seam is
// real and Phase-2 cannot drift the contract).
var (
	_ Actuator = (*PhoenixActuator)(nil)
	_ Actuator = (*NativeActuator)(nil)
)
