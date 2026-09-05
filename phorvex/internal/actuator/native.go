/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 */

package actuator

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
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

	// [P-VCLUSTER O7] tenantNS records each tenant's declared namespaces (via EnsurePolicy). Actuate
	// fail-fast REJECTS a Request whose Namespace is not bound to its Tenant — an explicit Phorvex-layer
	// cross-tenant-actuation control (defense-in-depth above the per-namespace K8s RBAC backstop).
	tenantNS map[string]map[string]bool
	// StrictTenantNamespace fail-CLOSES on a Request whose Tenant has NO binding at all (production
	// posture once every tenant is bound). Default false preserves the legacy single-tenant path.
	StrictTenantNamespace bool
}

// NewNativeActuator constructs the native actuator over a controller-runtime client.
func NewNativeActuator(c client.Client) *NativeActuator { return &NativeActuator{Client: c} }

// SupportsAction answers only the fixtures the ACTUATOR PACKAGE itself knows — the
// per-target CONFIG predicates (MIG tuple, guardrail variants, serving endpoint, route
// Service, warm-shadow pool) are computed by the capability layer from the model's typed
// witnesses, so they are not re-derived here. The one thing only this package knows is
// whether the node-exec TRANSPORT is wired: mig-rebind fail-closes without it, yet the
// old status reported it supported (M-79). This makes that absence visible before scoring.
func (n *NativeActuator) SupportsAction(_ context.Context, a model.Action, _ Target) (bool, string) {
	if a == model.ActionMIGRebind && !NodeExecWired() {
		return false, "transport-unwired"
	}
	return true, ""
}

// Name implements Actuator.
func (*NativeActuator) Name() string { return "native" }

// EnsurePolicy records the tenant→namespace binding (O7) and pre-stages per-tenant native state where a
// handler needs it. The base K8s moves need no standing CR, so beyond the binding this is a no-op.
func (n *NativeActuator) EnsurePolicy(_ context.Context, target TenantTarget) error {
	if target.Tenant == "" || target.Namespace == "" {
		return nil
	}
	if n.tenantNS == nil {
		n.tenantNS = map[string]map[string]bool{}
	}
	if n.tenantNS[target.Tenant] == nil {
		n.tenantNS[target.Tenant] = map[string]bool{}
	}
	n.tenantNS[target.Tenant][target.Namespace] = true
	return nil
}

// assertTenantNamespace is the O7 fail-fast: a Request may only act in a namespace bound to its tenant.
func (n *NativeActuator) assertTenantNamespace(req Request) error {
	allowed, bound := n.tenantNS[req.Tenant]
	if !bound {
		if n.StrictTenantNamespace {
			return fmt.Errorf("native actuate DENIED (O7 strict): tenant %q has no namespace binding for %s/%s", req.Tenant, req.Namespace, req.Pod)
		}
		return nil // legacy/single-tenant: unbound tenant allowed; K8s per-namespace RBAC is the backstop
	}
	if !allowed[req.Namespace] {
		return fmt.Errorf("native actuate DENIED (O7): tenant %q is not bound to namespace %q — cross-tenant actuation refused (%s/%s)", req.Tenant, req.Namespace, req.Namespace, req.Pod)
	}
	return nil
}

// Actuate dispatches the move to its native handler. Implements Actuator.
func (n *NativeActuator) Actuate(ctx context.Context, req Request) (Result, error) {
	if err := n.assertTenantNamespace(req); err != nil {
		return Result{}, err
	}
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
