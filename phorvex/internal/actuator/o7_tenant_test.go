/*
 * Phorvex — P-VCLUSTER O7: cross-tenant actuation denial at the Phorvex boundary (defense-in-depth
 * above the per-namespace K8s RBAC backstop).
 */

package actuator

import (
	"context"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestO7_CrossTenantActuationDenied(t *testing.T) {
	n := NewNativeActuator(nil)
	// tenant A is bound to ns-a; tenant B to ns-b.
	_ = n.EnsurePolicy(context.Background(), TenantTarget{Tenant: "A", Namespace: "ns-a"})
	_ = n.EnsurePolicy(context.Background(), TenantTarget{Tenant: "B", Namespace: "ns-b"})

	// A forged/confused Request for tenant A targeting tenant B's namespace MUST be rejected at the
	// Phorvex boundary, BEFORE any handler dispatch (nil client → a dispatch would panic, so rejection
	// is proven by the absence of a panic + the error).
	_, err := n.Actuate(context.Background(), Request{Tenant: "A", Namespace: "ns-b", Pod: "victim", Action: model.ActionRotate})
	if err == nil {
		t.Fatal("O7: a Request for tenant A in tenant B's namespace MUST be denied at the Phorvex boundary")
	}

	// A's own namespace is permitted by the assertion (it proceeds past the O7 check; the nil-client
	// dispatch then errors on the action, which is fine — O7 only governs the tenant/namespace gate).
	if err := n.assertTenantNamespace(Request{Tenant: "A", Namespace: "ns-a", Pod: "own"}); err != nil {
		t.Errorf("O7: tenant A acting in its own bound namespace must pass the assertion, got %v", err)
	}

	// Strict mode: an unbound tenant is fail-closed.
	n.StrictTenantNamespace = true
	if err := n.assertTenantNamespace(Request{Tenant: "ghost", Namespace: "ns-a", Pod: "x"}); err == nil {
		t.Error("O7 strict: an unbound tenant must be denied")
	}

	// Legacy single-tenant (no bindings declared at all) still passes — backward-compatible default.
	legacy := NewNativeActuator(nil)
	if err := legacy.assertTenantNamespace(Request{Tenant: "", Namespace: "ns", Pod: "p"}); err != nil {
		t.Errorf("legacy single-tenant (no binding) must pass, got %v", err)
	}
}
