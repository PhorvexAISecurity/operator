package actuator

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
)

func m091Target(uid, tenant, namespace string) TenantTarget {
	return TenantTarget{PolicyName: "policy", PolicyUID: uid, Tenant: tenant, Namespace: namespace}
}

func m091Request(uid, tenant, namespace string) Request {
	return Request{PolicyName: "policy", PolicyUID: uid, Tenant: tenant, Namespace: namespace, Pod: "target"}
}

func TestM091OwnerBindingsReplaceRetireAndKeepLegacyIsolated(t *testing.T) {
	n := NewNativeActuator(nil)
	if err := n.EnsurePolicy(t.Context(), m091Target("", "legacy", "legacy-ns")); err != nil {
		t.Fatal(err)
	}
	if err := n.assertTenantNamespace(m091Request("", "legacy", "legacy-ns")); err != nil {
		t.Fatalf("never-tracked legacy binding refused: %v", err)
	}
	if err := n.assertTenantNamespace(m091Request("", "legacy", "other")); err == nil {
		t.Fatal("legacy cross-namespace request passed")
	}

	if err := n.EnsurePolicy(t.Context(), m091Target("owner-a", "tenant-a", "ns-a")); err != nil {
		t.Fatal(err)
	}
	if !n.bindingsTracked || n.tenantNS != nil || len(n.bindingsByUID) != 1 {
		t.Fatalf("owner activation did not clear legacy state: tracked=%v legacy=%v owners=%v", n.bindingsTracked, n.tenantNS, n.bindingsByUID)
	}
	for name, req := range map[string]Request{
		"missing-owner":   m091Request("", "tenant-a", "ns-a"),
		"unknown-owner":   m091Request("owner-x", "tenant-a", "ns-a"),
		"wrong-tenant":    m091Request("owner-a", "tenant-x", "ns-a"),
		"wrong-namespace": m091Request("owner-a", "tenant-a", "ns-x"),
		"old-legacy":      m091Request("", "legacy", "legacy-ns"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := n.assertTenantNamespace(req); err == nil || !strings.Contains(err.Error(), "DENIED (O7)") {
				t.Fatalf("request was not owner-refused: %v", err)
			}
		})
	}
	if err := n.assertTenantNamespace(m091Request("owner-a", "tenant-a", "ns-a")); err != nil {
		t.Fatalf("exact owner refused: %v", err)
	}

	// One UID has exactly one current value; replacement cannot accumulate the old tuple.
	if err := n.EnsurePolicy(t.Context(), m091Target("owner-a", "tenant-b", "ns-b")); err != nil {
		t.Fatal(err)
	}
	if err := n.assertTenantNamespace(m091Request("owner-a", "tenant-a", "ns-a")); err == nil {
		t.Fatal("old same-owner binding survived replacement")
	}
	if err := n.assertTenantNamespace(m091Request("owner-a", "tenant-b", "ns-b")); err != nil {
		t.Fatalf("replacement binding refused: %v", err)
	}

	before := n.bindingsByUID["owner-a"]
	badSelector := m091Target("owner-a", "changed", "changed")
	badSelector.Selector = &metav1.LabelSelector{}
	if err := n.EnsurePolicy(t.Context(), badSelector); err == nil || n.bindingsByUID["owner-a"] != before {
		t.Fatalf("invalid selector changed binding: err=%v before=%+v after=%+v", err, before, n.bindingsByUID["owner-a"])
	}
	if err := n.EnsurePolicy(t.Context(), m091Target("owner-a", "", "ns")); err == nil || n.bindingsByUID["owner-a"] != before {
		t.Fatalf("missing owner tuple changed binding: err=%v before=%+v after=%+v", err, before, n.bindingsByUID["owner-a"])
	}
	if err := n.EnsurePolicy(t.Context(), m091Target("", "legacy", "legacy-ns")); err == nil || n.tenantNS != nil {
		t.Fatalf("empty UID recreated legacy authority after tracking: err=%v legacy=%v", err, n.tenantNS)
	}

	n.RetirePolicyBinding("")
	if !n.bindingsTracked || len(n.bindingsByUID) != 1 {
		t.Fatal("empty retirement changed owner state")
	}
	n.RetirePolicyBinding("owner-a")
	if !n.bindingsTracked || len(n.bindingsByUID) != 0 {
		t.Fatalf("last-owner retirement reopened or retained authority: tracked=%v owners=%v", n.bindingsTracked, n.bindingsByUID)
	}
	if err := n.assertTenantNamespace(m091Request("owner-a", "tenant-b", "ns-b")); err == nil {
		t.Fatal("retired owner remained authorized")
	}
}

func TestM091SharedTenantOwnersRetireIndependently(t *testing.T) {
	for _, namespaces := range [][2]string{{"shared-ns", "shared-ns"}, {"ns-a", "ns-b"}} {
		n := NewNativeActuator(nil)
		if err := n.EnsurePolicy(t.Context(), m091Target("owner-a", "shared", namespaces[0])); err != nil {
			t.Fatal(err)
		}
		if err := n.EnsurePolicy(t.Context(), m091Target("owner-b", "shared", namespaces[1])); err != nil {
			t.Fatal(err)
		}
		n.RetirePolicyBinding("owner-a")
		if err := n.assertTenantNamespace(m091Request("owner-a", "shared", namespaces[0])); err == nil {
			t.Fatal("retired shared-tenant owner remained authorized")
		}
		if err := n.assertTenantNamespace(m091Request("owner-b", "shared", namespaces[1])); err != nil {
			t.Fatalf("surviving shared-tenant owner refused: %v", err)
		}
	}
}

func TestM091OwnerBindingRaceAndBoundedChurn(t *testing.T) {
	n := NewNativeActuator(nil)
	const owners = 64
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < owners; i++ {
				uid := fmt.Sprintf("owner-%d", i)
				tenant := fmt.Sprintf("tenant-%d", worker%2)
				_ = n.EnsurePolicy(context.Background(), m091Target(uid, tenant, "ns"))
				_ = n.assertTenantNamespace(m091Request(uid, tenant, "ns"))
				if (i+worker)%3 == 0 {
					n.RetirePolicyBinding(uid)
				}
			}
		}()
	}
	wg.Wait()
	for i := 0; i < owners; i++ {
		n.RetirePolicyBinding(fmt.Sprintf("owner-%d", i))
	}
	n.bindingMu.RLock()
	defer n.bindingMu.RUnlock()
	if !n.bindingsTracked || len(n.bindingsByUID) != 0 || n.tenantNS != nil {
		t.Fatalf("ordered final retirement left authority: tracked=%v owners=%d legacy=%v", n.bindingsTracked, len(n.bindingsByUID), n.tenantNS)
	}
}

func TestM091PublicRollbackChecksExactOwnerBeforeEffects(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Request)
		want bool
	}{
		{name: "exact", want: true},
		{name: "missing-owner", edit: func(r *Request) { r.PolicyUID = "" }},
		{name: "unknown-owner", edit: func(r *Request) { r.PolicyUID = "other" }},
		{name: "wrong-tenant", edit: func(r *Request) { r.Tenant = "other" }},
		{name: "wrong-namespace", edit: func(r *Request) { r.Namespace = "other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
			req, ref := m087Rotate(t, f)
			spy := &m087Spy{}
			wrapped := m087WrappedClient{Client: f.client, spy: spy}
			n := NewNativeActuator(wrapped)
			n.SetBoundaryReader(wrapped)
			n.JournalNamespace = f.native.JournalNamespace
			if err := n.EnsurePolicy(t.Context(), m091Target(req.PolicyUID, "t", "route-unit")); err != nil {
				t.Fatal(err)
			}
			if tc.edit != nil {
				tc.edit(&req)
			}
			spy.reset()
			err := n.Rollback(t.Context(), req, ref)
			if tc.want {
				if err != nil || spy.writes == 0 {
					t.Fatalf("exact owner rollback err=%v reads=%d writes=%d", err, spy.reads, spy.writes)
				}
				return
			}
			if err == nil || spy.reads != 0 || spy.writes != 0 {
				t.Fatalf("refused rollback crossed boundary: err=%v reads=%d writes=%d", err, spy.reads, spy.writes)
			}
		})
	}
}

func TestM091HybridForwardsRetirementAndPreservesPhoenixQuarantineRoute(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	h := NewHybridActuator(c)
	prep := h.PrepareRoutes(t.Context(), TenantTarget{
		Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "owner",
		EnabledActions: map[model.Action]bool{model.ActionDisable: true},
	})
	if err := prep.ForAction(model.ActionDisable); err != nil {
		t.Fatal(err)
	}
	req := Request{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "owner", Action: model.ActionDisable}
	result, err := h.Actuate(t.Context(), req)
	if err != nil || result.NoEffect != NoEffectDeclared || strings.Contains(result.Note, "DENIED (O7)") {
		t.Fatalf("native-routed control did not cross owner boundary: result=%+v err=%v", result, err)
	}
	h.RetirePolicyBinding("owner")
	if _, err := h.Actuate(t.Context(), req); err == nil || !strings.Contains(err.Error(), "DENIED (O7)") {
		t.Fatalf("hybrid did not forward native retirement: %v", err)
	}
	result, err = h.Actuate(t.Context(), Request{Tenant: "tenant", Namespace: "ns", Pod: "pod", TargetUID: "pod-uid", TargetNamespaceUID: "namespace-uid", OperationID: strings.Repeat("a", 40), Action: model.ActionQuarantine})
	if err != nil || !result.Emitted || result.RuleType != amtdv1beta1.PhorvexRuleTypeQuarantine {
		t.Fatalf("Phoenix route changed by native retirement: result=%+v err=%v", result, err)
	}
}
