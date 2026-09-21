package actuator

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func m135Target() TenantTarget {
	return TenantTarget{
		Tenant: "team", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", Generation: 4,
		MatchLabels:      map[string]string{"app": "api"},
		EnabledActions:   map[model.Action]bool{model.ActionRotate: true},
		PolicyOwnerCount: 1,
	}
}

func TestM135PhoenixMaintenanceWritesOnlyForMissingOrOwnedDrift(t *testing.T) {
	base := fake.NewClientBuilder().WithScheme(m126Scheme(t)).Build()
	counting := &m126CountingClient{Client: base}
	phoenix := NewPhoenixActuator(counting)
	target := m135Target()

	observed := phoenix.ObserveStandingPolicy(t.Context(), target)
	if observed.Phoenix.State != PolicyMaintenanceMissing || counting.creates != 0 || counting.updates != 0 {
		t.Fatalf("read-only missing observation = %+v writes=%d/%d", observed, counting.creates, counting.updates)
	}
	created := phoenix.ReconcileStandingPolicy(t.Context(), target)
	if created.Phoenix.State != PolicyMaintenanceRepaired || counting.creates != 1 || counting.updates != 0 {
		t.Fatalf("missing reconcile = %+v writes=%d/%d", created, counting.creates, counting.updates)
	}
	second := phoenix.ReconcileStandingPolicy(t.Context(), target)
	if second.Phoenix.State != PolicyMaintenanceInSync || counting.creates != 1 || counting.updates != 0 {
		t.Fatalf("in-sync reconcile wrote: %+v writes=%d/%d", second, counting.creates, counting.updates)
	}

	var current amtdv1beta1.AdaptiveMovingTargetDefense
	if err := base.Get(t.Context(), client.ObjectKey{Namespace: "ns", Name: amtdName("ns", "team")}, &current); err != nil {
		t.Fatal(err)
	}
	current.Spec.PodSelector = map[string]string{"app": "drifted"}
	current.Annotations["example.com/foreign"] = "preserve"
	if err := base.Update(t.Context(), &current); err != nil {
		t.Fatal(err)
	}
	counting.updates = 0
	observed = phoenix.ObserveStandingPolicy(t.Context(), target)
	if observed.Phoenix.State != PolicyMaintenanceDrifted || counting.updates != 0 {
		t.Fatalf("read-only drift observation = %+v updates=%d", observed, counting.updates)
	}
	repaired := phoenix.ReconcileStandingPolicy(t.Context(), target)
	if repaired.Phoenix.State != PolicyMaintenanceRepaired || counting.updates != 1 {
		t.Fatalf("drift reconcile = %+v updates=%d", repaired, counting.updates)
	}
	if err := base.Get(t.Context(), client.ObjectKeyFromObject(&current), &current); err != nil {
		t.Fatal(err)
	}
	if current.Spec.PodSelector["app"] != "api" || current.Annotations["example.com/foreign"] != "preserve" {
		t.Fatalf("repair lost desired or unrelated data: %+v", current)
	}
}

func TestM135PhoenixMaintenanceOwnershipGenerationAndFailures(t *testing.T) {
	target := m135Target()
	desired, err := desiredPhoenixPolicy(target)
	if err != nil {
		t.Fatal(err)
	}
	owned := &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: desired.name,
			Labels:      map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": tenantLabel("team")},
			Annotations: mergeAnnotations(desired.identity, map[string]string{"example.com/foreign": "keep"}),
		},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{PodSelector: desired.selector, Strategy: desired.strategies, MatcherMode: amtdv1beta1.MatcherModeExact},
	}

	t.Run("same owner new generation repairs", func(t *testing.T) {
		copy := owned.DeepCopy()
		copy.Annotations[policyGenerationAnnotation] = "3"
		base := &m126CountingClient{Client: fake.NewClientBuilder().WithScheme(m126Scheme(t)).WithObjects(copy).Build()}
		result := NewPhoenixActuator(base).ReconcileStandingPolicy(t.Context(), target)
		if result.Phoenix.State != PolicyMaintenanceRepaired || base.updates != 1 {
			t.Fatalf("result=%+v updates=%d", result, base.updates)
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(*amtdv1beta1.AdaptiveMovingTargetDefense)
	}{
		{name: "foreign UID", mutate: func(a *amtdv1beta1.AdaptiveMovingTargetDefense) { a.Annotations[policyUIDAnnotation] = "other-uid" }},
		{name: "legacy ownerless", mutate: func(a *amtdv1beta1.AdaptiveMovingTargetDefense) {
			delete(a.Annotations, policyNameAnnotation)
			delete(a.Annotations, policyUIDAnnotation)
			delete(a.Annotations, policyGenerationAnnotation)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := owned.DeepCopy()
			tc.mutate(copy)
			base := &m126CountingClient{Client: fake.NewClientBuilder().WithScheme(m126Scheme(t)).WithObjects(copy).Build()}
			result := NewPhoenixActuator(base).ReconcileStandingPolicy(t.Context(), target)
			if result.Phoenix.State != PolicyMaintenanceOwnershipRefused || base.creates != 0 || base.updates != 0 {
				t.Fatalf("result=%+v writes=%d/%d", result, base.creates, base.updates)
			}
		})
	}

	collisionClient := &m126CountingClient{Client: fake.NewClientBuilder().WithScheme(m126Scheme(t)).Build()}
	collision := target
	collision.PolicyOwnerCount = 2
	result := NewPhoenixActuator(collisionClient).ReconcileStandingPolicy(t.Context(), collision)
	if result.Phoenix.State != PolicyMaintenanceOwnershipRefused || collisionClient.creates != 0 {
		t.Fatalf("collision result=%+v creates=%d", result, collisionClient.creates)
	}

	failureClient := &m126CountingClient{Client: fake.NewClientBuilder().WithScheme(m126Scheme(t)).Build(), createErr: errors.New("create unavailable")}
	phoenix := NewPhoenixActuator(failureClient)
	result = phoenix.ReconcileStandingPolicy(t.Context(), target)
	if result.Phoenix.State != PolicyMaintenanceUnknown || result.Preparation.PhoenixErr == nil {
		t.Fatalf("failed repair hidden: %+v", result)
	}
	failureClient.createErr = nil
	result = phoenix.ReconcileStandingPolicy(t.Context(), target)
	if result.Phoenix.State != PolicyMaintenanceRepaired {
		t.Fatalf("later recovery failed: %+v", result)
	}
}

func TestM135HybridRouteIsolationAndNativeObservation(t *testing.T) {
	phoenixBase := &m126CountingClient{Client: fake.NewClientBuilder().WithScheme(m126Scheme(t)).Build()}
	native := NewNativeActuator(nil)
	hybrid := &HybridActuator{phoenix: NewPhoenixActuator(phoenixBase), native: native}
	target := m135Target()
	target.EnabledActions = map[model.Action]bool{model.ActionKVReset: true}

	before := hybrid.ObserveStandingPolicy(t.Context(), target)
	if before.Native.State != PolicyMaintenanceMissing || before.Phoenix.State != PolicyMaintenanceNotRequired || phoenixBase.creates != 0 {
		t.Fatalf("native-only observation=%+v phoenix creates=%d", before, phoenixBase.creates)
	}
	after := hybrid.ReconcileStandingPolicy(t.Context(), target)
	if after.Native.State != PolicyMaintenanceRepaired || after.Phoenix.State != PolicyMaintenanceNotRequired || phoenixBase.creates != 0 {
		t.Fatalf("native-only reconcile=%+v phoenix creates=%d", after, phoenixBase.creates)
	}
	steady := hybrid.ReconcileStandingPolicy(t.Context(), target)
	if steady.Native.State != PolicyMaintenanceInSync || phoenixBase.creates != 0 {
		t.Fatalf("native steady=%+v phoenix creates=%d", steady, phoenixBase.creates)
	}

	// A Phoenix collision is route-local and cannot prevent independent native binding.
	both := m135Target()
	both.PolicyOwnerCount = 2
	both.EnabledActions[model.ActionKVReset] = true
	mixed := hybrid.ReconcileStandingPolicy(context.Background(), both)
	if mixed.Phoenix.State != PolicyMaintenanceOwnershipRefused || mixed.Native.State != PolicyMaintenanceInSync || mixed.Preparation.NativeErr != nil {
		t.Fatalf("route-local refusal lost native route: %+v", mixed)
	}
}
