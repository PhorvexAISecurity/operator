package console

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

func TestInfraNetworkEdgeRetryReconcileIsReadOnlyAndExact(t *testing.T) {
	profile := infraTestProfile(t, infraFamilyNetworkEdge)
	podLabels, err := labels.ConvertSelectorToLabelsMap(profile.Selector)
	if err != nil {
		t.Fatal(err)
	}
	persisted := AttackCatalogResult{CatalogueID: profile.ID, Family: profile.Family, RunID: "cat-1",
		Signal: AttackCatalogSignalResult{Name: "catalogue-event", TargetUID: "target-uid"}}
	policyName := strings.TrimPrefix(networkPolicyObject(profile.Namespace, "target-uid"), "NetworkPolicy/"+profile.Namespace+"/")
	newRuntime := func(event bool, policy bool, marker bool) (*kubernetesInfraCatalogueRuntime, *kubefake.Clientset, *dynamicfake.FakeDynamicClient) {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "demo-api-a", Namespace: profile.Namespace, UID: "target-uid", Labels: map[string]string{}}}
		for key, value := range podLabels {
			pod.Labels[key] = value
		}
		if marker {
			pod.Labels[infraNetworkIsolatedLabel] = "target-uid"
		}
		objects := []runtime.Object{pod}
		if policy {
			objects = append(objects, &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: profile.Namespace}})
		}
		kube := kubefake.NewSimpleClientset(objects...)
		var events []runtime.Object
		if event {
			events = append(events, &unstructured.Unstructured{Object: map[string]any{
				"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
				"metadata": map[string]any{"name": persisted.Signal.Name}}})
		}
		dynamic := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
			map[schema.GroupVersionResource]string{securityEventGVR: "SecurityEventList"}, events...)
		return &kubernetesInfraCatalogueRuntime{profile: profile, kube: kube, dynamic: dynamic}, kube, dynamic
	}

	for _, tc := range []struct {
		name                  string
		event, policy, marker bool
		reason                string
	}{
		{name: "clean"},
		{name: "event", event: true, reason: "run-owned SecurityEvent is still present"},
		{name: "policy", policy: true, reason: "prior target isolation NetworkPolicy is still present"},
		{name: "marker", marker: true, reason: "a fixture Pod still carries network isolation markers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kubeRuntime, kube, dynamic := newRuntime(tc.event, tc.policy, tc.marker)
			adapter := &infraAttackCatalogAdapter{profile: profile, fixedRuntime: kubeRuntime}
			safety, err := adapter.ReconcileRetrySafety(context.Background(), persisted)
			if err != nil {
				t.Fatal(err)
			}
			clean := tc.reason == ""
			if safety.Verified != clean || safety.RetrySafe != clean || (!clean && safety.Reason != tc.reason) {
				t.Fatalf("safety = %+v, want clean=%v reason=%q", safety, clean, tc.reason)
			}
			for _, action := range append(kube.Actions(), dynamic.Actions()...) {
				if verb := action.GetVerb(); verb != "get" && verb != "list" {
					t.Fatalf("reconciliation mutated the cluster: %s %s", verb, action.GetResource().Resource)
				}
			}
		})
	}

	kubeRuntime, _, _ := newRuntime(false, false, false)
	adapter := &infraAttackCatalogAdapter{profile: profile, fixedRuntime: kubeRuntime}
	for _, wrong := range []AttackCatalogResult{
		{CatalogueID: "AML.T0108", Family: profile.Family, RunID: "cat-1", Signal: persisted.Signal},
		{CatalogueID: profile.ID, Family: infraFamilyImage, RunID: "cat-1", Signal: persisted.Signal},
		{CatalogueID: profile.ID, Family: profile.Family, Signal: persisted.Signal},
		{CatalogueID: profile.ID, Family: profile.Family, RunID: "cat-1", Signal: AttackCatalogSignalResult{Name: "catalogue-event"}},
	} {
		if safety, err := adapter.ReconcileRetrySafety(context.Background(), wrong); err == nil || safety.RetrySafe {
			t.Fatalf("reconciliation accepted an inexact identity %+v: %+v", wrong, safety)
		}
	}
	if (&infraAttackCatalogAdapter{profile: infraTestProfile(t, infraFamilyImage)}).supportsRetryReconcile() {
		t.Fatal("image family must not claim read-only retry reconciliation")
	}
	if _, ok := attackCatalogReconcilerFor(adapter); !ok {
		t.Fatal("network-edge adapter is not registered as a retry reconciler")
	}
}
