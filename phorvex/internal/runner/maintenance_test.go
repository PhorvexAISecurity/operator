package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

func TestIdleNativeTickRecoversWithoutDecisionSnapshot(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, networkingv1.AddToScheme, appsv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	ready := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	old := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "old", UID: "old-uid", ResourceVersion: "7", CreationTimestamp: metav1.NewTime(time.Unix(1, 0)), Labels: map[string]string{"phorvex.ai/swap-group": "g", "phorvex.ai/role": "leader"}}, Status: corev1.PodStatus{Conditions: ready}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "serve", Image: "fixture"}}}}
	shadow := old.DeepCopy()
	shadow.Name, shadow.UID, shadow.Labels["phorvex.ai/role"], shadow.Labels["phorvex.ai/model-loaded"] = "new", "new-uid", "warm-shadow", "true"
	for _, p := range []*corev1.Pod{old, shadow} {
		p.Labels["app"] = "pool"
		p.Annotations = map[string]string{"phorvex.ai/route-service": "pool", "phorvex.ai/model-id": "fixture"}
	}
	controller := true
	owner := metav1.OwnerReference{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "pool", UID: "pool-uid", Controller: &controller}
	old.OwnerReferences, shadow.OwnerReferences = []metav1.OwnerReference{owner}, []metav1.OwnerReference{owner}
	replicas := int32(2)
	templateLabels := map[string]string{"app": "pool", "phorvex.ai/swap-group": "g", "phorvex.ai/role": "warm-shadow", "phorvex.ai/model-loaded": "false"}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pool", UID: "pool-uid", Generation: 1}, Spec: appsv1.ReplicaSetSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "pool", "phorvex.ai/swap-group": "g"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: templateLabels, Annotations: map[string]string{"phorvex.ai/route-service": "pool"}}, Spec: old.Spec}}, Status: appsv1.ReplicaSetStatus{ObservedGeneration: 1, Replicas: 2}}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pool", UID: "service-uid"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "pool", "phorvex.ai/swap-group": "g", "phorvex.ai/role": "leader"}, Ports: []corev1.ServicePort{{Port: 80}}}}
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"phorvex.ai/swap-group": "g"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionWarmSwap)}}}}
	failPhase := true
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(old, shadow, rs, service, pol, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetUID() == "" {
				obj.SetUID(types.UID("created-" + obj.GetName()))
			}
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if _, ok := obj.(*corev1.ConfigMap); ok && failPhase {
				failPhase = false
				return errors.New("post-promotion journal outage")
			}
			return c.Update(ctx, obj, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if err := c.Delete(ctx, obj, opts...); err != nil {
				return err
			}
			p, ok := obj.(*corev1.Pod)
			if !ok || p.UID != old.UID {
				return nil
			}
			replacement := shadow.DeepCopy()
			replacement.Name, replacement.UID, replacement.ResourceVersion = "controller-new", "controller-new-uid", ""
			replacement.Labels["phorvex.ai/model-loaded"] = "true"
			return c.Create(ctx, replacement)
		},
	}).Build()
	native := actuator.NewNativeActuator(base)
	native.Reader, native.JournalNamespace = base, "operator"
	legacy, _ := actuator.LoadServingSecurityFile("", actuator.ServingSecurityLegacyPlaintext, "operator")
	native.SetServingSecurity(legacy)
	if _, err := native.Actuate(ctx, actuator.Request{Namespace: "ns", Pod: "old", TargetUID: "old-uid", Action: model.ActionWarmSwap, PolicyName: "policy", PolicyUID: "policy-uid"}); err == nil {
		t.Fatal("producer did not interrupt after promotion")
	}
	phoenix, err := NewManagerWithBackend(base, logr.Discard(), actuator.BackendResolution{Backend: actuator.BackendPhoenix})
	if err != nil {
		t.Fatal(err)
	}
	phoenix.Calibration = nil
	phoenix.KillSwitch.Namespace = "operator"
	if result := phoenix.tick(ctx); result != tickNoSnapshot {
		t.Fatalf("Phoenix idle tick status: %v", result)
	}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "old"}, &corev1.Pod{}); err != nil {
		t.Fatalf("Phoenix backend ran native retirement: %v", err)
	}
	m, err := NewManagerWithBackend(base, logr.Discard(), actuator.BackendResolution{Backend: actuator.BackendNative})
	if err != nil {
		t.Fatal(err)
	}
	m.Actuator = native
	m.Calibration = nil
	m.KillSwitch.Namespace = "operator"
	m.Client = interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if _, ok := list.(*corev1.PodList); ok {
			return errors.New("decision Pod inventory read forbidden on idle tick")
		}
		return c.List(ctx, list, opts...)
	}})
	if result := m.tick(ctx); result != tickNoSnapshot {
		t.Fatalf("idle maintenance needed expensive decision snapshot: %v", result)
	}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "old"}, &corev1.Pod{}); err == nil {
		t.Fatal("idle tick did not retire recorded old Pod")
	}
	newPod := &corev1.Pod{}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "new"}, newPod); err != nil || newPod.Labels["phorvex.ai/role"] != "leader" {
		t.Fatalf("recorded survivor lost: %v %+v", err, newPod.Labels)
	}
}
