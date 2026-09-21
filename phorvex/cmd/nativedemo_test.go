package main

import (
	"context"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestNativeDemoRotateCaller(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	one := int32(1)
	cap := int64(30)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "rs", Namespace: "demo", UID: "rs-uid"}, Spec: appsv1.ReplicaSetSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}}}}
	owned := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "owned", Namespace: "demo", UID: "pod-uid", ResourceVersion: "1", Labels: map[string]string{"app": "demo"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}}}
	bare := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "bare", Namespace: "demo", UID: "bare-uid", ResourceVersion: "1"}}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "demo", UID: "demo-uid"}}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "demo", UID: "policy-uid", ResourceVersion: "1"}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}},
		Budget:  v1alpha1.BudgetSpec{MaxGracePeriodSeconds: &cap},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRotate}},
	}}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(namespace, rs, owned, bare, policy).Build()
	n := newDemoActuator(c)
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		emitted bool
	}{{"owned", true}, {"bare", false}} {
		result, err := demoActuate(ctx, n, actuator.Request{Namespace: "demo", Pod: tc.name, Action: model.ActionRotate, PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, MaxGracePeriodSeconds: cap})
		if err != nil || result.Emitted != tc.emitted {
			t.Fatalf("%s: %+v %v", tc.name, result, err)
		}
		err = c.Get(ctx, client.ObjectKey{Namespace: "demo", Name: tc.name}, &corev1.Pod{})
		if tc.emitted && !apierrors.IsNotFound(err) {
			t.Fatalf("owned target not deleted: %v", err)
		}
		if !tc.emitted && (err != nil || !strings.Contains(result.Note, "ownerless")) {
			t.Fatalf("bare refusal not exercised: %+v %v", result, err)
		}
	}
}
