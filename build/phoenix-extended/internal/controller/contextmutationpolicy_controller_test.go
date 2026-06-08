/*
 * Copyright (C) 2023 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func labeledPod(name, ns string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "nim", Image: "old:1"}}},
	}
}

func reconcileCMP(t *testing.T, cl crclient.Client, ns, name string) {
	t.Helper()
	r := &ContextMutationPolicyReconciler{Client: cl, Scheme: seTestScheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: crclient.ObjectKey{Namespace: ns, Name: name}}); err != nil {
		t.Fatalf("Reconcile(%s/%s): %v", ns, name, err)
	}
}

func getCMP(t *testing.T, cl crclient.Client, ns, name string) *amtdv1beta1.ContextMutationPolicy {
	t.Helper()
	c := &amtdv1beta1.ContextMutationPolicy{}
	if err := cl.Get(context.Background(), crclient.ObjectKey{Namespace: ns, Name: name}, c); err != nil {
		t.Fatalf("get CMP %s/%s: %v", ns, name, err)
	}
	return c
}

// TestCMPReconcile_StatusAndAdvisory is the headline thin-reconciler test: a CMP
// (ADA Listing 1 shape) selecting app=nim-inference with 2 matching pods (and 1
// non-matching) writes Status.SelectedPodCount=2, ObservedGeneration, a
// ResolvedMutationSummary carrying image/gpu/env + the cpu/mem-not-applied note, and
// a GatekeeperViolationUnsupported advisory condition (because it declares a
// GatekeeperViolation trigger with no native emitter).
func TestCMPReconcile_StatusAndAdvisory(t *testing.T) {
	cmp := cmpListing1("default", "nim-risk-based-mutation")
	cmp.Generation = 3
	match1 := labeledPod("nim-a", "default", map[string]string{"app": "nim-inference"})
	match2 := labeledPod("nim-b", "default", map[string]string{"app": "nim-inference"})
	other := labeledPod("other", "default", map[string]string{"app": "something-else"})
	otherNS := labeledPod("nim-c", "kube-system", map[string]string{"app": "nim-inference"})

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(cmp, match1, match2, other, otherNS).
		WithStatusSubresource(cmp).
		Build()

	reconcileCMP(t, cl, "default", "nim-risk-based-mutation")

	got := getCMP(t, cl, "default", "nim-risk-based-mutation")
	if got.Status.SelectedPodCount != 2 {
		t.Errorf("SelectedPodCount = %d, want 2 (only same-namespace matching pods)", got.Status.SelectedPodCount)
	}
	if got.Status.ObservedGeneration != 3 {
		t.Errorf("ObservedGeneration = %d, want 3", got.Status.ObservedGeneration)
	}
	for _, want := range []string{"image=nvcr.io/nim/secure-nim:latest", "gpu=0", "env=RUNTIME_MODE", "not applied"} {
		if !contains(got.Status.ResolvedMutationSummary, want) {
			t.Errorf("ResolvedMutationSummary %q missing %q", got.Status.ResolvedMutationSummary, want)
		}
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, gatekeeperAdvisoryConditionType)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != "NoNativeEmitter" {
		t.Errorf("expected GatekeeperViolationUnsupported=True/NoNativeEmitter, got %+v", cond)
	}
}

// TestCMPReconcile_NoGatekeeperTrigger_NoAdvisory proves the advisory condition is
// NOT raised (and is cleared if previously present) when the policy declares no
// GatekeeperViolation trigger.
func TestCMPReconcile_NoGatekeeperTrigger_NoAdvisory(t *testing.T) {
	cmp := &amtdv1beta1.ContextMutationPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "prom-only"},
		Spec: amtdv1beta1.ContextMutationPolicySpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nim-inference"}},
			Triggers: amtdv1beta1.CMPTriggers{TelemetrySources: []amtdv1beta1.TelemetrySource{
				{Type: amtdv1beta1.CMPTriggerPrometheusAlert, Name: "high_gpu_usage"},
			}},
			Mutations: []amtdv1beta1.CMPMutation{
				{Type: amtdv1beta1.CMPMutationContainerImageUpdate, ContainerName: "nim", NewImage: "secure:2"},
			},
		},
	}
	// Pre-seed a stale advisory condition to prove it is cleared.
	meta.SetStatusCondition(&cmp.Status.Conditions, metav1.Condition{
		Type: gatekeeperAdvisoryConditionType, Status: metav1.ConditionTrue, Reason: "NoNativeEmitter", Message: "stale",
	})

	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(cmp).WithStatusSubresource(cmp).Build()
	reconcileCMP(t, cl, "default", "prom-only")

	got := getCMP(t, cl, "default", "prom-only")
	if meta.FindStatusCondition(got.Status.Conditions, gatekeeperAdvisoryConditionType) != nil {
		t.Error("GatekeeperViolationUnsupported condition must be cleared when no GatekeeperViolation trigger is declared")
	}
	if !contains(got.Status.ResolvedMutationSummary, "image=secure:2") {
		t.Errorf("summary missing image, got %q", got.Status.ResolvedMutationSummary)
	}
}

// TestCMPReconcile_NilSelectorSelectsNothing proves a CMP with no selector records
// SelectedPodCount=0 (a CMP with no selector targets no workload).
func TestCMPReconcile_NilSelectorSelectsNothing(t *testing.T) {
	cmp := &amtdv1beta1.ContextMutationPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "no-sel"},
		Spec:       amtdv1beta1.ContextMutationPolicySpec{},
	}
	pod := labeledPod("nim-a", "default", map[string]string{"app": "nim-inference"})
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(cmp, pod).WithStatusSubresource(cmp).Build()
	reconcileCMP(t, cl, "default", "no-sel")
	got := getCMP(t, cl, "default", "no-sel")
	if got.Status.SelectedPodCount != 0 {
		t.Errorf("SelectedPodCount = %d, want 0 for a nil selector", got.Status.SelectedPodCount)
	}
}
