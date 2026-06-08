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
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

var nimTestScheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(nimTestScheme))
	utilruntime.Must(amtdv1beta1.AddToScheme(nimTestScheme))
}

func TestNIMReconciler_Reconcile_NoAnnotation(t *testing.T) {
	ctx := context.Background()
	pod := nimPodWithAnnotations("test-pod", "default", nil)
	client := fake.NewClientBuilder().
		WithScheme(nimTestScheme).
		WithObjects(pod).
		Build()
	reconciler := &NIMReconciler{Client: client, Scheme: nimTestScheme}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKeyFromObject(pod)})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Errorf("expected no requeue, got Requeue=%v RequeueAfter=%v", result.Requeue, result.RequeueAfter)
	}
}

func TestNIMReconciler_Reconcile_NoTimedEvent(t *testing.T) {
	ctx := context.Background()
	applied := []amtdv1beta1.SecurityEvent{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "other"},
			Spec: amtdv1beta1.SecurityEventSpec{
				Rule:        amtdv1beta1.Rule{Type: "other", Source: "OtherSource"},
				Description: "other",
			},
		},
	}
	raw, _ := json.Marshal(applied)
	ann := map[string]string{AMTD_APPLIED_SECURITY_EVENTS: string(raw)}
	pod := nimPodWithAnnotations("test-pod", "default", ann)
	client := fake.NewClientBuilder().
		WithScheme(nimTestScheme).
		WithObjects(pod).
		Build()
	reconciler := &NIMReconciler{Client: client, Scheme: nimTestScheme}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKeyFromObject(pod)})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Errorf("expected no requeue when no timed event, got Requeue=%v RequeueAfter=%v", result.Requeue, result.RequeueAfter)
	}
	var after corev1.Pod
	if err := client.Get(ctx, crclient.ObjectKeyFromObject(pod), &after); err != nil {
		t.Fatalf("pod should still exist: %v", err)
	}
}

// TestNIMReconciler_Reconcile_ValidTimedEvent_PassThrough documents the Phase 0
// NIM DISSOLUTION (design rule #1). Previously, a timed SecurityEvent caused the
// NIM reconciler to itself annotate+delete the pod and requeue after 10s. That
// hard-coded self-action is now DEMOTED to pass-through: a timed rotation is the
// authoritative {type:'timed', source:'TimeBasedTrigger'} -> {rotate:{}} strategy,
// executed one-shot by the SecurityEvent reconciler's Rotate branch (see
// TestSecurityEventReconciler_Rotate_TimedReschedule). NIM must therefore NOT
// delete the pod and NOT self-requeue on a timed event (which would double-delete
// with the Rotate branch).
func TestNIMReconciler_Reconcile_ValidTimedEvent_PassThrough(t *testing.T) {
	ctx := context.Background()
	applied := []amtdv1beta1.SecurityEvent{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "timed-1"},
			Spec: amtdv1beta1.SecurityEventSpec{
				Rule:        amtdv1beta1.Rule{Type: TriggerTypeTimed, Source: TriggerSourceTimeBasedTrigger},
				Description: "timed",
			},
		},
	}
	raw, _ := json.Marshal(applied)
	ann := map[string]string{AMTD_APPLIED_SECURITY_EVENTS: string(raw)}
	pod := nimPodWithAnnotations("test-pod", "default", ann)
	client := fake.NewClientBuilder().
		WithScheme(nimTestScheme).
		WithObjects(pod).
		Build()
	reconciler := &NIMReconciler{Client: client, Scheme: nimTestScheme}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKeyFromObject(pod)})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Errorf("NIM must no longer self-requeue on a timed event (dissolved); got Requeue=%v RequeueAfter=%v", result.Requeue, result.RequeueAfter)
	}
	var after corev1.Pod
	if err := client.Get(ctx, crclient.ObjectKeyFromObject(pod), &after); err != nil {
		t.Errorf("NIM must NOT delete the pod on a timed event (rotation is now owned by the Rotate branch): %v", err)
	}
}

// TestNIMReconciler_Reconcile_InProgressEarlyReturn proves the D22 G2
// cross-controller lock: when the Rotate executor has set the in-progress
// annotation on a pod, the NIM reconciler early-returns (no self-action, no
// requeue, pod untouched) so it never races the one-shot rotation.
func TestNIMReconciler_Reconcile_InProgressEarlyReturn(t *testing.T) {
	ctx := context.Background()
	applied := []amtdv1beta1.SecurityEvent{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "timed-1"},
			Spec: amtdv1beta1.SecurityEventSpec{
				Rule:        amtdv1beta1.Rule{Type: TriggerTypeTimed, Source: TriggerSourceTimeBasedTrigger},
				Description: "timed",
			},
		},
	}
	raw, _ := json.Marshal(applied)
	ann := map[string]string{
		AMTD_APPLIED_SECURITY_EVENTS: string(raw),
		ROTATION_IN_PROGRESS:         "true",
	}
	pod := nimPodWithAnnotations("test-pod", "default", ann)
	client := fake.NewClientBuilder().
		WithScheme(nimTestScheme).
		WithObjects(pod).
		Build()
	reconciler := &NIMReconciler{Client: client, Scheme: nimTestScheme}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKeyFromObject(pod)})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Errorf("NIM must not requeue while a rotation is in progress; got Requeue=%v RequeueAfter=%v", result.Requeue, result.RequeueAfter)
	}
	var after corev1.Pod
	if err := client.Get(ctx, crclient.ObjectKeyFromObject(pod), &after); err != nil {
		t.Errorf("NIM must NOT delete a pod with a rotation in progress: %v", err)
	}
}

func TestNIMReconciler_Reconcile_InvalidJSON(t *testing.T) {
	ctx := context.Background()
	ann := map[string]string{AMTD_APPLIED_SECURITY_EVENTS: `not valid json`}
	pod := nimPodWithAnnotations("test-pod", "default", ann)
	client := fake.NewClientBuilder().
		WithScheme(nimTestScheme).
		WithObjects(pod).
		Build()
	reconciler := &NIMReconciler{Client: client, Scheme: nimTestScheme}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKeyFromObject(pod)})
	if err != nil {
		t.Fatalf("Reconcile should not return error for invalid JSON: %v", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Errorf("expected no requeue on invalid JSON, got Requeue=%v RequeueAfter=%v", result.Requeue, result.RequeueAfter)
	}
}

func TestNIMReconciler_Reconcile_PodNotFound(t *testing.T) {
	ctx := context.Background()
	client := fake.NewClientBuilder().WithScheme(nimTestScheme).Build()
	reconciler := &NIMReconciler{Client: client, Scheme: nimTestScheme}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKeyFromObject(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "missing", Namespace: "default"},
	})})
	if err != nil {
		t.Fatalf("Reconcile should ignore NotFound: %v", err)
	}
	if result.Requeue || result.RequeueAfter > 0 {
		t.Errorf("expected no requeue for missing pod")
	}
}

func TestNIMReconciler_DeterminePodStartupState(t *testing.T) {
	reconciler := &NIMReconciler{}
	tests := []struct {
		phase  corev1.PodPhase
		expect string
	}{
		{corev1.PodPending, NIM_STARTUP_STATE_PENDING},
		{corev1.PodRunning, NIM_STARTUP_STATE_RUNNING},
		{corev1.PodFailed, NIM_STARTUP_STATE_FAILED},
		{corev1.PodSucceeded, NIM_STARTUP_STATE_STARTING},
		{corev1.PodUnknown, NIM_STARTUP_STATE_STARTING},
	}
	for _, tt := range tests {
		t.Run(string(tt.phase), func(t *testing.T) {
			pod := corev1.Pod{Status: corev1.PodStatus{Phase: tt.phase}}
			got := reconciler.determinePodStartupState(pod)
			if got != tt.expect {
				t.Errorf("determinePodStartupState(%s) = %q, want %q", tt.phase, got, tt.expect)
			}
		})
	}
}

func TestFindTimedEvent(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		got := FindTimedEvent(nil, TriggerTypeTimed, TriggerSourceTimeBasedTrigger)
		if got != nil {
			t.Errorf("FindTimedEvent(nil) = %v, want nil", got)
		}
		got = FindTimedEvent([]amtdv1beta1.SecurityEvent{}, TriggerTypeTimed, TriggerSourceTimeBasedTrigger)
		if got != nil {
			t.Errorf("FindTimedEvent(empty) = %v, want nil", got)
		}
	})
	t.Run("no match", func(t *testing.T) {
		events := []amtdv1beta1.SecurityEvent{
			{Spec: amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Type: "other", Source: "Other"}}},
		}
		got := FindTimedEvent(events, TriggerTypeTimed, TriggerSourceTimeBasedTrigger)
		if got != nil {
			t.Errorf("FindTimedEvent(no match) = %v, want nil", got)
		}
	})
	t.Run("one match", func(t *testing.T) {
		events := []amtdv1beta1.SecurityEvent{
			{ObjectMeta: metav1.ObjectMeta{Name: "timed-1"}, Spec: amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Type: TriggerTypeTimed, Source: TriggerSourceTimeBasedTrigger}}},
		}
		got := FindTimedEvent(events, TriggerTypeTimed, TriggerSourceTimeBasedTrigger)
		if got == nil || got.Name != "timed-1" {
			t.Errorf("FindTimedEvent(one match) = %v, want event named timed-1", got)
		}
	})
	t.Run("first of two matches", func(t *testing.T) {
		events := []amtdv1beta1.SecurityEvent{
			{ObjectMeta: metav1.ObjectMeta{Name: "first"}, Spec: amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Type: TriggerTypeTimed, Source: TriggerSourceTimeBasedTrigger}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "second"}, Spec: amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Type: TriggerTypeTimed, Source: TriggerSourceTimeBasedTrigger}}},
		}
		got := FindTimedEvent(events, TriggerTypeTimed, TriggerSourceTimeBasedTrigger)
		if got == nil || got.Name != "first" {
			t.Errorf("FindTimedEvent(two matches) = %v, want event named first", got)
		}
	})
	t.Run("type match only no match", func(t *testing.T) {
		events := []amtdv1beta1.SecurityEvent{
			{Spec: amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Type: TriggerTypeTimed, Source: "Other"}}},
		}
		got := FindTimedEvent(events, TriggerTypeTimed, TriggerSourceTimeBasedTrigger)
		if got != nil {
			t.Errorf("FindTimedEvent(type only) = %v, want nil", got)
		}
	})
}

func nimPodWithAnnotations(name, namespace string, annotations map[string]string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Annotations: annotations},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if annotations != nil {
		pod.Annotations = annotations
	}
	return pod
}
