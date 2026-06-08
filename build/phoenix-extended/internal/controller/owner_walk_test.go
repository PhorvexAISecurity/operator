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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ownerRef(kind, name string) metav1.OwnerReference {
	tru := true
	return metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       kind,
		Name:       name,
		Controller: &tru,
	}
}

func podOwnedBy(name, namespace string, refs ...metav1.OwnerReference) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, OwnerReferences: refs},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "old:1"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func deploymentTemplate(name, namespace, image string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}},
			},
		},
	}
}

// replicaSetOwnedBy builds a ReplicaSet optionally owned by a Deployment.
func replicaSetOwnedBy(name, namespace, deployName string) *appsv1.ReplicaSet {
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	if deployName != "" {
		rs.OwnerReferences = []metav1.OwnerReference{ownerRef("Deployment", deployName)}
	}
	return rs
}

// TestClassify_DeploymentRoute proves Pod -> ReplicaSet -> Deployment classifies as
// the durable owner-template route with the Deployment as the top owner.
func TestClassify_DeploymentRoute(t *testing.T) {
	ctx := context.Background()
	dep := deploymentTemplate("web", "default", "old:1")
	rs := replicaSetOwnedBy("web-abc", "default", "web")
	pod := podOwnedBy("web-abc-123", "default", ownerRef("ReplicaSet", "web-abc"))
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(dep, rs, pod).Build()

	route, top, reason := classifyTopOwner(ctx, cl, pod, false)
	if route != routeDurableOwnerTemplate {
		t.Fatalf("route = %v, want routeDurableOwnerTemplate (reason %q)", route, reason)
	}
	if top == nil || top.kind != "Deployment" || top.name != "web" {
		t.Errorf("top owner = %+v, want Deployment/web", top)
	}
}

// TestClassify_StatefulSetRoute and DaemonSet prove direct workload owners are durable.
func TestClassify_StatefulSetRoute(t *testing.T) {
	ctx := context.Background()
	pod := podOwnedBy("db-0", "default", ownerRef("StatefulSet", "db"))
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(pod).Build()
	route, top, _ := classifyTopOwner(ctx, cl, pod, false)
	if route != routeDurableOwnerTemplate || top == nil || top.kind != "StatefulSet" || top.name != "db" {
		t.Errorf("StatefulSet route wrong: route=%v top=%+v", route, top)
	}
}

func TestClassify_DaemonSetRoute(t *testing.T) {
	ctx := context.Background()
	pod := podOwnedBy("agent-xyz", "default", ownerRef("DaemonSet", "agent"))
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(pod).Build()
	route, top, _ := classifyTopOwner(ctx, cl, pod, false)
	if route != routeDurableOwnerTemplate || top == nil || top.kind != "DaemonSet" || top.name != "agent" {
		t.Errorf("DaemonSet route wrong: route=%v top=%+v", route, top)
	}
}

// TestClassify_BarePod proves a pod with no controller owner is a BarePod cold fallback.
func TestClassify_BarePod(t *testing.T) {
	ctx := context.Background()
	pod := podOwnedBy("loner", "default")
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(pod).Build()
	route, top, reason := classifyTopOwner(ctx, cl, pod, false)
	if route != routeColdFallback || top != nil || reason != reasonBarePod {
		t.Errorf("bare pod wrong: route=%v top=%+v reason=%q (want coldFallback/nil/BarePod)", route, top, reason)
	}
}

// TestClassify_JobOwned proves a Job-owned pod is ImmutableJobTemplate cold fallback.
func TestClassify_JobOwned(t *testing.T) {
	ctx := context.Background()
	pod := podOwnedBy("batch-1", "default", ownerRef("Job", "batch"))
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(pod).Build()
	route, _, reason := classifyTopOwner(ctx, cl, pod, false)
	if route != routeColdFallback || reason != reasonImmutableJobTemplate {
		t.Errorf("job-owned wrong: route=%v reason=%q (want coldFallback/ImmutableJobTemplate)", route, reason)
	}
}

// TestClassify_BareReplicaSet proves a ReplicaSet with NO Deployment owner is NOT a
// durable target (we never patch a bare RS) -> PerPodOnSharedTemplate cold fallback.
func TestClassify_BareReplicaSet(t *testing.T) {
	ctx := context.Background()
	rs := replicaSetOwnedBy("orphan-rs", "default", "") // no Deployment owner
	pod := podOwnedBy("orphan-rs-1", "default", ownerRef("ReplicaSet", "orphan-rs"))
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(rs, pod).Build()
	route, top, reason := classifyTopOwner(ctx, cl, pod, false)
	if route != routeColdFallback || top != nil || reason != reasonPerPodOnSharedTemplate {
		t.Errorf("bare RS wrong: route=%v top=%+v reason=%q (want coldFallback/nil/PerPodOnSharedTemplate)", route, top, reason)
	}
}

// TestClassify_EmptyOverlayShortCircuits proves an empty overlay short-circuits to
// routeColdNoOverlay regardless of owner (no false durability for a nil-overlay Rotate).
func TestClassify_EmptyOverlayShortCircuits(t *testing.T) {
	ctx := context.Background()
	dep := deploymentTemplate("web", "default", "old:1")
	rs := replicaSetOwnedBy("web-abc", "default", "web")
	pod := podOwnedBy("web-abc-123", "default", ownerRef("ReplicaSet", "web-abc"))
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(dep, rs, pod).Build()
	route, top, reason := classifyTopOwner(ctx, cl, pod, true) // overlayEmpty=true
	if route != routeColdNoOverlay || top != nil || reason != "" {
		t.Errorf("empty overlay must short-circuit: route=%v top=%+v reason=%q", route, top, reason)
	}
}

// TestPatchOwnerTemplate_AppliesAndIsIdempotent proves patchOwnerTemplate writes the
// overlay onto the Deployment template the first time (durable, all replicas) and is
// an idempotent NO-OP the second time (the self-Update reconcile-loop guard).
func TestPatchOwnerTemplate_AppliesAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	dep := deploymentTemplate("web", "default", "old:1")
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(dep).Build()
	applier := NewMutationApplier()
	top := &topOwner{kind: "Deployment", namespace: "default", name: "web"}
	ov := EffectiveOverlay{Image: "golden:2", EnvPatch: []corev1.EnvVar{{Name: "RUNTIME_MODE", Value: "SECURE"}}}

	wrote, err := patchOwnerTemplate(ctx, cl, applier, top, ov)
	if err != nil {
		t.Fatalf("first patch: %v", err)
	}
	if !wrote {
		t.Fatal("first patch must write the template")
	}
	var got appsv1.Deployment
	if err := cl.Get(ctx, types.NamespacedName{Namespace: "default", Name: "web"}, &got); err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if got.Spec.Template.Spec.Containers[0].Image != "golden:2" {
		t.Errorf("deployment template image = %q, want golden:2", got.Spec.Template.Spec.Containers[0].Image)
	}
	foundEnv := false
	for _, e := range got.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "RUNTIME_MODE" && e.Value == "SECURE" {
			foundEnv = true
		}
	}
	if !foundEnv {
		t.Error("deployment template must carry RUNTIME_MODE=SECURE")
	}

	// Second patch with the same overlay => idempotent no-op (guard self-Update loop).
	wrote2, err := patchOwnerTemplate(ctx, cl, applier, top, ov)
	if err != nil {
		t.Fatalf("second patch: %v", err)
	}
	if wrote2 {
		t.Error("second patch with the same overlay must be an idempotent no-op (no write)")
	}
}
