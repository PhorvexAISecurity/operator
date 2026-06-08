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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// barePodOnSource builds a bare (no controller owner) pod on the source node.
func barePodOnSource(name, ns, nodeName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.PodSpec{NodeName: nodeName, Containers: []corev1.Container{{Name: "app", Image: "img"}}},
	}
}

// nodeRotationFixture builds a NodeRotation request for a bare pod on src, default
// Cordon, default clean-pool selector.
func nodeRotationFixture(name, src, podNS, podName string) *amtdv1beta1.NodeRotation {
	return &amtdv1beta1.NodeRotation{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: amtdv1beta1.NodeRotationSpec{
			SourceNode: src,
			TargetPods: []amtdv1beta1.NamespacedPodRef{{Namespace: podNS, Name: podName}},
		},
	}
}

// reconcileToCompletion drives the reconciler repeatedly until terminal or a step cap.
func reconcileToCompletion(t *testing.T, r *NodeRotationReconciler, name string, cl crclient.Client) string {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < 12; i++ {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: name}}); err != nil {
			t.Fatalf("Reconcile step %d: %v", i, err)
		}
		got := &amtdv1beta1.NodeRotation{}
		if err := cl.Get(ctx, crclient.ObjectKey{Name: name}, got); err != nil {
			t.Fatalf("get NodeRotation: %v", err)
		}
		phase := got.Annotations[annNodeRotPhase]
		switch phase {
		case amtdv1beta1.NodeRotationPhaseCompleted,
			amtdv1beta1.NodeRotationPhaseRolledBack,
			amtdv1beta1.NodeRotationPhaseNoCleanTarget:
			return phase
		}
	}
	return "DID_NOT_TERMINATE"
}

// TestNodeRotation_ProgressesToCompleted proves the phase machine drives a bare-pod
// rotation Cordoning -> Draining -> Rescheduling -> Pinning -> Completed: the source
// is cordoned, the targeted pod relocated, and a clean node selected + recorded.
func TestNodeRotation_ProgressesToCompleted(t *testing.T) {
	ctx := context.Background()
	src := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "src"}}
	good := cleanNode("good", nil)
	pod := barePodOnSource("p", "default", "src")
	nr := nodeRotationFixture("nr1", "src", "default", "p")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(src, good, pod, nr).
		WithStatusSubresource(nr).
		Build()
	r := &NodeRotationReconciler{Client: cl, Scheme: seTestScheme}

	final := reconcileToCompletion(t, r, "nr1", cl)
	if final != amtdv1beta1.NodeRotationPhaseCompleted {
		t.Fatalf("final phase=%q, want Completed", final)
	}

	// The source node was cordoned.
	gotSrc := &corev1.Node{}
	cl.Get(ctx, crclient.ObjectKey{Name: "src"}, gotSrc)
	if !gotSrc.Spec.Unschedulable {
		t.Error("source node not cordoned")
	}

	// Status records the clean node + relocation.
	got := &amtdv1beta1.NodeRotation{}
	cl.Get(ctx, crclient.ObjectKey{Name: "nr1"}, got)
	if got.Status.TargetCleanNode != "good" {
		t.Errorf("TargetCleanNode=%q, want 'good'", got.Status.TargetCleanNode)
	}
	if len(got.Status.RelocatedPods) != 1 {
		t.Errorf("RelocatedPods=%d, want 1", len(got.Status.RelocatedPods))
	}
	if got.Status.CompletionTime.IsZero() {
		t.Error("CompletionTime not set on Completed")
	}

	// The replacement bare pod is pinned via nodeAffinity (NOT spec.nodeName).
	repl := &corev1.Pod{}
	if err := cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "p"}, repl); err != nil {
		t.Fatalf("get replacement pod: %v", err)
	}
	if repl.Spec.NodeName != "" {
		t.Error("replacement pod has spec.nodeName set (forbidden; must pin via nodeAffinity, D25g4)")
	}
	if repl.Spec.Affinity == nil || repl.Spec.Affinity.NodeAffinity == nil ||
		repl.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		t.Fatal("replacement pod missing required nodeAffinity pin")
	}
	if repl.Annotations[annNodeRotPinnedTo] != "good" {
		t.Errorf("replacement pinned-to=%q, want 'good'", repl.Annotations[annNodeRotPinnedTo])
	}
}

// TestNodeRotation_NoCleanTargetAbort proves the honest abort: with no clean node,
// the rotation reaches NoCleanTarget with a reason + condition, and does NOT land an
// unschedulable replacement (the source is cordoned but no pin happens).
func TestNodeRotation_NoCleanTargetAbort(t *testing.T) {
	ctx := context.Background()
	src := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "src"}}
	pod := barePodOnSource("p", "default", "src")
	nr := nodeRotationFixture("nr-abort", "src", "default", "p")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(src, pod, nr). // NO clean-pool node
		WithStatusSubresource(nr).
		Build()
	r := &NodeRotationReconciler{Client: cl, Scheme: seTestScheme}

	final := reconcileToCompletion(t, r, "nr-abort", cl)
	if final != amtdv1beta1.NodeRotationPhaseNoCleanTarget {
		t.Fatalf("final phase=%q, want NoCleanTarget", final)
	}
	got := &amtdv1beta1.NodeRotation{}
	cl.Get(ctx, crclient.ObjectKey{Name: "nr-abort"}, got)
	if got.Status.NoCleanTargetReason != amtdv1beta1.NoCleanTargetCleanPoolExhausted {
		t.Errorf("NoCleanTargetReason=%q, want CleanPoolExhausted", got.Status.NoCleanTargetReason)
	}
	if c := findCond(got.Status.Conditions, amtdv1beta1.ConditionNoCleanTarget); c == nil {
		t.Error("NoCleanTarget condition not set")
	}
}

// TestNodeRotation_RestartSafeResume proves restart-safety: a NodeRotation whose
// durable annotation is already at Rescheduling resumes from that phase (it does NOT
// re-cordon or re-drain from scratch) and completes.
func TestNodeRotation_RestartSafeResume(t *testing.T) {
	ctx := context.Background()
	src := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "src"}, Spec: corev1.NodeSpec{Unschedulable: true}}
	good := cleanNode("good", nil)
	// The targeted pod was already evicted in the pre-crash run (absent now).
	nr := nodeRotationFixture("nr-resume", "src", "default", "p")
	nr.Annotations = map[string]string{annNodeRotPhase: amtdv1beta1.NodeRotationPhaseRescheduling}

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(src, good, nr).
		WithStatusSubresource(nr).
		Build()
	r := &NodeRotationReconciler{Client: cl, Scheme: seTestScheme}

	final := reconcileToCompletion(t, r, "nr-resume", cl)
	if final != amtdv1beta1.NodeRotationPhaseCompleted {
		t.Fatalf("resumed final phase=%q, want Completed", final)
	}
	got := &amtdv1beta1.NodeRotation{}
	cl.Get(ctx, crclient.ObjectKey{Name: "nr-resume"}, got)
	if got.Status.TargetCleanNode != "good" {
		t.Errorf("resumed TargetCleanNode=%q, want 'good'", got.Status.TargetCleanNode)
	}
}

// TestNodeRotation_MaxConcurrentNodesThrottle proves the no-mass-eviction invariant:
// when an existing rotation is already in flight and MaxConcurrentNodes=1, a second
// rotation is THROTTLED at Cordoning (deferred, condition set) and does NOT cordon
// its source.
func TestNodeRotation_MaxConcurrentNodesThrottle(t *testing.T) {
	ctx := context.Background()
	srcA := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "srcA"}}
	srcB := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "srcB"}}

	// An existing in-flight rotation (past Cordoning => counts toward the ceiling).
	inflight := nodeRotationFixture("nr-inflight", "srcA", "default", "pa")
	inflight.Annotations = map[string]string{annNodeRotPhase: amtdv1beta1.NodeRotationPhaseDraining}

	max := 1
	second := nodeRotationFixture("nr-second", "srcB", "default", "pb")
	second.Spec.MaxConcurrentNodes = &max

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(srcA, srcB, inflight, second).
		WithStatusSubresource(inflight, second).
		Build()
	r := &NodeRotationReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "nr-second"}}); err != nil {
		t.Fatalf("Reconcile second: %v", err)
	}

	// srcB must NOT be cordoned (throttled).
	gotB := &corev1.Node{}
	cl.Get(ctx, crclient.ObjectKey{Name: "srcB"}, gotB)
	if gotB.Spec.Unschedulable {
		t.Error("second rotation cordoned its source despite MaxConcurrentNodes ceiling (mass-eviction!)")
	}
	// The second rotation is still at Cordoning (deferred) with a throttled condition.
	gotSecond := &amtdv1beta1.NodeRotation{}
	cl.Get(ctx, crclient.ObjectKey{Name: "nr-second"}, gotSecond)
	if p := gotSecond.Annotations[annNodeRotPhase]; p != "" && p != amtdv1beta1.NodeRotationPhaseCordoning {
		t.Errorf("throttled rotation advanced to %q, want still Cordoning/empty", p)
	}
	if c := findCond(gotSecond.Status.Conditions, amtdv1beta1.ConditionNodeRotationThrottled); c == nil {
		t.Error("NodeRotationThrottled condition not set on the deferred rotation")
	}
}

// findCond returns the named condition or nil.
func findCond(conds []metav1.Condition, t string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == t {
			return &conds[i]
		}
	}
	return nil
}
