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

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// cleanNode builds a clean-pool Node carrying the default clean-pool label.
func cleanNode(name string, extraLabels map[string]string) *corev1.Node {
	labels := map[string]string{
		"r6security.com/clean-pool": "true",
		corev1.LabelHostname:        name,
	}
	for k, v := range extraLabels {
		labels[k] = v
	}
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

// nodeOnHost builds a pod assigned to a node (for drain/co-tenant tests).
func nodeOnHost(name, ns, nodeName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       corev1.PodSpec{NodeName: nodeName, Containers: []corev1.Container{{Name: "app", Image: "img"}}},
	}
}

// TestNodeDrainer_CordonTaintUncordon proves the real source-node operations:
// Cordon sets Unschedulable, Taint appends the AMTD-managed NoSchedule taint,
// Uncordon + RemoveTaint revert them (D25g2).
func TestNodeDrainer_CordonTaintUncordon(t *testing.T) {
	ctx := context.Background()
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "src"}}
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(node).Build()
	d := &NodeDrainer{Client: cl}

	// Cordon.
	if err := d.Cordon(ctx, "src"); err != nil {
		t.Fatalf("Cordon: %v", err)
	}
	got := &corev1.Node{}
	if err := cl.Get(ctx, crclient.ObjectKey{Name: "src"}, got); err != nil {
		t.Fatalf("get node: %v", err)
	}
	if !got.Spec.Unschedulable {
		t.Fatal("Cordon did not set Unschedulable=true")
	}
	// Cordon is idempotent (no error on re-cordon).
	if err := d.Cordon(ctx, "src"); err != nil {
		t.Fatalf("re-Cordon (idempotent) failed: %v", err)
	}

	// Taint appends the AMTD NoSchedule taint.
	if err := d.Taint(ctx, "src"); err != nil {
		t.Fatalf("Taint: %v", err)
	}
	cl.Get(ctx, crclient.ObjectKey{Name: "src"}, got)
	foundTaint := false
	for _, tt := range got.Spec.Taints {
		if tt.Key == amtdNodeRotateTaintKey && tt.Effect == corev1.TaintEffectNoSchedule {
			foundTaint = true
		}
	}
	if !foundTaint {
		t.Fatal("Taint did not append the AMTD-managed NoSchedule taint")
	}
	// Taint idempotent (no duplicate).
	if err := d.Taint(ctx, "src"); err != nil {
		t.Fatalf("re-Taint: %v", err)
	}
	cl.Get(ctx, crclient.ObjectKey{Name: "src"}, got)
	n := 0
	for _, tt := range got.Spec.Taints {
		if tt.Key == amtdNodeRotateTaintKey {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("Taint not idempotent: %d AMTD taints, want 1", n)
	}

	// Uncordon + RemoveTaint revert.
	if err := d.Uncordon(ctx, "src"); err != nil {
		t.Fatalf("Uncordon: %v", err)
	}
	if err := d.RemoveTaint(ctx, "src"); err != nil {
		t.Fatalf("RemoveTaint: %v", err)
	}
	cl.Get(ctx, crclient.ObjectKey{Name: "src"}, got)
	if got.Spec.Unschedulable {
		t.Error("Uncordon did not clear Unschedulable")
	}
	for _, tt := range got.Spec.Taints {
		if tt.Key == amtdNodeRotateTaintKey {
			t.Error("RemoveTaint did not remove the AMTD taint")
		}
	}
}

// TestNodeDrainer_Drain_TargetedOnlyDefault proves the D25g3 default: with a nil
// DrainPolicy, ONLY the targeted pod is evicted off the source; co-tenants are left
// alone.
func TestNodeDrainer_Drain_TargetedOnlyDefault(t *testing.T) {
	ctx := context.Background()
	src := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "src"}}
	target := nodeOnHost("target-pod", "default", "src")
	coTenant := nodeOnHost("cotenant-pod", "default", "src")

	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(src, target, coTenant).Build()
	d := &NodeDrainer{Client: cl}

	res, err := d.Drain(ctx, "src", []corev1.Pod{*target}, nil, logr.Discard())
	if err != nil {
		t.Fatalf("Drain (targeted-only): %v", err)
	}
	if res.EvictedTargeted != 1 {
		t.Errorf("EvictedTargeted=%d, want 1", res.EvictedTargeted)
	}
	if res.EvictedCoTenants != 0 {
		t.Errorf("EvictedCoTenants=%d, want 0 in the targeted-only default", res.EvictedCoTenants)
	}

	// The targeted pod is gone (evicted); the co-tenant remains.
	if err := cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "target-pod"}, &corev1.Pod{}); err == nil {
		t.Error("targeted pod still present after Drain (should be evicted)")
	}
	if err := cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "cotenant-pod"}, &corev1.Pod{}); err != nil {
		t.Error("co-tenant pod was evicted in the targeted-only default (should be left alone)")
	}
}

// TestNodeDrainer_Drain_CoTenantOptIn proves co-tenant drain is opt-in: with
// DrainPolicy.DrainCoTenants=true the co-resident pod is also evicted, while a
// DaemonSet pod is skipped (D25g3).
func TestNodeDrainer_Drain_CoTenantOptIn(t *testing.T) {
	ctx := context.Background()
	src := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "src"}}
	target := nodeOnHost("target-pod", "default", "src")
	coTenant := nodeOnHost("cotenant-pod", "default", "src")
	dsPod := nodeOnHost("ds-pod", "default", "src")
	tru := true
	dsPod.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: "ds", Controller: &tru}}

	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(src, target, coTenant, dsPod).Build()
	d := &NodeDrainer{Client: cl}

	policy := &amtdv1beta1.DrainPolicy{DrainCoTenants: true}
	res, err := d.Drain(ctx, "src", []corev1.Pod{*target}, policy, logr.Discard())
	if err != nil {
		t.Fatalf("Drain (co-tenant): %v", err)
	}
	if res.EvictedTargeted != 1 {
		t.Errorf("EvictedTargeted=%d, want 1", res.EvictedTargeted)
	}
	if res.EvictedCoTenants != 1 {
		t.Errorf("EvictedCoTenants=%d, want 1 (the non-DaemonSet co-tenant)", res.EvictedCoTenants)
	}
	// The DaemonSet pod is skipped (still present).
	if err := cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "ds-pod"}, &corev1.Pod{}); err != nil {
		t.Error("DaemonSet pod was evicted (should be skipped by default co-tenant drain)")
	}
}

// TestCleanNodeSelector_PicksAndExcludes proves CleanNodeSelector picks a clean-pool
// node and EXCLUDES the source/cordoned/tainted nodes (D25g4).
func TestCleanNodeSelector_PicksAndExcludes(t *testing.T) {
	ctx := context.Background()
	src := cleanNode("src", nil) // even labeled clean, the source is excluded
	cordoned := cleanNode("cordoned", nil)
	cordoned.Spec.Unschedulable = true
	tainted := cleanNode("tainted", nil)
	tainted.Spec.Taints = []corev1.Taint{{Key: "k", Effect: corev1.TaintEffectNoSchedule}}
	good := cleanNode("good", nil)
	notInPool := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "other", Labels: map[string]string{corev1.LabelHostname: "other"}}}

	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(src, cordoned, tainted, good, notInPool).Build()
	s := &CleanNodeSelector{Client: cl}

	pod := nodeOnHost("p", "default", "src")
	exclude := map[string]struct{}{"src": {}}
	res, err := s.SelectCleanNode(ctx, pod, nil, exclude)
	if err != nil {
		t.Fatalf("SelectCleanNode: %v", err)
	}
	if res.NodeName != "good" {
		t.Errorf("SelectCleanNode=%q, want 'good' (the only schedulable, untainted, non-source clean-pool node)", res.NodeName)
	}
}

// TestCleanNodeSelector_NoCleanTarget proves the honest abort: when no clean-pool
// node qualifies, it returns an empty NodeName + CleanPoolExhausted reason (D25g4) —
// never landing an unschedulable pod.
func TestCleanNodeSelector_NoCleanTarget(t *testing.T) {
	ctx := context.Background()
	src := cleanNode("src", nil)
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(src).Build()
	s := &CleanNodeSelector{Client: cl}

	pod := nodeOnHost("p", "default", "src")
	exclude := map[string]struct{}{"src": {}}
	res, err := s.SelectCleanNode(ctx, pod, nil, exclude)
	if err != nil {
		t.Fatalf("SelectCleanNode: %v", err)
	}
	if res.NodeName != "" {
		t.Errorf("expected NoCleanTarget (empty NodeName), got %q", res.NodeName)
	}
	if res.Reason != amtdv1beta1.NoCleanTargetCleanPoolExhausted {
		t.Errorf("reason=%q, want CleanPoolExhausted", res.Reason)
	}
}

// TestCleanNodeSelector_PVCTopologyBound proves the PVC-topology preflight: a pod
// bound to a node-affined PV cannot relocate to a clean node that does not satisfy
// the PV's topology, yielding PVCTopologyBound (D25g4).
func TestCleanNodeSelector_PVCTopologyBound(t *testing.T) {
	ctx := context.Background()
	// The only clean-pool node is "good"; the PV binds the pod to node "elsewhere".
	good := cleanNode("good", nil)

	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv1"},
		Spec: corev1.PersistentVolumeSpec{
			NodeAffinity: &corev1.VolumeNodeAffinity{
				Required: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{MatchExpressions: []corev1.NodeSelectorRequirement{
							{Key: corev1.LabelHostname, Operator: corev1.NodeSelectorOpIn, Values: []string{"elsewhere"}},
						}},
					},
				},
			},
		},
	}
	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "claim1", Namespace: "default"},
		Spec:       corev1.PersistentVolumeClaimSpec{VolumeName: "pv1"},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "default"},
		Spec: corev1.PodSpec{
			NodeName: "src",
			Volumes: []corev1.Volume{{
				Name:         "data",
				VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "claim1"}},
			}},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(good, pv, pvc, pod).Build()
	s := &CleanNodeSelector{Client: cl}

	res, err := s.SelectCleanNode(ctx, pod, nil, map[string]struct{}{"src": {}})
	if err != nil {
		t.Fatalf("SelectCleanNode: %v", err)
	}
	if res.NodeName != "" {
		t.Errorf("expected PVCTopologyBound abort, got node %q", res.NodeName)
	}
	if res.Reason != amtdv1beta1.NoCleanTargetPVCTopologyBound {
		t.Errorf("reason=%q, want PVCTopologyBound", res.Reason)
	}
}
