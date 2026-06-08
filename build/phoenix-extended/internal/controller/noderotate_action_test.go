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

// nodeRotateAMTD builds an AMTD whose strategy maps a KubeArmor high event to a
// NodeRotate action (arch §2.1 Strategy[] expression). strategy "" => default Cordon.
func nodeRotateAMTD(namespace, name, strategy string) *amtdv1beta1.AdaptiveMovingTargetDefense {
	return &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{"app": "nim"},
			Strategy: []amtdv1beta1.ResponseStrategy{
				{
					Rule: amtdv1beta1.Rule{Source: "KubeArmorIntegrator", ThreatLevel: "high"},
					Action: amtdv1beta1.AMTDAction{NodeRotate: &amtdv1beta1.NodeRotateAction{
						Strategy:           strategy,
						TargetNodeSelector: map[string]string{"r6security.com/clean-pool": "true"},
					}},
				},
			},
		},
	}
}

// nodeRotatePod builds an AMTD-managed pod assigned to a node (the rotation subject).
func nodeRotatePod(name, ns, amtdName, nodeName string) *corev1.Pod {
	p := managedPod(name, ns, ns, amtdName)
	p.Spec.NodeName = nodeName
	return p
}

// kubeArmorEvent builds a {source:KubeArmorIntegrator, threatLevel} SecurityEvent.
func kubeArmorEvent(name, target, threatLevel string) *amtdv1beta1.SecurityEvent {
	return &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets:     []string{target},
			Rule:        amtdv1beta1.Rule{Source: "KubeArmorIntegrator", ThreatLevel: threatLevel},
			Description: "kubearmor high severity",
		},
	}
}

// TestNodeRotateAction_AllowedCreatesNodeRotation proves the wiring + the D26 ALLOW
// path: an allowlisted Source + at/above-floor ThreatLevel creates exactly one
// NodeRotation, sets AppliedAction="nodeRotate", and stamps the NIM in-progress lock.
func TestNodeRotateAction_AllowedCreatesNodeRotation(t *testing.T) {
	ctx := context.Background()
	amtd := nodeRotateAMTD("default", "amtd-node", "")
	pod := nodeRotatePod("nim", "default", "amtd-node", "worker-1")
	ev := kubeArmorEvent("ka-ev", "default/nim", "high")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, pod, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "ka-ev"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// Exactly one NodeRotation, sourced from the pod's node.
	var list amtdv1beta1.NodeRotationList
	if err := cl.List(ctx, &list); err != nil {
		t.Fatalf("list NodeRotations: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("got %d NodeRotations, want exactly 1", len(list.Items))
	}
	nr := list.Items[0]
	if nr.Spec.SourceNode != "worker-1" {
		t.Errorf("SourceNode=%q, want 'worker-1'", nr.Spec.SourceNode)
	}
	if nr.Spec.TriggerProvenance.Source != "KubeArmorIntegrator" {
		t.Errorf("TriggerProvenance.Source=%q, want KubeArmorIntegrator", nr.Spec.TriggerProvenance.Source)
	}
	if nr.Spec.EffectiveStrategy() != amtdv1beta1.NodeRotationStrategyCordon {
		t.Errorf("EffectiveStrategy=%q, want Cordon (default)", nr.Spec.EffectiveStrategy())
	}

	// AppliedAction recorded.
	gotEv := &amtdv1beta1.SecurityEvent{}
	cl.Get(ctx, crclient.ObjectKey{Name: "ka-ev"}, gotEv)
	if gotEv.Status.AppliedAction != "nodeRotate" {
		t.Errorf("AppliedAction=%q, want 'nodeRotate'", gotEv.Status.AppliedAction)
	}

	// NIM in-progress lock stamped on the targeted pod.
	gotPod := &corev1.Pod{}
	cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "nim"}, gotPod)
	if gotPod.Annotations[ROTATION_IN_PROGRESS] != "true" {
		t.Error("NIM in-progress lock not set on the targeted pod (double-evict risk)")
	}

	// Idempotence: re-reconcile creates no second NodeRotation.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "ka-ev"}}); err != nil {
		t.Fatalf("re-Reconcile: %v", err)
	}
	cl.List(ctx, &list)
	if len(list.Items) != 1 {
		t.Fatalf("idempotence broken: %d NodeRotations after re-reconcile, want 1", len(list.Items))
	}
}

// TestNodeRotateGate_BlocksNonAllowlistedSource proves the D26 hard gate: a
// non-allowlisted Source creates NO NodeRotation and records AppliedAction=
// "nodeRotate-denied" + a denied condition.
func TestNodeRotateGate_BlocksNonAllowlistedSource(t *testing.T) {
	ctx := context.Background()
	amtd := nodeRotateAMTD("default", "amtd-node", "")
	// Override the rule Source to a NON-allowlisted forged emitter so the event MATCHES
	// the rule (exact 3-string projection) but the D26 gate must still block on the
	// allowlist. The ThreatLevel stays at the matching 'high'.
	amtd.Spec.Strategy[0].Rule.Source = "ForgedIntegrator"
	pod := nodeRotatePod("nim", "default", "amtd-node", "worker-1")
	ev := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "forged-ev"},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets:     []string{"default/nim"},
			Rule:        amtdv1beta1.Rule{Source: "ForgedIntegrator", ThreatLevel: "high"},
			Description: "forged",
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, pod, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "forged-ev"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	var list amtdv1beta1.NodeRotationList
	cl.List(ctx, &list)
	if len(list.Items) != 0 {
		t.Fatalf("a forged/non-allowlisted Source created %d NodeRotations, want 0 (D26 hard gate)", len(list.Items))
	}
	gotEv := &amtdv1beta1.SecurityEvent{}
	cl.Get(ctx, crclient.ObjectKey{Name: "forged-ev"}, gotEv)
	if gotEv.Status.AppliedAction != "nodeRotate-denied" {
		t.Errorf("AppliedAction=%q, want 'nodeRotate-denied'", gotEv.Status.AppliedAction)
	}
	gotAMTD := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "amtd-node"}, gotAMTD)
	if c := findCond(gotAMTD.Status.Conditions, gateDeniedSourceNotAllowed); c == nil {
		t.Error("NodeRotateGatedSourceNotAllowed condition not recorded on the AMTD")
	}
}

// TestNodeRotateGate_BlocksBelowFloor proves the D26 ThreatLevel floor: an
// allowlisted Source but a below-floor ThreatLevel ('low') creates NO NodeRotation.
func TestNodeRotateGate_BlocksBelowFloor(t *testing.T) {
	ctx := context.Background()
	amtd := nodeRotateAMTD("default", "amtd-node", "")
	amtd.Spec.Strategy[0].Rule.ThreatLevel = "low"
	pod := nodeRotatePod("nim", "default", "amtd-node", "worker-1")
	ev := kubeArmorEvent("low-ev", "default/nim", "low")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, pod, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "low-ev"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var list amtdv1beta1.NodeRotationList
	cl.List(ctx, &list)
	if len(list.Items) != 0 {
		t.Fatalf("a below-floor ThreatLevel created %d NodeRotations, want 0 (D26 floor)", len(list.Items))
	}
	gotEv := &amtdv1beta1.SecurityEvent{}
	cl.Get(ctx, crclient.ObjectKey{Name: "low-ev"}, gotEv)
	if gotEv.Status.AppliedAction != "nodeRotate-denied" {
		t.Errorf("AppliedAction=%q, want 'nodeRotate-denied'", gotEv.Status.AppliedAction)
	}
}

// TestNodeRotateGate_DeleteNeedsApproval proves the D26 human-approval gate for the
// irreversible Delete disposition: an allowlisted+high event with Strategy=Delete is
// DENIED without approval, and ALLOWED once the approval annotation is present.
func TestNodeRotateGate_DeleteNeedsApproval(t *testing.T) {
	ctx := context.Background()

	// (1) Delete WITHOUT approval => denied, no NodeRotation.
	amtd := nodeRotateAMTD("default", "amtd-node", amtdv1beta1.NodeRotationStrategyDelete)
	pod := nodeRotatePod("nim", "default", "amtd-node", "worker-1")
	ev := kubeArmorEvent("del-ev", "default/nim", "high")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, pod, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "del-ev"}}); err != nil {
		t.Fatalf("Reconcile (no approval): %v", err)
	}
	var list amtdv1beta1.NodeRotationList
	cl.List(ctx, &list)
	if len(list.Items) != 0 {
		t.Fatalf("Delete WITHOUT approval created %d NodeRotations, want 0 (D26 human-approval)", len(list.Items))
	}
	gotEv := &amtdv1beta1.SecurityEvent{}
	cl.Get(ctx, crclient.ObjectKey{Name: "del-ev"}, gotEv)
	if gotEv.Status.AppliedAction != "nodeRotate-denied" {
		t.Errorf("AppliedAction=%q, want 'nodeRotate-denied' for Delete without approval", gotEv.Status.AppliedAction)
	}

	// (2) Delete WITH the explicit approval annotation => allowed, NodeRotation created.
	amtd2 := nodeRotateAMTD("default", "amtd-node2", amtdv1beta1.NodeRotationStrategyDelete)
	pod2 := nodeRotatePod("nim2", "default", "amtd-node2", "worker-2")
	ev2 := kubeArmorEvent("del-ev2", "default/nim2", "high")
	ev2.Annotations = map[string]string{nodeDeleteApprovalAnnotation: "true"}

	cl2 := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd2, pod2, ev2).
		WithStatusSubresource(amtd2, ev2).
		Build()
	r2 := &SecurityEventReconciler{Client: cl2, Scheme: seTestScheme}
	if _, err := r2.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "del-ev2"}}); err != nil {
		t.Fatalf("Reconcile (with approval): %v", err)
	}
	var list2 amtdv1beta1.NodeRotationList
	cl2.List(ctx, &list2)
	if len(list2.Items) != 1 {
		t.Fatalf("Delete WITH approval created %d NodeRotations, want 1", len(list2.Items))
	}
	if list2.Items[0].Spec.Strategy != amtdv1beta1.NodeRotationStrategyDelete {
		t.Errorf("Strategy=%q, want Delete", list2.Items[0].Spec.Strategy)
	}
}
