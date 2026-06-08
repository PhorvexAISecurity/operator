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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// regenerateAMTD builds an AMTD whose drift strategy maps to a Regenerate action
// referencing the named WorkloadBaseline (arch §2.1 Strategy[] expression
// {rule:{type:'drift',source:'FalcoIntegrator'}, action:{regenerate:{baselineRef}}}).
func regenerateAMTD(namespace, name, wbName string) *amtdv1beta1.AdaptiveMovingTargetDefense {
	return &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{"app": "nim"},
			Strategy: []amtdv1beta1.ResponseStrategy{
				{
					Rule: amtdv1beta1.Rule{Type: "drift", ThreatLevel: "high", Source: "FalcoIntegrator"},
					Action: amtdv1beta1.AMTDAction{Regenerate: &amtdv1beta1.RegenerateAction{
						BaselineRef: &amtdv1beta1.LocalRef{Name: wbName},
					}},
				},
			},
		},
	}
}

// driftSecurityEvent builds a Type:'drift' SecurityEvent targeting the pod (as the
// BaselineDriftReconciler would emit).
func driftSecurityEvent(name, target string) *amtdv1beta1.SecurityEvent {
	return &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets:     []string{target},
			Rule:        amtdv1beta1.Rule{Type: "drift", ThreatLevel: "high", Source: "FalcoIntegrator"},
			Description: "baseline drift",
			Evidence:    &amtdv1beta1.DriftEvidence{ObservedDigest: "sha256:bad", ExpectedDigest: testDigest},
		},
	}
}

// managedDeploymentPod builds a Deployment->RS->Pod chain where the pod also carries
// the AMTD managed-by annotation so the SecurityEvent reconciler will act on it.
func managedDeploymentPod(name, ns, amtdName, image string) (*appsv1.Deployment, *appsv1.ReplicaSet, *corev1.Pod) {
	dep, rs, pod := deploymentOwnedPod(name, ns, image)
	info := []AMTDManageInfo{{AMTDNamespace: ns, AMTDName: amtdName, ManagedSince: "now"}}
	raw, _ := json.Marshal(info)
	pod.ObjectMeta.Annotations = map[string]string{AMTD_MANAGED_BY: string(raw)}
	return dep, rs, pod
}

// TestRegenerateAction_WiredEndToEnd proves the FULL wiring: a matched
// {regenerate:{baselineRef}} action invokes BaselineRestorer.Regenerate (patching
// the top owner template to the golden digest) and sets
// SecurityEventStatus.AppliedAction="regenerate".
func TestRegenerateAction_WiredEndToEnd(t *testing.T) {
	ctx := context.Background()
	km := newECDSAKey(t)
	wb := wbFixture("nim-baseline", km.pubPEM, km.signECD(testDigest), true)
	amtd := regenerateAMTD("default", "amtd-drift", "nim-baseline")

	driftedDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dep, rs, pod := managedDeploymentPod("nim", "default", "amtd-drift", "registry/app@"+driftedDigest)
	ev := driftSecurityEvent("drift-ev", "default/nim-pod")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(wb, amtd, dep, rs, pod, ev).
		WithStatusSubresource(wb, amtd, ev).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "drift-ev"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The Deployment template was restored to the GOLDEN digest.
	gotDep := &appsv1.Deployment{}
	if err := cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "nim"}, gotDep); err != nil {
		t.Fatalf("get dep: %v", err)
	}
	if gotDep.Spec.Template.Spec.Containers[0].Image != "registry/app@"+testDigest {
		t.Errorf("Deployment template image=%q, want golden registry/app@%s", gotDep.Spec.Template.Spec.Containers[0].Image, testDigest)
	}

	// SecurityEventStatus.AppliedAction set.
	gotEv := &amtdv1beta1.SecurityEvent{}
	_ = cl.Get(ctx, crclient.ObjectKey{Name: "drift-ev"}, gotEv)
	if gotEv.Status.AppliedAction != "regenerate" {
		t.Errorf("AppliedAction=%q, want 'regenerate'", gotEv.Status.AppliedAction)
	}
}

// TestRegenerateAction_MissingBaselineIsNoOp proves a referenced-but-missing
// WorkloadBaseline is a recorded no-op (not an error that wedges the reconcile).
func TestRegenerateAction_MissingBaselineIsNoOp(t *testing.T) {
	ctx := context.Background()
	amtd := regenerateAMTD("default", "amtd-drift", "does-not-exist")
	_, _, pod := managedDeploymentPod("nim", "default", "amtd-drift", "registry/app@sha256:bad")
	ev := driftSecurityEvent("drift-ev2", "default/nim-pod")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, pod, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "drift-ev2"}}); err != nil {
		t.Fatalf("Reconcile (missing baseline should be a no-op): %v", err)
	}
	gotEv := &amtdv1beta1.SecurityEvent{}
	_ = cl.Get(ctx, crclient.ObjectKey{Name: "drift-ev2"}, gotEv)
	if gotEv.Status.AppliedAction != "regenerate-notfound" {
		t.Errorf("AppliedAction=%q, want 'regenerate-notfound'", gotEv.Status.AppliedAction)
	}
}

// TestRegenerateAction_UnverifiableTarget_Aborts proves the wired path also honors
// verify-before-recreate: an unverifiable target leaves the workload untouched and
// records a 'regenerate-aborted' outcome (no forged success).
func TestRegenerateAction_UnverifiableTarget_Aborts(t *testing.T) {
	ctx := context.Background()
	signer := newECDSAKey(t)
	trusted := newECDSAKey(t)
	wb := wbFixture("nim-baseline", trusted.pubPEM, signer.signECD(testDigest), true) // wrong-key sig
	amtd := regenerateAMTD("default", "amtd-drift", "nim-baseline")

	driftedDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dep, rs, pod := managedDeploymentPod("nim", "default", "amtd-drift", "registry/app@"+driftedDigest)
	ev := driftSecurityEvent("drift-ev3", "default/nim-pod")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(wb, amtd, dep, rs, pod, ev).
		WithStatusSubresource(wb, amtd, ev).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "drift-ev3"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// Owner untouched.
	gotDep := &appsv1.Deployment{}
	_ = cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "nim"}, gotDep)
	if gotDep.Spec.Template.Spec.Containers[0].Image != "registry/app@"+driftedDigest {
		t.Errorf("owner template must be untouched on verify abort, got %q", gotDep.Spec.Template.Spec.Containers[0].Image)
	}
	gotEv := &amtdv1beta1.SecurityEvent{}
	_ = cl.Get(ctx, crclient.ObjectKey{Name: "drift-ev3"}, gotEv)
	if gotEv.Status.AppliedAction != "regenerate-aborted" {
		t.Errorf("AppliedAction=%q, want 'regenerate-aborted'", gotEv.Status.AppliedAction)
	}
}
