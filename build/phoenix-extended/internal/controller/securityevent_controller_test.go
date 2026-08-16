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
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

var seTestScheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(seTestScheme))
	utilruntime.Must(amtdv1beta1.AddToScheme(seTestScheme))
}

// managedPod builds an AMTD-managed pod whose managed-by annotation points at the
// given AMTD (namespace/name), as the AMTD reconciler would stamp it.
func managedPod(name, namespace, amtdNamespace, amtdName string) *corev1.Pod {
	info := []AMTDManageInfo{{AMTDNamespace: amtdNamespace, AMTDName: amtdName, ManagedSince: "now"}}
	raw, _ := json.Marshal(info)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				AMTD_MANAGED_BY: string(raw),
			},
		},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "test"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func timedRotateAMTD(namespace, name string) *amtdv1beta1.AdaptiveMovingTargetDefense {
	return &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{"app": "demo"},
			Strategy: []amtdv1beta1.ResponseStrategy{
				{
					Rule:   amtdv1beta1.Rule{Type: TriggerTypeTimed, ThreatLevel: "info", Source: TriggerSourceTimeBasedTrigger},
					Action: amtdv1beta1.AMTDAction{Rotate: &amtdv1beta1.RotateAction{}},
				},
			},
		},
	}
}

func timedSecurityEvent(name, target string) *amtdv1beta1.SecurityEvent {
	return &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets:     []string{target},
			Rule:        amtdv1beta1.Rule{Type: TriggerTypeTimed, ThreatLevel: "info", Source: TriggerSourceTimeBasedTrigger},
			Description: "timed rotation",
		},
	}
}

// TestSecurityEventReconciler_Rotate_TimedReschedule proves the dissolved NIM gate:
// a {type:'timed', source:'TimeBasedTrigger'} -> {rotate:{}} strategy, triggered by
// a matching timed SecurityEvent, reschedules the pod end-to-end through the CRD
// (NIM annotations stamped + pod deleted) — reproducing today's NIM-enhanced restart
// via the Rotate branch.
func TestSecurityEventReconciler_Rotate_TimedReschedule(t *testing.T) {
	ctx := context.Background()
	amtd := timedRotateAMTD("default", "amtd-demo")
	pod := managedPod("test-pod", "default", "default", "amtd-demo")
	ev := timedSecurityEvent("timed-ev", "default/test-pod")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, pod, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	_, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "timed-ev"}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The Rotate branch performs an annotate-then-delete reschedule, so the pod
	// must be gone (the owning controller would recreate it in a real cluster).
	var after corev1.Pod
	if err := cl.Get(ctx, crclient.ObjectKeyFromObject(pod), &after); err == nil {
		t.Error("expected pod to be deleted by the Phase 0 Rotate branch (cold reschedule)")
	}
}

// TestSecurityEventReconciler_ExactMatch_DeleteStillWorks proves backward
// compatibility: a legacy exact {type,threatLevel,source} -> {delete:{}} strategy
// still selects and deletes, identical to today.
func TestSecurityEventReconciler_ExactMatch_DeleteStillWorks(t *testing.T) {
	ctx := context.Background()
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: "amtd-del", Namespace: "default"},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{"app": "demo"},
			Strategy: []amtdv1beta1.ResponseStrategy{
				{
					Rule:   amtdv1beta1.Rule{Type: TriggerTypeTimed, ThreatLevel: "info", Source: TriggerSourceTimeBasedTrigger},
					Action: amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}},
				},
			},
		},
	}
	pod := managedPod("del-pod", "default", "default", "amtd-del")
	ev := timedSecurityEvent("del-ev", "default/del-pod")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, pod, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "del-ev"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var after corev1.Pod
	if err := cl.Get(ctx, crclient.ObjectKeyFromObject(pod), &after); err == nil {
		t.Error("exact {timed,info,TimeBasedTrigger} -> delete should still delete the pod")
	}
}

// TestSecurityEventReconciler_QuarantineReusesPolicyAndRelabelsReplacementPod
// covers the production regression where a deterministic deny-all NetworkPolicy
// survived an older pod. The replacement pod had no selector label, and the
// quarantine branch skipped all relabeling merely because the policy already
// existed, so a SecurityEvent was recorded as applied without isolating anything.
func TestSecurityEventReconciler_QuarantineReusesPolicyAndRelabelsReplacementPod(t *testing.T) {
	ctx := context.Background()
	rule := amtdv1beta1.Rule{Type: "phorvex.quarantine", ThreatLevel: "high", Source: "PhorvexController"}
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: "phorvex-nats", Namespace: "nats", UID: "amtd-uid"},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{"r6th.io/rotation-target": "true"},
			Strategy: []amtdv1beta1.ResponseStrategy{{
				Rule:   rule,
				Action: amtdv1beta1.AMTDAction{Quarantine: &amtdv1beta1.QuarantineAction{}},
			}},
		},
	}
	pod := managedPod("nats-0", "nats", "nats", "phorvex-nats")
	pod.Labels = map[string]string{
		"app":                     "nats",
		"r6th.io/rotation-target": "true",
	}
	isController := true
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "StatefulSet", Name: "nats", UID: "statefulset-uid", Controller: &isController,
	}}
	event := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "quarantine-event"},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets: []string{"nats/nats-0"}, Rule: rule, Description: "stateful quarantine",
		},
	}
	policyName := "nats-nats-0-policy"
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: "nats"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{AMTD_NETWORK_POLICY: policyName}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{},
			Egress:      []networkingv1.NetworkPolicyEgressRule{},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(amtd, pod, event, policy).Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}
	result, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: event.Name}})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.RequeueAfter == 0 {
		t.Fatal("expected requeue while the StatefulSet still owns the isolated pod")
	}

	var gotPod corev1.Pod
	if err := cl.Get(ctx, crclient.ObjectKeyFromObject(pod), &gotPod); err != nil {
		t.Fatalf("get quarantined pod: %v", err)
	}
	if got := gotPod.Labels[AMTD_NETWORK_POLICY]; got != policyName {
		t.Fatalf("quarantine selector label = %q, want %q", got, policyName)
	}
	if gotPod.Labels["app"] != "" || gotPod.Annotations["app"] != "nats" {
		t.Fatalf("non-AMTD label was not preserved under annotations: labels=%v annotations=%v", gotPod.Labels, gotPod.Annotations)
	}

	var gotPolicy networkingv1.NetworkPolicy
	if err := cl.Get(ctx, crclient.ObjectKeyFromObject(policy), &gotPolicy); err != nil {
		t.Fatalf("get reused NetworkPolicy: %v", err)
	}
	if got := gotPolicy.Spec.PodSelector.MatchLabels[AMTD_NETWORK_POLICY]; got != policyName {
		t.Fatalf("NetworkPolicy selector = %q, want %q", got, policyName)
	}
	if len(gotPolicy.Spec.Ingress) != 0 || len(gotPolicy.Spec.Egress) != 0 {
		t.Fatalf("quarantine policy must remain deny-all: ingress=%v egress=%v", gotPolicy.Spec.Ingress, gotPolicy.Spec.Egress)
	}
}

// TestSecurityEventReconciler_ExactMode_ScoredClauseInert proves a scored clause
// is INERT under the default Exact MatcherMode and that a MatcherModeWarning
// condition is recorded on the AMTD status (zero behavior change + observability).
func TestSecurityEventReconciler_ExactMode_ScoredClauseInert(t *testing.T) {
	ctx := context.Background()
	score := "0.99"
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: "amtd-scored", Namespace: "default"},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{"app": "demo"},
			// MatcherMode left empty => Exact (default).
			Strategy: []amtdv1beta1.ResponseStrategy{
				{
					Rule: amtdv1beta1.Rule{
						Source:         "FalcoIntegrator",
						ScoreThreshold: &score,
					},
					Action: amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}},
				},
			},
		},
	}
	pod := managedPod("scored-pod", "default", "default", "amtd-scored")
	// Event carries a high score and the right source; under Scored mode the clause
	// would match. Under Exact mode the clause is stripped, leaving the bare
	// projection {source:FalcoIntegrator} which does NOT equal this event's full
	// 3-string projection (the event has an empty Type/ThreatLevel here too, so the
	// projection actually matches — to make inertness observable we give the event a
	// non-empty ThreatLevel so the stripped exact rule fails).
	hi := "0.99"
	ev := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "scored-ev"},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets:      []string{"default/scored-pod"},
			Rule:         amtdv1beta1.Rule{Source: "FalcoIntegrator", ThreatLevel: "critical"},
			Description:  "panic",
			AnomalyScore: &hi,
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, pod, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "scored-ev"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// Inert: the scored clause did not select Delete, so the pod survives.
	var after corev1.Pod
	if err := cl.Get(ctx, crclient.ObjectKeyFromObject(pod), &after); err != nil {
		t.Errorf("scored clause must be INERT under Exact mode; pod should survive: %v", err)
	}

	// Observable: a MatcherModeWarning condition is set on the AMTD.
	var gotAMTD amtdv1beta1.AdaptiveMovingTargetDefense
	if err := cl.Get(ctx, crclient.ObjectKey{Name: "amtd-scored", Namespace: "default"}, &gotAMTD); err != nil {
		t.Fatalf("get AMTD: %v", err)
	}
	if meta.FindStatusCondition(gotAMTD.Status.Conditions, "MatcherModeWarning") == nil {
		t.Error("expected a MatcherModeWarning condition on the AMTD status when a scored clause is inert under Exact mode")
	}
}

// TestSecurityEventReconciler_ScoredMode_PanicSelectsRotate proves the scored path
// fires under MatcherMode=Scored: a Source-guarded anomalyScore>=threshold selects
// the Rotate action and reschedules the pod.
func TestSecurityEventReconciler_ScoredMode_PanicSelectsRotate(t *testing.T) {
	ctx := context.Background()
	thr := "0.85"
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: "amtd-panic", Namespace: "default"},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{"app": "demo"},
			MatcherMode: amtdv1beta1.MatcherModeScored,
			Strategy: []amtdv1beta1.ResponseStrategy{
				{
					Rule: amtdv1beta1.Rule{
						Source: "FalcoIntegrator",
						Match:  []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Gte", Value: thr}},
					},
					Action: amtdv1beta1.AMTDAction{Rotate: &amtdv1beta1.RotateAction{}},
				},
			},
		},
	}
	pod := managedPod("panic-pod", "default", "default", "amtd-panic")
	hi := "0.90"
	ev := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "panic-ev"},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets:      []string{"default/panic-pod"},
			Rule:         amtdv1beta1.Rule{Source: "FalcoIntegrator"},
			Description:  "panic",
			AnomalyScore: &hi,
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, pod, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "panic-ev"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	var after corev1.Pod
	if err := cl.Get(ctx, crclient.ObjectKeyFromObject(pod), &after); err == nil {
		t.Error("scored panic (anomalyScore 0.90 >= 0.85) should select Rotate and reschedule the pod")
	}
}
