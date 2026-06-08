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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// warmSwapAMTD builds an AMTD whose timed strategy maps to a WarmSwap action
// referencing the named WarmInferenceSet (arch §2.1 Strategy[] expression).
func warmSwapAMTD(namespace, name, wisName string) *amtdv1beta1.AdaptiveMovingTargetDefense {
	return &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{"app": "demo"},
			Strategy: []amtdv1beta1.ResponseStrategy{
				{
					Rule: amtdv1beta1.Rule{Type: TriggerTypeTimed, ThreatLevel: "info", Source: TriggerSourceTimeBasedTrigger},
					Action: amtdv1beta1.AMTDAction{WarmSwap: &amtdv1beta1.WarmSwapAction{
						WarmInferenceSetRef: &amtdv1beta1.LocalRef{Name: wisName},
					}},
				},
			},
		},
	}
}

// TestWarmSwapAction_SetsRequestAndOutcome proves the wiring: a matched
// {warmSwap:{warmInferenceSetRef:{name}}} action sets the referenced
// WarmInferenceSet's Spec.SwapRequest (restart-safe progressive model) and records
// SecurityEventStatus.AppliedAction="warmSwap". The action does NOT cut over inline —
// progression is the WarmInferenceSet reconciler's job.
func TestWarmSwapAction_SetsRequestAndOutcome(t *testing.T) {
	ctx := context.Background()
	amtd := warmSwapAMTD("default", "amtd-warm", "nim-pool")
	pod := managedPod("warm-pod", "default", "default", "amtd-warm")
	ev := timedSecurityEvent("warm-ev", "default/warm-pod")
	wis := wisFixture("default", "nim-pool", 2)

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, pod, ev, wis).
		WithStatusSubresource(amtd, ev, wis).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "warm-ev"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// The WarmInferenceSet now carries a SwapRequest keyed by the event name.
	gotWIS := &amtdv1beta1.WarmInferenceSet{}
	if err := cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "nim-pool"}, gotWIS); err != nil {
		t.Fatalf("get WIS: %v", err)
	}
	if gotWIS.Spec.SwapRequest == nil {
		t.Fatal("WarmSwap action did not set Spec.SwapRequest on the referenced WarmInferenceSet")
	}
	if gotWIS.Spec.SwapRequest.RequestID != "warm-ev" {
		t.Errorf("SwapRequest.RequestID=%q, want the event name 'warm-ev'", gotWIS.Spec.SwapRequest.RequestID)
	}

	// The per-event outcome is recorded.
	gotEv := &amtdv1beta1.SecurityEvent{}
	if err := cl.Get(ctx, crclient.ObjectKey{Name: "warm-ev"}, gotEv); err != nil {
		t.Fatalf("get event: %v", err)
	}
	if gotEv.Status.AppliedAction != "warmSwap" {
		t.Errorf("SecurityEventStatus.AppliedAction=%q, want 'warmSwap'", gotEv.Status.AppliedAction)
	}
}

// TestWarmSwapAction_DrainOverridePropagates proves the action's DrainTimeoutSeconds
// override is carried into the swap request.
func TestWarmSwapAction_DrainOverridePropagates(t *testing.T) {
	ctx := context.Background()
	amtd := warmSwapAMTD("default", "amtd-warm", "nim-pool")
	drain := int64(7)
	amtd.Spec.Strategy[0].Action.WarmSwap.DrainTimeoutSeconds = &drain
	pod := managedPod("warm-pod", "default", "default", "amtd-warm")
	ev := timedSecurityEvent("warm-ev2", "default/warm-pod")
	wis := wisFixture("default", "nim-pool", 2)

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, pod, ev, wis).
		WithStatusSubresource(amtd, ev, wis).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "warm-ev2"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	gotWIS := &amtdv1beta1.WarmInferenceSet{}
	if err := cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "nim-pool"}, gotWIS); err != nil {
		t.Fatalf("get WIS: %v", err)
	}
	if gotWIS.Spec.SwapRequest == nil || gotWIS.Spec.SwapRequest.DrainTimeoutSeconds == nil {
		t.Fatal("drain override not propagated to SwapRequest")
	}
	if *gotWIS.Spec.SwapRequest.DrainTimeoutSeconds != 7 {
		t.Errorf("SwapRequest.DrainTimeoutSeconds=%d, want 7", *gotWIS.Spec.SwapRequest.DrainTimeoutSeconds)
	}
}

// TestWarmSwapAction_MissingWISIsNoOp proves a referenced-but-missing WarmInferenceSet
// is a recorded no-op (not an error that wedges the reconcile).
func TestWarmSwapAction_MissingWISIsNoOp(t *testing.T) {
	ctx := context.Background()
	amtd := warmSwapAMTD("default", "amtd-warm", "does-not-exist")
	pod := managedPod("warm-pod", "default", "default", "amtd-warm")
	ev := timedSecurityEvent("warm-ev3", "default/warm-pod")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, pod, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "warm-ev3"}}); err != nil {
		t.Fatalf("Reconcile (missing WIS should be a no-op, not an error): %v", err)
	}
	gotEv := &amtdv1beta1.SecurityEvent{}
	if err := cl.Get(ctx, crclient.ObjectKey{Name: "warm-ev3"}, gotEv); err != nil {
		t.Fatalf("get event: %v", err)
	}
	if gotEv.Status.AppliedAction != "warmSwap-notfound" {
		t.Errorf("AppliedAction=%q, want 'warmSwap-notfound' for a missing WIS", gotEv.Status.AppliedAction)
	}
}
