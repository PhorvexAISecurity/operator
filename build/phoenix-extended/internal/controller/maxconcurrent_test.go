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

// Package controller — Phase 2 cap#4 executor enforcement test (h, D24).
//
// These fake-client tests prove the G6 MaxConcurrentRotations guard: with M pods
// already carrying the in-progress annotation under one AMTD whose
// MaxConcurrentRotations==M, the (M+1)th rotation is DEFERRED (skip +
// RotationThrottled/MaxConcurrentRotations, candidate pod survives, RotationCount
// unchanged); with the cap nil it PROCEEDS; with the cap not yet reached it
// PROCEEDS. The in-flight count is taken over the AMTD's PodSelector labels.
package controller

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// inFlightPod builds a pod carrying the AMTD's PodSelector labels (so it is
// counted by countInFlightRotations) and the in-progress rotation annotation.
func inFlightPod(name, namespace string, selector map[string]string) *corev1.Pod {
	labels := map[string]string{}
	for k, v := range selector {
		labels[k] = v
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: map[string]string{ROTATION_IN_PROGRESS: "true"},
			UID:         types.UID(name + "-uid"),
		},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "old:1"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// candidateManagedPod builds the AMTD-managed candidate pod (the (M+1)th) that the
// SecurityEvent targets. It carries the PodSelector labels too (a real managed pod
// would), the managed-by annotation, and is Ready. It does NOT yet carry the
// in-progress lock (that is set later in executeRotate), so at G6 time the cap is
// "others in flight".
func candidateManagedPod(name, namespace, amtdName string, selector map[string]string) *corev1.Pod {
	info := []AMTDManageInfo{{AMTDNamespace: namespace, AMTDName: amtdName, ManagedSince: "now"}}
	raw, _ := json.Marshal(info)
	labels := map[string]string{}
	for k, v := range selector {
		labels[k] = v
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: map[string]string{AMTD_MANAGED_BY: string(raw)},
			UID:         types.UID(name + "-uid"),
		},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "old:1"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	return pod
}

// TestMaxConcurrentRotations_DefersAtCap proves the (M+1)th rotation is deferred
// when M rotations are already in flight under a cap of M.
func TestMaxConcurrentRotations_DefersAtCap(t *testing.T) {
	selector := map[string]string{"app": "demo"}
	cap := 2
	ir := &amtdv1beta1.InferenceRotationSpec{
		GoldenImage:    "secure:2",
		RotationPolicy: &amtdv1beta1.RotationPolicy{MaxConcurrentRotations: &cap},
	}
	amtd := rotateAMTDWithOverlay("default", "amtd-cap", ir)

	// M == cap == 2 pods already in flight (carry the selector labels + in-progress).
	f1 := inFlightPod("inflight-1", "default", selector)
	f2 := inFlightPod("inflight-2", "default", selector)
	// The candidate (the 3rd) the event targets.
	cand := candidateManagedPod("cand-1", "default", "amtd-cap", selector)
	ev := timedSecurityEvent("evcap", "default/cand-1")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, f1, f2, cand, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	reconcileEvent(t, cl, "evcap")

	// Candidate must NOT be rotated (deferred): it survives, RotationCount unchanged.
	if !podExists(cl, "default", "cand-1") {
		t.Error("h) at cap: the candidate rotation must be DEFERRED (pod survives), not executed")
	}
	a := getAMTD(t, cl, "default", "amtd-cap")
	if a.Status.RotationCount != 0 {
		t.Errorf("h) at cap: RotationCount must stay 0 (deferred), got %d", a.Status.RotationCount)
	}
	if c := meta.FindStatusCondition(a.Status.Conditions, "RotationThrottled"); c == nil || c.Reason != "MaxConcurrentRotations" {
		t.Errorf("h) at cap: expected RotationThrottled/MaxConcurrentRotations condition, got %+v", c)
	}
}

// TestMaxConcurrentRotations_ProceedsUnderCap proves a rotation PROCEEDS when the
// in-flight count is below the cap (1 in flight, cap 2).
func TestMaxConcurrentRotations_ProceedsUnderCap(t *testing.T) {
	selector := map[string]string{"app": "demo"}
	cap := 2
	ir := &amtdv1beta1.InferenceRotationSpec{
		GoldenImage:    "secure:2",
		RotationPolicy: &amtdv1beta1.RotationPolicy{MaxConcurrentRotations: &cap},
	}
	amtd := rotateAMTDWithOverlay("default", "amtd-under", ir)

	// Only 1 in flight (< cap 2).
	f1 := inFlightPod("inflight-1", "default", selector)
	cand := candidateManagedPod("cand-1", "default", "amtd-under", selector)
	ev := timedSecurityEvent("evunder", "default/cand-1")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, f1, cand, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	reconcileEvent(t, cl, "evunder")

	// Candidate rotates (bare pod cold fallback => deleted), RotationCount advances.
	if podExists(cl, "default", "cand-1") {
		t.Error("h) under cap: the candidate rotation must PROCEED (pod cold-rescheduled/deleted)")
	}
	a := getAMTD(t, cl, "default", "amtd-under")
	if a.Status.RotationCount != 1 {
		t.Errorf("h) under cap: RotationCount = %d, want 1 (proceeded)", a.Status.RotationCount)
	}
}

// TestMaxConcurrentRotations_NilUnlimited proves a nil cap is unlimited: even with
// many in-flight rotations the candidate PROCEEDS (today's backward-compatible
// behavior; the guard is a no-op).
func TestMaxConcurrentRotations_NilUnlimited(t *testing.T) {
	selector := map[string]string{"app": "demo"}
	// No RotationPolicy at all => cap nil => unlimited.
	ir := &amtdv1beta1.InferenceRotationSpec{GoldenImage: "secure:2"}
	amtd := rotateAMTDWithOverlay("default", "amtd-nilcap", ir)

	// Several in flight, but cap is nil.
	f1 := inFlightPod("inflight-1", "default", selector)
	f2 := inFlightPod("inflight-2", "default", selector)
	f3 := inFlightPod("inflight-3", "default", selector)
	cand := candidateManagedPod("cand-1", "default", "amtd-nilcap", selector)
	ev := timedSecurityEvent("evnil", "default/cand-1")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, f1, f2, f3, cand, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	reconcileEvent(t, cl, "evnil")

	if podExists(cl, "default", "cand-1") {
		t.Error("h) nil cap (unlimited): the candidate must PROCEED regardless of in-flight count")
	}
	a := getAMTD(t, cl, "default", "amtd-nilcap")
	if a.Status.RotationCount != 1 {
		t.Errorf("h) nil cap: RotationCount = %d, want 1 (proceeded)", a.Status.RotationCount)
	}
}

// TestCountInFlightRotations_CountsOnlySelectorMatches proves the in-flight count
// is scoped to the AMTD's PodSelector (a pod NOT matching the selector, even with
// the in-progress annotation, is not counted).
func TestCountInFlightRotations_CountsOnlySelectorMatches(t *testing.T) {
	ctx := context.Background()
	selector := map[string]string{"app": "demo"}
	amtd := rotateAMTDWithOverlay("default", "amtd-count", &amtdv1beta1.InferenceRotationSpec{})

	matching1 := inFlightPod("m1", "default", selector)
	matching2 := inFlightPod("m2", "default", selector)
	// Different label => not in the selector => not counted.
	other := inFlightPod("o1", "default", map[string]string{"app": "other"})
	// A selector-matching pod WITHOUT the in-progress annotation => not counted.
	idle := inFlightPod("idle", "default", selector)
	delete(idle.Annotations, ROTATION_IN_PROGRESS)

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, matching1, matching2, other, idle).
		Build()

	got := countInFlightRotations(ctx, cl, amtd, logr.Discard())
	if got != 2 {
		t.Errorf("countInFlightRotations = %d, want 2 (only selector-matching + in-progress pods)", got)
	}
}
