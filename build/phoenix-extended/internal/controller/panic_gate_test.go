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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// panicAMTD builds a Scored AMTD whose scored Rotate strategy fires at
// score>=threshold, with N consecutive-high samples required and a recent prior
// rotation so the min-interval floor would block a NON-panic rotation. This
// isolates the panic G3-bypass.
func panicAMTD(ns, name, threshold string, n int) *amtdv1beta1.AdaptiveMovingTargetDefense {
	amtd := amtdScored(ns, name, &amtdv1beta1.AdaptiveRotationPolicy{
		PanicThreshold:         strptr(threshold),
		ConsecutiveHighSamples: intptr(n),
		EWMAAlpha:              strptr("1"), // alpha=1 => smoothed==score; deterministic panic
	}, threshold) // ScoreThreshold == panic threshold so the scored rule selects Rotate
	return amtd
}

// TestPanic_OnlyAfterNConsecutiveHigh proves the locked hysteresis: with N=3 and a
// recent prior rotation (min-interval NOT elapsed), the first TWO high scores do
// NOT panic (G3 floor still blocks => pod survives, no Panic condition), and the
// THIRD high score PANICS (bypasses the floor => pod rotated, Panic condition set).
func TestPanic_OnlyAfterNConsecutiveHigh(t *testing.T) {
	amtd := panicAMTD("default", "amtd-panic", "0.85", 3)
	// A prior rotation just happened so the min-interval floor blocks non-panic.
	amtd.Status.LastRotationTime = metav1.NewTime(time.Now())
	amtd.Status.RotationCount = 1
	pod := scoredPod("p1", "default", "amtd-panic")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod).WithStatusSubresource(amtd).Build()

	post := func(score string) {
		_ = cl.Delete(context.Background(), &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: "evp"}})
		if err := cl.Create(context.Background(), scoredEvent("evp", "default/p1", "PrometheusIntegrator", score)); err != nil {
			t.Fatalf("create event: %v", err)
		}
		if !podExists(cl, "default", "p1") {
			p := scoredPod("p1", "default", "amtd-panic")
			// keep the prior LastRotationTime recent so the floor still applies.
			_ = cl.Create(context.Background(), p)
		}
		reconcileEvent(t, cl, "evp")
	}

	// Sample 1 (high) -> count=1 < 3 => NO panic, floor blocks, pod survives.
	post("0.9")
	if !podExists(cl, "default", "p1") {
		t.Fatal("sample 1: must NOT panic (count<N); floor must block, pod survives")
	}
	a := getAMTD(t, cl, "default", "amtd-panic")
	if a.Status.ConsecutiveHighCount != 1 {
		t.Fatalf("sample 1: consec=%d want 1", a.Status.ConsecutiveHighCount)
	}
	if c := meta.FindStatusCondition(a.Status.Conditions, "Panic"); c != nil && c.Status == metav1.ConditionTrue {
		t.Error("sample 1: no Panic condition expected")
	}

	// Sample 2 (high) -> count=2 < 3 => still NO panic.
	post("0.92")
	if !podExists(cl, "default", "p1") {
		t.Fatal("sample 2: must NOT panic (count<N); pod survives")
	}
	a = getAMTD(t, cl, "default", "amtd-panic")
	if a.Status.ConsecutiveHighCount != 2 {
		t.Fatalf("sample 2: consec=%d want 2", a.Status.ConsecutiveHighCount)
	}

	// Sample 3 (high) -> count=3 >= 3 => PANIC: bypass floor, pod rotated.
	post("0.95")
	if podExists(cl, "default", "p1") {
		t.Error("sample 3: PANIC must bypass the min-interval floor and rotate (pod deleted)")
	}
	a = getAMTD(t, cl, "default", "amtd-panic")
	if c := meta.FindStatusCondition(a.Status.Conditions, "Panic"); c == nil || c.Status != metav1.ConditionTrue || c.Reason != "ScoreThresholdCrossed" {
		t.Errorf("sample 3: expected Panic/ScoreThresholdCrossed condition, got %+v", c)
	}
}

// TestPanic_SingleSpikeNoPanic proves a single 0.99 spike after zeros (count=1 < N)
// does NOT panic: the floor still blocks and the pod survives.
func TestPanic_SingleSpikeNoPanic(t *testing.T) {
	amtd := panicAMTD("default", "amtd-spike", "0.85", 3)
	amtd.Status.LastRotationTime = metav1.NewTime(time.Now()) // floor blocks non-panic
	amtd.Status.RotationCount = 1
	pod := scoredPod("p1", "default", "amtd-spike")
	ev := scoredEvent("evs", "default/p1", "PrometheusIntegrator", "0.99")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evs")

	if !podExists(cl, "default", "p1") {
		t.Error("single spike (count=1<N) must NOT panic; floor blocks, pod survives")
	}
	a := getAMTD(t, cl, "default", "amtd-spike")
	if a.Status.ConsecutiveHighCount != 1 {
		t.Errorf("single spike: consec=%d want 1", a.Status.ConsecutiveHighCount)
	}
	if c := meta.FindStatusCondition(a.Status.Conditions, "Panic"); c != nil && c.Status == metav1.ConditionTrue {
		t.Error("single spike must NOT set Panic condition")
	}
}

// TestPanic_DoesNotBypassReadiness proves panic bypasses ONLY the min-interval
// floor, NOT the G4 readiness gate: with N=1 (so the panic hysteresis arms on the
// first high score) AND a prior rotation recorded AND the target pod NOT Ready,
// the rotation is STILL blocked by readiness (pod survives, RotationThrottled/
// ReplacementNotReady recorded). This is the LOCKED guarantee (arch L330).
func TestPanic_DoesNotBypassReadiness(t *testing.T) {
	amtd := panicAMTD("default", "amtd-ready", "0.85", 1) // N=1 => panic arms immediately
	amtd.Status.LastRotationTime = metav1.NewTime(time.Now()) // floor would block (panic bypasses it)
	amtd.Status.RotationCount = 1
	// pod NOT Ready: readiness gate must still block (panic does NOT bypass G4).
	pod := managedOwnedPod("p1", "default", "amtd-ready", "", "", false, nil)
	ev := scoredEvent("evrd", "default/p1", "PrometheusIntegrator", "0.99")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evrd")

	if !podExists(cl, "default", "p1") {
		t.Error("panic must NOT bypass the readiness gate: a not-Ready replacement must block the rotation")
	}
	a := getAMTD(t, cl, "default", "amtd-ready")
	if c := meta.FindStatusCondition(a.Status.Conditions, "RotationThrottled"); c == nil || c.Reason != "ReplacementNotReady" {
		t.Errorf("panic+not-ready: expected RotationThrottled/ReplacementNotReady, got %+v", c)
	}
}

// TestScored_SelectsRotateAtThresholdNotBelow proves the scored rule selects Rotate
// at score>=threshold and NOT below (MatcherMode=Scored), reusing the matcher.
// No prior rotation => the first fire is not floor/readiness gated, so a selected
// Rotate actually deletes the pod.
func TestScored_SelectsRotateAtThresholdNotBelow(t *testing.T) {
	// At threshold: score 0.85 >= 0.85 => Rotate selected and fires.
	amtdHi := panicAMTD("default", "amtd-at", "0.85", 3)
	podHi := scoredPod("p1", "default", "amtd-at")
	evHi := scoredEvent("evhi", "default/p1", "PrometheusIntegrator", "0.85")
	clHi := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtdHi, podHi, evHi).WithStatusSubresource(amtdHi, evHi).Build()
	reconcileEvent(t, clHi, "evhi")
	if podExists(clHi, "default", "p1") {
		t.Error("score>=threshold must select Rotate and fire (pod deleted)")
	}

	// Below threshold: score 0.5 < 0.85 => scored rule does NOT select Rotate.
	amtdLo := panicAMTD("default", "amtd-below", "0.85", 3)
	podLo := scoredPod("p2", "default", "amtd-below")
	evLo := scoredEvent("evlo", "default/p2", "PrometheusIntegrator", "0.5")
	clLo := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtdLo, podLo, evLo).WithStatusSubresource(amtdLo, evLo).Build()
	reconcileEvent(t, clLo, "evlo")
	if !podExists(clLo, "default", "p2") {
		t.Error("score<threshold must NOT select Rotate (pod survives)")
	}
	// scoring still ran (the AMTD has AdaptiveRotation + Scored mode), but no action.
	a := getAMTD(t, clLo, "default", "amtd-below")
	if a.Status.LastObservedScore == "" {
		t.Error("scoring should still record the observed score even when no action fires")
	}
}

// ensure corev1 import used.
var _ = corev1.Pod{}
