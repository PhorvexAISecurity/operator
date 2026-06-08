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
	"math"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// getEvent fetches a SecurityEvent by name (cluster-scoped).
func getEvent(t *testing.T, cl crclient.Client, name string) *amtdv1beta1.SecurityEvent {
	t.Helper()
	e := &amtdv1beta1.SecurityEvent{}
	if err := cl.Get(context.Background(), types.NamespacedName{Name: name}, e); err != nil {
		t.Fatalf("get event %s: %v", name, err)
	}
	return e
}

// scoredPod builds an AMTD-managed (not owner-bound) pod for the scored path; it
// is Ready so readiness never blocks the first rotation.
func scoredPod(name, ns, amtdName string) *corev1.Pod {
	return managedOwnedPod(name, ns, amtdName, "", "", true, nil)
}

// TestScoring_TrustedScoreWritesAllFields proves the trusted-Source happy path:
// a Prometheus-sourced score "0.5" writes AMTD Status.SmoothedScore (=alpha*0.5
// with prev 0), LastObservedScore="0.5", CurrentInterval, and the SecurityEvent
// Status.ObservedScore + ComputedInterval. (Phase-3 §2.3 status writes.)
func TestScoring_TrustedScoreWritesAllFields(t *testing.T) {
	amtd := amtdScored("default", "amtd-sc", &amtdv1beta1.AdaptiveRotationPolicy{
		EWMAAlpha: strptr("0.3"),
	}, "")
	// give it a non-default interval band for a deterministic ComputedInterval.
	amtd.Spec.InferenceRotation.RotationPolicy = &amtdv1beta1.RotationPolicy{
		BaseInterval: &metav1.Duration{Duration: 10 * time.Minute},
		MinInterval:  &metav1.Duration{Duration: 1 * time.Minute},
	}
	pod := scoredPod("p1", "default", "amtd-sc")
	ev := scoredEvent("ev-sc", "default/p1", "PrometheusIntegrator", "0.5")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "ev-sc")

	a := getAMTD(t, cl, "default", "amtd-sc")
	// smoothed = 0.3*0.5 + 0.7*0 = 0.15
	if v, ok := parseScore(a.Status.SmoothedScore); !ok || math.Abs(v-0.15) > 1e-6 {
		t.Errorf("SmoothedScore = %q, want ~0.15", a.Status.SmoothedScore)
	}
	if a.Status.LastObservedScore == "" {
		t.Error("LastObservedScore must be set on a trusted scored event")
	}
	if a.Status.CurrentInterval.Duration == 0 {
		t.Error("CurrentInterval must be set")
	}
	// interval = 10m - 0.15*(10m-1m) = 10m - 1.35m = 8.65m
	wantInterval := 10*time.Minute - time.Duration(0.15*float64(9*time.Minute))
	if a.Status.CurrentInterval.Duration != wantInterval {
		t.Errorf("CurrentInterval = %s, want %s", a.Status.CurrentInterval.Duration, wantInterval)
	}
	e := getEvent(t, cl, "ev-sc")
	if e.Status.ObservedScore == "" {
		t.Error("SecurityEvent.Status.ObservedScore must be set")
	}
	if e.Status.ComputedInterval.Duration != wantInterval {
		t.Errorf("SecurityEvent.Status.ComputedInterval = %s, want %s", e.Status.ComputedInterval.Duration, wantInterval)
	}
}

// TestScoring_ProvenanceUntrustedIgnored proves a non-trusted Source ("EvilWorkload")
// has its score ignored even with AnomalyScore="0.99": no SmoothedScore /
// LastObservedScore is written and no panic. (D26g defense-in-depth.)
func TestScoring_ProvenanceUntrustedIgnored(t *testing.T) {
	amtd := amtdScored("default", "amtd-prov", &amtdv1beta1.AdaptiveRotationPolicy{
		PanicThreshold:         strptr("0.85"),
		ConsecutiveHighSamples: intptr(1), // even N=1 must not panic from an ignored score
	}, "")
	pod := scoredPod("p1", "default", "amtd-prov")
	ev := scoredEvent("ev-evil", "default/p1", "EvilWorkload", "0.99")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "ev-evil")

	a := getAMTD(t, cl, "default", "amtd-prov")
	if a.Status.SmoothedScore != "" {
		t.Errorf("untrusted score must NOT advance SmoothedScore, got %q", a.Status.SmoothedScore)
	}
	if a.Status.LastObservedScore != "" {
		t.Errorf("untrusted score must NOT set LastObservedScore, got %q", a.Status.LastObservedScore)
	}
	if c := meta.FindStatusCondition(a.Status.Conditions, "Panic"); c != nil && c.Status == metav1.ConditionTrue {
		t.Error("untrusted score must NOT panic")
	}
}

// TestScoring_ConsecutiveHighResets drives the sequence high,high,LOW,high through
// successive reconciles and asserts ConsecutiveHighCount = 1,2,0,1. The pod
// survives each cycle because we set BaseInterval/MinInterval so a non-panic score
// is throttled by the floor after the first fire — but we isolate the COUNTER by
// using fresh pods/events per step and reading the persisted count.
func TestScoring_ConsecutiveHighResets(t *testing.T) {
	thr := "0.8"
	amtd := amtdScored("default", "amtd-cons", &amtdv1beta1.AdaptiveRotationPolicy{
		PanicThreshold:         strptr(thr),
		ConsecutiveHighSamples: intptr(99), // very high N so no panic interferes with counter test
		EWMAAlpha:              strptr("1"), // alpha=1 => smoothed==score, deterministic
	}, "")
	pod := scoredPod("p1", "default", "amtd-cons")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod).WithStatusSubresource(amtd).Build()

	type step struct {
		score string
		want  int
	}
	steps := []step{{"0.9", 1}, {"0.95", 2}, {"0.1", 0}, {"0.9", 1}}
	for i, s := range steps {
		ev := scoredEvent("evc", "default/p1", "PrometheusIntegrator", s.score)
		// recreate the event each step (cluster-scoped, same name reused).
		_ = cl.Delete(context.Background(), &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: "evc"}})
		if err := cl.Create(context.Background(), ev); err != nil {
			t.Fatalf("step %d create event: %v", i, err)
		}
		// re-create the pod if a prior step rotated (deleted) it.
		if !podExists(cl, "default", "p1") {
			_ = cl.Create(context.Background(), scoredPod("p1", "default", "amtd-cons"))
		}
		reconcileEvent(t, cl, "evc")
		a := getAMTD(t, cl, "default", "amtd-cons")
		if a.Status.ConsecutiveHighCount != s.want {
			t.Errorf("step %d (score %s): ConsecutiveHighCount = %d, want %d", i, s.score, a.Status.ConsecutiveHighCount, s.want)
		}
	}
}

// TestScoring_StalenessDecaysToZero proves a stale event (creationTimestamp older
// than StalenessWindow) decays its effective score to 0: SmoothedScore moves
// toward 0, ConsecutiveHighCount resets to 0, and no panic — even though the raw
// AnomalyScore is 0.99. (D25 staleness.)
func TestScoring_StalenessDecaysToZero(t *testing.T) {
	amtd := amtdScored("default", "amtd-stale", &amtdv1beta1.AdaptiveRotationPolicy{
		PanicThreshold:         strptr("0.85"),
		ConsecutiveHighSamples: intptr(1),
		EWMAAlpha:              strptr("1"), // alpha=1 => smoothed==effective score
		StalenessWindow:        &metav1.Duration{Duration: 1 * time.Minute},
	}, "")
	// seed a prior high consecutive count to prove the stale sample RESETS it.
	amtd.Status.ConsecutiveHighCount = 5
	amtd.Status.SmoothedScore = "0.9"
	pod := scoredPod("p1", "default", "amtd-stale")
	ev := scoredEvent("ev-stale", "default/p1", "PrometheusIntegrator", "0.99")
	ev.CreationTimestamp = metav1.NewTime(time.Now().Add(-10 * time.Minute)) // older than 1m window
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "ev-stale")

	a := getAMTD(t, cl, "default", "amtd-stale")
	// alpha=1, effective=0 => smoothed=0
	if v, _ := parseScore(a.Status.SmoothedScore); v != 0 {
		t.Errorf("stale score must decay SmoothedScore to 0, got %q", a.Status.SmoothedScore)
	}
	if a.Status.ConsecutiveHighCount != 0 {
		t.Errorf("stale score (effective 0 < threshold) must reset ConsecutiveHighCount to 0, got %d", a.Status.ConsecutiveHighCount)
	}
	if c := meta.FindStatusCondition(a.Status.Conditions, "Panic"); c != nil && c.Status == metav1.ConditionTrue {
		t.Error("a stale score must NOT panic")
	}
	// raw score kept for audit.
	if a.Status.LastObservedScore == "" {
		t.Error("raw score should still be recorded for audit (LastObservedScore)")
	}
}

// TestScoring_ExactModeUnchanged proves that with MatcherMode=Exact (default) the
// scoring block is SKIPPED ENTIRELY: no SmoothedScore / LastObservedScore /
// ConsecutiveHighCount is written, even with a trusted high AnomalyScore. The
// exact dispatch still fires the matched Rotate (byte-compat).
func TestScoring_ExactModeUnchanged(t *testing.T) {
	amtd := amtdScored("default", "amtd-exact", &amtdv1beta1.AdaptiveRotationPolicy{}, "")
	amtd.Spec.MatcherMode = amtdv1beta1.MatcherModeExact // force Exact
	pod := scoredPod("p1", "default", "amtd-exact")
	// The exact rule is {timed,info,TimeBasedTrigger}; the event matches it AND
	// carries a high AnomalyScore that MUST be ignored (scoring skipped in Exact).
	ev := scoredEvent("ev-exact", "default/p1", TriggerSourceTimeBasedTrigger, "0.99")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "ev-exact")

	a := getAMTD(t, cl, "default", "amtd-exact")
	if a.Status.SmoothedScore != "" || a.Status.LastObservedScore != "" || a.Status.ConsecutiveHighCount != 0 {
		t.Errorf("Exact mode must not write scored Status: smoothed=%q last=%q consec=%d", a.Status.SmoothedScore, a.Status.LastObservedScore, a.Status.ConsecutiveHighCount)
	}
	// The exact {timed,info,TimeBasedTrigger} rule still matched -> pod rotated.
	if podExists(cl, "default", "p1") {
		t.Error("Exact-mode matched Rotate must still fire (pod deleted)")
	}
}

// TestScoring_NilAdaptiveRotationNoScoring proves that even in Scored mode, an AMTD
// WITHOUT an AdaptiveRotation block does not run scoring (Phase-0 inertness).
func TestScoring_NilAdaptiveRotationNoScoring(t *testing.T) {
	amtd := amtdScored("default", "amtd-noar", nil /* no AdaptiveRotation */, "")
	pod := scoredPod("p1", "default", "amtd-noar")
	ev := scoredEvent("ev-noar", "default/p1", "PrometheusIntegrator", "0.99")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "ev-noar")

	a := getAMTD(t, cl, "default", "amtd-noar")
	if a.Status.SmoothedScore != "" || a.Status.LastObservedScore != "" {
		t.Errorf("nil AdaptiveRotation must not score: smoothed=%q last=%q", a.Status.SmoothedScore, a.Status.LastObservedScore)
	}
}
