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
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// fixedClock is a deterministic poolClock for the readiness-gate dwell + swap-timing.
type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

// wisFixture builds a minimal WarmInferenceSet (Replicas, ServiceSelectorSwap default,
// busybox-style golden template that runs GPU-free) for tests.
func wisFixture(ns, name string, replicas int) *amtdv1beta1.WarmInferenceSet {
	r := replicas
	mw := 0
	rml := false // tests default RequireModelLoaded off unless a test opts in
	return &amtdv1beta1.WarmInferenceSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: amtdv1beta1.WarmInferenceSetSpec{
			Replicas: &r,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "nim-pool"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "nim", Image: "busybox:1"}}},
			},
			WarmReadyGate: amtdv1beta1.WarmReadyGate{
				MinWarmSeconds:     &mw,
				RequireModelLoaded: &rml,
			},
		},
	}
}

// newWISClient builds a fake client with the WIS as a status-subresource object.
func newWISClient(wis *amtdv1beta1.WarmInferenceSet, extra ...crclient.Object) crclient.Client {
	objs := append([]crclient.Object{wis}, extra...)
	return fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(objs...).
		WithStatusSubresource(wis).
		Build()
}

func reconcileWIS(t *testing.T, cl crclient.Client, clock poolClock, ns, name string) ctrl.Result {
	t.Helper()
	r := &WarmInferenceSetReconciler{Client: cl, Scheme: seTestScheme, clock: clock}
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: crclient.ObjectKey{Namespace: ns, Name: name}})
	if err != nil {
		t.Fatalf("Reconcile(%s/%s): %v", ns, name, err)
	}
	return res
}

func getWIS(t *testing.T, cl crclient.Client, ns, name string) *amtdv1beta1.WarmInferenceSet {
	t.Helper()
	w := &amtdv1beta1.WarmInferenceSet{}
	if err := cl.Get(context.Background(), crclient.ObjectKey{Namespace: ns, Name: name}, w); err != nil {
		t.Fatalf("get WIS %s/%s: %v", ns, name, err)
	}
	return w
}

func listPoolPods(t *testing.T, cl crclient.Client, ns, set string) []corev1.Pod {
	t.Helper()
	list := &corev1.PodList{}
	if err := cl.List(context.Background(), list,
		crclient.InNamespace(ns),
		crclient.MatchingLabels{amtdv1beta1.PoolPodLabel: set}); err != nil {
		t.Fatalf("list pool pods: %v", err)
	}
	return list.Items
}

func leaderCount(pods []corev1.Pod, key, val string) (int, string) {
	n := 0
	name := ""
	for _, p := range pods {
		if p.Labels[key] == val {
			n++
			name = p.Name
		}
	}
	return n, name
}

// markWarm flips a pool pod Ready=True (transitioned at readyAt) and sets the
// model-loaded annotation, then persists it.
func markWarm(t *testing.T, cl crclient.Client, ns, name string, readyAt time.Time) {
	t.Helper()
	p := &corev1.Pod{}
	if err := cl.Get(context.Background(), crclient.ObjectKey{Namespace: ns, Name: name}, p); err != nil {
		t.Fatalf("get pod %s: %v", name, err)
	}
	if p.Annotations == nil {
		p.Annotations = map[string]string{}
	}
	p.Annotations[amtdv1beta1.ModelLoadedAnnotation] = "true"
	p.Status.Conditions = []corev1.PodCondition{{
		Type:               corev1.PodReady,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.NewTime(readyAt),
	}}
	if err := cl.Status().Update(context.Background(), p); err != nil {
		t.Fatalf("status update pod %s: %v", name, err)
	}
	// The annotation lives on metadata, not status; persist it via a plain Update too.
	if err := cl.Update(context.Background(), p); err != nil {
		t.Fatalf("update pod %s: %v", name, err)
	}
}

// TestEnsurePool_CreatesNPodsAndOneLeaderAndService is the headline class-B test:
// EnsurePool on an empty pool creates N pods, exactly one carries the leader label,
// and the leader-selecting Service exists with a selector that includes the leader
// label.
func TestEnsurePool_CreatesNPodsAndOneLeaderAndService(t *testing.T) {
	clock := &fixedClock{t: time.Unix(1_000_000, 0)}
	wis := wisFixture("default", "nim-pool", 3)
	cl := newWISClient(wis)

	reconcileWIS(t, cl, clock, "default", "nim-pool")

	pods := listPoolPods(t, cl, "default", "nim-pool")
	if len(pods) != 3 {
		t.Fatalf("want 3 pool pods, got %d", len(pods))
	}
	key := wis.EffectiveLeaderLabelKey()
	val := wis.EffectiveLeaderLabelValue()
	n, leader := leaderCount(pods, key, val)
	if n != 1 {
		t.Fatalf("want exactly 1 leader, got %d", n)
	}
	if leader == "" {
		t.Fatal("leader name empty")
	}

	// Leader-selecting Service exists with the leader label in its selector.
	svc := &corev1.Service{}
	if err := cl.Get(context.Background(), crclient.ObjectKey{Namespace: "default", Name: wis.EffectiveServiceName()}, svc); err != nil {
		t.Fatalf("leader Service not created: %v", err)
	}
	if svc.Spec.Selector[key] != val {
		t.Errorf("Service selector missing leader label %s=%s, got %v", key, val, svc.Spec.Selector)
	}
	if svc.Spec.Selector[amtdv1beta1.PoolPodLabel] != "nim-pool" {
		t.Errorf("Service selector missing pool label, got %v", svc.Spec.Selector)
	}

	// Status records ActiveLeader.
	got := getWIS(t, cl, "default", "nim-pool")
	if got.Status.ActiveLeader != leader {
		t.Errorf("Status.ActiveLeader=%q, want %q", got.Status.ActiveLeader, leader)
	}
	if got.Status.CurrentReplicas != 3 {
		t.Errorf("Status.CurrentReplicas=%d, want 3", got.Status.CurrentReplicas)
	}
}

// TestEnsurePool_DefaultReplicasIsTwo proves the code default (nil Replicas => 2).
func TestEnsurePool_DefaultReplicasIsTwo(t *testing.T) {
	clock := &fixedClock{t: time.Unix(1_000_000, 0)}
	wis := wisFixture("default", "nim-pool", 2)
	wis.Spec.Replicas = nil // exercise the code default
	cl := newWISClient(wis)

	reconcileWIS(t, cl, clock, "default", "nim-pool")
	pods := listPoolPods(t, cl, "default", "nim-pool")
	if len(pods) != 2 {
		t.Fatalf("nil Replicas should default to 2 pods, got %d", len(pods))
	}
}

// TestReadinessGate_IsWarmMatrix exercises the strict warm definition:
// probe-not-Ready=false; MinWarmSeconds-not-elapsed=false; RequireModelLoaded-unmet=
// false; all-met=true.
func TestReadinessGate_IsWarmMatrix(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	gate := &ReadinessGate{clock: &fixedClock{t: now}}

	base := func() *amtdv1beta1.WarmInferenceSet {
		w := wisFixture("default", "p", 2)
		mw := 10
		rml := true
		w.Spec.WarmReadyGate.MinWarmSeconds = &mw
		w.Spec.WarmReadyGate.RequireModelLoaded = &rml
		return w
	}
	readyPod := func(readyAt time.Time, modelLoaded, ready bool) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "default"}}
		st := corev1.ConditionFalse
		if ready {
			st = corev1.ConditionTrue
		}
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: st, LastTransitionTime: metav1.NewTime(readyAt)}}
		if modelLoaded {
			p.Annotations = map[string]string{amtdv1beta1.ModelLoadedAnnotation: "true"}
		}
		return p
	}

	// Probe not Ready => false.
	if gate.IsWarm(base(), readyPod(now.Add(-time.Hour), true, false)) {
		t.Error("not-Ready pod must not be warm")
	}
	// Ready but MinWarmSeconds (10s) not yet elapsed (ready 5s ago) => false.
	if gate.IsWarm(base(), readyPod(now.Add(-5*time.Second), true, true)) {
		t.Error("dwell-not-elapsed pod must not be warm")
	}
	// Ready, dwell elapsed, but model NOT loaded => false (RequireModelLoaded true).
	if gate.IsWarm(base(), readyPod(now.Add(-time.Hour), false, true)) {
		t.Error("model-not-loaded pod must not be warm when RequireModelLoaded=true")
	}
	// All met => true.
	if !gate.IsWarm(base(), readyPod(now.Add(-time.Hour), true, true)) {
		t.Error("Ready + dwell-elapsed + model-loaded pod must be warm")
	}
	// RequireModelLoaded=false relaxes the model gate.
	w := base()
	off := false
	w.Spec.WarmReadyGate.RequireModelLoaded = &off
	if !gate.IsWarm(w, readyPod(now.Add(-time.Hour), false, true)) {
		t.Error("with RequireModelLoaded=false, Ready+dwell pod must be warm even without model signal")
	}
}

// TestClassB_NoSwapWithoutRequest proves the §1.3 invariant: repeated class-B
// reconciles (with warm shadows available) NEVER move the leader when there is no
// Spec.SwapRequest.
func TestClassB_NoSwapWithoutRequest(t *testing.T) {
	clock := &fixedClock{t: time.Unix(3_000_000, 0)}
	wis := wisFixture("default", "nim-pool", 2)
	cl := newWISClient(wis)

	// First reconcile creates the pool + elects a leader.
	reconcileWIS(t, cl, clock, "default", "nim-pool")
	pods := listPoolPods(t, cl, "default", "nim-pool")
	key, val := wis.EffectiveLeaderLabelKey(), wis.EffectiveLeaderLabelValue()
	_, leader0 := leaderCount(pods, key, val)

	// Make BOTH pods warm (a swap candidate exists) — class-B must still not swap.
	for _, p := range pods {
		markWarm(t, cl, "default", p.Name, clock.t.Add(-time.Hour))
	}

	// Several more class-B reconciles with no SwapRequest.
	for i := 0; i < 4; i++ {
		reconcileWIS(t, cl, clock, "default", "nim-pool")
		pods = listPoolPods(t, cl, "default", "nim-pool")
		_, leaderNow := leaderCount(pods, key, val)
		if leaderNow != leader0 {
			t.Fatalf("class-B reconcile #%d moved the leader from %q to %q WITHOUT a SwapRequest (invariant violation)", i, leader0, leaderNow)
		}
		if n, _ := leaderCount(pods, key, val); n != 1 {
			t.Fatalf("class-B reconcile #%d left %d leaders, want exactly 1", i, n)
		}
	}

	got := getWIS(t, cl, "default", "nim-pool")
	if got.Status.SwapPhase != amtdv1beta1.SwapPhaseIdle {
		t.Errorf("SwapPhase=%q, want Idle for a pool with no request", got.Status.SwapPhase)
	}
	if got.Status.ReadyShadows != 1 {
		t.Errorf("ReadyShadows=%d, want 1 (the non-leader warm pod)", got.Status.ReadyShadows)
	}
}

// TestSwap_FlipsRetiresRewarmsAndRecordsDuration drives the full swap phase machine
// to completion across reconciles and asserts: leader label moved to the warm shadow,
// old leader retired (deleted), a replacement re-warmed back to N, the request
// cleared, and LastSwapDurationMillis>0.
func TestSwap_FlipsRetiresRewarmsAndRecordsDuration(t *testing.T) {
	clock := &fixedClock{t: time.Unix(4_000_000, 0)}
	wis := wisFixture("default", "nim-pool", 2)
	drain := int64(0) // zero drain so the drain phase elapses immediately in-test
	wis.Spec.DrainTimeoutSeconds = &drain
	cl := newWISClient(wis)

	// Bring the pool up + make both pods warm.
	reconcileWIS(t, cl, clock, "default", "nim-pool")
	pods := listPoolPods(t, cl, "default", "nim-pool")
	key, val := wis.EffectiveLeaderLabelKey(), wis.EffectiveLeaderLabelValue()
	_, oldLeader := leaderCount(pods, key, val)
	var oldLeaderUID string
	for _, p := range pods {
		if p.Name == oldLeader {
			oldLeaderUID = string(p.UID)
		}
		markWarm(t, cl, "default", p.Name, clock.t.Add(-time.Hour))
	}

	// Set a swap request (as the WarmSwap action would).
	cur := getWIS(t, cl, "default", "nim-pool")
	cur.Spec.SwapRequest = &amtdv1beta1.WarmSwapRequest{RequestID: "ev-1", RequestedAt: metav1.NewTime(clock.t)}
	if err := cl.Update(context.Background(), cur); err != nil {
		t.Fatalf("set swap request: %v", err)
	}

	// Drive the phase machine: Flipping -> Draining -> Retiring -> Rewarming -> Idle.
	// Advance the clock a little each step so the recorded duration is > 0.
	for i := 0; i < 8; i++ {
		clock.t = clock.t.Add(250 * time.Millisecond)
		reconcileWIS(t, cl, clock, "default", "nim-pool")
		w := getWIS(t, cl, "default", "nim-pool")
		if w.Spec.SwapRequest == nil && w.Status.SwapPhase == amtdv1beta1.SwapPhaseIdle {
			break
		}
	}

	got := getWIS(t, cl, "default", "nim-pool")
	if got.Spec.SwapRequest != nil {
		t.Fatalf("SwapRequest not cleared after completion, phase=%q", got.Status.SwapPhase)
	}
	if got.Status.SwapPhase != amtdv1beta1.SwapPhaseIdle {
		t.Errorf("SwapPhase=%q, want Idle after completion", got.Status.SwapPhase)
	}
	if got.Status.LastSwapDurationMillis <= 0 {
		t.Errorf("LastSwapDurationMillis=%d, want >0 (control-plane flip+drain cutover)", got.Status.LastSwapDurationMillis)
	}

	// Leader moved off the old leader; old leader retired (deleted).
	pods = listPoolPods(t, cl, "default", "nim-pool")
	n, newLeader := leaderCount(pods, key, val)
	if n != 1 {
		t.Fatalf("want exactly 1 leader after swap, got %d", n)
	}
	if newLeader == oldLeader {
		t.Errorf("leader did not move off the old leader %q", oldLeader)
	}
	// Old leader RETIRED: the pod object that was the leader (its UID, if assigned, or
	// its now-non-leader role) is gone. Because the pool re-warms a replacement back to
	// N, the decisive proof of retirement is the live count: if the old leader had NOT
	// been deleted we would observe N+1 (old leader + new leader + fresh shadow). N live
	// pods => old leader was retired and exactly one replacement re-warmed.
	live := 0
	oldUIDStillPresent := false
	for i := range pods {
		if pods[i].DeletionTimestamp == nil {
			live++
		}
		if oldLeaderUID != "" && string(pods[i].UID) == oldLeaderUID {
			oldUIDStillPresent = true
		}
	}
	if live != 2 {
		t.Errorf("want N=2 live pods after retire+re-warm (N+1 would mean the old leader was NOT retired), got %d", live)
	}
	if oldLeaderUID != "" && oldUIDStillPresent {
		t.Errorf("old leader (UID %s) was not retired", oldLeaderUID)
	}
}

// TestSwap_BlockedWhenNoReadyShadow proves the readiness gate is the gate: a swap
// requested with NO warm shadow is BLOCKED — SwapBlockedNoReadyShadow condition set,
// leader unchanged, request retained.
func TestSwap_BlockedWhenNoReadyShadow(t *testing.T) {
	clock := &fixedClock{t: time.Unix(5_000_000, 0)}
	wis := wisFixture("default", "nim-pool", 2)
	rml := true
	wis.Spec.WarmReadyGate.RequireModelLoaded = &rml // shadows are NOT warm (no model signal)
	cl := newWISClient(wis)

	reconcileWIS(t, cl, clock, "default", "nim-pool")
	pods := listPoolPods(t, cl, "default", "nim-pool")
	key, val := wis.EffectiveLeaderLabelKey(), wis.EffectiveLeaderLabelValue()
	_, leader0 := leaderCount(pods, key, val)

	// Request a swap, but NO shadow is warm.
	cur := getWIS(t, cl, "default", "nim-pool")
	cur.Spec.SwapRequest = &amtdv1beta1.WarmSwapRequest{RequestID: "ev-blocked"}
	if err := cl.Update(context.Background(), cur); err != nil {
		t.Fatalf("set swap request: %v", err)
	}

	reconcileWIS(t, cl, clock, "default", "nim-pool")

	got := getWIS(t, cl, "default", "nim-pool")
	cond := meta.FindStatusCondition(got.Status.Conditions, amtdv1beta1.ConditionSwapBlockedNoReadyShadow)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected SwapBlockedNoReadyShadow=True, got %+v", cond)
	}
	if got.Spec.SwapRequest == nil {
		t.Error("BLOCKED swap must RETAIN the request, but it was cleared")
	}
	pods = listPoolPods(t, cl, "default", "nim-pool")
	_, leaderNow := leaderCount(pods, key, val)
	if leaderNow != leader0 {
		t.Errorf("BLOCKED swap must NOT move the leader; moved %q->%q", leader0, leaderNow)
	}
}
