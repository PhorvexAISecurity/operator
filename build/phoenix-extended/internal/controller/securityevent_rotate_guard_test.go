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
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// managedOwnedPod builds an AMTD-managed pod that is ALSO owned (controller=true)
// by the given owner kind/name, plus carries any extra annotations.
func managedOwnedPod(name, namespace, amtdName, ownerKind, ownerName string, ready bool, extra map[string]string) *corev1.Pod {
	info := []AMTDManageInfo{{AMTDNamespace: namespace, AMTDName: amtdName, ManagedSince: "now"}}
	raw, _ := json.Marshal(info)
	ann := map[string]string{AMTD_MANAGED_BY: string(raw)}
	for k, v := range extra {
		ann[k] = v
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Annotations: ann, UID: types.UID(name + "-uid")},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "old:1"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if ownerKind != "" {
		pod.OwnerReferences = []metav1.OwnerReference{ownerRef(ownerKind, ownerName)}
	}
	cond := corev1.ConditionFalse
	if ready {
		cond = corev1.ConditionTrue
	}
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: cond}}
	return pod
}

// rotateAMTDWithOverlay builds an AMTD with a timed Rotate strategy whose PolicyRef
// resolves to the embedded InferenceRotation overlay (golden image + env + gpu).
func rotateAMTDWithOverlay(namespace, name string, ir *amtdv1beta1.InferenceRotationSpec) *amtdv1beta1.AdaptiveMovingTargetDefense {
	return &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector:       map[string]string{"app": "demo"},
			InferenceRotation: ir,
			Strategy: []amtdv1beta1.ResponseStrategy{
				{
					Rule:   amtdv1beta1.Rule{Type: TriggerTypeTimed, ThreatLevel: "info", Source: TriggerSourceTimeBasedTrigger},
					Action: amtdv1beta1.AMTDAction{Rotate: &amtdv1beta1.RotateAction{PolicyRef: &amtdv1beta1.LocalPolicyRef{Kind: "InferenceRotation"}}},
				},
			},
		},
	}
}

func reconcileEvent(t *testing.T, cl crclient.Client, evName string) {
	t.Helper()
	r := &SecurityEventReconciler{Client: cl, Scheme: seTestScheme}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: crclient.ObjectKey{Name: evName}}); err != nil {
		t.Fatalf("Reconcile(%s): %v", evName, err)
	}
}

func getAMTD(t *testing.T, cl crclient.Client, ns, name string) *amtdv1beta1.AdaptiveMovingTargetDefense {
	t.Helper()
	a := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, a); err != nil {
		t.Fatalf("get AMTD %s/%s: %v", ns, name, err)
	}
	return a
}

func podExists(cl crclient.Client, ns, name string) bool {
	var p corev1.Pod
	return cl.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &p) == nil
}

// TestRotate_DurableRoute_MutatesOwnerTemplate is the headline Phase-1 test: a
// Deployment-owned pod with a non-empty InferenceRotation overlay routes to (a) —
// the Deployment template is patched with the golden image + RUNTIME_MODE=SECURE +
// nvidia.com/gpu:0 (durable, all replicas) — and the pod is cold-rescheduled. The
// AMTD Status records MutationDurable=true, RotationPathFired="Rotate",
// RotationCount=1, LastRotationTime, and LastKnownGoodRef.
func TestRotate_DurableRoute_MutatesOwnerTemplate(t *testing.T) {
	ctx := context.Background()
	ir := &amtdv1beta1.InferenceRotationSpec{
		GoldenImage: "nvcr.io/nim/secure-nim:latest",
		EnvPatch:    []corev1.EnvVar{{Name: "RUNTIME_MODE", Value: "SECURE"}},
		GPUResource: "0",
	}
	amtd := rotateAMTDWithOverlay("default", "amtd-rot", ir)
	dep := deploymentTemplate("web", "default", "old:1")
	rs := replicaSetOwnedBy("web-abc", "default", "web")
	pod := managedOwnedPod("web-abc-1", "default", "amtd-rot", "ReplicaSet", "web-abc", true, nil)
	ev := timedSecurityEvent("ev1", "default/web-abc-1")

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(amtd, dep, rs, pod, ev).
		WithStatusSubresource(amtd, ev).
		Build()
	reconcileEvent(t, cl, "ev1")

	// Deployment template carries the mutation (durable, all replicas).
	var gotDep appsv1.Deployment
	if err := cl.Get(ctx, types.NamespacedName{Namespace: "default", Name: "web"}, &gotDep); err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	c := gotDep.Spec.Template.Spec.Containers[0]
	if c.Image != "nvcr.io/nim/secure-nim:latest" {
		t.Errorf("template image = %q, want nvcr.io/nim/secure-nim:latest", c.Image)
	}
	if q, ok := c.Resources.Limits[gpuResourceName]; !ok || q.String() != "0" {
		t.Errorf("template nvidia.com/gpu limit = %v (ok=%v), want 0", q, ok)
	}
	gotEnv := false
	for _, e := range c.Env {
		if e.Name == "RUNTIME_MODE" && e.Value == "SECURE" {
			gotEnv = true
		}
	}
	if !gotEnv {
		t.Error("template must carry RUNTIME_MODE=SECURE")
	}

	// Pod cold-rescheduled (deleted) after the durable patch.
	if podExists(cl, "default", "web-abc-1") {
		t.Error("expected the triggering pod to be cold-rescheduled (deleted) after the durable patch")
	}

	// Status audit.
	a := getAMTD(t, cl, "default", "amtd-rot")
	if !a.Status.MutationDurable {
		t.Error("Status.MutationDurable must be true on the durable route")
	}
	if a.Status.RotationPathFired != "Rotate" {
		t.Errorf("Status.RotationPathFired = %q, want Rotate", a.Status.RotationPathFired)
	}
	if a.Status.RotationCount != 1 {
		t.Errorf("Status.RotationCount = %d, want 1", a.Status.RotationCount)
	}
	if a.Status.LastRotationTime.IsZero() {
		t.Error("Status.LastRotationTime must be set")
	}
	if a.Status.EffectiveSource != "InferenceRotation" {
		t.Errorf("Status.EffectiveSource = %q, want InferenceRotation", a.Status.EffectiveSource)
	}
	if a.Status.LastKnownGoodRef == nil || a.Status.LastKnownGoodRef.Name != "nvcr.io/nim/secure-nim:latest" {
		t.Errorf("Status.LastKnownGoodRef = %+v, want image ref", a.Status.LastKnownGoodRef)
	}
}

// TestRotate_ColdFallback_BarePod proves a bare (unowned) managed pod with a
// non-empty overlay routes to (b) cold fallback with MutationNotDurableReason=BarePod.
func TestRotate_ColdFallback_BarePod(t *testing.T) {
	ir := &amtdv1beta1.InferenceRotationSpec{GoldenImage: "secure:2"}
	amtd := rotateAMTDWithOverlay("default", "amtd-bare", ir)
	pod := managedOwnedPod("bare-1", "default", "amtd-bare", "", "", true, nil)
	ev := timedSecurityEvent("evb", "default/bare-1")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evb")

	if podExists(cl, "default", "bare-1") {
		t.Error("bare pod must be cold-rescheduled (deleted)")
	}
	a := getAMTD(t, cl, "default", "amtd-bare")
	if a.Status.MutationDurable {
		t.Error("bare pod mutation must NOT be durable")
	}
	if a.Status.MutationNotDurableReason != reasonBarePod {
		t.Errorf("MutationNotDurableReason = %q, want BarePod", a.Status.MutationNotDurableReason)
	}
	if a.Status.RotationPathFired != "cold" {
		t.Errorf("RotationPathFired = %q, want cold", a.Status.RotationPathFired)
	}
}

// TestRotate_ColdFallback_JobOwned proves a Job-owned managed pod with a non-empty
// overlay routes to (b) cold fallback with reason ImmutableJobTemplate.
func TestRotate_ColdFallback_JobOwned(t *testing.T) {
	ir := &amtdv1beta1.InferenceRotationSpec{GoldenImage: "secure:2"}
	amtd := rotateAMTDWithOverlay("default", "amtd-job", ir)
	pod := managedOwnedPod("job-1", "default", "amtd-job", "Job", "batch", true, nil)
	ev := timedSecurityEvent("evj", "default/job-1")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evj")

	a := getAMTD(t, cl, "default", "amtd-job")
	if a.Status.MutationDurable || a.Status.MutationNotDurableReason != reasonImmutableJobTemplate {
		t.Errorf("job-owned: durable=%v reason=%q (want false/ImmutableJobTemplate)", a.Status.MutationDurable, a.Status.MutationNotDurableReason)
	}
}

// TestRotate_NilOverlay_PureColdReschedule proves a Rotate with an EMPTY overlay
// (PolicyRef resolves to an AMTD without InferenceRotation) degrades to exactly the
// Phase-0 cold reschedule: pod deleted, MutationDurable=false, RotationPathFired=cold,
// NO MutationNotDurableReason (nothing was mutated), RotationCount=1.
func TestRotate_NilOverlay_PureColdReschedule(t *testing.T) {
	// AMTD has a Rotate strategy but NO InferenceRotation block => empty overlay.
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: "amtd-nil", Namespace: "default"},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{"app": "demo"},
			Strategy: []amtdv1beta1.ResponseStrategy{{
				Rule:   amtdv1beta1.Rule{Type: TriggerTypeTimed, ThreatLevel: "info", Source: TriggerSourceTimeBasedTrigger},
				Action: amtdv1beta1.AMTDAction{Rotate: &amtdv1beta1.RotateAction{}},
			}},
		},
	}
	// Deployment-owned, but overlay is empty so it must NOT patch the template.
	dep := deploymentTemplate("web", "default", "old:1")
	rs := replicaSetOwnedBy("web-abc", "default", "web")
	pod := managedOwnedPod("web-abc-1", "default", "amtd-nil", "ReplicaSet", "web-abc", true, nil)
	ev := timedSecurityEvent("evn", "default/web-abc-1")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, dep, rs, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evn")

	if podExists(cl, "default", "web-abc-1") {
		t.Error("nil-overlay Rotate must still cold-reschedule (delete) the pod")
	}
	// Deployment template MUST be untouched (no false durable patch).
	var gotDep appsv1.Deployment
	_ = cl.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: "web"}, &gotDep)
	if gotDep.Spec.Template.Spec.Containers[0].Image != "old:1" {
		t.Errorf("nil overlay must NOT patch the owner template; image = %q", gotDep.Spec.Template.Spec.Containers[0].Image)
	}
	a := getAMTD(t, cl, "default", "amtd-nil")
	if a.Status.MutationDurable {
		t.Error("nil overlay must not claim durability")
	}
	if a.Status.RotationPathFired != "cold" {
		t.Errorf("RotationPathFired = %q, want cold", a.Status.RotationPathFired)
	}
	if a.Status.MutationNotDurableReason != "" {
		t.Errorf("nil overlay must NOT set a non-durable reason (nothing mutated); got %q", a.Status.MutationNotDurableReason)
	}
	if a.Status.RotationCount != 1 {
		t.Errorf("RotationCount = %d, want 1", a.Status.RotationCount)
	}
}

// TestRotate_G1_Idempotence proves a pod already stamped with the current
// (podUID/eventUID) rotation key is NOT acted on again (G1).
func TestRotate_G1_Idempotence(t *testing.T) {
	ir := &amtdv1beta1.InferenceRotationSpec{GoldenImage: "secure:2"}
	amtd := rotateAMTDWithOverlay("default", "amtd-idem", ir)
	pod := managedOwnedPod("bare-1", "default", "amtd-idem", "", "", true, nil)
	ev := timedSecurityEvent("evi", "default/bare-1")
	// Pre-stamp the idempotence key = podUID/eventUID so G1 short-circuits.
	pod.UID = types.UID("pod-uid-1")
	ev.UID = types.UID("ev-uid-1")
	pod.Annotations[ROTATION_LAST_KEY] = "pod-uid-1/ev-uid-1"

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evi")

	if !podExists(cl, "default", "bare-1") {
		t.Error("G1 idempotence: a previously-acted (pod,event) must NOT be re-deleted")
	}
	a := getAMTD(t, cl, "default", "amtd-idem")
	if a.Status.RotationCount != 0 {
		t.Errorf("G1: RotationCount must stay 0 (no second action), got %d", a.Status.RotationCount)
	}
}

// TestRotate_G2_InProgressLock proves a pod carrying the in-progress lock is skipped.
func TestRotate_G2_InProgressLock(t *testing.T) {
	ir := &amtdv1beta1.InferenceRotationSpec{GoldenImage: "secure:2"}
	amtd := rotateAMTDWithOverlay("default", "amtd-prog", ir)
	pod := managedOwnedPod("bare-1", "default", "amtd-prog", "", "", true, map[string]string{ROTATION_IN_PROGRESS: "true"})
	ev := timedSecurityEvent("evp", "default/bare-1")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evp")

	if !podExists(cl, "default", "bare-1") {
		t.Error("G2 in-progress: a pod with a rotation underway must NOT be re-rotated")
	}
}

// TestRotate_G3_MinIntervalFloor is the core anti-thrash test (mirrors the live
// proof): with Status.LastRotationTime = now, a fresh matching event is SKIPPED by
// the min-interval floor (pod survives, RotationCount unchanged, a RotationThrottled
// condition recorded). It is the storm-guard the live FIRE#2 exercises.
func TestRotate_G3_MinIntervalFloor(t *testing.T) {
	ir := &amtdv1beta1.InferenceRotationSpec{GoldenImage: "secure:2"}
	amtd := rotateAMTDWithOverlay("default", "amtd-min", ir)
	// A prior rotation just happened => floor not elapsed.
	amtd.Status.LastRotationTime = metav1.NewTime(time.Now())
	amtd.Status.RotationCount = 1
	pod := managedOwnedPod("bare-1", "default", "amtd-min", "", "", true, nil)
	ev := timedSecurityEvent("evm", "default/bare-1")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evm")

	if !podExists(cl, "default", "bare-1") {
		t.Error("G3 min-interval: a re-fire within MinInterval must NOT rotate the pod")
	}
	a := getAMTD(t, cl, "default", "amtd-min")
	if a.Status.RotationCount != 1 {
		t.Errorf("G3: RotationCount must stay 1 (skipped), got %d", a.Status.RotationCount)
	}
	if c := meta.FindStatusCondition(a.Status.Conditions, "RotationThrottled"); c == nil || c.Reason != "MinIntervalFloor" {
		t.Errorf("G3: expected a RotationThrottled/MinIntervalFloor condition, got %+v", c)
	}
}

// TestRotate_G3_MinIntervalElapsed proves that once MinInterval HAS elapsed the
// rotation fires again (the floor is a floor, not a permanent block).
func TestRotate_G3_MinIntervalElapsed(t *testing.T) {
	ir := &amtdv1beta1.InferenceRotationSpec{GoldenImage: "secure:2"}
	amtd := rotateAMTDWithOverlay("default", "amtd-min2", ir)
	amtd.Status.LastRotationTime = metav1.NewTime(time.Now().Add(-2 * time.Minute)) // > 60s default
	amtd.Status.RotationCount = 1
	pod := managedOwnedPod("bare-1", "default", "amtd-min2", "", "", true, nil)
	ev := timedSecurityEvent("evm2", "default/bare-1")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evm2")

	if podExists(cl, "default", "bare-1") {
		t.Error("G3: once MinInterval elapsed, the rotation must fire (pod deleted)")
	}
	a := getAMTD(t, cl, "default", "amtd-min2")
	if a.Status.RotationCount != 2 {
		t.Errorf("G3 elapsed: RotationCount = %d, want 2", a.Status.RotationCount)
	}
}

// TestRotate_BurstOneAction proves a BURST of matching events yields exactly ONE
// action: the first rotates (RotationCount 1), the rest are min-interval-skipped.
// (The first pod is deleted; subsequent same-name events see NotFound, so we use
// distinct pods to model a burst on one workload and assert only one rotation total.)
func TestRotate_BurstOneAction(t *testing.T) {
	ir := &amtdv1beta1.InferenceRotationSpec{GoldenImage: "secure:2"}
	amtd := rotateAMTDWithOverlay("default", "amtd-burst", ir)
	p1 := managedOwnedPod("p1", "default", "amtd-burst", "", "", true, nil)
	p2 := managedOwnedPod("p2", "default", "amtd-burst", "", "", true, nil)
	p3 := managedOwnedPod("p3", "default", "amtd-burst", "", "", true, nil)
	e1 := timedSecurityEvent("e1", "default/p1")
	e2 := timedSecurityEvent("e2", "default/p2")
	e3 := timedSecurityEvent("e3", "default/p3")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, p1, p2, p3, e1, e2, e3).WithStatusSubresource(amtd, e1, e2, e3).Build()

	reconcileEvent(t, cl, "e1")
	reconcileEvent(t, cl, "e2")
	reconcileEvent(t, cl, "e3")

	a := getAMTD(t, cl, "default", "amtd-burst")
	if a.Status.RotationCount != 1 {
		t.Errorf("burst must yield exactly ONE action: RotationCount = %d, want 1", a.Status.RotationCount)
	}
	// p1 rotated (deleted); p2/p3 throttled (survive).
	if podExists(cl, "default", "p1") {
		t.Error("first burst event must rotate p1 (deleted)")
	}
	if !podExists(cl, "default", "p2") || !podExists(cl, "default", "p3") {
		t.Error("subsequent burst events must be min-interval-skipped (p2/p3 survive)")
	}
}

// TestRotate_G4_ReadinessGate proves that with a prior rotation recorded and the
// target pod NOT Ready, the next rotation is skipped (don't rotate until the prior
// replacement is Ready). MinInterval is set elapsed so G3 passes and G4 is isolated.
func TestRotate_G4_ReadinessGate(t *testing.T) {
	ir := &amtdv1beta1.InferenceRotationSpec{GoldenImage: "secure:2"}
	amtd := rotateAMTDWithOverlay("default", "amtd-ready", ir)
	amtd.Status.LastRotationTime = metav1.NewTime(time.Now().Add(-2 * time.Minute)) // G3 passes
	amtd.Status.RotationCount = 1
	pod := managedOwnedPod("bare-1", "default", "amtd-ready", "", "", false, nil) // NOT ready
	ev := timedSecurityEvent("evr", "default/bare-1")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evr")

	if !podExists(cl, "default", "bare-1") {
		t.Error("G4 readiness: must NOT rotate while the prior replacement is not Ready")
	}
	a := getAMTD(t, cl, "default", "amtd-ready")
	if c := meta.FindStatusCondition(a.Status.Conditions, "RotationThrottled"); c == nil || c.Reason != "ReplacementNotReady" {
		t.Errorf("G4: expected RotationThrottled/ReplacementNotReady, got %+v", c)
	}
}

// TestRotate_G5_BackoffWindowSkips proves that while Status.BackoffUntil is in the
// future the rotation is skipped (crash-loop backoff in effect).
func TestRotate_G5_BackoffWindowSkips(t *testing.T) {
	ir := &amtdv1beta1.InferenceRotationSpec{GoldenImage: "secure:2"}
	amtd := rotateAMTDWithOverlay("default", "amtd-bk", ir)
	amtd.Status.LastRotationTime = metav1.NewTime(time.Now().Add(-2 * time.Minute)) // G3 passes
	amtd.Status.BackoffUntil = metav1.NewTime(time.Now().Add(5 * time.Minute))      // backing off
	amtd.Status.FailedRotationCount = 5
	pod := managedOwnedPod("bare-1", "default", "amtd-bk", "", "", true, nil)
	ev := timedSecurityEvent("evbk", "default/bare-1")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evbk")

	if !podExists(cl, "default", "bare-1") {
		t.Error("G5 backoff: must NOT rotate while BackoffUntil is in the future")
	}
}

// TestRotate_G5_CrashLoopArmsBackoffAndRollsBack proves the crash-loop ceiling:
// when the target replacement is CrashLoopBackOff and FailedRotationCount would
// exceed MaxFailedRotations, the executor arms BackoffUntil and rolls the durable
// owner template image back to LastKnownGoodRef.
func TestRotate_G5_CrashLoopArmsBackoffAndRollsBack(t *testing.T) {
	ctx := context.Background()
	maxFailed := 1
	ir := &amtdv1beta1.InferenceRotationSpec{
		GoldenImage:      "bad-golden:2",
		AdaptiveRotation: &amtdv1beta1.AdaptiveRotationPolicy{MaxFailedRotations: &maxFailed},
	}
	amtd := rotateAMTDWithOverlay("default", "amtd-cl", ir)
	amtd.Status.LastRotationTime = metav1.NewTime(time.Now().Add(-2 * time.Minute)) // G3 passes
	amtd.Status.FailedRotationCount = 1                                             // next failure (2) exceeds max=1
	amtd.Status.LastKnownGoodRef = &amtdv1beta1.LocalRef{Name: "known-good:1"}
	// Deployment currently runs the bad golden image; rollback must restore known-good.
	dep := deploymentTemplate("web", "default", "bad-golden:2")
	rs := replicaSetOwnedBy("web-abc", "default", "web")
	pod := managedOwnedPod("web-abc-1", "default", "amtd-cl", "ReplicaSet", "web-abc", true, nil)
	// Mark the pod's container CrashLoopBackOff.
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
		Name:  "app",
		State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
	}}
	ev := timedSecurityEvent("evcl", "default/web-abc-1")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, dep, rs, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evcl")

	a := getAMTD(t, cl, "default", "amtd-cl")
	if a.Status.FailedRotationCount != 2 {
		t.Errorf("crash-loop: FailedRotationCount = %d, want 2", a.Status.FailedRotationCount)
	}
	if a.Status.BackoffUntil.IsZero() || a.Status.BackoffUntil.Time.Before(time.Now()) {
		t.Errorf("crash-loop: BackoffUntil must be armed in the future, got %v", a.Status.BackoffUntil)
	}
	// Rollback: the durable owner template image restored to last-known-good.
	var gotDep appsv1.Deployment
	if err := cl.Get(ctx, types.NamespacedName{Namespace: "default", Name: "web"}, &gotDep); err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if gotDep.Spec.Template.Spec.Containers[0].Image != "known-good:1" {
		t.Errorf("crash-loop rollback: template image = %q, want known-good:1", gotDep.Spec.Template.Spec.Containers[0].Image)
	}
	// Pod must NOT be rotated again on a failing replacement.
	if !podExists(cl, "default", "web-abc-1") {
		t.Error("crash-loop: must NOT rotate again on a failing replacement (pod survives)")
	}
}

// TestRotate_SuccessResetsFailureCounter proves a successful rotation resets
// FailedRotationCount to 0, clears BackoffUntil, and advances RotationCount.
func TestRotate_SuccessResetsFailureCounter(t *testing.T) {
	ir := &amtdv1beta1.InferenceRotationSpec{GoldenImage: "secure:2"}
	amtd := rotateAMTDWithOverlay("default", "amtd-ok", ir)
	amtd.Status.FailedRotationCount = 2 // a prior failure that should reset on success
	pod := managedOwnedPod("bare-1", "default", "amtd-ok", "", "", true, nil)
	ev := timedSecurityEvent("evok", "default/bare-1")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evok")

	a := getAMTD(t, cl, "default", "amtd-ok")
	if a.Status.FailedRotationCount != 0 {
		t.Errorf("success must reset FailedRotationCount to 0, got %d", a.Status.FailedRotationCount)
	}
	if !a.Status.BackoffUntil.IsZero() {
		t.Error("success must clear BackoffUntil")
	}
	if a.Status.RotationCount != 1 {
		t.Errorf("RotationCount = %d, want 1", a.Status.RotationCount)
	}
}

// TestRotate_SecurityEventStatusOutcome proves the per-event outcome is recorded on
// the SecurityEvent (AppliedAction=rotate, ProcessedAt set).
func TestRotate_SecurityEventStatusOutcome(t *testing.T) {
	ir := &amtdv1beta1.InferenceRotationSpec{GoldenImage: "secure:2"}
	amtd := rotateAMTDWithOverlay("default", "amtd-se", ir)
	pod := managedOwnedPod("bare-1", "default", "amtd-se", "", "", true, nil)
	ev := timedSecurityEvent("evse", "default/bare-1")
	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).WithObjects(amtd, pod, ev).WithStatusSubresource(amtd, ev).Build()
	reconcileEvent(t, cl, "evse")

	var gotEv amtdv1beta1.SecurityEvent
	if err := cl.Get(context.Background(), types.NamespacedName{Name: "evse"}, &gotEv); err != nil {
		t.Fatalf("get event: %v", err)
	}
	if gotEv.Status.AppliedAction != "rotate" {
		t.Errorf("SecurityEvent.Status.AppliedAction = %q, want rotate", gotEv.Status.AppliedAction)
	}
	if gotEv.Status.ProcessedAt.IsZero() {
		t.Error("SecurityEvent.Status.ProcessedAt must be set")
	}
}
