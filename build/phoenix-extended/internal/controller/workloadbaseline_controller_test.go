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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// wbFixture builds a cluster-scoped WorkloadBaseline pinning a single container to
// the test digest, with an inline-PEM key-based SignaturePolicy and a selector.
func wbFixture(name, pubPEM, sig string, requireSig bool) *amtdv1beta1.WorkloadBaseline {
	rs := requireSig
	return &amtdv1beta1.WorkloadBaseline{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: amtdv1beta1.WorkloadBaselineSpec{
			BaselineSpec: amtdv1beta1.BaselineSpec{
				ImageDigests: []amtdv1beta1.ImageDigest{
					{ContainerName: "app", Repository: "registry/app", Digest: testDigest, Signature: sig},
				},
				Signature: &amtdv1beta1.SignaturePolicy{
					PublicKeyRef:     &amtdv1beta1.KeyRef{InlinePEM: pubPEM},
					RequireSignature: &rs,
				},
			},
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nim"}},
		},
	}
}

func governedPod(name, ns, digest string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"app": "nim"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "registry/app@" + digest}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// TestRecordBaseline_VerifiesAndWritesStatus proves the RECORD path: the reconciler
// verifies the pinned digests against the SignaturePolicy and writes
// Status.LastVerifiedTime + PinnedDigests + the BaselineVerified condition.
func TestRecordBaseline_VerifiesAndWritesStatus(t *testing.T) {
	ctx := context.Background()
	km := newECDSAKey(t)
	wb := wbFixture("nim-baseline", km.pubPEM, km.signECD(testDigest), true)

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(wb).
		WithStatusSubresource(wb).
		Build()
	r := &BaselineDriftReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "nim-baseline"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := &amtdv1beta1.WorkloadBaseline{}
	if err := cl.Get(ctx, crclient.ObjectKey{Name: "nim-baseline"}, got); err != nil {
		t.Fatalf("get wb: %v", err)
	}
	if got.Status.LastVerifiedTime.IsZero() {
		t.Error("expected Status.LastVerifiedTime to be set after a successful verify")
	}
	if len(got.Status.PinnedDigests) != 1 || got.Status.PinnedDigests[0] != "registry/app@"+testDigest {
		t.Errorf("PinnedDigests=%v, want [registry/app@%s]", got.Status.PinnedDigests, testDigest)
	}
	if c := meta.FindStatusCondition(got.Status.Conditions, amtdv1beta1.ConditionBaselineVerified); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("expected BaselineVerified=True, got %+v", c)
	}
	// The provenance!=benignity caveat is ALWAYS surfaced.
	if c := meta.FindStatusCondition(got.Status.Conditions, amtdv1beta1.ConditionVerificationBenignityCaveat); c == nil {
		t.Error("expected the always-present VerificationBenignityCaveat condition (D6/D11)")
	}
}

// TestRecordBaseline_Unsigned_RequireSignature_Mismatch proves a RequireSignature
// baseline whose pin is unsigned records a SignatureMismatch and does NOT write a
// verified status (positive failure).
func TestRecordBaseline_Unsigned_RequireSignature_Mismatch(t *testing.T) {
	ctx := context.Background()
	km := newECDSAKey(t)
	wb := wbFixture("nim-baseline", km.pubPEM, "", true) // RequireSignature but no signature

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(wb).
		WithStatusSubresource(wb).
		Build()
	r := &BaselineDriftReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "nim-baseline"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := &amtdv1beta1.WorkloadBaseline{}
	_ = cl.Get(ctx, crclient.ObjectKey{Name: "nim-baseline"}, got)
	if c := meta.FindStatusCondition(got.Status.Conditions, amtdv1beta1.ConditionSignatureMismatch); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("expected SignatureMismatch=True for unsigned+RequireSignature, got %+v", c)
	}
	if c := meta.FindStatusCondition(got.Status.Conditions, amtdv1beta1.ConditionBaselineVerified); c != nil && c.Status == metav1.ConditionTrue {
		t.Error("did not expect BaselineVerified=True on a signature mismatch")
	}
}

// TestVerificationUnavailable_ReusesCachedLastGood proves the SPLIT fail mode: a
// keyless-only policy (verification unavailable) sets VerificationUnavailable and
// REUSES the cached last-good PinnedDigests rather than mass-flagging drift.
func TestVerificationUnavailable_ReusesCachedLastGood(t *testing.T) {
	ctx := context.Background()
	req := true
	wb := &amtdv1beta1.WorkloadBaseline{
		ObjectMeta: metav1.ObjectMeta{Name: "nim-baseline"},
		Spec: amtdv1beta1.WorkloadBaselineSpec{
			BaselineSpec: amtdv1beta1.BaselineSpec{
				ImageDigests: []amtdv1beta1.ImageDigest{
					{ContainerName: "app", Repository: "registry/app", Digest: testDigest, Signature: "AAAA"},
				},
				Signature: &amtdv1beta1.SignaturePolicy{
					KeylessIdentity:  &amtdv1beta1.KeylessIdentity{Issuer: "https://issuer", SubjectRegexp: ".*"},
					RequireSignature: &req,
				},
			},
		},
		// Pre-seed a cached last-good (as a prior verify would have).
		Status: amtdv1beta1.WorkloadBaselineStatus{PinnedDigests: []string{"registry/app@" + testDigest}},
	}

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(wb).
		WithStatusSubresource(wb).
		Build()
	r := &BaselineDriftReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "nim-baseline"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	got := &amtdv1beta1.WorkloadBaseline{}
	_ = cl.Get(ctx, crclient.ObjectKey{Name: "nim-baseline"}, got)
	if c := meta.FindStatusCondition(got.Status.Conditions, amtdv1beta1.ConditionVerificationUnavailable); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("expected VerificationUnavailable=True, got %+v", c)
	}
	// Cached last-good preserved (NOT cleared).
	if len(got.Status.PinnedDigests) != 1 || got.Status.PinnedDigests[0] != "registry/app@"+testDigest {
		t.Errorf("expected cached last-good PinnedDigests preserved, got %v", got.Status.PinnedDigests)
	}
}

// TestBaselineDrift_EmitsDriftEvent_DoesNotAct proves the core invariant: the
// reconciler EMITS a Type:'drift' SecurityEvent with Evidence for a drifted
// governed pod and does NOT itself patch/delete the pod.
func TestBaselineDrift_EmitsDriftEvent_DoesNotAct(t *testing.T) {
	ctx := context.Background()
	km := newECDSAKey(t)
	wb := wbFixture("nim-baseline", km.pubPEM, km.signECD(testDigest), true)
	driftedDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	pod := governedPod("nim-pod", "default", driftedDigest)

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(wb, pod).
		WithStatusSubresource(wb).
		Build()
	r := &BaselineDriftReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "nim-baseline"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// A Type:'drift' SecurityEvent must exist carrying Evidence.
	evList := &amtdv1beta1.SecurityEventList{}
	if err := cl.List(ctx, evList); err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(evList.Items) != 1 {
		t.Fatalf("expected exactly 1 drift SecurityEvent, got %d", len(evList.Items))
	}
	ev := evList.Items[0]
	if ev.Spec.Rule.Type != "drift" || ev.Spec.Rule.Source != "FalcoIntegrator" {
		t.Errorf("event Rule=%+v, want Type=drift Source=FalcoIntegrator (matcher-routable exact rule)", ev.Spec.Rule)
	}
	if ev.Spec.Evidence == nil || ev.Spec.Evidence.ObservedDigest != driftedDigest || ev.Spec.Evidence.ExpectedDigest != testDigest {
		t.Errorf("event Evidence=%+v, want Observed=%q Expected=%q", ev.Spec.Evidence, driftedDigest, testDigest)
	}
	if ev.Spec.Targets[0] != "default/nim-pod" {
		t.Errorf("event Targets=%v, want [default/nim-pod]", ev.Spec.Targets)
	}

	// The reconciler did NOT act: the pod still exists, unmodified.
	gotPod := &corev1.Pod{}
	if err := cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "nim-pod"}, gotPod); err != nil {
		t.Fatalf("the reconciler must NOT delete the drifted pod, but get failed: %v", err)
	}
	if gotPod.Spec.Containers[0].Image != "registry/app@"+driftedDigest {
		t.Error("the reconciler must NOT patch the drifted pod image")
	}

	// Drift accounting recorded.
	gotWB := &amtdv1beta1.WorkloadBaseline{}
	_ = cl.Get(ctx, crclient.ObjectKey{Name: "nim-baseline"}, gotWB)
	if gotWB.Status.DriftDetections != 1 {
		t.Errorf("DriftDetections=%d, want 1", gotWB.Status.DriftDetections)
	}
}

// TestBaselineDrift_NoDrift_NoEvent proves a governed pod at the pinned digest does
// not emit any drift event.
func TestBaselineDrift_NoDrift_NoEvent(t *testing.T) {
	ctx := context.Background()
	km := newECDSAKey(t)
	wb := wbFixture("nim-baseline", km.pubPEM, km.signECD(testDigest), true)
	pod := governedPod("nim-pod", "default", testDigest) // at the pin

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(wb, pod).
		WithStatusSubresource(wb).
		Build()
	r := &BaselineDriftReconciler{Client: cl, Scheme: seTestScheme}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: crclient.ObjectKey{Name: "nim-baseline"}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	evList := &amtdv1beta1.SecurityEventList{}
	_ = cl.List(ctx, evList)
	if len(evList.Items) != 0 {
		t.Fatalf("expected no drift event for a pod at the pinned digest, got %d", len(evList.Items))
	}
}

// TestRegenerate_RestoresTopOwnerTemplate proves the restore: a verified target is
// patched onto the top owner (Deployment) template image (verify-before-recreate),
// and WorkloadBaselineStatus.LastRegeneration is set.
func TestRegenerate_RestoresTopOwnerTemplate(t *testing.T) {
	ctx := context.Background()
	km := newECDSAKey(t)
	wb := wbFixture("nim-baseline", km.pubPEM, km.signECD(testDigest), true)

	driftedDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dep, rs, pod := deploymentOwnedPod("nim", "default", "registry/app@"+driftedDigest)

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(wb, dep, rs, pod).
		WithStatusSubresource(wb).
		Build()

	restorer := NewBaselineRestorer(cl, NewBaselineVerifier(cl, "default"))
	res, err := restorer.Regenerate(ctx, pod, wb, false, ctrl.Log)
	if err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	if !res.Restored || !res.Durable || res.PinnedRef != "registry/app@"+testDigest {
		t.Errorf("result=%+v, want Restored+Durable to registry/app@%s", res, testDigest)
	}

	// The Deployment template image was patched to the GOLDEN digest.
	gotDep := &appsv1.Deployment{}
	if err := cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "nim"}, gotDep); err != nil {
		t.Fatalf("get dep: %v", err)
	}
	if gotDep.Spec.Template.Spec.Containers[0].Image != "registry/app@"+testDigest {
		t.Errorf("Deployment template image=%q, want golden registry/app@%s", gotDep.Spec.Template.Spec.Containers[0].Image, testDigest)
	}

	// LastRegeneration recorded.
	gotWB := &amtdv1beta1.WorkloadBaseline{}
	_ = cl.Get(ctx, crclient.ObjectKey{Name: "nim-baseline"}, gotWB)
	if gotWB.Status.LastRegeneration.IsZero() {
		t.Error("expected WorkloadBaselineStatus.LastRegeneration to be set after a restore")
	}
}

// TestRegenerate_RejectsUnverifiableTarget proves verify-before-recreate: a target
// whose pin does not verify (wrong signature) ABORTS the restore and leaves the
// owner template UNTOUCHED.
func TestRegenerate_RejectsUnverifiableTarget(t *testing.T) {
	ctx := context.Background()
	signer := newECDSAKey(t)
	trusted := newECDSAKey(t)
	// Pin signed by the WRONG key => will not verify against trusted.pubPEM.
	wb := wbFixture("nim-baseline", trusted.pubPEM, signer.signECD(testDigest), true)

	driftedDigest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dep, rs, pod := deploymentOwnedPod("nim", "default", "registry/app@"+driftedDigest)

	cl := fake.NewClientBuilder().
		WithScheme(seTestScheme).
		WithObjects(wb, dep, rs, pod).
		WithStatusSubresource(wb).
		Build()

	restorer := NewBaselineRestorer(cl, NewBaselineVerifier(cl, "default"))
	_, err := restorer.Regenerate(ctx, pod, wb, false, ctrl.Log)
	if err == nil {
		t.Fatal("expected Regenerate to ABORT on an unverifiable target (verify-before-recreate)")
	}

	// Owner template MUST be untouched (still the drifted image).
	gotDep := &appsv1.Deployment{}
	_ = cl.Get(ctx, crclient.ObjectKey{Namespace: "default", Name: "nim"}, gotDep)
	if gotDep.Spec.Template.Spec.Containers[0].Image != "registry/app@"+driftedDigest {
		t.Errorf("owner template must be untouched on a verify abort, got %q", gotDep.Spec.Template.Spec.Containers[0].Image)
	}
}

// deploymentOwnedPod builds a Deployment -> ReplicaSet -> Pod chain so
// classifyTopOwner resolves a durable owner-template target. The pod and template
// carry the drifted image.
func deploymentOwnedPod(name, ns, image string) (*appsv1.Deployment, *appsv1.ReplicaSet, *corev1.Pod) {
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}},
			},
		},
	}
	ctrlTrue := true
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: name + "-rs", Namespace: ns,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: name, Controller: &ctrlTrue}},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name + "-pod", Namespace: ns, Labels: map[string]string{"app": "nim"},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: name + "-rs", Controller: &ctrlTrue}},
		},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	return dep, rs, pod
}
