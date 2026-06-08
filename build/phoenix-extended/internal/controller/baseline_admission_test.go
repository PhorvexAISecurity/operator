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

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// admissionRequestForPod builds an admission.Request carrying the pod as raw JSON.
func admissionRequestForPod(t *testing.T, pod *corev1.Pod) admission.Request {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	return admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Namespace: pod.Namespace,
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
}

func admittedPod(name, ns, image string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}},
	}
}

// newAdmissionHandler builds the handler over a fake client seeded with the given
// objects (a WorkloadBaseline).
func newAdmissionHandler(t *testing.T, objs ...runtime.Object) *BaselineAdmission {
	t.Helper()
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithRuntimeObjects(objs...).Build()
	dec := admission.NewDecoder(seTestScheme)
	return NewBaselineAdmission(cl, NewBaselineVerifier(cl, ""), dec)
}

// TestBaselineAdmission_DeniesUnsigned proves fail-CLOSED: an enforced baseline
// denies a pod whose image is correctly pinned/digested but UNSIGNED.
func TestBaselineAdmission_DeniesUnsigned(t *testing.T) {
	km := newECDSAKey(t)
	wb := wbFixture("nim-baseline", km.pubPEM, km.signECD(testDigest), true) // RequireSignature
	h := newAdmissionHandler(t, wb)

	// Pod at the pinned digest but with no signature available to the admission check
	// (the baseline pin carries the signature; here the running image matches the
	// digest, so signature verify runs against the pin — which IS signed, so this
	// would ALLOW). To exercise the unsigned-deny, use a baseline whose pin is unsigned.
	wbUnsigned := wbFixture("nim-baseline", km.pubPEM, "", true)
	h = newAdmissionHandler(t, wbUnsigned)
	pod := admittedPod("nim-pod", "default", "registry/app@"+testDigest, map[string]string{"app": "nim"})

	resp := h.Handle(context.Background(), admissionRequestForPod(t, pod))
	if resp.Allowed {
		t.Fatalf("expected DENY for an unsigned image under RequireSignature, got allowed: %s", respMsg(resp))
	}
	_ = wb
}

// TestBaselineAdmission_DeniesDriftedDigest proves fail-CLOSED on a digest that does
// not match the pinned baseline digest.
func TestBaselineAdmission_DeniesDriftedDigest(t *testing.T) {
	km := newECDSAKey(t)
	wb := wbFixture("nim-baseline", km.pubPEM, km.signECD(testDigest), true)
	h := newAdmissionHandler(t, wb)
	drifted := "registry/app@sha256:2222222222222222222222222222222222222222222222222222222222222222"
	pod := admittedPod("nim-pod", "default", drifted, map[string]string{"app": "nim"})

	resp := h.Handle(context.Background(), admissionRequestForPod(t, pod))
	if resp.Allowed {
		t.Fatalf("expected DENY for a drifted digest, got allowed: %s", respMsg(resp))
	}
}

// TestBaselineAdmission_DeniesUnpinned proves fail-CLOSED on a tag (un-pinned) image.
func TestBaselineAdmission_DeniesUnpinned(t *testing.T) {
	km := newECDSAKey(t)
	wb := wbFixture("nim-baseline", km.pubPEM, km.signECD(testDigest), true)
	h := newAdmissionHandler(t, wb)
	pod := admittedPod("nim-pod", "default", "registry/app:latest", map[string]string{"app": "nim"}) // tag, not digest

	resp := h.Handle(context.Background(), admissionRequestForPod(t, pod))
	if resp.Allowed {
		t.Fatalf("expected DENY for an un-pinned (tag) image, got allowed: %s", respMsg(resp))
	}
}

// TestBaselineAdmission_AllowsVerifiedPinned proves a signed + pinned + matching
// image is ADMITTED.
func TestBaselineAdmission_AllowsVerifiedPinned(t *testing.T) {
	km := newECDSAKey(t)
	wb := wbFixture("nim-baseline", km.pubPEM, km.signECD(testDigest), true)
	h := newAdmissionHandler(t, wb)
	pod := admittedPod("nim-pod", "default", "registry/app@"+testDigest, map[string]string{"app": "nim"})

	resp := h.Handle(context.Background(), admissionRequestForPod(t, pod))
	if !resp.Allowed {
		t.Fatalf("expected ALLOW for a signed+pinned image at the verified digest, got deny: %s", respMsg(resp))
	}
}

// TestBaselineAdmission_AdmissionEnforceFalse_Allows proves AdmissionEnforce=false
// disables the gate for the baseline (allow).
func TestBaselineAdmission_AdmissionEnforceFalse_Allows(t *testing.T) {
	km := newECDSAKey(t)
	wb := wbFixture("nim-baseline", km.pubPEM, "", true) // unsigned pin would otherwise deny
	enforce := false
	wb.Spec.DriftPolicy = &amtdv1beta1.DriftPolicy{AdmissionEnforce: &enforce}
	h := newAdmissionHandler(t, wb)
	pod := admittedPod("nim-pod", "default", "registry/app@"+testDigest, map[string]string{"app": "nim"})

	resp := h.Handle(context.Background(), admissionRequestForPod(t, pod))
	if !resp.Allowed {
		t.Fatalf("expected ALLOW when AdmissionEnforce=false, got deny: %s", respMsg(resp))
	}
}

// TestBaselineAdmission_NotGoverned_Allows proves a pod not matched by any baseline
// selector is allowed (the webhook is not a global gate).
func TestBaselineAdmission_NotGoverned_Allows(t *testing.T) {
	km := newECDSAKey(t)
	wb := wbFixture("nim-baseline", km.pubPEM, km.signECD(testDigest), true)
	h := newAdmissionHandler(t, wb)
	pod := admittedPod("other-pod", "default", "registry/app:latest", map[string]string{"app": "other"}) // does not match selector

	resp := h.Handle(context.Background(), admissionRequestForPod(t, pod))
	if !resp.Allowed {
		t.Fatalf("expected ALLOW for an ungoverned pod, got deny: %s", respMsg(resp))
	}
}

func respMsg(r admission.Response) string {
	if r.Result != nil {
		return r.Result.Message
	}
	return ""
}
