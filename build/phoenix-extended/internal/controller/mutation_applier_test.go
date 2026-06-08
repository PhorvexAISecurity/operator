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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// amtdWithInferenceRotation builds an AMTD carrying a Spec.InferenceRotation block
// for the PolicyRef-resolution tests.
func amtdWithInferenceRotation(ir *amtdv1beta1.InferenceRotationSpec) *amtdv1beta1.AdaptiveMovingTargetDefense {
	return &amtdv1beta1.AdaptiveMovingTargetDefense{
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{InferenceRotation: ir},
	}
}

// TestMutationApplier_Resolve_OverridesWinsOverPolicyRef proves D1 precedence:
// inline Overrides win over PolicyRef even when both are set.
func TestMutationApplier_Resolve_OverridesWinsOverPolicyRef(t *testing.T) {
	applier := NewMutationApplier()
	amtd := amtdWithInferenceRotation(&amtdv1beta1.InferenceRotationSpec{
		GoldenImage: "from-policyref:latest",
	})
	action := &amtdv1beta1.RotateAction{
		PolicyRef: &amtdv1beta1.LocalPolicyRef{Kind: "InferenceRotation"},
		Overrides: &amtdv1beta1.InferenceRotationOverlay{Image: "from-overrides:latest"},
	}
	ov, src, err := applier.Resolve(context.Background(), nil, action, amtd)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ov.Image != "from-overrides:latest" {
		t.Errorf("Overrides must win over PolicyRef: got image %q, want from-overrides:latest", ov.Image)
	}
	if src != "RotateAction.Overrides" {
		t.Errorf("EffectiveSource = %q, want RotateAction.Overrides", src)
	}
}

// TestMutationApplier_Resolve_PolicyRefInferenceRotation proves an empty-Kind and
// an explicit "InferenceRotation" Kind both resolve to the matched AMTD's
// Spec.InferenceRotation (image/env/gpu/container projected).
func TestMutationApplier_Resolve_PolicyRefInferenceRotation(t *testing.T) {
	applier := NewMutationApplier()
	amtd := amtdWithInferenceRotation(&amtdv1beta1.InferenceRotationSpec{
		ContainerName: "nim",
		GoldenImage:   "nvcr.io/nim/secure-nim:latest",
		EnvPatch:      []corev1.EnvVar{{Name: "RUNTIME_MODE", Value: "SECURE"}},
		GPUResource:   "0",
	})

	for _, kind := range []string{"", "InferenceRotation"} {
		action := &amtdv1beta1.RotateAction{PolicyRef: &amtdv1beta1.LocalPolicyRef{Kind: kind}}
		ov, src, err := applier.Resolve(context.Background(), nil, action, amtd)
		if err != nil {
			t.Fatalf("Kind %q: Resolve: %v", kind, err)
		}
		if src != "InferenceRotation" {
			t.Errorf("Kind %q: EffectiveSource = %q, want InferenceRotation", kind, src)
		}
		if ov.ContainerName != "nim" || ov.Image != "nvcr.io/nim/secure-nim:latest" || ov.GPUResource != "0" {
			t.Errorf("Kind %q: overlay projection wrong: %+v", kind, ov)
		}
		if len(ov.EnvPatch) != 1 || ov.EnvPatch[0].Name != "RUNTIME_MODE" || ov.EnvPatch[0].Value != "SECURE" {
			t.Errorf("Kind %q: env projection wrong: %+v", kind, ov.EnvPatch)
		}
	}
}

// cmpListing1 builds a ContextMutationPolicy mirroring ADA Listing 1: an
// ContainerImageUpdate (nim -> nvcr.io/nim/secure-nim:latest), a ResourceAdjustment
// (nim, limits nvidia.com/gpu:"0", requests cpu/memory — the requests are
// recognized-but-not-applied), and an EnvPatch (nim, RUNTIME_MODE=SECURE).
func cmpListing1(ns, name string) *amtdv1beta1.ContextMutationPolicy {
	return &amtdv1beta1.ContextMutationPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: amtdv1beta1.ContextMutationPolicySpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "nim-inference"}},
			Triggers: amtdv1beta1.CMPTriggers{TelemetrySources: []amtdv1beta1.TelemetrySource{
				{Type: amtdv1beta1.CMPTriggerPrometheusAlert, Name: "high_gpu_usage"},
				{Type: amtdv1beta1.CMPTriggerGatekeeperViolation, Constraint: "disallowed-hostpath"},
			}},
			Mutations: []amtdv1beta1.CMPMutation{
				{Type: amtdv1beta1.CMPMutationContainerImageUpdate, ContainerName: "nim", NewImage: "nvcr.io/nim/secure-nim:latest"},
				{Type: amtdv1beta1.CMPMutationResourceAdjustment, ContainerName: "nim", Resources: &corev1.ResourceRequirements{
					Limits:   corev1.ResourceList{gpuResourceName: resource.MustParse("0")},
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("256Mi")},
				}},
				{Type: amtdv1beta1.CMPMutationEnvPatch, ContainerName: "nim", Env: []corev1.EnvVar{{Name: "RUNTIME_MODE", Value: "SECURE"}}},
			},
		},
	}
}

// TestMutationApplier_Resolve_ContextMutationPolicy proves a CMP-kind PolicyRef is
// now FETCHED and its Mutations[] are projected into the overlay (D7g): the ADA
// Listing-1 image/gpu/env land, EffectiveSource = "ContextMutationPolicy", and the
// cpu/memory requests are recognized-but-not-applied (no overlay field).
func TestMutationApplier_Resolve_ContextMutationPolicy(t *testing.T) {
	applier := NewMutationApplier()
	cmp := cmpListing1("default", "nim-risk-based-mutation")
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).WithObjects(cmp).Build()
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "amtd1"}}
	action := &amtdv1beta1.RotateAction{PolicyRef: &amtdv1beta1.LocalPolicyRef{Kind: "ContextMutationPolicy", Name: "nim-risk-based-mutation"}}

	ov, src, err := applier.Resolve(context.Background(), cl, action, amtd)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if src != "ContextMutationPolicy" {
		t.Errorf("EffectiveSource = %q, want ContextMutationPolicy", src)
	}
	if ov.ContainerName != "nim" {
		t.Errorf("ContainerName = %q, want nim", ov.ContainerName)
	}
	if ov.Image != "nvcr.io/nim/secure-nim:latest" {
		t.Errorf("Image = %q, want nvcr.io/nim/secure-nim:latest", ov.Image)
	}
	if ov.GPUResource != "0" {
		t.Errorf("GPUResource = %q, want 0", ov.GPUResource)
	}
	if len(ov.EnvPatch) != 1 || ov.EnvPatch[0].Name != "RUNTIME_MODE" || ov.EnvPatch[0].Value != "SECURE" {
		t.Errorf("EnvPatch projection wrong: %+v", ov.EnvPatch)
	}
	// Summary must surface the not-applied cpu/memory-requests note (honest).
	_, summary := projectCMPMutations(cmp.Spec.Mutations)
	if !contains(summary, "not applied") {
		t.Errorf("summary must note cpu/mem requests not applied, got %q", summary)
	}
}

// TestMutationApplier_Resolve_ContextMutationPolicyNotFound proves a CMP PolicyRef
// pointing at a missing CMP degrades to an empty overlay + "" source (honest cold
// reschedule) with a nil error.
func TestMutationApplier_Resolve_ContextMutationPolicyNotFound(t *testing.T) {
	applier := NewMutationApplier()
	cl := fake.NewClientBuilder().WithScheme(seTestScheme).Build()
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "amtd1"}}
	action := &amtdv1beta1.RotateAction{PolicyRef: &amtdv1beta1.LocalPolicyRef{Kind: "ContextMutationPolicy", Name: "missing"}}

	ov, src, err := applier.Resolve(context.Background(), cl, action, amtd)
	if err != nil {
		t.Fatalf("Resolve NotFound must be nil error, got %v", err)
	}
	if !ov.IsEmpty() || src != "" {
		t.Errorf("missing CMP must degrade to cold: overlay %+v src %q", ov, src)
	}
}

// TestMutationApplier_Resolve_BothNilEmpty proves a Rotate with neither Overrides
// nor PolicyRef yields an empty overlay (today's cold reschedule).
func TestMutationApplier_Resolve_BothNilEmpty(t *testing.T) {
	applier := NewMutationApplier()
	ov, src, err := applier.Resolve(context.Background(), nil, &amtdv1beta1.RotateAction{}, amtdWithInferenceRotation(nil))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !ov.IsEmpty() || src != "" {
		t.Errorf("nil overlay Rotate must resolve empty: got overlay %+v src %q", ov, src)
	}
}

// contains is a tiny substring helper for the summary assertion.
func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestMutationApplier_Apply_ImageDefaultContainer proves an image swap lands on the
// first (default) container when ContainerName is empty.
func TestMutationApplier_Apply_ImageDefaultContainer(t *testing.T) {
	applier := NewMutationApplier()
	spec := &corev1.PodSpec{Containers: []corev1.Container{
		{Name: "app", Image: "old:1"},
		{Name: "sidecar", Image: "sc:1"},
	}}
	changed, err := applier.ApplyToPodSpec(spec, EffectiveOverlay{Image: "golden:2"})
	if err != nil {
		t.Fatalf("ApplyToPodSpec: %v", err)
	}
	if !changed {
		t.Error("expected changed=true for an image swap")
	}
	if spec.Containers[0].Image != "golden:2" {
		t.Errorf("first container image = %q, want golden:2", spec.Containers[0].Image)
	}
	if spec.Containers[1].Image != "sc:1" {
		t.Errorf("sidecar image must be untouched, got %q", spec.Containers[1].Image)
	}
}

// TestMutationApplier_Apply_ImageNamedContainer proves ContainerName selects the
// target container for the image swap.
func TestMutationApplier_Apply_ImageNamedContainer(t *testing.T) {
	applier := NewMutationApplier()
	spec := &corev1.PodSpec{Containers: []corev1.Container{
		{Name: "app", Image: "old:1"},
		{Name: "nim", Image: "nim:1"},
	}}
	changed, err := applier.ApplyToPodSpec(spec, EffectiveOverlay{ContainerName: "nim", Image: "secure-nim:2"})
	if err != nil {
		t.Fatalf("ApplyToPodSpec: %v", err)
	}
	if !changed || spec.Containers[1].Image != "secure-nim:2" {
		t.Errorf("named container swap failed: changed=%v image=%q", changed, spec.Containers[1].Image)
	}
	if spec.Containers[0].Image != "old:1" {
		t.Errorf("non-target container must be untouched, got %q", spec.Containers[0].Image)
	}
}

// TestMutationApplier_Apply_ContainerNotFound proves an unknown ContainerName is an
// error (so the executor can fail honestly rather than silently apply to the wrong
// container).
func TestMutationApplier_Apply_ContainerNotFound(t *testing.T) {
	applier := NewMutationApplier()
	spec := &corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "old:1"}}}
	_, err := applier.ApplyToPodSpec(spec, EffectiveOverlay{ContainerName: "missing", Image: "x:1"})
	if err == nil {
		t.Error("expected an error when ContainerName is not found")
	}
}

// TestMutationApplier_Apply_EnvSetAndOverwrite proves EnvPatch both APPENDS a new
// var and OVERWRITES an existing one by Name.
func TestMutationApplier_Apply_EnvSetAndOverwrite(t *testing.T) {
	applier := NewMutationApplier()
	spec := &corev1.PodSpec{Containers: []corev1.Container{{
		Name:  "app",
		Image: "img:1",
		Env:   []corev1.EnvVar{{Name: "RUNTIME_MODE", Value: "NORMAL"}, {Name: "KEEP", Value: "yes"}},
	}}}
	changed, err := applier.ApplyToPodSpec(spec, EffectiveOverlay{EnvPatch: []corev1.EnvVar{
		{Name: "RUNTIME_MODE", Value: "SECURE"}, // overwrite
		{Name: "NEW_VAR", Value: "added"},       // append
	}})
	if err != nil {
		t.Fatalf("ApplyToPodSpec: %v", err)
	}
	if !changed {
		t.Error("expected changed=true for env patch")
	}
	got := map[string]string{}
	for _, e := range spec.Containers[0].Env {
		got[e.Name] = e.Value
	}
	if got["RUNTIME_MODE"] != "SECURE" {
		t.Errorf("RUNTIME_MODE must be overwritten to SECURE, got %q", got["RUNTIME_MODE"])
	}
	if got["NEW_VAR"] != "added" {
		t.Errorf("NEW_VAR must be appended, got %q", got["NEW_VAR"])
	}
	if got["KEEP"] != "yes" {
		t.Errorf("KEEP must be preserved, got %q", got["KEEP"])
	}
}

// TestMutationApplier_Apply_GPUDropToZero proves GPUResource "0" sets the
// nvidia.com/gpu limit (DropToZero quarantine).
func TestMutationApplier_Apply_GPUDropToZero(t *testing.T) {
	applier := NewMutationApplier()
	spec := &corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "img:1"}}}
	changed, err := applier.ApplyToPodSpec(spec, EffectiveOverlay{GPUResource: "0"})
	if err != nil {
		t.Fatalf("ApplyToPodSpec: %v", err)
	}
	if !changed {
		t.Error("expected changed=true for gpu set")
	}
	q, ok := spec.Containers[0].Resources.Limits[gpuResourceName]
	if !ok {
		t.Fatalf("nvidia.com/gpu limit not set")
	}
	want := resource.MustParse("0")
	if q.Cmp(want) != 0 {
		t.Errorf("nvidia.com/gpu limit = %s, want 0", q.String())
	}
}

// TestMutationApplier_Apply_GPUInvalidQuantity proves a malformed GPUResource is an
// error (ParseQuantity, not MustParse — no panic).
func TestMutationApplier_Apply_GPUInvalidQuantity(t *testing.T) {
	applier := NewMutationApplier()
	spec := &corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "img:1"}}}
	_, err := applier.ApplyToPodSpec(spec, EffectiveOverlay{GPUResource: "not-a-quantity"})
	if err == nil {
		t.Error("expected an error for an invalid GPUResource quantity")
	}
}

// TestMutationApplier_Apply_EmptyOverlayNoChange proves an empty overlay is a no-op
// (returns false) so a nil-overlay Rotate stays a pure cold reschedule.
func TestMutationApplier_Apply_EmptyOverlayNoChange(t *testing.T) {
	applier := NewMutationApplier()
	spec := &corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "img:1"}}}
	changed, err := applier.ApplyToPodSpec(spec, EffectiveOverlay{})
	if err != nil {
		t.Fatalf("ApplyToPodSpec: %v", err)
	}
	if changed {
		t.Error("empty overlay must be a no-op (changed=false)")
	}
	if spec.Containers[0].Image != "img:1" {
		t.Error("empty overlay must not change the image")
	}
}

// TestMutationApplier_Apply_IdempotentReapply proves re-applying the SAME overlay
// reports changed=false (the self-Update-loop guard for the owner-template patch).
func TestMutationApplier_Apply_IdempotentReapply(t *testing.T) {
	applier := NewMutationApplier()
	spec := &corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "img:1"}}}
	ov := EffectiveOverlay{Image: "golden:2", EnvPatch: []corev1.EnvVar{{Name: "RUNTIME_MODE", Value: "SECURE"}}, GPUResource: "0"}
	if changed, err := applier.ApplyToPodSpec(spec, ov); err != nil || !changed {
		t.Fatalf("first apply: changed=%v err=%v (want true,nil)", changed, err)
	}
	changed, err := applier.ApplyToPodSpec(spec, ov)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if changed {
		t.Error("re-applying the same overlay must report changed=false (idempotent)")
	}
}

// TestMutationApplier_Apply_NoContainersError proves applying a non-empty overlay to
// a pod spec with no containers is an error.
func TestMutationApplier_Apply_NoContainersError(t *testing.T) {
	applier := NewMutationApplier()
	spec := &corev1.PodSpec{}
	_, err := applier.ApplyToPodSpec(spec, EffectiveOverlay{Image: "x:1"})
	if err == nil {
		t.Error("expected an error applying an overlay to a pod spec with no containers")
	}
}
