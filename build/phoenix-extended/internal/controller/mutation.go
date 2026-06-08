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

// Package controller — Phase 1 MutationApplier + D3 owner-walk classifier.
//
// This file implements two collaborating pieces of capability #1 (mutating
// rotation), kept in ONE place so later phases (GPU-shuffle/encrypted-memory/RAG
// in cap #3, and ContextMutationPolicy in cap #5) reuse the SAME apply site:
//
//  1. MutationApplier — resolves the EFFECTIVE overlay for a Rotate action
//     (RotateAction.Overrides wins over RotateAction.PolicyRef -> the matched
//     AMTD's Spec.InferenceRotation, per D1 precedence) and applies it to a
//     PodSpec. Phase 1 interprets ONLY the image / env / gpu-quantity primitives
//     (arch §2.4). GPU-shuffle modes, encrypted memory, RAG and endpoint rotation
//     are Phase 3 and are intentionally not interpreted.
//
//  2. classifyTopOwner — the D3 mutation-survival classifier (arch §1.3 #7, §3):
//     it walks the pod's ownerReferences to the TOP controller and decides whether
//     a mutation can be made DURABLE (patch the top owner's PodTemplateSpec, all
//     replicas) or must fall back to a non-durable cold reschedule with an honest
//     Status reason (BarePod | ImmutableJobTemplate | PerPodOnSharedTemplate).
package controller

import (
	"context"
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// EffectiveSourceContextMutationPolicy is the EffectiveSource string written to
// AMTDStatus when a Rotate's overlay was resolved from a ContextMutationPolicy
// (D7g). It is the CMP peer of "InferenceRotation" / "RotateAction.Overrides".
const EffectiveSourceContextMutationPolicy = "ContextMutationPolicy"

// gpuResourceName is the GPU resource limit key set by the Phase 1 overlay.
// Phase 1 fixes it to nvidia.com/gpu; GPUShufflePolicy.ResourceName override is
// Phase 3.
const gpuResourceName corev1.ResourceName = "nvidia.com/gpu"

// EffectiveOverlay is the resolved, applier-ready overlay. It is a SUPERSET of
// api InferenceRotationOverlay (which has no ContainerName) so that an overlay
// projected from InferenceRotationSpec can also carry the target container
// selector. Phase 1 fields only (image / env / gpu-quantity).
type EffectiveOverlay struct {
	// ContainerName selects the target container; empty = first/only container.
	ContainerName string
	// Image is the (golden) image to set on the target container; empty = no swap.
	Image string
	// EnvPatch is the set-or-overwrite env list.
	EnvPatch []corev1.EnvVar
	// GPUResource is the nvidia.com/gpu limit quantity as a string; empty = no change.
	GPUResource string
}

// IsEmpty reports whether the overlay would make no change at all (so a Rotate
// degrades to a pure cold reschedule == today's Phase 0 behavior).
func (o EffectiveOverlay) IsEmpty() bool {
	return o.Image == "" && len(o.EnvPatch) == 0 && o.GPUResource == ""
}

// MutationApplier resolves and applies a rotation overlay. It is the SINGLE apply
// site for image/env/gpu mutation so Phase 3 (GPU-shuffle/etc.) and CMP (Phase 5)
// reuse it. There is one concrete implementation (defaultMutationApplier).
type MutationApplier interface {
	// Resolve computes the effective overlay for a Rotate action against the
	// matched AMTD and returns it together with the EffectiveSource string written
	// to AMTDStatus (D1): "RotateAction.Overrides" | "InferenceRotation" |
	// "ContextMutationPolicy" | "".
	//
	// ctx + reader are threaded in so a PolicyRef{Kind:"ContextMutationPolicy"} can
	// be FETCHED (a standalone CMP CR in the AMTD's namespace) and its Mutations[]
	// projected into the overlay (D7g). The inline-Overrides and embedded
	// InferenceRotation legs do not read the cluster, so reader may be nil for those.
	// A fetch error (other than NotFound) is returned; a NotFound CMP degrades to an
	// empty overlay + "" source (honest cold reschedule) with a nil error.
	Resolve(ctx context.Context, reader client.Reader, action *amtdv1beta1.RotateAction, amtd *amtdv1beta1.AdaptiveMovingTargetDefense) (EffectiveOverlay, string, error)
	// ApplyToPodSpec applies the overlay to a PodSpec in place and reports whether
	// any change was made. An empty overlay is a no-op (returns false, nil).
	ApplyToPodSpec(spec *corev1.PodSpec, ov EffectiveOverlay) (bool, error)
}

// defaultMutationApplier is the Phase 1 MutationApplier (image/env/gpu only).
type defaultMutationApplier struct{}

// NewMutationApplier returns the Phase 1 MutationApplier.
func NewMutationApplier() MutationApplier { return defaultMutationApplier{} }

// Resolve implements the D1 overlay-resolution precedence:
//
//   - RotateAction.Overrides set         -> use it inline; source "RotateAction.Overrides".
//   - else RotateAction.PolicyRef set    -> Kind defaulting per LocalPolicyRef:
//     empty Kind OR "InferenceRotation"  -> project the matched AMTD's
//     Spec.InferenceRotation; source "InferenceRotation".
//     "ContextMutationPolicy"            -> FETCH the named ContextMutationPolicy
//     in the AMTD's namespace and project its Mutations[] into the overlay; source
//     "ContextMutationPolicy" (D7g). A NotFound CMP degrades to empty + "" (cold).
//   - else (both nil)                    -> empty overlay; source "" (pure cold reschedule).
//
// Inline Overrides ALWAYS wins over PolicyRef (D1 precedence).
func (defaultMutationApplier) Resolve(ctx context.Context, reader client.Reader, action *amtdv1beta1.RotateAction, amtd *amtdv1beta1.AdaptiveMovingTargetDefense) (EffectiveOverlay, string, error) {
	if action == nil {
		return EffectiveOverlay{}, "", nil
	}

	// (1) inline Overrides win.
	if action.Overrides != nil {
		ov := EffectiveOverlay{
			Image:       action.Overrides.Image,
			EnvPatch:    action.Overrides.EnvPatch,
			GPUResource: action.Overrides.GPUResource,
			// InferenceRotationOverlay carries no ContainerName in Phase 1; the
			// overlay targets the default (first/only) container.
		}
		return ov, "RotateAction.Overrides", nil
	}

	// (2) PolicyRef -> InferenceRotation (embedded) OR ContextMutationPolicy (standalone).
	if action.PolicyRef != nil {
		switch action.PolicyRef.Kind {
		case "", "InferenceRotation":
			if amtd != nil && amtd.Spec.InferenceRotation != nil {
				ir := amtd.Spec.InferenceRotation
				return EffectiveOverlay{
					ContainerName: ir.ContainerName,
					Image:         ir.GoldenImage,
					EnvPatch:      ir.EnvPatch,
					GPUResource:   ir.GPUResource,
				}, "InferenceRotation", nil
			}
			// PolicyRef points at InferenceRotation but the AMTD has none: nothing
			// to apply -> degrade to cold reschedule.
			return EffectiveOverlay{}, "", nil
		case EffectiveSourceContextMutationPolicy:
			// D7g: FETCH the named ContextMutationPolicy in the AMTD's namespace and
			// project its Mutations[] into the SAME EffectiveOverlay the embedded
			// InferenceRotation/Overrides resolve to. This binds CMP Mutations[] to the
			// one apply site (ApplyToPodSpec), so D3 routing + D22 guards are reused
			// unchanged. A nameless ref or a NotFound CMP degrades to a cold reschedule
			// (empty overlay, "" source, nil error) — honest, not a false durability.
			if reader == nil || amtd == nil || action.PolicyRef.Name == "" {
				return EffectiveOverlay{}, "", nil
			}
			cmp := &amtdv1beta1.ContextMutationPolicy{}
			key := types.NamespacedName{Namespace: amtd.Namespace, Name: action.PolicyRef.Name}
			if err := reader.Get(ctx, key, cmp); err != nil {
				if apierrors.IsNotFound(err) {
					return EffectiveOverlay{}, "", nil
				}
				return EffectiveOverlay{}, "", fmt.Errorf("resolve ContextMutationPolicy %s: %w", key, err)
			}
			ov, _ := projectCMPMutations(cmp.Spec.Mutations)
			if ov.IsEmpty() {
				// The CMP declared no projectable image/env/gpu mutation -> cold.
				return EffectiveOverlay{}, "", nil
			}
			return ov, EffectiveSourceContextMutationPolicy, nil
		default:
			return EffectiveOverlay{}, "", nil
		}
	}

	// (3) both nil.
	return EffectiveOverlay{}, "", nil
}

// projectCMPMutations projects a ContextMutationPolicy's typed Mutations[] (ADA
// Listing 1) into the Phase-1 EffectiveOverlay (image/env/gpu only), using the SAME
// primitives ApplyToPodSpec interprets. It returns the overlay and a human-readable
// summary of what was (and was NOT) projected.
//
// Projection map:
//   - ContainerImageUpdate -> ContainerName + Image (NewImage)
//   - ResourceAdjustment   -> ContainerName + GPUResource = limits["nvidia.com/gpu"]
//   - EnvPatch             -> ContainerName + EnvPatch (Env)
//
// NOT-APPLIED (documented, NOT silently dropped): a ResourceAdjustment's cpu/memory
// REQUESTS are BEYOND the Phase-1 image/env/gpu overlay (EffectiveOverlay carries no
// requests fields). They are recognized here and surfaced in the summary as a
// "(cpu/mem requests recognized, not applied)" note; projecting them is an overlay
// extension deferred to a later phase (per the Stage-2 extend-OR-document decision).
//
// ContainerName precedence: the LAST non-empty ContainerName across the mutation set
// wins (Listing 1 names the same container "nim" on every mutation, so this is a
// no-op there; if mutations disagree, the overlay still targets a single container,
// matching the single-container EffectiveOverlay contract).
func projectCMPMutations(muts []amtdv1beta1.CMPMutation) (EffectiveOverlay, string) {
	ov := EffectiveOverlay{}
	requestsNotApplied := false
	for i := range muts {
		m := muts[i]
		if m.ContainerName != "" {
			ov.ContainerName = m.ContainerName
		}
		switch m.Type {
		case amtdv1beta1.CMPMutationContainerImageUpdate:
			if m.NewImage != "" {
				ov.Image = m.NewImage
			}
		case amtdv1beta1.CMPMutationResourceAdjustment:
			if m.Resources != nil {
				if q, ok := m.Resources.Limits[gpuResourceName]; ok {
					ov.GPUResource = q.String()
				}
				if len(m.Resources.Requests) > 0 {
					requestsNotApplied = true
				}
			}
		case amtdv1beta1.CMPMutationEnvPatch:
			if len(m.Env) > 0 {
				ov.EnvPatch = append(ov.EnvPatch, m.Env...)
			}
		}
	}
	return ov, summarizeOverlay(ov, requestsNotApplied)
}

// summarizeOverlay renders a one-line summary of a projected overlay for the CMP
// Status.ResolvedMutationSummary (and audit). requestsNotApplied appends the honest
// cpu/memory-requests note when a ResourceAdjustment carried requests the Phase-1
// overlay does not interpret.
func summarizeOverlay(ov EffectiveOverlay, requestsNotApplied bool) string {
	parts := []string{}
	if ov.Image != "" {
		parts = append(parts, "image="+ov.Image)
	}
	if ov.GPUResource != "" {
		parts = append(parts, "gpu="+ov.GPUResource)
	}
	if len(ov.EnvPatch) > 0 {
		names := make([]string, 0, len(ov.EnvPatch))
		for _, e := range ov.EnvPatch {
			names = append(names, e.Name)
		}
		parts = append(parts, "env="+strings.Join(names, ","))
	}
	if ov.ContainerName != "" {
		parts = append(parts, "container="+ov.ContainerName)
	}
	s := "none"
	if len(parts) > 0 {
		s = strings.Join(parts, "; ")
	}
	if requestsNotApplied {
		s += " (cpu/mem requests recognized, not applied)"
	}
	return s
}

// ApplyToPodSpec applies the Phase 1 primitives (image / env / gpu-quantity) to
// spec in place. It returns whether any change was made (so an empty overlay
// stays a pure no-op and the path remains a cold reschedule). The GPU quantity is
// parsed with resource.ParseQuantity (NOT MustParse) so a malformed value returns
// an error instead of panicking.
func (defaultMutationApplier) ApplyToPodSpec(spec *corev1.PodSpec, ov EffectiveOverlay) (bool, error) {
	if ov.IsEmpty() {
		return false, nil
	}
	if spec == nil || len(spec.Containers) == 0 {
		return false, fmt.Errorf("cannot apply rotation overlay: pod spec has no containers")
	}

	// Container selection: ContainerName if set, else the first container.
	idx := 0
	if ov.ContainerName != "" {
		found := -1
		for i := range spec.Containers {
			if spec.Containers[i].Name == ov.ContainerName {
				found = i
				break
			}
		}
		if found < 0 {
			return false, fmt.Errorf("cannot apply rotation overlay: container %q not found in pod spec", ov.ContainerName)
		}
		idx = found
	}
	c := &spec.Containers[idx]

	changed := false

	// IMAGE swap.
	if ov.Image != "" && c.Image != ov.Image {
		c.Image = ov.Image
		changed = true
	}

	// ENV set-or-overwrite by Name.
	for _, e := range ov.EnvPatch {
		replaced := false
		for i := range c.Env {
			if c.Env[i].Name == e.Name {
				if !envVarEqual(c.Env[i], e) {
					c.Env[i] = e
					changed = true
				}
				replaced = true
				break
			}
		}
		if !replaced {
			c.Env = append(c.Env, e)
			changed = true
		}
	}

	// GPU limit quantity (nvidia.com/gpu). "0" => DropToZero quarantine.
	if ov.GPUResource != "" {
		q, err := resource.ParseQuantity(ov.GPUResource)
		if err != nil {
			return changed, fmt.Errorf("cannot apply rotation overlay: invalid GPUResource quantity %q: %w", ov.GPUResource, err)
		}
		if c.Resources.Limits == nil {
			c.Resources.Limits = corev1.ResourceList{}
		}
		if cur, ok := c.Resources.Limits[gpuResourceName]; !ok || cur.Cmp(q) != 0 {
			c.Resources.Limits[gpuResourceName] = q
			changed = true
		}
	}

	return changed, nil
}

// envVarEqual compares two EnvVars by the fields Phase 1 sets (Name/Value and the
// ValueFrom pointer identity is compared shallowly: a differing ValueFrom is
// treated as changed). It exists so a re-apply of an already-applied env does not
// spuriously report a change (idempotence for the owner-template self-Update guard).
func envVarEqual(a, b corev1.EnvVar) bool {
	if a.Name != b.Name || a.Value != b.Value {
		return false
	}
	// Both nil ValueFrom is the common Phase 1 case (RUNTIME_MODE=SECURE).
	return (a.ValueFrom == nil) == (b.ValueFrom == nil)
}

// ----------------------------------------------------------------------------
// D3 owner-walk classifier (arch §1.3 #7, §3)
// ----------------------------------------------------------------------------

// rotationRoute is the D3 routing decision for a pod.
type rotationRoute int

const (
	// routeColdNoOverlay: the overlay is empty, so there is nothing to make
	// durable; perform a pure cold reschedule (RotationPathFired="cold",
	// MutationDurable=false, no MutationNotDurableReason since nothing was mutated).
	routeColdNoOverlay rotationRoute = iota
	// routeDurableOwnerTemplate: a non-empty overlay AND a workload-wide mutable
	// top owner (Deployment via ReplicaSet / StatefulSet / DaemonSet) -> patch the
	// TOP owner PodTemplateSpec (durable, all replicas) then cold-reschedule the
	// pod. MutationDurable=true, RotationPathFired="Rotate".
	routeDurableOwnerTemplate
	// routeColdFallback: a non-empty overlay but durable per-pod mutation is
	// physically impossible (bare pod / Job-owned immutable template / per-pod on
	// shared template without a warm pool) -> cold fallback. MutationDurable=false
	// + a MutationNotDurableReason.
	routeColdFallback
)

// D3 non-durability reasons (the exact arch §1.3 #7 / D3 tokens).
const (
	reasonBarePod                = "BarePod"
	reasonImmutableJobTemplate   = "ImmutableJobTemplate"
	reasonPerPodOnSharedTemplate = "PerPodOnSharedTemplate"
)

// topOwner identifies the durable patch target discovered by the owner walk.
type topOwner struct {
	kind      string // "Deployment" | "StatefulSet" | "DaemonSet"
	namespace string
	name      string
}

// classifyTopOwner walks pod.OwnerReferences to the TOP controller and returns
// the D3 route, the durable top-owner target (only set for
// routeDurableOwnerTemplate), and the non-durability reason (only set for
// routeColdFallback). overlayEmpty short-circuits to routeColdNoOverlay so a
// nil-overlay Rotate stays exactly today's cold reschedule with no false
// durability claim.
//
// Walk rules (controller=true ownerReferences):
//   - no controller owner                -> BARE pod                 (cold fallback)
//   - Job owner                          -> immutable .spec.template (cold fallback)
//   - ReplicaSet owner -> ascend to its Deployment -> DURABLE (top = Deployment);
//     a BARE ReplicaSet (no Deployment owner) is NOT a durable target -> we never
//     patch a bare ReplicaSet directly, so it is a per-pod-on-shared-template cold
//     fallback.
//   - StatefulSet / DaemonSet owner      -> DURABLE (top = that owner).
//   - any other / unknown controller     -> per-pod-on-shared-template cold fallback.
func classifyTopOwner(ctx context.Context, c client.Client, pod *corev1.Pod, overlayEmpty bool) (rotationRoute, *topOwner, string) {
	if overlayEmpty {
		return routeColdNoOverlay, nil, ""
	}

	ctrlRef := metav1.GetControllerOf(pod)
	if ctrlRef == nil {
		return routeColdFallback, nil, reasonBarePod
	}

	switch ctrlRef.Kind {
	case "Job":
		// Job .spec.template is immutable -> mutation cannot survive recreate.
		return routeColdFallback, nil, reasonImmutableJobTemplate

	case "StatefulSet":
		return routeDurableOwnerTemplate, &topOwner{kind: "StatefulSet", namespace: pod.Namespace, name: ctrlRef.Name}, ""

	case "DaemonSet":
		return routeDurableOwnerTemplate, &topOwner{kind: "DaemonSet", namespace: pod.Namespace, name: ctrlRef.Name}, ""

	case "ReplicaSet":
		// Ascend ReplicaSet -> Deployment. NEVER patch a bare ReplicaSet directly.
		rs := &appsv1.ReplicaSet{}
		if err := c.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: ctrlRef.Name}, rs); err != nil {
			// Cannot resolve the RS (e.g. RBAC/not-found): be honest, treat as a
			// per-pod-on-shared-template cold fallback rather than guessing a
			// durable target.
			return routeColdFallback, nil, reasonPerPodOnSharedTemplate
		}
		if dep := metav1.GetControllerOf(rs); dep != nil && dep.Kind == "Deployment" {
			return routeDurableOwnerTemplate, &topOwner{kind: "Deployment", namespace: rs.Namespace, name: dep.Name}, ""
		}
		// Bare ReplicaSet (no Deployment owner): not a durable target.
		return routeColdFallback, nil, reasonPerPodOnSharedTemplate

	default:
		// Unknown controller kind owning a shared template, no warm pool here in
		// Phase 1 (WarmInferenceSet cutover is Phase 4) -> cold fallback.
		return routeColdFallback, nil, reasonPerPodOnSharedTemplate
	}
}

// patchOwnerTemplate applies the overlay to the TOP owner's PodTemplateSpec and
// Updates it, making the mutation durable for ALL replicas (D3 route (a)). It is
// idempotent: if the template already carries the target image/env/gpu the
// ApplyToPodSpec returns changed=false and NO Update is issued — this is the guard
// against re-triggering the AMTD self-Update reconcile loop. It returns whether an
// update was actually written.
func patchOwnerTemplate(ctx context.Context, c client.Client, applier MutationApplier, top *topOwner, ov EffectiveOverlay) (bool, error) {
	switch top.kind {
	case "Deployment":
		obj := &appsv1.Deployment{}
		if err := c.Get(ctx, types.NamespacedName{Namespace: top.namespace, Name: top.name}, obj); err != nil {
			return false, err
		}
		changed, err := applier.ApplyToPodSpec(&obj.Spec.Template.Spec, ov)
		if err != nil || !changed {
			return false, err
		}
		return true, c.Update(ctx, obj)

	case "StatefulSet":
		obj := &appsv1.StatefulSet{}
		if err := c.Get(ctx, types.NamespacedName{Namespace: top.namespace, Name: top.name}, obj); err != nil {
			return false, err
		}
		changed, err := applier.ApplyToPodSpec(&obj.Spec.Template.Spec, ov)
		if err != nil || !changed {
			return false, err
		}
		return true, c.Update(ctx, obj)

	case "DaemonSet":
		obj := &appsv1.DaemonSet{}
		if err := c.Get(ctx, types.NamespacedName{Namespace: top.namespace, Name: top.name}, obj); err != nil {
			return false, err
		}
		changed, err := applier.ApplyToPodSpec(&obj.Spec.Template.Spec, ov)
		if err != nil || !changed {
			return false, err
		}
		return true, c.Update(ctx, obj)

	default:
		return false, fmt.Errorf("patchOwnerTemplate: unsupported top owner kind %q", top.kind)
	}
}
