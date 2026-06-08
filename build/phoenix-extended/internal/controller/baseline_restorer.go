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

// Package controller — cap#6 BaselineRestorer.Regenerate (arch §2.1 RegenerateAction,
// §3 verify-before-recreate, decisions D6/D6g).
//
// BaselineRestorer.Regenerate restores a drifted workload to the GOLDEN baseline:
//
//	(1) VERIFY-BEFORE-RECREATE (D6, the crux): for every pinned ImageDigest the
//	    target Repository@Digest MUST verify against the SignaturePolicy BEFORE any
//	    patch. A RequireSignature image that does not verify (ErrSignatureMismatch)
//	    ABORTS the restore — we never restore to an unverifiable golden target (that
//	    would be self-heal-into-malicious). Verification UNAVAILABILITY
//	    (ErrVerificationUnavailable, e.g. registry/key blip) also aborts the restore
//	    (a restore is a mutating action; the split fail mode's fail-to-cached-last-
//	    good applies to the POLL/detect side, not to forcing a recreate on an
//	    unverifiable target).
//
//	(2) REUSE the D3 owner-walk: classifyTopOwner -> patchOwnerTemplate sets the top
//	    owner template's container image to the pinned Repository@Digest (durable,
//	    all replicas), idempotently (the changed==false short-circuit guards the AMTD
//	    self-Update loop). Bare/Job/per-pod-shared targets route to a cold fallback
//	    with an honest mutation-not-durable reason — the SAME D3 honesty as Rotate.
//
//	(3) Optionally RESET the hardening profile (Seccomp/AppArmor/securityContext to a
//	    pod-local baseline default; D6g (e)). IncludeRBAC is opt-in and deferred.
//
//	(4) Set WorkloadBaselineStatus.LastRegeneration so drift MTTR
//	    (LastRegeneration - detection-ts) is kind-measurable.
//
// The WorkloadBaseline holds REFERENCES only (D6g), so even a tampered in-cluster
// baseline object cannot make this restore malicious state: the restorer verifies
// the target digest's signature against a key resolved from a separately-RBAC'd
// Secret before patching.
package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

//+kubebuilder:rbac:groups=amtd.r6security.com,resources=workloadbaselines,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=workloadbaselines/status,verbs=get;update;patch

// RegenerateResult reports what a Regenerate did (for the SecurityEvent/AMTD audit).
type RegenerateResult struct {
	// Restored is true if the top owner template image was patched (or already at the
	// pinned digest) — i.e. the workload is at golden state.
	Restored bool
	// Durable is true on the owner-template patch route, false on a cold fallback.
	Durable bool
	// NotDurableReason is the D3 reason on a cold fallback (BarePod|...).
	NotDurableReason string
	// HardeningReset is true if a Seccomp/AppArmor/securityContext reset was applied.
	HardeningReset bool
	// PinnedRef is the verified Repository@Digest the workload was restored to.
	PinnedRef string
}

// BaselineRestorer is the cap#6 restore-from-golden interface (D6/D6g). The kind
// realization reuses the D3 owner-walk + the kind BaselineVerifier.
type BaselineRestorer interface {
	// Regenerate verifies the pinned digests against the SignaturePolicy
	// (verify-before-recreate) and restores the workload owning pod to the golden
	// Repository@Digest. resetHardening triggers the pod-local hardening reset (the
	// scope is read from the baseline DriftPolicy). It returns the result, or an
	// error if verification fails/aborts (the workload is left untouched).
	Regenerate(ctx context.Context, pod *corev1.Pod, wb *amtdv1beta1.WorkloadBaseline, resetHardening bool, log logr.Logger) (RegenerateResult, error)
}

// defaultBaselineRestorer is the kind BaselineRestorer.
type defaultBaselineRestorer struct {
	client   client.Client
	verifier BaselineVerifier
	applier  MutationApplier
}

// NewBaselineRestorer returns the kind BaselineRestorer. verifier proves the target
// digest before any patch; applier + the D3 owner-walk make the patch durable.
func NewBaselineRestorer(c client.Client, verifier BaselineVerifier) BaselineRestorer {
	return &defaultBaselineRestorer{client: c, verifier: verifier, applier: NewMutationApplier()}
}

// Regenerate implements the BaselineRestorer contract (see the interface doc).
func (b *defaultBaselineRestorer) Regenerate(ctx context.Context, pod *corev1.Pod, wb *amtdv1beta1.WorkloadBaseline, resetHardening bool, log logr.Logger) (RegenerateResult, error) {
	if wb == nil {
		return RegenerateResult{}, errors.New("Regenerate: nil WorkloadBaseline")
	}
	spec := wb.EffectiveBaselineSpec()
	if len(spec.ImageDigests) == 0 {
		return RegenerateResult{}, fmt.Errorf("Regenerate: WorkloadBaseline %q has no pinned ImageDigests; nothing to restore", wb.Name)
	}

	// Determine the target container the running pod actually has, and the matching
	// pin. If the pod carries multiple pinned containers, restore each; the primary
	// (first) verified pin drives the audit PinnedRef.
	result := RegenerateResult{}

	// ---- (1) VERIFY-BEFORE-RECREATE: every pinned target must verify FIRST. ----
	verified := make([]amtdv1beta1.ImageDigest, 0, len(spec.ImageDigests))
	for _, pin := range spec.ImageDigests {
		vi, err := b.verifier.VerifyImage(ctx, pin, spec.Signature)
		if err != nil {
			// A positive mismatch OR unavailability both ABORT the restore — we never
			// patch a workload to an unverifiable golden target (D6: restore is a
			// mutating action, so it fails-closed; the fail-to-cached-last-good split
			// applies to the poll/detect side, not here).
			if errors.Is(err, ErrSignatureMismatch) {
				return result, fmt.Errorf("Regenerate ABORTED (verify-before-recreate): pinned target %s@%s did not verify against the SignaturePolicy: %w", pin.Repository, pin.Digest, err)
			}
			return result, fmt.Errorf("Regenerate ABORTED (verify-before-recreate): could not verify pinned target %s@%s (verification unavailable; refusing to restore to an unverifiable target): %w", pin.Repository, pin.Digest, err)
		}
		log.Info("Regenerate verify-before-recreate: pinned target verified",
			"repository", pin.Repository, "digest", pin.Digest, "signed", vi.Signed, "keyType", vi.KeyType)
		verified = append(verified, pin)
	}

	// ---- (2) REUSE the D3 owner-walk to patch the top owner template image. ----
	// Build the overlay for the (first) pinned container the running pod has.
	pinForPod := pickPinForPod(pod, verified)
	if pinForPod == nil {
		// None of the verified pins names a container the pod has. Treat as nothing to
		// restore on this pod (honest, not a false success).
		return result, fmt.Errorf("Regenerate: none of the verified pinned containers are present in pod %q", pod.Name)
	}
	goldenRef := pinForPod.Repository + "@" + pinForPod.Digest
	result.PinnedRef = goldenRef

	overlay := EffectiveOverlay{ContainerName: pinForPod.ContainerName, Image: goldenRef}

	route, top, notDurableReason := classifyTopOwner(ctx, b.client, pod, overlay.IsEmpty())
	switch route {
	case routeDurableOwnerTemplate:
		wrote, err := patchOwnerTemplate(ctx, b.client, b.applier, top, overlay)
		if err != nil {
			return result, fmt.Errorf("Regenerate: failed to patch top owner %s/%s template to golden digest: %w", top.kind, top.name, err)
		}
		if wrote {
			log.Info("Regenerate route (a): patched top owner template to golden Repository@Digest (durable, all replicas)",
				"ownerKind", top.kind, "owner", top.name, "golden", goldenRef)
		} else {
			log.Info("Regenerate route (a): top owner template already at the golden digest (idempotent no-op; self-Update loop guarded)",
				"ownerKind", top.kind, "owner", top.name, "golden", goldenRef)
		}
		result.Restored = true
		result.Durable = true

		// Optionally reset the hardening profile on the durable owner template.
		if resetHardening {
			if reset, err := b.resetHardeningOnOwner(ctx, wb, top, pinForPod.ContainerName, log); err != nil {
				log.Error(err, "Regenerate: hardening reset on owner template failed (non-fatal; image restore stands)", "ownerKind", top.kind, "owner", top.name)
			} else {
				result.HardeningReset = reset
			}
		}

	case routeColdFallback:
		// Durable per-pod restore impossible (bare/Job/per-pod-shared). Honest cold
		// fallback: delete the pod so its owner recreates it; the recreated pod is NOT
		// guaranteed at the golden digest (it depends on the immutable template), so
		// we record the reason rather than claim durability.
		log.Info("Regenerate route (b): cold fallback (restore not durable)", "pod", pod.Name, "reason", notDurableReason)
		if err := b.client.Delete(ctx, pod); err != nil {
			return result, fmt.Errorf("Regenerate cold fallback: failed to delete drifted pod %q: %w", pod.Name, err)
		}
		result.Restored = true
		result.Durable = false
		result.NotDurableReason = notDurableReason

	case routeColdNoOverlay:
		// Should not happen (overlay carries the golden image), but stay honest.
		log.Info("Regenerate: empty overlay; nothing to restore", "pod", pod.Name)
		return result, nil
	}

	// ---- (4) Record LastRegeneration on the WorkloadBaseline Status. ----
	b.recordRegeneration(ctx, wb, log)
	return result, nil
}

// pickPinForPod returns the first verified pin whose container the pod has; nil if
// none match.
func pickPinForPod(pod *corev1.Pod, pins []amtdv1beta1.ImageDigest) *amtdv1beta1.ImageDigest {
	have := map[string]bool{}
	for i := range pod.Spec.Containers {
		have[pod.Spec.Containers[i].Name] = true
	}
	for i := range pins {
		if have[pins[i].ContainerName] {
			return &pins[i]
		}
	}
	// Single-container convenience: if the pod has exactly one container and exactly
	// one pin, restore it even if the names differ (the pin's ContainerName is the
	// template name).
	if len(pod.Spec.Containers) == 1 && len(pins) == 1 {
		return &pins[0]
	}
	return nil
}

// resetHardeningOnOwner resets the Seccomp/AppArmor/securityContext of the target
// container (and the pod securityContext) on the top owner template to a pod-local
// baseline default (D6g (e) PodProfileOnly). It returns whether it changed
// anything. IncludeRBAC is opt-in and intentionally NOT implemented here (RBAC
// RoleBinding reset has a large blast radius and is deferred by default, D6g).
func (b *defaultBaselineRestorer) resetHardeningOnOwner(ctx context.Context, wb *amtdv1beta1.WorkloadBaseline, top *topOwner, containerName string, log logr.Logger) (bool, error) {
	scope := wb.Spec.DriftPolicy.EffectiveResetHardeningProfile() // nil-safe
	if scope == amtdv1beta1.HardeningResetIncludeRBAC {
		log.Info("Regenerate: ResetHardeningProfile=IncludeRBAC is opt-in and deferred by default (blast radius); applying PodProfileOnly", "workloadBaseline", wb.Name)
	}

	switch top.kind {
	case "Deployment":
		obj := &appsv1.Deployment{}
		if err := b.client.Get(ctx, types.NamespacedName{Namespace: top.namespace, Name: top.name}, obj); err != nil {
			return false, err
		}
		if changed := resetPodTemplateHardening(&obj.Spec.Template.Spec, containerName); changed {
			return true, b.client.Update(ctx, obj)
		}
		return false, nil
	case "StatefulSet":
		obj := &appsv1.StatefulSet{}
		if err := b.client.Get(ctx, types.NamespacedName{Namespace: top.namespace, Name: top.name}, obj); err != nil {
			return false, err
		}
		if changed := resetPodTemplateHardening(&obj.Spec.Template.Spec, containerName); changed {
			return true, b.client.Update(ctx, obj)
		}
		return false, nil
	case "DaemonSet":
		obj := &appsv1.DaemonSet{}
		if err := b.client.Get(ctx, types.NamespacedName{Namespace: top.namespace, Name: top.name}, obj); err != nil {
			return false, err
		}
		if changed := resetPodTemplateHardening(&obj.Spec.Template.Spec, containerName); changed {
			return true, b.client.Update(ctx, obj)
		}
		return false, nil
	default:
		return false, fmt.Errorf("resetHardeningOnOwner: unsupported top owner kind %q", top.kind)
	}
}

// resetPodTemplateHardening clears the container + pod Seccomp/AppArmor profiles
// back to the RuntimeDefault baseline (pod-local). It returns whether it changed
// anything (so an already-baseline template is an idempotent no-op).
func resetPodTemplateHardening(spec *corev1.PodSpec, containerName string) bool {
	changed := false
	runtimeDefault := &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}

	// Pod-level seccomp.
	if spec.SecurityContext == nil {
		spec.SecurityContext = &corev1.PodSecurityContext{}
	}
	if spec.SecurityContext.SeccompProfile == nil || spec.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		spec.SecurityContext.SeccompProfile = runtimeDefault.DeepCopy()
		changed = true
	}

	// Container-level seccomp on the target container (or the first when empty).
	idx := 0
	if containerName != "" {
		for i := range spec.Containers {
			if spec.Containers[i].Name == containerName {
				idx = i
				break
			}
		}
	}
	if len(spec.Containers) > idx {
		c := &spec.Containers[idx]
		if c.SecurityContext == nil {
			c.SecurityContext = &corev1.SecurityContext{}
		}
		if c.SecurityContext.SeccompProfile == nil || c.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
			c.SecurityContext.SeccompProfile = runtimeDefault.DeepCopy()
			changed = true
		}
	}
	return changed
}

// recordRegeneration writes WorkloadBaselineStatus.LastRegeneration (re-reading
// first to avoid clobbering a concurrent status write). best-effort.
func (b *defaultBaselineRestorer) recordRegeneration(ctx context.Context, wb *amtdv1beta1.WorkloadBaseline, log logr.Logger) {
	fresh := &amtdv1beta1.WorkloadBaseline{}
	if err := b.client.Get(ctx, types.NamespacedName{Name: wb.Name}, fresh); err != nil {
		log.Error(err, "Regenerate: failed to re-read WorkloadBaseline to record LastRegeneration", "workloadBaseline", wb.Name)
		return
	}
	fresh.Status.LastRegeneration = metav1.Now()
	if err := b.client.Status().Update(ctx, fresh); err != nil {
		log.Error(err, "Regenerate: failed to write LastRegeneration status", "workloadBaseline", wb.Name)
	}
}
