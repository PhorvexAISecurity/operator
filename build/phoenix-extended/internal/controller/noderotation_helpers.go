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

// Package controller — NodeRotationReconciler durable-state + pinning helpers
// (cap#7, D25g4). Mirrors the swap.go re-read-before-write annotation discipline.
package controller

import (
	"context"
	"encoding/json"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// maxNodeRotationHistory bounds the AMTDStatus.NodeRotations[] history (cap N=20, a
// flagged proposal, arch §2.3).
const maxNodeRotationHistory = 20

// pinReplacementLabel/annotation mark a pinned-recreated replacement so it is not
// re-processed. The recreated pod carries NO rotation-in-progress lock (clearing it,
// so NIM resumes), and an annotation recording the clean node it was pinned to.
const annNodeRotPinnedTo = "amtd.r6security.com/noderotation-pinned-to"

// annNodeRotBareSnapshot holds the JSON snapshot of the BARE targeted pods captured
// before eviction (relocate-before-dispose, D25g4). The Pinning phase rebuilds the
// pinned replacement from this durable snapshot, so the flow is restart-safe even
// after the bare pod has been evicted off the source.
const annNodeRotBareSnapshot = "amtd.r6security.com/noderotation-bare-snapshot"

// barePodSnapshot is the minimal restorable shape of a bare pod (name/namespace/
// labels/non-lock annotations/spec) captured before eviction.
type barePodSnapshot struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Spec        corev1.PodSpec    `json:"spec"`
}

// snapshotBareTargets records a JSON snapshot of the BARE (no-controller-owner)
// targeted pods on the NodeRotation BEFORE they are evicted, so the Pinning phase can
// rebuild the pinned replacement. Idempotent: if a snapshot already exists (a resume
// after the drain already ran), it is not overwritten.
func (r *NodeRotationReconciler) snapshotBareTargets(ctx context.Context, nr *amtdv1beta1.NodeRotation, targets []corev1.Pod) error {
	if nr.Annotations != nil && nr.Annotations[annNodeRotBareSnapshot] != "" {
		return nil
	}
	snaps := make([]barePodSnapshot, 0, len(targets))
	for i := range targets {
		p := &targets[i]
		if metav1.GetControllerOf(p) != nil {
			continue // owner-managed: controller recreates it
		}
		snaps = append(snaps, barePodSnapshot{
			Name:        p.Name,
			Namespace:   p.Namespace,
			Labels:      p.Labels,
			Annotations: p.Annotations,
			Spec:        *p.Spec.DeepCopy(),
		})
	}
	if len(snaps) == 0 {
		return nil
	}
	raw, err := json.Marshal(snaps)
	if err != nil {
		return err
	}
	return r.setAnnotations(ctx, nr, map[string]string{annNodeRotBareSnapshot: string(raw)})
}

// loadBareSnapshots decodes the bare-pod snapshot annotation (empty => none).
func loadBareSnapshots(nr *amtdv1beta1.NodeRotation) map[string]barePodSnapshot {
	out := map[string]barePodSnapshot{}
	if nr.Annotations == nil {
		return out
	}
	raw := nr.Annotations[annNodeRotBareSnapshot]
	if raw == "" {
		return out
	}
	var snaps []barePodSnapshot
	if err := json.Unmarshal([]byte(raw), &snaps); err != nil {
		return out
	}
	for _, s := range snaps {
		out[s.Namespace+"/"+s.Name] = s
	}
	return out
}

// setAnnotations re-reads the NodeRotation, applies the annotation delta (empty value
// => delete), and persists via a normal Update. It keeps the in-memory nr's
// annotations in sync (mirrors swap.go setSwapAnnotations).
func (r *NodeRotationReconciler) setAnnotations(ctx context.Context, nr *amtdv1beta1.NodeRotation, delta map[string]string) error {
	fresh := &amtdv1beta1.NodeRotation{}
	if err := r.Get(ctx, client.ObjectKey{Name: nr.Name}, fresh); err != nil {
		return client.IgnoreNotFound(err)
	}
	if fresh.Annotations == nil {
		fresh.Annotations = map[string]string{}
	}
	for k, v := range delta {
		if v == "" {
			delete(fresh.Annotations, k)
		} else {
			fresh.Annotations[k] = v
		}
	}
	if err := r.Update(ctx, fresh); err != nil {
		return err
	}
	if nr.Annotations == nil {
		nr.Annotations = map[string]string{}
	}
	for k, v := range delta {
		if v == "" {
			delete(nr.Annotations, k)
		} else {
			nr.Annotations[k] = v
		}
	}
	nr.ResourceVersion = fresh.ResourceVersion
	return nil
}

// mirrorStatus is a BEST-EFFORT status mirror of the durable phase. It re-reads,
// sets Phase + ObservedGeneration, applies the mutate callback, and writes the
// status subresource. A conflict is swallowed (the durable truth lives in the
// annotations). On Completed it also appends the bounded AMTDStatus history entry.
func (r *NodeRotationReconciler) mirrorStatus(ctx context.Context, nr *amtdv1beta1.NodeRotation, phase string, mutate func(*amtdv1beta1.NodeRotationStatus)) {
	fresh := &amtdv1beta1.NodeRotation{}
	if err := r.Get(ctx, client.ObjectKey{Name: nr.Name}, fresh); err != nil {
		return
	}
	fresh.Status.Phase = phase
	fresh.Status.ObservedGeneration = fresh.Generation
	if mutate != nil {
		mutate(&fresh.Status)
	}
	_ = r.Status().Update(ctx, fresh)
}

// setThrottledCondition records the NodeRotationThrottled condition (no-mass-eviction
// deferral, D25g3). Best-effort.
func (r *NodeRotationReconciler) setThrottledCondition(ctx context.Context, nr *amtdv1beta1.NodeRotation, inflight, max int) {
	fresh := &amtdv1beta1.NodeRotation{}
	if err := r.Get(ctx, client.ObjectKey{Name: nr.Name}, fresh); err != nil {
		return
	}
	meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
		Type:               amtdv1beta1.ConditionNodeRotationThrottled,
		Status:             metav1.ConditionTrue,
		Reason:             "MaxConcurrentNodesReached",
		Message:            "The MaxConcurrentNodes ceiling was reached; this node rotation's first cordon is deferred to preserve the no-mass-eviction invariant (D25g3).",
		ObservedGeneration: fresh.Generation,
	})
	_ = r.Status().Update(ctx, fresh)
}

// fetchTargetPods fetches the live TargetPods (missing/already-gone pods are skipped;
// a pod evicted in a prior reconcile is simply absent, which is success on resume).
func (r *NodeRotationReconciler) fetchTargetPods(ctx context.Context, nr *amtdv1beta1.NodeRotation) ([]corev1.Pod, error) {
	out := make([]corev1.Pod, 0, len(nr.Spec.TargetPods))
	for _, ref := range nr.Spec.TargetPods {
		p := &corev1.Pod{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, p); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		out = append(out, *p)
	}
	return out, nil
}

// pinReplacements relocates the targeted pod(s) PINNED to the clean node via
// nodeAffinity on the REPLACEMENT spec (D25g4). For a BARE pod it is a one-shot
// pinned recreate (build a fresh pod spec, strip nodeName, inject the nodeAffinity,
// recreate). For an OWNER-managed pod, a per-pod move on a shared template is
// ill-posed, so durable relocation rides the cap#2 warm-swap shadow when a
// WarmInferenceSet covers the pod; absent that, the replacement is recreated pinned
// (cold fallback). It NEVER sets spec.nodeName and NEVER patches the shared owner
// template.
//
// On kind the recreated replacement lands Pending (fake nodes have no kubelet) —
// the TRUE relocation onto a different REAL clean node is REAL-NODE/GPU-PENDING.
func (r *NodeRotationReconciler) pinReplacements(ctx context.Context, nr *amtdv1beta1.NodeRotation, cleanNode string, logger logr.Logger) ([]amtdv1beta1.NamespacedPodRef, error) {
	relocated := make([]amtdv1beta1.NamespacedPodRef, 0, len(nr.Spec.TargetPods))
	cleanSelector := nr.Spec.EffectiveCleanSelector()
	snapshots := loadBareSnapshots(nr)

	for _, ref := range nr.Spec.TargetPods {
		key := ref.Namespace + "/" + ref.Name

		// BARE pod: rebuild the one-shot pinned replacement from the pre-eviction
		// snapshot (the live pod is gone after eviction). The replacement is pinned via
		// nodeAffinity on the REPLACEMENT spec — never spec.nodeName, never the shared
		// owner template (D25g4).
		if snap, ok := snapshots[key]; ok {
			replacement := buildPinnedReplacementFromSnapshot(snap, cleanNode, cleanSelector)
			// Safety net: delete any lingering original of the same name.
			orig := &corev1.Pod{}
			if err := r.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, orig); err == nil {
				if orig.DeletionTimestamp == nil {
					if err := r.Delete(ctx, orig); err != nil && !apierrors.IsNotFound(err) {
						return nil, err
					}
				}
			}
			if err := r.Create(ctx, replacement); err != nil && !apierrors.IsAlreadyExists(err) {
				return nil, err
			}
			relocated = append(relocated, amtdv1beta1.NamespacedPodRef{Namespace: ref.Namespace, Name: ref.Name})
			continue
		}

		// No snapshot: either the pod is owner-managed (the controller recreates it; per
		// pod pinning rides the cap#2 warm-swap shadow when a WIS covers the pod — the
		// shared owner template is NEVER patched, D25g4), or the pod is still live and
		// bare (a resume before the drain snapshot ran). For an owner-managed live pod we
		// record the relocation intent without patching the template.
		orig := &corev1.Pod{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, orig); err != nil {
			if apierrors.IsNotFound(err) {
				relocated = append(relocated, amtdv1beta1.NamespacedPodRef{Namespace: ref.Namespace, Name: ref.Name})
				continue
			}
			return nil, err
		}
		if metav1.GetControllerOf(orig) != nil {
			logger.Info("NodeRotation: owner-managed pod; per-pod pin rides the warm-swap shadow / controller recreation (shared owner template NOT patched, D25g4)",
				"nodeRotation", nr.Name, "pod", key)
			relocated = append(relocated, amtdv1beta1.NamespacedPodRef{Namespace: ref.Namespace, Name: ref.Name})
			continue
		}
		// Bare + still live (no snapshot taken yet): pinned recreate from the live pod.
		replacement := buildPinnedReplacement(orig, cleanNode, cleanSelector)
		if orig.DeletionTimestamp == nil {
			if err := r.Delete(ctx, orig); err != nil && !apierrors.IsNotFound(err) {
				return nil, err
			}
		}
		if err := r.Create(ctx, replacement); err != nil && !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
		relocated = append(relocated, amtdv1beta1.NamespacedPodRef{Namespace: ref.Namespace, Name: ref.Name})
	}

	// Append the bounded AMTDStatus history entry (best-effort) for each relocated
	// pod's source/target (D25g; arch §2.3).
	r.appendAMTDHistory(ctx, nr, cleanNode, relocated, logger)
	return relocated, nil
}

// buildPinnedReplacement builds a fresh bare-pod replacement from orig, stripping
// nodeName + scheduler-assigned fields and INJECTING nodeAffinity that REQUIRES the
// clean node (by hostname) AND the clean-pool labels (D25g4). The replacement
// carries NO rotation-in-progress annotation (clearing the NIM lock) and is marked
// pinned.
func buildPinnedReplacement(orig *corev1.Pod, cleanNode string, cleanSelector map[string]string) *corev1.Pod {
	spec := *orig.Spec.DeepCopy()
	// NEVER spec.nodeName (bypasses scheduler -> defeats PVC/GPU/taint admission, D25g4).
	spec.NodeName = ""

	// Inject the required nodeAffinity onto the REPLACEMENT spec.
	spec.Affinity = injectCleanNodeAffinity(spec.Affinity, cleanNode, cleanSelector)

	annotations := map[string]string{
		annNodeRotPinnedTo: cleanNode,
	}
	// Carry over non-AMTD-management annotations except the rotation lock.
	for k, v := range orig.Annotations {
		if k == ROTATION_IN_PROGRESS {
			continue // clear the NIM lock so NIM resumes
		}
		if _, exists := annotations[k]; !exists {
			annotations[k] = v
		}
	}

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        orig.Name,
			Namespace:   orig.Namespace,
			Labels:      orig.Labels,
			Annotations: annotations,
		},
		Spec: spec,
	}
}

// buildPinnedReplacementFromSnapshot rebuilds a pinned bare-pod replacement from the
// pre-eviction snapshot (the live pod is gone). It strips nodeName, injects the
// clean-node nodeAffinity, and clears the NIM rotation-in-progress lock.
func buildPinnedReplacementFromSnapshot(snap barePodSnapshot, cleanNode string, cleanSelector map[string]string) *corev1.Pod {
	spec := *snap.Spec.DeepCopy()
	spec.NodeName = "" // NEVER spec.nodeName (D25g4)
	spec.Affinity = injectCleanNodeAffinity(spec.Affinity, cleanNode, cleanSelector)

	annotations := map[string]string{annNodeRotPinnedTo: cleanNode}
	for k, v := range snap.Annotations {
		if k == ROTATION_IN_PROGRESS {
			continue // clear the NIM lock so NIM resumes
		}
		if _, exists := annotations[k]; !exists {
			annotations[k] = v
		}
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        snap.Name,
			Namespace:   snap.Namespace,
			Labels:      snap.Labels,
			Annotations: annotations,
		},
		Spec: spec,
	}
}

// injectCleanNodeAffinity returns an Affinity that REQUIRES (during scheduling) the
// clean node by hostname AND the clean-pool labels. It preserves any existing
// affinity terms by ANDing in a new required node-selector term.
func injectCleanNodeAffinity(existing *corev1.Affinity, cleanNode string, cleanSelector map[string]string) *corev1.Affinity {
	aff := existing
	if aff == nil {
		aff = &corev1.Affinity{}
	}
	if aff.NodeAffinity == nil {
		aff.NodeAffinity = &corev1.NodeAffinity{}
	}
	if aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution = &corev1.NodeSelector{}
	}

	exprs := []corev1.NodeSelectorRequirement{
		{
			Key:      corev1.LabelHostname,
			Operator: corev1.NodeSelectorOpIn,
			Values:   []string{cleanNode},
		},
	}
	for k, v := range cleanSelector {
		exprs = append(exprs, corev1.NodeSelectorRequirement{
			Key:      k,
			Operator: corev1.NodeSelectorOpIn,
			Values:   []string{v},
		})
	}

	ns := aff.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution
	ns.NodeSelectorTerms = append(ns.NodeSelectorTerms, corev1.NodeSelectorTerm{MatchExpressions: exprs})
	return aff
}

// appendAMTDHistory appends a bounded NodeRotationRecord to the governing AMTD's
// Status.NodeRotations[] for each relocated pod (best-effort audit, D25g/arch §2.3).
// The governing AMTD is discovered from the targeted pod's AMTD_MANAGED_BY
// annotation; absent that, the append is skipped (the NodeRotation Status is the
// per-drain record either way).
func (r *NodeRotationReconciler) appendAMTDHistory(ctx context.Context, nr *amtdv1beta1.NodeRotation, cleanNode string, relocated []amtdv1beta1.NamespacedPodRef, logger logr.Logger) {
	amtds := r.governingAMTDs(ctx, nr)
	if len(amtds) == 0 {
		return
	}
	now := metav1.Now()
	for key := range amtds {
		fresh := &amtdv1beta1.AdaptiveMovingTargetDefense{}
		if err := r.Get(ctx, key, fresh); err != nil {
			continue
		}
		for _, ref := range relocated {
			fresh.Status.NodeRotations = append(fresh.Status.NodeRotations, amtdv1beta1.NodeRotationRecord{
				SourceNode: nr.Spec.SourceNode,
				TargetNode: cleanNode,
				PodName:    ref.Namespace + "/" + ref.Name,
				Time:       now,
				Phase:      amtdv1beta1.NodeRotationPhaseCompleted,
			})
		}
		// Bound the history to the last maxNodeRotationHistory entries.
		if n := len(fresh.Status.NodeRotations); n > maxNodeRotationHistory {
			fresh.Status.NodeRotations = fresh.Status.NodeRotations[n-maxNodeRotationHistory:]
		}
		fresh.Status.RotationPathFired = "NodeRotate"
		if err := r.Status().Update(ctx, fresh); err != nil {
			logger.Error(err, "NodeRotation: failed to append AMTD NodeRotations history", "amtd", key.String())
		}
	}
}

// governingAMTDs discovers the set of AMTDs governing the targeted pods (from each
// pod's AMTD_MANAGED_BY annotation). Returns a set of namespaced names.
func (r *NodeRotationReconciler) governingAMTDs(ctx context.Context, nr *amtdv1beta1.NodeRotation) map[client.ObjectKey]struct{} {
	out := map[client.ObjectKey]struct{}{}
	for _, ref := range nr.Spec.TargetPods {
		p := &corev1.Pod{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, p); err != nil {
			continue
		}
		raw, ok := p.Annotations[AMTD_MANAGED_BY]
		if !ok {
			continue
		}
		var infos []AMTDManageInfo
		if err := json.Unmarshal([]byte(raw), &infos); err != nil {
			continue
		}
		for _, info := range infos {
			out[client.ObjectKey{Namespace: info.AMTDNamespace, Name: info.AMTDName}] = struct{}{}
		}
	}
	return out
}
