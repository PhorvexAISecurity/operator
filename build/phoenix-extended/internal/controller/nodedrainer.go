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

// Package controller — cap#7 NodeDrainer + CleanNodeSelector (arch §3 cap#7,
// decisions D25g2/D25g3/D25g4).
//
// NodeDrainer does the REAL source-node operations of a node rotation:
//   - Cordon: patch node.Spec.Unschedulable=true (reversible; the D25g2 default).
//   - Taint:  append an AMTD-managed NoSchedule taint to node.Spec.Taints.
//     NoExecute is explicitly NOT auto-applied (a separate PDB-bypassing
//     rung, D25g2).
//   - Uncordon: set Unschedulable=false (rollback + teardown; Cordon is reversible).
//   - Drain:  evict pods via the policy/v1 EVICTION subresource so PodDisruption
//     Budgets are honored (D25g3). DEFAULT targeted-pod-only when
//     DrainPolicy.DrainCoTenants is false; co-tenant drain is opt-in and
//     skips DaemonSet/mirror pods.
//
// CleanNodeSelector picks the destination clean node (D25g4): the label-pool
// default r6security.com/clean-pool=true, schedulable, EXCLUDING the source/cordoned/
// tainted/excluded nodes, with a PVC-topology preflight (and a GPU-MIG preflight
// seam that is GPU-PENDING on kind). It returns a NoCleanTarget reason rather than
// landing an unschedulable pod.
package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// amtdNodeRotateTaintKey is the key of the AMTD-managed NoSchedule taint applied by
// the Taint disposition (D25g2). It is AMTD-owned so Uncordon/teardown can remove it.
const amtdNodeRotateTaintKey = "amtd.r6security.com/node-rotation"

// defaultEvictionGracePeriodSeconds reuses the NIM 30s grace when DrainPolicy
// GracePeriodSeconds is nil (D25g3 / matches the rest of the operator).
const defaultEvictionGracePeriodSeconds int64 = 30

// NodeDrainer performs the real cordon/taint/uncordon/drain source-node operations
// of a node rotation through the EVICTION API (PDB-honoring).
type NodeDrainer struct {
	client.Client
}

// Cordon marks the node unschedulable (node.Spec.Unschedulable=true). It re-reads
// the node and is idempotent: if already unschedulable, no Update is issued (the
// same self-Update-guard discipline as patchOwnerTemplate).
func (d *NodeDrainer) Cordon(ctx context.Context, nodeName string) error {
	node := &corev1.Node{}
	if err := d.Get(ctx, client.ObjectKey{Name: nodeName}, node); err != nil {
		return err
	}
	if node.Spec.Unschedulable {
		return nil
	}
	node.Spec.Unschedulable = true
	return d.Update(ctx, node)
}

// Uncordon sets node.Spec.Unschedulable=false (rollback + teardown). Idempotent.
func (d *NodeDrainer) Uncordon(ctx context.Context, nodeName string) error {
	node := &corev1.Node{}
	if err := d.Get(ctx, client.ObjectKey{Name: nodeName}, node); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !node.Spec.Unschedulable {
		return nil
	}
	node.Spec.Unschedulable = false
	return d.Update(ctx, node)
}

// Taint appends the AMTD-managed NoSchedule taint to node.Spec.Taints (D25g2). It
// is idempotent (skip if the AMTD taint is already present). NoExecute is NOT
// applied here — it is a separate, PDB-bypassing escalation rung, intentionally not
// auto-applied.
func (d *NodeDrainer) Taint(ctx context.Context, nodeName string) error {
	node := &corev1.Node{}
	if err := d.Get(ctx, client.ObjectKey{Name: nodeName}, node); err != nil {
		return err
	}
	for i := range node.Spec.Taints {
		if node.Spec.Taints[i].Key == amtdNodeRotateTaintKey {
			return nil // already tainted
		}
	}
	node.Spec.Taints = append(node.Spec.Taints, corev1.Taint{
		Key:    amtdNodeRotateTaintKey,
		Value:  "true",
		Effect: corev1.TaintEffectNoSchedule,
	})
	return d.Update(ctx, node)
}

// RemoveTaint removes the AMTD-managed taint (teardown/rollback). Idempotent.
func (d *NodeDrainer) RemoveTaint(ctx context.Context, nodeName string) error {
	node := &corev1.Node{}
	if err := d.Get(ctx, client.ObjectKey{Name: nodeName}, node); err != nil {
		return client.IgnoreNotFound(err)
	}
	kept := node.Spec.Taints[:0]
	changed := false
	for _, t := range node.Spec.Taints {
		if t.Key == amtdNodeRotateTaintKey {
			changed = true
			continue
		}
		kept = append(kept, t)
	}
	if !changed {
		return nil
	}
	node.Spec.Taints = kept
	return d.Update(ctx, node)
}

// drainResult reports what a Drain did (for the Status mirror + tests).
type drainResult struct {
	// EvictedTargeted is the number of targeted pods evicted.
	EvictedTargeted int
	// EvictedCoTenants is the number of co-resident pods evicted (only > 0 when
	// DrainPolicy.DrainCoTenants is set).
	EvictedCoTenants int
}

// Drain evicts pods OFF the source node via the policy/v1 Eviction subresource
// (PDB-honoring, D25g3). The DEFAULT (policy nil or DrainCoTenants=false) evicts
// ONLY the targeted pods. When DrainPolicy.DrainCoTenants is true it additionally
// evicts the node's co-resident pods, SKIPPING DaemonSet-owned and mirror pods.
//
// A 429 (PDB block / TooManyRequests) on a co-tenant is treated as "not yet
// evictable" and surfaced as an error so the reconciler can REQUEUE rather than
// force-delete (we never break a co-tenant quorum). A NotFound (already gone) is a
// success.
func (d *NodeDrainer) Drain(ctx context.Context, nodeName string, targets []corev1.Pod, policy *amtdv1beta1.DrainPolicy, logger logr.Logger) (drainResult, error) {
	res := drainResult{}
	grace := defaultEvictionGracePeriodSeconds
	if policy != nil && policy.GracePeriodSeconds != nil {
		grace = *policy.GracePeriodSeconds
	}

	// (1) targeted pods (always, the D25g3 default).
	for i := range targets {
		p := &targets[i]
		if p.DeletionTimestamp != nil {
			continue // already terminating
		}
		if err := d.evictPod(ctx, p, grace); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return res, err
		}
		res.EvictedTargeted++
	}

	// (2) co-tenant drain only when explicitly opted in (D25g3).
	if policy == nil || !policy.DrainCoTenants {
		return res, nil
	}

	var podList corev1.PodList
	if err := d.List(ctx, &podList, client.MatchingFields{"spec.nodeName": nodeName}); err != nil {
		// Field-index may be unavailable (fake client / no index): fall back to a
		// full list + in-memory node filter.
		podList = corev1.PodList{}
		if err2 := d.List(ctx, &podList); err2 != nil {
			return res, err2
		}
	}
	targetedSet := map[string]struct{}{}
	for i := range targets {
		targetedSet[targets[i].Namespace+"/"+targets[i].Name] = struct{}{}
	}
	for i := range podList.Items {
		p := &podList.Items[i]
		if p.Spec.NodeName != nodeName {
			continue
		}
		if _, isTarget := targetedSet[p.Namespace+"/"+p.Name]; isTarget {
			continue // already evicted above
		}
		if p.DeletionTimestamp != nil {
			continue
		}
		if isDaemonSetOrMirrorPod(p) {
			continue // DaemonSet/mirror pods are skipped by default (D25g3)
		}
		if err := d.evictPod(ctx, p, grace); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			// 429/PDB block: surface so the reconciler requeues (no force-delete).
			return res, fmt.Errorf("evict co-tenant %s/%s: %w", p.Namespace, p.Name, err)
		}
		res.EvictedCoTenants++
	}
	return res, nil
}

// evictPod issues a policy/v1 Eviction for the pod via the eviction subresource so
// the apiserver enforces any PodDisruptionBudget. This is the load-bearing
// PDB-honoring primitive (D25g3) — NOT a raw delete.
func (d *NodeDrainer) evictPod(ctx context.Context, pod *corev1.Pod, graceSeconds int64) error {
	eviction := &policyv1.Eviction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pod.Name,
			Namespace: pod.Namespace,
		},
		DeleteOptions: &metav1.DeleteOptions{
			GracePeriodSeconds: &graceSeconds,
		},
	}
	return d.SubResource("eviction").Create(ctx, pod, eviction)
}

// isDaemonSetOrMirrorPod reports whether a pod is DaemonSet-owned or a static/mirror
// pod (both are skipped by the default co-tenant drain, D25g3).
func isDaemonSetOrMirrorPod(pod *corev1.Pod) bool {
	if pod.Annotations != nil {
		if _, ok := pod.Annotations[corev1.MirrorPodAnnotationKey]; ok {
			return true
		}
	}
	if ctrlRef := metav1.GetControllerOf(pod); ctrlRef != nil && ctrlRef.Kind == "DaemonSet" {
		return true
	}
	return false
}

// ----------------------------------------------------------------------------
// CleanNodeSelector (D25g4)
// ----------------------------------------------------------------------------

// cleanNodeResult is the outcome of a clean-node selection: a chosen node name, or
// an empty name with a NoCleanTarget reason.
type cleanNodeResult struct {
	NodeName string
	// Reason is one of NoCleanTargetCleanPoolExhausted|PVCTopologyBound|NoMatchingGPU
	// (only set when NodeName is empty).
	Reason string
}

// CleanNodeSelector selects a clean-pool node to relocate a flagged pod onto
// (D25g4). The v1 realization is the label-pool selector; attested/autoscaled pools
// are pluggable behind this same type.
type CleanNodeSelector struct {
	client.Client
}

// SelectCleanNode lists Nodes matching sel (default r6security.com/clean-pool=true),
// keeps only schedulable+untainted ones, EXCLUDES excludeNodes (the source + any
// flagged/cordoned/tainted node), runs the PVC-topology preflight against forPod's
// volumes (and the GPU-MIG preflight seam — GPU-PENDING on kind), and returns the
// first qualifying node. If none qualifies it returns an empty NodeName + a
// NoCleanTarget reason so the reconciler ABORTS rather than landing an
// unschedulable pod.
func (s *CleanNodeSelector) SelectCleanNode(ctx context.Context, forPod *corev1.Pod, sel map[string]string, excludeNodes map[string]struct{}) (cleanNodeResult, error) {
	if len(sel) == 0 {
		sel = amtdv1beta1.DefaultCleanPoolSelector
	}

	var nodes corev1.NodeList
	if err := s.List(ctx, &nodes, client.MatchingLabels(sel)); err != nil {
		return cleanNodeResult{}, err
	}

	// Resolve the pod's node-affined/local PV topology constraints once (D25g4 PVC
	// preflight). A pod bound to a node-affined PV can only relocate to a node that
	// satisfies that PV's nodeAffinity.
	pvTopologyOK, pvErr := s.pvTopologyChecker(ctx, forPod)
	if pvErr != nil {
		return cleanNodeResult{}, pvErr
	}

	sawCandidatePool := false  // a node matched the label pool (before exclusions)
	pvBoundBlockedAll := false // every pool node was rejected by PV topology
	anyPoolNodeAfterExclude := false

	for i := range nodes.Items {
		n := &nodes.Items[i]
		sawCandidatePool = true

		if excludeNodes != nil {
			if _, excluded := excludeNodes[n.Name]; excluded {
				continue
			}
		}
		if n.Spec.Unschedulable {
			continue // cordoned
		}
		if nodeHasBlockingTaint(n) {
			continue // tainted (incl. the AMTD-managed taint)
		}
		anyPoolNodeAfterExclude = true

		// PVC-topology preflight (D25g4): node-affined/local PV must be satisfiable.
		if !pvTopologyOK(n) {
			pvBoundBlockedAll = true
			continue
		}

		// GPU-MIG preflight seam (D25g4): GPU-PENDING on kind. The label-pool +
		// PVC-topology selection is kind-testable; the GPU free-capacity/MIG-profile
		// check is a real-GPU concern and is intentionally a permissive no-op here so
		// kind selection works. A real-GPU impl plugs in behind this method.
		if !s.gpuPreflightOK(n, forPod) {
			continue
		}

		return cleanNodeResult{NodeName: n.Name}, nil
	}

	// Nothing qualified — choose the most specific NoCleanTarget reason.
	switch {
	case anyPoolNodeAfterExclude && pvBoundBlockedAll:
		return cleanNodeResult{Reason: amtdv1beta1.NoCleanTargetPVCTopologyBound}, nil
	case sawCandidatePool:
		// Pool nodes existed but all were excluded/cordoned/tainted, OR PV-bound on a
		// subset; default to pool-exhausted (PVCTopologyBound already returned above
		// when it was the sole blocker).
		return cleanNodeResult{Reason: amtdv1beta1.NoCleanTargetCleanPoolExhausted}, nil
	default:
		return cleanNodeResult{Reason: amtdv1beta1.NoCleanTargetCleanPoolExhausted}, nil
	}
}

// pvTopologyChecker resolves forPod's PVC-backed volumes to their PVs and returns a
// predicate reporting whether a given node satisfies every node-affined PV's
// topology (D25g4). A pod with no node-affined PV always passes (the predicate
// returns true for all nodes). On a PVC/PV resolution miss the pod is treated as
// topology-free (we do not over-block on a transient lookup gap; the scheduler is
// the final admission anyway).
func (s *CleanNodeSelector) pvTopologyChecker(ctx context.Context, forPod *corev1.Pod) (func(*corev1.Node) bool, error) {
	var nodeAffinities []*corev1.VolumeNodeAffinity
	if forPod != nil {
		for vi := range forPod.Spec.Volumes {
			v := &forPod.Spec.Volumes[vi]
			if v.PersistentVolumeClaim == nil {
				continue
			}
			pvc := &corev1.PersistentVolumeClaim{}
			if err := s.Get(ctx, client.ObjectKey{Namespace: forPod.Namespace, Name: v.PersistentVolumeClaim.ClaimName}, pvc); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, err
			}
			if pvc.Spec.VolumeName == "" {
				continue
			}
			pv := &corev1.PersistentVolume{}
			if err := s.Get(ctx, client.ObjectKey{Name: pvc.Spec.VolumeName}, pv); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}
				return nil, err
			}
			if pv.Spec.NodeAffinity != nil && pv.Spec.NodeAffinity.Required != nil {
				nodeAffinities = append(nodeAffinities, pv.Spec.NodeAffinity)
			}
		}
	}
	if len(nodeAffinities) == 0 {
		return func(*corev1.Node) bool { return true }, nil
	}
	return func(n *corev1.Node) bool {
		for _, na := range nodeAffinities {
			if !nodeMatchesVolumeAffinity(n, na) {
				return false
			}
		}
		return true
	}, nil
}

// gpuPreflightOK is the GPU-MIG free-capacity/profile preflight seam (D25g4). It is
// GPU-PENDING on kind: the label-pool + PVC-topology selection is kind-testable, but
// real GPU free-capacity/MIG-profile matching needs real hardware. It is a
// permissive no-op here so kind selection works; a real-GPU impl replaces it.
func (s *CleanNodeSelector) gpuPreflightOK(_ *corev1.Node, _ *corev1.Pod) bool {
	return true
}

// nodeHasBlockingTaint reports whether the node carries a NoSchedule/NoExecute
// taint (so it is not a clean destination). It excludes the well-known
// not-ready/unreachable taints? No — any blocking taint disqualifies a "clean"
// destination, which is the conservative reading of D25g4.
func nodeHasBlockingTaint(n *corev1.Node) bool {
	for i := range n.Spec.Taints {
		e := n.Spec.Taints[i].Effect
		if e == corev1.TaintEffectNoSchedule || e == corev1.TaintEffectNoExecute {
			return true
		}
	}
	return false
}

// nodeMatchesVolumeAffinity reports whether the node satisfies a PV's required
// node-affinity (the local/topology-PV binding, D25g4). It evaluates the node
// selector terms against the node's labels (a node satisfies the affinity if it
// matches ANY term; within a term all match-expressions must hold).
func nodeMatchesVolumeAffinity(node *corev1.Node, na *corev1.VolumeNodeAffinity) bool {
	if na == nil || na.Required == nil || len(na.Required.NodeSelectorTerms) == 0 {
		return true
	}
	for _, term := range na.Required.NodeSelectorTerms {
		if nodeSelectorTermMatches(node, term) {
			return true
		}
	}
	return false
}

// nodeSelectorTermMatches evaluates a single NodeSelectorTerm's match-expressions
// (In/NotIn/Exists/DoesNotExist) against the node's labels. All expressions in the
// term must hold (AND). Match-fields are not evaluated (PV topology uses labels).
func nodeSelectorTermMatches(node *corev1.Node, term corev1.NodeSelectorTerm) bool {
	for _, expr := range term.MatchExpressions {
		val, has := node.Labels[expr.Key]
		switch expr.Operator {
		case corev1.NodeSelectorOpIn:
			if !has || !containsString(expr.Values, val) {
				return false
			}
		case corev1.NodeSelectorOpNotIn:
			if has && containsString(expr.Values, val) {
				return false
			}
		case corev1.NodeSelectorOpExists:
			if !has {
				return false
			}
		case corev1.NodeSelectorOpDoesNotExist:
			if has {
				return false
			}
		default:
			// Gt/Lt over labels are not used by PV topology; treat as non-matching to
			// stay conservative.
			return false
		}
	}
	return true
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
