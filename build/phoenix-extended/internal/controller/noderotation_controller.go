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

// Package controller — the NodeRotationReconciler (cap#7, arch §3, D25g/D25g2/
// D25g3/D25g4/D26).
//
// The NodeRotationReconciler progresses a single in-flight node drain through the
// phase machine
//
//	Cordoning -> Draining -> Rescheduling -> Pinning -> Completed
//
// (or terminal NoCleanTarget / RolledBack). It is RESTART-SAFE in exactly the
// swap.go shape: the durable phase is stored in an ANNOTATION on the NodeRotation
// (the single source of truth), advanced ONE durable step per reconcile, with a
// re-read-before-write on every transition; Status.Phase is a best-effort mirror.
// A killed-and-restarted operator resumes from the durable phase without
// double-cordoning or double-evicting.
//
// CLASS-(B) CONTINUATION ONLY (arch §1.3 invariant): the reconcile only progresses
// a NodeRotation that a matched NodeRotate action created (Spec.SourceNode set) — it
// NEVER self-initiates a node move. No NodeRotation object => nothing happens.
//
// NO-MASS-EVICTION (D25g3): before the FIRST cordon (Cordoning -> Draining) it
// counts other in-flight NodeRotations (past Cordoning, not terminal) and, if that
// reaches Spec.MaxConcurrentNodes, DEFERS with a NodeRotationThrottled condition.
// This hard ceiling holds regardless of DrainPolicy, so a full-drain config can
// never evict the whole fleet at once.
//
// PINNING (D25g4): the targeted pod is relocated PINNED to the clean node via
// nodeAffinity on the REPLACEMENT pod spec — never spec.nodeName (bypasses the
// scheduler), never the shared owner template (would rotate all replicas). For a
// bare pod this is a one-shot pinned recreate; for an owner-managed pod the
// per-pod move is ill-posed on a shared template, so the durable relocation rides
// the cap#2 warm-swap shadow when a WarmInferenceSet covers the pod (Service
// continuity) — otherwise the replacement is recreated pinned (cold fallback).
//
// REAL-NODE/GPU-PENDING: on kind the cluster has ONE real node and fake Node
// objects have no kubelet, so the TRUE relocation (the targeted pod RUNNING on a
// different real clean node) and the node-rotation MTTR (CompletionTime-StartTime)
// are REAL-NODE/GPU-PENDING and are never measured here. The control plane —
// selection, cordon/taint, drain/evict, the D26 gate, no-mass-eviction,
// NoCleanTarget abort, restart-safe phase progression — is kind-testable.
package controller

import (
	"context"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// Node-rotation durable annotation keys (the single source of truth for in-flight
// drain progress; metadata, written atomically, mirroring swap.go).
const (
	annNodeRotPhase         = "amtd.r6security.com/noderotation-phase"
	annNodeRotStartUnixNano = "amtd.r6security.com/noderotation-start-unixnano"
	annNodeRotCleanNode     = "amtd.r6security.com/noderotation-clean-node"
)

// nodeRotRequeue is how soon to re-reconcile while a node rotation is in flight.
const nodeRotRequeue = 1 * time.Second

// NodeRotationReconciler progresses an in-flight NodeRotation drain (class-B
// continuation; restart-safe).
type NodeRotationReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=amtd.r6security.com,resources=noderotations,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=noderotations/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=noderotations/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;delete
//+kubebuilder:rbac:groups=core,resources=pods/eviction,verbs=create
//+kubebuilder:rbac:groups=core,resources=persistentvolumeclaims;persistentvolumes,verbs=get;list;watch
//+kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch

// Reconcile advances the node-rotation phase machine by at most one durable step.
func (r *NodeRotationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	nr := &amtdv1beta1.NodeRotation{}
	if err := r.Get(ctx, req.NamespacedName, nr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	phase := nr.Annotations[annNodeRotPhase]
	if phase == "" {
		phase = amtdv1beta1.NodeRotationPhaseCordoning
	}

	switch phase {
	case amtdv1beta1.NodeRotationPhaseCordoning:
		return r.doCordon(ctx, nr, logger)
	case amtdv1beta1.NodeRotationPhaseDraining:
		return r.doDrain(ctx, nr, logger)
	case amtdv1beta1.NodeRotationPhaseRescheduling:
		return r.doReschedule(ctx, nr, logger)
	case amtdv1beta1.NodeRotationPhasePinning:
		return r.doPin(ctx, nr, logger)
	case amtdv1beta1.NodeRotationPhaseCompleted,
		amtdv1beta1.NodeRotationPhaseRolledBack,
		amtdv1beta1.NodeRotationPhaseNoCleanTarget:
		// Terminal: nothing to do.
		return ctrl.Result{}, nil
	default:
		return r.doCordon(ctx, nr, logger)
	}
}

// doCordon is the FIRST durable step: it honors the MaxConcurrentNodes ceiling
// (no-mass-eviction), then cordons (or taints/deletes) the source node and
// transitions to Draining. The MaxConcurrentNodes check happens BEFORE the cordon so
// the Nth+1 concurrent rotation is deferred, never cordoning past the ceiling.
func (r *NodeRotationReconciler) doCordon(ctx context.Context, nr *amtdv1beta1.NodeRotation, logger logr.Logger) (ctrl.Result, error) {
	// NO-MASS-EVICTION ceiling (D25g3): count other in-flight rotations.
	if nr.Spec.MaxConcurrentNodes != nil {
		inflight, err := r.countOtherInFlight(ctx, nr.Name)
		if err != nil {
			return ctrl.Result{}, err
		}
		if inflight >= *nr.Spec.MaxConcurrentNodes {
			r.setThrottledCondition(ctx, nr, inflight, *nr.Spec.MaxConcurrentNodes)
			logger.Info("NodeRotation THROTTLED: MaxConcurrentNodes ceiling reached; deferring cordon (no-mass-eviction)",
				"nodeRotation", nr.Name, "inFlight", inflight, "max", *nr.Spec.MaxConcurrentNodes)
			return ctrl.Result{RequeueAfter: nodeRotRequeue}, nil
		}
	}

	drainer := &NodeDrainer{Client: r.Client}
	strategy := nr.Spec.EffectiveStrategy()
	switch strategy {
	case amtdv1beta1.NodeRotationStrategyTaint:
		if err := drainer.Cordon(ctx, nr.Spec.SourceNode); err != nil {
			return r.rollback(ctx, nr, drainer, logger, err)
		}
		if err := drainer.Taint(ctx, nr.Spec.SourceNode); err != nil {
			return r.rollback(ctx, nr, drainer, logger, err)
		}
	case amtdv1beta1.NodeRotationStrategyDelete:
		// Delete disposition: still cordon+relocate FIRST (relocate-before-dispose,
		// D25g2). The Node-object delete (+ optional cloud termination) is performed at
		// Completed time, AFTER the targeted pod is confirmed relocated. Here we only
		// cordon so co-tenants stop scheduling.
		if err := drainer.Cordon(ctx, nr.Spec.SourceNode); err != nil {
			return r.rollback(ctx, nr, drainer, logger, err)
		}
	default: // Cordon (default)
		if err := drainer.Cordon(ctx, nr.Spec.SourceNode); err != nil {
			return r.rollback(ctx, nr, drainer, logger, err)
		}
	}

	startNano := firstNonEmpty(nr.Annotations[annNodeRotStartUnixNano], strconv.FormatInt(time.Now().UnixNano(), 10))
	if err := r.setAnnotations(ctx, nr, map[string]string{
		annNodeRotPhase:         amtdv1beta1.NodeRotationPhaseDraining,
		annNodeRotStartUnixNano: startNano,
	}); err != nil {
		return ctrl.Result{}, err
	}
	r.mirrorStatus(ctx, nr, amtdv1beta1.NodeRotationPhaseDraining, func(st *amtdv1beta1.NodeRotationStatus) {
		st.SourceNode = nr.Spec.SourceNode
		if st.StartTime.IsZero() {
			if n, _ := strconv.ParseInt(startNano, 10, 64); n > 0 {
				st.StartTime = metav1.NewTime(time.Unix(0, n))
			}
		}
	})
	logger.Info("NodeRotation: source node cordoned (relocate-before-dispose); draining targeted pod(s)",
		"nodeRotation", nr.Name, "sourceNode", nr.Spec.SourceNode, "strategy", strategy)
	return ctrl.Result{RequeueAfter: nodeRotRequeue}, nil
}

// doDrain evicts the targeted pod(s) off the source via the Eviction API
// (PDB-honoring; targeted-pod-only default), then transitions to Rescheduling. A
// PDB block (eviction error) requeues rather than force-deletes.
func (r *NodeRotationReconciler) doDrain(ctx context.Context, nr *amtdv1beta1.NodeRotation, logger logr.Logger) (ctrl.Result, error) {
	drainer := &NodeDrainer{Client: r.Client}

	targets, err := r.fetchTargetPods(ctx, nr)
	if err != nil {
		return ctrl.Result{}, err
	}

	// SNAPSHOT the bare targeted pods BEFORE eviction (relocate-before-dispose,
	// D25g4): eviction removes the bare pod, so the Pinning phase rebuilds the pinned
	// replacement from this durable snapshot (restart-safe). Owner-managed pods are
	// recreated by their controller, so they need no snapshot.
	if err := r.snapshotBareTargets(ctx, nr, targets); err != nil {
		return ctrl.Result{}, err
	}

	res, err := drainer.Drain(ctx, nr.Spec.SourceNode, targets, nr.Spec.DrainPolicy, logger)
	if err != nil {
		// PDB block / transient eviction error: requeue (no force-delete).
		logger.Info("NodeRotation: drain deferred (PDB/eviction not yet satisfiable); requeueing",
			"nodeRotation", nr.Name, "err", err.Error())
		return ctrl.Result{RequeueAfter: nodeRotRequeue}, nil
	}

	if err := r.setAnnotations(ctx, nr, map[string]string{annNodeRotPhase: amtdv1beta1.NodeRotationPhaseRescheduling}); err != nil {
		return ctrl.Result{}, err
	}
	r.mirrorStatus(ctx, nr, amtdv1beta1.NodeRotationPhaseRescheduling, func(st *amtdv1beta1.NodeRotationStatus) {
		st.EvictedCoTenants = res.EvictedCoTenants
	})
	logger.Info("NodeRotation: targeted pod(s) evicted off source; selecting a clean node",
		"nodeRotation", nr.Name, "evictedTargeted", res.EvictedTargeted, "evictedCoTenants", res.EvictedCoTenants)
	return ctrl.Result{RequeueAfter: nodeRotRequeue}, nil
}

// doReschedule selects a clean-pool node (CleanNodeSelector). On a miss it ABORTS to
// NoCleanTarget (sets the reason + condition, NO further action) rather than land an
// unschedulable pod (D25g4). On success it records the clean node and transitions to
// Pinning.
func (r *NodeRotationReconciler) doReschedule(ctx context.Context, nr *amtdv1beta1.NodeRotation, logger logr.Logger) (ctrl.Result, error) {
	selector := &CleanNodeSelector{Client: r.Client}

	// Exclude the source node + any node hosting a still-flagged pod (the source is
	// the minimum exclusion; D25g4).
	exclude := map[string]struct{}{nr.Spec.SourceNode: {}}

	// Use the first targeted pod as the relocation subject for PVC/GPU preflight.
	var forPod *corev1.Pod
	targets, err := r.fetchTargetPods(ctx, nr)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(targets) > 0 {
		forPod = &targets[0]
	}

	result, err := selector.SelectCleanNode(ctx, forPod, nr.Spec.EffectiveCleanSelector(), exclude)
	if err != nil {
		return ctrl.Result{}, err
	}
	if result.NodeName == "" {
		// ABORT to NoCleanTarget — never land an unschedulable pod.
		return r.abortNoCleanTarget(ctx, nr, result.Reason, logger)
	}

	if err := r.setAnnotations(ctx, nr, map[string]string{
		annNodeRotPhase:     amtdv1beta1.NodeRotationPhasePinning,
		annNodeRotCleanNode: result.NodeName,
	}); err != nil {
		return ctrl.Result{}, err
	}
	r.mirrorStatus(ctx, nr, amtdv1beta1.NodeRotationPhasePinning, func(st *amtdv1beta1.NodeRotationStatus) {
		st.TargetCleanNode = result.NodeName
	})
	logger.Info("NodeRotation: clean node selected; pinning the replacement via nodeAffinity",
		"nodeRotation", nr.Name, "cleanNode", result.NodeName)
	return ctrl.Result{RequeueAfter: nodeRotRequeue}, nil
}

// doPin recreates the targeted pod(s) PINNED to the clean node via nodeAffinity on
// the REPLACEMENT spec (never spec.nodeName, never the shared owner template,
// D25g4), then transitions to Completed. For a Delete disposition it disposes of the
// source Node object after the relocation.
func (r *NodeRotationReconciler) doPin(ctx context.Context, nr *amtdv1beta1.NodeRotation, logger logr.Logger) (ctrl.Result, error) {
	cleanNode := nr.Annotations[annNodeRotCleanNode]
	if cleanNode == "" {
		cleanNode = nr.Status.TargetCleanNode
	}

	relocated, err := r.pinReplacements(ctx, nr, cleanNode, logger)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Delete disposition: dispose the source Node object AFTER relocation
	// (relocate-before-dispose, D25g2). Cloud-instance termination is a documented
	// extension; the kind/control-plane realization deletes the Node object only.
	if nr.Spec.EffectiveStrategy() == amtdv1beta1.NodeRotationStrategyDelete {
		node := &corev1.Node{}
		if err := r.Get(ctx, client.ObjectKey{Name: nr.Spec.SourceNode}, node); err == nil {
			if delErr := r.Delete(ctx, node); delErr != nil && !apierrors.IsNotFound(delErr) {
				return ctrl.Result{}, delErr
			}
			logger.Info("NodeRotation: source Node object deleted (Delete disposition; cloud termination is a documented extension)",
				"nodeRotation", nr.Name, "sourceNode", nr.Spec.SourceNode)
		}
	}

	// Completed: record CompletionTime + the bounded AMTDStatus history entry.
	if err := r.setAnnotations(ctx, nr, map[string]string{annNodeRotPhase: amtdv1beta1.NodeRotationPhaseCompleted}); err != nil {
		return ctrl.Result{}, err
	}
	r.mirrorStatus(ctx, nr, amtdv1beta1.NodeRotationPhaseCompleted, func(st *amtdv1beta1.NodeRotationStatus) {
		st.TargetCleanNode = cleanNode
		st.RelocatedPods = relocated
		st.CompletionTime = metav1.Now()
	})
	logger.Info("NodeRotation COMPLETE: targeted pod(s) relocated + pinned via nodeAffinity (true relocation onto a different REAL clean node + node-rotation MTTR are REAL-NODE/GPU-PENDING)",
		"nodeRotation", nr.Name, "cleanNode", cleanNode, "relocated", len(relocated))
	return ctrl.Result{}, nil
}

// abortNoCleanTarget records the NoCleanTarget terminal phase + reason + condition.
// It performs NO further node action — an honest abort over landing an
// unschedulable pod (D25g4).
func (r *NodeRotationReconciler) abortNoCleanTarget(ctx context.Context, nr *amtdv1beta1.NodeRotation, reason string, logger logr.Logger) (ctrl.Result, error) {
	if reason == "" {
		reason = amtdv1beta1.NoCleanTargetCleanPoolExhausted
	}
	if err := r.setAnnotations(ctx, nr, map[string]string{annNodeRotPhase: amtdv1beta1.NodeRotationPhaseNoCleanTarget}); err != nil {
		return ctrl.Result{}, err
	}
	fresh := &amtdv1beta1.NodeRotation{}
	if err := r.Get(ctx, client.ObjectKey{Name: nr.Name}, fresh); err == nil {
		fresh.Status.Phase = amtdv1beta1.NodeRotationPhaseNoCleanTarget
		fresh.Status.NoCleanTargetReason = reason
		fresh.Status.ObservedGeneration = fresh.Generation
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               amtdv1beta1.ConditionNoCleanTarget,
			Status:             metav1.ConditionTrue,
			Reason:             reason,
			Message:            "No clean-pool node satisfied the selector + PVC/GPU preflight after excluding the source/cordoned/tainted nodes; the rotation aborted rather than land an unschedulable pod (D25g4).",
			ObservedGeneration: fresh.Generation,
		})
		_ = r.Status().Update(ctx, fresh)
	}
	logger.Info("NodeRotation ABORTED: NoCleanTarget (no unschedulable pod landed)",
		"nodeRotation", nr.Name, "reason", reason)
	return ctrl.Result{}, nil
}

// rollback uncordons the source (Cordon is reversible, D25g2/D25g4), removes the
// AMTD taint, and records the RolledBack terminal phase + condition on an
// unrecoverable failure mid-drain.
func (r *NodeRotationReconciler) rollback(ctx context.Context, nr *amtdv1beta1.NodeRotation, drainer *NodeDrainer, logger logr.Logger, cause error) (ctrl.Result, error) {
	_ = drainer.Uncordon(ctx, nr.Spec.SourceNode)
	_ = drainer.RemoveTaint(ctx, nr.Spec.SourceNode)
	if err := r.setAnnotations(ctx, nr, map[string]string{annNodeRotPhase: amtdv1beta1.NodeRotationPhaseRolledBack}); err != nil {
		return ctrl.Result{}, err
	}
	fresh := &amtdv1beta1.NodeRotation{}
	if err := r.Get(ctx, client.ObjectKey{Name: nr.Name}, fresh); err == nil {
		fresh.Status.Phase = amtdv1beta1.NodeRotationPhaseRolledBack
		fresh.Status.ObservedGeneration = fresh.Generation
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               amtdv1beta1.ConditionNodeRotationRolledBack,
			Status:             metav1.ConditionTrue,
			Reason:             "UnrecoverableDrainFailure",
			Message:            "The node rotation hit an unrecoverable failure mid-drain; the source node was uncordoned (Cordon is reversible) and the rotation rolled back.",
			ObservedGeneration: fresh.Generation,
		})
		_ = r.Status().Update(ctx, fresh)
	}
	logger.Error(cause, "NodeRotation ROLLED BACK: uncordoned the source after an unrecoverable failure", "nodeRotation", nr.Name)
	return ctrl.Result{}, nil
}

// countOtherInFlight counts NodeRotations OTHER than self that are past Cordoning
// and not terminal (Completed/RolledBack/NoCleanTarget) — the number of node drains
// already consuming the MaxConcurrentNodes ceiling (D25g3). On a list error it
// returns the error (we do NOT fail-open on the no-mass-eviction invariant).
func (r *NodeRotationReconciler) countOtherInFlight(ctx context.Context, selfName string) (int, error) {
	var list amtdv1beta1.NodeRotationList
	if err := r.List(ctx, &list); err != nil {
		return 0, err
	}
	n := 0
	for i := range list.Items {
		item := &list.Items[i]
		if item.Name == selfName {
			continue
		}
		phase := item.Annotations[annNodeRotPhase]
		if phase == "" {
			phase = item.Status.Phase
		}
		switch phase {
		case amtdv1beta1.NodeRotationPhaseDraining,
			amtdv1beta1.NodeRotationPhaseRescheduling,
			amtdv1beta1.NodeRotationPhasePinning:
			n++
		}
	}
	return n, nil
}

// SetupWithManager wires the reconciler to its own NodeRotation CRD (class-B
// continuation: it watches only its owned objects and progresses them; it never
// self-initiates a node move).
func (r *NodeRotationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&amtdv1beta1.NodeRotation{}).
		Named("noderotation").
		Complete(r)
}
