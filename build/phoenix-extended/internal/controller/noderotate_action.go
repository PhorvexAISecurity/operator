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

// Package controller — the NodeRotate action wiring (cap#7, arch §2.1/§3, D25g/D26).
//
// requestNodeRotate is the SecurityEvent dispatch branch for a matched NodeRotate
// action (the LAST honest no-op stub, now wired). After the D26 trust gate it
// CREATES a cluster-scoped NodeRotation request for the targeted pod's node — it does
// NOT cordon/drain inline. The NodeRotationReconciler owns the restart-safe
// Cordoning->Draining->Rescheduling->Pinning->Completed progression. This keeps the
// CRD reconcile class-B (no request => no node move) and survives operator restart.
//
// The per-event outcome is recorded on SecurityEventStatus.AppliedAction
// ("nodeRotate" on success, "nodeRotate-denied" when the D26 gate blocks);
// RotationPathFired="NodeRotate" is mirrored to the AMTD status. The targeted pod
// gets the existing ROTATION_IN_PROGRESS lock so NIM early-returns (no double-evict).
package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// requestNodeRotate evaluates the D26 gate and, on pass, creates a NodeRotation for
// the targeted pod's node. A failed gate creates NO NodeRotation and records a
// denied condition + AppliedAction="nodeRotate-denied". A pod with no assigned node
// (NodeName empty) is a recorded no-op (nothing to rotate).
func (r *SecurityEventReconciler) requestNodeRotate(
	ctx context.Context,
	pod *corev1.Pod,
	amtd *amtdv1beta1.AdaptiveMovingTargetDefense,
	ev *amtdv1beta1.SecurityEvent,
	action *amtdv1beta1.NodeRotateAction,
	log logr.Logger,
) error {
	strategy := effectiveActionStrategy(action)

	// ---- D26 HARD TRUST GATE (checked BEFORE creating any NodeRotation) ----
	decision := evaluateNodeRotateGate(amtd, ev, strategy)
	if !decision.Allowed {
		log.Info("NodeRotate GATED (D26): no NodeRotation created",
			"pod", pod.Name, "source", ev.Spec.Rule.Source, "threatLevel", ev.Spec.Rule.ThreatLevel,
			"strategy", strategy, "reason", decision.DeniedReason)
		r.recordNodeRotateGated(ctx, amtd, ev, decision, log)
		return nil
	}

	if pod.Spec.NodeName == "" {
		log.Info("NodeRotate: targeted pod has no assigned node (NodeName empty); nothing to rotate (no-op)", "pod", pod.Name)
		r.recordNodeRotateOutcome(ctx, ev, "nodeRotate-noNode", log)
		return nil
	}

	// Idempotence: one SecurityEvent => one NodeRotation. The name is derived from the
	// event so a re-reconcile of the same event does not create a second drain.
	nrName := nodeRotationName(ev, pod)
	existing := &amtdv1beta1.NodeRotation{}
	if err := r.Client.Get(ctx, client.ObjectKey{Name: nrName}, existing); err == nil {
		log.Info("NodeRotate: a NodeRotation for this event already exists; idempotent no-op", "nodeRotation", nrName, "event", ev.Name)
		r.recordNodeRotateOutcome(ctx, ev, "nodeRotate", log)
		return nil
	} else if !errors.IsNotFound(err) {
		return err
	}

	// Resolve the no-mass-eviction ceiling from the AMTD's NodeRotationPolicy (carried
	// onto the NodeRotation so the reconciler enforces it, D25g3).
	var maxConcurrent *int
	var stagger *metav1.Duration
	if amtd != nil && amtd.Spec.NodeRotationPolicy != nil {
		maxConcurrent = amtd.Spec.NodeRotationPolicy.MaxConcurrentNodes
		stagger = amtd.Spec.NodeRotationPolicy.Stagger
	}

	nr := &amtdv1beta1.NodeRotation{
		ObjectMeta: metav1.ObjectMeta{
			Name: nrName,
		},
		Spec: amtdv1beta1.NodeRotationSpec{
			SourceNode:         pod.Spec.NodeName,
			TargetPods:         []amtdv1beta1.NamespacedPodRef{{Namespace: pod.Namespace, Name: pod.Name}},
			Strategy:           strategy,
			DrainPolicy:        action.DrainPolicy,
			TargetNodeSelector: action.TargetNodeSelector,
			TriggerProvenance: amtdv1beta1.TriggerProvenance{
				Source:      ev.Spec.Rule.Source,
				ThreatLevel: ev.Spec.Rule.ThreatLevel,
				EventName:   ev.Name,
			},
			MaxConcurrentNodes: maxConcurrent,
			Stagger:            stagger,
		},
	}
	if err := r.Client.Create(ctx, nr); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	log.Info("NodeRotate: created NodeRotation request (restart-safe drain; class-B continuation owns progression)",
		"nodeRotation", nrName, "sourceNode", pod.Spec.NodeName, "strategy", strategy)

	// NIM in-progress lock on the targeted pod (no double-evict; NIM early-returns).
	if err := r.setPodRotationInProgress(ctx, pod, log); err != nil {
		log.Error(err, "NodeRotate: failed to set the in-progress lock on the targeted pod", "pod", pod.Name)
	}

	r.recordNodeRotateOutcome(ctx, ev, "nodeRotate", log)
	r.mirrorNodeRotatePath(ctx, amtd, log)
	return nil
}

// effectiveActionStrategy resolves the action Strategy, code default Cordon (D25g2).
func effectiveActionStrategy(action *amtdv1beta1.NodeRotateAction) string {
	if action != nil && action.Strategy != "" {
		return action.Strategy
	}
	return amtdv1beta1.NodeRotationStrategyCordon
}

// nodeRotationName derives a stable, idempotent NodeRotation name from the event
// (one event => one drain). The cluster-scoped NodeRotation name encodes the event
// name + the pod so re-reconcile of the same event is a no-op.
func nodeRotationName(ev *amtdv1beta1.SecurityEvent, pod *corev1.Pod) string {
	return fmt.Sprintf("nrot-%s-%s", ev.Name, pod.Name)
}

// setPodRotationInProgress sets the existing ROTATION_IN_PROGRESS annotation on the
// targeted pod so the NIM reconciler early-returns (the cross-controller lock, D22).
// The pinned replacement carries no such annotation, clearing the lock.
func (r *SecurityEventReconciler) setPodRotationInProgress(ctx context.Context, pod *corev1.Pod, log logr.Logger) error {
	fresh := &corev1.Pod{}
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, fresh); err != nil {
		return client.IgnoreNotFound(err)
	}
	if fresh.Annotations == nil {
		fresh.Annotations = map[string]string{}
	}
	if fresh.Annotations[ROTATION_IN_PROGRESS] == "true" {
		return nil
	}
	fresh.Annotations[ROTATION_IN_PROGRESS] = "true"
	return r.Client.Update(ctx, fresh)
}

// recordNodeRotateOutcome writes SecurityEventStatus.AppliedAction + ProcessedAt
// (mirrors the WarmSwap/Rotate per-event Status write). best-effort.
func (r *SecurityEventReconciler) recordNodeRotateOutcome(ctx context.Context, ev *amtdv1beta1.SecurityEvent, applied string, log logr.Logger) {
	freshEv := &amtdv1beta1.SecurityEvent{}
	if err := r.Client.Get(ctx, namespacedNameOfEvent(ev), freshEv); err == nil {
		freshEv.Status.AppliedAction = applied
		freshEv.Status.ProcessedAt = metav1.Now()
		if ev.Spec.AnomalyScore != nil {
			freshEv.Status.ObservedScore = *ev.Spec.AnomalyScore
		}
		if err := r.Client.Status().Update(ctx, freshEv); err != nil {
			log.Error(err, "NodeRotate: failed to write SecurityEvent outcome status", "SecurityEvent", ev.Name)
		}
	}
}

// recordNodeRotateGated records the D26 denied outcome: AppliedAction="nodeRotate-denied"
// on the event + a gated condition on the AMTD. NO NodeRotation is created.
func (r *SecurityEventReconciler) recordNodeRotateGated(ctx context.Context, amtd *amtdv1beta1.AdaptiveMovingTargetDefense, ev *amtdv1beta1.SecurityEvent, decision gateDecision, log logr.Logger) {
	r.recordNodeRotateOutcome(ctx, ev, "nodeRotate-denied", log)
	if amtd == nil {
		return
	}
	fresh := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	if err := r.Client.Get(ctx, namespacedNameOf(amtd), fresh); err != nil {
		return
	}
	meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
		Type:               decision.DeniedReason,
		Status:             metav1.ConditionTrue,
		Reason:             decision.DeniedReason,
		Message:            decision.Message,
		ObservedGeneration: fresh.Generation,
	})
	if err := r.Client.Status().Update(ctx, fresh); err != nil {
		log.Error(err, "NodeRotate: failed to record gated condition on AMTD", "AMTD", amtd.Name)
	}
}

// mirrorNodeRotatePath records RotationPathFired="NodeRotate" on the AMTD Status (D2
// audit). best-effort.
func (r *SecurityEventReconciler) mirrorNodeRotatePath(ctx context.Context, amtd *amtdv1beta1.AdaptiveMovingTargetDefense, log logr.Logger) {
	if amtd == nil {
		return
	}
	fresh := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	if err := r.Client.Get(ctx, namespacedNameOf(amtd), fresh); err == nil {
		fresh.Status.RotationPathFired = "NodeRotate"
		if err := r.Client.Status().Update(ctx, fresh); err != nil {
			log.Error(err, "NodeRotate: failed to mirror RotationPathFired on AMTD status", "AMTD", amtd.Name)
		}
	}
}
