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

// Package controller — the WarmSwap action wiring (cap#2, arch §2.1/§3, D11/D12).
//
// requestWarmSwap is the SecurityEvent dispatch branch for a matched WarmSwap action.
// It resolves the referenced WarmInferenceSet in the pod's namespace and SETS its
// Spec.SwapRequest (the restart-safe progressive model, arch §3) — it does NOT cut
// over inline. The WarmInferenceSet reconciler owns the Ready->flip->drain->retire->
// rewarm progression. The per-event outcome is recorded on
// SecurityEventStatus.AppliedAction="warmSwap"; RotationPathFired="WarmSwap" is
// mirrored to the AMTD WarmPool status when reachable.
package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

//+kubebuilder:rbac:groups=amtd.r6security.com,resources=warminferencesets,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=warminferencesets/status,verbs=get;update;patch

// requestWarmSwap resolves the WarmInferenceSet named by the action and sets its
// Spec.SwapRequest. A nil ref or missing WarmInferenceSet is recorded as a no-op
// outcome (not an error) so a misconfigured policy does not wedge the reconcile.
func (r *SecurityEventReconciler) requestWarmSwap(
	ctx context.Context,
	pod *corev1.Pod,
	amtd *amtdv1beta1.AdaptiveMovingTargetDefense,
	ev *amtdv1beta1.SecurityEvent,
	action *amtdv1beta1.WarmSwapAction,
	log logr.Logger,
) error {
	if action.WarmInferenceSetRef == nil || action.WarmInferenceSetRef.Name == "" {
		log.Info("WarmSwap: action has no warmInferenceSetRef.name; nothing to swap (no-op)", "pod", pod.Name)
		r.recordWarmSwapOutcome(ctx, ev, "warmSwap-noref", log)
		return nil
	}

	wisName := action.WarmInferenceSetRef.Name
	key := types.NamespacedName{Namespace: pod.Namespace, Name: wisName}

	wis := &amtdv1beta1.WarmInferenceSet{}
	if err := r.Client.Get(ctx, key, wis); err != nil {
		if errors.IsNotFound(err) {
			log.Info(fmt.Sprintf(`WarmSwap: WarmInferenceSet "%s/%s" referenced by the action does not exist (no-op)`, pod.Namespace, wisName))
			r.recordWarmSwapOutcome(ctx, ev, "warmSwap-notfound", log)
			return nil
		}
		return err
	}

	// Idempotence: if a swap request for THIS event is already set, do not re-set it
	// (one SecurityEvent => one swap; the reconciler clears the request on completion).
	if wis.Spec.SwapRequest != nil && wis.Spec.SwapRequest.RequestID == ev.Name {
		log.Info("WarmSwap: a swap request for this event is already pending; idempotent no-op", "wis", wisName, "event", ev.Name)
		r.recordWarmSwapOutcome(ctx, ev, "warmSwap", log)
		return nil
	}

	// Set the swap request (the WarmInferenceSet reconciler progresses it).
	req := &amtdv1beta1.WarmSwapRequest{
		RequestID:           ev.Name,
		RequestedAt:         metav1.Now(),
		DrainTimeoutSeconds: action.DrainTimeoutSeconds, // action override; nil => spec/default
	}
	wis.Spec.SwapRequest = req
	if err := r.Client.Update(ctx, wis); err != nil {
		return err
	}
	log.Info("WarmSwap: set Spec.SwapRequest on the referenced WarmInferenceSet (restart-safe progressive cutover)",
		"wis", wisName, "namespace", pod.Namespace, "requestID", ev.Name)

	// Per-event outcome + AMTD WarmPool path mirror.
	r.recordWarmSwapOutcome(ctx, ev, "warmSwap", log)
	r.mirrorWarmSwapPath(ctx, amtd, log)
	return nil
}

// recordWarmSwapOutcome writes SecurityEventStatus.AppliedAction + ProcessedAt
// (mirrors the Rotate executor's per-event Status write). best-effort.
func (r *SecurityEventReconciler) recordWarmSwapOutcome(ctx context.Context, ev *amtdv1beta1.SecurityEvent, applied string, log logr.Logger) {
	freshEv := &amtdv1beta1.SecurityEvent{}
	if err := r.Client.Get(ctx, namespacedNameOfEvent(ev), freshEv); err == nil {
		freshEv.Status.AppliedAction = applied
		freshEv.Status.ProcessedAt = metav1.Now()
		if ev.Spec.AnomalyScore != nil {
			freshEv.Status.ObservedScore = *ev.Spec.AnomalyScore
		}
		if err := r.Client.Status().Update(ctx, freshEv); err != nil {
			log.Error(err, "WarmSwap: failed to write SecurityEvent outcome status", "SecurityEvent", ev.Name)
		}
	}
}

// mirrorWarmSwapPath records RotationPathFired="WarmSwap" on the AMTD Status (D2 audit)
// when the AMTD is reachable. best-effort.
func (r *SecurityEventReconciler) mirrorWarmSwapPath(ctx context.Context, amtd *amtdv1beta1.AdaptiveMovingTargetDefense, log logr.Logger) {
	if amtd == nil {
		return
	}
	fresh := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	if err := r.Client.Get(ctx, namespacedNameOf(amtd), fresh); err == nil {
		fresh.Status.RotationPathFired = "WarmSwap"
		if err := r.Client.Status().Update(ctx, fresh); err != nil {
			log.Error(err, "WarmSwap: failed to mirror RotationPathFired on AMTD status", "AMTD", amtd.Name)
		}
	}
}
