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

// Package controller — the Regenerate action wiring (cap#6, arch §2.1/§3, D6/D6g).
//
// executeRegenerate is the SecurityEvent dispatch branch for a matched Regenerate
// action. It resolves the cluster-scoped WorkloadBaseline named by the action's
// BaselineRef and invokes BaselineRestorer.Regenerate (verify-before-recreate ->
// reuse the D3 owner-walk to patch the top owner template back to the pinned
// Repository@Digest -> optionally reset the hardening profile -> record
// WorkloadBaselineStatus.LastRegeneration). The per-event outcome is recorded on
// SecurityEventStatus.AppliedAction="regenerate"; RotationPathFired is mirrored to
// the AMTD Status (D2 audit). KEEP HONEST: a verify-before-recreate failure ABORTS
// the restore (the workload is left untouched) and is recorded as a no-op outcome,
// never a forged success.
package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// executeRegenerate resolves the referenced WorkloadBaseline and restores the pod's
// workload to the golden baseline (verify-before-recreate). A nil/empty ref or a
// missing WorkloadBaseline is recorded as a no-op outcome (not an error that wedges
// the reconcile). A verify-before-recreate ABORT is recorded as a no-op outcome too
// — we never claim a restore that did not verify.
func (r *SecurityEventReconciler) executeRegenerate(
	ctx context.Context,
	pod *corev1.Pod,
	amtd *amtdv1beta1.AdaptiveMovingTargetDefense,
	ev *amtdv1beta1.SecurityEvent,
	action *amtdv1beta1.RegenerateAction,
	log logr.Logger,
) error {
	if action.BaselineRef == nil || action.BaselineRef.Name == "" {
		log.Info("Regenerate: action has no baselineRef.name; nothing to restore (no-op)", "pod", pod.Name)
		r.recordRegenerateOutcome(ctx, ev, "regenerate-noref", log)
		return nil
	}

	wbName := action.BaselineRef.Name
	wb := &amtdv1beta1.WorkloadBaseline{}
	// WorkloadBaseline is CLUSTER-SCOPED, so the lookup is name-only (no namespace).
	if err := r.Client.Get(ctx, types.NamespacedName{Name: wbName}, wb); err != nil {
		if errors.IsNotFound(err) {
			log.Info(fmt.Sprintf(`Regenerate: WorkloadBaseline %q referenced by the action does not exist (no-op)`, wbName), "pod", pod.Name)
			r.recordRegenerateOutcome(ctx, ev, "regenerate-notfound", log)
			return nil
		}
		return err
	}

	// resetHardening = the action flag OR the baseline DriftPolicy default
	// (PodProfileOnly). The action flag is the explicit opt-in on the Strategy[] entry.
	resetHardening := action.ResetHardeningProfile

	restorer := NewBaselineRestorer(r.Client, NewBaselineVerifier(r.Client, pod.Namespace))
	res, err := restorer.Regenerate(ctx, pod, wb, resetHardening, log)
	if err != nil {
		// verify-before-recreate ABORT (or owner-patch failure). KEEP HONEST: record a
		// no-op outcome with the reason; do NOT claim a restore. A verify abort is the
		// intended fail-safe (we never self-heal onto an unverifiable target).
		log.Error(err, "Regenerate: restore aborted (verify-before-recreate or owner patch)", "pod", pod.Name, "workloadBaseline", wbName)
		r.recordRegenerateOutcome(ctx, ev, "regenerate-aborted", log)
		r.setRegenerateAbortedCondition(ctx, amtd, err, log)
		return nil
	}

	log.Info("Regenerate: workload restored to golden baseline",
		"pod", pod.Name, "workloadBaseline", wbName, "golden", res.PinnedRef,
		"durable", res.Durable, "hardeningReset", res.HardeningReset, "notDurableReason", res.NotDurableReason)

	r.recordRegenerateOutcome(ctx, ev, "regenerate", log)
	r.mirrorRegeneratePath(ctx, amtd, res, log)
	return nil
}

// recordRegenerateOutcome writes SecurityEventStatus.AppliedAction + ProcessedAt
// (mirrors the WarmSwap/Rotate per-event Status write). best-effort.
func (r *SecurityEventReconciler) recordRegenerateOutcome(ctx context.Context, ev *amtdv1beta1.SecurityEvent, applied string, log logr.Logger) {
	freshEv := &amtdv1beta1.SecurityEvent{}
	if err := r.Client.Get(ctx, namespacedNameOfEvent(ev), freshEv); err == nil {
		freshEv.Status.AppliedAction = applied
		freshEv.Status.ProcessedAt = metav1.Now()
		if ev.Spec.AnomalyScore != nil {
			freshEv.Status.ObservedScore = *ev.Spec.AnomalyScore
		}
		if err := r.Client.Status().Update(ctx, freshEv); err != nil {
			log.Error(err, "Regenerate: failed to write SecurityEvent outcome status", "SecurityEvent", ev.Name)
		}
	}
}

// mirrorRegeneratePath records RotationPathFired + the durability audit on the AMTD
// Status (D2/D3 audit) when the AMTD is reachable. best-effort.
func (r *SecurityEventReconciler) mirrorRegeneratePath(ctx context.Context, amtd *amtdv1beta1.AdaptiveMovingTargetDefense, res RegenerateResult, log logr.Logger) {
	if amtd == nil {
		return
	}
	fresh := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	if err := r.Client.Get(ctx, namespacedNameOf(amtd), fresh); err == nil {
		fresh.Status.RotationPathFired = "Regenerate"
		fresh.Status.MutationDurable = res.Durable
		if res.Durable {
			fresh.Status.MutationNotDurableReason = ""
		} else {
			fresh.Status.MutationNotDurableReason = res.NotDurableReason
		}
		// Mirror the baseline regeneration timestamp onto the AMTD Baseline sub-status
		// for at-a-glance audit.
		if fresh.Status.Baseline == nil {
			fresh.Status.Baseline = &amtdv1beta1.BaselineStatus{}
		}
		fresh.Status.Baseline.LastRegeneration = metav1.Now()
		if err := r.Client.Status().Update(ctx, fresh); err != nil {
			log.Error(err, "Regenerate: failed to mirror RotationPathFired on AMTD status", "AMTD", amtd.Name)
		}
	}
}

// setRegenerateAbortedCondition records a RegenerateAborted condition on the AMTD so
// a verify-before-recreate abort is observable (fail-safe + honest). best-effort.
func (r *SecurityEventReconciler) setRegenerateAbortedCondition(ctx context.Context, amtd *amtdv1beta1.AdaptiveMovingTargetDefense, cause error, log logr.Logger) {
	if amtd == nil {
		return
	}
	fresh := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	if err := r.Client.Get(ctx, namespacedNameOf(amtd), fresh); err != nil {
		return
	}
	cond := metav1.Condition{
		Type:               "RegenerateAborted",
		Status:             metav1.ConditionTrue,
		Reason:             "VerifyBeforeRecreateFailed",
		Message:            fmt.Sprintf("Regenerate did not restore: %v. The workload was left untouched (we never self-heal onto an unverifiable golden target). %s", cause, amtdv1beta1.VerificationBenignityCaveatMessage),
		ObservedGeneration: fresh.Generation,
	}
	if meta.SetStatusCondition(&fresh.Status.Conditions, cond) {
		if err := r.Client.Status().Update(ctx, fresh); err != nil {
			log.Error(err, "Regenerate: failed to write RegenerateAborted condition", "AMTD", amtd.Name)
		}
	}
}
