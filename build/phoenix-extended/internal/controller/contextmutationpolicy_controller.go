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

// Package controller — the THIN ContextMutationPolicy status reconciler (D7g, arch
// §3 / §2.4 item 4).
//
// THIS RECONCILER DOES NOT ROTATE. Per the locked design rule, every workload effect
// flows through AMTD Strategy[] -> SecurityEvent -> the Rotate executor; a CMP's
// Mutations[] are applied ONLY when a routed Rotate's PolicyRef{Kind:
// "ContextMutationPolicy"} is resolved by the shared MutationApplier. This reconciler
// is observability-only: it records, on the CMP's Status,
//
//   - ObservedGeneration       (the generation the status reflects),
//   - SelectedPodCount         (# pods currently matched by Spec.Selector),
//   - ResolvedMutationSummary  (a one-line summary of the projected mutation set,
//     computed with the SAME projection the MutationApplier uses, including the
//     honest cpu/memory-requests not-applied note), and
//   - a GatekeeperViolationUnsupported ADVISORY condition whenever the policy
//     declares a GatekeeperViolation trigger — because NO native OPA-Gatekeeper
//     emitter exists in any repo (receiver-only / future-work). The condition is
//     cleared when no such trigger is present.
package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// gatekeeperAdvisoryConditionType is the advisory condition the thin reconciler
// raises when a CMP declares a GatekeeperViolation trigger that has no emitter.
const gatekeeperAdvisoryConditionType = "GatekeeperViolationUnsupported"

// ContextMutationPolicyReconciler is the thin status reconciler for the CMP kind.
type ContextMutationPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=amtd.r6security.com,resources=contextmutationpolicies,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=contextmutationpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=contextmutationpolicies/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch

// Reconcile records the thin status (observedGeneration / selected-pod count /
// resolved-mutation summary / GatekeeperViolation advisory). It never mutates a
// workload.
func (r *ContextMutationPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	cmp := &amtdv1beta1.ContextMutationPolicy{}
	if err := r.Get(ctx, req.NamespacedName, cmp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// (1) Count pods matched by the selector (status-only; recomputed each reconcile).
	selectedPods, err := r.countSelectedPods(ctx, cmp)
	if err != nil {
		logger.Error(err, "ContextMutationPolicy: failed to list selected pods", "cmp", cmp.Name)
		return ctrl.Result{}, err
	}

	// (2) Project the mutation set into the same overlay the MutationApplier uses, and
	// summarize it (incl. the cpu/mem-requests not-applied note).
	_, summary := projectCMPMutations(cmp.Spec.Mutations)

	// (3) GatekeeperViolation advisory: receiver-only, no native emitter.
	hasGatekeeperTrigger := cmpHasGatekeeperTrigger(cmp)

	// Re-read before status write to avoid clobbering a concurrent update.
	fresh := &amtdv1beta1.ContextMutationPolicy{}
	if err := r.Get(ctx, req.NamespacedName, fresh); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	fresh.Status.ObservedGeneration = fresh.Generation
	fresh.Status.SelectedPodCount = selectedPods
	fresh.Status.ResolvedMutationSummary = summary

	if hasGatekeeperTrigger {
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               gatekeeperAdvisoryConditionType,
			Status:             metav1.ConditionTrue,
			Reason:             "NoNativeEmitter",
			Message:            "This policy declares a GatekeeperViolation trigger, but NO OPA-Gatekeeper-audit->SecurityEvent emitter exists in any integrator repo; the trigger is receiver-only and documented as future work (D7g). A routed gatekeeper-violation SecurityEvent (Source=GatekeeperIntegrator, Type=gatekeeper-violation, Metrics[gatekeeper.constraint]) would still drive a Rotate to this policy.",
			ObservedGeneration: fresh.Generation,
		})
	} else {
		meta.RemoveStatusCondition(&fresh.Status.Conditions, gatekeeperAdvisoryConditionType)
	}

	if err := r.Status().Update(ctx, fresh); err != nil {
		logger.Error(err, "ContextMutationPolicy: failed to write status", "cmp", cmp.Name)
		return ctrl.Result{}, err
	}

	logger.Info("ContextMutationPolicy reconciled (thin status; no rotation performed)",
		"cmp", cmp.Name, "selectedPods", selectedPods, "mutations", summary, "gatekeeperAdvisory", hasGatekeeperTrigger)
	return ctrl.Result{}, nil
}

// countSelectedPods lists pods in the CMP's namespace matched by Spec.Selector. A
// nil selector selects nothing (0). An empty selector ({}) matches everything, per
// metav1.LabelSelectorAsSelector semantics — but a nil Spec.Selector is treated as
// "select nothing" because a CMP with no selector targets no workload.
func (r *ContextMutationPolicyReconciler) countSelectedPods(ctx context.Context, cmp *amtdv1beta1.ContextMutationPolicy) (int, error) {
	if cmp.Spec.Selector == nil {
		return 0, nil
	}
	sel, err := metav1.LabelSelectorAsSelector(cmp.Spec.Selector)
	if err != nil {
		return 0, fmt.Errorf("invalid selector: %w", err)
	}
	podList := &corev1.PodList{}
	if err := r.List(ctx, podList,
		client.InNamespace(cmp.Namespace),
		client.MatchingLabelsSelector{Selector: sel},
	); err != nil {
		return 0, err
	}
	return len(podList.Items), nil
}

// cmpHasGatekeeperTrigger reports whether any telemetry source is a
// GatekeeperViolation (the no-emitter advisory trigger).
func cmpHasGatekeeperTrigger(cmp *amtdv1beta1.ContextMutationPolicy) bool {
	for _, ts := range cmp.Spec.Triggers.TelemetrySources {
		if ts.Type == amtdv1beta1.CMPTriggerGatekeeperViolation {
			return true
		}
	}
	return false
}

// SetupWithManager wires the thin CMP reconciler (watches ContextMutationPolicy only;
// the selected-pod count is recomputed on each CMP reconcile — minimal and honest,
// mirroring the NIM reconciler's For(...).Named(...).Complete(r) pattern).
func (r *ContextMutationPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&amtdv1beta1.ContextMutationPolicy{}).
		Named("contextmutationpolicy").
		Complete(r)
}
