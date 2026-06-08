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

// Package controller — the WarmInferenceSet reconciler (cap#2, arch §3 / §1.2-§1.3,
// D11/D12).
//
// TWO CLASSES OF RECONCILE, kept strictly separate:
//
//   - CLASS-B MAINTENANCE (always): WarmPoolManager.EnsurePool keeps N warm pods,
//     exactly one leader carrying the leader label, the leader-selecting Service
//     resolving to it. Status (ActiveLeader / ReadyShadows / CurrentReplicas) is
//     recomputed. This path MUST NOT self-initiate a swap (arch §1.3 invariant).
//
//   - CLASS-A SWAP (only when Spec.SwapRequest is set): LeaderSwapper.Swap runs the
//     restart-safe phase machine Ready->flip->drain->retire->rewarm, recording
//     Status.SwapPhase + LastSwapDurationMillis and clearing the request on
//     completion. The request is set ONLY by a matched WarmSwap action (the matcher
//     selected it from a SecurityEvent) — never by class-B maintenance. No request
//     => no swap, which is what makes class-B provably honest.
//
// If NO shadow passes the readiness gate when a swap is requested, the swap is
// BLOCKED: a SwapBlockedNoReadyShadow condition is set, the request is retained, and
// nothing is cut over (the readiness gate is the gate, arch §3).
package controller

import (
	"context"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// WarmInferenceSetReconciler is the cap#2 warm-pool control-plane reconciler.
type WarmInferenceSetReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// clock is injectable for tests (MinWarmSeconds dwell + swap timing). nil =>
	// realClock.
	clock poolClock
}

//+kubebuilder:rbac:groups=amtd.r6security.com,resources=warminferencesets,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=warminferencesets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=amtd.r6security.com,resources=warminferencesets/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;create;delete;patch;update
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch

// Reconcile runs class-B maintenance every time, then — only if Spec.SwapRequest is
// set — advances the class-A swap phase machine.
func (r *WarmInferenceSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	wis := &amtdv1beta1.WarmInferenceSet{}
	if err := r.Get(ctx, req.NamespacedName, wis); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	clk := r.effectiveClock()
	gate := &ReadinessGate{clock: clk}
	pool := &WarmPoolManager{Client: r.Client, Scheme: r.Scheme, gate: gate}

	// ---- CLASS-B MAINTENANCE (always; never initiates a swap) ----
	leaderName, err := pool.EnsurePool(ctx, wis)
	if err != nil {
		logger.Error(err, "WarmInferenceSet: EnsurePool (class-B) failed", "wis", wis.Name)
		return ctrl.Result{}, err
	}

	// ---- CLASS-A SWAP (only on an explicit request) ----
	// Ownership of the Status SwapPhase / blocked-condition during a swap belongs to the
	// swap machine (which mirrors them off the durable annotation truth). To avoid two
	// writers racing the Status subresource, the reconciler's own writeStatus runs ONLY
	// when no swap is in flight; during a swap the LeaderSwapper is the sole Status
	// writer.
	var requeue ctrl.Result
	swapInFlight := wis.Spec.SwapRequest != nil
	if swapInFlight {
		swapper := &LeaderSwapper{
			Client:  r.Client,
			Scheme:  r.Scheme,
			pool:    pool,
			steerer: &TrafficSteerer{Client: r.Client},
			gate:    gate,
			clock:   clk,
		}
		res, newLeader, err := swapper.Swap(ctx, wis, logger)
		if err != nil {
			return ctrl.Result{}, err
		}
		if newLeader != "" {
			leaderName = newLeader
		}
		requeue = res
	} else {
		// ---- Recompute + write Status (class-B only) ----
		if err := r.writeStatus(ctx, req.NamespacedName, wis, pool, leaderName, logger); err != nil {
			return ctrl.Result{}, err
		}
	}

	logger.Info("WarmInferenceSet reconciled (class-B maintenance + restart-safe swap progression)",
		"wis", wis.Name, "leader", leaderName, "swapInFlight", swapInFlight)
	return requeue, nil
}

// writeStatus re-reads the WIS and records ActiveLeader / ReadyShadows /
// CurrentReplicas / ObservedGeneration + the WarmGuaranteeVoid advisory. SwapPhase /
// LastSwapDurationMillis / SwapBlockedNoReadyShadow are written by the swap machine
// directly (it owns those fields); this only fills the maintenance surface and clears
// the blocked condition when no swap is pending.
func (r *WarmInferenceSetReconciler) writeStatus(ctx context.Context, key client.ObjectKey, observed *amtdv1beta1.WarmInferenceSet, pool *WarmPoolManager, leaderName string, logger logr.Logger) error {
	readyShadows, err := pool.ReadyShadows(ctx, observed)
	if err != nil {
		return err
	}
	pods, err := pool.poolPods(ctx, observed)
	if err != nil {
		return err
	}
	current := 0
	for i := range pods {
		if alive(&pods[i]) {
			current++
		}
	}

	fresh := &amtdv1beta1.WarmInferenceSet{}
	if err := r.Get(ctx, key, fresh); err != nil {
		return client.IgnoreNotFound(err)
	}
	fresh.Status.ObservedGeneration = fresh.Generation
	fresh.Status.ActiveLeader = leaderName
	fresh.Status.ReadyShadows = readyShadows
	fresh.Status.CurrentReplicas = current
	if fresh.Status.SwapPhase == "" {
		fresh.Status.SwapPhase = amtdv1beta1.SwapPhaseIdle
	}

	// WarmGuaranteeVoid advisory: fewer warm shadows than (N-1) expected standbys, or
	// no leader at all.
	wantStandbys := observed.EffectiveReplicas() - 1
	if leaderName == "" || readyShadows < wantStandbys {
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               amtdv1beta1.ConditionWarmGuaranteeVoid,
			Status:             metav1.ConditionTrue,
			Reason:             "InsufficientWarmShadows",
			Message:            "The warm pool does not yet have a leader and N-1 warm standbys; the warm guarantee is temporarily void while standbys are provisioned/warming.",
			ObservedGeneration: fresh.Generation,
		})
	} else {
		meta.RemoveStatusCondition(&fresh.Status.Conditions, amtdv1beta1.ConditionWarmGuaranteeVoid)
	}

	// If no swap is pending, ensure the blocked condition is cleared.
	if fresh.Spec.SwapRequest == nil {
		meta.RemoveStatusCondition(&fresh.Status.Conditions, amtdv1beta1.ConditionSwapBlockedNoReadyShadow)
	}

	if err := r.Status().Update(ctx, fresh); err != nil {
		logger.Error(err, "WarmInferenceSet: failed to write status", "wis", fresh.Name)
		return err
	}
	return nil
}

func (r *WarmInferenceSetReconciler) effectiveClock() poolClock {
	if r.clock != nil {
		return r.clock
	}
	return realClock{}
}

// SetupWithManager wires the reconciler: it owns the warm pods and the leader Service
// so a change to either re-triggers a reconcile (class-B keeps them at desired state).
func (r *WarmInferenceSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&amtdv1beta1.WarmInferenceSet{}).
		Owns(&corev1.Pod{}).
		Owns(&corev1.Service{}).
		Named("warminferenceset").
		Complete(r)
}
