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

// Package controller — LeaderSwapper.Swap, the cap#2 create-new-then-cutover phase
// machine (arch §3, D3 PRIMARY per-instance durability).
//
// Swap is driven by Spec.SwapRequest (set ONLY by a matched WarmSwap action) and is
// RESTART-SAFE and CONFLICT-TOLERANT: it progresses one durable step per reconcile
// through Flipping -> Draining -> Retiring -> Rewarming -> (clear request), persisting
// the phase + the swap start/flip timestamps + old-leader name in ANNOTATIONS on the
// WIS metadata. The SINGLE SOURCE OF TRUTH for swap progress is those annotations
// (written together with the spec in ONE Update), NOT Status — because the class-B
// maintenance reconcile concurrently writes Status, and storing phase in Status would
// let a status-write conflict silently lose a transition (re-flipping forever).
// Status.SwapPhase / LastSwapDurationMillis are a best-effort MIRROR written after the
// durable annotation step. Every durable write re-reads the latest object first, so a
// concurrent modification does not corrupt progress.
//
// The recorded Status.LastSwapDurationMillis is the CONTROL-PLANE cutover time
// (flip + drain). GPU-PENDING: it is explicitly NOT the GPU model-load downtime SLO
// (400s->15s / p50<=5s / p95<=15s are real-GPU runs, never measured on kind).
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

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// Swap-progress annotation keys on the WarmInferenceSet (the durable single source of
// truth for in-flight swap state; metadata, written atomically with the spec).
const (
	annSwapPhase         = "amtd.r6security.com/swap-phase"
	annSwapStartUnixNano = "amtd.r6security.com/swap-start-unixnano"
	annSwapFlipUnixNano  = "amtd.r6security.com/swap-flip-unixnano"
	annSwapOldLeader     = "amtd.r6security.com/swap-old-leader"
	annSwapRequestID     = "amtd.r6security.com/swap-request-id"
)

// swapRequeue is how soon to re-reconcile while a swap is in flight (drain wait).
const swapRequeue = 1 * time.Second

// LeaderSwapper executes the create-new-then-cutover swap as a phase machine.
type LeaderSwapper struct {
	client.Client
	Scheme  *runtime.Scheme
	pool    *WarmPoolManager
	steerer *TrafficSteerer
	gate    *ReadinessGate
	clock   poolClock
}

// Swap advances the swap phase machine by (at most) one durable step per call. It
// returns a requeue Result (non-zero while the swap is in flight), the (possibly new)
// leader name, and an error. When no shadow is warm it BLOCKS: it sets the
// SwapBlockedNoReadyShadow condition, retains the request, and returns without cutting
// over. The current phase is read from the durable annotation (not Status), so a prior
// status-write conflict cannot lose progress.
func (s *LeaderSwapper) Swap(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet, logger logr.Logger) (ctrl.Result, string, error) {
	if wis.Spec.SwapRequest == nil {
		return ctrl.Result{}, "", nil
	}
	now := s.clock.Now()

	phase := wis.Annotations[annSwapPhase]
	if phase == "" {
		phase = amtdv1beta1.SwapPhaseFlipping
	}

	switch phase {
	case amtdv1beta1.SwapPhaseFlipping:
		return s.doFlip(ctx, wis, now, logger)
	case amtdv1beta1.SwapPhaseDraining:
		return s.doDrain(ctx, wis, now, logger)
	case amtdv1beta1.SwapPhaseRetiring:
		return s.doRetire(ctx, wis, now, logger)
	case amtdv1beta1.SwapPhaseRewarming:
		return s.doRewarm(ctx, wis, now, logger)
	default:
		return s.doFlip(ctx, wis, now, logger)
	}
}

// doFlip picks a warm shadow (the readiness gate is the gate), moves the leader label
// to it (TrafficSteerer.CutTraffic; the Service now resolves to the new leader), and
// transitions to Draining. If NO shadow is warm, it BLOCKS. It is idempotent: the
// CURRENT leader at flip time is the old leader; the picked shadow becomes the new
// leader; once the annotations record the flip, the phase advances to Draining and we
// never re-enter Flipping for this request.
func (s *LeaderSwapper) doFlip(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet, now time.Time, logger logr.Logger) (ctrl.Result, string, error) {
	oldLeaderName, err := s.pool.CurrentLeader(ctx, wis)
	if err != nil {
		return ctrl.Result{}, "", err
	}

	shadow, err := s.pool.pickReadyShadow(ctx, wis, oldLeaderName)
	if err != nil {
		return ctrl.Result{}, "", err
	}
	if shadow == nil {
		// BLOCKED: no warm shadow. Set the condition, keep the request, no cutover.
		if err := s.setBlockedCondition(ctx, wis); err != nil {
			return ctrl.Result{}, "", err
		}
		logger.Info("WarmSwap BLOCKED: no warm shadow (readiness gate); request retained", "wis", wis.Name)
		return ctrl.Result{RequeueAfter: swapRequeue}, oldLeaderName, nil
	}

	oldPod, err := s.getPod(ctx, wis.Namespace, oldLeaderName)
	if err != nil {
		return ctrl.Result{}, "", err
	}

	// Flip the leader label to the shadow (Service now resolves to the new leader).
	if err := s.steerer.CutTraffic(ctx, wis, oldPod, shadow); err != nil {
		return ctrl.Result{}, "", err
	}

	// Durable transition to Draining: record phase + flip time + start time + old
	// leader, atomically in the metadata. Clear the blocked condition on the status
	// mirror afterwards.
	startNano := firstNonEmpty(wis.Annotations[annSwapStartUnixNano], strconv.FormatInt(now.UnixNano(), 10))
	if err := s.setSwapAnnotations(ctx, wis, map[string]string{
		annSwapPhase:         amtdv1beta1.SwapPhaseDraining,
		annSwapFlipUnixNano:  strconv.FormatInt(now.UnixNano(), 10),
		annSwapStartUnixNano: startNano,
		annSwapOldLeader:     oldLeaderName,
		annSwapRequestID:     wis.Spec.SwapRequest.RequestID,
	}); err != nil {
		return ctrl.Result{}, "", err
	}
	_ = s.mirrorPhaseStatus(ctx, wis, amtdv1beta1.SwapPhaseDraining, true /*clearBlocked*/, 0)
	logger.Info("WarmSwap: leader label flipped to warm shadow (ServiceSelectorSwap cutover); draining",
		"wis", wis.Name, "oldLeader", oldLeaderName, "newLeader", shadow.Name)
	return ctrl.Result{RequeueAfter: swapRequeue}, shadow.Name, nil
}

// doDrain waits DrainTimeoutSeconds after the flip before retiring the old leader.
func (s *LeaderSwapper) doDrain(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet, now time.Time, logger logr.Logger) (ctrl.Result, string, error) {
	flipNano, _ := strconv.ParseInt(wis.Annotations[annSwapFlipUnixNano], 10, 64)
	drain := effectiveSwapDrainSeconds(wis)
	if flipNano > 0 && now.Sub(time.Unix(0, flipNano)) < time.Duration(drain)*time.Second {
		return ctrl.Result{RequeueAfter: swapRequeue}, "", nil // still draining
	}
	if err := s.setSwapAnnotations(ctx, wis, map[string]string{annSwapPhase: amtdv1beta1.SwapPhaseRetiring}); err != nil {
		return ctrl.Result{}, "", err
	}
	_ = s.mirrorPhaseStatus(ctx, wis, amtdv1beta1.SwapPhaseRetiring, false, 0)
	logger.Info("WarmSwap: drain window elapsed; retiring old leader", "wis", wis.Name, "drainSeconds", drain)
	return ctrl.Result{RequeueAfter: swapRequeue}, "", nil
}

// doRetire deletes the old leader pod, then transitions to Rewarming.
func (s *LeaderSwapper) doRetire(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet, now time.Time, logger logr.Logger) (ctrl.Result, string, error) {
	oldName := wis.Annotations[annSwapOldLeader]
	if oldName != "" {
		oldPod, err := s.getPod(ctx, wis.Namespace, oldName)
		if err != nil {
			return ctrl.Result{}, "", err
		}
		if oldPod != nil && oldPod.DeletionTimestamp == nil {
			if err := s.Delete(ctx, oldPod); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, "", err
			}
		}
	}
	if err := s.setSwapAnnotations(ctx, wis, map[string]string{annSwapPhase: amtdv1beta1.SwapPhaseRewarming}); err != nil {
		return ctrl.Result{}, "", err
	}
	_ = s.mirrorPhaseStatus(ctx, wis, amtdv1beta1.SwapPhaseRewarming, false, 0)
	logger.Info("WarmSwap: old leader retired; re-warming a replacement shadow", "wis", wis.Name, "retired", oldName)
	return ctrl.Result{RequeueAfter: swapRequeue}, "", nil
}

// doRewarm re-warms a replacement shadow (EnsurePool back to N), records the
// control-plane swap duration (flip+drain) into Status.LastSwapDurationMillis, clears
// Spec.SwapRequest + the swap annotations, and returns to Idle.
func (s *LeaderSwapper) doRewarm(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet, now time.Time, logger logr.Logger) (ctrl.Result, string, error) {
	// EnsurePool re-provisions a standby back to N (the create-new half), then re-reads
	// the current leader.
	newLeader, err := s.pool.EnsurePool(ctx, wis)
	if err != nil {
		return ctrl.Result{}, "", err
	}

	startNano, _ := strconv.ParseInt(wis.Annotations[annSwapStartUnixNano], 10, 64)
	var durMillis int64
	if startNano > 0 {
		durMillis = now.Sub(time.Unix(0, startNano)).Milliseconds()
		if durMillis < 0 {
			durMillis = 0
		}
	}

	// Clear the request + swap annotations (durable Update), then mirror the final
	// Status (Idle + duration).
	if err := s.clearSwap(ctx, wis); err != nil {
		return ctrl.Result{}, "", err
	}
	_ = s.mirrorPhaseStatus(ctx, wis, amtdv1beta1.SwapPhaseIdle, true, durMillis)
	logger.Info("WarmSwap COMPLETE: replacement re-warmed; control-plane cutover recorded (flip+drain; NOT the GPU model-load downtime SLO — GPU-PENDING)",
		"wis", wis.Name, "lastSwapDurationMillis", durMillis, "leader", newLeader)
	return ctrl.Result{}, newLeader, nil
}

// effectiveSwapDrainSeconds resolves the drain window: the per-request override if
// present, else the spec/default.
func effectiveSwapDrainSeconds(wis *amtdv1beta1.WarmInferenceSet) int64 {
	if wis.Spec.SwapRequest != nil && wis.Spec.SwapRequest.DrainTimeoutSeconds != nil {
		if v := *wis.Spec.SwapRequest.DrainTimeoutSeconds; v >= 0 {
			return v
		}
	}
	return wis.EffectiveDrainTimeoutSeconds()
}

// getPod fetches a pod by name, returning (nil, nil) if not found.
func (s *LeaderSwapper) getPod(ctx context.Context, ns, name string) (*corev1.Pod, error) {
	if name == "" {
		return nil, nil
	}
	p := &corev1.Pod{}
	if err := s.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, p); err != nil {
		return nil, client.IgnoreNotFound(err)
	}
	return p, nil
}

// setSwapAnnotations re-reads the WIS, applies the annotation delta (empty value =>
// delete), and persists via a normal Update (metadata). It keeps the in-memory wis's
// annotations in sync so subsequent reads in the same reconcile see the new phase.
func (s *LeaderSwapper) setSwapAnnotations(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet, delta map[string]string) error {
	fresh := &amtdv1beta1.WarmInferenceSet{}
	if err := s.Get(ctx, client.ObjectKey{Namespace: wis.Namespace, Name: wis.Name}, fresh); err != nil {
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
	if err := s.Update(ctx, fresh); err != nil {
		return err
	}
	// Reflect onto the working copy.
	if wis.Annotations == nil {
		wis.Annotations = map[string]string{}
	}
	for k, v := range delta {
		if v == "" {
			delete(wis.Annotations, k)
		} else {
			wis.Annotations[k] = v
		}
	}
	wis.ResourceVersion = fresh.ResourceVersion
	return nil
}

// clearSwap re-reads the WIS, removes Spec.SwapRequest and ALL swap annotations, and
// persists via a normal Update.
func (s *LeaderSwapper) clearSwap(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet) error {
	fresh := &amtdv1beta1.WarmInferenceSet{}
	if err := s.Get(ctx, client.ObjectKey{Namespace: wis.Namespace, Name: wis.Name}, fresh); err != nil {
		return client.IgnoreNotFound(err)
	}
	fresh.Spec.SwapRequest = nil
	for _, k := range []string{annSwapPhase, annSwapStartUnixNano, annSwapFlipUnixNano, annSwapOldLeader, annSwapRequestID} {
		delete(fresh.Annotations, k)
	}
	return s.Update(ctx, fresh)
}

// setBlockedCondition re-reads the WIS and sets the SwapBlockedNoReadyShadow status
// condition (and ensures the phase annotation stays Flipping).
func (s *LeaderSwapper) setBlockedCondition(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet) error {
	// Ensure the durable phase is Flipping (so a restart resumes here).
	if wis.Annotations[annSwapPhase] != amtdv1beta1.SwapPhaseFlipping {
		if err := s.setSwapAnnotations(ctx, wis, map[string]string{annSwapPhase: amtdv1beta1.SwapPhaseFlipping}); err != nil {
			return err
		}
	}
	fresh := &amtdv1beta1.WarmInferenceSet{}
	if err := s.Get(ctx, client.ObjectKey{Namespace: wis.Namespace, Name: wis.Name}, fresh); err != nil {
		return client.IgnoreNotFound(err)
	}
	fresh.Status.SwapPhase = amtdv1beta1.SwapPhaseFlipping
	meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
		Type:               amtdv1beta1.ConditionSwapBlockedNoReadyShadow,
		Status:             metav1.ConditionTrue,
		Reason:             "NoReadyShadow",
		Message:            "A WarmSwap was requested but no shadow passes the readiness gate (Ready + MinWarmSeconds + RequireModelLoaded); the swap is deferred until a warm shadow exists. The request is retained.",
		ObservedGeneration: fresh.Generation,
	})
	return s.Status().Update(ctx, fresh)
}

// mirrorPhaseStatus is a BEST-EFFORT status mirror of the durable phase (+ optional
// final duration; + clear the blocked condition). Because the reconciler's own
// writeStatus is SKIPPED during a swap, this also refreshes ActiveLeader + ReadyShadows
// so the maintenance surface stays current. A conflict here is harmless because the
// durable truth lives in the annotations, so the error is swallowed by the caller.
func (s *LeaderSwapper) mirrorPhaseStatus(ctx context.Context, wis *amtdv1beta1.WarmInferenceSet, phase string, clearBlocked bool, durMillis int64) error {
	leader, _ := s.pool.CurrentLeader(ctx, wis)
	readyShadows, _ := s.pool.ReadyShadows(ctx, wis)

	fresh := &amtdv1beta1.WarmInferenceSet{}
	if err := s.Get(ctx, client.ObjectKey{Namespace: wis.Namespace, Name: wis.Name}, fresh); err != nil {
		return client.IgnoreNotFound(err)
	}
	fresh.Status.SwapPhase = phase
	fresh.Status.ActiveLeader = leader
	fresh.Status.ReadyShadows = readyShadows
	if durMillis > 0 {
		fresh.Status.LastSwapDurationMillis = durMillis
	}
	if clearBlocked {
		meta.RemoveStatusCondition(&fresh.Status.Conditions, amtdv1beta1.ConditionSwapBlockedNoReadyShadow)
	}
	return s.Status().Update(ctx, fresh)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
