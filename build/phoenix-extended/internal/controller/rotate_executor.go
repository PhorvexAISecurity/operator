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

// Package controller — Phase 1 Rotate executor + D22 storm-guard pipeline.
//
// executeRotate is the one-shot Rotate executor (D2): it wraps the Phase 0 cold
// reschedule with the D22 storm-guard pipeline (arch §1.3 #5, dec D22) and the D3
// mutation-survival routing (arch §1.3 #7), then writes the audit Status fields
// (D1/D2/D3/D23). It is called from the SecurityEvent reconciler's Rotate branch.
//
// STATE HOME (the honest reconciliation locked by the Stage-1 plan):
//   - AMTDStatus is a per-AMTD AGGREGATE (single LastRotationTime / RotationCount /
//     FailedRotationCount / BackoffUntil / LastKnownGoodRef). The min-interval
//     floor, crash-loop backoff and counters read/write the aggregate.
//   - There is NO per-pod map in Status, so the per-pod idempotence key and the
//     in-progress lock live on the POD as UID-keyed annotations. This is the honest
//     reconciliation of D22's "idempotence key = pod UID + SecurityEvent UID" with
//     "state home = AMTDStatus aggregate".
//
// PHASE 1 SCOPE: the storm-guard is the timer / idempotence / min-interval / backoff
// set. The SCORE-driven guards (EWMA SmoothedScore + N-consecutive-high +
// PanicThreshold floor-bypass) are Phase 3/5 — the Status fields exist but stay
// unwritten here.
package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// Phase 1 per-pod rotation annotations (UID-keyed state, since AMTDStatus has no
// per-pod map). The in-progress key is the cross-controller lock the NIM
// reconciler early-returns on.
const (
	// ROTATION_LAST_KEY records the last (podUID/eventUID) this pod was rotated
	// for (G1 idempotence).
	ROTATION_LAST_KEY string = "rotation.r6security.com/last-rotation-key"
	// ROTATION_IN_PROGRESS marks a rotation underway for this pod (G2 lock). The
	// NIM reconciler early-returns while it is present.
	ROTATION_IN_PROGRESS string = "rotation.r6security.com/in-progress"
)

// Phase 1 storm-guard defaults (D22 / arch §1.3 #9 flagged proposals applied in
// code so nil policy == today's behavior without a CRD-default round-trip).
const (
	// defaultMinInterval is the anti-flap FLOOR when RotationPolicy.MinInterval is nil.
	defaultMinInterval = 60 * time.Second
	// defaultMaxFailedRotations is the crash-loop ceiling when
	// AdaptiveRotationPolicy.MaxFailedRotations is nil.
	defaultMaxFailedRotations = 3
	// backoffBase is the base of the exponential crash-loop backoff.
	backoffBase = 30 * time.Second
)

// rotateOutcome is the result of a guard evaluation: whether the Rotate should
// proceed and, if skipped, a short machine reason for the audit Event/condition.
type rotateOutcome struct {
	proceed bool
	reason  string
	message string
}

// effectiveMinInterval returns the configured MinInterval or the 60s default.
func effectiveMinInterval(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) time.Duration {
	if amtd != nil && amtd.Spec.InferenceRotation != nil && amtd.Spec.InferenceRotation.RotationPolicy != nil {
		if mi := amtd.Spec.InferenceRotation.RotationPolicy.MinInterval; mi != nil {
			return mi.Duration
		}
	}
	return defaultMinInterval
}

// effectiveMaxFailedRotations returns the configured MaxFailedRotations or 3.
func effectiveMaxFailedRotations(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) int {
	if amtd != nil && amtd.Spec.InferenceRotation != nil && amtd.Spec.InferenceRotation.AdaptiveRotation != nil {
		if m := amtd.Spec.InferenceRotation.AdaptiveRotation.MaxFailedRotations; m != nil {
			return *m
		}
	}
	return defaultMaxFailedRotations
}

// rotationKeyFor builds the (podUID/eventUID) idempotence key.
func rotationKeyFor(pod *corev1.Pod, ev *amtdv1beta1.SecurityEvent) string {
	return fmt.Sprintf("%s/%s", pod.UID, ev.UID)
}

// podIsReady reports whether the pod's PodReady condition is True.
func podIsReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// podInCrashLoop reports whether any container is waiting in CrashLoopBackOff,
// the Phase 1 "failed replacement" signal feeding the crash-loop counter (G5).
func podInCrashLoop(pod *corev1.Pod) bool {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason == "CrashLoopBackOff" {
			return true
		}
	}
	return false
}

// executeRotate runs the full Phase 1 Rotate: D22 guards -> resolve overlay -> D3
// classify -> (durable owner-template patch OR cold fallback) -> cold reschedule
// -> Status writes. It is the SINGLE entry point the Rotate branch calls.
//
// One SecurityEvent => at most one action; no controller self-requeue to
// re-mutate. A SKIP (any guard) is a no-op for the pod and records the reason.
func (r *SecurityEventReconciler) executeRotate(
	ctx context.Context,
	pod *corev1.Pod,
	amtd *amtdv1beta1.AdaptiveMovingTargetDefense,
	ev *amtdv1beta1.SecurityEvent,
	action *amtdv1beta1.RotateAction,
	score scoringResult,
	log logr.Logger,
) error {
	now := time.Now()

	// ---- G1 IDEMPOTENCE (per-pod, UID-keyed): same (pod,event) => no-op. -------
	key := rotationKeyFor(pod, ev)
	if pod.Annotations != nil && pod.Annotations[ROTATION_LAST_KEY] == key {
		log.Info("Rotate G1 idempotence: this (pod,event) was already acted on; skipping", "pod", pod.Name, "key", key)
		return nil
	}

	// ---- G2 IN-PROGRESS LOCK (per-pod): a rotation is underway => skip re-fire. -
	if pod.Annotations != nil && pod.Annotations[ROTATION_IN_PROGRESS] == "true" {
		log.Info("Rotate G2 in-progress: a rotation is already underway for this pod; skipping re-fire", "pod", pod.Name)
		return nil
	}

	// ---- G3 MIN-INTERVAL FLOOR (aggregate Status): the core anti-thrash guard. --
	// PANIC (D25/arch L330 LOCKED) bypasses ONLY this floor: when the EWMA-smoothed
	// score is >= panicThreshold AND the N-consecutive-high hysteresis is armed
	// (score.panic, computed in applyScoring), the min-interval wait is collapsed so
	// the rotation fires immediately. A single spike or an unsmoothed blip leaves
	// score.panic=false, so the floor still applies. EVERY other guard (G2/G4/G5/G6)
	// is retained below — panic does NOT bypass readiness, backoff, or max-concurrent.
	minInterval := effectiveMinInterval(amtd)
	if !score.panic && !amtd.Status.LastRotationTime.IsZero() {
		earliest := amtd.Status.LastRotationTime.Time.Add(minInterval)
		if now.Before(earliest) {
			out := rotateOutcome{
				proceed: false,
				reason:  "MinIntervalFloor",
				message: fmt.Sprintf("rotation skipped: min-interval floor %s not elapsed since last rotation %s (earliest %s)", minInterval, amtd.Status.LastRotationTime.Time.Format(time.RFC3339), earliest.Format(time.RFC3339)),
			}
			log.Info("Rotate G3 min-interval: skipping", "pod", pod.Name, "minInterval", minInterval.String(), "lastRotation", amtd.Status.LastRotationTime.Time)
			r.recordRotationThrottled(ctx, amtd, out, log)
			return nil
		}
	}
	if score.panic && !amtd.Status.LastRotationTime.IsZero() {
		log.Info("Rotate PANIC: bypassing ONLY the min-interval floor (readiness/backoff/max-concurrent retained)", "pod", pod.Name, "smoothedScore", formatScore(score.smoothed), "consecutiveHighCount", score.consecHigh)
	}

	// ---- G5a BACKOFF window (aggregate Status): crash-loop backoff in effect. ---
	// (checked here, before doing any work, so a backing-off AMTD never rotates.)
	if !amtd.Status.BackoffUntil.IsZero() && now.Before(amtd.Status.BackoffUntil.Time) {
		out := rotateOutcome{
			proceed: false,
			reason:  "CrashLoopBackoff",
			message: fmt.Sprintf("rotation skipped: in crash-loop backoff until %s (failedRotationCount=%d)", amtd.Status.BackoffUntil.Time.Format(time.RFC3339), amtd.Status.FailedRotationCount),
		}
		log.Info("Rotate G5 backoff: skipping", "pod", pod.Name, "backoffUntil", amtd.Status.BackoffUntil.Time, "failedRotationCount", amtd.Status.FailedRotationCount)
		r.recordRotationThrottled(ctx, amtd, out, log)
		return nil
	}

	// ---- G4 READINESS GATE (aggregate + observed pod): don't rotate again until
	// the prior replacement is Ready. Honest minimal form: only gate when a prior
	// rotation has happened (LastRotationTime set) AND the current target pod is
	// not Ready (still stabilizing from that prior rotation). The first-ever
	// rotation (no LastRotationTime) is never readiness-gated.
	if !amtd.Status.LastRotationTime.IsZero() && !podIsReady(pod) {
		out := rotateOutcome{
			proceed: false,
			reason:  "ReplacementNotReady",
			message: fmt.Sprintf("rotation skipped: prior replacement pod %q is not Ready yet", pod.Name),
		}
		log.Info("Rotate G4 readiness: skipping", "pod", pod.Name)
		r.recordRotationThrottled(ctx, amtd, out, log)
		return nil
	}

	// ---- G5b CRASH-LOOP DETECTION + ROLLBACK: the target replacement is failing.
	// Count the failure; once it exceeds MaxFailedRotations, arm an exponential
	// backoff and roll back to LastKnownGoodRef (Phase 1 rollback = restore the
	// last-known-good image overlay onto the durable owner template; the full
	// Regenerate baseline restore is Phase 5). Do NOT proceed with a new rotation
	// on a failing replacement.
	if podInCrashLoop(pod) {
		return r.handleCrashLoop(ctx, pod, amtd, action, now, log)
	}

	// ---- G6 MAX-CONCURRENT-ROTATIONS (D24, Phase-2 half of cap#4): defer this
	// rotation if the AMTD already has >= cap rotations in flight. "In flight" =
	// pods under the AMTD's PodSelector carrying the Phase-1 in-progress annotation.
	// The candidate pod is not yet stamped (its lock is set below), so the cap is
	// "others in flight" — the correct reading of max-concurrent with this pod as
	// the candidate. nil/0 cap => unlimited (today's behavior; guard is a no-op).
	//
	// DEVIATION (D24 prefers requeue-not-drop): this one-shot executor does not own
	// the Reconcile Result stack, so a true ctrl.Result{RequeueAfter} cannot be
	// returned from here. The honest realization is skip + RotationThrottled
	// condition; the timed SecurityEvent re-fires on the next cadence tick, so the
	// deferred rotation is re-selected then (documented as "deferred via skip +
	// condition; re-selected on next cadence emission").
	if maxConcurrent := effectiveMaxConcurrentRotations(amtd); maxConcurrent >= 0 {
		inFlight := countInFlightRotations(ctx, r.Client, amtd, log)
		if inFlight >= maxConcurrent {
			out := rotateOutcome{
				proceed: false,
				reason:  "MaxConcurrentRotations",
				message: fmt.Sprintf("rotation deferred: in-flight rotations %d >= MaxConcurrentRotations cap %d for AMTD %q; re-selected on the next cadence emission", inFlight, maxConcurrent, amtd.Name),
			}
			log.Info("Rotate G6 max-concurrent: deferring", "pod", pod.Name, "inFlight", inFlight, "cap", maxConcurrent)
			r.recordRotationThrottled(ctx, amtd, out, log)
			return nil
		}
	}

	// ---- Cadence-policy observations (best-effort, recorded when a Rotate fires
	// because that is when the cadence policy is consulted): the 5m BaseInterval
	// floor (D9) and the PseudoRandom EntropyWarning (D13). These do not gate the
	// rotation; they make the effective cadence policy honest/observable. The seed
	// Secret is loaded/created here so the per-AMTD jitter seed exists and is
	// restart-reproducible (D5); the scheduler.Next stagger phase is keyed by it.
	if _, floored := effectiveBaseInterval(amtd); floored {
		if rp := rotationPolicyOf(amtd); rp != nil && rp.BaseInterval != nil {
			r.recordBaseIntervalFloored(ctx, amtd, rp.BaseInterval.Duration, baseIntervalFloor, log)
		}
	}
	if effectiveEntropySource(amtd) == amtdv1beta1.EntropySourcePseudoRandom {
		r.recordEntropyWarning(ctx, amtd, log)
	}
	// Ensure the persisted jitter seed exists (creates on first miss; D5). The
	// returned seed is NOT published anywhere world-readable (schedule secrecy).
	_ = r.jitterSeed(ctx, amtd, log)

	// ====================== PROCEED: perform the rotation =======================

	applier := NewMutationApplier()
	// Resolve the effective overlay. A PolicyRef{Kind:"ContextMutationPolicy"} is
	// FETCHED here via r.Client (D7g) and projected into the same overlay an embedded
	// InferenceRotation/inline Overrides produces. A fetch error (other than NotFound,
	// which degrades to cold) is fatal to this one-shot — fail honestly rather than
	// rotate with a half-resolved overlay.
	overlay, effectiveSource, err := applier.Resolve(ctx, r.Client, action, amtd)
	if err != nil {
		log.Error(err, "Rotate: failed to resolve effective overlay", "pod", pod.Name)
		return err
	}

	// D3 owner-walk routing.
	route, top, notDurableReason := classifyTopOwner(ctx, r.Client, pod, overlay.IsEmpty())

	mutationDurable := false
	rotationPathFired := "cold"

	switch route {
	case routeDurableOwnerTemplate:
		// (a) Patch the TOP owner template (durable, all replicas), idempotently.
		wrote, err := patchOwnerTemplate(ctx, r.Client, applier, top, overlay)
		if err != nil {
			log.Error(err, "Rotate route (a): failed to patch top owner template", "ownerKind", top.kind, "owner", top.name)
			return err
		}
		if wrote {
			log.Info("Rotate route (a): patched top owner template (durable, all replicas)", "ownerKind", top.kind, "owner", top.name)
		} else {
			log.Info("Rotate route (a): top owner template already carries the overlay (idempotent no-op; self-Update loop guarded)", "ownerKind", top.kind, "owner", top.name)
		}
		mutationDurable = true
		rotationPathFired = "Rotate"

	case routeColdFallback:
		// (b) durable per-pod mutation is physically impossible; honest cold fallback.
		log.Info("Rotate route (b): cold fallback (mutation not durable)", "pod", pod.Name, "reason", notDurableReason)
		if notDurableReason == reasonPerPodOnSharedTemplate {
			log.Info("Rotate: warm cutover deferred to Phase 4; treating as cold fallback now", "pod", pod.Name)
		}
		mutationDurable = false
		rotationPathFired = "cold"

	case routeColdNoOverlay:
		// Pure cold reschedule (today's Phase 0 behavior). Nothing was mutated, so
		// no durability is claimed and no non-durability reason is recorded.
		log.Info("Rotate: empty overlay -> pure cold reschedule (Phase 0 behavior)", "pod", pod.Name)
		mutationDurable = false
		rotationPathFired = "cold"
	}

	// Stamp the per-pod idempotence key + in-progress lock onto the pod BEFORE the
	// reschedule. rescheduleByAnnotateThenDelete persists these via its Update,
	// then deletes the pod; the recreated pod has no annotations, so the lock
	// clears naturally. (In the durable route the recreated replicas already carry
	// the patched template.)
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[ROTATION_LAST_KEY] = key
	pod.Annotations[ROTATION_IN_PROGRESS] = "true"

	startupState := determinePodStartupStateFor(*pod)
	if err := rescheduleByAnnotateThenDelete(ctx, r.Client, pod, startupState, defaultRotateGracePeriodSeconds, log); err != nil {
		log.Error(err, "Rotate: failed cold reschedule", "pod", pod.Name)
		return err
	}

	// ---- ON SUCCESS: write the aggregate Status (D22 counters + D1/D2/D3 audit +
	// D25 Panic condition when this fire was a panic).
	r.recordRotationSuccess(ctx, amtd, ev, overlay, effectiveSource, rotationPathFired, mutationDurable, notDurableReason, score, now, log)

	log.Info("Pod successfully rotated", "pod", pod.Name, "rotationPathFired", rotationPathFired, "mutationDurable", mutationDurable, "effectiveSource", effectiveSource)
	return nil
}

// handleCrashLoop implements G5: increment FailedRotationCount; if it exceeds
// MaxFailedRotations, arm an exponential backoff and roll back to LastKnownGoodRef.
func (r *SecurityEventReconciler) handleCrashLoop(
	ctx context.Context,
	pod *corev1.Pod,
	amtd *amtdv1beta1.AdaptiveMovingTargetDefense,
	action *amtdv1beta1.RotateAction,
	now time.Time,
	log logr.Logger,
) error {
	fresh := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	if err := r.Client.Get(ctx, namespacedNameOf(amtd), fresh); err != nil {
		log.Error(err, "Rotate G5: failed to re-read AMTD for crash-loop accounting", "AMTD", amtd.Name)
		return nil
	}
	fresh.Status.FailedRotationCount++
	maxFailed := effectiveMaxFailedRotations(amtd)

	if fresh.Status.FailedRotationCount > maxFailed {
		// Exponential backoff keyed on the failure count over the ceiling.
		over := fresh.Status.FailedRotationCount - maxFailed
		backoff := backoffBase * time.Duration(1<<uint(minInt(over-1, 16)))
		fresh.Status.BackoffUntil = metav1.NewTime(now.Add(backoff))

		// Phase 1 rollback: restore the last-known-good image overlay onto the
		// durable owner template (if any). The full Regenerate baseline restore is
		// Phase 5; here we roll the durable template's image back to the last-known
		// -good ref name when one is recorded and the pod has a durable owner.
		if fresh.Status.LastKnownGoodRef != nil && fresh.Status.LastKnownGoodRef.Name != "" {
			if route, top, _ := classifyTopOwner(ctx, r.Client, pod, false); route == routeDurableOwnerTemplate {
				rollback := EffectiveOverlay{Image: fresh.Status.LastKnownGoodRef.Name}
				if _, err := patchOwnerTemplate(ctx, r.Client, NewMutationApplier(), top, rollback); err != nil {
					log.Error(err, "Rotate G5 rollback: failed to restore last-known-good image onto owner template", "ownerKind", top.kind, "owner", top.name)
				} else {
					log.Info("Rotate G5 rollback: restored last-known-good image onto owner template", "ownerKind", top.kind, "owner", top.name, "lastKnownGood", fresh.Status.LastKnownGoodRef.Name)
				}
			}
		}

		cond := metav1.Condition{
			Type:               "RotationBackoff",
			Status:             metav1.ConditionTrue,
			Reason:             "CrashLoopBackoff",
			Message:            fmt.Sprintf("replacement crash-looped; failedRotationCount=%d exceeds maxFailedRotations=%d; backing off until %s", fresh.Status.FailedRotationCount, maxFailed, fresh.Status.BackoffUntil.Time.Format(time.RFC3339)),
			ObservedGeneration: fresh.Generation,
		}
		meta.SetStatusCondition(&fresh.Status.Conditions, cond)
		log.Info("Rotate G5: crash-loop ceiling exceeded; armed backoff + rollback", "pod", pod.Name, "failedRotationCount", fresh.Status.FailedRotationCount, "backoffUntil", fresh.Status.BackoffUntil.Time)
	} else {
		log.Info("Rotate G5: replacement crash-looping; incremented failure count (under ceiling)", "pod", pod.Name, "failedRotationCount", fresh.Status.FailedRotationCount, "maxFailedRotations", maxFailed)
	}

	if err := r.Client.Status().Update(ctx, fresh); err != nil {
		log.Error(err, "Rotate G5: failed to write crash-loop Status", "AMTD", amtd.Name)
	}
	return nil
}

// recordRotationThrottled records a skip (G3/G4/G5) as a RotationThrottled
// condition on the AMTD. Best-effort: a write failure is logged, not fatal (the
// skip itself is the fail-safe behavior).
func (r *SecurityEventReconciler) recordRotationThrottled(ctx context.Context, amtd *amtdv1beta1.AdaptiveMovingTargetDefense, out rotateOutcome, log logr.Logger) {
	fresh := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	if err := r.Client.Get(ctx, namespacedNameOf(amtd), fresh); err != nil {
		log.Error(err, "Rotate: failed to re-read AMTD to record throttle", "AMTD", amtd.Name)
		return
	}
	cond := metav1.Condition{
		Type:               "RotationThrottled",
		Status:             metav1.ConditionTrue,
		Reason:             out.reason,
		Message:            out.message,
		ObservedGeneration: fresh.Generation,
	}
	if meta.SetStatusCondition(&fresh.Status.Conditions, cond) {
		if err := r.Client.Status().Update(ctx, fresh); err != nil {
			log.Error(err, "Rotate: failed to write RotationThrottled condition", "AMTD", amtd.Name)
		}
	}
}

// recordRotationSuccess writes the post-rotation aggregate Status (D22 counters
// reset + D1/D2/D3 audit) on the AMTD and the per-event outcome on the
// SecurityEvent. It re-reads the AMTD first to avoid clobbering a concurrently
// updated status (the fake client and apiserver both reject stale status writes
// otherwise). Best-effort with logging.
func (r *SecurityEventReconciler) recordRotationSuccess(
	ctx context.Context,
	amtd *amtdv1beta1.AdaptiveMovingTargetDefense,
	ev *amtdv1beta1.SecurityEvent,
	overlay EffectiveOverlay,
	effectiveSource, rotationPathFired string,
	mutationDurable bool,
	notDurableReason string,
	score scoringResult,
	now time.Time,
	log logr.Logger,
) {
	fresh := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	if err := r.Client.Get(ctx, namespacedNameOf(amtd), fresh); err != nil {
		log.Error(err, "Rotate: failed to re-read AMTD to record success", "AMTD", amtd.Name)
		return
	}

	fresh.Status.LastRotationTime = metav1.NewTime(now)
	fresh.Status.RotationCount++
	fresh.Status.FailedRotationCount = 0
	fresh.Status.BackoffUntil = metav1.Time{}
	fresh.Status.EffectiveSource = effectiveSource
	fresh.Status.RotationPathFired = rotationPathFired
	fresh.Status.MutationDurable = mutationDurable
	if mutationDurable {
		fresh.Status.MutationNotDurableReason = ""
	} else {
		fresh.Status.MutationNotDurableReason = notDurableReason
	}
	// Record the last-known-good image ref on a successful durable rotation so a
	// later crash-loop can roll back to it (G5). Cold fallbacks do not mutate, so
	// they do not advance the last-known-good image.
	if mutationDurable && overlay.Image != "" {
		fresh.Status.LastKnownGoodRef = &amtdv1beta1.LocalRef{Name: overlay.Image}
	}

	// Clear any prior throttle/backoff condition now that a rotation succeeded.
	meta.RemoveStatusCondition(&fresh.Status.Conditions, "RotationThrottled")
	meta.RemoveStatusCondition(&fresh.Status.Conditions, "RotationBackoff")

	// D25 PANIC condition: when this fire was a panic (smoothed >= threshold AND
	// consec >= N, bypassing ONLY the min-interval floor), record it on the AMTD so
	// the panic is auditable. Panic = immediate Rotate ONLY — it does NOT move nodes
	// or quarantine (those are the separate ThreatLevel-keyed NodeRotate/Quarantine
	// actions). When NOT a panic, clear any stale Panic condition.
	if score.panic {
		cond := metav1.Condition{
			Type:               "Panic",
			Status:             metav1.ConditionTrue,
			Reason:             "ScoreThresholdCrossed",
			Message:            panicConditionMessage(score, effectiveConsecutiveHighSamples(amtd)),
			ObservedGeneration: fresh.Generation,
		}
		meta.SetStatusCondition(&fresh.Status.Conditions, cond)
		log.Info("Rotate: recorded Panic condition (immediate Rotate; node-move/quarantine NOT triggered)", "AMTD", amtd.Name, "smoothedScore", formatScore(score.smoothed), "consecutiveHighCount", score.consecHigh)
	} else {
		meta.RemoveStatusCondition(&fresh.Status.Conditions, "Panic")
	}

	if err := r.Client.Status().Update(ctx, fresh); err != nil {
		log.Error(err, "Rotate: failed to write success Status on AMTD", "AMTD", amtd.Name)
	}

	// Per-event outcome on the SecurityEvent (best-effort).
	freshEv := &amtdv1beta1.SecurityEvent{}
	if err := r.Client.Get(ctx, namespacedNameOfEvent(ev), freshEv); err == nil {
		freshEv.Status.AppliedAction = "rotate"
		freshEv.Status.ProcessedAt = metav1.NewTime(now)
		if ev.Spec.AnomalyScore != nil {
			freshEv.Status.ObservedScore = *ev.Spec.AnomalyScore
		}
		if err := r.Client.Status().Update(ctx, freshEv); err != nil {
			log.Error(err, "Rotate: failed to write SecurityEvent outcome status", "SecurityEvent", ev.Name)
		}
	}
}

// minInt is a tiny helper (Go <1.21 compatible spelling avoided; kept local to
// not collide with any builtin).
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// namespacedNameOf / namespacedNameOfEvent are small ObjectKey helpers.
func namespacedNameOf(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) types.NamespacedName {
	return types.NamespacedName{Namespace: amtd.Namespace, Name: amtd.Name}
}
func namespacedNameOfEvent(ev *amtdv1beta1.SecurityEvent) types.NamespacedName {
	return types.NamespacedName{Namespace: ev.Namespace, Name: ev.Name}
}

// podHasRotationInProgress reports whether the per-pod in-progress lock is set; it
// is the accessor the NIM reconciler early-returns on (G2 cross-controller lock).
func podHasRotationInProgress(pod *corev1.Pod) bool {
	return pod.Annotations != nil && pod.Annotations[ROTATION_IN_PROGRESS] == "true"
}
