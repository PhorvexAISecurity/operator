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

// Package controller — Phase 3 telemetry-scoring UPDATE (cap#5, arch §2.3/§2.4,
// D19/D20/D22/D25/D26g). applyScoring runs on the SecurityEvent reconcile path
// ONLY when an AMTD is in MatcherMode=Scored AND carries an AdaptiveRotation
// block. It scores the event (Passthrough by default), applies the D26g
// provenance gate + D25 staleness decay, advances the D22 EWMA SmoothedScore and
// N-consecutive-high counter, computes the monotone-decreasing ComputedInterval,
// and writes ALL of it to Status (restart-safe; NOTHING lives in controller
// memory). It returns the smoothed score + whether the panic hysteresis is armed
// so the executor's G3 floor-bypass (panic_gate) can consult it.
//
// EXACT-MATCH (MatcherMode=Exact/unset) NEVER calls this — the scored Status
// fields stay unwritten and the dispatch path is byte-for-byte today's behavior.
package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// scoringResult is what applyScoring computes and threads into the executor. All
// of it is also persisted to Status; the struct is the in-reconcile carrier so
// the panic gate sees the just-computed values without a re-read.
type scoringResult struct {
	scored       bool          // a usable (trusted, parseable) score was produced
	rawScore     string        // the raw post-provenance score (pre-staleness), audit
	effective    float64       // the effective score after staleness decay
	smoothed     float64       // EWMA SmoothedScore after this sample
	consecHigh   int           // ConsecutiveHighCount after this sample
	computed     time.Duration // ComputedInterval = f(smoothed), bounded [min,base]
	panic        bool          // panic hysteresis armed (smoothed>=thr && consec>=N)
}

// applyScoring performs the Phase 3 scoring UPDATE for one matched AMTD against
// one SecurityEvent and persists the result to both Status structs. It is a
// best-effort observability/feedback write: a Status write failure is logged, not
// fatal (the rotation decision still proceeds with the in-memory scoringResult).
//
// Order (arch §2.3, D26g -> D25 -> D22): (a) score + PROVENANCE gate, (b)
// STALENESS decay, (c) EWMA, (d) N-consecutive-high, (e) ComputedInterval, (f)
// write AMTDStatus + SecurityEventStatus.
func (r *SecurityEventReconciler) applyScoring(
	ctx context.Context,
	amtd *amtdv1beta1.AdaptiveMovingTargetDefense,
	ev *amtdv1beta1.SecurityEvent,
	log logr.Logger,
) scoringResult {
	now := time.Now()

	// Re-read the AMTD so the EWMA chain reads the freshest persisted SmoothedScore
	// / ConsecutiveHighCount and the write does not clobber a concurrent status
	// update (same pattern as recordRotationSuccess).
	fresh := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	if err := r.Client.Get(ctx, namespacedNameOf(amtd), fresh); err != nil {
		log.Error(err, "applyScoring: failed to re-read AMTD; scoring this cycle in-memory only", "AMTD", amtd.Name)
		fresh = amtd.DeepCopy()
	}

	// ---- (a) SCORE + PROVENANCE (D20 + D26g) ---------------------------------
	// The scorer (Passthrough default) yields a [0,1] decimal string; the score is
	// honored ONLY when the event's Source is on the trusted allowlist. RBAC is the
	// PRIMARY gate (a workload SA cannot create securityevents); this allowlist is
	// defense-in-depth. A non-trusted Source => treat as unscored (score ignored).
	scorer, policy := scorerFor(amtd)
	rawScore, scored := scorer.Score(ev, policy)
	if scored && !isTrustedScoreSource(ev) {
		log.Info("applyScoring: score from a non-trusted Source ignored (D26g provenance)", "source", ev.Spec.Rule.Source, "AMTD", amtd.Name)
		scored = false
		rawScore = ""
	}

	res := scoringResult{scored: scored, rawScore: rawScore}

	// If unscored, there is nothing to advance: leave the persisted EWMA/counter
	// untouched, do NOT write LastObservedScore (it stays empty == "unscored"), and
	// compute the interval from the EXISTING smoothed score (so an unscored event
	// neither accelerates nor resets the cadence).
	if !scored {
		prev := parseSmoothed(fresh.Status.SmoothedScore)
		res.smoothed = prev
		res.consecHigh = fresh.Status.ConsecutiveHighCount
		res.computed = computedInterval(amtd, prev)
		// Still surface the current ComputedInterval so Status reflects the cadence.
		r.writeScoringStatus(ctx, fresh, ev, res, now, false /*advance*/, log)
		return res
	}

	effective, _ := parseScore(rawScore) // rawScore came from the scorer => valid.

	// ---- (b) STALENESS (D25): a stale score decays to 0 ----------------------
	// A score older than StalenessWindow neither accelerates nor suppresses: its
	// effective value is 0. The raw score is kept for audit (LastObservedScore).
	if win := effectiveStalenessWindow(amtd); win > 0 {
		age := now.Sub(ev.CreationTimestamp.Time)
		if !ev.CreationTimestamp.IsZero() && age > win {
			log.Info("applyScoring: score is stale; decaying effective score to 0 (D25)", "age", age.String(), "stalenessWindow", win.String(), "AMTD", amtd.Name)
			effective = 0
		}
	}
	res.effective = effective

	// ---- (c) EWMA (D22): smoothed = alpha*score + (1-alpha)*prev -------------
	alpha := effectiveEWMAAlpha(amtd)
	prev := parseSmoothed(fresh.Status.SmoothedScore)
	smoothed := alpha*effective + (1-alpha)*prev
	smoothed = clamp01(smoothed)
	res.smoothed = smoothed

	// ---- (d) N-CONSECUTIVE-HIGH (D22): count >= panicThreshold else reset ----
	// Per the spec wording ("score>=panicThreshold"), the EFFECTIVE (post-staleness)
	// score is compared to the threshold, so a decayed-stale score resets the count.
	panicThreshold := effectivePanicThreshold(amtd)
	if effective >= panicThreshold {
		res.consecHigh = fresh.Status.ConsecutiveHighCount + 1
	} else {
		res.consecHigh = 0
	}

	// ---- (e) ComputedInterval = monotone-decreasing f(smoothed) [min,base] ---
	res.computed = computedInterval(amtd, smoothed)

	// ---- panic hysteresis (consulted by the executor G3 bypass, D25) ---------
	// PANIC = smoothed >= threshold AND consecHigh >= N. A single spike
	// (consec < N) or an unsmoothed blip (smoothed < threshold) does NOT panic.
	res.panic = smoothed >= panicThreshold && res.consecHigh >= effectiveConsecutiveHighSamples(amtd)

	// ---- (f) persist to Status (restart-safe) --------------------------------
	r.writeScoringStatus(ctx, fresh, ev, res, now, true /*advance*/, log)

	log.Info("applyScoring: scored",
		"AMTD", amtd.Name, "rawScore", rawScore, "effective", effective,
		"smoothed", formatScore(smoothed), "consecutiveHighCount", res.consecHigh,
		"computedInterval", res.computed.String(), "panic", res.panic)
	return res
}

// writeScoringStatus persists the scoring outputs. When advance==true it writes
// the EWMA/counter/LastObservedScore (a real scored sample). When advance==false
// (unscored event) it only refreshes CurrentInterval and leaves the EWMA chain,
// the counter and LastObservedScore untouched. Both branches write the
// SecurityEventStatus (ObservedScore + ComputedInterval) so the per-event outcome
// is always recorded on the trigger object. Best-effort.
func (r *SecurityEventReconciler) writeScoringStatus(
	ctx context.Context,
	fresh *amtdv1beta1.AdaptiveMovingTargetDefense,
	ev *amtdv1beta1.SecurityEvent,
	res scoringResult,
	now time.Time,
	advance bool,
	log logr.Logger,
) {
	fresh.Status.CurrentInterval = metav1.Duration{Duration: res.computed}
	if advance {
		fresh.Status.SmoothedScore = formatScore(res.smoothed)
		fresh.Status.ConsecutiveHighCount = res.consecHigh
		fresh.Status.LastObservedScore = res.rawScore
	}
	if err := r.Client.Status().Update(ctx, fresh); err != nil {
		log.Error(err, "applyScoring: failed to write AMTD scoring Status", "AMTD", fresh.Name)
	}

	// SecurityEventStatus: ObservedScore (raw) + ComputedInterval, independent of
	// whether a Rotate fires. Re-read to avoid clobbering a concurrent status write.
	freshEv := &amtdv1beta1.SecurityEvent{}
	if err := r.Client.Get(ctx, namespacedNameOfEvent(ev), freshEv); err == nil {
		freshEv.Status.ObservedScore = res.rawScore
		freshEv.Status.ComputedInterval = metav1.Duration{Duration: res.computed}
		if err := r.Client.Status().Update(ctx, freshEv); err != nil {
			log.Error(err, "applyScoring: failed to write SecurityEvent scoring Status", "SecurityEvent", ev.Name)
		}
	}
}

// computedInterval is the monotone-DECREASING linear cadence map f(SmoothedScore)
// bounded to [MinInterval, BaseInterval] (D20 linear default):
//
//	interval = BaseInterval - smoothed*(BaseInterval - MinInterval)
//
// smoothed=0 -> BaseInterval (slowest), smoothed=1 -> MinInterval (fastest). The
// result is clamped to [MinInterval, BaseInterval]. effectiveBaseInterval already
// applies the 60m default + 5m floor (D9); effectiveMinInterval applies the 60s
// default. If MinInterval > BaseInterval (a misconfiguration), the interval is
// pinned to BaseInterval (the floor wins, fail-safe-slow).
func computedInterval(amtd *amtdv1beta1.AdaptiveMovingTargetDefense, smoothed float64) time.Duration {
	base, _ := effectiveBaseInterval(amtd)
	min := effectiveMinInterval(amtd)
	if min >= base {
		return base
	}
	s := clamp01(smoothed)
	span := base - min
	interval := base - time.Duration(s*float64(span))
	if interval < min {
		interval = min
	}
	if interval > base {
		interval = base
	}
	return interval
}

// parseSmoothed parses a persisted SmoothedScore string; an empty/malformed value
// is treated as 0 (the EWMA seed = "no prior signal").
func parseSmoothed(s string) float64 {
	if s == "" {
		return 0
	}
	if v, ok := parseScore(s); ok {
		return v
	}
	return 0
}

// panicConditionMessage builds the human-readable Panic condition message.
func panicConditionMessage(res scoringResult, n int) string {
	return fmt.Sprintf("score panic: smoothedScore=%s >= panicThreshold and consecutiveHighCount=%d >= consecutiveHighSamples=%d; bypassing ONLY the min-interval floor (readiness/backoff/max-concurrent guards retained)",
		formatScore(res.smoothed), res.consecHigh, n)
}
