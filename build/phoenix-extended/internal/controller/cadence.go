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

// Package controller — Phase 2 cadence glue (arch §2.4 / §6 Phase 2; D5/D9/D10/
// D12g/D13/D14/D24).
//
// This file is the bridge between the api RotationPolicy cadence fields and the
// self-contained internal/scheduler PRIMITIVE:
//
//   - effectiveBaseInterval / effectiveJitter* / effectiveStagger* /
//     effectiveEntropySource: apply the CODE defaults (60m base / 5m floor /
//     10-30 band / Uniform / Crypto / PerPodPhaseOffset) so a nil policy
//     reproduces today's deterministic cadence. The 5m floor (D9) is enforced
//     HERE (clamp-up + BaseIntervalFloored condition) because metav1.Duration is
//     not portably comparable in CEL; the jitter bounds are enforced apiserver-
//     side by the CEL XValidation rule on RotationPolicy.
//   - schedulerPolicyFor: projects RotationPolicy -> scheduler.Policy.
//   - randSourceFor: picks the crypto (default) or seeded (PseudoRandom) RNG and
//     flags PseudoRandom on a live AMTD with an EntropyWarning condition (D13).
//   - jitterSeed: loads/creates the per-AMTD jitter SEED Secret (D5, arch L228) —
//     a dedicated RBAC-gated Secret, NEVER a Status/CR field, so the secret
//     cadence is not re-exposed via a world-readable Status.
//   - effectiveMaxConcurrentRotations + countInFlightRotations: the Phase-2 half
//     of cap#4 (D24) — the cap accessor and the in-flight counter the G6 guard
//     consults.
//
// SCHEDULE SECRECY (D5): nothing here writes a next-fire to Status or any
// world-readable field. AMTDStatus exposes only PAST cadence
// (LastRotationTime/CurrentInterval/RotationCount); no NextRotationTime exists.
package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	"github.com/r6security/phoenix/internal/scheduler"
)

// Phase 2 cadence defaults (D9/D10/D12g — flagged design proposals applied in
// code so a nil policy == today's deterministic cadence without a CRD-default
// round-trip).
const (
	// defaultBaseInterval is the cadence PERIOD R when RotationPolicy.BaseInterval
	// is nil (AMTD-AI §3.2 verbatim).
	defaultBaseInterval = 60 * time.Minute
	// baseIntervalFloor is the HARD floor (D9, flagged proposal): a sub-floor
	// BaseInterval is clamped up to this and a BaseIntervalFloored condition is set.
	baseIntervalFloor = 5 * time.Minute
	// defaultJitterMinPercent / defaultJitterMaxPercent are the paper band endpoints
	// (D10) used when the corresponding pointer is nil.
	defaultJitterMinPercent = 10
	defaultJitterMaxPercent = 30
	// jitterSeedBytes is the length of the persisted crypto seed (D5).
	jitterSeedBytes = 32
)

// rotationPolicyOf returns the AMTD's RotationPolicy or nil.
func rotationPolicyOf(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) *amtdv1beta1.RotationPolicy {
	if amtd != nil && amtd.Spec.InferenceRotation != nil {
		return amtd.Spec.InferenceRotation.RotationPolicy
	}
	return nil
}

// effectiveBaseInterval returns the cadence period with the 60m default applied,
// CLAMPED UP to the 5m floor (D9). It returns whether the clamp fired so the
// caller can record the BaseIntervalFloored condition (clamp is availability-safe;
// the condition makes the flooring honest/observable). A nil/zero BaseInterval
// takes the default (which is already above the floor, so no clamp).
func effectiveBaseInterval(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) (time.Duration, bool) {
	rp := rotationPolicyOf(amtd)
	if rp == nil || rp.BaseInterval == nil || rp.BaseInterval.Duration <= 0 {
		return defaultBaseInterval, false
	}
	d := rp.BaseInterval.Duration
	if d < baseIntervalFloor {
		return baseIntervalFloor, true
	}
	return d, false
}

// effectiveJitterMinPercent / effectiveJitterMaxPercent return the band endpoints
// with the 10/30 defaults applied. (The apiserver CEL rule has already enforced
// 0<=min<=max<=100 for any explicitly-set values.)
func effectiveJitterMinPercent(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) int {
	if rp := rotationPolicyOf(amtd); rp != nil && rp.JitterMinPercent != nil {
		return *rp.JitterMinPercent
	}
	return defaultJitterMinPercent
}

func effectiveJitterMaxPercent(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) int {
	if rp := rotationPolicyOf(amtd); rp != nil && rp.JitterMaxPercent != nil {
		return *rp.JitterMaxPercent
	}
	return defaultJitterMaxPercent
}

// effectiveJitterDistribution returns the distribution with the Uniform default.
func effectiveJitterDistribution(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) scheduler.Distribution {
	if rp := rotationPolicyOf(amtd); rp != nil && rp.JitterDistribution != "" {
		return scheduler.Distribution(rp.JitterDistribution)
	}
	return scheduler.Uniform
}

// effectiveStaggerMode returns the stagger with the PerPodPhaseOffset default.
func effectiveStaggerMode(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) scheduler.Stagger {
	if rp := rotationPolicyOf(amtd); rp != nil && rp.StaggerMode != "" {
		return scheduler.Stagger(rp.StaggerMode)
	}
	return scheduler.PerPodPhaseOffset
}

// effectiveEntropySource returns the entropy source with the Crypto default.
func effectiveEntropySource(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) amtdv1beta1.EntropySource {
	if rp := rotationPolicyOf(amtd); rp != nil && rp.EntropySource != "" {
		return rp.EntropySource
	}
	return amtdv1beta1.EntropySourceCrypto
}

// effectiveMaxConcurrentRotations returns the cap (D24); nil => -1 == unlimited
// (today's behavior). A non-positive configured value is treated as unlimited too
// (an explicit 0 would otherwise wedge all rotation; unlimited is the safe read).
func effectiveMaxConcurrentRotations(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) int {
	if rp := rotationPolicyOf(amtd); rp != nil && rp.MaxConcurrentRotations != nil {
		if *rp.MaxConcurrentRotations > 0 {
			return *rp.MaxConcurrentRotations
		}
	}
	return -1 // unlimited sentinel.
}

// ----------------------------------------------------------------------------
// Phase 3 scoring / panic effective-policy helpers (D20/D22/D25). Mirror the
// effectiveMinInterval pattern: a nil AdaptiveRotation or a nil field takes the
// CODE default, so nil == today's behavior without a CRD-default round-trip. The
// defaults are FLAGGED design proposals (arch §1.3 #9), NOT paper values.
// ----------------------------------------------------------------------------

const (
	// defaultPanicThreshold is the SmoothedScore at/above which a panic is a
	// candidate when AdaptiveRotation.PanicThreshold is nil (D25, flagged 0.85).
	defaultPanicThreshold = 0.85
	// defaultEWMAAlpha is the EWMA smoothing factor when EWMAAlpha is nil (D22).
	defaultEWMAAlpha = 0.3
	// defaultConsecutiveHighSamples is N (the panic anti-flap count) when
	// ConsecutiveHighSamples is nil (D22).
	defaultConsecutiveHighSamples = 3
	// defaultStalenessWindow is the staleness decay window when StalenessWindow is
	// nil: 0 == DISABLED (no decay; today's behavior) (D25).
	defaultStalenessWindow time.Duration = 0
)

// adaptiveRotationOf returns the AMTD's AdaptiveRotationPolicy or nil.
func adaptiveRotationOf(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) *amtdv1beta1.AdaptiveRotationPolicy {
	if amtd != nil && amtd.Spec.InferenceRotation != nil {
		return amtd.Spec.InferenceRotation.AdaptiveRotation
	}
	return nil
}

// effectivePanicThreshold returns the configured PanicThreshold (parsed from its
// decimal string) or the 0.85 default. A malformed/out-of-range value falls back
// to the default (fail-safe: a bad threshold never silently disables panic).
func effectivePanicThreshold(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) float64 {
	if ar := adaptiveRotationOf(amtd); ar != nil && ar.PanicThreshold != nil {
		if v, ok := parseScore(*ar.PanicThreshold); ok {
			return v
		}
	}
	return defaultPanicThreshold
}

// effectiveEWMAAlpha returns the configured EWMAAlpha (parsed) or 0.3. A value
// outside (0,1] falls back to the default.
func effectiveEWMAAlpha(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) float64 {
	if ar := adaptiveRotationOf(amtd); ar != nil && ar.EWMAAlpha != nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(*ar.EWMAAlpha), 64); err == nil && v > 0 && v <= 1 {
			return v
		}
	}
	return defaultEWMAAlpha
}

// effectiveConsecutiveHighSamples returns the configured N or 3. A non-positive
// value falls back to the default (a 0/negative N would make a single sample
// "panic", defeating the anti-flap purpose).
func effectiveConsecutiveHighSamples(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) int {
	if ar := adaptiveRotationOf(amtd); ar != nil && ar.ConsecutiveHighSamples != nil && *ar.ConsecutiveHighSamples > 0 {
		return *ar.ConsecutiveHighSamples
	}
	return defaultConsecutiveHighSamples
}

// effectiveStalenessWindow returns the configured StalenessWindow or 0
// (disabled). A non-positive configured value is treated as disabled.
func effectiveStalenessWindow(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) time.Duration {
	if ar := adaptiveRotationOf(amtd); ar != nil && ar.StalenessWindow != nil && ar.StalenessWindow.Duration > 0 {
		return ar.StalenessWindow.Duration
	}
	return defaultStalenessWindow
}

// schedulerPolicyFor projects the AMTD's effective cadence policy into the
// api-free scheduler.Policy (defaults + 5m floor already applied). It returns the
// projected policy and whether the BaseInterval was floored (so the caller can
// record the condition once).
func schedulerPolicyFor(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) (scheduler.Policy, bool) {
	base, floored := effectiveBaseInterval(amtd)
	return scheduler.Policy{
		BaseInterval:     base,
		JitterMinPercent: effectiveJitterMinPercent(amtd),
		JitterMaxPercent: effectiveJitterMaxPercent(amtd),
		Distribution:     effectiveJitterDistribution(amtd),
		Stagger:          effectiveStaggerMode(amtd),
	}, floored
}

// randSourceFor returns the scheduler.RandSource for the AMTD's EntropySource:
// crypto/rand for Crypto (the default), or a seeded math/rand source (derived
// deterministically from the persisted seed) for PseudoRandom. PseudoRandom is a
// test/opt-in lower-assurance source; it is the caller's responsibility to surface
// the EntropyWarning condition (see recordEntropyWarning) on a live AMTD.
func randSourceFor(amtd *amtdv1beta1.AdaptiveMovingTargetDefense, seed []byte) scheduler.RandSource {
	if effectiveEntropySource(amtd) == amtdv1beta1.EntropySourcePseudoRandom {
		return scheduler.NewSeededRand(scheduler.SeedToInt63(seed))
	}
	return scheduler.NewCryptoRand()
}

// ----------------------------------------------------------------------------
// Persisted jitter SEED Secret (D5, arch L228).
// ----------------------------------------------------------------------------

// jitterSeedSecretName is the per-AMTD seed Secret name.
func jitterSeedSecretName(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) string {
	return "amtd-jitter-seed-" + amtd.Name
}

// jitterSeedSecretKey is the data key inside the seed Secret.
const jitterSeedSecretKey = "seed"

// jitterSeed loads the per-AMTD jitter seed from its dedicated RBAC-gated Secret,
// CREATING it (with 32 crypto/rand bytes + an ownerRef to the AMTD) on first miss
// (D5). The seed is the restart-reproducibility root: re-seeding from this Secret
// after an operator restart reproduces the same PerPodPhaseOffset phase, so a
// restart adds <= 1 extra rotation. It is deliberately a Secret and NOT a
// Status/CR field because a CR Status is world-readable to anyone with `get` on
// the AMTD, which would re-expose the secret cadence (mirrors the score-trust-root
// principle). On any error it returns a best-effort fallback seed derived from the
// stable AMTD UID so cadence still proceeds (never blocks a rotation on Secret I/O).
func (r *SecurityEventReconciler) jitterSeed(ctx context.Context, amtd *amtdv1beta1.AdaptiveMovingTargetDefense, log logr.Logger) []byte {
	name := jitterSeedSecretName(amtd)
	sec := &corev1.Secret{}
	err := r.Client.Get(ctx, types.NamespacedName{Namespace: amtd.Namespace, Name: name}, sec)
	if err == nil {
		if v, ok := sec.Data[jitterSeedSecretKey]; ok && len(v) > 0 {
			return v
		}
		// Secret exists but is missing/empty key: fall back deterministically.
		log.Info("jitter seed Secret present but missing key; using UID-derived fallback", "secret", name)
		return uidFallbackSeed(amtd)
	}
	if !errors.IsNotFound(err) {
		log.Error(err, "failed to read jitter seed Secret; using UID-derived fallback", "secret", name)
		return uidFallbackSeed(amtd)
	}

	// First miss: mint a fresh crypto seed and persist it (RBAC-gated Secret).
	seed, gerr := scheduler.RandBytes(jitterSeedBytes)
	if gerr != nil {
		log.Error(gerr, "failed to generate jitter seed; using UID-derived fallback", "secret", name)
		return uidFallbackSeed(amtd)
	}
	newSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: amtd.Namespace,
			Name:      name,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{jitterSeedSecretKey: seed},
	}
	// Owner the Secret to the AMTD so it is garbage-collected with the policy.
	if err := ctrl.SetControllerReference(amtd, newSec, r.Scheme); err != nil {
		log.Error(err, "failed to set AMTD owner on jitter seed Secret (continuing)", "secret", name)
	}
	if err := r.Client.Create(ctx, newSec); err != nil {
		if errors.IsAlreadyExists(err) {
			// Race: someone created it; re-read.
			if rerr := r.Client.Get(ctx, types.NamespacedName{Namespace: amtd.Namespace, Name: name}, sec); rerr == nil {
				if v, ok := sec.Data[jitterSeedSecretKey]; ok && len(v) > 0 {
					return v
				}
			}
		}
		log.Error(err, "failed to create jitter seed Secret; using the generated seed in-memory this cycle", "secret", name)
		// Use the freshly-generated seed for THIS cycle even if persistence failed.
		return seed
	}
	log.Info("created persisted jitter seed Secret (RBAC-gated; not published in Status)", "secret", name)
	return seed
}

// uidFallbackSeed derives a stable seed from the AMTD UID (a last-resort seed when
// the Secret cannot be read/created). It is stable across restarts (UID is durable)
// so the PerPodPhaseOffset phase is still restart-reproducible, but it is NOT
// secret — hence only a fallback, never the primary.
func uidFallbackSeed(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) []byte {
	return []byte("amtd-uid:" + string(amtd.UID) + ":" + amtd.Namespace + "/" + amtd.Name)
}

// ----------------------------------------------------------------------------
// MaxConcurrentRotations enforcement support (D24, the Phase-2 half of cap#4).
// ----------------------------------------------------------------------------

// countInFlightRotations counts pods under the AMTD's PodSelector (in the AMTD's
// namespace) that currently carry the Phase-1 in-progress rotation annotation
// (rotation.r6security.com/in-progress == "true"). This is the number of OTHER
// rotations in flight for this AMTD; the candidate pod is not yet stamped at G6
// time (its lock is set later in executeRotate), so the cap means "others in
// flight" — the correct reading of "max concurrent" with this pod as the
// candidate. On a list error it returns 0 (fail-open: never block a rotation on a
// transient list failure; the min-interval + in-progress guards still bound storms).
func countInFlightRotations(ctx context.Context, c client.Client, amtd *amtdv1beta1.AdaptiveMovingTargetDefense, log logr.Logger) int {
	if amtd == nil || len(amtd.Spec.PodSelector) == 0 {
		return 0
	}
	var pods corev1.PodList
	if err := c.List(ctx, &pods,
		client.InNamespace(amtd.Namespace),
		client.MatchingLabels(amtd.Spec.PodSelector),
	); err != nil {
		log.Error(err, "MaxConcurrentRotations: failed to list pods for in-flight count (fail-open: counting 0)", "AMTD", amtd.Name)
		return 0
	}
	n := 0
	for i := range pods.Items {
		if podHasRotationInProgress(&pods.Items[i]) {
			n++
		}
	}
	return n
}

// recordBaseIntervalFloored records the BaseIntervalFloored condition on the AMTD
// when the configured BaseInterval was clamped up to the 5m floor (D9). Best-effort.
func (r *SecurityEventReconciler) recordBaseIntervalFloored(ctx context.Context, amtd *amtdv1beta1.AdaptiveMovingTargetDefense, configured, floor time.Duration, log logr.Logger) {
	fresh := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	if err := r.Client.Get(ctx, namespacedNameOf(amtd), fresh); err != nil {
		log.Error(err, "failed to re-read AMTD to record BaseIntervalFloored", "AMTD", amtd.Name)
		return
	}
	cond := metav1.Condition{
		Type:               "BaseIntervalFloored",
		Status:             metav1.ConditionTrue,
		Reason:             "BelowFloor",
		Message:            fmt.Sprintf("configured baseInterval %s is below the %s floor; clamped up to %s", configured, floor, floor),
		ObservedGeneration: fresh.Generation,
	}
	if meta.SetStatusCondition(&fresh.Status.Conditions, cond) {
		if err := r.Client.Status().Update(ctx, fresh); err != nil {
			log.Error(err, "failed to write BaseIntervalFloored condition", "AMTD", amtd.Name)
		}
	}
}

// recordEntropyWarning records the EntropyWarning condition when a live AMTD opts
// into the PseudoRandom entropy source (D13) — a leaked PRNG seed makes every
// future rotation forecastable. Best-effort.
func (r *SecurityEventReconciler) recordEntropyWarning(ctx context.Context, amtd *amtdv1beta1.AdaptiveMovingTargetDefense, log logr.Logger) {
	fresh := &amtdv1beta1.AdaptiveMovingTargetDefense{}
	if err := r.Client.Get(ctx, namespacedNameOf(amtd), fresh); err != nil {
		log.Error(err, "failed to re-read AMTD to record EntropyWarning", "AMTD", amtd.Name)
		return
	}
	cond := metav1.Condition{
		Type:               "EntropyWarning",
		Status:             metav1.ConditionTrue,
		Reason:             "PseudoRandomEntropySource",
		Message:            "spec.inferenceRotation.rotationPolicy.entropySource=PseudoRandom: cadence uses a seeded (non-crypto) RNG; a leaked seed makes future rotations forecastable. Use Crypto (the default) in production.",
		ObservedGeneration: fresh.Generation,
	}
	if meta.SetStatusCondition(&fresh.Status.Conditions, cond) {
		if err := r.Client.Status().Update(ctx, fresh); err != nil {
			log.Error(err, "failed to write EntropyWarning condition", "AMTD", amtd.Name)
		}
	}
}
