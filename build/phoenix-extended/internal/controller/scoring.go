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

// Package controller — Phase 3 pluggable AnomalyScorer (cap#5, arch §2.3/§2.4,
// D20). The scoring BRAIN is deferred (ADA §6.3.3): the default scorer invents NO
// math. It consumes the score the trusted integrator already wrote on
// SecurityEvent.Spec.AnomalyScore (D19/D26g). The opt-in WeightedScorer computes
// a weighted sum over Spec.Metrics from an operator-supplied ScoringPolicy, but
// it is INERT unless ScoringPolicy is set with a non-empty Weights map — there
// are NO default weights (the illustrative {0.5,0.3,0.2} never ships).
package controller

import (
	"strconv"
	"strings"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// trustedScoreSources is the D26g provenance allowlist: AnomalyScore is honored
// only when the event's Rule.Source is one of these trusted integrators. The
// PRIMARY gate is RBAC (a stock workload ServiceAccount has no securityevents
// create grant, so it cannot mint a SecurityEvent about itself); this allowlist
// is defense-in-depth, the same posture as the documented optional :9443
// provenance webhook. It is a const slice now (a configurable CRD field is
// deferred); a non-trusted Source has its score IGNORED.
var trustedScoreSources = map[string]struct{}{
	"PrometheusIntegrator": {},
	"FalcoIntegrator":      {},
	"KubeArmorIntegrator":  {},
}

// isTrustedScoreSource reports whether the event's Source is on the D26g
// allowlist. An empty Source is NOT trusted (fail-safe).
func isTrustedScoreSource(ev *amtdv1beta1.SecurityEvent) bool {
	if ev == nil {
		return false
	}
	_, ok := trustedScoreSources[ev.Spec.Rule.Source]
	return ok
}

// AnomalyScorer is the pluggable scoring interface (D20). Score returns the
// decimal-string score in [0,1] for an event and whether it produced a score at
// all (false => unscored; the caller treats it exactly like a nil AnomalyScore).
// Implementations MUST NOT mutate the event.
type AnomalyScorer interface {
	Score(ev *amtdv1beta1.SecurityEvent, policy *amtdv1beta1.ScoringPolicy) (string, bool)
}

// PassthroughScorer is the DEFAULT scorer (D20): it consumes the score the
// trusted integrator already wrote on Spec.AnomalyScore, inventing NO math. nil
// AnomalyScore => unscored.
type PassthroughScorer struct{}

func (PassthroughScorer) Score(ev *amtdv1beta1.SecurityEvent, _ *amtdv1beta1.ScoringPolicy) (string, bool) {
	if ev == nil || ev.Spec.AnomalyScore == nil {
		return "", false
	}
	// Validate it parses into [0,1]; a malformed score is treated as unscored
	// (fail-safe: never panic on a garbage score), and is re-emitted clamped so
	// downstream EWMA/threshold math is always well-formed.
	v, ok := parseScore(*ev.Spec.AnomalyScore)
	if !ok {
		return "", false
	}
	return formatScore(v), true
}

// WeightedScorer is the OPT-IN scorer (D20): a weighted sum over Spec.Metrics
// using ScoringPolicy.Weights, normalized/clamped into [0,1]. It is INERT unless
// ScoringPolicy carries a non-empty Weights map — there are NO default weights.
// A metrics key referenced by Weights but absent on the event contributes 0
// (it does not abort the computation). If NO referenced key is present, the
// scorer returns unscored (it had nothing to score).
type WeightedScorer struct{}

func (WeightedScorer) Score(ev *amtdv1beta1.SecurityEvent, policy *amtdv1beta1.ScoringPolicy) (string, bool) {
	if ev == nil || policy == nil || len(policy.Weights) == 0 {
		return "", false // inert: no default weights.
	}
	var sum, totalWeight float64
	anyPresent := false
	for key, wStr := range policy.Weights {
		w, err := strconv.ParseFloat(strings.TrimSpace(wStr), 64)
		if err != nil {
			continue // a malformed weight is skipped (fail-safe).
		}
		totalWeight += w
		mv, ok := ev.Spec.Metrics[key]
		if !ok {
			continue // absent metric contributes 0.
		}
		m, err := strconv.ParseFloat(strings.TrimSpace(mv), 64)
		if err != nil {
			continue
		}
		anyPresent = true
		sum += w * m
	}
	if !anyPresent || totalWeight <= 0 {
		return "", false
	}

	var score float64
	switch policy.Normalization {
	case "minmax":
		// Weighted average normalized by total weight (assumes per-metric values in
		// [0,1]); then clamped. This keeps the output in [0,1] without inventing
		// per-metric min/max (none are supplied), so it degrades to the weighted mean.
		score = sum / totalWeight
	case "zscore":
		// No distribution parameters are supplied on the policy, so a true z-score is
		// not computable; honestly degrade to the clamped weighted mean rather than
		// invent a mean/stddev. (A real z-score impl is future AnomalyScorer work.)
		score = sum / totalWeight
	default: // "clamp" or empty: clamp the raw weighted sum into [0,1].
		score = sum
	}
	return formatScore(clamp01(score)), true
}

// scorerFor selects the scorer for an AMTD: the opt-in WeightedScorer iff a
// ScoringPolicy is set, else the default PassthroughScorer (D20). The chosen
// scorer's policy argument is returned alongside so the caller passes it straight
// through.
func scorerFor(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) (AnomalyScorer, *amtdv1beta1.ScoringPolicy) {
	if ar := adaptiveRotationOf(amtd); ar != nil && ar.ScoringPolicy != nil {
		return WeightedScorer{}, ar.ScoringPolicy
	}
	return PassthroughScorer{}, nil
}

// ----------------------------------------------------------------------------
// Shared score parse/format/clamp helpers (decimal-string [0,1] representation,
// D19). formatScore uses %.6g so the EWMA chain does not accrete float noise and
// the Status string stays compact and stable across round-trips.
// ----------------------------------------------------------------------------

// parseScore parses a decimal-string score and reports whether it is a valid
// number in [0,1]. Out-of-range or malformed => (0, false).
func parseScore(s string) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, false
	}
	if v < 0 || v > 1 {
		return 0, false
	}
	return v, true
}

// formatScore renders a float as the canonical compact decimal string.
func formatScore(v float64) string {
	return strconv.FormatFloat(v, 'g', 6, 64)
}

// clamp01 clamps a float into [0,1].
func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
