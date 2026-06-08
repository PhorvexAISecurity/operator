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

package main

import (
	"fmt"
	"strconv"
	"strings"

	amtdapi "github.com/r6security/phoenix/api/v1beta1"
)

// canonical.go — Phase 7 emit-site NORMALIZATION + SCORE-CARRIER for the KubeArmor
// integrator (arch 1.3 invariant #11 / section 7 prereq #2-3).
//
// Normalization (the PRIMARY deliverable) maps KubeArmor's native numeric Severity
// (1..10) + PolicyName onto the SHARED canonical vocabulary. The score-carrier was
// originally flagged best-effort because this tree pinned the published phoenix
// (no AnomalyScore/Metrics field) and its old kustomize/cli-runtime set conflicted
// (gnostic vs gnostic-models) with a `replace`. Phase 7 RESOLVED that conflict by
// bumping kustomize api/kyaml -> v0.20.1 and k8s cli-runtime -> v0.34.0 (both
// gnostic-models-aware), so the `replace github.com/r6security/phoenix =>
// ../phoenix-extended` now builds cleanly and the canonical constants + the extended
// SecurityEventSpec (AnomalyScore/Metrics) ARE imported here. Score-carrier is
// therefore DELIVERED, not dependency-blocked.

// canonical ThreatLevel / Type values re-exported from the shared phoenix
// vocabulary (imported via the replace) so the rest of this package reads them by a
// short local name without re-deriving the strings.
const (
	threatLevelInfo     = amtdapi.ThreatLevelInfo
	threatLevelLow      = amtdapi.ThreatLevelLow
	threatLevelMedium   = amtdapi.ThreatLevelMedium
	threatLevelHigh     = amtdapi.ThreatLevelHigh
	threatLevelCritical = amtdapi.ThreatLevelCritical

	typePolicyViolation = amtdapi.TypePolicyViolation
)

// NormalizeSeverity maps KubeArmor's NUMERIC severity (1..10, emitted as a string)
// onto the canonical ThreatLevel.
//
// DESIGN-CHOICE BUCKETS (flagged: KubeArmor severity is a 1..10 scale with no
// official mapping to a 5-level vocabulary; these buckets are our choice):
//
//	9-10 -> critical
//	7-8  -> high
//	4-6  -> medium
//	1-3  -> low
//	(non-numeric / out-of-range) -> medium   (safe default; raw kept for audit)
//
// Note KubeArmor never emits "info"-class severities (its scale floors at 1), so
// "info" is reachable only via the canonical vocabulary, not from this mapping.
func NormalizeSeverity(raw string) (canonical string, recognized bool) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return threatLevelMedium, false
	}
	switch {
	case n >= 9 && n <= 10:
		return threatLevelCritical, true
	case n >= 7 && n <= 8:
		return threatLevelHigh, true
	case n >= 4 && n <= 6:
		return threatLevelMedium, true
	case n >= 1 && n <= 3:
		return threatLevelLow, true
	default:
		// out of the 1..10 range
		return threatLevelMedium, false
	}
}

// NormalizePolicyType maps a KubeArmor PolicyName onto the canonical Type. KubeArmor
// emits security-policy hits, so the canonical Type is always TypePolicyViolation;
// the raw PolicyName is preserved by the caller in Description + Metrics for audit.
func NormalizePolicyType(policyName string) string {
	return typePolicyViolation
}

// anomalyScoreForLevel is the severity-derived PROXY (documented; NOT a measured
// anomaly score — KubeArmor emits a discrete severity, not an anomaly score) used to
// populate the score-carrier so a scored rule (anomalyScore Gte X) can consume a
// KubeArmor event.
//
//	info 0.1 / low 0.3 / medium 0.5 / high 0.8 / critical 0.95
func anomalyScoreForLevel(level string) string {
	switch level {
	case threatLevelCritical:
		return "0.95"
	case threatLevelHigh:
		return "0.8"
	case threatLevelMedium:
		return "0.5"
	case threatLevelLow:
		return "0.3"
	default:
		return "0.1"
	}
}

// buildKubeArmorSpec assembles the normalized SecurityEventSpec from a KubeArmor
// policy event. PURE function (no client/gRPC dependency) so the normalization +
// score derivation is table-testable without a live KubeArmor relay.
func buildKubeArmorSpec(policyEvent KubeArmorPolicyEvent) amtdapi.SecurityEventSpec {
	level, _ := NormalizeSeverity(policyEvent.Severity)
	canonicalType := NormalizePolicyType(policyEvent.PolicyName)
	score := anomalyScoreForLevel(level)

	return amtdapi.SecurityEventSpec{
		Targets: []string{fmt.Sprintf("%s/%s", policyEvent.NamespaceName, policyEvent.PodName)},
		// keep the raw policy name + severity for AUDIT in the Description.
		Description: fmt.Sprintf("%s [kubearmor.policy=%q kubearmor.severity=%q]",
			policyEvent.Result, policyEvent.PolicyName, policyEvent.Severity),
		Rule: amtdapi.Rule{
			Type:        canonicalType,
			ThreatLevel: level,
			Source:      "KubeArmorIntegrator",
		},
		// SCORE-CARRIER: severity-derived PROXY (documented; not a measured anomaly).
		AnomalyScore: &score,
		// raw emitter signals retained for audit.
		Metrics: map[string]string{
			"kubearmor.policy":   policyEvent.PolicyName,
			"kubearmor.severity": policyEvent.Severity,
		},
	}
}
