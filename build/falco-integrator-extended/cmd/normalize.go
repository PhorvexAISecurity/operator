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
	"strings"

	amtdapi "github.com/r6security/phoenix/api/v1beta1"
)

// normalize.go — Phase 7 emit-site NORMALIZATION + SCORE-CARRIER for the Falco
// integrator (arch 1.3 invariant #11 / section 7 prereq #2-3). It maps Falco's
// native vocabulary (syslog Priority + the rule NAME) onto the SHARED canonical
// vocabulary defined in github.com/r6security/phoenix/api/v1beta1 (imported here via
// the `replace => ../phoenix-extended` directive in go.mod). The original rule name
// + priority are preserved in Description and Metrics for AUDIT; the contract
// (SecurityEvent shape) and Source ("FalcoIntegrator") are unchanged.

// NormalizePriority maps a Falco syslog Priority to the canonical ThreatLevel.
//
// DOCUMENTED MAPPING (Falco priority -> canonical ThreatLevel):
//
//	Emergency | Alert | Critical -> critical
//	Error                        -> high
//	Warning                      -> medium
//	Notice                       -> low
//	Informational | Debug        -> info
//	(unrecognized)               -> info   (safe floor; raw kept in Metrics)
//
// Comparison is case-insensitive and whitespace-trimmed (Falco emits "Critical").
func NormalizePriority(priority string) string {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case "emergency", "alert", "critical":
		return amtdapi.ThreatLevelCritical
	case "error":
		return amtdapi.ThreatLevelHigh
	case "warning":
		return amtdapi.ThreatLevelMedium
	case "notice":
		return amtdapi.ThreatLevelLow
	case "informational", "info", "debug":
		return amtdapi.ThreatLevelInfo
	default:
		return amtdapi.ThreatLevelInfo
	}
}

// NormalizeFalcoType maps a Falco rule NAME to the canonical Type.
//
// DOCUMENTED MAPPING (substring match on the rule name, case-insensitive):
//
//	contains "container drift"                              -> drift
//	contains runc | cve-2019-5736 | container breakout |
//	         "escape"                                       -> panic
//	(otherwise)                                             -> policy-violation
//
// The default for an unrecognized rule is TypePolicyViolation (a generic runtime
// violation); the RAW rule name is always retained in Metrics["falco.rule"] and the
// Description for audit, so normalization is never lossy.
func NormalizeFalcoType(ruleName string) string {
	r := strings.ToLower(strings.TrimSpace(ruleName))
	switch {
	case strings.Contains(r, "container drift"):
		return amtdapi.TypeDrift
	case strings.Contains(r, "runc"),
		strings.Contains(r, "cve-2019-5736"),
		strings.Contains(r, "container breakout"),
		strings.Contains(r, "escape"):
		return amtdapi.TypePanic
	default:
		return amtdapi.TypePolicyViolation
	}
}

// AnomalyScoreForLevel returns a SEVERITY-DERIVED PROXY anomaly score in [0,1] for a
// canonical ThreatLevel. It is NOT a measured anomaly score — a real anomaly score
// requires a scoring backend; this is a documented proxy so a scored rule
// (anomalyScore Gte X) has something deterministic to consume from a Falco event.
//
//	info 0.1 / low 0.3 / medium 0.5 / high 0.8 / critical 0.95
func AnomalyScoreForLevel(level string) string {
	switch level {
	case amtdapi.ThreatLevelCritical:
		return "0.95"
	case amtdapi.ThreatLevelHigh:
		return "0.8"
	case amtdapi.ThreatLevelMedium:
		return "0.5"
	case amtdapi.ThreatLevelLow:
		return "0.3"
	default: // info / unknown
		return "0.1"
	}
}

// buildFalcoSpec assembles the normalized SecurityEventSpec from a parsed Falco
// Response. It is a PURE function (no client/k8s dependency) so the normalization +
// score derivation is table-testable. The handler calls it and wraps the result in
// a SecurityEvent.
func buildFalcoSpec(response Response) amtdapi.SecurityEventSpec {
	level := NormalizePriority(response.Priority)
	canonicalType := NormalizeFalcoType(response.Rule)
	score := AnomalyScoreForLevel(level)

	// Keep the original rule name + priority for AUDIT in the Description, alongside
	// the Falco output text.
	desc := response.Output
	if response.Rule != "" {
		desc = fmt.Sprintf("%s [falco.rule=%q falco.priority=%q]", response.Output, response.Rule, response.Priority)
	}

	return amtdapi.SecurityEventSpec{
		Targets:     []string{fmt.Sprintf("%s/%s", response.OutputFields.Namespace, response.OutputFields.Pod)},
		Description: desc,
		Rule: amtdapi.Rule{
			Type:        canonicalType,
			ThreatLevel: level,
			Source:      "FalcoIntegrator",
		},
		// SCORE-CARRIER: severity-derived PROXY (documented; not a measured anomaly).
		AnomalyScore: &score,
		// Raw emitter signals retained for audit / in-operator recompute.
		Metrics: map[string]string{
			"falco.rule":     response.Rule,
			"falco.priority": response.Priority,
		},
	}
}
