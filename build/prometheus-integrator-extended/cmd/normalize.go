/*
 * Copyright (C) 2024 R6 Security, Inc.
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

// normalize.go — Phase 7 emit-site NORMALIZATION + SCORE-CARRIER for the Prometheus
// integrator (arch 1.3 invariant #11 / section 7 prereq #2-3). It maps the
// Alertmanager alert's native labels (Labels["type"], Labels["threatlevel"]) onto
// the SHARED canonical vocabulary (github.com/r6security/phoenix/api/v1beta1,
// imported via the `replace => ../phoenix-extended` directive). Raw values + the
// alert labels (the high_gpu_usage-style signals the ContextMutationPolicy row
// consumes) are carried in Metrics; AnomalyScore is taken from an alert
// label/annotation if present, else a documented severity-derived proxy. Contract +
// Source ("PrometheusIntegrator") unchanged.

// NormalizePromThreatLevel maps Labels["threatlevel"] onto the canonical
// ThreatLevel. Already-canonical values (info/low/medium/high/critical, any case)
// pass straight through (via ThreatLevelRank). A couple of common Prometheus
// aliases are accepted. An unrecognized value falls back to a SAFE DEFAULT
// (medium) and the raw value is retained in Metrics["prometheus.threatlevel.raw"].
func NormalizePromThreatLevel(raw string) (canonical string, recognized bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	// canonical pass-through.
	if amtdapi.ThreatLevelRank(v) >= 0 {
		return v, true
	}
	// common Prometheus / Alertmanager aliases.
	switch v {
	case "warning", "warn":
		return amtdapi.ThreatLevelMedium, true
	case "page", "emergency", "fatal":
		return amtdapi.ThreatLevelCritical, true
	case "error", "err":
		return amtdapi.ThreatLevelHigh, true
	case "none", "informational":
		return amtdapi.ThreatLevelInfo, true
	}
	// SAFE DEFAULT: medium (a non-trivial but non-maximal floor); raw kept for audit.
	return amtdapi.ThreatLevelMedium, false
}

// NormalizePromType maps Labels["type"] onto the canonical Type. Already-canonical
// values pass through; an unrecognized value defaults to TypePolicyViolation and the
// raw value is retained in Metrics["prometheus.type.raw"].
func NormalizePromType(raw string) (canonical string, recognized bool) {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case amtdapi.TypeDrift, amtdapi.TypePanic, amtdapi.TypePolicyViolation,
		amtdapi.TypeTimed, amtdapi.TypeDisable:
		return v, true
	}
	return amtdapi.TypePolicyViolation, false
}

// anomalyScoreForLevel is the severity-derived PROXY (documented; not a measured
// anomaly score) used when an alert carries no explicit anomaly_score.
func anomalyScoreForLevel(level string) string {
	switch level {
	case amtdapi.ThreatLevelCritical:
		return "0.95"
	case amtdapi.ThreatLevelHigh:
		return "0.8"
	case amtdapi.ThreatLevelMedium:
		return "0.5"
	case amtdapi.ThreatLevelLow:
		return "0.3"
	default:
		return "0.1"
	}
}

// ScoreFromAlert derives the AnomalyScore for an alert. PREFERENCE ORDER:
//  1. Labels["anomaly_score"] if it parses as a float in [0,1] (a real upstream
//     score — Prometheus is a metrics source, so this is the one integrator that can
//     carry a measured-ish value).
//  2. Annotations["anomaly_score"] likewise.
//  3. otherwise the documented severity-derived PROXY from the normalized level.
//
// The second return reports whether the value came from the alert (true) vs the
// proxy (false), so the caller can label provenance in Metrics.
func ScoreFromAlert(alert Alert, normalizedLevel string) (score string, fromAlert bool) {
	for _, raw := range []string{alert.Labels["anomaly_score"], alert.Annotations["anomaly_score"]} {
		if raw == "" {
			continue
		}
		if f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64); err == nil && f >= 0 && f <= 1 {
			return strings.TrimSpace(raw), true
		}
	}
	return anomalyScoreForLevel(normalizedLevel), false
}

// buildPrometheusSpec assembles the normalized SecurityEventSpec from a single
// Alertmanager Alert. PURE function (no client dependency) so normalization + score
// derivation is table-testable.
func buildPrometheusSpec(alert Alert) amtdapi.SecurityEventSpec {
	canonicalType, typeOK := NormalizePromType(alert.Labels["type"])
	level, levelOK := NormalizePromThreatLevel(alert.Labels["threatlevel"])
	score, scoreFromAlert := ScoreFromAlert(alert, level)

	// Metrics: carry ALL alert labels (the high_gpu_usage-style signals the CMP row
	// consumes) plus raw-vocabulary audit entries + score provenance.
	metrics := map[string]string{}
	for k, v := range alert.Labels {
		metrics[k] = v
	}
	if !typeOK {
		metrics["prometheus.type.raw"] = alert.Labels["type"]
	}
	if !levelOK {
		metrics["prometheus.threatlevel.raw"] = alert.Labels["threatlevel"]
	}
	if scoreFromAlert {
		metrics["anomaly_score.source"] = "alert"
	} else {
		metrics["anomaly_score.source"] = "severity-proxy"
	}

	desc := alert.Fingerprint
	if alert.Labels["type"] != "" || alert.Labels["threatlevel"] != "" {
		desc = fmt.Sprintf("%s [prometheus.type=%q prometheus.threatlevel=%q]",
			alert.Fingerprint, alert.Labels["type"], alert.Labels["threatlevel"])
	}

	return amtdapi.SecurityEventSpec{
		Targets:     []string{fmt.Sprintf("%s/%s", alert.Labels["namespace"], alert.Labels["pod"])},
		Description: desc,
		Rule: amtdapi.Rule{
			Type:        canonicalType,
			ThreatLevel: level,
			Source:      "PrometheusIntegrator",
		},
		AnomalyScore: &score,
		Metrics:      metrics,
	}
}
