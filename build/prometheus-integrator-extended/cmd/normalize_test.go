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
	"testing"

	amtdapi "github.com/r6security/phoenix/api/v1beta1"
)

func TestNormalizePromThreatLevel(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"critical", amtdapi.ThreatLevelCritical, true},
		{"HIGH", amtdapi.ThreatLevelHigh, true},
		{"warning", amtdapi.ThreatLevelMedium, true}, // alias
		{"page", amtdapi.ThreatLevelCritical, true},  // alias
		{"info", amtdapi.ThreatLevelInfo, true},
		{"bogus", amtdapi.ThreatLevelMedium, false}, // safe default
		{"", amtdapi.ThreatLevelMedium, false},
	}
	for _, c := range cases {
		got, ok := NormalizePromThreatLevel(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("NormalizePromThreatLevel(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestNormalizePromType(t *testing.T) {
	if got, ok := NormalizePromType("drift"); got != amtdapi.TypeDrift || !ok {
		t.Errorf("drift -> (%q,%v)", got, ok)
	}
	if got, ok := NormalizePromType("unknown-thing"); got != amtdapi.TypePolicyViolation || ok {
		t.Errorf("unknown -> (%q,%v), want (policy-violation,false)", got, ok)
	}
}

// TestBuildPrometheusSpec_CMPRow is the ContextMutationPolicy conformance row: an
// alert with a high_gpu_usage signal + canonical labels yields canonical
// Type/ThreatLevel, AnomalyScore from the alert label, and Metrics carrying the
// raw alert labels (the signals the CMP row consumes).
func TestBuildPrometheusSpec_CMPRow(t *testing.T) {
	alert := Alert{
		Labels: map[string]string{
			"type":           "drift",
			"threatlevel":    "critical",
			"anomaly_score":  "0.91",
			"high_gpu_usage": "true",
			"namespace":      "ml",
			"pod":            "inference-0",
		},
		Fingerprint: "abc123",
	}
	spec := buildPrometheusSpec(alert)

	if spec.Rule.Type != amtdapi.TypeDrift {
		t.Errorf("Type = %q, want drift", spec.Rule.Type)
	}
	if spec.Rule.ThreatLevel != amtdapi.ThreatLevelCritical {
		t.Errorf("ThreatLevel = %q, want critical", spec.Rule.ThreatLevel)
	}
	if spec.Rule.Source != "PrometheusIntegrator" {
		t.Errorf("Source = %q, want PrometheusIntegrator (unchanged)", spec.Rule.Source)
	}
	if spec.AnomalyScore == nil || *spec.AnomalyScore != "0.91" {
		t.Errorf("AnomalyScore = %v, want 0.91 from alert label", spec.AnomalyScore)
	}
	if spec.Metrics["high_gpu_usage"] != "true" {
		t.Errorf("Metrics[high_gpu_usage] = %q, want true (CMP signal)", spec.Metrics["high_gpu_usage"])
	}
	if spec.Metrics["anomaly_score.source"] != "alert" {
		t.Errorf("Metrics[anomaly_score.source] = %q, want alert", spec.Metrics["anomaly_score.source"])
	}
}

// TestBuildPrometheusSpec_UnknownLevelSafeDefault proves an unrecognized threatlevel
// falls back to a safe default AND keeps the raw value in Metrics for audit, and the
// score falls back to the severity-derived proxy.
func TestBuildPrometheusSpec_UnknownLevelSafeDefault(t *testing.T) {
	alert := Alert{
		Labels: map[string]string{
			"type":        "weird-type",
			"threatlevel": "super-bad",
			"namespace":   "ns",
			"pod":         "p",
		},
	}
	spec := buildPrometheusSpec(alert)

	if spec.Rule.ThreatLevel != amtdapi.ThreatLevelMedium {
		t.Errorf("ThreatLevel = %q, want medium (safe default)", spec.Rule.ThreatLevel)
	}
	if spec.Metrics["prometheus.threatlevel.raw"] != "super-bad" {
		t.Errorf("raw threatlevel not kept: %q", spec.Metrics["prometheus.threatlevel.raw"])
	}
	if spec.Rule.Type != amtdapi.TypePolicyViolation {
		t.Errorf("Type = %q, want policy-violation default", spec.Rule.Type)
	}
	if spec.Metrics["prometheus.type.raw"] != "weird-type" {
		t.Errorf("raw type not kept: %q", spec.Metrics["prometheus.type.raw"])
	}
	// proxy score for medium
	if spec.AnomalyScore == nil || *spec.AnomalyScore != "0.5" {
		t.Errorf("AnomalyScore = %v, want proxy 0.5 for medium", spec.AnomalyScore)
	}
	if spec.Metrics["anomaly_score.source"] != "severity-proxy" {
		t.Errorf("anomaly_score.source = %q, want severity-proxy", spec.Metrics["anomaly_score.source"])
	}
}
