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
	"testing"

	amtdapi "github.com/r6security/phoenix/api/v1beta1"
)

func TestNormalizePriority(t *testing.T) {
	cases := map[string]string{
		"Emergency":     amtdapi.ThreatLevelCritical,
		"Alert":         amtdapi.ThreatLevelCritical,
		"Critical":      amtdapi.ThreatLevelCritical,
		"Error":         amtdapi.ThreatLevelHigh,
		"Warning":       amtdapi.ThreatLevelMedium,
		"Notice":        amtdapi.ThreatLevelLow,
		"Informational": amtdapi.ThreatLevelInfo,
		"Debug":         amtdapi.ThreatLevelInfo,
		"CRITICAL":      amtdapi.ThreatLevelCritical, // case-insensitive
		"weird":         amtdapi.ThreatLevelInfo,     // safe default
	}
	for in, want := range cases {
		if got := NormalizePriority(in); got != want {
			t.Errorf("NormalizePriority(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeFalcoType(t *testing.T) {
	cases := map[string]string{
		"Container Drift Detected (open+create)":           amtdapi.TypeDrift,
		"Drift detected: container drift":                  amtdapi.TypeDrift,
		"Launch Privileged Container via runc":             amtdapi.TypePanic,
		"CVE-2019-5736 exploit attempt":                    amtdapi.TypePanic,
		"Container Breakout via overlayfs":                 amtdapi.TypePanic,
		"Possible container escape detected":               amtdapi.TypePanic,
		"Write below etc":                                  amtdapi.TypePolicyViolation,
		"Terminal shell in container":                      amtdapi.TypePolicyViolation,
	}
	for in, want := range cases {
		if got := NormalizeFalcoType(in); got != want {
			t.Errorf("NormalizeFalcoType(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBuildFalcoSpec_CriticalContainerDrift is the conformance row: a Falco
// Critical "Container Drift" alert must normalize to {Type:drift,
// ThreatLevel:critical, AnomalyScore set}, with the raw rule kept for audit.
func TestBuildFalcoSpec_CriticalContainerDrift(t *testing.T) {
	resp := Response{
		Priority: "Critical",
		Rule:     "Container Drift Detected (open+create)",
		Output:   "Drift detected on pod web-1",
		OutputFields: ResponseOutputFields{
			Namespace: "prod",
			Pod:       "web-1",
		},
	}
	spec := buildFalcoSpec(resp)

	if spec.Rule.Type != amtdapi.TypeDrift {
		t.Errorf("Type = %q, want %q", spec.Rule.Type, amtdapi.TypeDrift)
	}
	if spec.Rule.ThreatLevel != amtdapi.ThreatLevelCritical {
		t.Errorf("ThreatLevel = %q, want %q", spec.Rule.ThreatLevel, amtdapi.ThreatLevelCritical)
	}
	if spec.Rule.Source != "FalcoIntegrator" {
		t.Errorf("Source = %q, want FalcoIntegrator (unchanged)", spec.Rule.Source)
	}
	if spec.AnomalyScore == nil || *spec.AnomalyScore != "0.95" {
		t.Errorf("AnomalyScore = %v, want proxy 0.95 for critical", spec.AnomalyScore)
	}
	if spec.Metrics["falco.rule"] != resp.Rule {
		t.Errorf("Metrics[falco.rule] = %q, want raw rule %q (audit)", spec.Metrics["falco.rule"], resp.Rule)
	}
	if spec.Metrics["falco.priority"] != "Critical" {
		t.Errorf("Metrics[falco.priority] = %q, want Critical (audit)", spec.Metrics["falco.priority"])
	}
	if len(spec.Targets) != 1 || spec.Targets[0] != "prod/web-1" {
		t.Errorf("Targets = %v, want [prod/web-1]", spec.Targets)
	}
}

func TestBuildFalcoSpec_WarningGeneric(t *testing.T) {
	spec := buildFalcoSpec(Response{Priority: "Warning", Rule: "Write below etc"})
	if spec.Rule.ThreatLevel != amtdapi.ThreatLevelMedium {
		t.Errorf("ThreatLevel = %q, want medium", spec.Rule.ThreatLevel)
	}
	if spec.Rule.Type != amtdapi.TypePolicyViolation {
		t.Errorf("Type = %q, want policy-violation (default)", spec.Rule.Type)
	}
	if spec.AnomalyScore == nil || *spec.AnomalyScore != "0.5" {
		t.Errorf("AnomalyScore = %v, want proxy 0.5 for medium", spec.AnomalyScore)
	}
}

func TestBuildFalcoSpec_RuncEscapePanic(t *testing.T) {
	spec := buildFalcoSpec(Response{Priority: "Error", Rule: "Launch Privileged Container via runc"})
	if spec.Rule.Type != amtdapi.TypePanic {
		t.Errorf("Type = %q, want panic", spec.Rule.Type)
	}
	if spec.Rule.ThreatLevel != amtdapi.ThreatLevelHigh {
		t.Errorf("ThreatLevel = %q, want high", spec.Rule.ThreatLevel)
	}
	if spec.AnomalyScore == nil || *spec.AnomalyScore != "0.8" {
		t.Errorf("AnomalyScore = %v, want proxy 0.8 for high", spec.AnomalyScore)
	}
}
