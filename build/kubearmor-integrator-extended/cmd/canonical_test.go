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
	"strings"
	"testing"
)

// TestNormalizeSeverity pins the design-choice severity buckets (1..10 -> canonical
// ThreatLevel) and the non-numeric safe default.
func TestNormalizeSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"10", threatLevelCritical, true},
		{"9", threatLevelCritical, true},
		{"8", threatLevelHigh, true},
		{"7", threatLevelHigh, true},
		{"6", threatLevelMedium, true},
		{"5", threatLevelMedium, true},
		{"4", threatLevelMedium, true},
		{"3", threatLevelLow, true},
		{"2", threatLevelLow, true},
		{"1", threatLevelLow, true},
		{"0", threatLevelMedium, false},   // out of range
		{"11", threatLevelMedium, false},  // out of range
		{"high", threatLevelMedium, false}, // non-numeric safe default
		{"", threatLevelMedium, false},
	}
	for _, c := range cases {
		got, ok := NormalizeSeverity(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("NormalizeSeverity(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// TestNormalizePolicyType: KubeArmor policy hits always map to policy-violation.
func TestNormalizePolicyType(t *testing.T) {
	if got := NormalizePolicyType("ksp-block-shell"); got != typePolicyViolation {
		t.Errorf("NormalizePolicyType = %q, want policy-violation", got)
	}
	if got := NormalizePolicyType(""); got != typePolicyViolation {
		t.Errorf("NormalizePolicyType(empty) = %q, want policy-violation", got)
	}
}

// TestCanonicalStringsMirrorPhoenix guards the self-contained mirror against drift
// from the shared phoenix vocabulary (phoenix vocabulary.go / TestCanonicalConstants
// pins the same wire strings).
func TestCanonicalStringsMirrorPhoenix(t *testing.T) {
	want := map[string]string{
		"info":             threatLevelInfo,
		"low":              threatLevelLow,
		"medium":           threatLevelMedium,
		"high":             threatLevelHigh,
		"critical":         threatLevelCritical,
		"policy-violation": typePolicyViolation,
	}
	for w, got := range want {
		if got != w {
			t.Errorf("canonical mirror drift: const = %q, want %q", got, w)
		}
	}
}

// TestKubeArmorSeverity9_Conformance is the conformance row: a KubeArmor severity-9
// policy hit normalizes to {ThreatLevel:critical, Type:policy-violation} with the
// raw PolicyName preserved for audit AND the score-carrier populated.
func TestKubeArmorSeverity9_Conformance(t *testing.T) {
	ev := KubeArmorPolicyEvent{
		NamespaceName: "prod",
		PodName:       "db-0",
		Result:        "Permission denied",
		PolicyName:    "ksp-deny-cap-net-raw",
		Severity:      "9",
	}
	spec := buildKubeArmorSpec(ev)

	if spec.Rule.ThreatLevel != threatLevelCritical {
		t.Errorf("ThreatLevel = %q, want critical", spec.Rule.ThreatLevel)
	}
	if spec.Rule.Type != typePolicyViolation {
		t.Errorf("Type = %q, want policy-violation", spec.Rule.Type)
	}
	if spec.Rule.Source != "KubeArmorIntegrator" {
		t.Errorf("Source = %q, want KubeArmorIntegrator (unchanged)", spec.Rule.Source)
	}
	// score-carrier (no longer dependency-blocked).
	if spec.AnomalyScore == nil || *spec.AnomalyScore != "0.95" {
		t.Errorf("AnomalyScore = %v, want proxy 0.95 for critical", spec.AnomalyScore)
	}
	if spec.Metrics["kubearmor.policy"] != ev.PolicyName {
		t.Errorf("Metrics[kubearmor.policy] = %q, want raw policy %q (audit)", spec.Metrics["kubearmor.policy"], ev.PolicyName)
	}
	if spec.Metrics["kubearmor.severity"] != "9" {
		t.Errorf("Metrics[kubearmor.severity] = %q, want 9 (audit)", spec.Metrics["kubearmor.severity"])
	}
	// raw policy/severity also retained in Description for audit.
	if !strings.Contains(spec.Description, ev.PolicyName) {
		t.Errorf("Description missing raw policy name for audit: %q", spec.Description)
	}
}

// TestBuildKubeArmorSpec_MidLevels covers the medium/low buckets + their proxy
// scores.
func TestBuildKubeArmorSpec_MidLevels(t *testing.T) {
	if s := buildKubeArmorSpec(KubeArmorPolicyEvent{Severity: "5"}); s.Rule.ThreatLevel != threatLevelMedium || *s.AnomalyScore != "0.5" {
		t.Errorf("severity 5 -> {%q,%v}, want {medium,0.5}", s.Rule.ThreatLevel, *s.AnomalyScore)
	}
	if s := buildKubeArmorSpec(KubeArmorPolicyEvent{Severity: "2"}); s.Rule.ThreatLevel != threatLevelLow || *s.AnomalyScore != "0.3" {
		t.Errorf("severity 2 -> {%q,%v}, want {low,0.3}", s.Rule.ThreatLevel, *s.AnomalyScore)
	}
	if s := buildKubeArmorSpec(KubeArmorPolicyEvent{Severity: "garbage"}); s.Rule.ThreatLevel != threatLevelMedium {
		t.Errorf("non-numeric severity -> %q, want medium default", s.Rule.ThreatLevel)
	}
}
