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

package v1beta1

import "testing"

// TestThreatLevelRank pins the canonical ordering info<low<medium<high<critical,
// case-insensitivity / whitespace-trimming, and the unknown=-1 fail-safe.
func TestThreatLevelRank(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{ThreatLevelInfo, 0},
		{ThreatLevelLow, 1},
		{ThreatLevelMedium, 2},
		{ThreatLevelHigh, 3},
		{ThreatLevelCritical, 4},
		// case-insensitive + whitespace-trimmed
		{"INFO", 0},
		{"High", 3},
		{"  critical  ", 4},
		{"Medium", 2},
		// unknown -> -1 (fail-safe)
		{"", -1},
		{"warning", -1},
		{"emergency", -1},
		{"5", -1},
	}
	for _, c := range cases {
		if got := ThreatLevelRank(c.in); got != c.want {
			t.Errorf("ThreatLevelRank(%q) = %d, want %d", c.in, got, c.want)
		}
	}

	// strict ordering must hold across the canonical set.
	order := []string{ThreatLevelInfo, ThreatLevelLow, ThreatLevelMedium, ThreatLevelHigh, ThreatLevelCritical}
	for i := 1; i < len(order); i++ {
		if !(ThreatLevelRank(order[i-1]) < ThreatLevelRank(order[i])) {
			t.Errorf("ordering broken: rank(%s) !< rank(%s)", order[i-1], order[i])
		}
	}
}

// TestCanonicalConstants documents the exact wire strings the integrators mirror.
// kubearmor-integrator defines these self-contained; this guards against drift.
func TestCanonicalConstants(t *testing.T) {
	want := map[string]string{
		"ThreatLevelInfo":     "info",
		"ThreatLevelLow":      "low",
		"ThreatLevelMedium":   "medium",
		"ThreatLevelHigh":     "high",
		"ThreatLevelCritical": "critical",
		"TypeDrift":           "drift",
		"TypePanic":           "panic",
		"TypePolicyViolation": "policy-violation",
		"TypeTimed":           "timed",
		"TypeDisable":         "disable",
	}
	got := map[string]string{
		"ThreatLevelInfo":     ThreatLevelInfo,
		"ThreatLevelLow":      ThreatLevelLow,
		"ThreatLevelMedium":   ThreatLevelMedium,
		"ThreatLevelHigh":     ThreatLevelHigh,
		"ThreatLevelCritical": ThreatLevelCritical,
		"TypeDrift":           TypeDrift,
		"TypePanic":           TypePanic,
		"TypePolicyViolation": TypePolicyViolation,
		"TypeTimed":           TypeTimed,
		"TypeDisable":         TypeDisable,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("canonical constant %s = %q, want %q", k, got[k], v)
		}
	}
}

// TestMatchStrategy_RankAwareThreatLevel proves the Phase 7 rank-aware matcher:
// Gte/Gt/Lte/Lt on field "threatLevel" compare by ThreatLevelRank (a severity
// FLOOR rule), while In/NotIn/Eq stay canonical-string comparisons and the exact
// fast path is unaffected.
func TestMatchStrategy_RankAwareThreatLevel(t *testing.T) {
	ev := func(level string) SecurityEventSpec {
		return SecurityEventSpec{Rule: Rule{Source: "KubeArmorIntegrator", ThreatLevel: level}}
	}
	gteHigh := Rule{Source: "KubeArmorIntegrator", Match: []MatchExpression{
		{Field: "threatLevel", Op: "Gte", Value: ThreatLevelHigh},
	}}

	t.Run("Gte high matches high and critical, not medium/low", func(t *testing.T) {
		if !MatchStrategy(gteHigh, ev(ThreatLevelHigh)) {
			t.Error("threatLevel Gte high should match high")
		}
		if !MatchStrategy(gteHigh, ev(ThreatLevelCritical)) {
			t.Error("threatLevel Gte high should match critical (rank 4 >= 3)")
		}
		if MatchStrategy(gteHigh, ev(ThreatLevelMedium)) {
			t.Error("threatLevel Gte high should NOT match medium")
		}
		if MatchStrategy(gteHigh, ev(ThreatLevelLow)) {
			t.Error("threatLevel Gte high should NOT match low")
		}
		if MatchStrategy(gteHigh, ev(ThreatLevelInfo)) {
			t.Error("threatLevel Gte high should NOT match info")
		}
	})

	t.Run("Gte high case-insensitive", func(t *testing.T) {
		if !MatchStrategy(gteHigh, ev("CRITICAL")) {
			t.Error("threatLevel Gte high should match CRITICAL case-insensitively")
		}
	})

	t.Run("Gt high matches only critical", func(t *testing.T) {
		gtHigh := Rule{Source: "KubeArmorIntegrator", Match: []MatchExpression{
			{Field: "threatLevel", Op: "Gt", Value: ThreatLevelHigh},
		}}
		if MatchStrategy(gtHigh, ev(ThreatLevelHigh)) {
			t.Error("threatLevel Gt high should NOT match high")
		}
		if !MatchStrategy(gtHigh, ev(ThreatLevelCritical)) {
			t.Error("threatLevel Gt high should match critical")
		}
	})

	t.Run("Lte medium matches info/low/medium not high", func(t *testing.T) {
		lteMed := Rule{Source: "KubeArmorIntegrator", Match: []MatchExpression{
			{Field: "threatLevel", Op: "Lte", Value: ThreatLevelMedium},
		}}
		for _, lvl := range []string{ThreatLevelInfo, ThreatLevelLow, ThreatLevelMedium} {
			if !MatchStrategy(lteMed, ev(lvl)) {
				t.Errorf("threatLevel Lte medium should match %s", lvl)
			}
		}
		if MatchStrategy(lteMed, ev(ThreatLevelHigh)) {
			t.Error("threatLevel Lte medium should NOT match high")
		}
	})

	t.Run("unknown level on either side is fail-safe false", func(t *testing.T) {
		// non-canonical event level
		if MatchStrategy(gteHigh, ev("warning")) {
			t.Error("unknown event threatLevel must not satisfy a rank floor")
		}
		// empty event level (present=false)
		if MatchStrategy(gteHigh, ev("")) {
			t.Error("empty event threatLevel must not satisfy a rank floor")
		}
		// non-canonical rule value
		badRule := Rule{Source: "KubeArmorIntegrator", Match: []MatchExpression{
			{Field: "threatLevel", Op: "Gte", Value: "emergency"},
		}}
		if MatchStrategy(badRule, ev(ThreatLevelCritical)) {
			t.Error("non-canonical rule threatLevel value must be fail-safe false")
		}
	})

	t.Run("In high,critical unchanged (canonical-string membership)", func(t *testing.T) {
		inRule := Rule{Source: "KubeArmorIntegrator", Match: []MatchExpression{
			{Field: "threatLevel", Op: "In", Value: "high,critical"},
		}}
		if !MatchStrategy(inRule, ev(ThreatLevelCritical)) {
			t.Error("critical In {high,critical} should match")
		}
		if !MatchStrategy(inRule, ev(ThreatLevelHigh)) {
			t.Error("high In {high,critical} should match")
		}
		if MatchStrategy(inRule, ev(ThreatLevelMedium)) {
			t.Error("medium In {high,critical} should NOT match")
		}
	})

	t.Run("Eq on threatLevel stays exact string", func(t *testing.T) {
		eqRule := Rule{Source: "KubeArmorIntegrator", Match: []MatchExpression{
			{Field: "threatLevel", Op: "Eq", Value: ThreatLevelHigh},
		}}
		if !MatchStrategy(eqRule, ev(ThreatLevelHigh)) {
			t.Error("threatLevel Eq high should match high")
		}
		if MatchStrategy(eqRule, ev(ThreatLevelCritical)) {
			t.Error("threatLevel Eq high must NOT match critical (Eq is exact, not rank)")
		}
	})

	t.Run("anomalyScore Gte stays numeric (not rank)", func(t *testing.T) {
		scoreRule := Rule{Source: "FalcoIntegrator", Match: []MatchExpression{
			{Field: "anomalyScore", Op: "Gte", Value: "0.85"},
		}}
		hit := SecurityEventSpec{Rule: Rule{Source: "FalcoIntegrator"}, AnomalyScore: strptr("0.90")}
		if !MatchStrategy(scoreRule, hit) {
			t.Error("anomalyScore 0.90 Gte 0.85 should match numerically")
		}
		miss := SecurityEventSpec{Rule: Rule{Source: "FalcoIntegrator"}, AnomalyScore: strptr("0.50")}
		if MatchStrategy(scoreRule, miss) {
			t.Error("anomalyScore 0.50 Gte 0.85 should NOT match")
		}
	})
}
