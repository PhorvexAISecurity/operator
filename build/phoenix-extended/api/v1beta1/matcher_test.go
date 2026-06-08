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

import (
	"reflect"
	"testing"
)

func strptr(s string) *string { return &s }

// TestMatchStrategy_ByteCompatWithDeepEqual proves the locked byte-compat
// theorem: for any (rule, event) where rule.Match==nil && rule.ScoreThreshold==nil
// and the event Rule carries nil Match/ScoreThreshold (every legacy emitter),
// MatchStrategy returns exactly what reflect.DeepEqual(rule, ev.Rule) returns.
func TestMatchStrategy_ByteCompatWithDeepEqual(t *testing.T) {
	vals := []string{"", "timed", "info", "TimeBasedTrigger", "panic", "FalcoIntegrator", "critical"}
	mk := func(ty, lvl, src string) Rule { return Rule{Type: ty, ThreatLevel: lvl, Source: src} }

	tried := 0
	for _, rt := range vals {
		for _, rl := range vals {
			for _, rs := range vals {
				rule := mk(rt, rl, rs)
				for _, et := range vals {
					for _, el := range vals {
						for _, es := range vals {
							evRule := mk(et, el, es)
							ev := SecurityEventSpec{Rule: evRule}
							want := reflect.DeepEqual(rule, evRule)
							got := MatchStrategy(rule, ev)
							if got != want {
								t.Fatalf("byte-compat broken: rule=%+v evRule=%+v DeepEqual=%v MatchStrategy=%v",
									rule, evRule, want, got)
							}
							tried++
						}
					}
				}
			}
		}
	}
	if tried == 0 {
		t.Fatal("no cases exercised")
	}
}

// TestMatchStrategy_TimedRotateRule covers the dissolved NIM gate rule:
// {type:timed, source:TimeBasedTrigger} selecting (or not) timed events.
func TestMatchStrategy_TimedRotateRule(t *testing.T) {
	rule := Rule{Type: "timed", Source: "TimeBasedTrigger"}

	// exact match (threatLevel empty on both)
	if !MatchStrategy(rule, SecurityEventSpec{Rule: Rule{Type: "timed", Source: "TimeBasedTrigger"}}) {
		t.Error("expected timed/TimeBasedTrigger event to match")
	}
	// threatLevel differs but rule leaves it empty -> in EXACT path this is a 3-string
	// projection, so an event with a non-empty threatLevel does NOT match (same as DeepEqual).
	if MatchStrategy(rule, SecurityEventSpec{Rule: Rule{Type: "timed", ThreatLevel: "info", Source: "TimeBasedTrigger"}}) {
		t.Error("exact path must compare all 3 strings; threatLevel mismatch should fail")
	}
	// source differs -> no match
	if MatchStrategy(rule, SecurityEventSpec{Rule: Rule{Type: "timed", Source: "Other"}}) {
		t.Error("source mismatch should not match")
	}
}

func TestMatchStrategy_ScoredPath(t *testing.T) {
	score := func(s string) SecurityEventSpec {
		return SecurityEventSpec{Rule: Rule{Source: "FalcoIntegrator"}, AnomalyScore: strptr(s)}
	}

	t.Run("ScoreThreshold gte hit", func(t *testing.T) {
		rule := Rule{Source: "FalcoIntegrator", ScoreThreshold: strptr("0.85")}
		if !MatchStrategy(rule, score("0.90")) {
			t.Error("0.90 >= 0.85 should match")
		}
		if MatchStrategy(rule, score("0.50")) {
			t.Error("0.50 >= 0.85 should NOT match")
		}
	})

	t.Run("score clause vs nil AnomalyScore is false", func(t *testing.T) {
		rule := Rule{Source: "FalcoIntegrator", ScoreThreshold: strptr("0.85")}
		ev := SecurityEventSpec{Rule: Rule{Source: "FalcoIntegrator"}} // nil AnomalyScore
		if MatchStrategy(rule, ev) {
			t.Error("nil AnomalyScore must evaluate score clause as FALSE")
		}
	})

	t.Run("source guard blocks unrelated event", func(t *testing.T) {
		rule := Rule{Source: "FalcoIntegrator", Match: []MatchExpression{{Field: "anomalyScore", Op: "Gte", Value: "0.1"}}}
		ev := SecurityEventSpec{Rule: Rule{Source: "KubeArmorIntegrator"}, AnomalyScore: strptr("0.99")}
		if MatchStrategy(rule, ev) {
			t.Error("source guard must block a high score from an unrelated source")
		}
	})

	t.Run("metrics Exists", func(t *testing.T) {
		rule := Rule{Source: "PrometheusIntegrator", Match: []MatchExpression{{Field: "metrics.high_gpu_usage", Op: "Exists"}}}
		ev := SecurityEventSpec{Rule: Rule{Source: "PrometheusIntegrator"}, Metrics: map[string]string{"high_gpu_usage": "true"}}
		if !MatchStrategy(rule, ev) {
			t.Error("metrics.high_gpu_usage Exists should match")
		}
		ev2 := SecurityEventSpec{Rule: Rule{Source: "PrometheusIntegrator"}}
		if MatchStrategy(rule, ev2) {
			t.Error("missing metric should not match Exists")
		}
	})

	t.Run("In on threatLevel", func(t *testing.T) {
		rule := Rule{Source: "KubeArmorIntegrator", Match: []MatchExpression{{Field: "threatLevel", Op: "In", Value: "high,critical"}}}
		ev := SecurityEventSpec{Rule: Rule{Source: "KubeArmorIntegrator", ThreatLevel: "critical"}}
		if !MatchStrategy(rule, ev) {
			t.Error("critical In {high,critical} should match")
		}
		ev2 := SecurityEventSpec{Rule: Rule{Source: "KubeArmorIntegrator", ThreatLevel: "low"}}
		if MatchStrategy(rule, ev2) {
			t.Error("low In {high,critical} should NOT match")
		}
	})

	t.Run("conjunction AND", func(t *testing.T) {
		rule := Rule{Source: "FalcoIntegrator", Match: []MatchExpression{
			{Field: "anomalyScore", Op: "Gte", Value: "0.85"},
			{Field: "threatLevel", Op: "Eq", Value: "critical"},
		}}
		hit := SecurityEventSpec{Rule: Rule{Source: "FalcoIntegrator", ThreatLevel: "critical"}, AnomalyScore: strptr("0.9")}
		if !MatchStrategy(rule, hit) {
			t.Error("both clauses satisfied should match")
		}
		miss := SecurityEventSpec{Rule: Rule{Source: "FalcoIntegrator", ThreatLevel: "warning"}, AnomalyScore: strptr("0.9")}
		if MatchStrategy(rule, miss) {
			t.Error("one clause unsatisfied should NOT match (AND)")
		}
	})
}

// TestMatchStrategyForMode proves Exact mode renders scored clauses inert and
// outcome-identical to today, while Scored mode honors them.
func TestMatchStrategyForMode(t *testing.T) {
	scoredRule := Rule{Source: "FalcoIntegrator", ScoreThreshold: strptr("0.85")}
	ev := SecurityEventSpec{Rule: Rule{Source: "FalcoIntegrator"}, AnomalyScore: strptr("0.99")}

	// Exact mode: ScoreThreshold ignored, rule degrades to {source:FalcoIntegrator}
	// projection; event Rule is {source:FalcoIntegrator} so 3-string projection matches.
	if !MatchStrategyForMode(scoredRule, ev, MatcherModeExact) {
		t.Error("Exact mode should match on the bare 3-string projection")
	}
	// But an event whose Rule has an extra non-empty field must NOT match in Exact
	// (projection compares all three), proving the clause was truly ignored.
	evExtra := SecurityEventSpec{Rule: Rule{Source: "FalcoIntegrator", ThreatLevel: "critical"}, AnomalyScore: strptr("0.99")}
	if MatchStrategyForMode(scoredRule, evExtra, MatcherModeExact) {
		t.Error("Exact mode must compare the full 3-string projection")
	}

	// Scored mode honors the threshold.
	if !MatchStrategyForMode(scoredRule, ev, MatcherModeScored) {
		t.Error("Scored mode should honor ScoreThreshold and match 0.99>=0.85")
	}
	low := SecurityEventSpec{Rule: Rule{Source: "FalcoIntegrator"}, AnomalyScore: strptr("0.5")}
	if MatchStrategyForMode(scoredRule, low, MatcherModeScored) {
		t.Error("Scored mode 0.5>=0.85 should NOT match")
	}

	if !RuleHasScoredClause(scoredRule) {
		t.Error("RuleHasScoredClause should detect ScoreThreshold")
	}
	if RuleHasScoredClause(Rule{Type: "timed", Source: "TimeBasedTrigger"}) {
		t.Error("a pure 3-string rule has no scored clause")
	}
}
