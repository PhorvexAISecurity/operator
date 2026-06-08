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

package controller

import (
	"reflect"
	"testing"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func sp(s string) *string { return &s }

// ---------------------------------------------------------------------------
// (a) Legacy 3-string rules select IDENTICALLY to the old reflect.DeepEqual.
//
// The historical matcher at securityevent_controller.go was a bare
// reflect.DeepEqual(strategy.Rule, securityEvent.Spec.Rule). For every legacy
// rule/event (both carry nil Match/ScoreThreshold), the controller-package
// MatchStrategy must return EXACTLY what that DeepEqual returned. This sweeps a
// matrix of (strategy.Rule, event.Rule) including equal, unequal, and empty-Rule
// cases. This is the Phase-0 backward-compat gate (design rule #2 / byte-compat
// theorem).
// ---------------------------------------------------------------------------
func TestMatchStrategy_LegacyEqualsDeepEqual(t *testing.T) {
	// Includes "" (empty-Rule / unset field) so empty-vs-populated cases are covered,
	// plus the real emitter vocabularies (timed/TimeBasedTrigger, Falco, KubeArmor).
	vals := []string{"", "timed", "info", "TimeBasedTrigger", "panic", "critical", "FalcoIntegrator", "KubeArmorIntegrator"}
	mk := func(ty, lvl, src string) amtdv1beta1.Rule {
		return amtdv1beta1.Rule{Type: ty, ThreatLevel: lvl, Source: src}
	}

	cases := 0
	for _, rt := range vals {
		for _, rl := range vals {
			for _, rs := range vals {
				rule := mk(rt, rl, rs)
				for _, et := range vals {
					for _, el := range vals {
						for _, es := range vals {
							evRule := mk(et, el, es)
							ev := amtdv1beta1.SecurityEventSpec{Rule: evRule}

							// The exact predicate the controller now uses.
							got := MatchStrategy(rule, ev)
							// The historical behavior at the old L139.
							want := reflect.DeepEqual(rule, evRule)

							if got != want {
								t.Fatalf("legacy mismatch vs DeepEqual: rule=%+v evRule=%+v want=%v got=%v",
									rule, evRule, want, got)
							}
							cases++
						}
					}
				}
			}
		}
	}
	if cases == 0 {
		t.Fatal("matrix exercised zero cases")
	}
	t.Logf("verified MatchStrategy == reflect.DeepEqual over %d legacy (rule,event) pairs", cases)
}

// Explicit equal / unequal / empty-Rule spot checks (in addition to the sweep),
// so an intent-revealing failure shows up if the projection is ever broken.
func TestMatchStrategy_LegacySpotChecks(t *testing.T) {
	tests := []struct {
		name string
		rule amtdv1beta1.Rule
		ev   amtdv1beta1.Rule
		want bool
	}{
		{"all-equal full triple", amtdv1beta1.Rule{Type: "timed", ThreatLevel: "info", Source: "TimeBasedTrigger"}, amtdv1beta1.Rule{Type: "timed", ThreatLevel: "info", Source: "TimeBasedTrigger"}, true},
		{"type differs", amtdv1beta1.Rule{Type: "timed", Source: "TimeBasedTrigger"}, amtdv1beta1.Rule{Type: "other", Source: "TimeBasedTrigger"}, false},
		{"threatLevel differs", amtdv1beta1.Rule{Type: "timed", ThreatLevel: "info", Source: "TimeBasedTrigger"}, amtdv1beta1.Rule{Type: "timed", ThreatLevel: "warning", Source: "TimeBasedTrigger"}, false},
		{"source differs", amtdv1beta1.Rule{Type: "timed", Source: "TimeBasedTrigger"}, amtdv1beta1.Rule{Type: "timed", Source: "Other"}, false},
		{"both empty Rule", amtdv1beta1.Rule{}, amtdv1beta1.Rule{}, true},
		{"empty rule vs populated event", amtdv1beta1.Rule{}, amtdv1beta1.Rule{Type: "timed"}, false},
		{"populated rule vs empty event", amtdv1beta1.Rule{Source: "FalcoIntegrator"}, amtdv1beta1.Rule{}, false},
		{"rule omits threatLevel, event sets it (exact compares all 3)", amtdv1beta1.Rule{Type: "timed", Source: "TimeBasedTrigger"}, amtdv1beta1.Rule{Type: "timed", ThreatLevel: "info", Source: "TimeBasedTrigger"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchStrategy(tc.rule, amtdv1beta1.SecurityEventSpec{Rule: tc.ev})
			if got != tc.want {
				t.Errorf("MatchStrategy(%+v, ev.Rule=%+v) = %v, want %v", tc.rule, tc.ev, got, tc.want)
			}
			// And it must equal DeepEqual of the two Rules for these legacy inputs.
			if de := reflect.DeepEqual(tc.rule, tc.ev); de != got {
				t.Errorf("legacy input diverges from DeepEqual: DeepEqual=%v MatchStrategy=%v", de, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// (b) Scored comparison operators: Gte/Gt/Lte/Lt/In/NotIn/Eq/Exists/NotEq.
// All evaluated through the pure MatchStrategy (mode-independent). Each rule
// carries a Source guard that the event satisfies, so the test isolates the
// MatchExpression operator semantics.
// ---------------------------------------------------------------------------
func TestMatchStrategy_ScoredOperators(t *testing.T) {
	src := "FalcoIntegrator"
	// event with anomalyScore=0.85, threatLevel=critical, a metric present.
	evScore := func(score string) amtdv1beta1.SecurityEventSpec {
		return amtdv1beta1.SecurityEventSpec{
			Rule:         amtdv1beta1.Rule{Source: src, ThreatLevel: "critical"},
			AnomalyScore: sp(score),
			Metrics:      map[string]string{"high_gpu_usage": "true"},
		}
	}

	tests := []struct {
		name  string
		match []amtdv1beta1.MatchExpression
		ev    amtdv1beta1.SecurityEventSpec
		want  bool
	}{
		// Gte
		{"Gte hit (0.90>=0.85)", []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Gte", Value: "0.85"}}, evScore("0.90"), true},
		{"Gte boundary (0.85>=0.85)", []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Gte", Value: "0.85"}}, evScore("0.85"), true},
		{"Gte miss (0.50>=0.85)", []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Gte", Value: "0.85"}}, evScore("0.50"), false},
		// Gt
		{"Gt hit (0.86>0.85)", []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Gt", Value: "0.85"}}, evScore("0.86"), true},
		{"Gt boundary excluded (0.85>0.85)", []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Gt", Value: "0.85"}}, evScore("0.85"), false},
		// Lte
		{"Lte hit (0.50<=0.85)", []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Lte", Value: "0.85"}}, evScore("0.50"), true},
		{"Lte boundary (0.85<=0.85)", []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Lte", Value: "0.85"}}, evScore("0.85"), true},
		{"Lte miss (0.90<=0.85)", []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Lte", Value: "0.85"}}, evScore("0.90"), false},
		// Lt
		{"Lt hit (0.50<0.85)", []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Lt", Value: "0.85"}}, evScore("0.50"), true},
		{"Lt boundary excluded (0.85<0.85)", []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Lt", Value: "0.85"}}, evScore("0.85"), false},
		// In (on threatLevel)
		{"In hit (critical in {high,critical})", []amtdv1beta1.MatchExpression{{Field: "threatLevel", Op: "In", Value: "high,critical"}}, evScore("0.85"), true},
		{"In miss (critical in {low,medium})", []amtdv1beta1.MatchExpression{{Field: "threatLevel", Op: "In", Value: "low,medium"}}, evScore("0.85"), false},
		// NotIn (on threatLevel)
		{"NotIn hit (critical not in {low,medium})", []amtdv1beta1.MatchExpression{{Field: "threatLevel", Op: "NotIn", Value: "low,medium"}}, evScore("0.85"), true},
		{"NotIn miss (critical not in {high,critical})", []amtdv1beta1.MatchExpression{{Field: "threatLevel", Op: "NotIn", Value: "high,critical"}}, evScore("0.85"), false},
		// Eq (on threatLevel)
		{"Eq hit (threatLevel==critical)", []amtdv1beta1.MatchExpression{{Field: "threatLevel", Op: "Eq", Value: "critical"}}, evScore("0.85"), true},
		{"Eq miss (threatLevel==warning)", []amtdv1beta1.MatchExpression{{Field: "threatLevel", Op: "Eq", Value: "warning"}}, evScore("0.85"), false},
		// NotEq (on threatLevel)
		{"NotEq hit (threatLevel!=warning)", []amtdv1beta1.MatchExpression{{Field: "threatLevel", Op: "NotEq", Value: "warning"}}, evScore("0.85"), true},
		{"NotEq miss (threatLevel!=critical)", []amtdv1beta1.MatchExpression{{Field: "threatLevel", Op: "NotEq", Value: "critical"}}, evScore("0.85"), false},
		// Exists (on metrics.<k>)
		{"Exists hit (metrics.high_gpu_usage present)", []amtdv1beta1.MatchExpression{{Field: "metrics.high_gpu_usage", Op: "Exists"}}, evScore("0.85"), true},
		{"Exists miss (metrics.absent_key)", []amtdv1beta1.MatchExpression{{Field: "metrics.absent_key", Op: "Exists"}}, evScore("0.85"), false},
		// metrics.<k> Eq
		{"metrics Eq hit", []amtdv1beta1.MatchExpression{{Field: "metrics.high_gpu_usage", Op: "Eq", Value: "true"}}, evScore("0.85"), true},
		{"metrics Eq miss", []amtdv1beta1.MatchExpression{{Field: "metrics.high_gpu_usage", Op: "Eq", Value: "false"}}, evScore("0.85"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := amtdv1beta1.Rule{Source: src, Match: tc.match}
			if got := MatchStrategy(rule, tc.ev); got != tc.want {
				t.Errorf("MatchStrategy(match=%+v) = %v, want %v", tc.match, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// (c) ScoreThreshold sugar == anomalyScore Gte.
// ScoreThreshold X must be semantically identical to Match{anomalyScore,Gte,X}.
// ---------------------------------------------------------------------------
func TestMatchStrategy_ScoreThresholdEqualsGte(t *testing.T) {
	src := "FalcoIntegrator"
	for _, thr := range []string{"0.0", "0.5", "0.85", "1.0"} {
		for _, score := range []string{"0.0", "0.49", "0.5", "0.84", "0.85", "0.86", "0.99", "1.0"} {
			ev := amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Source: src}, AnomalyScore: sp(score)}

			sugar := amtdv1beta1.Rule{Source: src, ScoreThreshold: sp(thr)}
			explicit := amtdv1beta1.Rule{Source: src, Match: []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Gte", Value: thr}}}

			gotSugar := MatchStrategy(sugar, ev)
			gotExplicit := MatchStrategy(explicit, ev)
			if gotSugar != gotExplicit {
				t.Errorf("ScoreThreshold sugar diverges from Gte: thr=%s score=%s sugar=%v explicit=%v", thr, score, gotSugar, gotExplicit)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// (d) A score clause vs a nil AnomalyScore evaluates FALSE (Phase-0 inertness).
// This is what makes the contract change safe to land before any scorer exists.
// ---------------------------------------------------------------------------
func TestMatchStrategy_ScoreClauseVsNilScoreIsFalse(t *testing.T) {
	src := "FalcoIntegrator"
	evNoScore := amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Source: src}} // AnomalyScore == nil

	t.Run("ScoreThreshold vs nil score", func(t *testing.T) {
		rule := amtdv1beta1.Rule{Source: src, ScoreThreshold: sp("0.85")}
		if MatchStrategy(rule, evNoScore) {
			t.Error("ScoreThreshold clause vs nil AnomalyScore must be FALSE")
		}
	})
	t.Run("Match anomalyScore Gte vs nil score", func(t *testing.T) {
		rule := amtdv1beta1.Rule{Source: src, Match: []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Gte", Value: "0.0"}}}
		if MatchStrategy(rule, evNoScore) {
			t.Error("anomalyScore Gte 0.0 vs nil AnomalyScore must be FALSE (no panic, never selects)")
		}
	})
	t.Run("anomalyScore Exists vs nil score is false", func(t *testing.T) {
		rule := amtdv1beta1.Rule{Source: src, Match: []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Exists"}}}
		if MatchStrategy(rule, evNoScore) {
			t.Error("anomalyScore Exists vs nil AnomalyScore must be FALSE")
		}
	})
	t.Run("metric clause vs absent metric is false", func(t *testing.T) {
		rule := amtdv1beta1.Rule{Source: src, Match: []amtdv1beta1.MatchExpression{{Field: "metrics.missing", Op: "Gte", Value: "1"}}}
		if MatchStrategy(rule, evNoScore) {
			t.Error("numeric clause vs an absent metric must be FALSE")
		}
	})
}

// ---------------------------------------------------------------------------
// (e) MatcherMode=Exact renders Match/ScoreThreshold inert (zero behavior change),
// while MatcherMode=Scored honors them. This is the per-AMTD gating that guards
// every cluster that never opts in.
// ---------------------------------------------------------------------------
func TestMatchStrategyForMode_ExactInertScoredHonored(t *testing.T) {
	src := "FalcoIntegrator"
	scoredRule := amtdv1beta1.Rule{Source: src, ScoreThreshold: sp("0.85")}

	// Event whose Rule projection is exactly {source:FalcoIntegrator} and which
	// carries a high score. Under Scored the threshold matches; under Exact the
	// clause is stripped and the bare projection {source} also matches this event.
	evMatchProj := amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Source: src}, AnomalyScore: sp("0.99")}

	// Event whose Rule has an EXTRA non-empty field (threatLevel), so the stripped
	// bare projection {source} != the event's full 3-string projection. Under Exact
	// this must NOT match (proving the scored clause was truly ignored, not used);
	// under Scored the Source guard still holds and the threshold matches.
	evExtraField := amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Source: src, ThreatLevel: "critical"}, AnomalyScore: sp("0.99")}

	// --- Exact mode (default): scored clause inert ---
	if !MatchStrategyForMode(scoredRule, evMatchProj, amtdv1beta1.MatcherModeExact) {
		t.Error("Exact mode should match purely on the bare 3-string projection {source}")
	}
	if MatchStrategyForMode(scoredRule, evExtraField, amtdv1beta1.MatcherModeExact) {
		t.Error("Exact mode must compare the FULL 3-string projection (extra threatLevel must fail), proving the scored clause is ignored")
	}

	// Inertness is independent of score magnitude: a LOW score that would fail the
	// threshold still matches in Exact mode (because the clause is not consulted).
	evLowScore := amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Source: src}, AnomalyScore: sp("0.01")}
	if !MatchStrategyForMode(scoredRule, evLowScore, amtdv1beta1.MatcherModeExact) {
		t.Error("Exact mode must ignore the threshold entirely (low score still matches the bare projection)")
	}

	// Empty mode string == Exact (the default) — same behavior as MatcherModeExact.
	if !MatchStrategyForMode(scoredRule, evMatchProj, amtdv1beta1.MatcherMode("")) {
		t.Error("empty MatcherMode must behave as Exact (default)")
	}
	if MatchStrategyForMode(scoredRule, evExtraField, amtdv1beta1.MatcherMode("")) {
		t.Error("empty MatcherMode must behave as Exact (default) and fail on the extra field")
	}

	// --- Scored mode: scored clause honored ---
	if !MatchStrategyForMode(scoredRule, evMatchProj, amtdv1beta1.MatcherModeScored) {
		t.Error("Scored mode should honor ScoreThreshold (0.99>=0.85)")
	}
	if !MatchStrategyForMode(scoredRule, evExtraField, amtdv1beta1.MatcherModeScored) {
		t.Error("Scored mode: Source guard holds and threshold matches even with extra threatLevel on the event")
	}
	if MatchStrategyForMode(scoredRule, evLowScore, amtdv1beta1.MatcherModeScored) {
		t.Error("Scored mode 0.01>=0.85 should NOT match")
	}

	// RuleHasScoredClause drives the MatcherModeWarning.
	if !RuleHasScoredClause(scoredRule) {
		t.Error("RuleHasScoredClause should detect ScoreThreshold")
	}
	if RuleHasScoredClause(amtdv1beta1.Rule{Source: src, Match: []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Gte", Value: "0.85"}}}) == false {
		t.Error("RuleHasScoredClause should detect Match")
	}
	if RuleHasScoredClause(amtdv1beta1.Rule{Type: "timed", Source: "TimeBasedTrigger"}) {
		t.Error("a pure 3-string rule has no scored clause")
	}
}

// ---------------------------------------------------------------------------
// (f) A Source/Type guard prevents a score clause from matching an unrelated
// event. The non-empty legacy string fields are an AND-guard in the scored path.
// ---------------------------------------------------------------------------
func TestMatchStrategy_GuardBlocksUnrelatedEvent(t *testing.T) {
	t.Run("Source guard blocks a high score from another source", func(t *testing.T) {
		rule := amtdv1beta1.Rule{Source: "FalcoIntegrator", Match: []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Gte", Value: "0.1"}}}
		// Event from a DIFFERENT source with a very high score.
		ev := amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Source: "KubeArmorIntegrator"}, AnomalyScore: sp("0.99")}
		if MatchStrategy(rule, ev) {
			t.Error("Source guard must block a high score originating from an unrelated source")
		}
		// Same score, MATCHING source -> selects.
		evSame := amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Source: "FalcoIntegrator"}, AnomalyScore: sp("0.99")}
		if !MatchStrategy(rule, evSame) {
			t.Error("matching source + score over threshold should select")
		}
	})

	t.Run("Type guard blocks a score clause on a mismatched type", func(t *testing.T) {
		rule := amtdv1beta1.Rule{Type: "drift", Match: []amtdv1beta1.MatchExpression{{Field: "anomalyScore", Op: "Gte", Value: "0.1"}}}
		ev := amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Type: "panic"}, AnomalyScore: sp("0.99")}
		if MatchStrategy(rule, ev) {
			t.Error("Type guard must block a score clause when the event Type differs")
		}
		evSame := amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Type: "drift"}, AnomalyScore: sp("0.99")}
		if !MatchStrategy(rule, evSame) {
			t.Error("matching type + score over threshold should select")
		}
	})

	t.Run("conjunction of guards and clauses (AND)", func(t *testing.T) {
		rule := amtdv1beta1.Rule{
			Source: "FalcoIntegrator",
			Match: []amtdv1beta1.MatchExpression{
				{Field: "anomalyScore", Op: "Gte", Value: "0.85"},
				{Field: "threatLevel", Op: "Eq", Value: "critical"},
			},
		}
		hit := amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Source: "FalcoIntegrator", ThreatLevel: "critical"}, AnomalyScore: sp("0.9")}
		if !MatchStrategy(rule, hit) {
			t.Error("all of {source guard, score>=0.85, threatLevel==critical} satisfied should select")
		}
		// One MatchExpression unsatisfied -> no match.
		miss := amtdv1beta1.SecurityEventSpec{Rule: amtdv1beta1.Rule{Source: "FalcoIntegrator", ThreatLevel: "warning"}, AnomalyScore: sp("0.9")}
		if MatchStrategy(rule, miss) {
			t.Error("one clause unsatisfied must fail the conjunction")
		}
	})
}
