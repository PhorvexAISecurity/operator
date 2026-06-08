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
	"strconv"
	"strings"
)

// MatchStrategy reports whether a strategy Rule selects the given SecurityEvent
// spec. It is a STRICT SUPERSET of today's reflect.DeepEqual(strategy.Rule,
// ev.Rule):
//
//   - EXACT FAST PATH (rule.Match == nil && rule.ScoreThreshold == nil): equality
//     of the 3-string projection {Type, ThreatLevel, Source} of rule against
//     ev.Rule. This is outcome-identical to today's whole-struct DeepEqual,
//     because legacy CRs and legacy events both carry nil Match/ScoreThreshold so
//     DeepEqual already reduced to equality of those three strings. The whole-
//     struct DeepEqual is deliberately narrowed to the 3 strings so adding Match
//     to one strategy cannot perturb a sibling exact strategy in the same AMTD.
//
//   - SCORED PATH (rule.Match or rule.ScoreThreshold set): a conjunction (AND) of
//     (i) every NON-EMPTY legacy string field of rule (Type/ThreatLevel/Source)
//     still equals ev.Rule's same field — a guard so a score clause cannot match
//     unrelated events — AND (ii) every MatchExpression holds against ev (plus the
//     ScoreThreshold sugar). A clause referencing anomalyScore against an event
//     with a nil AnomalyScore evaluates FALSE (it never panics and never selects),
//     which is what makes this contract change safe to land before scoring exists.
//
// MatchStrategy reads the whole SecurityEventSpec (NOT only ev.Rule), which is
// what makes ev.AnomalyScore / ev.Metrics reachable.
//
// IMPORTANT: MatchStrategy does NOT consult MatcherMode. The per-AMTD MatcherMode
// feature flag is enforced by the CALLER (see MatchStrategyForMode), so that the
// pure predicate stays trivially testable and the byte-compat theorem is a
// property of this function alone.
func MatchStrategy(rule Rule, ev SecurityEventSpec) bool {
	// Exact fast path — outcome-identical to reflect.DeepEqual today.
	if rule.Match == nil && rule.ScoreThreshold == nil {
		return rule.Type == ev.Rule.Type &&
			rule.ThreatLevel == ev.Rule.ThreatLevel &&
			rule.Source == ev.Rule.Source
	}

	// Scored path — legacy string guards first (only the non-empty ones).
	if rule.Type != "" && rule.Type != ev.Rule.Type {
		return false
	}
	if rule.ThreatLevel != "" && rule.ThreatLevel != ev.Rule.ThreatLevel {
		return false
	}
	if rule.Source != "" && rule.Source != ev.Rule.Source {
		return false
	}

	// ScoreThreshold X is exact sugar for Match{anomalyScore, Gte, X}.
	if rule.ScoreThreshold != nil {
		if !evalExpression(MatchExpression{Field: "anomalyScore", Op: "Gte", Value: *rule.ScoreThreshold}, ev) {
			return false
		}
	}

	// Every MatchExpression must hold (AND).
	for i := range rule.Match {
		if !evalExpression(rule.Match[i], ev) {
			return false
		}
	}
	return true
}

// MatchStrategyForMode applies the per-AMTD MatcherMode feature flag in front of
// MatchStrategy. In Exact mode (the default), any Match/ScoreThreshold on the
// rule is IGNORED: the rule is evaluated as its bare 3-string projection, so a
// scored clause is inert and behavior is exactly today's. In Scored mode the
// full MatchStrategy semantics apply.
//
// Callers that want to surface the MatcherModeWarning Status condition can use
// RuleHasScoredClause to detect a rule whose scored clauses were ignored.
func MatchStrategyForMode(rule Rule, ev SecurityEventSpec, mode MatcherMode) bool {
	if mode == MatcherModeScored {
		return MatchStrategy(rule, ev)
	}
	// Exact (default): strip scored clauses to the bare projection.
	exact := Rule{Type: rule.Type, ThreatLevel: rule.ThreatLevel, Source: rule.Source}
	return MatchStrategy(exact, ev)
}

// RuleHasScoredClause reports whether a rule carries any scored clause
// (Match or ScoreThreshold). Used to emit a MatcherModeWarning when such a rule
// is evaluated under Exact mode (where the clause is inert).
func RuleHasScoredClause(rule Rule) bool {
	return rule.Match != nil || rule.ScoreThreshold != nil
}

// evalExpression evaluates a single MatchExpression against a SecurityEvent spec.
// Unknown fields/ops evaluate false (fail-safe: never selects on a clause it does
// not understand).
func evalExpression(e MatchExpression, ev SecurityEventSpec) bool {
	val, present := projectField(e.Field, ev)

	switch e.Op {
	case "Exists":
		return present
	case "Eq":
		return present && val == e.Value
	case "NotEq":
		// Absent value is treated as not-equal-to any concrete value.
		return !present || val != e.Value
	case "In":
		return present && inList(val, e.Value)
	case "NotIn":
		return !present || !inList(val, e.Value)
	case "Gte", "Gt", "Lte", "Lt":
		if !present {
			// An ordered clause vs an absent value (e.g. nil AnomalyScore, or an
			// empty threatLevel) is FALSE.
			return false
		}
		// RANK-AWARE path: ordered comparison on the canonical threatLevel field is
		// done by ThreatLevelRank, NOT numeric parse — so `threatLevel Gte high`
		// matches "critical" (rank 4 >= rank 3) the way a severity FLOOR rule
		// intends. This is the ONLY field whose Gte/Gt/Lte/Lt is rank-based; every
		// other ordered comparison (anomalyScore, metrics.<k>) stays numeric.
		// In/NotIn/Eq/NotEq on threatLevel remain canonical-STRING comparisons, and
		// the exact 3-string fast path in MatchStrategy is untouched.
		if e.Field == "threatLevel" {
			lr := ThreatLevelRank(val)
			rr := ThreatLevelRank(e.Value)
			if lr < 0 || rr < 0 {
				// An unknown (non-canonical) level on either side never satisfies a
				// rank floor — fail-safe, mirroring the numeric-parse-failure path.
				return false
			}
			switch e.Op {
			case "Gte":
				return lr >= rr
			case "Gt":
				return lr > rr
			case "Lte":
				return lr <= rr
			case "Lt":
				return lr < rr
			}
		}
		lhs, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
		if err != nil {
			return false
		}
		rhs, err := strconv.ParseFloat(strings.TrimSpace(e.Value), 64)
		if err != nil {
			return false
		}
		switch e.Op {
		case "Gte":
			return lhs >= rhs
		case "Gt":
			return lhs > rhs
		case "Lte":
			return lhs <= rhs
		case "Lt":
			return lhs < rhs
		}
	}
	return false
}

// projectField resolves a MatchExpression Field to its (value, present) tuple on
// the SecurityEvent spec. Supported fields: type|threatLevel|source|anomalyScore|
// metrics.<k>. A nil AnomalyScore or a missing metrics key reports present=false.
func projectField(field string, ev SecurityEventSpec) (string, bool) {
	switch field {
	case "type":
		return ev.Rule.Type, ev.Rule.Type != ""
	case "threatLevel":
		return ev.Rule.ThreatLevel, ev.Rule.ThreatLevel != ""
	case "source":
		return ev.Rule.Source, ev.Rule.Source != ""
	case "anomalyScore":
		if ev.AnomalyScore == nil {
			return "", false
		}
		return *ev.AnomalyScore, true
	}
	if strings.HasPrefix(field, "metrics.") {
		key := strings.TrimPrefix(field, "metrics.")
		if ev.Metrics == nil {
			return "", false
		}
		v, ok := ev.Metrics[key]
		return v, ok
	}
	return "", false
}

// inList reports whether val is a member of the comma-separated list (whitespace
// around each element is trimmed).
func inList(val, list string) bool {
	for _, item := range strings.Split(list, ",") {
		if strings.TrimSpace(item) == val {
			return true
		}
	}
	return false
}
