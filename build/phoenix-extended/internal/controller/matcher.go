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

// Package controller — relaxed action matcher (Phase 0, design rule #2).
//
// This file is the controller-side entry point the SecurityEvent reconciler
// calls to choose an AMTDAction for an incoming SecurityEvent, replacing the
// historical bare reflect.DeepEqual(strategy.Rule, securityEvent.Spec.Rule) at
// securityevent_controller.go. It is a STRICT SUPERSET of that DeepEqual:
//
//   - EXACT FAST PATH (rule.Match == nil && rule.ScoreThreshold == nil): equality
//     of the 3-string projection {Type, ThreatLevel, Source} of the strategy rule
//     against the event's Rule. This is outcome-identical to the old whole-struct
//     DeepEqual — legacy CRs and legacy emitters both carry nil Match/ScoreThreshold,
//     so DeepEqual already reduced to equality of exactly those three strings
//     (proven exhaustively by matcher_test.go's byte-compat matrix and by the
//     api-package matcher_test.go's 7^6 sweep against reflect.DeepEqual).
//
//   - SCORED PATH (rule.Match or rule.ScoreThreshold set): a conjunction (AND) of
//     (i) every non-empty legacy string field of the rule (Type/ThreatLevel/Source)
//     still equals the event Rule's same field — a Source/Type guard so a score
//     clause cannot select on an unrelated event — AND (ii) every MatchExpression
//     holds against the whole event spec (anomalyScore / metrics.<k> reachable).
//     ScoreThreshold X is exact sugar for Match{anomalyScore, Gte, X}. A clause that
//     references anomalyScore against an event with a nil AnomalyScore evaluates
//     FALSE (never panics, never selects) — the Phase-0 inertness that makes this
//     contract change safe to land before any scorer exists.
//
// The actual predicate semantics live in the shared api/v1beta1 module
// (api/v1beta1/matcher.go) so the operator, every integrator, and the CRD all see
// one definition of "does this rule match this event". These controller-package
// functions are thin, intentional re-exports under the exact signatures the
// reconciler uses, keeping the matching decision in one place while giving the
// controller a local, package-cohesive call site.
package controller

import (
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// MatchStrategy reports whether a strategy Rule selects the given SecurityEvent
// spec, WITHOUT consulting MatcherMode (the pure predicate). It is the
// controller-package form of the relaxed matcher; the per-AMTD MatcherMode
// feature flag is applied by MatchStrategyForMode. Use MatchStrategyForMode in
// the reconcile path so a scored clause is honored only when the AMTD opts in.
func MatchStrategy(rule amtdv1beta1.Rule, ev amtdv1beta1.SecurityEventSpec) bool {
	return amtdv1beta1.MatchStrategy(rule, ev)
}

// MatchStrategyForMode applies the per-AMTD MatcherMode feature flag in front of
// MatchStrategy. In Exact mode (the default) any Match/ScoreThreshold on the rule
// is IGNORED: the rule is evaluated as its bare 3-string projection, so a scored
// clause is inert and behavior is exactly today's. In Scored mode the full
// MatchStrategy semantics apply. THIS is what the SecurityEvent reconciler calls
// at its first-match-wins loop so that exact (legacy) rules keep selecting
// byte-for-byte while scored rules are opt-in per AMTD.
func MatchStrategyForMode(rule amtdv1beta1.Rule, ev amtdv1beta1.SecurityEventSpec, mode amtdv1beta1.MatcherMode) bool {
	return amtdv1beta1.MatchStrategyForMode(rule, ev, mode)
}

// RuleHasScoredClause reports whether a rule carries any scored clause
// (Match or ScoreThreshold). The reconciler uses it to surface a
// MatcherModeWarning condition when such a rule is evaluated under the default
// Exact mode (where the clause is inert) so the operator can see it had no effect.
func RuleHasScoredClause(rule amtdv1beta1.Rule) bool {
	return amtdv1beta1.RuleHasScoredClause(rule)
}
