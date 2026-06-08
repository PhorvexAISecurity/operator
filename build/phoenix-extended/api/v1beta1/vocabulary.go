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

import "strings"

// vocabulary.go — THE shared canonical vocabulary for SecurityEvent.Rule fields
// (Phase 7, arch 1.3 invariant #11 / section 7 prereq #2 normalization).
//
// Every emitting integrator (falco/prometheus/kubearmor) NORMALIZES its native,
// emitter-specific ThreatLevel and Type strings to ONE of these exported constants
// at the emit site, and the operator's matcher / gates compare against THE SAME
// values. Integrators that carry the `replace github.com/r6security/phoenix =>
// ../phoenix-extended` directive import these constants directly (falco,
// prometheus); the kubearmor integrator (no replace, pinned to a published phoenix)
// mirrors these exact strings self-contained and documents that it mirrors this
// vocabulary.
//
// This closes the inert-until-normalized gap: a rule keyed on a canonical value
// (e.g. {type:"drift"} or threatLevel Gte "high") now natively selects normalized
// events regardless of which integrator emitted them.

// Canonical ThreatLevel vocabulary. A SecurityEvent's Rule.ThreatLevel, after
// integrator-side normalization, is exactly one of these (lowercase). The ordering
// info < low < medium < high < critical is the rank used by the rank-aware matcher
// (ThreatLevelRank) and is consistent with the D26 NodeRotate floor set.
const (
	// ThreatLevelInfo is the lowest canonical severity (rank 0).
	ThreatLevelInfo = "info"
	// ThreatLevelLow is canonical low severity (rank 1).
	ThreatLevelLow = "low"
	// ThreatLevelMedium is canonical medium severity (rank 2).
	ThreatLevelMedium = "medium"
	// ThreatLevelHigh is canonical high severity (rank 3).
	ThreatLevelHigh = "high"
	// ThreatLevelCritical is the highest canonical severity (rank 4).
	ThreatLevelCritical = "critical"
)

// Canonical Type vocabulary. A SecurityEvent's Rule.Type, after integrator-side
// normalization, is one of these (or, for a signal a normalizer does not recognize,
// a documented per-integrator default — typically TypePolicyViolation — with the raw
// emitter type retained in Metrics/Description for audit).
const (
	// TypeDrift = container/baseline image drift (Falco "Container Drift" family).
	TypeDrift = "drift"
	// TypePanic = a container-escape / breakout class signal (runc / CVE-2019-5736 /
	// Container Breakout / escape) that warrants a panic-class response.
	TypePanic = "panic"
	// TypePolicyViolation = a generic runtime policy violation (KubeArmor policy hits,
	// and the default for an otherwise-unclassified detection).
	TypePolicyViolation = "policy-violation"
	// TypeTimed = the scheduled / time-based rotation trigger
	// ({type:"timed",source:"TimeBasedTrigger"}); kept here so the timed-rotate
	// vocabulary is centralized.
	TypeTimed = "timed"
	// TypeDisable = an explicit disable/quarantine-class signal.
	TypeDisable = "disable"
)

// threatLevelRanks maps each canonical ThreatLevel to its ordinal. The map is the
// single source of truth for ThreatLevelRank.
var threatLevelRanks = map[string]int{
	ThreatLevelInfo:     0,
	ThreatLevelLow:      1,
	ThreatLevelMedium:   2,
	ThreatLevelHigh:     3,
	ThreatLevelCritical: 4,
}

// ThreatLevelRank returns the ordinal rank of a canonical ThreatLevel string:
// info=0, low=1, medium=2, high=3, critical=4. The comparison is case-insensitive
// (surrounding whitespace trimmed) so native variants (High/HIGH/" high ") still
// rank. Any value outside the canonical set returns -1 (unknown), which callers
// treat as fail-safe (an unknown level never satisfies a rank-based floor).
func ThreatLevelRank(s string) int {
	if r, ok := threatLevelRanks[strings.ToLower(strings.TrimSpace(s))]; ok {
		return r
	}
	return -1
}
