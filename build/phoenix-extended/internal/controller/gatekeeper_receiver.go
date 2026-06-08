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

// Package controller — GatekeeperViolation RECEIVER convention (D7g, arch §7 prereq #1).
//
// =============================================================================
// THERE IS NO OPA-GATEKEEPER-AUDIT -> SecurityEvent EMITTER IN ANY OF THE 5 REPOS.
// =============================================================================
//
// This was VERIFIED, not assumed: the prometheus/falco/kubearmor integrators emit
// SecurityEvents, and time-based-trigger / BaselineDriftReconciler emit them too,
// but NONE of them watch OPA-Gatekeeper audit results. The GatekeeperViolation leg
// of ADA Listing 1's triggers is therefore PAPER-ONLY and is documented future-work
// (arch §7 "Documented unmet prerequisites" #1; decisions.md D7g). This file does
// NOT create or fake an emitter — it ONLY defines the canonical convention an
// operator-side RECEIVER uses so that, the day a real Gatekeeper emitter is added
// (or a trusted integrator injects such an event), the existing matcher -> Rotate
// -> MutationApplier path routes it to a ContextMutationPolicy with NO matcher or
// executor change.
//
// CONVENTION (what a future GatekeeperIntegrator emitter WOULD set, and what an
// AMTD strategy rule MATCHES today):
//
//	SecurityEvent.Spec.Rule.Source = "GatekeeperIntegrator"   (GatekeeperViolationSource)
//	SecurityEvent.Spec.Rule.Type   = "gatekeeper-violation"   (GatekeeperViolationType)
//	SecurityEvent.Spec.Metrics["gatekeeper.constraint"] = "<constraint>"
//	                                                      (GatekeeperConstraintMetricKey)
//
// The constraint value (e.g. "disallowed-hostpath") corresponds 1:1 to a
// ContextMutationPolicy's Triggers.TelemetrySources[GatekeeperViolation].Constraint,
// so the CMP author and the (future) emitter agree on the same key.
//
// MATCHING AMTD STRATEGY RULE (Scored mode; the matcher already supports metrics.<k>
// projection via Eq/Exists — NO matcher change is needed):
//
//	strategy:
//	- rule:
//	    source: GatekeeperIntegrator
//	    type:   gatekeeper-violation
//	    match:
//	    - field: metrics.gatekeeper.constraint
//	      op:    Eq
//	      value: disallowed-hostpath
//	  action:
//	    rotate:
//	      policyRef:
//	        kind: ContextMutationPolicy
//	        name: nim-risk-based-mutation
//
// RECEIVER PATH (end to end, all reusing existing Phase 0-3 machinery):
//
//	injected GatekeeperViolation SecurityEvent
//	  -> MatchStrategyForMode (Scored) selects the rule above
//	  -> SecurityEventReconciler Rotate branch -> executeRotate
//	  -> MutationApplier.Resolve fetches the named ContextMutationPolicy
//	  -> projects its Mutations[] into the EffectiveOverlay
//	  -> D3 owner-walk -> durable owner-template patch (or honest cold fallback)
//
// "Injected" = a trusted integrator (RBAC-gated, D26g) creating the SecurityEvent;
// the operator merely RECEIVES and routes it. No new trigger path is reachable
// outside the matcher (design Rule #1 preserved).
package controller

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

const (
	// GatekeeperViolationSource is the canonical SecurityEvent.Spec.Rule.Source a
	// FUTURE OPA-Gatekeeper-audit emitter would set. RECEIVER-ONLY today.
	GatekeeperViolationSource = "GatekeeperIntegrator"
	// GatekeeperViolationType is the canonical SecurityEvent.Spec.Rule.Type for a
	// gatekeeper constraint violation. RECEIVER-ONLY today.
	GatekeeperViolationType = "gatekeeper-violation"
	// GatekeeperConstraintMetricKey is the SecurityEvent.Spec.Metrics key encoding
	// the violated constraint name; it pairs with a CMP's
	// Triggers.TelemetrySources[GatekeeperViolation].Constraint. Read by the scored
	// matcher as the field "metrics.gatekeeper.constraint".
	GatekeeperConstraintMetricKey = "gatekeeper.constraint"
	// GatekeeperConstraintMatchField is the matcher Field a strategy rule uses to
	// match the constraint (the "metrics." prefix the matcher's projectField reads).
	GatekeeperConstraintMatchField = "metrics." + GatekeeperConstraintMetricKey
)

// NewGatekeeperViolationEvent builds a SecurityEvent in the canonical receiver
// convention for the given target(s) and constraint. It is a TEST/RECEIVER helper
// modeling what a future GatekeeperIntegrator emitter WOULD produce; it is NOT an
// emitter and is NOT wired to any OPA-Gatekeeper audit source. It exists so the
// receiver path can be exercised end-to-end (and a future emitter has a canonical
// shape to target).
func NewGatekeeperViolationEvent(name, constraint string, targets ...string) *amtdv1beta1.SecurityEvent {
	return &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets: targets,
			Rule: amtdv1beta1.Rule{
				Source: GatekeeperViolationSource,
				Type:   GatekeeperViolationType,
			},
			Description: "OPA-Gatekeeper constraint violation (receiver convention; no native emitter)",
			Metrics:     map[string]string{GatekeeperConstraintMetricKey: constraint},
		},
	}
}

// gatekeeperConstraintMatchExpression returns the MatchExpression an AMTD strategy
// rule uses to match a GatekeeperViolation event's constraint (Eq on the metrics
// key). Provided so the receiver convention and the strategy rule share one source
// of truth for the field/op.
func gatekeeperConstraintMatchExpression(constraint string) amtdv1beta1.MatchExpression {
	return amtdv1beta1.MatchExpression{
		Field: GatekeeperConstraintMatchField,
		Op:    "Eq",
		Value: constraint,
	}
}
