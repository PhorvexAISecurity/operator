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

// Package controller — the D26 node-rotation TRUST GATE (the cluster-DoS lever).
//
// A node-eviction primitive can cordon/taint/delete every node, so a forged or
// non-allowlisted or below-floor SecurityEvent must NOT be able to select/execute a
// NodeRotate. evaluateNodeRotateGate is a HARD gate checked BEFORE any NodeRotation
// is created. RBAC provenance is the base (workload SAs cannot create
// securityevents, D26g); this gate adds, on top of that base:
//
//	(a) Source allowlist  — ev.Spec.Rule.Source must be on the per-AMTD trusted
//	    allowlist (default {KubeArmorIntegrator,FalcoIntegrator}).
//	(b) ThreatLevel floor — ev.Spec.Rule.ThreatLevel must be at/above the floor
//	    (default {high,critical}).
//	(c) Delete human-approval — Strategy=Delete (irreversible node termination)
//	    additionally requires an explicit approval (the per-event approval annotation
//	    OR the AMTD admin opt-in AllowDeleteWithoutApproval). Absent => DENIED, not
//	    auto-degraded.
//
// On FAIL no NodeRotation is created and a gated/denied reason is returned so the
// caller records the condition + AppliedAction="nodeRotate-denied".
package controller

import (
	"strings"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// nodeDeleteApprovalAnnotation is the explicit per-event human-approval the D26 gate
// requires for the irreversible Strategy=Delete disposition (D26 (c)). It is set on
// the triggering SecurityEvent by an admin.
const nodeDeleteApprovalAnnotation = "amtd.r6security.com/node-delete-approved"

// D26 default allowlist + floor (FLAGGED proposals applied in code, mirroring the
// Effective*() discipline; a nil NodeRotateTrust on the AMTD resolves to these).
var (
	defaultNodeRotateAllowedSources   = []string{"KubeArmorIntegrator", "FalcoIntegrator"}
	defaultNodeRotateThreatLevelFloor = []string{"high", "critical"}
)

// gateDecision is the result of the D26 gate.
type gateDecision struct {
	// Allowed reports whether NodeRotate may proceed.
	Allowed bool
	// DeniedReason is a short machine reason when Allowed is false:
	// NodeRotateGatedSourceNotAllowed | NodeRotateGatedBelowFloor |
	// NodeRotateGatedDeleteNeedsApproval.
	DeniedReason string
	// Message is the human-readable explanation (for the condition).
	Message string
}

// D26 denied reason constants (recorded as conditions on the AMTD).
const (
	gateDeniedSourceNotAllowed    = "NodeRotateGatedSourceNotAllowed"
	gateDeniedBelowFloor          = "NodeRotateGatedBelowFloor"
	gateDeniedDeleteNeedsApproval = "NodeRotateGatedDeleteNeedsApproval"
)

// effectiveAllowedSources returns the AMTD's NodeRotate Source allowlist or the code
// default (D26 (a)).
func effectiveAllowedSources(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) []string {
	if amtd != nil && amtd.Spec.NodeRotateTrust != nil && len(amtd.Spec.NodeRotateTrust.AllowedSources) > 0 {
		return amtd.Spec.NodeRotateTrust.AllowedSources
	}
	return defaultNodeRotateAllowedSources
}

// effectiveThreatLevelFloor returns the AMTD's ThreatLevel floor set or the code
// default (D26 (b)).
func effectiveThreatLevelFloor(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) []string {
	if amtd != nil && amtd.Spec.NodeRotateTrust != nil && len(amtd.Spec.NodeRotateTrust.ThreatLevelFloor) > 0 {
		return amtd.Spec.NodeRotateTrust.ThreatLevelFloor
	}
	return defaultNodeRotateThreatLevelFloor
}

// allowDeleteWithoutApproval reports whether the AMTD admin opted into Delete without
// a per-event approval (D26 (c)). Default false.
func allowDeleteWithoutApproval(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) bool {
	return amtd != nil && amtd.Spec.NodeRotateTrust != nil && amtd.Spec.NodeRotateTrust.AllowDeleteWithoutApproval
}

// evaluateNodeRotateGate is the HARD D26 gate. It returns Allowed=true only if the
// event's Source is allowlisted AND its ThreatLevel is at/above the floor AND (for
// Strategy=Delete) it carries the human approval. Comparison is case-insensitive on
// ThreatLevel so native vocab variations (High/HIGH) still gate; Source is matched
// exactly (the emitter-native identity).
func evaluateNodeRotateGate(
	amtd *amtdv1beta1.AdaptiveMovingTargetDefense,
	ev *amtdv1beta1.SecurityEvent,
	strategy string,
) gateDecision {
	// (a) Source allowlist.
	if !containsString(effectiveAllowedSources(amtd), ev.Spec.Rule.Source) {
		return gateDecision{
			Allowed:      false,
			DeniedReason: gateDeniedSourceNotAllowed,
			Message:      "NodeRotate DENIED (D26): the triggering SecurityEvent's Source '" + ev.Spec.Rule.Source + "' is not on the trusted-Source allowlist. A forged/non-allowlisted event cannot drive a node eviction (cluster-DoS lever).",
		}
	}

	// (b) ThreatLevel floor.
	if !threatLevelAtOrAboveFloor(ev.Spec.Rule.ThreatLevel, effectiveThreatLevelFloor(amtd)) {
		return gateDecision{
			Allowed:      false,
			DeniedReason: gateDeniedBelowFloor,
			Message:      "NodeRotate DENIED (D26): the triggering SecurityEvent's ThreatLevel '" + ev.Spec.Rule.ThreatLevel + "' is below the configured floor. Only a sufficiently-severe event may drive a node eviction.",
		}
	}

	// (c) Delete human-approval gate (irreversible disposition).
	if strategy == amtdv1beta1.NodeRotationStrategyDelete {
		if !allowDeleteWithoutApproval(amtd) && !eventHasDeleteApproval(ev) {
			return gateDecision{
				Allowed:      false,
				DeniedReason: gateDeniedDeleteNeedsApproval,
				Message:      "NodeRotate(Delete) DENIED (D26): the irreversible node-delete disposition requires an explicit human approval (the '" + nodeDeleteApprovalAnnotation + "=true' annotation on the SecurityEvent, or the AMTD admin opt-in). It is never auto-applied.",
			}
		}
	}

	return gateDecision{Allowed: true}
}

// threatLevelAtOrAboveFloor reports whether the event's ThreatLevel is in the floor
// set (case-insensitive). The floor is an explicit at/above set (e.g. {high,critical})
// expressed as the locked Rule.Match In-guard semantics — membership IS at/above.
func threatLevelAtOrAboveFloor(level string, floor []string) bool {
	l := strings.ToLower(strings.TrimSpace(level))
	for _, f := range floor {
		if strings.ToLower(strings.TrimSpace(f)) == l {
			return true
		}
	}
	return false
}

// eventHasDeleteApproval reports whether the SecurityEvent carries the explicit
// per-event human-approval annotation for Strategy=Delete (D26 (c)).
func eventHasDeleteApproval(ev *amtdv1beta1.SecurityEvent) bool {
	return ev != nil && ev.Annotations != nil && strings.EqualFold(ev.Annotations[nodeDeleteApprovalAnnotation], "true")
}
