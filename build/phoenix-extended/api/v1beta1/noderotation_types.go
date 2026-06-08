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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NodeRotation is the cap#7 "panic-move to a clean node" as a distinct,
// CLUSTER-scoped kind that models an IN-FLIGHT DRAIN so progress survives an
// operator restart (arch §2.4 item 2, §3 cap#7; decisions D25g/D25g2/D25g3/
// D25g4/D26). It is the canonical "object whose restart-safety/observability
// exceed a spec field" the D1 hybrid reserves a standalone CRD for (an in-flight
// node drain), corroborated by SecurityEvent itself being cluster-scoped.
//
// CLASS-(B) CONTINUATION ONLY (arch §1.3 invariant, conformance row): the
// NodeRotationReconciler only PROGRESSES a NodeRotation that a matched NodeRotate
// action (the matcher selected it from a SecurityEvent) already created — it does
// NOT self-initiate a node move. No request object => nothing happens.
//
// THE D26 CLUSTER-DoS LEVER (locked): a node-eviction primitive can cordon/taint/
// delete every node, so the AUTHORIZING event is recorded in TriggerProvenance
// (Source + ThreatLevel) for audit, and the NodeRotate action only creates a
// NodeRotation AFTER the D26 trust gate (Source allowlist + ThreatLevel floor +
// human-approval-for-Delete). The CRD body itself is the realized, already-gated
// drain.

// NodeRotation phase constants (arch §2.4 / D25g4). The durable phase lives in an
// ANNOTATION (the single source of truth, mirroring swap.go) and is MIRRORED to
// Status.Phase. Empty phase == start == Cordoning.
const (
	// NodeRotationPhaseCordoning marks the source node unschedulable (Cordon) or
	// adds the AMTD-managed NoSchedule taint (Taint), the reversible first step.
	NodeRotationPhaseCordoning = "Cordoning"
	// NodeRotationPhaseDraining evicts the targeted pod(s) off the source via the
	// policy/v1 Eviction API (PDB-honoring; targeted-pod-only by default, D25g3).
	NodeRotationPhaseDraining = "Draining"
	// NodeRotationPhaseRescheduling selects a clean-pool node (CleanNodeSelector);
	// on a miss it aborts to NoCleanTarget rather than land an unschedulable pod.
	NodeRotationPhaseRescheduling = "Rescheduling"
	// NodeRotationPhasePinning recreates the targeted pod PINNED to the clean node
	// via nodeAffinity on the REPLACEMENT spec (never spec.nodeName, never the
	// shared owner template, D25g4).
	NodeRotationPhasePinning = "Pinning"
	// NodeRotationPhaseCompleted is the terminal success phase (CompletionTime set,
	// a bounded AMTDStatus.NodeRotations[] record appended).
	NodeRotationPhaseCompleted = "Completed"
	// NodeRotationPhaseRolledBack is the terminal failure phase: an unrecoverable
	// error uncordoned the source (Cordon is reversible, D25g2/D25g4).
	NodeRotationPhaseRolledBack = "RolledBack"
	// NodeRotationPhaseNoCleanTarget is the terminal abort phase: no clean node
	// satisfied the selector + PVC/GPU preflight (reason in NoCleanTargetReason).
	NodeRotationPhaseNoCleanTarget = "NoCleanTarget"
)

// NoCleanTarget abort reasons (D25g4): the CleanNodeSelector returns one of these
// rather than landing an unschedulable pod.
const (
	// NoCleanTargetCleanPoolExhausted means no node matched the clean-pool selector
	// after excluding the source/cordoned/tainted/flagged nodes.
	NoCleanTargetCleanPoolExhausted = "CleanPoolExhausted"
	// NoCleanTargetPVCTopologyBound means the pod's node-affined/local PV binds it to
	// a topology no clean-pool candidate satisfies.
	NoCleanTargetPVCTopologyBound = "PVCTopologyBound"
	// NoCleanTargetNoMatchingGPU means no clean-pool candidate has free GPUs of the
	// required type/MIG profile (GPU-PENDING on kind; the preflight seam exists).
	NoCleanTargetNoMatchingGPU = "NoMatchingGPU"
)

// NodeRotation Status condition type constants (on NodeRotationStatus.Conditions
// and mirrored as the AMTDStatus NoCleanTarget slot, arch §2.3).
const (
	// ConditionNodeRotationThrottled=True means the MaxConcurrentNodes ceiling
	// deferred this rotation's first cordon (the no-mass-eviction invariant, D25g3).
	ConditionNodeRotationThrottled = "NodeRotationThrottled"
	// ConditionNoCleanTarget=True means the rotation aborted because no clean node
	// qualified (reason in NoCleanTargetReason).
	ConditionNoCleanTarget = "NoCleanTarget"
	// ConditionNodeRotationRolledBack=True means the rotation rolled back and
	// uncordoned the source after an unrecoverable failure.
	ConditionNodeRotationRolledBack = "NodeRotationRolledBack"
)

// DefaultCleanPoolSelector is the D25g4 default clean-pool label selector used when
// TargetNodeSelector is empty. A node carrying r6security.com/clean-pool=true,
// schedulable, and not the source/excluded is a candidate.
var DefaultCleanPoolSelector = map[string]string{"r6security.com/clean-pool": "true"}

// NodeRotationStrategy disposition constants (D25g2). Mirrors the
// NodeRotateAction.Strategy enum.
const (
	// NodeRotationStrategyCordon (default) marks the source unschedulable
	// (reversible; the replacement is pinned away so the pod cannot re-land).
	NodeRotationStrategyCordon = "Cordon"
	// NodeRotationStrategyTaint adds an AMTD-managed NoSchedule taint (NoExecute is
	// a SEPARATE PDB-bypassing rung, NOT auto-applied).
	NodeRotationStrategyTaint = "Taint"
	// NodeRotationStrategyDelete deletes the Node object (+ optional cloud-instance
	// termination); the irreversible rung gated behind the D26 human-approval.
	NodeRotationStrategyDelete = "Delete"
)

// NamespacedPodRef is a namespace/name reference to a pod to relocate.
type NamespacedPodRef struct {
	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}

// TriggerProvenance records the authorizing SecurityEvent for the node rotation
// (audit / D26). It is the provenance trail proving the drain was created from a
// trusted, sufficiently-severe event that passed the D26 gate.
type TriggerProvenance struct {
	// +kubebuilder:validation:Optional
	// Source is the triggering SecurityEvent's Rule.Source (e.g. KubeArmorIntegrator).
	Source string `json:"source,omitempty"`
	// +kubebuilder:validation:Optional
	// ThreatLevel is the triggering event's Rule.ThreatLevel.
	ThreatLevel string `json:"threatLevel,omitempty"`
	// +kubebuilder:validation:Optional
	// EventName is the triggering SecurityEvent's name (idempotence/audit).
	EventName string `json:"eventName,omitempty"`
}

// NodeRotationSpec is the desired state of a single in-flight node rotation
// (arch §2.4 item 2, §3 cap#7). It is created by a matched NodeRotate action
// (post-D26-gate) and reconciled to completion by the NodeRotationReconciler.
type NodeRotationSpec struct {
	// +kubebuilder:validation:Required
	// SourceNode is the node the targeted pod currently runs on (cordon/taint/delete
	// target after relocation).
	SourceNode string `json:"sourceNode"`

	// +kubebuilder:validation:Optional
	// +listType=atomic
	// TargetPods are the in-selector targeted inference pods to relocate (D25g3/g4).
	// Default targeted-pod-only: only these are evicted unless DrainPolicy opts into
	// a co-tenant drain.
	TargetPods []NamespacedPodRef `json:"targetPods,omitempty"`

	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=Cordon;Taint;Delete
	// Strategy is the source-node disposition (D25g2). CODE default Cordon via
	// EffectiveStrategy() (not a CRD-default marker, mirroring the Effective*()
	// discipline). Delete additionally requires the D26 human-approval at action time.
	Strategy string `json:"strategy,omitempty"`

	// +kubebuilder:validation:Optional
	// DrainPolicy opts into Eviction-API co-tenant draining (PDB-honoring). nil =>
	// relocate the targeted pod only, no co-tenant drain (D25g3). REUSES the existing
	// DrainPolicy type.
	DrainPolicy *DrainPolicy `json:"drainPolicy,omitempty"`

	// +kubebuilder:validation:Optional
	// TargetNodeSelector selects the clean-pool nodes. CODE default
	// {r6security.com/clean-pool:true} via EffectiveCleanSelector() (D25g4).
	TargetNodeSelector map[string]string `json:"targetNodeSelector,omitempty"`

	// +kubebuilder:validation:Optional
	// TriggerProvenance records the authorizing event (audit / D26).
	TriggerProvenance TriggerProvenance `json:"triggerProvenance,omitempty"`

	// +kubebuilder:validation:Optional
	// MaxConcurrentNodes is the no-mass-eviction ceiling carried from the AMTD's
	// NodeRotationPolicy (D25g3). nil => unlimited (today's behavior); the reconciler
	// counts in-flight NodeRotations past Cordoning before cordoning a new source.
	MaxConcurrentNodes *int `json:"maxConcurrentNodes,omitempty"`

	// +kubebuilder:validation:Optional
	// Stagger spaces successive cordons (D25g3). nil => no inter-cordon spacing.
	Stagger *metav1.Duration `json:"stagger,omitempty"`
}

// NodeRotationStatus is the cap#7 observability + restart-safe progress surface.
// The durable phase ALSO lives in an annotation (the single source of truth);
// Status.Phase is the best-effort mirror.
type NodeRotationStatus struct {
	// +kubebuilder:validation:Optional
	// Phase mirrors the durable annotation phase {Cordoning;Draining;Rescheduling;
	// Pinning;Completed;RolledBack;NoCleanTarget}.
	Phase string `json:"phase,omitempty"`

	// +kubebuilder:validation:Optional
	// ObservedGeneration is the .metadata.generation the Status reflects.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +kubebuilder:validation:Optional
	// SourceNode echoes Spec.SourceNode.
	SourceNode string `json:"sourceNode,omitempty"`

	// +kubebuilder:validation:Optional
	// TargetCleanNode is the selected clean-pool node the targeted pod is pinned to.
	TargetCleanNode string `json:"targetCleanNode,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=atomic
	// RelocatedPods are the pods that were relocated (pinned-recreated/evicted).
	RelocatedPods []NamespacedPodRef `json:"relocatedPods,omitempty"`

	// +kubebuilder:validation:Optional
	// EvictedCoTenants counts co-resident pods evicted when DrainPolicy.DrainCoTenants
	// was set (D25g3). 0 in the targeted-pod-only default.
	EvictedCoTenants int `json:"evictedCoTenants,omitempty"`

	// +kubebuilder:validation:Optional
	// NoCleanTargetReason is set when Phase==NoCleanTarget
	// (CleanPoolExhausted|PVCTopologyBound|NoMatchingGPU).
	NoCleanTargetReason string `json:"noCleanTargetReason,omitempty"`

	// +kubebuilder:validation:Optional
	// StartTime is when the rotation started (first cordon). Node-rotation MTTR =
	// CompletionTime-StartTime is REAL-NODE/GPU-PENDING (never measured on kind).
	StartTime metav1.Time `json:"startTime,omitempty"`

	// +kubebuilder:validation:Optional
	// CompletionTime is when the rotation reached Completed.
	CompletionTime metav1.Time `json:"completionTime,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	// Conditions carries NodeRotationThrottled, NoCleanTarget, NodeRotationRolledBack.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ---------------------------------------------------------------------------
// CODE DEFAULT HELPERS (FLAGGED via code, NOT CRD-default markers, mirroring the
// WarmInferenceSet/BaselineSpec Effective*() convention).
// ---------------------------------------------------------------------------

// EffectiveStrategy returns Spec.Strategy, default Cordon (D25g2; the reversible
// minimum action).
func (s *NodeRotationSpec) EffectiveStrategy() string {
	if s != nil && s.Strategy != "" {
		return s.Strategy
	}
	return NodeRotationStrategyCordon
}

// EffectiveCleanSelector returns Spec.TargetNodeSelector, default
// {r6security.com/clean-pool:true} (D25g4).
func (s *NodeRotationSpec) EffectiveCleanSelector() map[string]string {
	if s != nil && len(s.TargetNodeSelector) > 0 {
		return s.TargetNodeSelector
	}
	out := make(map[string]string, len(DefaultCleanPoolSelector))
	for k, v := range DefaultCleanPoolSelector {
		out[k] = v
	}
	return out
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=nrot
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=`.spec.sourceNode`
// +kubebuilder:printcolumn:name="CleanNode",type=string,JSONPath=`.status.targetCleanNode`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// NodeRotation is the Schema for the noderotations API (cap#7, D25g/D26).
// CLUSTER-scoped; models a restart-safe in-flight node drain; class-(B) continuation.
type NodeRotation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeRotationSpec   `json:"spec,omitempty"`
	Status NodeRotationStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// NodeRotationList contains a list of NodeRotation.
type NodeRotationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeRotation `json:"items"`
}

// NodeRotationPolicy is the cap#7 SCHEDULED node-rotation cadence block embedded on
// AMTDSpec (arch §2.4 item / §3 conformance, D25g). DEFAULT-OFF: a nil
// NodeRotationPolicy on the AMTD means panic/event-driven only (no scheduled node
// rotation), because node rotation is far costlier than pod rotation. Per Rule #1
// this is NOT a hidden timer — it only TUNES cadence; the scheduled rotation is
// still triggered by a {Type:'timed',Source:'TimeBasedTrigger'} SecurityEvent
// matched to a NodeRotate action.
type NodeRotationPolicy struct {
	// +kubebuilder:validation:Optional
	// Enabled gates the scheduled node-rotation cadence. false (the default) =>
	// panic/event-driven only.
	Enabled bool `json:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	// Interval is the scheduled node-rotation period (inherits the D9 cadence floor
	// via the single time-based-trigger owner). nil => no scheduled cadence.
	Interval *metav1.Duration `json:"interval,omitempty"`

	// +kubebuilder:validation:Optional
	// Jitter is the +/- band applied to Interval (D10).
	Jitter *metav1.Duration `json:"jitter,omitempty"`

	// +kubebuilder:validation:Optional
	// MaxConcurrentNodes is the HARD no-mass-eviction ceiling: never cordon/drain more
	// than this many nodes at once, regardless of DrainPolicy (D25g3). nil => unlimited.
	MaxConcurrentNodes *int `json:"maxConcurrentNodes,omitempty"`

	// +kubebuilder:validation:Optional
	// Stagger spaces successive cordons (the staggered-rotation no-simultaneous-restart
	// invariant, D25g3).
	Stagger *metav1.Duration `json:"stagger,omitempty"`

	// +kubebuilder:validation:Optional
	// TargetNodeSelector selects the clean pool for scheduled rotations (D25g4 default
	// when empty).
	TargetNodeSelector map[string]string `json:"targetNodeSelector,omitempty"`
}

// NodeRotateTrustPolicy is the per-AMTD D26 trust gate config consumed BEFORE a
// NodeRotate action may create a NodeRotation (the cluster-DoS lever guard). It is
// expressed entirely with simple allowlist/floor fields so a forged/non-allowlisted/
// below-floor SecurityEvent cannot select/execute NodeRotate.
//
// nil on the AMTD => the CODE defaults apply (allowlist {KubeArmorIntegrator,
// FalcoIntegrator}; floor {high,critical}; Delete requires human approval) — the
// gate is ALWAYS on (fail-safe), never silently bypassed.
type NodeRotateTrustPolicy struct {
	// +kubebuilder:validation:Optional
	// +listType=atomic
	// AllowedSources is the trusted-Source allowlist (D26 (a)). Empty => the code
	// default {KubeArmorIntegrator,FalcoIntegrator}.
	AllowedSources []string `json:"allowedSources,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=atomic
	// ThreatLevelFloor is the set of at/above-floor ThreatLevels (D26 (b)). Empty =>
	// the code default {high,critical}.
	ThreatLevelFloor []string `json:"threatLevelFloor,omitempty"`

	// +kubebuilder:validation:Optional
	// AllowDeleteWithoutApproval, when true, is the explicit admin opt-in that lets
	// Strategy=Delete (irreversible node termination) proceed (D26 (c)). Default false
	// => Delete requires the per-event approval annotation. This is the human-approval
	// gate; absent approval, Delete is denied (NOT auto-degraded).
	AllowDeleteWithoutApproval bool `json:"allowDeleteWithoutApproval,omitempty"`
}

func init() {
	SchemeBuilder.Register(&NodeRotation{}, &NodeRotationList{})
}
