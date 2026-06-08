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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContextMutationPolicy is the standalone kind that gives ADA Listing 1 fidelity
// (arch §2.4 item 4, decision D7g). It is faithful to the paper's
// ContextMutationPolicy shape (selector + telemetry-source triggers + a typed
// Mutations[] set) but is registered on the OPERATOR group amtd.r6security.com/
// v1beta1 — NOT the paper literal "ADA.security.r6.dev/v1", which is non-idiomatic
// and likely fails K8s group-name (DNS-1123) validation and would force a second
// scheme/RBAC surface (D7g).
//
// SCOPE = NAMESPACED (decision documented here): ADA Listing 1's selector binds to
// pods by matchLabels and its mutations name a container/image/env that live inside
// a workload namespace, so a CMP is a per-namespace policy object exactly like the
// workloads it mutates. (SecurityEvent is cluster-scoped because it is an
// integrator-written trust object; a CMP is operator/operator-team-authored policy
// co-located with its workloads, so namespaced is the idiomatic, lower-privilege
// choice and matches the namespaced selector semantics of Listing 1.)
//
// REICONCILER ROLE = THIN STATUS ONLY (D7g, arch §3): the ContextMutationPolicy
// reconciler records Status (observedGeneration, # selected pods, a summary of the
// resolved mutation set, and the GatekeeperViolation no-emitter advisory). It does
// NOT itself perform rotations — rotation flows through AMTD Strategy[] ->
// SecurityEvent -> the Rotate executor, and a Rotate's PolicyRef{Kind:
// "ContextMutationPolicy"} is resolved by the SAME MutationApplier that resolves an
// embedded InferenceRotation (binds CMP Mutations[] to the one apply site).

// CMPTriggerType enumerates the telemetry-source types a CMP trigger may name.
// Faithful to ADA Listing 1 (PrometheusAlert, GatekeeperViolation).
//
// NOTE: GatekeeperViolation is RECEIVER-ONLY. There is NO OPA-Gatekeeper-audit ->
// SecurityEvent emitter in ANY of the 5 repos (verified, arch §7 prereq #1 / the
// flow diagram's "[GatekeeperViolation]: NO emitter exists" row). A CMP MAY declare
// a GatekeeperViolation trigger for Listing-1 fidelity, and the operator WOULD route
// an injected gatekeeper-violation SecurityEvent to Rotate (see the receiver
// convention in internal/controller/gatekeeper_receiver.go), but the upstream emitter
// is documented future-work — the thin reconciler raises an advisory Status condition
// so this gap is observable rather than silently broken.
//
// +kubebuilder:validation:Enum=PrometheusAlert;GatekeeperViolation
type CMPTriggerType string

const (
	// CMPTriggerPrometheusAlert is the realized leg: prometheus-integrator emits
	// SecurityEvents carrying Metrics (e.g. high_gpu_usage), routed by the Phase-3
	// scored matcher.
	CMPTriggerPrometheusAlert CMPTriggerType = "PrometheusAlert"
	// CMPTriggerGatekeeperViolation is RECEIVER-ONLY / paper-only: no native emitter
	// exists (future-work).
	CMPTriggerGatekeeperViolation CMPTriggerType = "GatekeeperViolation"
)

// CMPMutationType enumerates the typed mutation kinds a CMP may declare. Faithful
// to ADA Listing 1 (ContainerImageUpdate, ResourceAdjustment, EnvPatch).
//
// +kubebuilder:validation:Enum=ContainerImageUpdate;ResourceAdjustment;EnvPatch
type CMPMutationType string

const (
	// CMPMutationContainerImageUpdate swaps the named container's image to NewImage.
	CMPMutationContainerImageUpdate CMPMutationType = "ContainerImageUpdate"
	// CMPMutationResourceAdjustment adjusts the named container's resources. The
	// Phase-1 image/env/gpu overlay projects ONLY limits["nvidia.com/gpu"]; cpu/memory
	// requests are recognized-but-not-projected (documented, see the MutationApplier).
	CMPMutationResourceAdjustment CMPMutationType = "ResourceAdjustment"
	// CMPMutationEnvPatch sets-or-overwrites the named container's env from Env.
	CMPMutationEnvPatch CMPMutationType = "EnvPatch"
)

// TelemetrySource is one trigger leg of a ContextMutationPolicy (ADA Listing 1
// triggers.telemetrySources[]). It declares the telemetry signal whose arrival
// (as a routed SecurityEvent) should drive the mutation set.
type TelemetrySource struct {
	// +kubebuilder:validation:Required
	// Type is the telemetry-source kind (PrometheusAlert | GatekeeperViolation).
	Type CMPTriggerType `json:"type"`

	// +kubebuilder:validation:Optional
	// Name is the alert/signal name (e.g. "high_gpu_usage" for a PrometheusAlert). It
	// is the key the prometheus-integrator surfaces in SecurityEvent.Spec.Metrics.
	Name string `json:"name,omitempty"`

	// +kubebuilder:validation:Optional
	// Constraint is the GatekeeperViolation constraint name (e.g.
	// "disallowed-hostpath"). It is the value a FUTURE gatekeeper emitter would encode
	// in SecurityEvent.Spec.Metrics["gatekeeper.constraint"] (see the receiver
	// convention). Meaningless for a PrometheusAlert.
	Constraint string `json:"constraint,omitempty"`
}

// CMPTriggers groups the telemetry-source triggers (ADA Listing 1 triggers{}).
type CMPTriggers struct {
	// +kubebuilder:validation:Optional
	// +listType=atomic
	// TelemetrySources is the list of telemetry signals that drive this policy.
	TelemetrySources []TelemetrySource `json:"telemetrySources,omitempty"`
}

// CMPMutation is one typed mutation of a ContextMutationPolicy (ADA Listing 1
// mutations[]). The interpreted projection into the Phase-1 EffectiveOverlay is:
//   - ContainerImageUpdate -> ContainerName + Image(NewImage)
//   - ResourceAdjustment   -> GPUResource = Resources.Limits["nvidia.com/gpu"]
//     (cpu/memory requests recognized-but-not-projected — see MutationApplier)
//   - EnvPatch             -> EnvPatch(Env)
type CMPMutation struct {
	// +kubebuilder:validation:Required
	// Type selects which mutation primitive this entry expresses.
	Type CMPMutationType `json:"type"`

	// +kubebuilder:validation:Optional
	// ContainerName selects the target container; empty = first/only container.
	ContainerName string `json:"containerName,omitempty"`

	// +kubebuilder:validation:Optional
	// NewImage is the image to set for a ContainerImageUpdate (e.g. ADA Listing 1's
	// nvcr.io/nim/secure-nim:latest). Ignored for other mutation types.
	NewImage string `json:"newImage,omitempty"`

	// +kubebuilder:validation:Optional
	// Resources is the resource requirements for a ResourceAdjustment. Only
	// limits["nvidia.com/gpu"] is projected into the Phase-1 overlay; cpu/memory
	// requests are recognized-but-not-projected (overlay extension deferred).
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=atomic
	// Env is the set-or-overwrite env list for an EnvPatch (e.g. RUNTIME_MODE=SECURE).
	Env []corev1.EnvVar `json:"env,omitempty"`
}

// ContextMutationPolicySpec mirrors ADA Listing 1 (selector + triggers + mutations).
type ContextMutationPolicySpec struct {
	// +kubebuilder:validation:Optional
	// Selector matches the pods this policy targets (ADA Listing 1 selector.matchLabels,
	// e.g. {app: nim-inference}). nil selects nothing (the reconciler records 0 pods).
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// +kubebuilder:validation:Optional
	// Triggers declares the telemetry sources that drive this policy's mutations.
	Triggers CMPTriggers `json:"triggers,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=atomic
	// Mutations is the typed mutation set applied on a routed rotation, bound to the
	// SAME MutationApplier as RotateAction/InferenceRotation (D7g).
	Mutations []CMPMutation `json:"mutations,omitempty"`
}

// ContextMutationPolicyStatus is the thin reconciler's observability surface.
type ContextMutationPolicyStatus struct {
	// +kubebuilder:validation:Optional
	// ObservedGeneration is the .metadata.generation the Status reflects.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +kubebuilder:validation:Optional
	// SelectedPodCount is the number of pods currently matched by Spec.Selector.
	SelectedPodCount int `json:"selectedPodCount,omitempty"`

	// +kubebuilder:validation:Optional
	// ResolvedMutationSummary is a one-line summary of the projected mutation set
	// (e.g. "image=nvcr.io/nim/secure-nim:latest; gpu=0; env=RUNTIME_MODE"), computed
	// with the SAME projection the MutationApplier uses, plus any not-applied note.
	ResolvedMutationSummary string `json:"resolvedMutationSummary,omitempty"`

	// +kubebuilder:validation:Optional
	// +listType=map
	// +listMapKey=type
	// Conditions carries the advisory conditions, notably GatekeeperViolationUnsupported.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=cmp
// +kubebuilder:printcolumn:name="SelectedPods",type=integer,JSONPath=`.status.selectedPodCount`
// +kubebuilder:printcolumn:name="Mutations",type=string,JSONPath=`.status.resolvedMutationSummary`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// ContextMutationPolicy is the Schema for the contextmutationpolicies API (D7g).
type ContextMutationPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ContextMutationPolicySpec   `json:"spec,omitempty"`
	Status ContextMutationPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ContextMutationPolicyList contains a list of ContextMutationPolicy.
type ContextMutationPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ContextMutationPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ContextMutationPolicy{}, &ContextMutationPolicyList{})
}
