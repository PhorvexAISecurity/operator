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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// SecurityEventSpec defines the desired state of SecurityEvent
type SecurityEventSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:validation:Required
	// Targets contains the list of affected pods, each item in the form of "namespace/name" or "/name"
	Targets []string `json:"targets"`

	// +kubebuilder:validation:Required
	Rule Rule `json:"rule"`

	// +kubebuilder:validation:Required
	// Description of the security threat
	Description string `json:"description"`

	// +kubebuilder:validation:Optional
	// AnomalyScore is a decimal string in [0,1] (e.g. "0.85"); cap #5. It lives on
	// the SPEC (NOT on Rule) so Rule stays a pure match key and the exact matcher
	// fast path is preserved. nil means unscored = today's behavior. It is
	// authoritative only because this CR is cluster-scoped and RBAC-gated to
	// trusted integrator ServiceAccounts (D26g).
	AnomalyScore *string `json:"anomalyScore,omitempty"`

	// +kubebuilder:validation:Optional
	// Metrics carries the raw component signals (GPU entropy / query deviation /
	// cache misses) for in-operator recompute/audit. Read by the scored matcher as
	// metrics.<k>.
	Metrics map[string]string `json:"metrics,omitempty"`

	// +kubebuilder:validation:Optional
	// Evidence carries drift evidence (observed vs expected digest + detail); cap #6.
	Evidence *DriftEvidence `json:"evidence,omitempty"`
}

// DriftEvidence is the cap #6 baseline-drift evidence attached to a SecurityEvent.
type DriftEvidence struct {
	// +kubebuilder:validation:Optional
	ObservedDigest string `json:"observedDigest,omitempty"`

	// +kubebuilder:validation:Optional
	ExpectedDigest string `json:"expectedDigest,omitempty"`

	// +kubebuilder:validation:Optional
	Detail string `json:"detail,omitempty"`
}

// SecurityEventStatus is the per-event OUTCOME on the trigger object. The
// subresource is already enabled. All fields are optional.
type SecurityEventStatus struct {
	// +kubebuilder:validation:Optional
	// AppliedAction is the matched action that fired (e.g. delete|rotate|quarantine).
	AppliedAction string `json:"appliedAction,omitempty"`

	// +kubebuilder:validation:Optional
	// ObservedScore is the decimal-string anomaly score at processing time.
	ObservedScore string `json:"observedScore,omitempty"`

	// +kubebuilder:validation:Optional
	ComputedInterval metav1.Duration `json:"computedInterval,omitempty"`

	// +kubebuilder:validation:Optional
	ProcessedAt metav1.Time `json:"processedAt,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.targets[*]`
// +kubebuilder:printcolumn:name="Source",type=string,JSONPath=`.spec.rule.source`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.rule.type`
// +kubebuilder:printcolumn:name="Level",type=string,JSONPath=`.spec.rule.threatLevel`
// +kubebuilder:printcolumn:name="Description",type=string,JSONPath=`.spec.description`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// SecurityEvent is the Schema for the securityevents API
type SecurityEvent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecurityEventSpec   `json:"spec,omitempty"`
	Status SecurityEventStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// SecurityEventList contains a list of SecurityEvent
type SecurityEventList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityEvent `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecurityEvent{}, &SecurityEventList{})
}
