/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package v1alpha1 contains the API schema for the Phorvex MVP (P0) control
// surface. The single P0 kind is PhorvexPolicy — a PER-TENANT policy object
// (namespace-scoped from line one so vcluster multi-tenancy is not a retrofit).
// +kubebuilder:object:generate=true
// +groupName=phorvex.ai
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the group/version for the Phorvex API (per the PRD:
	// apiVersion: phorvex.ai/v1alpha1).
	GroupVersion = schema.GroupVersion{Group: "phorvex.ai", Version: "v1alpha1"}

	// SchemeBuilder registers the Phorvex Go types with a runtime.Scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the Phorvex types to a given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
