package main

import (
	"context"
	"testing"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The production manager uses this exact scheme for its uncached APIReader.
// A separately assembled test scheme would miss a boot-time registration gap.
func TestProductionSchemeSupportsNamedPolicyCRDRead(t *testing.T) {
	const name = "phorvexpolicies.phorvex.ai"
	if _, _, err := scheme.ObjectKinds(&apiextv1.CustomResourceDefinition{}); err != nil {
		t.Fatalf("production scheme cannot decode CRD: %v", err)
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&apiextv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: name, UID: "uid", ResourceVersion: "17"}}).Build()
	var got apiextv1.CustomResourceDefinition
	if err := reader.Get(context.Background(), client.ObjectKey{Name: name}, &got); err != nil || got.Name != name {
		t.Fatalf("production-scheme named CRD GET failed: %v %+v", err, got.ObjectMeta)
	}
}
