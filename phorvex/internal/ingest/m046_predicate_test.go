package ingest

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestM46GPUInfoUsesCanonicalMIGResourceName(t *testing.T) {
	tests := []struct {
		name     string
		resource corev1.ResourceName
		quantity string
		wantGPU  bool
		wantMIG  string
	}{
		{name: "whole GPU", resource: "nvidia.com/gpu", quantity: "1", wantGPU: true},
		{name: "shared whole GPU", resource: "nvidia.com/gpu.shared", quantity: "1", wantGPU: true},
		{name: "exclusive MIG", resource: "nvidia.com/mig-1g.10gb", quantity: "1", wantGPU: true, wantMIG: "nvidia.com/mig-1g.10gb"},
		{name: "exclusive MIG media extension", resource: "nvidia.com/mig-1g.10gb.me", quantity: "1", wantGPU: true, wantMIG: "nvidia.com/mig-1g.10gb.me"},
		{name: "shared MIG remains GPU context", resource: "nvidia.com/mig-1g.10gb.shared", quantity: "1", wantGPU: true},
		{name: "shared MIG media extension remains GPU context", resource: "nvidia.com/mig-1g.10gb.me.shared", quantity: "1", wantGPU: true},
		{name: "zero whole GPU", resource: "nvidia.com/gpu", quantity: "0"},
		{name: "zero MIG", resource: "nvidia.com/mig-1g.10gb", quantity: "0"},
		{name: "unrelated NVIDIA MPS name", resource: "nvidia.com/mps", quantity: "1"},
		{name: "unrelated NVIDIA device", resource: "nvidia.com/unrelated-device", quantity: "1"},
		{name: "GPU-looking unrelated name", resource: "nvidia.com/gpu-migration", quantity: "1"},
		{name: "non-Kubernetes media syntax", resource: "nvidia.com/mig-1g.10gb+me", quantity: "1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{tt.resource: resource.MustParse(tt.quantity)},
				},
			}}}}
			hasGPU, mig := gpuInfo(p)
			if hasGPU != tt.wantGPU {
				t.Errorf("GPU context = %v, want %v", hasGPU, tt.wantGPU)
			}
			if mig != tt.wantMIG {
				t.Errorf("MIG device = %q, want %q", mig, tt.wantMIG)
			}
		})
	}
}
