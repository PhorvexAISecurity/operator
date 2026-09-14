package ingest

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestM46GPUInfoUsesCanonicalMIGResourceName(t *testing.T) {
	tests := []struct {
		name    corev1.ResourceName
		wantMIG string
	}{
		{name: "nvidia.com/mig-1g.10gb", wantMIG: "nvidia.com/mig-1g.10gb"},
		{name: "nvidia.com/mps", wantMIG: ""},
		{name: "nvidia.com/gpu-migration", wantMIG: ""},
	}
	for _, tt := range tests {
		p := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Resources: corev1.ResourceRequirements{
				Limits: corev1.ResourceList{tt.name: resource.MustParse("1")},
			},
		}}}}
		hasGPU, mig := gpuInfo(p)
		if !hasGPU {
			t.Fatalf("%s: NVIDIA resource must still establish GPU context", tt.name)
		}
		if mig != tt.wantMIG {
			t.Errorf("%s: MIG device = %q, want %q", tt.name, mig, tt.wantMIG)
		}
	}
}
