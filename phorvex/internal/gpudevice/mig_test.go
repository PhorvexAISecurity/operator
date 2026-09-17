package gpudevice

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func gpuResourcePod(list string, name corev1.ResourceName, quantity string) *corev1.Pod {
	requirements := corev1.ResourceRequirements{}
	resources := corev1.ResourceList{name: resource.MustParse(quantity)}
	if list == "requests" {
		requirements.Requests = resources
	} else {
		requirements.Limits = resources
	}
	return &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Resources: requirements}}}}
}

func TestGPUResourceEvidenceRequiresSupportedNameAndPositiveQuantity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resource corev1.ResourceName
		quantity string
		want     bool
	}{
		{"whole", "nvidia.com/gpu", "1", true},
		{"shared-whole", "nvidia.com/gpu.shared", "1", true},
		{"mig", "nvidia.com/mig-1g.10gb", "1", true},
		{"mig-media-extension", "nvidia.com/mig-1g.10gb.me", "1", true},
		{"shared-mig", "nvidia.com/mig-1g.10gb.shared", "1", true},
		{"shared-mig-media-extension", "nvidia.com/mig-1g.10gb.me.shared", "1", true},
		{"zero", "nvidia.com/gpu", "0", false},
		{"unrelated-domain-resource", "nvidia.com/mps", "1", false},
		{"unrelated-device", "nvidia.com/unrelated-device", "1", false},
		{"lookalike", "nvidia.com/gpu-migration", "1", false},
		{"non-kubernetes-media-syntax", "nvidia.com/mig-1g.10gb+me", "1", false},
	} {
		for _, list := range []string{"requests", "limits"} {
			t.Run(tc.name+"/"+list, func(t *testing.T) {
				if got := HasGPUResource(gpuResourcePod(list, tc.resource, tc.quantity)); got != tc.want {
					t.Fatalf("HasGPUResource = %v, want %v", got, tc.want)
				}
			})
		}
	}
}

func TestMIGResourceNameRequiresPositiveExclusiveProfile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resource corev1.ResourceName
		quantity string
		want     string
	}{
		{"exclusive", "nvidia.com/mig-1g.10gb", "1", "nvidia.com/mig-1g.10gb"},
		{"media-extension", "nvidia.com/mig-1g.10gb.me", "1", "nvidia.com/mig-1g.10gb.me"},
		{"zero", "nvidia.com/mig-1g.10gb", "0", ""},
		{"shared", "nvidia.com/mig-1g.10gb.shared", "1", ""},
		{"shared-media-extension", "nvidia.com/mig-1g.10gb.me.shared", "1", ""},
		{"non-kubernetes-media-syntax", "nvidia.com/mig-1g.10gb+me", "1", ""},
		{"malformed", "nvidia.com/mig-profile", "1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MIGResourceName(gpuResourcePod("requests", tc.resource, tc.quantity)); got != tc.want {
				t.Fatalf("MIGResourceName = %q, want %q", got, tc.want)
			}
		})
	}
}
