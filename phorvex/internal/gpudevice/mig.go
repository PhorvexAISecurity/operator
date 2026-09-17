// Package gpudevice owns the source-level interpretation of Kubernetes GPU
// device-plugin evidence shared by ingest and actuation.
package gpudevice

import (
	"regexp"
	"sort"

	corev1 "k8s.io/api/core/v1"
)

const (
	gpuResource       = "nvidia.com/gpu"
	sharedGPUResource = "nvidia.com/gpu.shared"
	migResourcePrefix = "nvidia.com/mig-"
)

var (
	migResourcePattern       = regexp.MustCompile(`^` + regexp.QuoteMeta(migResourcePrefix) + `[0-9]+g\.[0-9]+gb(?:\.me)?$`)
	sharedMIGResourcePattern = regexp.MustCompile(`^` + regexp.QuoteMeta(migResourcePrefix) + `[0-9]+g\.[0-9]+gb(?:\.me)?\.shared$`)
)

// IsGPUResourceName recognizes the NVIDIA device-plugin's built-in names for whole
// GPUs, exclusive MIG profiles, and their renameByDefault shared variants. Arbitrary
// configured aliases need a separate trusted mapping; a name in the nvidia.com domain
// alone is not structural GPU evidence.
func IsGPUResourceName(name corev1.ResourceName) bool {
	s := string(name)
	return s == gpuResource || s == sharedGPUResource ||
		migResourcePattern.MatchString(s) || sharedMIGResourcePattern.MatchString(s)
}

// HasGPUResource reports whether a Pod has a positive request or limit for a
// supported NVIDIA GPU resource. This is declaration evidence, not proof of a
// runtime physical allocation; zero-valued map entries establish no context.
func HasGPUResource(pod *corev1.Pod) bool {
	if pod == nil {
		return false
	}
	for i := range pod.Spec.Containers {
		for _, resources := range []corev1.ResourceList{
			pod.Spec.Containers[i].Resources.Requests,
			pod.Spec.Containers[i].Resources.Limits,
		} {
			for name, quantity := range resources {
				if quantity.Sign() > 0 && IsGPUResourceName(name) {
					return true
				}
			}
		}
	}
	return false
}

// MIGResourceName returns the canonical NVIDIA MIG extended-resource name
// positively requested or limited by a Pod. Kubernetes defaults an extended-resource
// request from its limit during admission, but scanning both lists keeps direct
// construction and API-admitted objects consistent. Shared and noncanonical NVIDIA
// resources establish no exclusive MIG identity for destructive rebind operations.
func MIGResourceName(pod *corev1.Pod) string {
	if pod == nil {
		return ""
	}
	names := map[string]struct{}{}
	scan := func(resources corev1.ResourceList) {
		for name, quantity := range resources {
			s := string(name)
			if quantity.Sign() > 0 && migResourcePattern.MatchString(s) {
				names[s] = struct{}{}
			}
		}
	}
	for i := range pod.Spec.Containers {
		scan(pod.Spec.Containers[i].Resources.Requests)
		scan(pod.Spec.Containers[i].Resources.Limits)
	}
	if len(names) == 0 {
		return ""
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	return ordered[0]
}
