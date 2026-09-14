// Package gpudevice owns the source-level interpretation of Kubernetes GPU
// device-plugin evidence shared by ingest and actuation.
package gpudevice

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const migResourcePrefix = "nvidia.com/mig-"

// MIGResourceName returns the canonical NVIDIA MIG extended-resource name
// declared by a Pod. Kubernetes defaults an extended-resource request from its
// limit during admission, but scanning both lists keeps direct construction and
// API-admitted objects consistent. Noncanonical NVIDIA resources are not MIG.
func MIGResourceName(pod *corev1.Pod) string {
	if pod == nil {
		return ""
	}
	names := map[string]struct{}{}
	scan := func(resources corev1.ResourceList) {
		for name := range resources {
			s := string(name)
			if strings.HasPrefix(s, migResourcePrefix) && len(s) > len(migResourcePrefix) {
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
