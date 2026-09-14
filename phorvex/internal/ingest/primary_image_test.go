package ingest

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// M-173: PodInfo.ImageID is the running digest of the PRIMARY container (spec container 0),
// resolved in Status.ContainerStatuses by exact Name. The kubelet does not promise that the
// status slice is in spec order, so a positional read carries a sidecar digest into the
// image-rarity and EPSS consumers. Absence (no spec container/name, no matching status, or an
// empty matching ImageID) stays "" — never a sidecar digest and never the declared tag.
const (
	primaryDigest  = "docker.io/vllm/vllm-openai@sha256:4f4037303e8c7b69439db1077bb849a0823517c0f785b894dc8e96d58ef3a0c2"
	sidecarDigest  = "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
	logDigest      = "docker.io/fluent/fluent-bit@sha256:0b7f0b4f5c6e3a2d1c9b8a7f6e5d4c3b2a1908f7e6d5c4b3a2918f7e6d5c4b3a2"
	prefixedDigest = "docker-pullable://" + primaryDigest
)

func primaryImagePod(spec []corev1.Container, statuses []corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "vllm-77d4b5fc5f-d5j5m", Namespace: "vllm"},
		Spec:       corev1.PodSpec{Containers: spec},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: statuses},
	}
}

func TestProjectPodPrimaryImageMatchesSpecContainerByName(t *testing.T) {
	appMesh := []corev1.Container{
		{Name: "vllm", Image: "vllm/vllm-openai:v0.7.3"},
		{Name: "guardrail", Image: "python:3.11-slim"},
	}
	appMeshLog := append(append([]corev1.Container{}, appMesh...), corev1.Container{Name: "log", Image: "fluent/fluent-bit:3.1"})
	status := func(name, id string) corev1.ContainerStatus {
		return corev1.ContainerStatus{Name: name, ImageID: id}
	}
	cases := []struct {
		name     string
		spec     []corev1.Container
		statuses []corev1.ContainerStatus
		want     string
	}{
		// Positive controls: spec order and status order agree.
		{"aligned-status-order", appMesh, []corev1.ContainerStatus{status("vllm", primaryDigest), status("guardrail", sidecarDigest)}, primaryDigest},
		{"aligned-runtime-prefixed-digest", appMesh, []corev1.ContainerStatus{status("vllm", prefixedDigest), status("guardrail", sidecarDigest)}, prefixedDigest},
		// The incident: the sidecar status is reported first.
		{"reversed-status-order", appMesh, []corev1.ContainerStatus{status("guardrail", sidecarDigest), status("vllm", primaryDigest)}, primaryDigest},
		{"multi-sidecar-primary-last", appMeshLog, []corev1.ContainerStatus{status("log", logDigest), status("guardrail", sidecarDigest), status("vllm", primaryDigest)}, primaryDigest},
		{"reversed-runtime-prefixed-digest", appMesh, []corev1.ContainerStatus{status("guardrail", sidecarDigest), status("vllm", prefixedDigest)}, prefixedDigest},
		// Explicit absence: the primary's running identity is unknown even when a sidecar's is not.
		{"primary-status-imageid-empty", appMesh, []corev1.ContainerStatus{status("guardrail", sidecarDigest), status("vllm", "")}, ""},
		{"primary-status-missing", appMesh, []corev1.ContainerStatus{status("guardrail", sidecarDigest)}, ""},
		{"no-statuses-declared-tag-is-not-running-identity", appMesh, nil, ""},
		{"no-spec-containers", nil, []corev1.ContainerStatus{status("guardrail", sidecarDigest)}, ""},
		{"spec-primary-name-empty", []corev1.Container{{Name: "", Image: "vllm/vllm-openai:v0.7.3"}}, []corev1.ContainerStatus{status("", primaryDigest)}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := primaryImagePod(tc.spec, tc.statuses)
			got := projectPod(pod, time.Unix(1_789_070_400, 0)).ImageID
			t.Logf("spec primary=%q statuses=%v projected=%q want=%q", specPrimaryName(pod), statusNames(pod), got, tc.want)
			if got != tc.want {
				t.Errorf("ImageID = %q, want %q", got, tc.want)
			}
		})
	}
}

func specPrimaryName(p *corev1.Pod) string {
	if len(p.Spec.Containers) == 0 {
		return "<none>"
	}
	return p.Spec.Containers[0].Name
}

func statusNames(p *corev1.Pod) []string {
	out := make([]string, 0, len(p.Status.ContainerStatuses))
	for _, cs := range p.Status.ContainerStatuses {
		out = append(out, cs.Name)
	}
	return out
}
