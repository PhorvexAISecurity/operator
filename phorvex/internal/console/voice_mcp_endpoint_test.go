package console

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestVoiceMCPBotRouteRequiresCanonicalDirectEndpoint(t *testing.T) {
	for _, endpoint := range []string{voiceMCPURL, voiceMCPURL + "/", voiceMCPURL + "?redirect=1", "http://other/mcp"} {
		pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "bot", Env: []corev1.EnvVar{{Name: "MCP_URL", Value: endpoint}}}}}}
		if got := voiceMCPBotRoute(pod); got != (endpoint == voiceMCPURL) {
			t.Fatalf("endpoint %q admitted=%v", endpoint, got)
		}
	}
	pod := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "bot", Env: []corev1.EnvVar{{Name: "MCP_URL", Value: voiceMCPURL}}}}}}
	pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, pod.Spec.Containers[0].Env[0])
	if voiceMCPBotRoute(pod) {
		t.Fatal("ambiguous endpoint admitted")
	}
	pod.Spec.Containers[0].Env = pod.Spec.Containers[0].Env[:1]
	pod.Spec.Containers[0].Env[0].ValueFrom = &corev1.EnvVarSource{}
	if voiceMCPBotRoute(pod) {
		t.Fatal("indirect endpoint admitted")
	}
}
