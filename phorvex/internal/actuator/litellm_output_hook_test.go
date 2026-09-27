package actuator

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestLiteOutputPodHookRequiresAllPrivateMountsAndSourcePins(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "litellm-a"}}
	pod.Spec.Volumes = []corev1.Volume{
		{Name: "litellm-output-policy", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "litellm-output-policy"}}}},
		{Name: "litellm-output-document", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "phorvex-litellm-output-document"}}},
		{Name: "litellm-output-prompt", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "phorvex-litellm-output-prompt"}}},
	}
	env := func(name, value string) corev1.EnvVar { return corev1.EnvVar{Name: name, Value: value} }
	pod.Spec.Containers = []corev1.Container{{Name: "litellm-admission-gateway", Env: []corev1.EnvVar{
		env("PHORVEX_LITELLM_OUTPUT_POLICY_FILE", "/etc/phorvex-litellm-output/policy.json"),
		env("PHORVEX_LITELLM_OUTPUT_D_SEED_FILE", "/etc/phorvex-litellm-output-doc/seed"),
		env("PHORVEX_LITELLM_OUTPUT_P_SEED_FILE", "/etc/phorvex-litellm-output-prompt/seed"),
		env("PHORVEX_LITELLM_OUTPUT_D_SECRET_UID", "doc-uid"), env("PHORVEX_LITELLM_OUTPUT_P_SECRET_UID", "prompt-uid"),
		env("PHORVEX_LITELLM_OUTPUT_POLICY_CONFIGMAP_UID", "policy-uid"), env("PHORVEX_LITELLM_OUTPUT_SERVICE_UID", "service-uid"),
		env("PHORVEX_LITELLM_OUTPUT_DEPLOYMENT_UID", "deploy-uid"),
		{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}},
	}, VolumeMounts: []corev1.VolumeMount{
		{Name: "litellm-output-policy", MountPath: "/etc/phorvex-litellm-output", ReadOnly: true},
		{Name: "litellm-output-document", MountPath: "/etc/phorvex-litellm-output-doc", ReadOnly: true},
		{Name: "litellm-output-prompt", MountPath: "/etc/phorvex-litellm-output-prompt", ReadOnly: true},
	}}}
	check := func() bool {
		return liteOutputPodHook(pod, "policy-uid", "service-uid", "deploy-uid", "doc-uid", "prompt-uid")
	}
	if !check() {
		t.Fatal("reviewed hook with POD_UID downward API rejected")
	}
	pod.Spec.Containers[0].VolumeMounts[0].SubPath = "policy.json"
	if check() {
		t.Fatal("subPath prevents policy projection recovery")
	}
	pod.Spec.Containers[0].VolumeMounts[0].SubPath = ""
	pod.Spec.Containers[0].Env[3].Value = "stale-doc"
	if check() {
		t.Fatal("stale private document Secret UID accepted")
	}
}
