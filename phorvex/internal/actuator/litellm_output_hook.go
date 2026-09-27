package actuator

import (
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/litellmclient"
	"github.com/phorvex/phorvex/internal/outputpolicy"
)

func liteOutputSecrets(ctx context.Context, reader client.Reader, depUID string) (*corev1.Secret, *corev1.Secret, error) {
	get := func(name string) (*corev1.Secret, error) {
		s := &corev1.Secret{}
		if err := reader.Get(ctx, client.ObjectKey{Namespace: outputpolicy.LiteNamespace, Name: name}, s); err != nil {
			return nil, err
		}
		owner := metav1.GetControllerOf(s)
		if s.DeletionTimestamp != nil || s.Immutable == nil || !*s.Immutable || s.UID == "" || len(s.Data) != 1 || len(s.Data["seed"]) < 32 || len(s.Data["seed"]) > 64 ||
			owner == nil || owner.APIVersion != "apps/v1" || owner.Kind != "Deployment" || owner.Name != "litellm" || string(owner.UID) != depUID {
			return nil, errors.New("LiteLLM output context Secret invalid")
		}
		return s, nil
	}
	document, err := get(outputpolicy.LiteDocumentSecret)
	if err != nil {
		return nil, nil, err
	}
	prompt, err := get(outputpolicy.LitePromptSecret)
	if err != nil {
		return nil, nil, err
	}
	return document, prompt, nil
}

func liteOutputPodHook(p *corev1.Pod, policyUID, serviceUID, depUID, documentUID, promptUID string) bool {
	if p == nil || p.DeletionTimestamp != nil || policyUID == "" || serviceUID == "" || depUID == "" || documentUID == "" || promptUID == "" {
		return false
	}
	volumes := map[string]corev1.VolumeSource{}
	for _, v := range p.Spec.Volumes {
		if _, duplicate := volumes[v.Name]; duplicate {
			return false
		}
		volumes[v.Name] = v.VolumeSource
	}
	if volumes["litellm-output-policy"].ConfigMap == nil || volumes["litellm-output-policy"].ConfigMap.Name != outputpolicy.LitePolicyConfigMap ||
		volumes["litellm-output-document"].Secret == nil || volumes["litellm-output-document"].Secret.SecretName != outputpolicy.LiteDocumentSecret ||
		volumes["litellm-output-prompt"].Secret == nil || volumes["litellm-output-prompt"].Secret.SecretName != outputpolicy.LitePromptSecret ||
		(volumes["litellm-output-policy"].ConfigMap.Optional != nil && *volumes["litellm-output-policy"].ConfigMap.Optional) ||
		(volumes["litellm-output-document"].Secret.Optional != nil && *volumes["litellm-output-document"].Secret.Optional) ||
		(volumes["litellm-output-prompt"].Secret.Optional != nil && *volumes["litellm-output-prompt"].Secret.Optional) {
		return false
	}
	for _, container := range p.Spec.Containers {
		if container.Name != litellmclient.GatewayContainerName {
			continue
		}
		env := map[string]corev1.EnvVar{}
		for _, e := range container.Env {
			if _, present := env[e.Name]; present {
				return false
			}
			env[e.Name] = e
		}
		want := map[string]string{"PHORVEX_LITELLM_OUTPUT_POLICY_FILE": "/etc/phorvex-litellm-output/policy.json",
			"PHORVEX_LITELLM_OUTPUT_D_SEED_FILE":  "/etc/phorvex-litellm-output-doc/seed",
			"PHORVEX_LITELLM_OUTPUT_P_SEED_FILE":  "/etc/phorvex-litellm-output-prompt/seed",
			"PHORVEX_LITELLM_OUTPUT_D_SECRET_UID": documentUID, "PHORVEX_LITELLM_OUTPUT_P_SECRET_UID": promptUID,
			"PHORVEX_LITELLM_OUTPUT_POLICY_CONFIGMAP_UID": policyUID, "PHORVEX_LITELLM_OUTPUT_SERVICE_UID": serviceUID,
			"PHORVEX_LITELLM_OUTPUT_DEPLOYMENT_UID": depUID}
		for key, value := range want {
			if env[key].ValueFrom != nil || env[key].Value != value {
				return false
			}
		}
		mounts := map[string]bool{}
		mountPaths := map[string]bool{}
		for _, m := range container.VolumeMounts {
			if mountPaths[m.MountPath] {
				return false
			}
			mountPaths[m.MountPath] = true
			if m.ReadOnly && m.SubPath == "" && m.SubPathExpr == "" {
				mounts[m.Name+"="+m.MountPath] = true
			}
		}
		return mounts["litellm-output-policy=/etc/phorvex-litellm-output"] &&
			mounts["litellm-output-document=/etc/phorvex-litellm-output-doc"] &&
			mounts["litellm-output-prompt=/etc/phorvex-litellm-output-prompt"]
	}
	return false
}
