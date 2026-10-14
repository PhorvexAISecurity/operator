package litellmclient

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func reviewedSourceBytes(t *testing.T, sha string) []byte {
	t.Helper()
	file := "../../../build/test-harness/fixtures/litellm-live/gateway.py"
	if sha == AuthMetricsSourceSHA256 {
		file = "../../../build/test-harness/fixtures/litellm-live/gateway_metrics.py"
	}
	if sha == MetricsSourceSHA256 {
		file = "../../../deploy/helm/phorvex-stack/files/litellm-m1b/gateway-metrics-source-configmap.json"
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if sha == MetricsSourceSHA256 {
		var cm corev1.ConfigMap
		if json.Unmarshal(raw, &cm) != nil || cm.Immutable == nil || !*cm.Immutable || cm.Name != ApprovedSourceConfigMap(sha) || len(cm.Data) != 1 {
			t.Fatal("frozen M1b source ConfigMap differs")
		}
		raw = []byte(cm.Data[SourceKey])
	}
	if SHA256(raw) != sha {
		t.Fatalf("source drift %s: %s", file, SHA256(raw))
	}
	return raw
}

func addAuthMetricsBinding(p *corev1.Pod) {
	group, mode, optional := int64(10001), int32(0440), false
	p.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &group}
	p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: MetricsTokenVolumeName, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
		SecretName: "phorvex-litellm-gateway-metrics-token-v1", Optional: &optional, DefaultMode: &mode, Items: []corev1.KeyToPath{{Key: "token", Path: "token"}},
	}}})
	gateway := &p.Spec.Containers[1]
	gateway.Env = append(gateway.Env, corev1.EnvVar{Name: "PHORVEX_LITELLM_METRICS_ENABLED", Value: "1"},
		corev1.EnvVar{Name: "PHORVEX_LITELLM_METRICS_TOKEN_FILE", Value: MetricsTokenFilePath},
		corev1.EnvVar{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
		corev1.EnvVar{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}})
	gateway.VolumeMounts = append(gateway.VolumeMounts, corev1.VolumeMount{Name: MetricsTokenVolumeName, MountPath: MetricsTokenMountPath, ReadOnly: true})
}

func TestSourceApprovalIsExactAndRuntimeBound(t *testing.T) {
	for _, sha := range []string{ApprovedSourceSHA256, MetricsSourceSHA256, AuthMetricsSourceSHA256} {
		reviewedSourceBytes(t, sha)
		if !ApprovedSource(sha) || ApprovedSourceConfigMap(sha) != "phorvex-litellm-admission-gateway-"+sha[:12] || !ApprovedRuntime(sha, ApprovedRuntimeImage) {
			t.Fatal("reviewed source/runtime rejected")
		}
	}
	for _, sha := range []string{"", strings.Repeat("a", 64), strings.ToUpper(MetricsSourceSHA256), MetricsSourceSHA256[:12] + strings.Repeat("a", 52),
		strings.ToUpper(AuthMetricsSourceSHA256), AuthMetricsSourceSHA256[:12] + strings.Repeat("a", 52)} {
		if ApprovedSource(sha) || ApprovedSourceConfigMap(sha) != "" || ApprovedRuntime(sha, ApprovedRuntimeImage) {
			t.Fatal("unapproved source accepted")
		}
	}
	if ApprovedRuntime(MetricsSourceSHA256, ApprovedGatewayImage) || ApprovedRuntime(AuthMetricsSourceSHA256, ApprovedGatewayImage) || ApprovedRuntime(ApprovedSourceSHA256, "gateway:latest") {
		t.Fatal("unreviewed runtime pair accepted")
	}
}

// Retain the old immutable CM alongside the new one: selection must follow
// verified observed Pods, never whichever approved CM happens to exist first.
func compatibilityFixture(t *testing.T, sha string, image string) client.Client {
	t.Helper()
	ctx := context.Background()
	c, _ := liveFixture(t)
	sourceName := ApprovedSourceConfigMap(sha)
	if sha != ApprovedSourceSHA256 {
		raw := reviewedSourceBytes(t, sha)
		immutable := true
		if err := c.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: Namespace, Name: sourceName, UID: "metrics-source-uid"}, Immutable: &immutable, Data: map[string]string{SourceKey: string(raw)}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"litellm-a", "litellm-b"} {
		p := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: name}, p); err != nil {
			t.Fatal(err)
		}
		p.Annotations[SourceSHAAnnotation] = sha
		p.Annotations[GatewayImageAnnotation] = image
		p.Spec.Containers[1].Image = image
		for i := range p.Spec.Containers[1].Env {
			if p.Spec.Containers[1].Env[i].Name == "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256" {
				p.Spec.Containers[1].Env[i].Value = sha
			}
		}
		p.Spec.Volumes[0].ConfigMap.Name = sourceName
		p.Status.ContainerStatuses[1].ImageID = image
		if sha == AuthMetricsSourceSHA256 {
			addAuthMetricsBinding(p)
		}
		desiredStatus := p.Status.DeepCopy()
		if err := c.Update(ctx, p); err != nil {
			t.Fatal(err)
		}
		p.Status = *desiredStatus
		if err := c.Status().Update(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestLiveOldNewAndInvalidSourceControls(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ name, sha, image string }{
		{"legacy-original-runtime", ApprovedSourceSHA256, ApprovedGatewayImage},
		{"legacy-published-runtime", ApprovedSourceSHA256, ApprovedRuntimeImage},
		{"frozen-m1b-published-runtime", MetricsSourceSHA256, ApprovedRuntimeImage},
		{"auth-metrics-published-runtime", AuthMetricsSourceSHA256, ApprovedRuntimeImage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := compatibilityFixture(t, tc.sha, tc.image)
			live, err := ValidateLive(ctx, c, "pod-a", "pod-b")
			if err != nil || live.SourceSHA256 != tc.sha {
				t.Fatalf("reviewed graph rejected: %+v %v", live, err)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(client.Client)
	}{
		{"mixed-source-convergence", func(c client.Client) {
			p := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-b"}, p)
			p.Annotations[SourceSHAAnnotation] = ApprovedSourceSHA256
			_ = c.Update(ctx, p)
		}},
		{"old-volume-new-annotation", func(c client.Client) {
			p := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-a"}, p)
			p.Spec.Volumes[0].ConfigMap.Name = SourceConfigMapName
			_ = c.Update(ctx, p)
		}},
		{"forged-source-prefix", func(c client.Client) {
			p := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-a"}, p)
			p.Annotations[SourceSHAAnnotation] = MetricsSourceSHA256[:12] + strings.Repeat("a", 52)
			_ = c.Update(ctx, p)
		}},
		{"source-byte-drift", func(c client.Client) {
			cm := &corev1.ConfigMap{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: ApprovedSourceConfigMap(AuthMetricsSourceSHA256)}, cm)
			cm.Data[SourceKey] += "\n"
			_ = c.Update(ctx, cm)
		}},
		{"source-key-remap", func(c client.Client) {
			p := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-a"}, p)
			p.Spec.Volumes[0].ConfigMap.Items = []corev1.KeyToPath{{Key: SourceKey, Path: "other.py"}}
			_ = c.Update(ctx, p)
		}},
		{"duplicate-source-env", func(c client.Client) {
			p := &corev1.Pod{}
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-a"}, p)
			p.Spec.Containers[1].Env = append(p.Spec.Containers[1].Env, corev1.EnvVar{Name: "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256", Value: ApprovedSourceSHA256})
			_ = c.Update(ctx, p)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := compatibilityFixture(t, AuthMetricsSourceSHA256, ApprovedRuntimeImage)
			tc.mutate(c)
			if _, err := ValidateLive(ctx, c, "pod-a", "pod-b"); err == nil {
				t.Fatal("invalid graph accepted")
			}
		})
	}
	if _, err := ValidateLive(ctx, compatibilityFixture(t, AuthMetricsSourceSHA256, ApprovedGatewayImage), "pod-a", "pod-b"); err == nil {
		t.Fatal("metrics on original runtime accepted")
	}
}

func TestConsolePodSourceBindingRejectsStaleVolumeAndCommand(t *testing.T) {
	ctx := context.Background()
	for _, sha := range []string{ApprovedSourceSHA256, MetricsSourceSHA256, AuthMetricsSourceSHA256} {
		c := compatibilityFixture(t, sha, ApprovedRuntimeImage)
		pod := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-a"}, pod); err != nil {
			t.Fatal(err)
		}
		if err := ValidateGatewaySourceBinding(pod, sha, ApprovedRuntimeImage); err != nil {
			t.Fatal(err)
		}
		bad := pod.DeepCopy()
		bad.Spec.Containers[1].Command = []string{"python3", "-c", "unreviewed"}
		if err := ValidateGatewaySourceBinding(bad, sha, ApprovedRuntimeImage); err == nil {
			t.Fatal("alternate executable accepted")
		}
		shadow := pod.DeepCopy()
		shadow.Spec.Containers[1].VolumeMounts = append(shadow.Spec.Containers[1].VolumeMounts, corev1.VolumeMount{Name: "shadow", MountPath: "/opt/phorvex/gateway.py", ReadOnly: true})
		if err := ValidateGatewaySourceBinding(shadow, sha, ApprovedRuntimeImage); err == nil {
			t.Fatal("shadowed executable accepted")
		}

		bad = pod.DeepCopy()
		bad.Spec.Volumes[0].ConfigMap.Name = "other-source"
		if err := ValidateGatewaySourceBinding(bad, sha, ApprovedRuntimeImage); err == nil {
			t.Fatal("unreviewed source volume accepted")
		}
	}
}

func TestAuthMetricsBindingRejectsUnsafeProjectionAndContradictoryOptIn(t *testing.T) {
	ctx := context.Background()
	c := compatibilityFixture(t, AuthMetricsSourceSHA256, ApprovedRuntimeImage)
	good := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-a"}, good); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateLive(ctx, c, "pod-a", "pod-b"); err != nil {
		t.Fatal(err)
	}
	setEnv := func(p *corev1.Pod, name string, entry corev1.EnvVar) {
		for i := range p.Spec.Containers[1].Env {
			if p.Spec.Containers[1].Env[i].Name == name {
				entry.Name = name
				p.Spec.Containers[1].Env[i] = entry
				return
			}
		}
		t.Fatal("fixture environment absent")
	}
	token := func(p *corev1.Pod) *corev1.SecretVolumeSource { return p.Spec.Volumes[len(p.Spec.Volumes)-1].Secret }
	mount := func(p *corev1.Pod) *corev1.VolumeMount {
		mounts := p.Spec.Containers[1].VolumeMounts
		return &mounts[len(mounts)-1]
	}
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Pod)
	}{
		{"opt-in-zero-no-rotation-state", func(p *corev1.Pod) { setEnv(p, "PHORVEX_LITELLM_METRICS_ENABLED", corev1.EnvVar{Value: "0"}) }},
		{"opt-in-absent", func(p *corev1.Pod) { setEnv(p, "PHORVEX_LITELLM_METRICS_ENABLED", corev1.EnvVar{}) }},
		{"opt-in-value-from", func(p *corev1.Pod) {
			setEnv(p, "PHORVEX_LITELLM_METRICS_ENABLED", corev1.EnvVar{ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{Key: "enabled"}}})
		}},
		{"wrong-token-file", func(p *corev1.Pod) {
			setEnv(p, "PHORVEX_LITELLM_METRICS_TOKEN_FILE", corev1.EnvVar{Value: "/other/token"})
		}},
		{"absent-token-file", func(p *corev1.Pod) { setEnv(p, "PHORVEX_LITELLM_METRICS_TOKEN_FILE", corev1.EnvVar{}) }},
		{"duplicate-token-env", func(p *corev1.Pod) {
			p.Spec.Containers[1].Env = append(p.Spec.Containers[1].Env, corev1.EnvVar{Name: "PHORVEX_LITELLM_METRICS_TOKEN_FILE", Value: MetricsTokenFilePath})
		}},
		{"envFrom-shadow", func(p *corev1.Pod) {
			p.Spec.Containers[1].EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "unreviewed"}}}}
		}},
		{"literal-pod-identity", func(p *corev1.Pod) { setEnv(p, "POD_NAME", corev1.EnvVar{Value: p.Name}) }},
		{"wrong-pod-field", func(p *corev1.Pod) {
			setEnv(p, "POD_NAMESPACE", corev1.EnvVar{ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}})
		}},
		{"missing-fsGroup", func(p *corev1.Pod) { p.Spec.SecurityContext = nil }},
		{"wrong-fsGroup", func(p *corev1.Pod) { *p.Spec.SecurityContext.FSGroup = 10002 }},
		{"optional-secret", func(p *corev1.Pod) { *token(p).Optional = true }},
		{"implicit-optional", func(p *corev1.Pod) { token(p).Optional = nil }},
		{"missing-secret-ref", func(p *corev1.Pod) { token(p).SecretName = "" }},
		{"default-file-mode", func(p *corev1.Pod) { token(p).DefaultMode = nil }},
		{"world-readable-file", func(p *corev1.Pod) { *token(p).DefaultMode = 0444 }},
		{"item-mode-override", func(p *corev1.Pod) { mode := int32(0644); token(p).Items[0].Mode = &mode }},
		{"wrong-secret-key", func(p *corev1.Pod) { token(p).Items[0].Key = "credential" }},
		{"wrong-projected-path", func(p *corev1.Pod) { token(p).Items[0].Path = "other/token" }},
		{"whole-secret-projection", func(p *corev1.Pod) { token(p).Items = nil }},
		{"additional-secret-key", func(p *corev1.Pod) {
			token(p).Items = append(token(p).Items, corev1.KeyToPath{Key: "extra", Path: "extra"})
		}},
		{"duplicate-token-volume", func(p *corev1.Pod) { p.Spec.Volumes = append(p.Spec.Volumes, p.Spec.Volumes[len(p.Spec.Volumes)-1]) }},
		{"alias-token-volume", func(p *corev1.Pod) {
			alias := p.Spec.Volumes[len(p.Spec.Volumes)-1]
			alias.Name = "alias"
			p.Spec.Volumes = append(p.Spec.Volumes, alias)
		}},
		{"missing-token-volume", func(p *corev1.Pod) { p.Spec.Volumes = p.Spec.Volumes[:len(p.Spec.Volumes)-1] }},
		{"writable-token-mount", func(p *corev1.Pod) { mount(p).ReadOnly = false }},
		{"wrong-token-mount", func(p *corev1.Pod) { mount(p).MountPath = "/other/token" }},
		{"subPath-token-mount", func(p *corev1.Pod) { mount(p).SubPath = "token" }},
		{"subPathExpr-token-mount", func(p *corev1.Pod) { mount(p).SubPathExpr = "$(POD_NAME)" }},
		{"duplicate-token-mount", func(p *corev1.Pod) {
			p.Spec.Containers[1].VolumeMounts = append(p.Spec.Containers[1].VolumeMounts, *mount(p))
		}},
		{"child-shadow", func(p *corev1.Pod) {
			p.Spec.Containers[1].VolumeMounts = append(p.Spec.Containers[1].VolumeMounts, corev1.VolumeMount{Name: "shadow", MountPath: MetricsTokenFilePath})
		}},
		{"parent-shadow", func(p *corev1.Pod) {
			p.Spec.Containers[1].VolumeMounts = append(p.Spec.Containers[1].VolumeMounts, corev1.VolumeMount{Name: "shadow", MountPath: "/etc"})
		}},
		{"backend-token-access", func(p *corev1.Pod) { p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{*mount(p)} }},
		{"init-token-access", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: "init", VolumeMounts: []corev1.VolumeMount{*mount(p)}}}
		}},
		{"ephemeral-token-access", func(p *corev1.Pod) {
			p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", VolumeMounts: []corev1.VolumeMount{*mount(p)}}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := good.DeepCopy()
			tc.mutate(bad)
			if err := ValidateGatewaySourceBinding(bad, AuthMetricsSourceSHA256, ApprovedRuntimeImage); err == nil {
				t.Fatal("unsafe metrics binding accepted")
			}
			if err := c.Update(ctx, bad); err != nil {
				t.Fatal(err)
			}
			if _, err := ValidateLive(ctx, c, "pod-a", "pod-b"); err == nil {
				t.Fatal("native observation accepted unsafe metrics binding")
			}
			good.ResourceVersion = bad.ResourceVersion
			if err := c.Update(ctx, good); err != nil {
				t.Fatal(err)
			}
		})
	}
}
