package litellmclient

import (
	"context"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSourceApprovalIsExactAndRuntimeBound(t *testing.T) {
	for _, tc := range []struct{ file, sha string }{{"gateway.py", ApprovedSourceSHA256}, {"gateway_metrics.py", MetricsSourceSHA256}} {
		raw, err := os.ReadFile("../../../build/test-harness/fixtures/litellm-live/" + tc.file)
		if err != nil || SHA256(raw) != tc.sha {
			t.Fatalf("source drift %s: %v", tc.file, err)
		}
		if !ApprovedSource(tc.sha) || ApprovedSourceConfigMap(tc.sha) != "phorvex-litellm-admission-gateway-"+tc.sha[:12] || !ApprovedRuntime(tc.sha, ApprovedRuntimeImage) {
			t.Fatal("reviewed source/runtime rejected")
		}
	}
	for _, sha := range []string{"", strings.Repeat("a", 64), strings.ToUpper(MetricsSourceSHA256), MetricsSourceSHA256[:12] + strings.Repeat("a", 52)} {
		if ApprovedSource(sha) || ApprovedSourceConfigMap(sha) != "" || ApprovedRuntime(sha, ApprovedRuntimeImage) {
			t.Fatal("unapproved source accepted")
		}
	}
	if ApprovedRuntime(MetricsSourceSHA256, ApprovedGatewayImage) || ApprovedRuntime(ApprovedSourceSHA256, "gateway:latest") {
		t.Fatal("unreviewed runtime pair accepted")
	}
}

// Retain the old immutable CM alongside the new one: selection must follow
// verified observed Pods, never whichever approved CM happens to exist first.
func compatibilityFixture(t *testing.T, metrics bool, image string) client.Client {
	t.Helper()
	ctx := context.Background()
	c, _ := liveFixture(t)
	sha, sourceName := ApprovedSourceSHA256, SourceConfigMapName
	if metrics {
		raw, err := os.ReadFile("../../../build/test-harness/fixtures/litellm-live/gateway_metrics.py")
		if err != nil {
			t.Fatal(err)
		}
		sha, sourceName = MetricsSourceSHA256, ApprovedSourceConfigMap(MetricsSourceSHA256)
		immutable := true
		if err = c.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: Namespace, Name: sourceName, UID: "metrics-source-uid"}, Immutable: &immutable, Data: map[string]string{SourceKey: string(raw)}}); err != nil {
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
		if err := c.Update(ctx, p); err != nil {
			t.Fatal(err)
		}
		if err := c.Status().Update(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func TestLiveOldNewAndInvalidSourceControls(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		metrics bool
		image   string
	}{{"legacy-original-runtime", false, ApprovedGatewayImage}, {"legacy-published-runtime", false, ApprovedRuntimeImage}, {"metrics-published-runtime", true, ApprovedRuntimeImage}} {
		t.Run(tc.name, func(t *testing.T) {
			c := compatibilityFixture(t, tc.metrics, tc.image)
			live, err := ValidateLive(ctx, c, "pod-a", "pod-b")
			want := ApprovedSourceSHA256
			if tc.metrics {
				want = MetricsSourceSHA256
			}
			if err != nil || live.SourceSHA256 != want {
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
			_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: ApprovedSourceConfigMap(MetricsSourceSHA256)}, cm)
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
			c := compatibilityFixture(t, true, ApprovedRuntimeImage)
			tc.mutate(c)
			if _, err := ValidateLive(ctx, c, "pod-a", "pod-b"); err == nil {
				t.Fatal("invalid graph accepted")
			}
		})
	}
	if _, err := ValidateLive(ctx, compatibilityFixture(t, true, ApprovedGatewayImage), "pod-a", "pod-b"); err == nil {
		t.Fatal("metrics on original runtime accepted")
	}
}

func TestConsolePodSourceBindingRejectsStaleVolumeAndCommand(t *testing.T) {
	ctx := context.Background()
	for _, metrics := range []bool{false, true} {
		c := compatibilityFixture(t, metrics, ApprovedRuntimeImage)
		pod := &corev1.Pod{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "litellm-a"}, pod); err != nil {
			t.Fatal(err)
		}
		sha := pod.Annotations[SourceSHAAnnotation]
		if err := ValidateGatewaySourceBinding(pod, sha, ApprovedRuntimeImage); err != nil {
			t.Fatal(err)
		}
		bad := pod.DeepCopy()
		bad.Spec.Containers[1].Command = []string{"python3", "-c", "unreviewed"}
		if err := ValidateGatewaySourceBinding(bad, sha, ApprovedRuntimeImage); err == nil {
			t.Fatal("alternate executable accepted")
		}
		bad = pod.DeepCopy()
		bad.Spec.Volumes[0].ConfigMap.Name = "other-source"
		if err := ValidateGatewaySourceBinding(bad, sha, ApprovedRuntimeImage); err == nil {
			t.Fatal("unreviewed source volume accepted")
		}
	}
}
