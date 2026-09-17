package ingest

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestM064LocalKVEffectIsNotFullSessionFreshness(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "model", Annotations: map[string]string{
		"phorvex.ai/kv-reset-epoch":        "reset-old",
		"phorvex.ai/kv-migrate-epoch":      "migrate-old",
		"phorvex.ai/kv-local-effect-epoch": "local-new",
	}}}
	projected := projectPod(pod, time.Unix(10, 0))
	if projected.SessionEpoch != "reset-old|migrate-old" {
		t.Fatalf("local-only effect changed full session fingerprint: %q", projected.SessionEpoch)
	}
	if !projected.KVLocalEffectEpoch.Present || projected.KVLocalEffectEpoch.Value != "local-new" {
		t.Fatalf("structured local-effect observation lost: %+v", projected.KVLocalEffectEpoch)
	}
	if !projected.KVResetEpoch.Present || !projected.KVMigrateEpoch.Present {
		t.Fatalf("structured full-session observations lost: reset=%+v migrate=%+v", projected.KVResetEpoch, projected.KVMigrateEpoch)
	}
}
