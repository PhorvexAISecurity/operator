package ingest

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestProjectPodCarriesReadyTransitionTime(t *testing.T) {
	readyAt := time.Unix(1_700_000_060, 0).UTC()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "replacement", Namespace: "ns"},
		Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{
			Type: corev1.PodReady, Status: corev1.ConditionTrue,
			LastTransitionTime: metav1.NewTime(readyAt),
		}}},
	}
	got := projectPod(pod, readyAt.Add(time.Minute))
	if !got.Ready || !got.ReadyAt.Equal(readyAt) {
		t.Fatalf("projected Ready state = (%v, %s), want (true, %s)", got.Ready, got.ReadyAt, readyAt)
	}
}
