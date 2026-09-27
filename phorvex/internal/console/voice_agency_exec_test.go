package console

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func agencyExecPod() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "bot-1", UID: "pod-uid",
		Annotations: map[string]string{"phorvex.ai/voice-refund-source-sha256": strings.Repeat("a", 64)}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "bot"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning,
			Conditions:        []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "bot", Ready: true, ContainerID: "containerd://exact", ImageID: "image@sha256:exact"}}}}
}

func TestVoiceAgencyExecBracketsOneExactPodMutation(t *testing.T) {
	pin := voiceAgencyPodPin{Name: "bot-1", UID: "pod-uid", ContainerID: "containerd://exact", ImageID: "image@sha256:exact", SourceSHA256: strings.Repeat("a", 64)}
	for _, tc := range []struct {
		name       string
		before     func(*corev1.Pod)
		after      func(*corev1.Pod)
		invokeErr  error
		wantReads  int
		wantCalls  int
		wantResult bool
	}{
		{name: "exact", wantReads: 2, wantCalls: 1, wantResult: true},
		{name: "reused name before exec", before: func(p *corev1.Pod) { p.UID = "replacement" }, wantReads: 1},
		{name: "restarted container before exec", before: func(p *corev1.Pod) { p.Status.ContainerStatuses[0].RestartCount = 1 }, wantReads: 1},
		{name: "source drift before exec", before: func(p *corev1.Pod) { p.Annotations["phorvex.ai/voice-refund-source-sha256"] = strings.Repeat("b", 64) }, wantReads: 1},
		{name: "replaced after ambiguous exec", after: func(p *corev1.Pod) { p.UID = "replacement" }, wantReads: 2, wantCalls: 1},
		{name: "exec acknowledgement lost", invokeErr: errors.New("lost acknowledgement"), wantReads: 2, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reads, calls := 0, 0
			get := func(_ context.Context, _ string) (*corev1.Pod, error) {
				reads++
				p := agencyExecPod()
				if reads == 1 && tc.before != nil {
					tc.before(p)
				}
				if reads == 2 && tc.after != nil {
					tc.after(p)
				}
				return p, nil
			}
			invoke := func(_ context.Context, _, script string, input []byte) ([]byte, error) {
				calls++
				if script != "fixed-script" || string(input) != `{"run":"owned"}` {
					t.Fatal("probe source/input changed before exact Pod exec")
				}
				return []byte(`{"status":"observed"}`), tc.invokeErr
			}
			answer, err := voiceAgencyRunExactPod(context.Background(), pin, "fixed-script", []byte(`{"run":"owned"}`), get, invoke)
			if reads != tc.wantReads || calls != tc.wantCalls || (err == nil) != tc.wantResult {
				t.Fatalf("reads=%d calls=%d answer=%q err=%v", reads, calls, answer, err)
			}
		})
	}
}

func TestVoiceAgencyExecRejectsUnboundedInputBeforePodRead(t *testing.T) {
	called := false
	get := func(context.Context, string) (*corev1.Pod, error) { called = true; return agencyExecPod(), nil }
	invoke := func(context.Context, string, string, []byte) ([]byte, error) { called = true; return nil, nil }
	_, err := voiceAgencyRunExactPod(context.Background(), voiceAgencyPodPin{}, "fixed-script", []byte(strings.Repeat("x", 128<<10+1)), get, invoke)
	if err == nil || called {
		t.Fatal("unbounded probe input reached Pod")
	}
}

func TestVoiceAgencyExecAllowsPinnedPriorRestart(t *testing.T) {
	pod := agencyExecPod()
	pod.Status.ContainerStatuses[0].RestartCount = 2
	pin := voiceAgencyPodPin{Name: pod.Name, UID: string(pod.UID), ContainerID: "containerd://exact", ImageID: "image@sha256:exact",
		RestartCount: 2, SourceSHA256: strings.Repeat("a", 64)}
	if !voiceAgencyExactPod(pod, pin) {
		t.Fatal("healthy pinned restarted container refused")
	}
	pod.Status.ContainerStatuses[0].RestartCount = 3
	if voiceAgencyExactPod(pod, pin) {
		t.Fatal("restart during scoped operation accepted")
	}
}
