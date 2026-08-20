package platform

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

func TestTerminalPodsDoNotContaminateRunningFleetPhysics(t *testing.T) {
	node := ingest.NodeInfo{
		Name: "n1", AllocatableCPUMilli: 4000, AllocatableMemBytes: 8 << 30,
	}
	running := []model.Pod{
		{Namespace: "a", Name: "p1", Node: "n1", Phase: string(corev1.PodRunning), ImageID: "img-a", ModelID: "model-a", CPURequestMilli: 500, MemRequestBytes: 1 << 30},
		{Namespace: "b", Name: "p2", Node: "n1", Phase: string(corev1.PodRunning), ImageID: "img-b", ModelID: "model-b", CPURequestMilli: 500, MemRequestBytes: 1 << 30},
	}
	baseline := (genericK8s{}).Derive(&ingest.Snapshot{Nodes: []ingest.NodeInfo{node}, Pods: running})

	withHistory := append([]model.Pod(nil), running...)
	withHistory = append(withHistory,
		model.Pod{Namespace: "old-success", Name: "job", Node: "n1", Phase: string(corev1.PodSucceeded), ImageID: "img-a", ModelID: "model-a", CPURequestMilli: 3000, MemRequestBytes: 6 << 30},
		model.Pod{Namespace: "old-failure", Name: "job", Node: "n1", Phase: string(corev1.PodFailed), ImageID: "img-a", ModelID: "model-a", CPURequestMilli: 3000, MemRequestBytes: 6 << 30},
	)
	got := (genericK8s{}).Derive(&ingest.Snapshot{Nodes: []ingest.NodeInfo{node}, Pods: withHistory})

	for _, key := range []string{"a/p1", "b/p2"} {
		if !reflect.DeepEqual(got[key], baseline[key]) {
			t.Fatalf("%s witness changed when terminal pods were added:\n baseline=%+v\n got=%+v", key, baseline[key], got[key])
		}
	}
}
