package ingest

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestProjectPodCapabilityWitnesses(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "inference", Annotations: map[string]string{
			"phorvex.ai/model-id": "model", "phorvex.ai/route-service": "infer",
			"phorvex.ai/parallel-size":      "2",
			"phorvex.ai/gpu-id":             "0",
			"phorvex.ai/mig-target-profile": "2g.20gb",
			"phorvex.ai/guardrail-variant":  "v1", "phorvex.ai/guardrail-variants": "v1, v2, v2",
		}},
		Status: corev1.PodStatus{PodIP: "10.0.0.2", Conditions: []corev1.PodCondition{{
			Type: corev1.PodReady, Status: corev1.ConditionTrue,
		}}},
	}
	got := projectPod(pod, time.Unix(10, 0))
	if !got.ServingEndpointReady || got.RouteService != "infer" || got.GuardrailVariants != 2 || got.ParallelSize != 2 ||
		got.MIGGPUID != "0" || got.MIGTargetProfile != "2g.20gb" {
		t.Fatalf("capability projection = %+v", got)
	}
}

func TestProjectPodInvalidParallelSizeIsUnavailable(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{
		"phorvex.ai/parallel-size": "not-a-number",
	}}}
	if got := projectPod(pod, time.Unix(10, 0)).ParallelSize; got != 0 {
		t.Fatalf("invalid parallel-size projected as %d, want 0", got)
	}
}

func TestCollectNodeAndServiceCapabilities(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "gpu-a"},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{corev1.ResourceName("nvidia.com/gpu"): resource.MustParse("1")},
			Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "infer"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "infer", "phorvex.ai/serving": "true"}},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(node, service).Build()
	nodes := collectNodes(context.Background(), client)
	services := collectServices(context.Background(), client)
	if len(nodes) != 1 || !nodes[0].Schedulable || nodes[0].AllocatableGPU != 1 {
		t.Fatalf("node projection = %+v", nodes)
	}
	if len(services) != 1 || services[0].Selector["phorvex.ai/serving"] != "true" {
		t.Fatalf("service projection = %+v", services)
	}
}
