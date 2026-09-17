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
	if !got.ServingEndpointReady || got.RouteService != "infer" || got.GuardrailVariants != 2 || got.ParallelSize != 2 {
		t.Fatalf("capability projection = %+v", got)
	}
}

func TestServingEndpointReadyProducerMatrix(t *testing.T) {
	for _, tc := range []struct {
		name                                                 string
		gpu, model, port, ready, ip, wantDeclared, wantReady bool
	}{
		{"cpu-model", false, true, false, true, true, true, true},
		{"cpu-port", false, false, true, true, true, true, true},
		{"gpu-batch", true, false, false, true, true, false, false},
		{"plain", false, false, false, true, true, false, false},
		{"declared-unready", false, true, false, false, true, true, false},
		{"declared-missing-ip", false, true, false, true, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ann := map[string]string{}
			if tc.model {
				ann["phorvex.ai/model-id"] = "m"
			}
			if tc.port {
				ann["phorvex.ai/serving-port"] = "8000"
			}
			p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: ann}, Status: corev1.PodStatus{}}
			if tc.ip {
				p.Status.PodIP = "10.0.0.2"
			}
			if tc.ready {
				p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
			}
			if tc.gpu {
				p.Spec.Containers = []corev1.Container{{Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{"nvidia.com/gpu": resource.MustParse("1")}}}}
			}
			got := projectPod(p, time.Unix(10, 0))
			if got.ServingDeclared != tc.wantDeclared || got.ServingEndpointReady != tc.wantReady {
				t.Fatalf("declared=%v ready=%v, want declared=%v ready=%v", got.ServingDeclared, got.ServingEndpointReady, tc.wantDeclared, tc.wantReady)
			}
		})
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
