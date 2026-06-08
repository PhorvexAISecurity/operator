package capability

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func node(name string, ready, unschedulable bool, alloc map[corev1.ResourceName]string, labels map[string]string) corev1.Node {
	al := corev1.ResourceList{}
	for k, v := range alloc {
		al[k] = resource.MustParse(v)
	}
	cond := corev1.NodeCondition{Type: corev1.NodeReady, Status: corev1.ConditionFalse}
	if ready {
		cond.Status = corev1.ConditionTrue
	}
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec:       corev1.NodeSpec{Unschedulable: unschedulable},
		Status: corev1.NodeStatus{
			Allocatable: al,
			Conditions:  []corev1.NodeCondition{cond},
		},
	}
}

func TestSingleCPUNode(t *testing.T) {
	// Mirrors the live kind cluster: one ready, schedulable, no-GPU node.
	nodes := []corev1.Node{node("amtd-test-control-plane", true, false, nil, nil)}
	caps := DetectFromNodes(nodes)
	if caps.GPU || caps.MIG || caps.MultiNode {
		t.Fatalf("single CPU node must have no caps: %+v", caps)
	}
	if caps.NodeCount != 1 {
		t.Fatalf("node count want 1 got %d", caps.NodeCount)
	}
}

func TestGPUDetection(t *testing.T) {
	nodes := []corev1.Node{
		node("gpu-1", true, false, map[corev1.ResourceName]string{"nvidia.com/gpu": "4"}, nil),
	}
	caps := DetectFromNodes(nodes)
	if !caps.GPU {
		t.Fatalf("expected GPU detected")
	}
	if caps.MIG {
		t.Fatalf("plain GPU node must not be MIG")
	}
}

func TestGPUZeroAllocatableNotDetected(t *testing.T) {
	nodes := []corev1.Node{
		node("gpu-0", true, false, map[corev1.ResourceName]string{"nvidia.com/gpu": "0"}, nil),
	}
	caps := DetectFromNodes(nodes)
	if caps.GPU {
		t.Fatalf("zero-allocatable GPU must not count as GPU")
	}
}

func TestMIGDetection(t *testing.T) {
	nodes := []corev1.Node{
		node("mig-1", true, false, map[corev1.ResourceName]string{"nvidia.com/mig-1g.5gb": "7"}, nil),
	}
	caps := DetectFromNodes(nodes)
	if !caps.MIG || !caps.GPU {
		t.Fatalf("MIG resource must set MIG and GPU: %+v", caps)
	}
}

func TestMIGLabelDetection(t *testing.T) {
	nodes := []corev1.Node{
		node("mig-2", true, false, nil, map[string]string{"nvidia.com/mig.strategy": "single"}),
	}
	caps := DetectFromNodes(nodes)
	if !caps.MIG {
		t.Fatalf("MIG strategy label must set MIG")
	}
}

func TestMultiNodeCountsOnlySchedulable(t *testing.T) {
	nodes := []corev1.Node{
		node("n1", true, false, nil, nil),
		node("n2", true, true, nil, nil),  // unschedulable -> not counted
		node("n3", false, false, nil, nil), // not ready -> not counted
	}
	caps := DetectFromNodes(nodes)
	if caps.MultiNode {
		t.Fatalf("only one schedulable node => not multi-node")
	}
	if caps.NodeCount != 1 {
		t.Fatalf("schedulable count want 1 got %d", caps.NodeCount)
	}
}

func TestMultiNodeTrue(t *testing.T) {
	nodes := []corev1.Node{
		node("n1", true, false, nil, nil),
		node("n2", true, false, nil, nil),
	}
	caps := DetectFromNodes(nodes)
	if !caps.MultiNode || caps.NodeCount != 2 {
		t.Fatalf("two schedulable nodes => multi-node, count 2; got %+v", caps)
	}
}
