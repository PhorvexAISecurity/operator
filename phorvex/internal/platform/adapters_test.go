package platform

import (
	"reflect"
	"testing"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// TestAdapterSelectionIsLabelDriven — the EKS adapter is selected by a real EKS node label,
// NOT by registration order. A CPU cluster (kind) => generic-k8s; a GPU node with an EKS label
// => eks-gpu; a GPU node WITHOUT a cloud label => the gpu-marketplace fallback.
func TestAdapterSelectionIsLabelDriven(t *testing.T) {
	gpuNode := func(labels map[string]string) ingest.NodeInfo {
		return ingest.NodeInfo{Name: "n", AllocatableGPU: 4, MIGResources: map[string]int64{}, Labels: labels}
	}
	cases := []struct {
		name  string
		nodes []ingest.NodeInfo
		want  string
	}{
		{"kind-cpu-only", []ingest.NodeInfo{{Name: "kind", MIGResources: map[string]int64{}, Labels: map[string]string{"kubernetes.io/hostname": "kind"}}}, "generic-k8s"},
		{"eks-gpu", []ingest.NodeInfo{gpuNode(map[string]string{"eks.amazonaws.com/nodegroup": "gpu-ng", "node.kubernetes.io/instance-type": "g5.xlarge"})}, "eks-gpu"},
		{"coreweave-gpu", []ingest.NodeInfo{gpuNode(map[string]string{"node.coreweave.cloud/class": "gpu"})}, "coreweave"},
		{"gpu-without-cloud-label", []ingest.NodeInfo{gpuNode(map[string]string{"node.kubernetes.io/instance-type": "bare-metal"})}, "gpu-marketplace"},
	}
	for _, c := range cases {
		name, _ := Derive(&ingest.Snapshot{Nodes: c.nodes})
		if name != c.want {
			t.Errorf("%s: adapter = %q, want %q", c.name, name, c.want)
		}
	}
}

// TestGPUAdapterKsHalfByteIdentical — GATE PRESERVATION: the EKS/CoreWeave adapters inherit
// genericK8s.Derive verbatim when DCGM is absent, so on the SAME GPU snapshot the per-pod
// witness is byte-identical to generic-k8s with GPUPresent=false. Adding node Labels +
// label-driven Detect did NOT perturb the physics witness.
func TestGPUAdapterKsHalfByteIdentical(t *testing.T) {
	snap := &ingest.Snapshot{
		Nodes: []ingest.NodeInfo{{Name: "n", AllocatableCPUMilli: 8000, AllocatableMemBytes: 16 << 30, AllocatableGPU: 4, MIGResources: map[string]int64{}, Labels: map[string]string{"eks.amazonaws.com/nodegroup": "gpu"}}},
		Pods: []model.Pod{
			{Namespace: "a", Name: "p1", Node: "n", ImageID: "img-x"},
			{Namespace: "b", Name: "p2", Node: "n", ImageID: "img-y"},
		},
	}
	gen := genericK8s{}.Derive(snap)
	eks := eksGPU{}.Derive(snap)
	if !reflect.DeepEqual(gen, eks) {
		t.Fatalf("eks-gpu witness diverged from generic-k8s K8s half:\n generic=%+v\n eks=%+v", gen, eks)
	}
	for k, w := range eks {
		if w.GPUPresent {
			t.Errorf("pod %s: GPUPresent=true on a node with no DCGM feed — must be honest-absent", k)
		}
	}
}
