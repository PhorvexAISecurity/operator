// Package capability probes the LIVE cluster at runtime to detect the
// capabilities scenarios may require (GPU, real multi-node, MIG). NOTHING is
// hardcoded per environment: the SAME detection runs on kind / EKS / CoreWeave /
// vcluster and the runner skips scenarios whose requirements are unmet.
package capability

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// Detect probes the cluster and returns the capability set plus a human-readable
// note per capability (for the skip-with-note report).
func Detect(ctx context.Context, kube kubernetes.Interface) (core.Capabilities, map[string]string, error) {
	notes := map[string]string{}
	nodes, err := kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return core.Capabilities{}, notes, err
	}
	return DetectFromNodes(nodes.Items), notesFromNodes(nodes.Items), nil
}

// DetectFromNodes is the pure, testable core of detection: it derives the
// capability set from a node list with NO API calls.
func DetectFromNodes(nodes []corev1.Node) core.Capabilities {
	caps := core.Capabilities{}

	schedulable := 0
	for i := range nodes {
		n := nodes[i]
		if !nodeSchedulable(n) {
			continue
		}
		schedulable++

		// GPU: any node advertising nvidia.com/gpu allocatable > 0.
		if q, ok := n.Status.Allocatable["nvidia.com/gpu"]; ok && !q.IsZero() {
			caps.GPU = true
		}
		// MIG: any nvidia.com/mig-* allocatable resource, or a MIG strategy label.
		for rn := range n.Status.Allocatable {
			if strings.HasPrefix(string(rn), "nvidia.com/mig-") {
				caps.MIG = true
				caps.GPU = true // a MIG node is a GPU node
			}
		}
		for k, v := range n.Labels {
			if k == "nvidia.com/mig.strategy" && v != "" && v != "none" {
				caps.MIG = true
			}
			if strings.HasPrefix(k, "nvidia.com/mig-") {
				caps.MIG = true
			}
		}
	}

	caps.NodeCount = schedulable
	// Real multi-node = more than one schedulable node.
	caps.MultiNode = schedulable > 1
	return caps
}

// nodeSchedulable reports whether a node is genuinely schedulable (Ready, not
// cordoned, no NoSchedule master/control-plane taint without a toleration —
// conservatively: count it if Ready and not Unschedulable).
func nodeSchedulable(n corev1.Node) bool {
	if n.Spec.Unschedulable {
		return false
	}
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func notesFromNodes(nodes []corev1.Node) map[string]string {
	caps := DetectFromNodes(nodes)
	notes := map[string]string{}
	if caps.GPU {
		notes["CapGPU"] = "at least one node advertises nvidia.com/gpu allocatable"
	} else {
		notes["CapGPU"] = "no node advertises nvidia.com/gpu — GPU scenarios skip-with-note"
	}
	if caps.MultiNode {
		notes["CapMultiNode"] = "more than one schedulable node detected"
	} else {
		notes["CapMultiNode"] = "single schedulable node — multi-node scenarios skip-with-note"
	}
	if caps.MIG {
		notes["CapMIG"] = "MIG profile resources/labels detected"
	} else {
		notes["CapMIG"] = "no MIG resources/labels — MIG scenarios skip-with-note"
	}
	return notes
}
