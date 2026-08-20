/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

func pod(ns, name, node string) model.Pod {
	return model.Pod{Namespace: ns, Name: name, Node: node, Phase: string(corev1.PodRunning)}
}

// Namespaces are counted DISTINCT per node: ten pods of one tenant are not co-residency, they
// are one tenant. Counting pods instead would make a single busy service look like a crowded
// node and inflate the whole distribution.
func TestNamespacesAreCountedDistinctNotByPod(t *testing.T) {
	snap := &ingest.Snapshot{
		Nodes: []ingest.NodeInfo{{Name: "n1", Schedulable: true}},
		Pods: []model.Pod{
			pod("a", "p1", "n1"), pod("a", "p2", "n1"), pod("a", "p3", "n1"),
			pod("b", "p4", "n1"),
		},
	}
	got := NodesFromSnapshot(snap)
	if len(got) != 1 {
		t.Fatalf("nodes = %d, want 1", len(got))
	}
	if got[0].Namespaces != 2 {
		t.Fatalf("namespaces = %d, want 2 (a and b), not the 4 pods", got[0].Namespaces)
	}
	if got[0].X() != 1 {
		t.Fatalf("X = %v, want 1 — the node's own first tenant contributes no co-residency", got[0].X())
	}
}

// A schedulable node with no pods must survive projection as X=0. Deriving the node set from
// pods would drop it and bias the fleet to look denser than it is.
func TestEmptySchedulableNodeSurvivesProjection(t *testing.T) {
	snap := &ingest.Snapshot{
		Nodes: []ingest.NodeInfo{{Name: "busy", Schedulable: true}, {Name: "fresh", Schedulable: true}},
		Pods:  []model.Pod{pod("a", "p1", "busy")},
	}
	got := NodesFromSnapshot(snap)
	if len(got) != 2 {
		t.Fatalf("nodes = %d, want 2 — the empty node was dropped", len(got))
	}
	for _, n := range got {
		if n.Name == "fresh" && (n.Pods != 0 || n.X() != 0) {
			t.Fatalf("fresh node projected as pods=%d X=%v, want 0 and 0", n.Pods, n.X())
		}
	}
}

// An unscheduled pod belongs to no node's tenancy yet and must not invent a node.
func TestUnscheduledPodsAreIgnored(t *testing.T) {
	snap := &ingest.Snapshot{
		Nodes: []ingest.NodeInfo{{Name: "n1", Schedulable: true}},
		Pods:  []model.Pod{pod("a", "p1", "n1"), pod("b", "pending", "")},
	}
	got := NodesFromSnapshot(snap)
	if len(got) != 1 {
		t.Fatalf("nodes = %d, want 1 — a pod with no node created one", len(got))
	}
	if got[0].Namespaces != 1 {
		t.Fatalf("namespaces = %d, want 1 — the pending pod's namespace was counted", got[0].Namespaces)
	}
}

// Projection is order-stable so an exported report diffs cleanly between refreshes.
func TestProjectionIsSortedByName(t *testing.T) {
	snap := &ingest.Snapshot{
		Nodes: []ingest.NodeInfo{{Name: "z", Schedulable: true}, {Name: "a", Schedulable: true}, {Name: "m", Schedulable: true}},
	}
	got := NodesFromSnapshot(snap)
	for i := 1; i < len(got); i++ {
		if got[i-1].Name > got[i].Name {
			t.Fatalf("projection is not sorted: %v", got)
		}
	}
}

func TestNilSnapshotIsEmptyNotPanic(t *testing.T) {
	if got := NodesFromSnapshot(nil); len(got) != 0 {
		t.Fatalf("nil snapshot produced %d observations", len(got))
	}
}

func TestTerminalPodsAreExcludedFromCalibrationProjection(t *testing.T) {
	runningA := pod("a", "running-a", "n1")
	runningB := pod("b", "running-b", "n1")
	succeeded := pod("terminal-success", "old-job", "n1")
	succeeded.Phase = string(corev1.PodSucceeded)
	failed := pod("terminal-failure", "old-failure", "n1")
	failed.Phase = string(corev1.PodFailed)
	snap := &ingest.Snapshot{
		Nodes: []ingest.NodeInfo{{Name: "n1", Schedulable: true}},
		Pods:  []model.Pod{runningA, runningB, succeeded, failed},
	}
	witness := map[string]model.PhysicsWitness{}
	for _, p := range snap.Pods {
		witness[p.Namespace+"/"+p.Name] = model.PhysicsWitness{
			Scanned: true, ImageRarity: 1.5, EPSS: 1.2, ModelRarity: 1,
		}
	}

	nodes := NodesFromSnapshot(snap)
	if len(nodes) != 1 || nodes[0].Pods != 2 || nodes[0].Namespaces != 2 {
		t.Fatalf("terminal pods contaminated node projection: %+v", nodes)
	}
	assets := AssetsFromSnapshot(snap, witness)
	if len(assets) != 2 || assets[0].Key != "a/running-a" || assets[1].Key != "b/running-b" {
		t.Fatalf("terminal pods contaminated asset projection: %+v", assets)
	}
}
