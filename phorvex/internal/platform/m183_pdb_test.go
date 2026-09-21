package platform

import (
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"k8s.io/apimachinery/pkg/labels"
	"testing"
)

func m183PDB(name string, allowed, desired int, generation, observed int64) ingest.PDBInfo {
	return ingest.PDBInfo{Namespace: "ns", Name: name, UID: "uid-" + name, Generation: generation, ObservedGeneration: observed, Selector: labels.SelectorFromSet(labels.Set{"app": "voice"}), SelectorValid: true, MinAvailable: -1, MinAvailableText: "50%", DisruptionsAllowed: allowed, CurrentHealthy: 2, DesiredHealthy: desired, ExpectedPods: 2}
}

func TestM183PDBObservationIsFreshAndAggregatesEveryMatch(t *testing.T) {
	pod := &model.Pod{Namespace: "ns", Name: "voice", Labels: map[string]string{"app": "voice"}}
	unobserved := matchPDB(nil, false, false, pod)
	if unobserved.attempted || unobserved.available || unobserved.reason != "pdb-inventory-unobserved" {
		t.Fatalf("unobserved=%+v", unobserved)
	}
	none := matchPDB(nil, true, true, pod)
	if !none.attempted || !none.available || none.matched || none.disruptionsAllowed != -1 {
		t.Fatalf("observed empty inventory=%+v", none)
	}
	got := matchPDB([]ingest.PDBInfo{m183PDB("percentage", 2, 1, 3, 3), m183PDB("max-unavailable", 0, 2, 4, 4)}, true, true, pod)
	if !got.available || !got.matched || got.count != 2 || got.disruptionsAllowed != 0 || got.desiredHealthy != 2 {
		t.Fatalf("aggregate=%+v", got)
	}
	stale := matchPDB([]ingest.PDBInfo{m183PDB("stale", 1, 1, 5, 4)}, true, true, pod)
	if stale.available || stale.reason != "pdb-status-generation-stale" {
		t.Fatalf("stale=%+v", stale)
	}
	failed := matchPDB(nil, true, false, pod)
	if failed.available || failed.reason != "pdb-inventory-unavailable" {
		t.Fatalf("failed=%+v", failed)
	}
}
