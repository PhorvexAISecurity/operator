package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// TestGate0NodeCordonDrainReplaceSelectableFrozenBrain is the Gate-0 offline proof for the
// node-cordon-drain-replace loop (lane p4): the FROZEN decision engine (ucw-recon, logic unchanged,
// only additive cover/fact/cost) SELECTS the node recycle for a pod carrying a trusted container→
// host-escape observation (AML.T0105), OVER a pod-local rotate AND quarantine, with NO knob tuning —
// and does NOT select it without the observation (purely additive; rotate/quarantine behaviour is
// unchanged when no host-escape is observed).
//
// Scenario: the threat is a COMPROMISED HOST (the node), not a lateral edge to a valued neighbour
// (that is quarantine's job). A pod-local rotate respawns the pod — possibly onto the same hostile
// node — and quarantine isolates the pod while the host stays compromised; only node-cordon-drain-
// replace recycles the node. The fixture has no crown neighbour under lateral attack, so quarantine's
// lateral-edge cover is (correctly) empty here.
func TestGate0NodeCordonDrainReplaceSelectableFrozenBrain(t *testing.T) {
	v := covView("ncdr", true, 2*time.Hour, false)
	v.Neighbors = nil
	v.Pod.Node = "worker-node-a"
	v.Pod.NodeEscapeObservation = &model.NodeEscapeObservation{
		EventName: "p4-host-escape-1", EventUID: "event-uid", CreatorIdentity: "system:serviceaccount:p4:p4-attacks",
		TargetPodUID:     v.Pod.UID,
		NodeName:         "worker-node-a",
		PolicyName:       "node-defense", PolicyUID: "policy-uid", PolicyGeneration: 1,
		EscapeSHA256:     "escape-sha",
		CreatedAt:        time.Now(),
	}

	pol := covPolicy(1)
	pol.PolicyName, pol.PolicyUID, pol.PolicyGeneration = "node-defense", "policy-uid", 1
	// Enable all three competing responses: prove the frozen engine prefers the node recycle over
	// BOTH the full-kill rotate and the full-containment quarantine, on merit (cover - cost).
	pol.EnabledActions = map[model.Action]bool{
		model.ActionRotate: true, model.ActionQuarantine: true, model.ActionNodeCordonDrainReplace: true,
	}

	e := NewCoverageEngine()
	rp, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("missing UCW profile")
	}
	e.Recon = rp

	// The host-escape fact must reach the candidate set as node-cordon-drain-replace cover and NOWHERE else.
	fact := (recon.Fact{Scope: recon.ScopePod, Asset: v.Pod.Namespace + "/" + v.Pod.Name, Kind: recon.FactNodeHostEscape}).Key()
	set, _ := e.AssembleSet([]*model.WorkloadView{v}, pol)
	foundCover := false
	for _, c := range set.Candidates {
		for _, key := range c.CoverKeys {
			if key == fact {
				if c.Action != model.ActionNodeCordonDrainReplace {
					t.Fatalf("host-escape fact leaked cover to %s", c.Action)
				}
				foundCover = true
			}
		}
	}
	if !foundCover {
		t.Fatalf("host-escape observation did not reach the candidate set as node-cordon-drain-replace cover: %+v", set)
	}

	// SELECTION: the frozen engine selects exactly node-cordon-drain-replace for this asset.
	selected := model.Action("")
	for _, d := range e.Decide([]*model.WorkloadView{v}, pol) {
		if d.Selected {
			if selected != "" {
				t.Fatalf("more than one selected action: %s and %s", selected, d.Action)
			}
			selected = d.Action
		}
	}
	if selected != model.ActionNodeCordonDrainReplace {
		t.Fatalf("frozen brain did not select node-cordon-drain-replace (selected %q) — ordinary policy+cost, no knob tuning", selected)
	}

	// NEGATIVE / additivity: with NO bound observation, node-cordon-drain-replace has zero cover and
	// is never selected; pre-existing rotate/quarantine behaviour is unchanged (frozen).
	noObs := covView("ncdr", true, 2*time.Hour, false)
	noObs.Neighbors = nil
	noObs.Pod.Node = "worker-node-a"
	noObsSet, _ := e.AssembleSet([]*model.WorkloadView{noObs}, pol)
	for _, c := range noObsSet.Candidates {
		if c.Action == model.ActionNodeCordonDrainReplace {
			t.Fatalf("node-cordon-drain-replace gained a candidate without any observation: %+v", c)
		}
	}
	for _, d := range e.Decide([]*model.WorkloadView{noObs}, pol) {
		if d.Selected && d.Action == model.ActionNodeCordonDrainReplace {
			t.Fatalf("node-cordon-drain-replace selected with no observation: %+v", d)
		}
	}

	// NEGATIVE (safety gate): an observation whose NodeName does not match the pod's live node does
	// not qualify — a forged event can never name an arbitrary node to recycle.
	badNode := covView("ncdr", true, 2*time.Hour, false)
	badNode.Neighbors = nil
	badNode.Pod.Node = "worker-node-a"
	badNode.Pod.NodeEscapeObservation = &model.NodeEscapeObservation{
		EventName: "p4-host-escape-1", EventUID: "event-uid", CreatorIdentity: "system:serviceaccount:p4:p4-attacks",
		TargetPodUID: badNode.Pod.UID, NodeName: "some-other-node",
		PolicyName: "node-defense", PolicyUID: "policy-uid", PolicyGeneration: 1, EscapeSHA256: "escape-sha",
	}
	if badNode.Pod.HasBoundNodeEscapeObservation() {
		t.Fatal("observation naming a node other than the pod's live node qualified")
	}

	// NEGATIVE: a mis-bound observation (wrong target UID) does not qualify.
	badBind := covView("ncdr", true, 2*time.Hour, false)
	badBind.Neighbors = nil
	badBind.Pod.Node = "worker-node-a"
	badBind.Pod.NodeEscapeObservation = &model.NodeEscapeObservation{
		EventName: "p4-host-escape-1", EventUID: "event-uid", CreatorIdentity: "system:serviceaccount:p4:p4-attacks",
		TargetPodUID: "u-someone-else", NodeName: "worker-node-a",
		PolicyName: "node-defense", PolicyUID: "policy-uid", PolicyGeneration: 1, EscapeSHA256: "escape-sha",
	}
	if badBind.Pod.HasBoundNodeEscapeObservation() {
		t.Fatal("observation bound to the wrong pod UID qualified")
	}
}
