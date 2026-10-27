package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// TestGate0NetworkIsolateSelectableFrozenBrain is the Gate-0 offline proof for the
// network-isolate loop (lane p3): the FROZEN decision engine (ucw-recon, logic unchanged,
// only additive cover/fact) SELECTS the surgical network-isolate (egress edge cut) for a pod
// with a trusted open-egress-channel observation, OVER rotate and quarantine, with NO knob
// tuning — and does NOT select it without the observation (purely additive; rotate/quarantine
// behaviour is unchanged when no network-edge is observed).
//
// Scenario modelling: the 9 network-isolate attacks (AML.T0096 C2, T0108, ASI07, the IMDS
// pair, the exposed-route rows) are the pod's OWN outbound channel edge — not lateral movement
// to a high-value neighbour (that is quarantine's job). So the fixture has NO crown neighbour
// under lateral attack; the threat is the egress channel, covered uniquely by network-isolate.
func TestGate0NetworkIsolateSelectableFrozenBrain(t *testing.T) {
	v := covView("netiso", true, 2*time.Hour, false)
	// Pure C2/egress scenario: the pod's own outbound channel is the threat, not a lateral
	// edge to a valued neighbour. Drop the generic crown neighbour so quarantine's lateral-edge
	// cover is (correctly) empty here — if a crown WERE under active lateral attack, a full
	// quarantine could legitimately win, which is not this attack.
	v.Neighbors = nil
	v.Pod.NetworkIsolateObservation = &model.NetworkIsolateObservation{
		EventName: "p3-netedge-1", EventUID: "event-uid", CreatorIdentity: "system:serviceaccount:p3:p3-attacks",
		TargetPodUID:     v.Pod.UID,
		PolicyName:       "demo-api-defense", PolicyUID: "policy-uid", PolicyGeneration: 1,
		ForbiddenEdges:   []string{"169.254.169.254/32", "10.0.0.5/32"},
		ChannelSHA256:    "edge-sha",
		CreatedAt:        time.Now(),
	}

	pol := covPolicy(1)
	pol.PolicyName, pol.PolicyUID, pol.PolicyGeneration = "demo-api-defense", "policy-uid", 1
	// Enable all three competing network responses: prove the frozen engine prefers the
	// surgical edge cut over BOTH the full-kill rotate and the full-containment quarantine.
	pol.EnabledActions = map[model.Action]bool{
		model.ActionRotate: true, model.ActionQuarantine: true, model.ActionNetworkIsolate: true,
	}

	e := NewCoverageEngine()
	rp, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("missing UCW profile")
	}
	e.Recon = rp

	// The channel fact must reach the candidate set as network-isolate cover and NOWHERE else.
	fact := (recon.Fact{Scope: recon.ScopePod, Asset: v.Pod.Namespace + "/" + v.Pod.Name, Kind: recon.FactNetworkEgressChannel}).Key()
	set, _ := e.AssembleSet([]*model.WorkloadView{v}, pol)
	foundCover := false
	for _, c := range set.Candidates {
		for _, key := range c.CoverKeys {
			if key == fact {
				if c.Action != model.ActionNetworkIsolate {
					t.Fatalf("egress-channel fact leaked cover to %s", c.Action)
				}
				foundCover = true
			}
		}
	}
	if !foundCover {
		t.Fatalf("network-edge observation did not reach the candidate set as network-isolate cover: %+v", set)
	}

	// SELECTION: the frozen engine selects exactly network-isolate for this asset.
	selected := model.Action("")
	for _, d := range e.Decide([]*model.WorkloadView{v}, pol) {
		if d.Selected {
			if selected != "" {
				t.Fatalf("more than one selected action: %s and %s", selected, d.Action)
			}
			selected = d.Action
		}
	}
	if selected != model.ActionNetworkIsolate {
		t.Fatalf("frozen brain did not select network-isolate (selected %q) — ordinary policy+cost, no knob tuning", selected)
	}

	// NEGATIVE / additivity: with NO bound observation, network-isolate has zero cover and is
	// never selected; the pre-existing rotate/quarantine behaviour is unchanged (frozen).
	noObs := covView("netiso", true, 2*time.Hour, false)
	noObs.Neighbors = nil
	noObsSet, _ := e.AssembleSet([]*model.WorkloadView{noObs}, pol)
	for _, c := range noObsSet.Candidates {
		if c.Action == model.ActionNetworkIsolate {
			t.Fatalf("network-isolate gained a candidate without any observation: %+v", c)
		}
	}
	for _, d := range e.Decide([]*model.WorkloadView{noObs}, pol) {
		if d.Selected && d.Action == model.ActionNetworkIsolate {
			t.Fatalf("network-isolate selected with no observation: %+v", d)
		}
	}

	// NEGATIVE: a mis-bound observation (wrong target UID) does not qualify.
	badBind := covView("netiso", true, 2*time.Hour, false)
	badBind.Neighbors = nil
	badBind.Pod.NetworkIsolateObservation = &model.NetworkIsolateObservation{
		EventName: "p3-netedge-1", EventUID: "event-uid", CreatorIdentity: "system:serviceaccount:p3:p3-attacks",
		TargetPodUID: "u-someone-else", PolicyName: "demo-api-defense", PolicyUID: "policy-uid", PolicyGeneration: 1,
		ForbiddenEdges: []string{"169.254.169.254/32"}, ChannelSHA256: "edge-sha",
	}
	if badBind.Pod.HasBoundNetworkIsolateObservation() {
		t.Fatal("observation bound to the wrong pod UID qualified")
	}
}
