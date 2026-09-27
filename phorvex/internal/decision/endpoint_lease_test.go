package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

func TestEndpointLeaseTypedFactReachesNewActionWithoutEndpointPathCredit(t *testing.T) {
	v := covView("lease", true, 2*time.Hour, false)
	v.Pod.Namespace = "vllm"
	v.Pod.EndpointLeaseObservation = &model.EndpointLeaseObservation{
		EventName: "event", EventUID: "event-uid", CreatorIdentity: "console",
		ScenarioID: "ai2-endpoint-security", EvidenceSource: "TEST_INJECTED",
		PolicyName: "vllm-defense", PolicyUID: "policy-uid", PolicyGeneration: 1,
		TargetPodUID: v.Pod.UID, ServiceUID: "service-uid", PolicyConfigMapUID: "cm-uid",
		ProxySourceSHA256: "source-sha", SecretUID: "secret-uid", SeedSHA256: "seed-sha",
		RevokedClientHMAC: "a", RetainedClientHMAC: "b",
		AcceptedStatus: 200, AcceptedResponseSHA256: "accepted-sha",
		RetainedBaselineStatus: 200, RetainedBaselineResponseSHA256: "retained-sha",
		ObservedAt: time.Now(),
	}
	pol := covPolicy(1)
	pol.PolicyName, pol.PolicyUID, pol.PolicyGeneration = "vllm-defense", "policy-uid", 1
	pol.EnabledActions = map[model.Action]bool{model.ActionEndpointLeaseRevoke: true, model.ActionEndpointRotate: true}
	e := NewCoverageEngine()
	rp, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("missing UCW profile")
	}
	e.Recon = rp
	set, _ := e.AssembleSet([]*model.WorkloadView{v}, pol)
	fact := (recon.Fact{Scope: recon.ScopePod, Asset: "vllm/lease", Kind: recon.FactEndpointLeaseReuse}).Key()
	foundCandidate := false
	for _, c := range set.Candidates {
		if c.Action == model.ActionEndpointLeaseRevoke {
			for _, key := range c.CoverKeys {
				foundCandidate = foundCandidate || key == fact
			}
		}
		if c.Action == model.ActionEndpointRotate {
			t.Fatal("endpoint-rotate gained a candidate from the lease fact")
		}
	}
	if !foundCandidate {
		t.Fatalf("typed lease fact did not reach candidate set: %+v", set)
	}
	foundSelectedRevoke := false
	for _, d := range e.Decide([]*model.WorkloadView{v}, pol) {
		if !d.Selected {
			continue
		}
		if d.Action != model.ActionEndpointLeaseRevoke {
			t.Fatalf("selected unrelated action %+v", d)
		}
		foundSelectedRevoke = true
	}
	if !foundSelectedRevoke {
		t.Fatal("ordinary policy and cost did not select endpoint-lease-revoke")
	}
	v.Pod.EndpointLeaseObservation.PolicyUID = "other-policy"
	set, _ = e.AssembleSet([]*model.WorkloadView{v}, pol)
	for _, c := range set.Candidates {
		if c.Action == model.ActionEndpointLeaseRevoke {
			t.Fatal("wrong policy still generated revoke")
		}
	}
}
