package actionset

import (
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

func endpointLeaseCandidateView() *model.WorkloadView {
	v := baseView("lease")
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
	return v
}

func TestEndpointLeaseCandidateRequiresBoundFactAndSelectingPolicy(t *testing.T) {
	d := ucwTestDeps(t)
	d.ECost = func(*model.WorkloadView, model.Move, model.Policy) float64 { return 0.1 }
	d.CHi = func(*model.WorkloadView, model.Move, model.Policy) float64 { return 0.2 }
	pol := testPolicy()
	pol.PolicyName, pol.PolicyUID, pol.PolicyGeneration = "vllm-defense", "policy-uid", 1
	pol.EnabledActions = map[model.Action]bool{model.ActionEndpointLeaseRevoke: true, model.ActionEndpointRotate: true}
	v := endpointLeaseCandidateView()
	set := d.Generate([]*model.WorkloadView{v}, pol)
	key := (recon.Fact{Scope: recon.ScopePod, Asset: "vllm/lease", Kind: recon.FactEndpointLeaseReuse}).Key()
	if !actionsFor(set, "vllm/lease")[model.ActionEndpointLeaseRevoke] || set.FactWeights[key] <= 0 {
		t.Fatalf("bound source/policy fact did not generate revoke: %+v", set)
	}
	if actionsFor(set, "vllm/lease")[model.ActionEndpointRotate] {
		t.Fatal("endpoint-rotate gained credential invalidation credit")
	}
	v.Pod.EndpointLeaseObservation.PolicyUID = "other-policy"
	set = d.Generate([]*model.WorkloadView{v}, pol)
	if actionsFor(set, "vllm/lease")[model.ActionEndpointLeaseRevoke] {
		t.Fatal("wrong selecting policy generated revoke")
	}
	found := false
	for _, ex := range set.Excluded {
		found = found || ex.Action == model.ActionEndpointLeaseRevoke && strings.Contains(ex.Reason, "identity/epoch")
	}
	if !found {
		t.Fatalf("wrong-policy exclusion missing: %+v", set.Excluded)
	}
	v.Pod.EndpointLeaseObservation = nil
	set = d.Generate([]*model.WorkloadView{v}, pol)
	if actionsFor(set, "vllm/lease")[model.ActionEndpointLeaseRevoke] {
		t.Fatal("unbound event generated revoke")
	}
}
