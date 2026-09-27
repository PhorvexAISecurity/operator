package recon

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func endpointLeaseView() *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{Namespace: "vllm", Name: "vllm", UID: "pod-uid",
		EndpointLeaseObservation: &model.EndpointLeaseObservation{
			EventName: "lease-event", EventUID: "event-uid", CreatorIdentity: "console-creator",
			ScenarioID: "ai2-endpoint-security", EvidenceSource: "TEST_INJECTED",
			PolicyName: "vllm-defense", PolicyUID: "policy-uid", PolicyGeneration: 1,
			TargetPodUID: "pod-uid", ServiceUID: "service-uid", PolicyConfigMapUID: "cm-uid",
			ProxySourceSHA256: "source-sha", SecretUID: "secret-uid", SeedSHA256: "seed-sha",
			RevokedClientHMAC: "a", RetainedClientHMAC: "b",
			AcceptedStatus: 200, AcceptedResponseSHA256: "accepted-sha",
			RetainedBaselineStatus: 200, RetainedBaselineResponseSHA256: "retained-sha",
			ObservedAt: time.Now(),
		}}}
}

func TestEndpointLeaseFactCoversOnlyExactRevoke(t *testing.T) {
	v := endpointLeaseView()
	if !v.Pod.HasBoundEndpointLeaseObservation() {
		t.Fatal("typed lease observation did not bind")
	}
	af := ucwRecon{}.AssetFacts(v, FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1})
	keys := af.CoverByAction[model.ActionEndpointLeaseRevoke]
	if len(keys) != 1 {
		t.Fatalf("lease cover keys = %v", keys)
	}
	if len(af.CoverByAction[model.ActionEndpointRotate]) != 0 || len(af.CoverByAction[model.ActionRouteRotate]) != 0 {
		t.Fatal("stable endpoint-path mechanism gained credential cover")
	}
	for _, f := range af.Facts {
		if f.Key() == keys[0] {
			if f.Kind != FactEndpointLeaseReuse || f.SteeredBy == nil ||
				f.SteeredBy.RuleType != model.AttackVectorEndpointLeaseReuse ||
				len(f.SteeredBy.Events) != 1 || f.SteeredBy.Events[0].EventUID != "event-uid" {
				t.Fatalf("lease fact lost typed attribution: %+v", f)
			}
			return
		}
	}
	t.Fatal("lease cover refers to no emitted fact")
}

func TestEndpointLeaseFactRejectsChangedBoundIdentity(t *testing.T) {
	for name, mutate := range map[string]func(*model.Pod){
		"target UID":      func(p *model.Pod) { p.EndpointLeaseObservation.TargetPodUID = "old-pod" },
		"namespace":       func(p *model.Pod) { p.Namespace = "other" },
		"source":          func(p *model.Pod) { p.EndpointLeaseObservation.ProxySourceSHA256 = "" },
		"policy":          func(p *model.Pod) { p.EndpointLeaseObservation.PolicyUID = "" },
		"accepted status": func(p *model.Pod) { p.EndpointLeaseObservation.AcceptedStatus = 401 },
		"same clients": func(p *model.Pod) {
			p.EndpointLeaseObservation.RetainedClientHMAC = p.EndpointLeaseObservation.RevokedClientHMAC
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := endpointLeaseView()
			mutate(&v.Pod)
			if v.Pod.HasBoundEndpointLeaseObservation() || len(ucwRecon{}.AssetFacts(v, FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1}).CoverByAction[model.ActionEndpointLeaseRevoke]) != 0 {
				t.Fatal("unbound credential observation gained cover")
			}
		})
	}
}
