package recon

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func m043ScalarShardLeader() model.Pod {
	return model.Pod{
		Namespace: "ns", Name: "leader", UID: "old-uid", ModelID: "model-a",
		ServingDeclared: true, RouteService: "infer", WarmPoolConfigured: true,
		WarmPoolOwnerUID: "replicaset-uid",
		Labels: map[string]string{
			"phorvex.ai/model-shard": "main",
			"phorvex.ai/role":        "leader",
		},
	}
}

func m043CoverKinds(t *testing.T, profile ReconProfile, pod model.Pod) map[string]bool {
	t.Helper()
	af := profile.AssetFacts(&model.WorkloadView{Pod: pod}, FactContext{
		AssetValue: 1, PHold: 1, StageUrgency: 1,
	})
	if af.AbsentReason != "" {
		t.Fatalf("unexpected absent facts: %s", af.AbsentReason)
	}
	byKey := map[string]string{}
	for _, fact := range af.Facts {
		byKey[fact.Key()] = fact.Kind
	}
	got := map[string]bool{}
	for _, key := range af.CoverByAction[model.ActionModelShardReplace] {
		kind, ok := byKey[key]
		if !ok {
			t.Fatalf("cover named an unproduced fact: %s", key)
		}
		got[kind] = true
	}
	return got
}

func TestM043ScalarModelShardRetirementCoversOnlyOldProcessFacts(t *testing.T) {
	want := map[string]bool{FactPodIdentity: true, FactInMemory: true, FactSession: true}
	for _, profile := range []ReconProfile{standardRecon{}, ucwRecon{}} {
		t.Run(profile.Name(), func(t *testing.T) {
			got := m043CoverKinds(t, profile, m043ScalarShardLeader())
			if len(got) != len(want) {
				t.Fatalf("model-shard process cover = %v, want %v", got, want)
			}
			for kind := range want {
				if !got[kind] {
					t.Errorf("model-shard process cover missing %s: %v", kind, got)
				}
			}
			for _, forbidden := range []string{
				FactModelFingerprint, FactEndpointPath, FactNetworkIdentity,
				FactGPUColocation, FactGPUContentionChannel, FactCredential,
			} {
				if got[forbidden] {
					t.Errorf("model-shard process retirement must not cover %s", forbidden)
				}
			}
		})
	}
}

func TestM043ScalarModelShardCoverRequiresVerifiedFamilyWitness(t *testing.T) {
	base := m043ScalarShardLeader()
	for _, tc := range []struct {
		name   string
		mutate func(*model.Pod)
	}{
		{"bare-labels", func(p *model.Pod) { p.WarmPoolConfigured = false }},
		{"missing-owner", func(p *model.Pod) { p.WarmPoolOwnerUID = "" }},
		{"missing-service", func(p *model.Pod) { p.RouteService = "" }},
		{"missing-shard", func(p *model.Pod) { delete(p.Labels, "phorvex.ai/model-shard") }},
		{"shadow-target", func(p *model.Pod) { p.Labels["phorvex.ai/role"] = "warm-shadow" }},
		{"parallel-group", func(p *model.Pod) { p.Labels["phorvex.ai/parallel-group"] = "tp-0" }},
		{"no-serving-context", func(p *model.Pod) { p.ModelID, p.ServingDeclared = "", false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := base
			pod.Labels = map[string]string{}
			for key, value := range base.Labels {
				pod.Labels[key] = value
			}
			tc.mutate(&pod)
			for _, profile := range []ReconProfile{standardRecon{}, ucwRecon{}} {
				if got := m043CoverKinds(t, profile, pod); len(got) != 0 {
					t.Errorf("%s admitted unsupported model-shard cover: %v", profile.Name(), got)
				}
			}
		})
	}
}
