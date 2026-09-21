package capability

import (
	"testing"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

func m043FactContext(v *model.WorkloadView) recon.FactContext {
	return recon.FactContext{AssetValue: 1, PHold: 1, StageUrgency: 1, HasGPU: v.Pod.HasGPU}
}

func m043Eligibility(t *testing.T, profileName string, view *model.WorkloadView, fleet []model.Pod, nodes []ingest.NodeInfo) ([]string, *Reason) {
	t.Helper()
	profile, ok := recon.Registry.Get(profileName)
	if !ok {
		t.Fatalf("missing recon profile %s", profileName)
	}
	cover := profile.AssetFacts(view, m043FactContext(view)).CoverByAction[model.ActionModelShardReplace]
	witness := witOver(fleet, nodes, nil)
	return cover, witness.Eligible(view, model.ActionModelShardReplace, cover)
}

func TestM043QualifiedScalarShardCoverPassesCurrentCapabilityWitness(t *testing.T) {
	views, _ := capFleet()
	fleet := []model.Pod{views[0].Pod, views[1].Pod, views[2].Pod}
	for _, profile := range []string{"standard-recon", "ucw-recon"} {
		t.Run(profile, func(t *testing.T) {
			cover, reason := m043Eligibility(t, profile, views[0], fleet, twoGPUNodes())
			if len(cover) != 3 || reason != nil {
				t.Fatalf("qualified scalar shard cover=%v exclusion=%+v", cover, reason)
			}
		})
	}
}

func TestM043ShardCoverDoesNotBypassCapabilityOrFamilyPredicates(t *testing.T) {
	views, _ := capFleet()
	base := views[0].Pod
	for _, tc := range []struct {
		name      string
		mutate    func(*model.Pod, *[]model.Pod)
		nodes     []ingest.NodeInfo
		wantCover bool
		wantKind  string
	}{
		{"one-gpu-node", func(*model.Pod, *[]model.Pod) {}, twoGPUNodes()[:1], true, ReasonCapability},
		{"missing-ready-shadow", func(_ *model.Pod, fleet *[]model.Pod) { (*fleet)[2].Ready = false }, twoGPUNodes(), true, ReasonCapability},
		{"bare-user-label", func(p *model.Pod, _ *[]model.Pod) { p.WarmPoolConfigured = false }, twoGPUNodes(), false, ReasonNoCover},
		{"missing-owner", func(p *model.Pod, _ *[]model.Pod) { p.WarmPoolOwnerUID = "" }, twoGPUNodes(), false, ReasonNoCover},
		{"parallel-group", func(p *model.Pod, _ *[]model.Pod) { p.Labels[labelParallelGroup] = "tp" }, twoGPUNodes(), false, ReasonNoCover},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leader := base
			leader.Labels = cloneMap(base.Labels)
			fleet := []model.Pod{leader, views[1].Pod, views[2].Pod}
			tc.mutate(&leader, &fleet)
			fleet[0] = leader
			cover, reason := m043Eligibility(t, "ucw-recon", &model.WorkloadView{Pod: leader}, fleet, tc.nodes)
			if (len(cover) > 0) != tc.wantCover {
				t.Fatalf("cover=%v, want present=%v", cover, tc.wantCover)
			}
			if reason == nil || !reason.Excluded || reason.Kind != tc.wantKind {
				t.Fatalf("exclusion=%+v, want %s", reason, tc.wantKind)
			}
		})
	}
}
