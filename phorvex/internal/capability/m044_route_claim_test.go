package capability

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// TestM044RouteRemainsSupportedButCannotWinOnRetainedLocators exercises the real
// recon producer, capability gate and action-set generator together. The route
// mechanism remains configured and transport-supported, but its empty cover makes
// it an explicit no-cover exclusion before feasibility or cost work. Quarantine is
// the independent qualified network-effect control through the same producer.
func TestM044RouteRemainsSupportedButCannotWinOnRetainedLocators(t *testing.T) {
	target := model.Pod{Namespace: "ns", Name: "target", UID: "uid-target", Ready: true,
		DesiredReplicas: 2, ReadyReplicas: 2, RouteService: "route",
		Labels: map[string]string{"app": "web", "phorvex.ai/route-key": "old"}}
	peer := target
	peer.Name, peer.UID = "peer", "uid-peer"
	service := ingest.ServiceInfo{Namespace: "ns", Name: "route",
		Selector: map[string]string{"app": "web", "phorvex.ai/route-key": "old"}}
	witness := witOver([]model.Pod{target, peer}, nil, []ingest.ServiceInfo{service})
	view := &model.WorkloadView{Pod: target, Phase: model.PhaseWarm, BlastRadius: 0.5,
		ExposureByVariable: map[string]time.Duration{model.VarNetworkIdentity: 2 * time.Hour}}
	if ok, why := witness.Capable(view, model.ActionRouteRotate); !ok || why != "" {
		t.Fatalf("configured route mechanism no longer supported: capable=%v why=%q", ok, why)
	}

	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon profile is not registered")
	}
	fctx := recon.FactContext{AssetValue: 1, PHold: 1, StageUrgency: 1, BlastRadius: view.BlastRadius}
	facts := profile.AssetFacts(view, fctx)
	if got := facts.CoverByAction[model.ActionRouteRotate]; len(got) != 0 {
		t.Fatalf("route selector membership received locator cover: %v", got)
	}
	networkKey := (recon.Fact{Scope: recon.ScopePod, Asset: "ns/target", Kind: recon.FactNetworkIdentity}).Key()
	if got := facts.CoverByAction[model.ActionQuarantine]; len(got) != 1 || got[0] != networkKey {
		t.Fatalf("qualified quarantine network effect changed: got %v want %s", got, networkKey)
	}

	pc := cost.NewP1Cost()
	deps := actionset.Deps{
		Recon:       profile,
		FactContext: func(*model.WorkloadView) recon.FactContext { return fctx },
		ECost:       pc.ECost, CHi: pc.CHi, CostCeiling: cost.DefaultCostCeiling,
		Eligible: func(v *model.WorkloadView, action model.Action, cover []string) *actionset.Eligibility {
			reason := witness.Eligible(v, action, cover)
			if reason == nil {
				return nil
			}
			return &actionset.Eligibility{Excluded: reason.Excluded, Kind: reason.Kind,
				Detail: reason.Detail, RBACUnknown: reason.RBACUnknown}
		},
	}
	policy := model.Policy{MinAvailableReplicas: 1, P99Ms: 200, AntiOverRotationWindow: 5 * time.Minute,
		EnabledActions: map[model.Action]bool{model.ActionRouteRotate: true, model.ActionQuarantine: true}}
	set := deps.Generate([]*model.WorkloadView{view}, policy)
	for _, candidate := range set.Candidates {
		if candidate.Action == model.ActionRouteRotate {
			t.Fatalf("coverless route entered candidates: %+v", candidate)
		}
	}
	foundRoute, foundQuarantine := false, false
	for _, excluded := range set.Excluded {
		if excluded.Action == model.ActionRouteRotate {
			foundRoute = true
			if excluded.EligibilityKind != ReasonNoCover || excluded.Reason != "recon-cover: action invalidates no facts for this asset" || len(excluded.CoverKeys) != 0 || excluded.FeasibilityEvaluated || excluded.CostEvaluated {
				t.Fatalf("route exclusion is not an early supported no-cover result: %+v", excluded)
			}
		}
	}
	for _, candidate := range set.Candidates {
		if candidate.Action == model.ActionQuarantine && len(candidate.CoverKeys) == 1 && candidate.CoverKeys[0] == networkKey {
			foundQuarantine = true
		}
	}
	if !foundRoute || !foundQuarantine {
		t.Fatalf("missing route no-cover or quarantine positive control: route=%v quarantine=%v exclusions=%+v candidates=%+v", foundRoute, foundQuarantine, set.Excluded, set.Candidates)
	}
}
