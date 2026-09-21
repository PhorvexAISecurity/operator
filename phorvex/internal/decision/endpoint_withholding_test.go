package decision

import (
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	"testing"
	"time"
)

func TestEndpointPathWithheldThroughSelection(t *testing.T) {
	for _, route := range []string{"", "missing-service", "infer"} {
		for _, gpu := range []bool{false, true} {
			for _, control := range []bool{false, true} {
				v := covView("endpoint", true, 2*time.Hour, false)
				v.Pod.HasGPU = gpu
				if gpu {
					// Exercise endpoint withholding on GPU hardware through an explicit
					// serving declaration, rather than recreating the repaired GPU=>serving inference.
					v.Pod.ServingDeclared = true
				} else {
					v.Pod.ModelID = "m"
				}
				v.Pod.RouteService = route
				p := covPolicy(1)
				// Keep both locator-retaining selector actions enabled in every arm. The
				// control independently enables quarantine, whose network reachability
				// effect remains legitimately covered and selectable.
				p.EnabledActions = map[model.Action]bool{
					model.ActionEndpointRotate: true,
					model.ActionRouteRotate:    true,
					model.ActionQuarantine:     control,
				}
				e := NewCoverageEngine()
				var ok bool
				e.Recon, ok = recon.Registry.Get("ucw-recon")
				if !ok {
					t.Fatal("missing real UCW producer")
				}
				set, _ := e.AssembleSet([]*model.WorkloadView{v}, p)
				key := (recon.Fact{Scope: recon.ScopePod, Asset: "ns/endpoint", Kind: recon.FactEndpointPath}).Key()
				if _, ok := set.FactWeights[key]; ok {
					t.Error("endpoint audit fact entered objective")
				}
				found := false
				for _, f := range set.FactsByAsset["ns/endpoint"] {
					if f.Key() == key && f.Weight > 0 {
						found = true
					}
				}
				if !found {
					t.Fatal("real producer did not retain weighted endpoint audit fact")
				}
				excluded := map[model.Action]bool{}
				for _, ex := range set.Excluded {
					if ex.Reason == "recon-cover: action invalidates no facts for this asset" {
						excluded[ex.Action] = true
					}
				}
				if !excluded[model.ActionEndpointRotate] || !excluded[model.ActionRouteRotate] {
					t.Errorf("missing structural locator-retaining no-cover exclusions: %+v", set.Excluded)
				}
				for _, c := range set.Candidates {
					for _, k := range c.CoverKeys {
						if k == key {
							t.Error("candidate received endpoint credit")
						}
					}
				}
				ds := e.Decide([]*model.WorkloadView{v}, p)
				selected := 0
				for _, d := range ds {
					if d.Selected {
						selected++
						if d.Action != model.ActionQuarantine {
							t.Errorf("selected locator-retaining action %s instead of quarantine control", d.Action)
						}
					}
				}
				want := 0
				if control {
					want = 1
				}
				if selected != want {
					t.Errorf("route=%q gpu=%v control=%v selected=%d want=%d decisions=%+v", route, gpu, control, selected, want, ds)
				}
			}
		}
	}
}
