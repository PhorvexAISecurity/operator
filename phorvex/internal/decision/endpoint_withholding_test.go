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
				p.EnabledActions = map[model.Action]bool{model.ActionEndpointRotate: true, model.ActionRouteRotate: control}
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
				excluded := false
				for _, ex := range set.Excluded {
					if ex.Action == model.ActionEndpointRotate && ex.Reason == "recon-cover: action invalidates no facts for this asset" {
						excluded = true
					}
				}
				if !excluded {
					t.Errorf("missing structural no-cover exclusion: %+v", set.Excluded)
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
						if d.Action != model.ActionRouteRotate {
							t.Errorf("selected unsupported action %s", d.Action)
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
