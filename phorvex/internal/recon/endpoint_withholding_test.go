package recon

import (
	"github.com/phorvex/phorvex/internal/model"
	"testing"
)

func TestEndpointPathWithheldByRealProducer(t *testing.T) {
	for _, asset := range []struct {
		name  string
		gpu   bool
		model string
	}{
		{"gpu-only", true, ""}, {"model-only", false, "m"}, {"both", true, "m"}, {"neither", false, ""},
	} {
		for _, route := range []string{"", "missing-service", "infer"} {
			for _, epoch := range []string{"", "ep-stale"} {
				t.Run(asset.name+"/"+route+"/"+epoch, func(t *testing.T) {
					v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "llm", HasGPU: asset.gpu, ModelID: asset.model, RouteService: route, RouteKeyEpoch: epoch, MIGDevice: "MIG-a", SuspectAdapter: "bad"}}
					v.Physics.ImageRarity = 2
					v.Physics.EPSSMultiplier = 1
					v.Physics.CoResidency = 1
					v.Physics.ModelRarity = 1
					ctx := FactContext{AssetValue: 10, PHold: 0.8, StageUrgency: 0.5, HasGPU: asset.gpu}
					af := ucwRecon{}.AssetFacts(v, ctx)
					key := (Fact{Scope: ScopePod, Asset: "ns/llm", Kind: FactEndpointPath}).Key()
					count := 0
					for _, f := range af.Facts {
						if f.Key() == key {
							count++
							if f.Weight != 12 {
								t.Errorf("audit weight=%v, want 12", f.Weight)
							}
						}
					}
					want := 0
					if asset.gpu || asset.model != "" {
						want = 1
					}
					if count != want {
						t.Fatalf("endpoint fact count=%d, want %d", count, want)
					}
					for a, keys := range af.CoverByAction {
						for _, k := range keys {
							if k == key {
								t.Errorf("unsupported endpointPath grant to %s", a)
							}
						}
					}
					if len(af.CoverByAction[model.ActionEndpointRotate]) != 0 {
						t.Error("endpoint-rotate still has cover")
					}
					// Independent positive control through the same producer, even in RED runs.
					network := (Fact{Scope: ScopePod, Asset: "ns/llm", Kind: FactNetworkIdentity}).Key()
					got := af.CoverByAction[model.ActionRouteRotate]
					if len(got) != 1 || got[0] != network {
						t.Fatalf("route control=%v", got)
					}
					if want == 1 {
						for a, kind := range map[model.Action]string{model.ActionModelShardReplace: FactModelFingerprint, model.ActionMIGRebind: FactGPUContentionChannel, model.ActionKVMigrateInvalidate: FactSession, model.ActionRequestDrain: FactInflightRequests, model.ActionGuardrailRotate: FactGuardrailBypass, model.ActionAdapterRotate: FactAdapterIntegrity} {
							keys := af.CoverByAction[a]
							expected := (Fact{Scope: ScopePod, Asset: "ns/llm", Kind: kind}).Key()
							if len(keys) != 1 || keys[0] != expected {
								t.Errorf("preserved %s grant=%v, want %s", a, keys, expected)
							}
						}
					}
					t.Logf("audit facts=%d endpoint facts=%d route control=%v", len(af.Facts), count, got)
				})
			}
		}
	}
}
