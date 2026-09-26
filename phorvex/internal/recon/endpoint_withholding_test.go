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
					v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "llm", HasGPU: asset.gpu, ModelID: asset.model, RouteService: route, RouteKeyEpoch: epoch, MIGDevice: "MIG-a", SuspectAdapter: "bad", ServingEndpointReady: asset.model != ""}}
					detectorAdapter(&v.Pod, "bad")
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
					if asset.model != "" {
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
					// The same producer withholds route-rotate credit while retaining the
					// independently qualified quarantine network effect.
					network := (Fact{Scope: ScopePod, Asset: "ns/llm", Kind: FactNetworkIdentity}).Key()
					got := af.CoverByAction[model.ActionRouteRotate]
					if len(got) != 0 {
						t.Fatalf("route selector change received locator credit=%v", got)
					}
					quarantine := af.CoverByAction[model.ActionQuarantine]
					if len(quarantine) != 1 || quarantine[0] != network {
						t.Fatalf("quarantine control=%v, want %s", quarantine, network)
					}
					if asset.gpu {
						keys := af.CoverByAction[model.ActionMIGRebind]
						expected := (Fact{Scope: ScopePod, Asset: "ns/llm", Kind: FactGPUContentionChannel}).Key()
						if len(keys) != 1 || keys[0] != expected {
							t.Errorf("preserved MIG grant=%v, want %s", keys, expected)
						}
					}
					if asset.model != "" {
						// M-037 also withholds modelFingerprint; preserve independent serving grants.
						// Cyclic guardrail rotation no longer claims deterministic bypass invalidation.
						for a, kind := range map[model.Action]string{model.ActionKVMigrateInvalidate: FactSession, model.ActionRequestDrain: FactInflightRequests} {
							keys := af.CoverByAction[a]
							expected := (Fact{Scope: ScopePod, Asset: "ns/llm", Kind: kind}).Key()
							if len(keys) != 1 || keys[0] != expected {
								t.Errorf("preserved %s grant=%v, want %s", a, keys, expected)
							}
						}
						if keys := af.CoverByAction[model.ActionGuardrailRotate]; len(keys) != 0 {
							t.Errorf("unsupported guardrail bypass grant=%v", keys)
						}
					}
					keys := af.CoverByAction[model.ActionAdapterRotate]
					expected := (Fact{Scope: ScopePod, Asset: "ns/llm", Kind: FactAdapterIntegrity}).Key()
					if len(keys) != 1 || keys[0] != expected {
						t.Errorf("preserved adapter grant=%v, want %s", keys, expected)
					}
					t.Logf("audit facts=%d endpoint facts=%d route cover=%v quarantine control=%v", len(af.Facts), count, got, quarantine)
				})
			}
		}
	}
}
