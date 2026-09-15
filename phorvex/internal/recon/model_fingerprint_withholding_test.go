package recon

import (
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// Declared model aliases and readiness are not loaded-identity/effect evidence.
func TestM037FingerprintWithheld(t *testing.T) {
	for _, tc := range []struct {
		name, alias string
		gpu         bool
	}{
		{"gpu-only", "", true}, {"model-only", "model-a", false},
		{"gpu-and-model", "model-a", true}, {"unequal-alias", "model-b", true},
		{"neither", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "leader", HasGPU: tc.gpu, ModelID: tc.alias,
				Ready: true, Node: "gpu-a", MIGDevice: "MIG-a", SuspectAdapter: "adapter-a", ServingEndpointReady: tc.gpu || tc.alias != ""},
				Physics: model.PhysicsWitness{ImageRarity: 1.2, EPSSMultiplier: 1.1, CoResidency: 1.2, ModelRarity: 1.5}}
			detectorAdapter(&v.Pod, "adapter-a")
			ctx := FactContext{AssetValue: 2, PHold: 0.8, StageUrgency: 0.5, HasGPU: tc.gpu}
			af := ucwRecon{}.AssetFacts(v, ctx)
			if af.AbsentReason != "" {
				t.Fatalf("fixture rejected: %s", af.AbsentReason)
			}
			byKind := map[string]Fact{}
			for _, f := range af.Facts {
				byKind[f.Kind] = f
			}
			mf, exists := byKind[FactModelFingerprint]
			if exists != (tc.gpu || tc.alias != "") {
				t.Fatalf("fingerprint presence = %v", exists)
			}
			scarcity, ok := DispersionMultiplier(v)
			if !ok {
				t.Fatal("invalid fixture scarcity")
			}
			base := 2 * 0.8 * 0.75 * scarcity
			if exists {
				if mf.Key() != (Fact{Scope: ScopePod, Asset: "ns/leader", Kind: FactModelFingerprint}).Key() || math.Abs(mf.Weight-base*1.5) > 1e-12 {
					t.Errorf("fingerprint key/weight changed: %+v want weight %g", mf, base*1.5)
				}
				for a, keys := range af.CoverByAction {
					for _, k := range keys {
						if k == mf.Key() {
							t.Errorf("unsupported fingerprint cover: %s", a)
						}
					}
				}
				// Existing independent grants; endpoint withholding is inherited from M-035.
				for action, kind := range map[model.Action]string{
					model.ActionMIGRebind:    FactGPUContentionChannel,
					model.ActionRequestDrain: FactInflightRequests, model.ActionGuardrailRotate: FactGuardrailBypass,
					model.ActionKVMigrateInvalidate: FactSession, model.ActionAdapterRotate: FactAdapterIntegrity,
				} {
					keys := af.CoverByAction[action]
					if len(keys) != 1 || keys[0] != byKind[kind].Key() {
						t.Errorf("control %s cover = %v", action, keys)
					}
				}
			}
			identity, hasIdentity := byKind[FactModelIdentity]
			if hasIdentity != (tc.alias != "") {
				t.Fatalf("shared identity presence = %v", hasIdentity)
			}
			if hasIdentity && (identity.Scope != ScopeModel || identity.Asset != tc.alias || math.Abs(identity.Weight-base) > 1e-12) {
				t.Errorf("shared identity changed: %+v", identity)
			}
			if len(af.CoverByAction[model.ActionModelShardReplace]) != 0 {
				t.Error("model-shard-replace must remain coverless without identity/effect evidence")
			}
		})
	}
}
