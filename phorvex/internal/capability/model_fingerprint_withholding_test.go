package capability

import (
	"testing"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// Exercise actual recon -> pool index -> eligibility -> candidate generation.
// Only actuator transport is stubbed (okActuator); aliases/model-loaded labels
// represent declarations, never a witness of distinct loaded model identity.
func TestM037CandidateWithholding(t *testing.T) {
	for _, tc := range []struct {
		name, leaderAlias, shadowAlias string
		gpu, shadow, ready             bool
	}{
		{"same-alias", "model", "model", true, true, true},
		{"unequal-alias", "model", "other", true, true, true},
		{"missing-shadow-alias", "model", "", true, true, true},
		{"gpu-only", "", "", true, true, true},
		{"model-only", "model", "other", false, true, true},
		{"no-shadow", "model", "model", true, false, false},
		{"unready-shadow", "model", "other", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			views, _ := capFleet()
			v := views[0]
			v.Pod.ModelID, v.Pod.HasGPU = tc.leaderAlias, tc.gpu
			v.Pod.DesiredReplicas, v.Pod.ReadyReplicas = 3, 3
			v.Physics = model.NeutralPhysics()
			v.Phase = model.PhaseWarm
			shadow := views[2].Pod
			shadow.ModelID, shadow.Ready = tc.shadowAlias, tc.ready
			fleet := []model.Pod{v.Pod}
			if tc.shadow {
				fleet = append(fleet, shadow)
			}
			witness := witOver(fleet, twoGPUNodes(), nil)
			capable, why := witness.Capable(v, model.ActionModelShardReplace)
			if capable != (tc.shadow && tc.ready) {
				t.Fatalf("fixture capability = %v (%s)", capable, why)
			}
			rp, ok := recon.Registry.Get("ucw-recon")
			if !ok {
				t.Fatal("missing real recon profile")
			}
			pc := cost.NewP1Cost()
			d := actionset.Deps{Recon: rp, FactContext: func(v *model.WorkloadView) recon.FactContext {
				return recon.FactContext{AssetValue: 2, PHold: 0.8, StageUrgency: 0.5, HasGPU: v.Pod.HasGPU}
			}, ECost: pc.ECost, CHi: pc.CHi,
				Eligible: func(v *model.WorkloadView, a model.Action, cover []string) *actionset.Eligibility {
					r := witness.Eligible(v, a, cover)
					if r == nil {
						return nil
					}
					return &actionset.Eligibility{Excluded: r.Excluded, Kind: r.Kind, Detail: r.Detail, RBACUnknown: r.RBACUnknown}
				},
			}
			pol := model.Policy{MinAvailableReplicas: 1, P99Ms: 200,
				EnabledActions: map[model.Action]bool{model.ActionModelShardReplace: true, model.ActionGuardrailRotate: true}}
			set := d.Generate([]*model.WorkloadView{v}, pol)
			if set.Rejected || len(set.FactsAbsent) != 0 {
				t.Fatalf("fixture rejected: %+v", set)
			}
			key := "ns/leader"
			fingerprint := (recon.Fact{Scope: recon.ScopePod, Asset: key, Kind: recon.FactModelFingerprint}).Key()
			auditFound := false
			for _, f := range set.FactsByAsset[key] {
				if f.Key() == fingerprint {
					auditFound = f.Weight > 0
				}
			}
			if !auditFound {
				t.Fatal("positive-weight fingerprint lost from audit")
			}
			if _, present := set.FactWeights[fingerprint]; present {
				t.Error("unsupported fingerprint entered ranking weights")
			}
			excluded := false
			for _, e := range set.Excluded {
				if e.Action == model.ActionModelShardReplace {
					excluded = true
					if e.EligibilityKind != ReasonNoCover || len(e.CoverKeys) != 0 || e.FeasibilityEvaluated || e.CostEvaluated {
						t.Errorf("want early no-cover exclusion, got %+v", e)
					}
				}
			}
			if !excluded {
				t.Error("missing model-shard-replace no-cover exclusion")
			}
			control := false
			for _, c := range set.Candidates {
				if c.Action == model.ActionModelShardReplace {
					t.Error("unsupported model-shard-replace entered candidates")
				}
				for _, k := range c.CoverKeys {
					if k == fingerprint {
						t.Error("candidate received fingerprint credit")
					}
				}
				if c.Action == model.ActionGuardrailRotate && len(c.CoverKeys) == 1 && set.FactWeights[c.CoverKeys[0]] > 0 {
					control = true
				}
			}
			if !control {
				t.Fatalf("positive guardrail candidate missing: exclusions %+v", set.Excluded)
			}
		})
	}
}
