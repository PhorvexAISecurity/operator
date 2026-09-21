package capability

import (
	"testing"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// Exercise actual recon -> pool index -> eligibility -> candidate generation.
// Only actuator transport is stubbed (okActuator). A qualified scalar shard pool may
// now predict old-process retirement, but aliases/model-loaded labels remain declarations,
// never a witness that the loaded model fingerprint changes.
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
			v.Pod.ServingDeclared, v.Pod.ServingEndpointReady = tc.leaderAlias != "", tc.leaderAlias != ""
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
			if capable != (tc.leaderAlias != "" && tc.shadow && tc.ready) {
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
			if auditFound != (tc.leaderAlias != "") {
				t.Fatalf("positive-weight fingerprint presence=%v, want declared model=%v", auditFound, tc.leaderAlias != "")
			}
			if _, present := set.FactWeights[fingerprint]; present {
				t.Error("unsupported fingerprint entered ranking weights")
			}
			processKinds := map[string]bool{}
			for _, fact := range set.FactsByAsset[key] {
				if fact.Kind == recon.FactPodIdentity || fact.Kind == recon.FactInMemory || fact.Kind == recon.FactSession {
					processKinds[fact.Key()] = true
				}
			}
			wantProcessCover := tc.leaderAlias != ""
			wantCandidate := wantProcessCover && capable
			excluded := false
			candidate := false
			for _, e := range set.Excluded {
				if e.Action == model.ActionModelShardReplace {
					excluded = true
					wantKind := ReasonCapability
					if !wantProcessCover {
						wantKind = ReasonNoCover
					}
					if e.EligibilityKind != wantKind || (wantProcessCover && len(e.CoverKeys) != 3) || (!wantProcessCover && len(e.CoverKeys) != 0) {
						t.Errorf("model-shard exclusion does not preserve cover/capability ordering: %+v", e)
					}
				}
			}
			control := false
			for _, c := range set.Candidates {
				if c.Action == model.ActionModelShardReplace {
					candidate = true
					if len(c.CoverKeys) != 3 {
						t.Errorf("qualified scalar retirement cover = %v", c.CoverKeys)
					}
					for _, coverKey := range c.CoverKeys {
						if !processKinds[coverKey] {
							t.Errorf("model-shard candidate received non-process cover %s", coverKey)
						}
					}
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
			if candidate != wantCandidate || excluded == wantCandidate {
				t.Fatalf("model-shard candidate=%v excluded=%v, want candidate=%v: exclusions=%+v", candidate, excluded, wantCandidate, set.Excluded)
			}
			if control != (tc.leaderAlias != "") {
				t.Fatalf("guardrail candidate=%v, want declared model=%v: exclusions %+v", control, tc.leaderAlias != "", set.Excluded)
			}
		})
	}
}
