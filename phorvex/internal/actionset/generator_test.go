/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package actionset

import (
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

func testPolicy() model.Policy {
	return model.Policy{
		Tenant:                 "t",
		NormSparsity:           0.4,
		FlowDisruption:         0.6,
		MinAvailableReplicas:   1,
		P99Ms:                  200,
		AntiOverRotationWindow: 5 * time.Minute,
		EnabledActions:         map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true},
	}
}

func setDetectorAdapter(v *model.WorkloadView, name string) {
	if v.Pod.UID == "" {
		v.Pod.UID = "synthetic-pod-uid"
	}
	v.Pod.SuspectAdapter = name
	v.Pod.AdapterObservation = &model.AdapterObservation{EventName: "detected", EventUID: "synthetic-event-uid",
		CreatorIdentity: "system:serviceaccount:ns:detector", TargetPodUID: v.Pod.UID, AdapterName: name}
}

func baseView(name string) *model.WorkloadView {
	return &model.WorkloadView{
		Pod: model.Pod{
			Namespace: "ns", Name: name, UID: "u-" + name,
			DesiredReplicas: 3, ReadyReplicas: 3, Ready: true,
		},
		Phase:       model.PhaseWarm,
		Telemetry:   model.Telemetry{ReqRate: model.PresentSignal(0, "fixture-measured")},
		BlastRadius: 0.5,
		ExposureByVariable: map[string]time.Duration{
			model.VarPodIdentity:     2 * time.Hour, // past the anti-over-rotation window (rotate's clock)
			model.VarNetworkIdentity: 2 * time.Hour, // quarantine's M-23 per-action clock, likewise past window
		},
	}
}

func TestMissingLoadUsesConservativeRotateGate(t *testing.T) {
	d := testDeps()
	pol := testPolicy()
	missing := baseView("missing-load")
	missing.Telemetry.ReqRate = model.Signal{}
	set := d.Generate([]*model.WorkloadView{missing}, pol)
	if actionsFor(set, "ns/missing-load")[model.ActionRotate] {
		t.Fatal("missing request load must not retain the measured-zero rotate candidate")
	}
	found := false
	for _, exclusion := range set.Excluded {
		if exclusion.Key == "ns/missing-load" && exclusion.Action == model.ActionRotate {
			found = strings.Contains(exclusion.Reason, "conformal-slo") && exclusion.CostEvaluated && exclusion.CHi > set.CostCeiling
		}
	}
	if !found {
		t.Fatalf("missing-load rotate lacks explicit conservative cost exclusion: %+v", set.Excluded)
	}
}

func testDeps() Deps {
	rp, _ := recon.Registry.Default()
	pc := cost.NewP1Cost()
	return Deps{
		Recon: rp,
		FactContext: func(v *model.WorkloadView) recon.FactContext {
			return recon.FactContext{
				AssetValue: 1.0, PHold: 0.8, StageUrgency: 0.5, BlastRadius: v.BlastRadius,
				HasGPU: v.Pod.HasGPU, Stateful: v.Pod.Stateful,
			}
		},
		ECost:       pc.ECost,
		CHi:         pc.CHi,
		CostCeiling: cost.DefaultCostCeiling,
	}
}

func ucwTestDeps(t *testing.T) Deps {
	t.Helper()
	d := testDeps()
	rp, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon profile is not registered")
	}
	d.Recon = rp
	return d
}

func actionsFor(set ActionSet, key string) map[model.Action]bool {
	out := map[model.Action]bool{}
	for _, c := range set.Candidates {
		if c.Key == key {
			out[c.Action] = true
		}
	}
	return out
}

// THE CORE-IP TEST: the generated feasible action set CHANGES with physics+context
// state — it is computed live, not a static list.
func TestDynamicActionSetChangesWithState(t *testing.T) {
	d := testDeps()
	pol := testPolicy()

	// 1. Normal pod => both rotate + quarantine feasible.
	normal := actionsFor(d.Generate([]*model.WorkloadView{baseView("normal")}, pol), "ns/normal")
	if !normal[model.ActionRotate] || !normal[model.ActionQuarantine] {
		t.Errorf("normal pod should offer rotate+quarantine, got %v", normal)
	}

	// 2. Stateful pod => rotate REMOVED (would destroy state), quarantine remains.
	sf := baseView("state")
	sf.Pod.Stateful = true
	stateful := actionsFor(d.Generate([]*model.WorkloadView{sf}, pol), "ns/state")
	if stateful[model.ActionRotate] {
		t.Errorf("stateful pod must NOT offer rotate (set must drop it)")
	}
	if !stateful[model.ActionQuarantine] {
		t.Errorf("stateful pod should still offer quarantine")
	}

	// 3. Freshly-moved pod (exposure < anti-over-rotation window) => BOTH removed.
	fresh := baseView("fresh")
	fresh.ExposureByVariable[model.VarPodIdentity] = 30 * time.Second     // freshly rotated
	fresh.ExposureByVariable[model.VarNetworkIdentity] = 30 * time.Second // and freshly quarantined (M-23 per-action clock)
	freshSet := actionsFor(d.Generate([]*model.WorkloadView{fresh}, pol), "ns/fresh")
	if len(freshSet) != 0 {
		t.Errorf("freshly-moved pod must have an EMPTY action set (anti-over-rotation), got %v", freshSet)
	}

	// 4. SLO-hot pod (p99 at ceiling) => BOTH removed (SLO hard gate).
	hot := baseView("hot")
	hot.Telemetry = model.Telemetry{P99Ms: model.PresentSignal(250, "test")}
	hotSet := actionsFor(d.Generate([]*model.WorkloadView{hot}, pol), "ns/hot")
	if len(hotSet) != 0 {
		t.Errorf("SLO-hot pod must have an EMPTY action set, got %v", hotSet)
	}

	// 5. GPU pod, uncalibrated cost => rotate pruned by the conformal SLO gate (worst-case
	// GPU warm-load [SP-0-PENDING] exceeds the ceiling); quarantine remains (safe fallback).
	gpu := baseView("gpu")
	gpu.Pod.HasGPU = true
	gpuSet := actionsFor(d.Generate([]*model.WorkloadView{gpu}, pol), "ns/gpu")
	if gpuSet[model.ActionRotate] {
		t.Errorf("uncalibrated GPU pod rotate must be pruned by the conformal SLO gate (safe-by-default)")
	}
	if !gpuSet[model.ActionQuarantine] {
		t.Errorf("GPU pod should still offer quarantine")
	}
}

func TestQuarantineCapacityIsHardAndLeavesOtherActionsEligible(t *testing.T) {
	d := testDeps()
	d.RetainSLO = func(string) bool { return true }
	view := baseView("capacity")
	base := testPolicy()
	base.QuarantineCapacityConfigured = true
	base.QuarantineCapacityLimit = 1

	cases := []struct {
		name       string
		known      bool
		used       int
		wantQ      bool
		wantReason string
	}{
		{name: "unknown inventory", known: false, wantReason: "quarantine-capacity-inventory-unknown"},
		{name: "exhausted", known: true, used: 1, wantReason: "quarantine-capacity-exhausted"},
		{name: "below cap", known: true, used: 0, wantQ: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pol := base
			pol.QuarantineCapacityKnown = tc.known
			pol.QuarantineCapacityUsed = tc.used
			pol.QuarantineCapacityReason = "fixture inventory unavailable"
			set := d.Generate([]*model.WorkloadView{view}, pol)
			actions := actionsFor(set, "ns/capacity")
			if actions[model.ActionQuarantine] != tc.wantQ {
				t.Fatalf("quarantine candidate=%v want %v; candidates=%+v excluded=%+v", actions[model.ActionQuarantine], tc.wantQ, set.Candidates, set.Excluded)
			}
			if !actions[model.ActionRotate] {
				t.Fatalf("capacity law must leave non-quarantine actions eligible: %+v", set)
			}
			if tc.wantReason != "" {
				found := false
				for _, exclusion := range set.Excluded {
					if exclusion.Action == model.ActionQuarantine && strings.Contains(exclusion.Reason, tc.wantReason) {
						found = true
					}
				}
				if !found {
					t.Fatalf("missing %q exclusion: %+v", tc.wantReason, set.Excluded)
				}
			}
		})
	}
}

// Inviolability at the generator layer: every excluded move carries a hard-constraint
// reason and NEVER appears as a candidate.
func TestExcludedMovesAreNeverCandidates(t *testing.T) {
	d := testDeps()
	pol := testPolicy()
	sf := baseView("state")
	sf.Pod.Stateful = true
	set := d.Generate([]*model.WorkloadView{sf}, pol)
	// rotate must be in Excluded with a reason, not in Candidates.
	for _, c := range set.Candidates {
		if c.Key == "ns/state" && c.Action == model.ActionRotate {
			t.Fatalf("stateful rotate leaked into the candidate set")
		}
	}
	found := false
	for _, ex := range set.Excluded {
		if ex.Key == "ns/state" && ex.Action == model.ActionRotate && ex.Reason != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("stateful rotate should be recorded in Excluded with a reason")
	}
}

func TestAdapterRotateWithoutSuspectAdapterIsStructurallyExcluded(t *testing.T) {
	d := ucwTestDeps(t)
	pol := testPolicy()
	pol.EnabledActions = map[model.Action]bool{model.ActionAdapterRotate: true}
	clean := baseView("clean-lora")
	clean.Pod.ModelID = "model-a"

	set := d.Generate([]*model.WorkloadView{clean}, pol)
	if len(set.Candidates) != 0 {
		t.Fatalf("adapter-rotate without an adapter-integrity fact must emit no candidates, got %+v", set.Candidates)
	}
	found := false
	for _, ex := range set.Excluded {
		if ex.Key == "ns/clean-lora" && ex.Action == model.ActionAdapterRotate && ex.Reason == emptyReconCoverReason {
			found = true
		}
	}
	if !found {
		t.Fatalf("adapter-rotate must be audited as structurally excluded, got %+v", set.Excluded)
	}
}

func TestAdapterRotateWithSuspectAdapterHasNonEmptyCover(t *testing.T) {
	d := ucwTestDeps(t)
	pol := testPolicy()
	pol.EnabledActions = map[model.Action]bool{model.ActionAdapterRotate: true}
	poisoned := baseView("poisoned-lora")
	poisoned.Pod.ModelID = "model-a"
	setDetectorAdapter(poisoned, "evil-adapter")

	set := d.Generate([]*model.WorkloadView{poisoned}, pol)
	if len(set.Candidates) != 1 {
		t.Fatalf("flagged adapter must produce one adapter-rotate candidate, got candidates=%+v excluded=%+v", set.Candidates, set.Excluded)
	}
	cand := set.Candidates[0]
	if cand.Action != model.ActionAdapterRotate || len(cand.CoverKeys) == 0 {
		t.Fatalf("flagged adapter candidate must carry adapter-integrity cover, got %+v", cand)
	}
}

func TestExtendedActionIsPrunedAboveImportedCostCeiling(t *testing.T) {
	d := ucwTestDeps(t)
	d.CostCeiling = cost.DefaultCostCeiling
	d.Evaluate = func(_ *model.WorkloadView, _ model.Move, _ model.Policy) (float64, float64, string, string) {
		return 1.0, cost.DefaultCostCeiling + 0.01, "", ""
	}
	pol := testPolicy()
	pol.EnabledActions = map[model.Action]bool{model.ActionAdapterRotate: true}
	view := baseView("costly-adapter")
	view.Pod.ModelID = "model-a"
	setDetectorAdapter(view, "evil-adapter")

	set := d.Generate([]*model.WorkloadView{view}, pol)
	if len(set.Candidates) != 0 {
		t.Fatalf("extended action above ceiling leaked into candidates: %+v", set.Candidates)
	}
	found := false
	for _, ex := range set.Excluded {
		if ex.Action == model.ActionAdapterRotate && ex.Reason != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("extended action ceiling exclusion missing: %+v", set.Excluded)
	}
}

func TestNaNCostIsDistinctUnfooledExclusion(t *testing.T) {
	d := ucwTestDeps(t)
	d.Evaluate = func(_ *model.WorkloadView, _ model.Move, _ model.Policy) (float64, float64, string, string) {
		return cost.NaNFailConservativeCost, cost.NaNFailConservativeCost,
			cost.UnactionableNaNCategory, "telemetry.reqRate"
	}
	pol := testPolicy()
	pol.EnabledActions = map[model.Action]bool{model.ActionAdapterRotate: true}
	view := baseView("nan-adapter")
	view.Pod.ModelID = "model-a"
	setDetectorAdapter(view, "evil-adapter")

	set := d.Generate([]*model.WorkloadView{view}, pol)
	if len(set.Candidates) != 0 || len(set.Excluded) != 1 {
		t.Fatalf("NaN action must be excluded exactly once: %+v", set)
	}
	ex := set.Excluded[0]
	if ex.Category != cost.UnactionableNaNCategory || ex.Detail != "telemetry.reqRate" {
		t.Fatalf("NaN exclusion category/detail lost: %+v", ex)
	}
}

func TestGenerateNeverEmitsAnEmptyCoverCandidate(t *testing.T) {
	d := ucwTestDeps(t)
	pol := testPolicy()
	pol.EnabledActions = make(map[model.Action]bool, len(model.MutatingActions))
	for _, action := range model.MutatingActions {
		pol.EnabledActions[action] = true
	}
	v := baseView("all-actions")
	v.Pod.HasGPU = true
	v.Pod.ModelID = "model-a"
	v.Pod.MIGDevice = "1g.10gb"
	setDetectorAdapter(v, "evil-adapter")

	set := d.Generate([]*model.WorkloadView{v}, pol)
	if len(set.Candidates) == 0 {
		t.Fatal("invariant fixture must exercise at least one emitted candidate")
	}
	for _, cand := range set.Candidates {
		if len(cand.CoverKeys) == 0 {
			t.Errorf("generator emitted empty-cover candidate %s/%s", cand.Key, cand.Action)
		}
	}
}

func TestM033IdentityVocabularyProducesDeclaredRefusal(t *testing.T) {
	d := ucwTestDeps(t)
	pol := testPolicy()
	pol.EnabledActions = map[model.Action]bool{model.ActionIdentityRotate: true, model.ActionRouteRotate: true}
	v := baseView("identity")
	set := d.Generate([]*model.WorkloadView{v}, pol)
	for _, cand := range set.Candidates {
		if cand.Action == model.ActionIdentityRotate {
			t.Fatalf("identity-rotate emitted from real recon producer: %+v", cand)
		}
	}
	for _, ex := range set.Excluded {
		if ex.Action == model.ActionIdentityRotate {
			if ex.Reason != model.IdentityRotateUnsupportedReason || ex.EligibilityKind != "capability-unsupported" {
				t.Fatalf("identity exclusion lacks declared reason: %+v", ex)
			}
			return
		}
	}
	t.Fatal("identity vocabulary produced neither candidate nor declared exclusion")
}
