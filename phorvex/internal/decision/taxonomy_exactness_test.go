package decision

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type withoutAuditTaxonomy struct {
	base recon.ReconProfile
}

func (p withoutAuditTaxonomy) Name() string { return "test-without-audit-taxonomy" }

func (p withoutAuditTaxonomy) AssetFacts(view *model.WorkloadView, ctx recon.FactContext) recon.AssetFacts {
	af := p.base.AssetFacts(view, ctx)
	auditOnly := map[string]bool{
		recon.FactNodeFoothold:            true,
		recon.FactModelIdentity:           true,
		recon.FactGuardrailVariant:        true,
		recon.FactCredential:              true,
		recon.FactRetrievalState:          true,
		recon.FactArtifactProvenance:      true,
		recon.FactControlPlanePersistence: true,
	}
	kept := af.Facts[:0]
	for _, fact := range af.Facts {
		if !auditOnly[fact.Kind] {
			kept = append(kept, fact)
		}
	}
	af.Facts = kept
	return af
}

func taxonomyEngine(profile recon.ReconProfile) *CoverageEngine {
	e := NewCoverageEngine()
	e.Recon = profile
	e.Now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	return e
}

func selectedTaxonomyDecisions(e *CoverageEngine, views []*model.WorkloadView, pol model.Policy) []string {
	selected := []string{}
	for _, decision := range e.Decide(views, pol) {
		if decision.Selected {
			selected = append(selected,
				decision.Namespace+"/"+decision.Pod+"/"+string(decision.Action))
		}
	}
	return selected
}

func TestAuditTaxonomyPreservesDecisionsAndExactObjective(t *testing.T) {
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon is not registered")
	}
	without := withoutAuditTaxonomy{base: profile}
	views := shippedFleet()
	policy := covPolicy(2)
	seeds := []int64{1, 2, 3}

	fullDecisions := selectedTaxonomyDecisions(taxonomyEngine(profile), views, policy)
	withoutDecisions := selectedTaxonomyDecisions(taxonomyEngine(without), views, policy)
	if !reflect.DeepEqual(fullDecisions, withoutDecisions) {
		t.Fatalf("adding zero-cover facts changed selected decisions: full=%v without=%v",
			fullDecisions, withoutDecisions)
	}

	full := taxonomyEngine(profile).Ablate(views, policy, seeds)
	baseline := taxonomyEngine(without).Ablate(views, policy, seeds)
	if math.Abs(full.GreedyObjective-baseline.GreedyObjective) > 1e-12 ||
		math.Abs(full.ExactObjective-baseline.ExactObjective) > 1e-12 {
		t.Fatalf("zero-cover facts changed objective: full greedy/exact=%.12f/%.12f, baseline=%.12f/%.12f",
			full.GreedyObjective, full.ExactObjective, baseline.GreedyObjective, baseline.ExactObjective)
	}
	if full.ExactSkipped || !full.CoversDisjoint || math.Abs(full.OptimalityRatio-1) > 1e-12 {
		t.Fatalf("taxonomy violated exactness gate: skipped=%v disjoint=%v ratio=%.12f note=%s",
			full.ExactSkipped, full.CoversDisjoint, full.OptimalityRatio, full.SharedKeyNote)
	}
	t.Logf("MEASURED identical fleet: selected=%v greedy=%.12f exact=%.12f ratio=%.12f disjoint=%v skipped=%v",
		fullDecisions, full.GreedyObjective, full.ExactObjective, full.OptimalityRatio,
		full.CoversDisjoint, full.ExactSkipped)
}
