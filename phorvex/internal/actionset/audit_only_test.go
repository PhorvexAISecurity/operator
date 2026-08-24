package actionset

import (
	"reflect"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type auditOnlyDecorator struct {
	base recon.ReconProfile
}

func (d auditOnlyDecorator) Name() string { return "test-audit-only-decorator" }

func (d auditOnlyDecorator) AssetFacts(view *model.WorkloadView, ctx recon.FactContext) recon.AssetFacts {
	af := d.base.AssetFacts(view, ctx)
	asset := view.Pod.Namespace + "/" + view.Pod.Name
	af.Facts = append(af.Facts,
		recon.Fact{
			Scope: recon.ScopeNode, Asset: "shared-node", Kind: recon.FactNodeFoothold,
			Weight: 1e12,
		},
		recon.Fact{
			Scope: recon.ScopePod, Asset: asset, Kind: recon.FactCredential,
			Weight: 1e12,
		},
	)
	return af
}

func TestAuditOnlyFactsCannotAffectGeneratedObjective(t *testing.T) {
	deps := testDeps()
	views := []*model.WorkloadView{baseView("one"), baseView("two")}
	policy := testPolicy()

	baseline := deps.Generate(views, policy)
	deps.Recon = auditOnlyDecorator{base: deps.Recon}
	withAudit := deps.Generate(views, policy)

	if !reflect.DeepEqual(withAudit.Candidates, baseline.Candidates) {
		t.Fatalf("zero-cover audit facts changed candidates\nwith audit: %+v\nbaseline: %+v",
			withAudit.Candidates, baseline.Candidates)
	}
	if !reflect.DeepEqual(withAudit.FactWeights, baseline.FactWeights) {
		t.Fatalf("zero-cover audit facts entered objective weights\nwith audit: %+v\nbaseline: %+v",
			withAudit.FactWeights, baseline.FactWeights)
	}
	if !reflect.DeepEqual(withAudit.Excluded, baseline.Excluded) {
		t.Fatalf("zero-cover audit facts changed exclusions\nwith audit: %+v\nbaseline: %+v",
			withAudit.Excluded, baseline.Excluded)
	}
	if withAudit.Rejected || len(withAudit.CrossBlockCollisions) != 0 {
		t.Fatalf("shared-scope audit keys were treated as selectable block collisions: %+v",
			withAudit.CrossBlockCollisions)
	}
}
