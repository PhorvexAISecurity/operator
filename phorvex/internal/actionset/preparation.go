package actionset

import (
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// PreparedCandidate has passed the real non-cost generator gates. It deliberately
// has no legacy cost fields: preparation does not manufacture zero prices or
// authorize selection. An explicit offline study must supply its own cost and
// admission evidence before selecting from this set.
type PreparedCandidate struct {
	GenerationRank int
	SLOExclusions  []string
	Key            string
	View           *model.WorkloadView
	Action         model.Action
	CoverKeys      []string
	Resources      []model.ResourceConsumption
	RBACUnknown    bool
}

// Preparation is the complete, shared non-cost generator result. Excluded rows
// retain their first real veto; gates after that veto were not evaluated.
type Preparation struct {
	Candidates           []PreparedCandidate
	Resources            []model.ResourceCapacity
	FactWeights          map[string]float64
	FactsByAsset         map[string][]recon.Fact
	FactsAbsent          map[string]string
	CrossBlockCollisions []CrossBlockCollision
	Rejected             bool
	Excluded             []Exclusion
	CoverByAsset         map[string]map[model.Action][]string
}

// Prepare uses exactly Generate's binding, capability, resource, recon and
// feasibility path and stops before legacy cost evaluation. Production Generate
// never calls this method and retains its existing pricing/CHi gates.
func (d Deps) Prepare(views []*model.WorkloadView, pol model.Policy) Preparation {
	var candidates []PreparedCandidate
	set := d.generate(views, pol, func(c PreparedCandidate) { candidates = append(candidates, c) })
	if set.Rejected {
		candidates = nil
	}
	return Preparation{Candidates: candidates, Resources: set.Resources, FactWeights: set.FactWeights,
		FactsByAsset: set.FactsByAsset, FactsAbsent: set.FactsAbsent, CrossBlockCollisions: set.CrossBlockCollisions,
		Rejected: set.Rejected, Excluded: set.Excluded, CoverByAsset: set.CoverByAsset}
}
