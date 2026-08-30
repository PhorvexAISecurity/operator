/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

// Package actionset is the DYNAMIC ACTION-SET GENERATOR — the core P1 IP. Each tick it
// computes the FEASIBLE (asset, action) set LIVE from physics+context state (NOT a
// static list); the submodular optimizer then selects ONLY from this generated set.
// Because every infeasible or SLO-unsafe move is EXCLUDED here, the optimizer can never
// return a hard-constraint-violating move — that is the structural inviolability proof
// (Layer A feasibility + the conformal SLO gate are applied before, not during,
// optimization).
package actionset

import (
	"fmt"

	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// Candidate is one feasible (asset, action) with a non-empty recon cover set and costs.
type Candidate struct {
	Key       string // "ns/pod"
	View      *model.WorkloadView
	Action    model.Action
	CoverKeys []string // recon fact keys this move invalidates
	ECost     float64  // expected (objective) cost
	CHi       float64  // conformal worst-case cost (used by the hard SLO gate)
}

// ActionSet is the generator output: the feasible candidates plus the tick's global
// recon fact-weight map (cover keys index into it for the coverage objective).
type ActionSet struct {
	Candidates []Candidate
	// FactWeights contains only keys referenced by at least one action cover. Audit-only facts stay
	// in recon.AssetFacts but cannot enter marginal gain, normalization, or collision ownership.
	FactWeights map[string]float64
	// FactsByAsset retains the already-generated recon output for the decision
	// trace, including audit-only facts. Selection continues to read FactWeights.
	FactsByAsset map[string][]recon.Fact
	// CrossBlockCollisions records the structural violations that make this entire
	// tick unsafe to optimize. Rejected is fail-closed: no candidate may be selected.
	CrossBlockCollisions []CrossBlockCollision
	Rejected             bool
	// Excluded records (asset,action,reason) pairs pruned by structural relevance or
	// a hard constraint — surfaced for audit/inviolability, never selectable.
	Excluded []Exclusion
}

// CrossBlockCollision is one recon key claimed by two distinct pod decision blocks.
// Reuse by multiple actions inside one block is legal under the partition constraint;
// reuse across blocks breaks modularity and voids the exact-optimality guarantee.
type CrossBlockCollision struct {
	Key              string
	ExistingBlock    string
	ConflictingBlock string
}

func (c CrossBlockCollision) Error() string {
	return fmt.Sprintf("cross-block recon-key collision: key %q belongs to both %q and %q",
		c.Key, c.ExistingBlock, c.ConflictingBlock)
}

// CollisionError returns the first structural error that rejected this set.
func (s ActionSet) CollisionError() error {
	if len(s.CrossBlockCollisions) == 0 {
		return nil
	}
	return s.CrossBlockCollisions[0]
}

// Exclusion is one pruned move and the structural or hard-constraint reason.
type Exclusion struct {
	Key                  string
	Action               model.Action
	Reason               string
	Category             string
	Detail               string
	CoverKeys            []string
	FeasibilityEvaluated bool
	Feasible             bool
	CostEvaluated        bool
	ECost                float64
	CHi                  float64
}

const emptyReconCoverReason = "recon-cover: action invalidates no facts for this asset"

// Deps are the per-tick collaborators the generator binds (supplied by the engine so
// the generator stays free of context/cost/killchain imports).
type Deps struct {
	Recon       recon.ReconProfile
	FactContext func(*model.WorkloadView) recon.FactContext
	ECost       func(*model.WorkloadView, model.Move, model.Policy) float64
	CHi         func(*model.WorkloadView, model.Move, model.Policy) float64
	// Evaluate optionally computes both costs once and carries a distinct
	// unactionable category/detail (for example a NaN feature). Existing swappable
	// test models may leave it nil and continue using ECost/CHi.
	Evaluate func(*model.WorkloadView, model.Move, model.Policy) (ecost, chi float64, category, detail string)
	// CostCeiling is the worst-case (CHi) cost above which a move is deemed SLO-unsafe
	// and pruned (the conformal SLO gate). The engine derives it from the policy.
	CostCeiling float64
}

func enabledActions(pol model.Policy) []model.Action {
	var out []model.Action
	for _, a := range model.MutatingActions { // single source of truth (cannot drift from candidateActions)
		if model.ActionEnabled(pol, a) {
			out = append(out, a)
		}
	}
	return out
}

// GeneratableActions is the canonical set the completeness invariant enumerates: every
// action a policy MAY enable and the generator MAY emit. It is model.MutatingActions (the
// CoverByAction keys are always a subset). The native actuator MUST carry a handler for
// each — actuator's completeness check fails the build (CI + startup) otherwise.
func GeneratableActions() []model.Action {
	out := make([]model.Action, len(model.MutatingActions))
	copy(out, model.MutatingActions)
	return out
}

// Generate builds the live feasible action set. Steps per (asset, enabled action):
//
//  1. Structural recon relevance — an action that invalidates no facts for this
//     asset is EXCLUDED before cost/feasibility work and cannot contaminate demand.
//  2. Layer-A hard feasibility (PDB/availability, SLO-p99, anti-over-rotation,
//     stateful-integrity) via the registry — an infeasible move is EXCLUDED.
//  3. Cost-data validity — a NaN-bearing action is excluded fail-conservative in
//     its own observable category, never silently folded into ordinary infeasibility.
//  4. Conformal SLO-cost gate — if the worst-case cost CHi exceeds CostCeiling the
//     move could breach the disruption budget, so it is EXCLUDED.
//  5. Survivors enter the set with their non-empty recon cover keys + costs.
//
// The set provably changes with state and contains NO hard-constraint-violating move.
func (d Deps) Generate(views []*model.WorkloadView, pol model.Policy) ActionSet {
	out := ActionSet{FactWeights: map[string]float64{}, FactsByAsset: map[string][]recon.Fact{}}
	keyOwners := map[string]string{}
	claim := func(factKey, block string) bool {
		owner, exists := keyOwners[factKey]
		if !exists {
			keyOwners[factKey] = block
			return true
		}
		if owner == block {
			return true // legal within-pod overlap across facts/actions
		}
		out.CrossBlockCollisions = append(out.CrossBlockCollisions, CrossBlockCollision{
			Key: factKey, ExistingBlock: owner, ConflictingBlock: block,
		})
		out.Rejected = true
		// Leave no partially generated candidates behind. Even a caller that forgets
		// to inspect CollisionError cannot select from a structurally invalid set.
		out.Candidates = nil
		return false
	}
	for _, v := range views {
		key := v.Pod.Namespace + "/" + v.Pod.Name
		af := d.Recon.AssetFacts(v, d.FactContext(v))
		out.FactsByAsset[key] = append([]recon.Fact(nil), af.Facts...)
		coveredKeys := map[string]bool{}
		// Scan every declared cover, including disabled actions. A topology-conditional
		// collision is a taxonomy violation independent of this tenant's current policy.
		for _, coverKeys := range af.CoverByAction {
			for _, factKey := range coverKeys {
				coveredKeys[factKey] = true
				if !claim(factKey, key) {
					return out
				}
			}
		}
		// Objective weights are projected strictly through action covers. This is the hard boundary
		// that keeps shared-scope and CANNOT-HELP facts audit-only: even a large audit weight cannot
		// influence selection unless a deterministic eraser explicitly names its key.
		for _, f := range af.Facts {
			factKey := f.Key()
			if !coveredKeys[factKey] {
				continue
			}
			if w := f.Weight; w > out.FactWeights[factKey] {
				out.FactWeights[factKey] = w
			}
		}
		for _, action := range enabledActions(pol) {
			coverKeys := af.CoverByAction[action]
			// A move with no cover has zero marginal security gain by construction. Letting
			// it through cannot improve the objective, but does inflate candidate/demand and
			// audit counts (adapter-rotate on an unflagged pod was the live example).
			if len(coverKeys) == 0 {
				out.Excluded = append(out.Excluded, Exclusion{
					Key: key, Action: action, Reason: emptyReconCoverReason,
				})
				continue
			}
			move := model.Move{Action: action}
			// (2) Layer-A hard feasibility.
			if verdict := feasibility.Evaluate(v, move, pol); !verdict.Feasible {
				out.Excluded = append(out.Excluded, Exclusion{
					Key: key, Action: action, Reason: verdict.Reason,
					CoverKeys: append([]string(nil), coverKeys...), FeasibilityEvaluated: true,
				})
				continue
			}
			// (3) Evaluate cost. A data-quality failure is a distinct fail-closed
			// category, not ordinary physical infeasibility and not a cheap default.
			ecost, chi := 0.0, 0.0
			category, detail := "", ""
			if d.Evaluate != nil {
				ecost, chi, category, detail = d.Evaluate(v, move, pol)
			} else {
				ecost, chi = d.ECost(v, move, pol), d.CHi(v, move, pol)
			}
			if category != "" {
				reason := category
				if detail != "" {
					reason += ": " + detail
				}
				out.Excluded = append(out.Excluded, Exclusion{
					Key: key, Action: action, Reason: reason, Category: category, Detail: detail,
					CoverKeys: append([]string(nil), coverKeys...), FeasibilityEvaluated: true, Feasible: true,
				})
				continue
			}
			// (4) Conformal SLO-cost gate (worst-case disruption must fit the budget).
			if d.CostCeiling > 0 && chi > d.CostCeiling {
				out.Excluded = append(out.Excluded, Exclusion{Key: key, Action: action,
					Reason:    "conformal-slo: worst-case cost " + ftoa(chi) + " > ceiling " + ftoa(d.CostCeiling),
					CoverKeys: append([]string(nil), coverKeys...), FeasibilityEvaluated: true, Feasible: true,
					CostEvaluated: true, ECost: ecost, CHi: chi})
				continue
			}
			out.Candidates = append(out.Candidates, Candidate{
				Key:       key,
				View:      v,
				Action:    action,
				CoverKeys: coverKeys,
				ECost:     ecost,
				CHi:       chi,
			})
		}
	}
	return out
}

func ftoa(f float64) string {
	// compact, allocation-light float formatting for audit reasons
	neg := f < 0
	if neg {
		f = -f
	}
	scaled := int64(f*100 + 0.5)
	whole := scaled / 100
	frac := scaled % 100
	s := itoa(whole) + "." + pad2(frac)
	if neg {
		return "-" + s
	}
	return s
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func pad2(n int64) string {
	if n < 10 {
		return "0" + itoa(n)
	}
	return itoa(n)
}
