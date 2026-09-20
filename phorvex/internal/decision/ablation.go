/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package decision

import (
	"math/rand"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// ScarcityAblation is the P-PHYSICS (UCW) separately-ablated IP measurement: the SAME
// engine + fleet + seeds run with the BASELINE recon profile (standard-recon, no
// discovered dispersion) vs the DISCOVERED-physics profile (ucw-recon, scarcity-
// conditioned weights). Any Ratio delta is therefore attributable to DISCOVERY alone.
// On a uniform fleet (no dispersion) the two are byte-identical (exact tie at 1.62x);
// only measured dispersion (rare images/models, co-residency, EPSS) lifts the scarcity
// ratio — the sound, separately-ablatable beat mechanism (real-GPU run: PHORVEXSEC-87).
type ScarcityAblation struct {
	Baseline     AblationResult `json:"baseline"`     // standard-recon
	Scarcity     AblationResult `json:"scarcity"`     // ucw-recon (discovered physics)
	ScarcityLift float64        `json:"scarcityLift"` // Scarcity.Ratio / Baseline.Ratio (>1 => discovery beats)
}

// AblateScarcity runs the separately-ablated A/B. views must already carry their
// discovered view.Physics (stamped by the platform scanner) for the scarcity arm to see
// dispersion.
func AblateScarcity(views []*model.WorkloadView, pol model.Policy, seeds []int64) ScarcityAblation {
	base := engineWithProfile("standard-recon").Ablate(views, pol, seeds)
	scar := engineWithProfile("ucw-recon").Ablate(views, pol, seeds)
	out := ScarcityAblation{Baseline: base, Scarcity: scar}
	if base.Ratio > 0 {
		out.ScarcityLift = scar.Ratio / base.Ratio
	}
	return out
}

// engineWithProfile builds a fresh engine pinned to a named recon profile (fresh
// calibrators so the A/B arms don't share stateful RLS/dual history).
func engineWithProfile(name string) *CoverageEngine {
	e := NewCoverageEngine()
	if r, ok := recon.Registry.Get(name); ok {
		e.Recon = r
	}
	return e
}

// AblationResult is the STEP-3 IP gate measurement: facts-invalidated-per-dollar for
// the P1 coverage optimizer vs RANDOM selection over the IDENTICAL feasible action set
// and the SAME budget (so only the selection RULE differs — an honest A/B on targeting).
type AblationResult struct {
	Budget          int     `json:"budget"`
	Assets          int     `json:"assets"`
	Candidates      int     `json:"candidates"`
	Seeds           int     `json:"seeds"`
	P1Weight        float64 `json:"p1Weight"`
	P1Cost          float64 `json:"p1Cost"`
	P1PerDollar     float64 `json:"p1PerDollar"`
	RandomWeight    float64 `json:"randomWeight"`
	RandomCost      float64 `json:"randomCost"`
	RandomPerDollar float64 `json:"randomPerDollar"`
	Ratio           float64 `json:"ratio"` // P1PerDollar / RandomPerDollar (>1 => P1 wins)
	// [P-OPTIMIZE-RATIO Step 1] greedy-vs-exact optimality (benchmark; no decision-path change).
	OptimalityOut
}

// Ablate runs the IP ablation: the P1 arm is the real coverage optimizer; the random
// arm selects B feasible moves (one per asset) uniformly at random from the SAME
// generated set, averaged over the given seeds. Returns recon-weight-invalidated per
// unit cost for each.
func (e *CoverageEngine) Ablate(views []*model.WorkloadView, pol model.Policy, seeds []int64) AblationResult {
	// Substrate FIRST, then the P1 arm. This freezes the exact generated set that
	// Decide saw for the random/exact comparison. Decide no longer treats its own
	// pHold prediction as a persistence label; observed outcomes enter only through
	// the typed trusted boundary.
	set, ctxByKey := e.AssembleSet(views, pol)
	decs := e.Decide(views, pol)
	var wP1, cP1 float64
	for _, d := range decs {
		if d.Selected {
			wP1 += d.CoveredWeight
			cP1 += d.Cost
		}
	}

	// Random arm over the identical substrate.
	set = selectionEligibleSet(set, pol)
	assets := map[string]bool{}
	for _, c := range set.Candidates {
		assets[c.Key] = true
	}
	B := pol.MaxMovesPerTick

	var wSum, cSum, pdSum float64
	valid := 0
	for _, s := range seeds {
		w, c := randomArm(set, B, s)
		wSum += w
		cSum += c
		if c > 0 {
			pdSum += w / c
			valid++
		}
	}

	res := AblationResult{Budget: B, Assets: len(assets), Candidates: len(set.Candidates), Seeds: len(seeds)}
	res.P1Weight, res.P1Cost = wP1, cP1
	if cP1 > 0 {
		res.P1PerDollar = wP1 / cP1
	}
	if valid > 0 {
		res.RandomWeight = wSum / float64(valid)
		res.RandomCost = cSum / float64(valid)
		res.RandomPerDollar = pdSum / float64(valid)
	}
	if res.RandomPerDollar > 0 {
		res.Ratio = res.P1PerDollar / res.RandomPerDollar
	}
	// [P-OPTIMIZE-RATIO Step 1] measure greedy vs brute-force exact on the SAME substrate + frozen λ.
	res.OptimalityOut = e.computeOptimality(decs, set, ctxByKey, pol)
	return res
}

// randomArm selects up to B feasible candidates (one per asset) uniformly at random
// for one seed and returns the UNION recon-weight invalidated + the total cost.
func randomArm(set actionset.ActionSet, b int, seed int64) (float64, float64) {
	rng := rand.New(rand.NewSource(seed))
	order := rng.Perm(len(set.Candidates))
	taken := map[string]bool{}
	covered := map[string]bool{}
	picks := 0
	var w, c float64
	for _, i := range order {
		if picks >= b {
			break
		}
		cand := set.Candidates[i]
		if taken[cand.Key] {
			continue
		}
		taken[cand.Key] = true
		picks++
		c += cand.ECost
		for _, k := range cand.CoverKeys {
			if !covered[k] {
				covered[k] = true
				w += set.FactWeights[k]
			}
		}
	}
	return w, c
}
