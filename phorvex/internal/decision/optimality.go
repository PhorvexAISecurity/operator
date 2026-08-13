/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-OPTIMIZE-RATIO)
 *
 * optimality.go — BENCHMARK ONLY (no decision-path change; Decide is byte-identical). Measures whether
 * the submodular greedy (coverage.go:175-207) is EXACTLY optimal vs a brute-force exact solve, and the
 * synthetic overlap/heavy-tailed sweep showing WHERE a real submodular gap would appear.
 *
 * The exact arm optimizes the IDENTICAL objective the greedy maximizes: it reuses the same AssembleSet
 * substrate, the FROZEN per-tick λ (carried on every Decision as d.Lambda), and a prov() re-created
 * byte-for-byte from coverage.go:152-167 — so the only difference measured is the SELECTION RULE.
 *
 * Finding (P-OPTIMIZE-RATIO-DECISION.md): because recon.Fact.Key prefixes every cover key with its
 * owning asset (facts.go:65), distinct candidates have DISJOINT cover universes, the objective is
 * MODULAR, and greedy == exact (ratio 1.000). This file turns that into a reproducible measured fact.
 */

package decision

import (
	"fmt"
	"math"
	"sort"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
)

// exactWorkBudget bounds the brute force by the WORK it will do, not by the asset count. Above it the
// exact arm is skipped (ExactSkipped=true) rather than run an intractable enumeration.
//
// The previous guard was a flat cap of 18 assets, which had no recorded derivation and was wrong in
// BOTH directions — the enumeration cost is driven by the move budget B far more than by the fleet
// size. Measured on the benchmark host (PHORVEXSEC-114; k = candidate actions per asset):
//
//	n=76   k=6  B=1  ->    0.98 ms      n=600  k=6  B=1  ->   28.7 ms
//	n=76   k=6  B=2  ->  102    ms      n=300  k=6  B=2  ->    4.7 s
//	n=76   k=6  B=3  ->   20.3 s        n=18   k=6  B=4  ->    2.8 s
//
// So at the live budget (every tenant policy sets maxMovesPerTick=1) the exact arm reaches a
// 600-asset fleet in 29 ms, while the old cap blocked it at 19 — and at B=4 the same cap happily ran
// a 2.8-second enumeration. Both failures disappear once the guard counts work.
//
// The enumeration visits sum over j<=B of C(n,j)*k^j candidate sets, at roughly 1-3 us each, so this
// budget is about 0.2-0.6 s worst case. It sits on the on-demand ablation/console path, not the
// per-tick decision loop.
const exactWorkBudget = 200_000

// exactWorkEstimate counts the candidate sets the enumeration will visit: choose at most B assets out
// of n, and one of up to k actions for each. maxPerAsset is used as a conservative upper bound.
// Returns +Inf on overflow so an enormous fleet always skips rather than wrapping to a small number.
func exactWorkEstimate(n, b, maxPerAsset int) float64 {
	if n <= 0 || b <= 0 {
		return 1
	}
	if maxPerAsset < 1 {
		maxPerAsset = 1
	}
	total, choose := 1.0, 1.0 // j=0: the empty set
	for j := 1; j <= b && j <= n; j++ {
		choose *= float64(n-j+1) / float64(j) // C(n,j) built incrementally
		total += choose * math.Pow(float64(maxPerAsset), float64(j))
		if math.IsInf(total, 1) || total > 1e18 {
			return math.Inf(1)
		}
	}
	return total
}

// provFn re-creates coverage.go's prov closure EXACTLY (the dispersion-steer decoy down-weighting), so
// the exact arm scores the SAME objective the greedy maximizes. KEEP IN SYNC with coverage.go:152-167.
func provFn(ctxByKey map[string]assetCtx, floorSec float64) func(string) float64 {
	return func(key string) float64 {
		if floorSec <= 0 {
			return 1
		}
		ac := ctxByKey[key]
		if ac.exposure >= floorSec || ac.assess.HasEvidence {
			return 1
		}
		r := ac.exposure / floorSec
		if r < 0 {
			r = 0
		}
		return provFloor + (1-provFloor)*r
	}
}

// setObjective computes f(S) = Σ_{k∈∪picks} w(k)·maxProv(k among picks) − λ·Σcost — the well-defined set
// value the greedy accumulates. On DISJOINT covers each key has one owner, so f(S)=Σ coverage(c)·prov(c)
// − λ·cost, which equals the greedy's accumulated Σ(marginal·prov − λ·ECost) — i.e. an exact match.
func setObjective(picks []actionset.Candidate, w map[string]float64, prov func(string) float64, lambda float64) float64 {
	cover := map[string]float64{} // key -> max prov among covering picks
	cost := 0.0
	for _, c := range picks {
		cost += c.ECost
		p := prov(c.Key)
		for _, k := range c.CoverKeys {
			if p > cover[k] {
				cover[k] = p
			}
		}
	}
	g := 0.0
	for k, p := range cover {
		g += w[k] * p
	}
	return g - lambda*cost
}

// exactObjective brute-forces the optimal feasible selection (one move per asset, ≤B mutating picks)
// for setObjective, returning (max f, skipped). The empty selection (f=0) is always feasible, so the
// exact is ≥ 0. Deterministic: assets are visited in sorted order.
func exactObjective(set actionset.ActionSet, B int, prov func(string) float64, lambda float64) (float64, bool) {
	byAsset := map[string][]actionset.Candidate{}
	var order []string
	for _, c := range set.Candidates {
		if _, ok := byAsset[c.Key]; !ok {
			order = append(order, c.Key)
		}
		byAsset[c.Key] = append(byAsset[c.Key], c)
	}
	maxPerAsset := 0
	for _, cs := range byAsset {
		if len(cs) > maxPerAsset {
			maxPerAsset = len(cs)
		}
	}
	if exactWorkEstimate(len(order), B, maxPerAsset) > exactWorkBudget {
		return 0, true
	}
	sort.Strings(order)
	best := 0.0
	var rec func(i, budget int, picks []actionset.Candidate)
	rec = func(i, budget int, picks []actionset.Candidate) {
		if i == len(order) {
			if v := setObjective(picks, set.FactWeights, prov, lambda); v > best {
				best = v
			}
			return
		}
		rec(i+1, budget, picks) // skip asset i
		if budget > 0 {
			for _, c := range byAsset[order[i]] {
				np := append(append([]actionset.Candidate{}, picks...), c) // copy: no aliasing
				rec(i+1, budget-1, np)
			}
		}
	}
	rec(0, B, nil)
	return best, false
}

// coversDisjoint is the self-check: true iff no cover key is shared across ≥2 assets (the modular
// condition under which greedy is provably exact). If shared, surfaces the offending key + assets.
func coversDisjoint(set actionset.ActionSet) (bool, string) {
	owners := map[string]map[string]bool{}
	for _, c := range set.Candidates {
		for _, k := range c.CoverKeys {
			if owners[k] == nil {
				owners[k] = map[string]bool{}
			}
			owners[k][c.Key] = true
		}
	}
	worst := ""
	maxShare := 1
	for k, as := range owners {
		if len(as) > maxShare {
			maxShare = len(as)
			names := make([]string, 0, len(as))
			for a := range as {
				names = append(names, a)
			}
			sort.Strings(names)
			worst = fmt.Sprintf("cover key %q SHARED across %d assets %v — objective is genuinely submodular here; greedy may be suboptimal", k, len(as), names)
		}
	}
	if worst != "" {
		return false, worst
	}
	return true, "all cover keys asset-disjoint (modular objective; greedy provably exact)"
}

// greedyPicksOnSet re-implements coverage.go:175-207 EXACTLY (same marginal, gain=marginal·prov−λ·ECost,
// strict-> first-seen tie-break, gain≤0 stop, one move/asset). Used by the Step-2 synthetic sweep; pinned
// to the real Decide by the cross-check in optimality_test.go (it must match GreedyObjective on real sets).
func greedyPicksOnSet(set actionset.ActionSet, B int, prov func(string) float64, lambda float64) []actionset.Candidate {
	covered := map[string]bool{}
	selectedAsset := map[string]bool{}
	var picks []actionset.Candidate
	for round := 0; round < B; round++ {
		bestIdx := -1
		bestGain := 0.0
		for i := range set.Candidates {
			c := set.Candidates[i]
			if selectedAsset[c.Key] {
				continue
			}
			marginal := 0.0
			for _, k := range c.CoverKeys {
				if !covered[k] {
					marginal += set.FactWeights[k]
				}
			}
			gain := marginal*prov(c.Key) - lambda*c.ECost
			if gain > bestGain {
				bestGain = gain
				bestIdx = i
			}
		}
		if bestIdx < 0 || bestGain <= 0 {
			break
		}
		c := set.Candidates[bestIdx]
		selectedAsset[c.Key] = true
		for _, k := range c.CoverKeys {
			covered[k] = true
		}
		picks = append(picks, c)
	}
	return picks
}

// OptimalityOut is the greedy-vs-exact measurement appended to AblationResult.
type OptimalityOut struct {
	GreedyObjective float64 `json:"greedyObjective"`
	ExactObjective  float64 `json:"exactObjective"`
	OptimalityRatio float64 `json:"optimalityRatio"` // greedy/exact (1.000 => greedy is exact)
	OptimalityGap   float64 `json:"optimalityGap"`   // exact - greedy (0 => no gap)
	CoversDisjoint  bool    `json:"coversDisjoint"`  // true => modular => greedy provably exact
	SharedKeyNote   string  `json:"sharedKeyNote"`   // the self-check message (surfaces a shared key)
	ExactSkipped    bool    `json:"exactSkipped"`    // fleet exceeded the brute-force cap
	// [Step 3] greedy-then-swaps local search (localsearch.go): >= greedy always; closes the hub-spoke gap.
	SwapObjective float64 `json:"swapObjective"`
	SwapRatio     float64 `json:"swapRatio"` // greedy+swaps / exact (1.000 => swaps reach the optimum)
}

// computeOptimality (Step 1) measures the REAL greedy (from the actual Decisions) against the brute-force
// exact over the same substrate + the FROZEN λ (d.Lambda) + the re-created prov. No Decide change.
func (e *CoverageEngine) computeOptimality(decs []model.Decision, set actionset.ActionSet, ctxByKey map[string]assetCtx, pol model.Policy) OptimalityOut {
	out := OptimalityOut{}
	lambda := 0.0
	for _, d := range decs { // every decision carries the frozen pre-Step λ; take the first
		lambda = d.Lambda
		break
	}
	prov := provFn(ctxByKey, pol.ProactiveFloor.Seconds())
	// greedy objective = Σ over the REAL selected decisions of (marginal·prov − λ·cost).
	gObj := 0.0
	for _, d := range decs {
		if d.Selected {
			gObj += d.CoveredWeight*prov(d.Namespace+"/"+d.Pod) - lambda*d.Cost
		}
	}
	out.GreedyObjective = gObj
	out.CoversDisjoint, out.SharedKeyNote = coversDisjoint(set)
	// greedy-then-swaps over the same substrate + frozen λ + re-created prov (>= greedy always).
	out.SwapObjective = setObjective(greedyThenSwaps(set, pol.MaxMovesPerTick, prov, lambda), set.FactWeights, prov, lambda)
	exObj, skipped := exactObjective(set, pol.MaxMovesPerTick, prov, lambda)
	out.ExactObjective, out.ExactSkipped = exObj, skipped
	if skipped {
		return out // OptimalityRatio/SwapRatio left 0 (not brute-forced)
	}
	out.OptimalityGap = exObj - gObj
	if exObj <= 1e-12 {
		out.OptimalityRatio, out.SwapRatio = 1, 1 // both correctly select nothing (objective 0)
	} else {
		out.OptimalityRatio = gObj / exObj
		out.SwapRatio = out.SwapObjective / exObj
	}
	return out
}

// meanCI95 returns the mean, the 95% CI half-width, and the min of xs (for the no-assert sweep report).
func meanCI95(xs []float64) (mean, ciHalf, min float64) {
	if len(xs) == 0 {
		return 0, 0, 0
	}
	min = xs[0]
	for _, x := range xs {
		mean += x
		if x < min {
			min = x
		}
	}
	mean /= float64(len(xs))
	if len(xs) < 2 {
		return mean, 0, min
	}
	sd := 0.0
	for _, x := range xs {
		sd += (x - mean) * (x - mean)
	}
	sd = math.Sqrt(sd / float64(len(xs)-1))
	ciHalf = 1.96 * sd / math.Sqrt(float64(len(xs)))
	return mean, ciHalf, min
}
