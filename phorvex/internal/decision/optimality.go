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
 * Finding (P-OPTIMIZE-RATIO-DECISION.md): because recon.Fact.Key prefixes every selectable cover
 * key with its scope and owning block, distinct blocks have DISJOINT cover universes, the objective is
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
// size. Originally measured at k=6 (PHORVEXSEC-114; k = candidate actions per asset):
//
//	n=76   k=6  B=1  ->    0.98 ms      n=600  k=6  B=1  ->   28.7 ms
//	n=76   k=6  B=2  ->  102    ms      n=300  k=6  B=2  ->    4.7 s
//	n=76   k=6  B=3  ->   20.3 s        n=18   k=6  B=4  ->    2.8 s
//
// So at the live budget (every tenant policy sets maxMovesPerTick=1) the exact arm reaches a
// 600-asset fleet in 29 ms, while the old cap blocked it at 19 — and at B=4 the same cap happily ran
// a 2.8-second enumeration. Both failures disappear once the guard counts work.
//
// Those figures are PRE-PRUNE and are kept only as the record of why the flat cap died; they are no
// longer what the code does. They also do not compare with the fixture below: productionScaleFleet
// yields k=2, and k enters as k^j, so the same (n,B) is ~3^B cheaper there. Reading a k=6 row as if
// it described the k=2 fixture is what made B=3/n=76 look like a 20 s wall when the fixture runs it
// in ~2 s. Current numbers are in the CALIBRATION block below.
//
// CALIBRATION (PHORVEXSEC-114). The time budget for the exact check is 500 ms -- ruled by the math
// owner on 2026-08-11, in answer to "how many seconds should the exact-check budget be". The guard
// is what enforces it, so the constant is derived FROM that ruling rather than guessed:
//
//	worst admitted case measured at the boundary   ->  375 ms   (n=10  k=2 B=7, work 289,695)
//	                                                   314 ms   (n=50k k=2 B=1, work 100,001)
//	                                                   237 ms   (n=19  k=2 B=4, work 281,964)
//	first skipped case just above the boundary     ->  n=274 k=2 B=2, work 300,306
//
// so 300_000 units lands the worst admitted run at ~375 ms, inside the 500 ms ruling with headroom
// for a slower host. Everything the ticket depends on stays admitted: the live fleet at the live
// budget (n=76 B=1, 0.8 ms), 8x the fleet (n=600 B=1, 8.6 ms), n=76 B=2 (30 ms) and even n=5000 B=1
// (26 ms). Retune by re-running TestExactArmHonorsTheTimeRuling, which measures these directly.
//
// Two earlier errors are worth keeping visible, because both made the guard claim a bound it did not
// enforce -- it admitted runs of 0.68 s, 1.06 s and 1.12 s while reporting them as inside budget:
//   - the per-set cost was taken as O(1). It is O(B) (see the *= b above), so high-B fleets were
//     under-counted by up to 7x.
//   - the enumeration walked every remaining asset after the move budget was spent, making each set
//     cost an extra O(n). That is now pruned in exactObjective, which is where the headroom came from
//     (n=5000 B=1 went 1.06 s -> 26 ms).
//
// It sits on the on-demand ablation/console path, not the per-tick decision loop.
const exactWorkBudget = 300_000

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
	// Scale by B: visiting a candidate set is NOT O(1). Each node copies the running pick slice and
	// setObjective re-scores all of it, so a set of j<=B picks costs O(B), not O(1). Counting sets
	// alone made the estimate a poor predictor of time -- at B=6 a fleet well inside the budget still
	// took 1.12 s, because 6x the per-set cost was invisible to the guard (PHVX-23).
	total *= float64(b)
	if math.IsInf(total, 1) || total > 1e18 {
		return math.Inf(1)
	}
	return total
}

// provFn re-creates coverage.go's prov closure EXACTLY, including its strict
// trusted-observation arm, so the exact arm scores the SAME objective the greedy maximizes.
func provFn(ctxByKey map[string]assetCtx, floorSec float64) func(string) float64 {
	return func(key string) float64 {
		if floorSec <= 0 {
			return 1
		}
		ac := ctxByKey[key]
		if ac.exposure >= floorSec || ac.assess.HasEventEvidence {
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
	return exactObjectiveWithBudget(set, B, prov, lambda, exactWorkBudget)
}

// exactObjectiveWithBudget is exactObjective with the work guard supplied rather than baked in. It
// exists so the exactness measurement (PHORVEXSEC-114) can be REPRODUCED at shapes the shipped guard
// declines to run: those runs are the evidence for the exactness claim, and evidence that only ever
// existed in a report is evidence that rots. Production always goes through exactObjective.
func exactObjectiveWithBudget(set actionset.ActionSet, B int, prov func(string) float64, lambda float64, workBudget float64) (float64, bool) {
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
	if exactWorkEstimate(len(order), B, maxPerAsset) > workBudget {
		return 0, true
	}
	sort.Strings(order)
	best := 0.0
	var rec func(i, budget int, picks []actionset.Candidate)
	rec = func(i, budget int, picks []actionset.Candidate) {
		// Once the move budget is spent, every remaining asset can only be skipped, so the whole
		// subtree below this node collapses to the single leaf `picks`. Evaluating it here is
		// OUTPUT-IDENTICAL to walking down to i == len(order), and it is what makes the work
		// estimate honest: without it each candidate set costs O(n) skip-frames rather than O(1),
		// and the guard under-counts the real cost by a factor of the fleet size (PHVX-23).
		if i == len(order) || budget == 0 {
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

// coversDisjoint is the self-check: true iff no cover key is shared across ≥2 owning blocks (the
// modular condition under which greedy is provably exact). Today candidates use pod blocks; the
// wording deliberately does not promote shared node/model/service audit facts into decisions.
// If shared, surfaces the offending key and blocks.
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
			worst = fmt.Sprintf("cover key %q SHARED across %d owning blocks %v — objective is genuinely submodular here; greedy may be suboptimal", k, len(as), names)
		}
	}
	if worst != "" {
		return false, worst
	}
	return true, "all selectable cover keys owning-block-disjoint (modular objective; greedy provably exact)"
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

// selectionEligibleSet applies the same reactive-only eligibility rule as Decide
// before a benchmark arm sees the candidates. Feasibility alone is not enough in
// reactive-only mode: an otherwise feasible proactive move is deliberately
// suppressed unless a direct attack or suspect adapter backs that asset.
//
// Without this projection the measured greedy arm contains only attacked assets,
// while exact and random are allowed to pick calm assets. That is not an
// optimality comparison over an identical substrate and can report a false gap on
// a perfectly block-disjoint taxonomy.
func selectionEligibleSet(set actionset.ActionSet, pol model.Policy) actionset.ActionSet {
	if !pol.ReactiveOnly {
		return set
	}
	filtered := set
	filtered.Candidates = make([]actionset.Candidate, 0, len(set.Candidates))
	for _, candidate := range set.Candidates {
		if candidate.View == nil {
			continue // no evidence carrier: fail closed in reactive-only mode
		}
		if candidate.View.Pod.SuspectAdapter != "" || hasDirectFoothold(candidate.View.Events) {
			filtered.Candidates = append(filtered.Candidates, candidate)
		}
	}
	return filtered
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
	costCoefficient := 0.0
	for _, d := range decs { // every decision carries the frozen descriptor; take the first
		costCoefficient = d.Lambda
		if d.Economics != nil {
			costCoefficient = d.Economics.EffectiveCostCoefficient
		}
		break
	}
	prov := provFn(ctxByKey, pol.ProactiveFloor.Seconds())
	// greedy objective uses the same frozen coefficient as the real selection.
	gObj := 0.0
	for _, d := range decs {
		if d.Selected {
			gObj += d.CoveredWeight*prov(d.Namespace+"/"+d.Pod) - costCoefficient*d.Cost
		}
	}
	out.GreedyObjective = gObj
	out.CoversDisjoint, out.SharedKeyNote = coversDisjoint(set)
	// greedy-then-swaps over the same substrate + frozen λ + re-created prov (>= greedy always).
	out.SwapObjective = setObjective(greedyThenSwaps(set, pol.MaxMovesPerTick, prov, costCoefficient), set.FactWeights, prov, costCoefficient)
	exObj, skipped := exactObjective(set, pol.MaxMovesPerTick, prov, costCoefficient)
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
