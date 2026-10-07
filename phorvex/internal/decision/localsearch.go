/*
 * Phorvex — P-OPTIMIZE-RATIO Step 3: greedy-then-swaps (the cheapest of the note's
 * "lazy-greedy-with-swaps / LP / MPC" tiers). A deterministic 1-exchange local search seeded from the
 * base greedy that CLOSES the hub-spoke submodular gap (0.845 -> 1.000) while remaining byte-identical to
 * greedy on asset-disjoint (modular) facts — so the exact-on-disjoint guarantee is preserved.
 *
 * BENCHMARK / OPT-IN ONLY: the shipped Decide is untouched. This is the proven optimizer + the live probe
 * the Optimizer Bench surfaces; promoting it to the default Decide is a separate gated rollout (a no-op on
 * the shipped disjoint facts, so no behavior change there).
 *
 * Honesty: local search NEVER underperforms greedy (it starts from greedy, applies only strictly-improving
 * exchanges) and reaches the GLOBAL optimum on the hub-spoke probe — but it is a local search, not a global
 * solver for every submodular instance. A global guarantee is the LP/MPC tier the note also lists.
 */

package decision

import (
	"sort"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
)

const localSearchMaxIter = 512 // safety cap; the objective strictly increases each step so this is never hit in practice

// greedyThenSwaps runs the base greedy, then a deterministic 1-exchange local search over the SAME
// feasible candidate set — add (under budget) / drop / swap, one move per asset, ≤B total — applying the
// single best strictly-improving exchange until none remains. On a modular (disjoint) objective there is
// no improving exchange, so the result equals greedy. Deterministic: fixed visitation order + strict-> gate.
func greedyThenSwaps(set actionset.ActionSet, B int, prov func(string) float64, lambda float64) []actionset.Candidate {
	n := len(set.Candidates)
	if B <= 0 || n == 0 {
		return nil
	}

	// --- base greedy, tracked by candidate index (matches greedyPicksOnSet: strict-> first-seen, gain≤0 stop) ---
	sel := map[int]bool{}
	selAsset := map[string]bool{}
	covered := map[string]bool{}
	resources := newResourceState(set)
	if !resources.baseFeasible() {
		return nil
	}
	for round := 0; round < B; round++ {
		best, bestGain := -1, 0.0
		for i := 0; i < n; i++ {
			c := set.Candidates[i]
			if selAsset[c.Key] {
				continue
			}
			if ok, _ := resources.canAdd(c); !ok {
				continue
			}
			marg := 0.0
			for _, k := range c.CoverKeys {
				if !covered[k] {
					marg += set.FactWeights[k]
				}
			}
			if g := marg*prov(c.Key) - candidatePenalty(c, lambda); g > bestGain {
				bestGain, best = g, i
			}
		}
		if best < 0 || bestGain <= 0 {
			break
		}
		sel[best] = true
		if !resources.add(set.Candidates[best]) {
			break
		}
		selAsset[set.Candidates[best].Key] = true
		for _, k := range set.Candidates[best].CoverKeys {
			covered[k] = true
		}
	}

	objOf := func(s map[int]bool) float64 {
		picks := make([]actionset.Candidate, 0, len(s))
		for i := range s {
			picks = append(picks, set.Candidates[i])
		}
		return setObjective(picks, set.FactWeights, prov, lambda)
	}
	feasible := func(s map[int]bool) bool {
		picks := make([]actionset.Candidate, 0, len(s))
		for i := range s {
			picks = append(picks, set.Candidates[i])
		}
		return resourceFeasible(set, picks)
	}
	assetsOf := func(s map[int]bool) map[string]bool {
		a := map[string]bool{}
		for i := range s {
			a[set.Candidates[i].Key] = true
		}
		return a
	}
	clone := func(s map[int]bool) map[int]bool {
		c := make(map[int]bool, len(s)+1)
		for i := range s {
			c[i] = true
		}
		return c
	}

	// --- 1-exchange local search ---
	for iter := 0; iter < localSearchMaxIter; iter++ {
		bestObj := objOf(sel)
		var apply func()
		selIdx := make([]int, 0, len(sel))
		for i := range sel {
			selIdx = append(selIdx, i)
		}
		sort.Ints(selIdx)
		assets := assetsOf(sel)

		// ADD (only if under budget)
		if len(sel) < B {
			for j := 0; j < n; j++ {
				if sel[j] || assets[set.Candidates[j].Key] {
					continue
				}
				trial := clone(sel)
				trial[j] = true
				if !feasible(trial) {
					continue
				}
				if v := objOf(trial); v > bestObj+1e-12 {
					bestObj = v
					jj := j
					apply = func() { sel[jj] = true }
				}
			}
		}
		// DROP
		for _, i := range selIdx {
			trial := clone(sel)
			delete(trial, i)
			if !feasible(trial) {
				continue
			}
			if v := objOf(trial); v > bestObj+1e-12 {
				bestObj = v
				ii := i
				apply = func() { delete(sel, ii) }
			}
		}
		// SWAP: member i -> non-member j (j's asset free, or the same asset as i)
		for _, i := range selIdx {
			ai := set.Candidates[i].Key
			for j := 0; j < n; j++ {
				if sel[j] {
					continue
				}
				aj := set.Candidates[j].Key
				if assets[aj] && aj != ai {
					continue
				}
				trial := clone(sel)
				delete(trial, i)
				trial[j] = true
				if !feasible(trial) {
					continue
				}
				if v := objOf(trial); v > bestObj+1e-12 {
					bestObj = v
					ii, jj := i, j
					apply = func() { delete(sel, ii); sel[jj] = true }
				}
			}
		}

		if apply == nil {
			break // local optimum reached
		}
		apply()
	}

	out := make([]actionset.Candidate, 0, len(sel))
	idx := make([]int, 0, len(sel))
	for i := range sel {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		out = append(out, set.Candidates[i])
	}
	return out
}

// ===== the hub-spoke fixtures (shared here so both the tests and the live probe use one definition) =====

// hubSpokeSharedSet — three `pool` facts (5) SHARED between a hub and three spokes; each spoke a private
// fact (9). The load-bearing inequality pool(5) < private(9) < 2*pool(10) makes greedy grab the hub first
// and lock out the better two-spoke pair => greedy 0.845 of optimum.
func hubSpokeSharedSet() actionset.ActionSet {
	return actionset.ActionSet{
		FactWeights: map[string]float64{
			"pool|0": 5.0, "pool|1": 5.0, "pool|2": 5.0,
			"ns/spoke-0|private": 9.0, "ns/spoke-1|private": 9.0, "ns/spoke-2|private": 9.0,
			"ns/hub|private": 0.0,
		},
		Candidates: []actionset.Candidate{
			{Key: "ns/hub", Action: model.ActionRotate, CoverKeys: []string{"pool|0", "pool|1", "pool|2", "ns/hub|private"}, ECost: 1.20},
			{Key: "ns/spoke-0", Action: model.ActionRotate, CoverKeys: []string{"pool|0", "ns/spoke-0|private"}, ECost: 0.08},
			{Key: "ns/spoke-1", Action: model.ActionRotate, CoverKeys: []string{"pool|1", "ns/spoke-1|private"}, ECost: 0.08},
			{Key: "ns/spoke-2", Action: model.ActionRotate, CoverKeys: []string{"pool|2", "ns/spoke-2|private"}, ECost: 0.08},
		},
	}
}

// hubSpokeDisjointSet — the paired control: the three pools re-keyed PER POD so nothing is shared
// (modular). Greedy is provably exact here; swaps make no change.
func hubSpokeDisjointSet() actionset.ActionSet {
	return actionset.ActionSet{
		FactWeights: map[string]float64{
			"ns/hub|p0": 5.0, "ns/hub|p1": 5.0, "ns/hub|p2": 5.0,
			"ns/spoke-0|p0": 5.0, "ns/spoke-1|p1": 5.0, "ns/spoke-2|p2": 5.0,
			"ns/spoke-0|private": 9.0, "ns/spoke-1|private": 9.0, "ns/spoke-2|private": 9.0,
			"ns/hub|private": 0.0,
		},
		Candidates: []actionset.Candidate{
			{Key: "ns/hub", Action: model.ActionRotate, CoverKeys: []string{"ns/hub|p0", "ns/hub|p1", "ns/hub|p2", "ns/hub|private"}, ECost: 1.20},
			{Key: "ns/spoke-0", Action: model.ActionRotate, CoverKeys: []string{"ns/spoke-0|p0", "ns/spoke-0|private"}, ECost: 0.08},
			{Key: "ns/spoke-1", Action: model.ActionRotate, CoverKeys: []string{"ns/spoke-1|p1", "ns/spoke-1|private"}, ECost: 0.08},
			{Key: "ns/spoke-2", Action: model.ActionRotate, CoverKeys: []string{"ns/spoke-2|p2", "ns/spoke-2|private"}, ECost: 0.08},
		},
	}
}

// ===== the live optimizer probe surfaced by the Optimizer Bench =====

// OptimizerProbeArm is greedy vs greedy+swaps vs brute-force exact on one fixture.
type OptimizerProbeArm struct {
	Name            string  `json:"name"`
	GreedyObjective float64 `json:"greedyObjective"`
	SwapObjective   float64 `json:"swapObjective"`
	ExactObjective  float64 `json:"exactObjective"`
	GreedyRatio     float64 `json:"greedyRatio"`
	SwapRatio       float64 `json:"swapRatio"`
	// ExactSkipped is TRUE when the fixture exceeded exactWorkBudget, so no exact solve ran
	// and BOTH ratios are unmeasured. It must be checked before either ratio is read or displayed:
	// an unmeasured arm is not a passing arm. (PHVX-23 / PHORVEXSEC-114)
	ExactSkipped   bool     `json:"exactSkipped"`
	GreedyPicks    []string `json:"greedyPicks"`
	SwapPicks      []string `json:"swapPicks"`
	CoversDisjoint bool     `json:"coversDisjoint"`
}

// OptimizerProbe is the shared-fact vs disjoint comparison: on the shared hub-spoke facts greedy is 0.845
// and greedy+swaps is 1.000; on the disjoint control both are 1.000 (no regression).
type OptimizerProbe struct {
	B        int               `json:"b"`
	Lambda   float64           `json:"lambda"`
	Shared   OptimizerProbeArm `json:"shared"`
	Disjoint OptimizerProbeArm `json:"disjoint"`
}

// RunOptimizerProbe evaluates both fixtures live (greedy / greedy+swaps / exact). No cluster, no Decide.
func RunOptimizerProbe() OptimizerProbe {
	const B = 2
	const lambda = 0.3
	return OptimizerProbe{
		B: B, Lambda: lambda,
		Shared:   probeArm("shared (hub-spoke)", hubSpokeSharedSet(), B, lambda),
		Disjoint: probeArm("disjoint (per-pod)", hubSpokeDisjointSet(), B, lambda),
	}
}

func probeArm(name string, set actionset.ActionSet, B int, lambda float64) OptimizerProbeArm {
	prov1 := func(string) float64 { return 1 }
	gPicks := greedyPicksOnSet(set, B, prov1, lambda)
	sPicks := greedyThenSwaps(set, B, prov1, lambda)
	gObj := setObjective(gPicks, set.FactWeights, prov1, lambda)
	sObj := setObjective(sPicks, set.FactWeights, prov1, lambda)
	exObj, skipped := exactObjective(set, B, prov1, lambda)
	dj, _ := coversDisjoint(set)
	arm := OptimizerProbeArm{
		Name: name, GreedyObjective: round4(gObj), SwapObjective: round4(sObj), ExactObjective: round4(exObj),
		GreedyPicks: candKeys(gPicks), SwapPicks: candKeys(sPicks), CoversDisjoint: dj,
		ExactSkipped: skipped,
	}
	// exObj == 0 carries TWO different meanings and they must not be conflated (PHVX-23):
	//
	//   skipped      -> the exact arm never ran; nothing was measured.
	//   not skipped  -> the exact solve ran and correctly selected nothing, so greedy matching it
	//                   at 0 IS a ratio of 1.
	//
	// Before this fix `skipped` was discarded, so an over-cap fixture fell into the second branch
	// and reported greedyRatio = swapRatio = 1.0000 — an unmeasured arm rendered as a perfect score,
	// which is exactly the "stale 1.0 with no signal" the ticket describes. Leave the ratios at zero
	// when skipped and let ExactSkipped carry the meaning.
	switch {
	case skipped:
		// ratios stay 0; ExactSkipped is the signal
	case exObj > 1e-12:
		arm.GreedyRatio = round4(gObj / exObj)
		arm.SwapRatio = round4(sObj / exObj)
	default:
		arm.GreedyRatio, arm.SwapRatio = 1, 1
	}
	return arm
}

func candKeys(cs []actionset.Candidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Key)
	}
	return out
}
