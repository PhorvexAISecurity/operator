/*
 * Phorvex — P-OPTIMIZE-RATIO Step 1 + Step 2 tests (benchmark/ablation only; Decide byte-identical).
 */

package decision

import (
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
)

// ===== STEP 1 — the in-tree measured fact: greedy == exact on the shipped fleets (ratio 1.000) =====

func shippedFleet() []*model.WorkloadView {
	return []*model.WorkloadView{
		covView("crown1", true, 3*time.Hour, false),
		covView("crown2", true, 3*time.Hour, false),
		lowValueView("cheap1"),
		lowValueView("cheap2"),
		lowValueView("cheap3"),
		lowValueView("cheap4"),
	}
}

func TestGreedyIsExactOnShippedFleets(t *testing.T) {
	e := NewCoverageEngine()
	pol := covPolicy(2)
	views := shippedFleet()
	res := e.Ablate(views, pol, []int64{1, 2, 3})

	if res.ExactSkipped {
		t.Fatalf("fleet (%d assets) should be within the brute-force cap", res.Assets)
	}
	// SELF-CHECK: the modular condition must hold (asset-disjoint covers).
	if !res.CoversDisjoint {
		t.Errorf("expected DISJOINT covers (modular) on the shipped profile; self-check surfaced: %s", res.SharedKeyNote)
	}
	// The headline: greedy is EXACTLY optimal.
	if math.Abs(res.OptimalityRatio-1.0) > 1e-9 {
		t.Errorf("greedy must be EXACTLY optimal on shipped fleets: ratio=%.12f gap=%.9f exact=%.6f greedy=%.6f (%s)",
			res.OptimalityRatio, res.OptimalityGap, res.ExactObjective, res.GreedyObjective, res.SharedKeyNote)
	}
	t.Logf("MEASURED: greedy=exact ratio=%.12f gap=%.3g disjoint=%v | %s", res.OptimalityRatio, res.OptimalityGap, res.CoversDisjoint, res.SharedKeyNote)

	// CROSS-CHECK: the Step-2 re-implemented greedy (greedyPicksOnSet) must reproduce the REAL greedy's
	// objective on the real substrate — pins the re-impl to Decide so the sweep is faithful.
	set, ctx := e.AssembleSet(views, pol)
	decs := e.Decide(views, pol)
	lam := decs[0].Lambda
	prov := provFn(ctx, pol.ProactiveFloor.Seconds())
	reObj := setObjective(greedyPicksOnSet(set, pol.MaxMovesPerTick, prov, lam), set.FactWeights, prov, lam)
	if math.Abs(reObj-res.GreedyObjective) > 1e-6 {
		t.Errorf("re-impl greedy drifted from real Decide: reimpl=%.6f real=%.6f", reObj, res.GreedyObjective)
	}
}

// A deliberately-overlapping fleet (a shared cover key across assets) must make the self-check FIRE —
// proving the check is real, not vacuous. (Synthetic ActionSet, exact arm only; no Decide involved.)
func TestSelfCheckFiresOnSharedKey(t *testing.T) {
	disjoint, _ := coversDisjoint(synthFleet(6, 0.0, 1.1, 0.0, 1))
	if !disjoint {
		t.Error("overlap=0 synthetic must be disjoint")
	}
	shared, note := coversDisjoint(synthFleet(6, 1.0, 1.1, 0.0, 1))
	if shared {
		t.Error("overlap=1 synthetic must NOT be disjoint (a shared key must be surfaced)")
	}
	if note == "" {
		t.Error("self-check must surface the shared key")
	}
	t.Logf("self-check fired: %s", note)
}

// ===== STEP 2 — benchmark-only synthetic sweep: WHERE a submodular gap appears (NO assert on cells) =====

// synthFleet builds a synthetic ActionSet with a heavy-tailed (Zipf) own-fact value and, under
// `overlap`, cross-asset cover OVERLAP onto a POOL of shared high-value facts (the hub/spoke regime:
// a myopic high-marginal pick that grabs several pool facts at once can BLOCK a better non-overlapping
// combination — the classic submodular suboptimality). overlap=0 => disjoint (modular). One cand/asset.
func synthFleet(n int, overlap, zipfAlpha, valCostCorr float64, seed int64) actionset.ActionSet {
	rng := rand.New(rand.NewSource(seed))
	w := map[string]float64{}
	poolSize := n / 3
	if poolSize < 2 {
		poolSize = 2
	}
	for p := 0; p < poolSize; p++ {
		w[fmt.Sprintf("pool|%d", p)] = 1.0 // high-value SHARED facts (the overlap surface)
	}
	var cands []actionset.Candidate
	for i := 0; i < n; i++ {
		asset := fmt.Sprintf("ns/asset-%d", i)
		ownKey := asset + "|recon"
		w[ownKey] = 0.2 / math.Pow(float64(i+1), zipfAlpha) // small, heavy-tailed own value
		keys := []string{ownKey}
		if rng.Float64() < overlap {
			for j := 0; j < 1+rng.Intn(2); j++ { // grab 1-2 random pool facts (hub when 2)
				keys = append(keys, fmt.Sprintf("pool|%d", rng.Intn(poolSize)))
			}
		}
		cost := 0.1 + valCostCorr*0.5 + (1-valCostCorr)*0.4*rng.Float64() // higher when value-cost correlated
		cands = append(cands, actionset.Candidate{Key: asset, Action: model.ActionRotate, CoverKeys: keys, ECost: cost})
	}
	return actionset.ActionSet{Candidates: cands, FactWeights: w}
}

func TestGreedyExactGapSweep(t *testing.T) {
	prov1 := func(string) float64 { return 1 } // isolate the submodular (coverage-overlap) gap from prov
	const lambda = 0.3
	const seeds = 200
	type cell struct {
		n, b           int
		overlap, alpha float64
		corr           float64
	}
	grid := []cell{}
	for _, n := range []int{8, 12} {
		for _, b := range []int{2, n / 2} {
			for _, ov := range []float64{0.0, 0.3, 0.6} {
				for _, corr := range []float64{0.0, 0.7} {
					grid = append(grid, cell{n, b, ov, 1.1, corr})
				}
			}
		}
	}
	t.Logf("greedy-vs-exact gap sweep (synthetic; benchmark-only; lambda=%.2f, %d seeds/cell) — NO assert on cells:", lambda, seeds)
	t.Logf("%-4s %-3s %-7s %-5s | %-9s %-19s %-8s", "N", "B", "overlap", "corr", "meanRatio", "95%CI", "minRatio")
	anyGap := false
	for _, cl := range grid {
		var ratios []float64
		for s := 0; s < seeds; s++ {
			set := synthFleet(cl.n, cl.overlap, cl.alpha, cl.corr, int64(s+1))
			gObj := setObjective(greedyPicksOnSet(set, cl.b, prov1, lambda), set.FactWeights, prov1, lambda)
			exObj, skipped := exactObjective(set, cl.b, prov1, lambda)
			if skipped || exObj <= 1e-12 {
				continue
			}
			ratios = append(ratios, gObj/exObj)
		}
		mean, ci, min := meanCI95(ratios)
		if min < 0.999999 {
			anyGap = true
		}
		t.Logf("%-4d %-3d %-7.1f %-5.1f | %-9.4f [%.4f,%.4f]   %-8.4f", cl.n, cl.b, cl.overlap, cl.corr, mean, mean-ci, mean+ci, min)
	}
	if !anyGap {
		t.Log("note: no cell showed a gap — increase overlap/correlation to expose the submodular regime")
	}

	// SANITY CROSS-CHECK (this one asserts): a DISJOINT synthetic fleet must be EXACTLY optimal (ratio
	// 1.000) — validates the re-impl greedy + the modular claim independently of the shipped fleet.
	for s := 0; s < 100; s++ {
		set := synthFleet(10, 0.0, 1.1, 0.7, int64(s+1)) // overlap=0 => disjoint => modular => exact
		gObj := setObjective(greedyPicksOnSet(set, 4, prov1, lambda), set.FactWeights, prov1, lambda)
		exObj, _ := exactObjective(set, 4, prov1, lambda)
		if exObj > 1e-12 && math.Abs(gObj/exObj-1.0) > 1e-9 {
			t.Fatalf("disjoint synthetic must be exact (modular): ratio=%.12f seed=%d", gObj/exObj, s)
		}
	}
}
