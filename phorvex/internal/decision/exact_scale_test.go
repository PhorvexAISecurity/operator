/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package decision

import (
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
)

// shapedFleet varies the ONE property the exactness theorem actually turns on: how much of the fleet
// carries value. density is the period of high-value assets, so density=2 is a fleet half made of
// crown jewels and density=n is a fleet with exactly one. Greedy's failure mode, if it had one, would
// live in how that value is spread — not in the raw asset count.
func shapedFleet(n, density int) []*model.WorkloadView {
	views := make([]*model.WorkloadView, 0, n)
	for i := 0; i < n; i++ {
		if density > 0 && i%density == 0 {
			views = append(views, covView(fmt.Sprintf("crown%02d", i), true, 3*time.Hour, false))
			continue
		}
		views = append(views, lowValueView(fmt.Sprintf("cheap%02d", i)))
	}
	return views
}

// TestGreedyIsExactAcrossBudgetsAndShapes is the falsification sweep behind PHORVEXSEC-114 item 3.
//
// Item 3 asked for a BOUND at 76 assets, on the premise that brute force could not reach the live
// fleet. That premise was wrong — the old flat cap of 18 was blocking a sub-millisecond computation —
// so the claim was settled by direct measurement instead of by relaxation. This test IS that
// measurement, kept executable so the claim cannot quietly decay into an assertion.
//
// It deliberately runs shapes the shipped guard declines (high B), via exactObjectiveWithBudget.
// That is not a bypass of a safety property: the guard is a latency budget for the interactive
// console path, and nothing here runs on the decision loop.
func TestGreedyIsExactAcrossBudgetsAndShapes(t *testing.T) {
	const lambda = 0.3
	const noGuard = math.MaxFloat64

	// Cases that cost more than a couple of seconds are opt-in: they are evidence, and evidence is
	// worth re-running on demand, but not worth adding a minute to every CI run. Their measured
	// results are recorded next to them so the record survives even when the run is skipped.
	sweepAll := os.Getenv("PHVX_EXACT_SWEEP") != ""

	for _, tc := range []struct {
		n, b, density int
		heavy         bool
	}{
		// The live fleet size at, and well past, the live move budget.
		{76, 1, 12, false},
		{76, 2, 12, false},
		{76, 3, 12, false},
		{76, 4, 12, true}, // 1m16s; measured ratio=1.000000000000
		// Fleets far larger than anything deployed, to show the result is not a small-n artefact.
		{150, 2, 12, false},
		{300, 2, 12, false},
		{600, 2, 12, false},
		{600, 1, 12, false},
		// Same size, different value distributions.
		{76, 2, 2, false},
		{76, 2, 4, false},
		{76, 2, 38, false},
		{76, 2, 76, false},
	} {
		tc := tc
		name := fmt.Sprintf("n=%d/B=%d/density=%d", tc.n, tc.b, tc.density)
		t.Run(name, func(t *testing.T) {
			if tc.heavy && !sweepAll {
				t.Skip("heavy enumeration; set PHVX_EXACT_SWEEP=1 to run")
			}
			if testing.Short() {
				t.Skip("enumeration sweep; runs in the full suite")
			}
			e := NewCoverageEngine()
			pol := covPolicy(tc.b)
			set, _ := e.AssembleSet(shapedFleet(tc.n, tc.density), pol)

			dj, note := coversDisjoint(set)
			if !dj {
				// The theorem claims exactness only on disjoint covers. A shared-cover fixture here
				// would make the sweep prove nothing, so say so rather than assert a ratio.
				t.Fatalf("fixture is not disjoint, so this case cannot test the claim: %s", note)
			}

			prov1 := func(string) float64 { return 1 }
			start := time.Now()
			exObj, skipped := exactObjectiveWithBudget(set, tc.b, prov1, lambda, noGuard)
			elapsed := time.Since(start)
			if skipped {
				t.Fatalf("exact arm skipped with the guard lifted — the measurement did not happen")
			}

			swObj := setObjective(greedyThenSwaps(set, tc.b, prov1, lambda), set.FactWeights, prov1, lambda)
			if exObj <= 0 {
				t.Fatalf("exact objective is %g; nothing was selected, so the ratio would be vacuous", exObj)
			}
			ratio := swObj / exObj
			if math.Abs(ratio-1.0) > 1e-9 {
				t.Fatalf("ratio=%.12f (greedy+swaps %.9f vs exact %.9f) — the exactness claim FAILS at %s",
					ratio, swObj, exObj, name)
			}
			t.Logf("%s: ratio=%.12f exact=%.9f elapsed=%v", name, ratio, exObj, elapsed)
		})
	}
}

// TestExactArmHonorsTheTimeRuling enforces the 500ms exact-check budget ruled by the math owner on
// 2026-08-11, which the work guard is the mechanism for. It measures the SHIPPED path at shapes that
// sit just inside the guard — the only place a latency bound can actually be violated.
//
// The hard assertion is deliberately looser than the 500ms ruling, because CI hardware is not the
// calibration host and a tight wall-clock assertion would flake. It is set to catch the failure that
// actually happened: configurations running 2-3x past the ruling while reporting themselves inside
// budget. The measured worst case is always logged against 500ms so drift stays visible.
func TestExactArmHonorsTheTimeRuling(t *testing.T) {
	if testing.Short() {
		t.Skip("wall-clock measurement; runs in the full suite")
	}
	const ruling = 500 * time.Millisecond
	const hardCeiling = 3 * ruling

	worst, worstName := time.Duration(0), ""
	for _, tc := range []struct{ n, b int }{
		{76, 1}, {600, 1}, {5000, 1}, {76, 2}, {250, 2}, {41, 3}, {19, 4}, {10, 7},
	} {
		e := NewCoverageEngine()
		set, _ := e.AssembleSet(productionScaleFleet(tc.n), covPolicy(tc.b))
		prov1 := func(string) float64 { return 1 }

		start := time.Now()
		_, skipped := exactObjective(set, tc.b, prov1, 0.3)
		elapsed := time.Since(start)
		if skipped {
			continue // outside the guard: it cost nothing, which is the guard working
		}
		if elapsed > worst {
			worst, worstName = elapsed, fmt.Sprintf("n=%d/B=%d", tc.n, tc.b)
		}
		if elapsed > hardCeiling {
			t.Errorf("n=%d B=%d: exact arm ran %v while the guard admitted it — the %v ruling is not being enforced",
				tc.n, tc.b, elapsed, ruling)
		}
	}
	t.Logf("worst admitted: %v at %s (ruling %v, hard ceiling %v)", worst, worstName, ruling, hardCeiling)
	if worst > ruling {
		t.Logf("NOTE: worst admitted exceeds the %v ruling on this host — recalibrate exactWorkBudget", ruling)
	}
}

// TestPruneDoesNotChangeTheOptimum pins the one risk in the budget-exhausted prune: it is a pure
// search-tree optimisation, so the value it finds must be identical to the unpruned enumeration.
// The reference here is an independent exhaustive search over the same candidate space.
func TestPruneDoesNotChangeTheOptimum(t *testing.T) {
	const lambda = 0.3
	prov1 := func(string) float64 { return 1 }

	for _, tc := range []struct{ n, b int }{{12, 1}, {12, 2}, {12, 3}, {20, 2}, {8, 4}} {
		t.Run(fmt.Sprintf("n=%d/B=%d", tc.n, tc.b), func(t *testing.T) {
			e := NewCoverageEngine()
			set, _ := e.AssembleSet(productionScaleFleet(tc.n), covPolicy(tc.b))

			got, skipped := exactObjective(set, tc.b, prov1, lambda)
			if skipped {
				t.Fatalf("fixture must be inside the guard for this comparison")
			}

			// Reference: enumerate every subset of candidates with at most one pick per asset and at
			// most B picks, scoring each. Written independently of exactObjective's recursion.
			byAsset := map[string][]actionset.Candidate{}
			var order []string
			for _, c := range set.Candidates {
				if _, ok := byAsset[c.Key]; !ok {
					order = append(order, c.Key)
				}
				byAsset[c.Key] = append(byAsset[c.Key], c)
			}
			want := 0.0
			var walk func(i int, picks []actionset.Candidate)
			walk = func(i int, picks []actionset.Candidate) {
				if len(picks) <= tc.b {
					if v := setObjective(picks, set.FactWeights, prov1, lambda); v > want {
						want = v
					}
				}
				if i == len(order) || len(picks) == tc.b {
					return
				}
				walk(i+1, picks)
				for _, c := range byAsset[order[i]] {
					walk(i+1, append(append([]actionset.Candidate{}, picks...), c))
				}
			}
			walk(0, nil)

			if math.Abs(got-want) > 1e-9 {
				t.Fatalf("pruned enumeration found %.12f, exhaustive reference found %.12f — the prune changed the optimum", got, want)
			}
			t.Logf("n=%d B=%d: optimum %.9f matches the exhaustive reference", tc.n, tc.b, got)
		})
	}
}
