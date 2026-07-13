/*
 * Phorvex — P-OPTIMIZE-RATIO: ONE clean, deterministic non-optimal example (benchmark/ablation only;
 * Decide byte-identical). A hand-specified hub/spoke instance where the P1 coverage greedy returns a
 * strictly sub-optimal move set BECAUSE three `pool` facts are SHARED between a hub and three spokes.
 * The paired control re-keys the pools per-pod (asset-disjoint) and the gap vanishes to ratio 1.000 —
 * proving the gap is the SHARING (submodularity), not a bug. This is the regression target a
 * lazy-greedy-with-swaps / LP / MPC optimizer must close.
 *
 * Adapted to this checkout's harness (greedyPicksOnSet + setObjective + exactObjective + coversDisjoint
 * from optimality.go), which the shipped Ablate uses live.
 */

package decision

import (
	"math"
	"testing"
)

// hub-spoke fixtures live in localsearch.go (shared by the tests and the live probe).

func TestScenarioNonOptimal_HubSpokeClean(t *testing.T) {
	const B, lambda = 2, 0.3
	prov1 := func(string) float64 { return 1 } // all pods aged past the proactive floor => prov=1

	set := hubSpokeSharedSet()

	// (1) the mechanism must be present: a SHARED cover key across assets.
	if disjoint, note := coversDisjoint(set); disjoint {
		t.Fatalf("fixture must use SHARED pool keys (the gap mechanism); self-check said: %s", note)
	}

	// (2) greedy vs brute-force exact over the IDENTICAL objective.
	picks := greedyPicksOnSet(set, B, prov1, lambda)
	gObj := setObjective(picks, set.FactWeights, prov1, lambda)
	exObj, skipped := exactObjective(set, B, prov1, lambda)
	if skipped {
		t.Fatal("4 assets must be within the brute-force cap")
	}
	ratio := gObj / exObj
	gap := exObj - gObj

	got := make([]string, 0, len(picks))
	for _, p := range picks {
		got = append(got, p.Key)
	}
	t.Logf("greedy picks %v -> objective %.3f", got, gObj)
	t.Logf("exact optimum            -> objective %.3f", exObj)
	t.Logf("OptimalityRatio=%.4f  gap=%.3f  (pure coverage 24/28=%.4f)", ratio, gap, 24.0/28.0)

	// (3) it must be a STRICT gap.
	if ratio >= 1.0 || gap <= 1e-6 {
		t.Fatalf("expected a strict sub-optimality; ratio=%.4f gap=%.4f", ratio, gap)
	}
	// (4) it must be the specific documented instance: greedy={hub,spoke-0} obj 23.616,
	//     exact={spoke-0,spoke-1} obj 27.952 => ratio 0.845.
	if math.Abs(ratio-0.845) > 0.005 {
		t.Fatalf("expected ratio ~0.845, got %.4f (greedy=%.3f exact=%.3f)", ratio, gObj, exObj)
	}
	if len(got) != 2 || got[0] != "ns/hub" {
		t.Fatalf("greedy should take the hub first then one spoke; got %v", got)
	}
}

func TestScenarioNonOptimal_DisjointControlIsExact(t *testing.T) {
	const B, lambda = 2, 0.3
	prov1 := func(string) float64 { return 1 }

	set := hubSpokeDisjointSet()
	if disjoint, _ := coversDisjoint(set); !disjoint {
		t.Fatal("control fixture must be asset-disjoint (no shared cover key)")
	}
	gObj := setObjective(greedyPicksOnSet(set, B, prov1, lambda), set.FactWeights, prov1, lambda)
	exObj, skipped := exactObjective(set, B, prov1, lambda)
	if skipped {
		t.Fatal("control must be within the brute-force cap")
	}
	ratio := gObj / exObj
	t.Logf("PAIRED CONTROL (per-pod keys, disjoint): ratio=%.6f — the gap vanishes; sharing is the cause", ratio)
	if math.Abs(ratio-1.0) > 1e-9 {
		t.Fatalf("disjoint control must be EXACTLY optimal (modular): ratio=%.9f", ratio)
	}
}

// ===== Step 3 — greedy-then-swaps CLOSES the gap (the note's regression target) =====

func TestSwapsCloseTheGap_HubSpoke(t *testing.T) {
	const B, lambda = 2, 0.3
	prov1 := func(string) float64 { return 1 }

	// SHARED: greedy is sub-optimal (0.845); greedy+swaps must reach the optimum (1.000).
	shared := hubSpokeSharedSet()
	exObj, _ := exactObjective(shared, B, prov1, lambda)
	gObj := setObjective(greedyPicksOnSet(shared, B, prov1, lambda), shared.FactWeights, prov1, lambda)
	sw := greedyThenSwaps(shared, B, prov1, lambda)
	swObj := setObjective(sw, shared.FactWeights, prov1, lambda)
	t.Logf("SHARED  greedy=%.3f (ratio %.4f)  swaps=%.3f (ratio %.4f) picks=%v  exact=%.3f",
		gObj, gObj/exObj, swObj, swObj/exObj, candKeys(sw), exObj)
	if gObj/exObj >= 0.999 {
		t.Fatal("precondition: greedy must be sub-optimal on the shared set")
	}
	if math.Abs(swObj/exObj-1.0) > 1e-9 {
		t.Fatalf("greedy+swaps must CLOSE the gap to 1.000 on hub-spoke; got ratio %.6f (swaps=%.3f exact=%.3f)", swObj/exObj, swObj, exObj)
	}

	// DISJOINT control: swaps must NOT change the already-exact greedy result (no regression).
	dj := hubSpokeDisjointSet()
	exObj2, _ := exactObjective(dj, B, prov1, lambda)
	swObj2 := setObjective(greedyThenSwaps(dj, B, prov1, lambda), dj.FactWeights, prov1, lambda)
	t.Logf("DISJOINT swaps ratio=%.6f (no regression)", swObj2/exObj2)
	if math.Abs(swObj2/exObj2-1.0) > 1e-9 {
		t.Fatalf("swaps must stay exact on the disjoint control: ratio %.9f", swObj2/exObj2)
	}
}

// swaps must NEVER underperform greedy across the whole submodular sweep (it starts from greedy and
// applies only strictly-improving exchanges) and must never exceed the exact optimum.
func TestSwapsNeverUnderperformGreedy_Sweep(t *testing.T) {
	prov1 := func(string) float64 { return 1 }
	const lambda = 0.3
	cells, improved := 0, 0
	for _, n := range []int{8, 12} {
		for _, b := range []int{2, n / 2} {
			for _, ov := range []float64{0.0, 0.3, 0.6} {
				for s := 0; s < 60; s++ {
					set := synthFleet(n, ov, 1.1, 0.0, int64(s+1))
					exObj, skipped := exactObjective(set, b, prov1, lambda)
					if skipped || exObj <= 1e-12 {
						continue
					}
					gObj := setObjective(greedyPicksOnSet(set, b, prov1, lambda), set.FactWeights, prov1, lambda)
					swObj := setObjective(greedyThenSwaps(set, b, prov1, lambda), set.FactWeights, prov1, lambda)
					cells++
					if swObj < gObj-1e-9 {
						t.Fatalf("swaps UNDERPERFORMED greedy: greedy=%.6f swaps=%.6f (n=%d b=%d ov=%.1f seed=%d)", gObj, swObj, n, b, ov, s)
					}
					if swObj > exObj+1e-9 {
						t.Fatalf("swaps exceeded the exact optimum (impossible): swaps=%.6f exact=%.6f", swObj, exObj)
					}
					if swObj > gObj+1e-9 {
						improved++
					}
				}
			}
		}
	}
	t.Logf("sweep: %d cells — swaps strictly improved greedy on %d, never underperformed, never exceeded exact", cells, improved)
}
