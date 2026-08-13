package decision

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
)

// exact_skipped_test.go — PHVX-23 / PHORVEXSEC-114 item 1.
//
// Above exactWorkBudget no exact solve runs, so no ratio was measured. The defect this file
// guards is that an UNMEASURED arm used to render as a PASSING one: probeArm discarded the skipped
// flag, the resulting exObj of 0 fell into the "both correctly selected nothing" branch, and the arm
// reported greedyRatio = swapRatio = 1.0000 — a perfect score for a computation that never happened.

// overCapWorkSet builds a fixture whose enumeration exceeds exactWorkBudget at B=4: 40 assets with
// 6 actions each is C(40,4)*6^4 = 118M candidate sets, measured at ~5.8s even at only 3 actions.
func overCapWorkSet() actionset.ActionSet {
	set := actionset.ActionSet{FactWeights: map[string]float64{}}
	acts := []model.Action{model.ActionRotate, model.ActionKVReset, model.ActionQuarantine,
		model.ActionEndpointRotate, model.ActionWarmSwap, model.ActionAdapterRotate}
	for i := 0; i < 40; i++ {
		key := fmt.Sprintf("ns/a%02d", i)
		for j := range acts {
			fact := fmt.Sprintf("%s|f%d", key, j)
			set.FactWeights[fact] = 5.0
			set.Candidates = append(set.Candidates, actionset.Candidate{
				Key: key, Action: acts[j], CoverKeys: []string{fact}, ECost: 0.10,
			})
		}
	}
	return set
}

// overCapSet builds a disjoint fixture with n assets, one action each.
func overCapSet(assets int) actionset.ActionSet {
	set := actionset.ActionSet{FactWeights: map[string]float64{}}
	for i := 0; i < assets; i++ {
		key := fmt.Sprintf("ns/a%02d", i)
		fact := key + "|p0"
		set.FactWeights[fact] = 5.0
		set.Candidates = append(set.Candidates, actionset.Candidate{
			Key: key, Action: model.ActionRotate, CoverKeys: []string{fact}, ECost: 0.10,
		})
	}
	return set
}

// TestOverCapProbeArmIsMarkedSkippedNotPerfect is the regression. Against the pre-fix code this
// fails with greedyRatio == 1, which is the whole point: it did not report "unknown", it reported
// "optimal".
func TestOverCapProbeArmIsMarkedSkippedNotPerfect(t *testing.T) {
	set := overCapWorkSet()
	arm := probeArm("over-cap", set, 4, 0.3)
	if !arm.ExactSkipped {
		t.Fatalf("a fixture whose estimated work is %.0f exceeds the budget of %d but ExactSkipped is false",
			exactWorkEstimate(len(set.FactWeights), 4, 6), exactWorkBudget)
	}
	if arm.GreedyRatio == 1 || arm.SwapRatio == 1 {
		t.Fatalf("an UNMEASURED arm reported a perfect ratio (greedy=%v swap=%v); a skipped exact solve "+
			"must never render as a passing score", arm.GreedyRatio, arm.SwapRatio)
	}
}

// TestUnderCapProbeArmStillMeasures pins the other side: the fix must not turn a real measurement
// into a skip.
func TestUnderCapProbeArmStillMeasures(t *testing.T) {
	arm := probeArm("under-cap", hubSpokeSharedSet(), 2, 0.3)
	if arm.ExactSkipped {
		t.Fatalf("the shipped shared fixture is inside the cap but was marked skipped")
	}
	if arm.GreedyRatio <= 0 {
		t.Fatalf("greedyRatio = %v; the measured arm lost its value", arm.GreedyRatio)
	}
}

// TestZeroObjectiveIsNotConfusedWithSkipped is the distinction the fix rests on. An exact solve that
// runs and correctly selects nothing genuinely IS a ratio of 1 — that branch must survive.
func TestZeroObjectiveIsNotConfusedWithSkipped(t *testing.T) {
	// One asset, one candidate whose cost outweighs its cover: the optimum is to select nothing.
	set := actionset.ActionSet{
		FactWeights: map[string]float64{"ns/a|p0": 0.0},
		Candidates: []actionset.Candidate{
			{Key: "ns/a", Action: model.ActionRotate, CoverKeys: []string{"ns/a|p0"}, ECost: 5.0},
		},
	}
	arm := probeArm("nothing-to-do", set, 2, 0.3)
	if arm.ExactSkipped {
		t.Fatalf("a 1-asset fixture must not be skipped")
	}
	if arm.GreedyRatio != 1 || arm.SwapRatio != 1 {
		t.Fatalf("both arms correctly select nothing, so the ratio is 1; got greedy=%v swap=%v",
			arm.GreedyRatio, arm.SwapRatio)
	}
}

// TestComputeOptimalitySkipDoesNotEmitRatios covers the OTHER path (the live decision path). It
// already handled skipping correctly; this pins it so the two paths cannot drift apart.
func TestComputeOptimalitySkipDoesNotEmitRatios(t *testing.T) {
	set := overCapWorkSet()
	_, skipped := exactObjective(set, 4, func(string) float64 { return 1 }, 0.3)
	if !skipped {
		t.Fatalf("exactObjective did not report a skip above the cap")
	}
}

// TestWorkBudgetReachesTheLiveFleet is the point of replacing the asset cap. Every live tenant policy
// sets maxMovesPerTick=1, and at that budget the exact arm must reach the whole 76-pod fleet — the
// old flat cap of 18 blocked it for no computational reason, which is why the exactness claim had
// never been measured at production scale.
func TestWorkBudgetReachesTheLiveFleet(t *testing.T) {
	for _, tc := range []struct {
		n, b, k  int
		wantSkip bool
		why      string
	}{
		{76, 1, 6, false, "live fleet at the live budget: measured 0.98ms"},
		{600, 1, 6, false, "8x the live fleet at B=1: measured 28.7ms"},
		{76, 2, 6, false, "measured 102ms"},
		{76, 3, 6, true, "measured 20.3s — must skip"},
		{40, 4, 6, true, "measured 5.8s at only k=3 — must skip"},
	} {
		t.Run(fmt.Sprintf("n=%d/B=%d/k=%d", tc.n, tc.b, tc.k), func(t *testing.T) {
			got := exactWorkEstimate(tc.n, tc.b, tc.k) > exactWorkBudget
			if got != tc.wantSkip {
				t.Fatalf("skip=%v want %v (work=%.0f budget=%d) — %s",
					got, tc.wantSkip, exactWorkEstimate(tc.n, tc.b, tc.k), exactWorkBudget, tc.why)
			}
		})
	}
}

// productionScaleFleet mirrors the shipped fixture's shape at the live fleet size (76 pods): a few
// high-value assets carrying secrets and a long tail of cheap ones.
func productionScaleFleet(n int) []*model.WorkloadView {
	views := make([]*model.WorkloadView, 0, n)
	for i := 0; i < n; i++ {
		if i%12 == 0 {
			views = append(views, covView(fmt.Sprintf("crown%02d", i), true, 3*time.Hour, false))
			continue
		}
		views = append(views, lowValueView(fmt.Sprintf("cheap%02d", i)))
	}
	return views
}

// TestGreedyIsExactAtProductionScale is the measurement the ticket says has never been run: the
// exactness claim evaluated at the live fleet size, at the live move budget. Every tenant policy on
// the cluster sets maxMovesPerTick=1, and the work-budget guard admits that case, so this is a direct
// brute-force comparison rather than a bound.
func TestGreedyIsExactAtProductionScale(t *testing.T) {
	for _, n := range []int{18, 40, 76} {
		t.Run(fmt.Sprintf("%d-assets", n), func(t *testing.T) {
			e := NewCoverageEngine()
			pol := covPolicy(1) // the LIVE budget: maxMovesPerTick=1 on every tenant
			res := e.Ablate(productionScaleFleet(n), pol, []int64{1, 2, 3})
			if res.ExactSkipped {
				t.Fatalf("%d assets at B=1 must be inside the work budget, but the exact arm skipped", n)
			}
			if math.Abs(res.OptimalityRatio-1.0) > 1e-9 {
				t.Fatalf("ratio=%.12f gap=%.9g at %d assets — the exactness claim does NOT hold at this scale (%s)",
					res.OptimalityRatio, res.OptimalityGap, n, res.SharedKeyNote)
			}
			t.Logf("%d assets, B=1: ratio=%.12f gap=%.3g disjoint=%v", n, res.OptimalityRatio, res.OptimalityGap, res.CoversDisjoint)
		})
	}
}
