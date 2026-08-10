package decision

import (
	"fmt"
	"testing"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
)

// exact_skipped_test.go — PHVX-23 / PHORVEXSEC-114 item 1.
//
// Above exactBruteForceAssetCap no exact solve runs, so no ratio was measured. The defect this file
// guards is that an UNMEASURED arm used to render as a PASSING one: probeArm discarded the skipped
// flag, the resulting exObj of 0 fell into the "both correctly selected nothing" branch, and the arm
// reported greedyRatio = swapRatio = 1.0000 — a perfect score for a computation that never happened.

// overCapSet builds a disjoint fixture with strictly more assets than the brute-force cap.
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
	arm := probeArm("over-cap", overCapSet(exactBruteForceAssetCap+1), 2, 0.3)
	if !arm.ExactSkipped {
		t.Fatalf("a fixture of %d assets exceeds the cap of %d but ExactSkipped is false",
			exactBruteForceAssetCap+1, exactBruteForceAssetCap)
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
	set := overCapSet(exactBruteForceAssetCap + 1)
	_, skipped := exactObjective(set, 2, func(string) float64 { return 1 }, 0.3)
	if !skipped {
		t.Fatalf("exactObjective did not report a skip above the cap")
	}
}
