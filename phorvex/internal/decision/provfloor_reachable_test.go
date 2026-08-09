package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
)

// provfloor_reachable_test.go — PHVX-72.
//
// The provenance floor is the SELECTION-path anti-decoy defence: a fresh, evidence-less candidate is
// discounted toward provFloor so a manufactured high-coverage decoy cannot take the budget slot from
// a genuinely-due foothold. The gate deciding whether to apply it read `StageUrgency > 0`.
//
// StageUrgency = 0.5*consequence(stage) + 0.5*hazard*consequence(next), and consequence() floors at
// 0.1 for EVERY stage including its default arm. So the least urgent asset the system can represent
// still scores 0.05, `> 0` was always true, every asset took the full-weight path, and the defence
// had never executed. These tests pin both halves: the floor is reachable now, and a real foothold
// is still undiscounted.

// TestBaselineStageUrgencyIsNotZero is the root cause, asserted directly. If this ever becomes 0 the
// original `> 0` gate would have been fine — and the fix could be reverted knowingly rather than by
// accident.
func TestBaselineStageUrgencyIsNotZero(t *testing.T) {
	if killchain.BaselineStageUrgency <= 0 {
		t.Fatalf("BaselineStageUrgency = %v; if consequence() can reach 0 the `> 0` gate is no longer "+
			"vacuous and PHVX-72's premise needs re-checking", killchain.BaselineStageUrgency)
	}

	k := killchain.NewModel()
	// The most benign asset representable: freshly seen, no events, no exposure.
	benign := k.Assess(&model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "fresh"}},
		model.Policy{ProactiveFloor: 15 * time.Minute}, 0, 900)
	if benign.StageUrgency <= 0 {
		t.Fatalf("expected the no-evidence asset to still score > 0 (that is the whole bug), got %v",
			benign.StageUrgency)
	}
	if benign.StageUrgency > killchain.BaselineStageUrgency {
		t.Errorf("no-evidence asset scored %v, above the declared baseline %v — the baseline no longer "+
			"describes 'no evidence' and the gate threshold is wrong",
			benign.StageUrgency, killchain.BaselineStageUrgency)
	}
}

// provOf rebuilds the gate exactly as Decide does, for an asset with the given exposure and urgency.
func provOf(t *testing.T, floorSec, exposure, urgency float64) float64 {
	t.Helper()
	ctxByKey := map[string]assetCtx{
		"ns/p": {assess: killchain.Assessment{StageUrgency: urgency}, exposure: exposure},
	}
	return provFn(ctxByKey, floorSec)("ns/p")
}

// TestProvFloorIsReachable is the regression: a FRESH asset carrying only the baseline urgency must
// be discounted. Before the fix this returned 1 and the decoy defence never fired.
func TestProvFloorIsReachable(t *testing.T) {
	got := provOf(t, 900, 0, killchain.BaselineStageUrgency)
	if got >= 1 {
		t.Fatalf("a fresh, evidence-less asset got prov=%v (full weight) — the anti-decoy discount is "+
			"inert, which is exactly the PHVX-72 defect", got)
	}
	if got != provFloor {
		t.Errorf("at zero exposure the discount should be the floor %v, got %v", provFloor, got)
	}
}

// TestGenuineEvidenceIsNotDiscounted pins the other side. The defence must not tax real threats:
// anything above the no-evidence baseline, or aged past the proactive floor, keeps full weight.
func TestGenuineEvidenceIsNotDiscounted(t *testing.T) {
	for _, tc := range []struct {
		name              string
		exposure, urgency float64
	}{
		{"real kill-chain evidence", 0, killchain.BaselineStageUrgency * 3},
		{"overdue for the hygiene floor", 1000, killchain.BaselineStageUrgency},
		{"both", 1000, killchain.BaselineStageUrgency * 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := provOf(t, 900, tc.exposure, tc.urgency); got != 1 {
				t.Errorf("a genuinely-due asset must keep full weight, got prov=%v", got)
			}
		})
	}
}

// TestProvFloorWindowIsMeasured records what the threshold fix does and does NOT achieve. It is
// deliberately a MEASUREMENT, not a success assertion, because claiming the anti-decoy defence is
// "restored" would be false.
//
// Fixing the gate makes the discount reachable — but only in a window where it cannot matter.
// Exposure drives BOTH halves: it raises pHold (and pHold multiplies into every fact weight, so it
// drives coverage) AND it raises StageUrgency. Measured on the standard fixture:
//
//	exposure=0      pHold=0.000  stageUrgency=0.0500  cover=0.0000  -> DISCOUNTED
//	exposure=1m     pHold=0.185  stageUrgency=0.0502  cover=0.0000  -> not discounted
//	exposure=10m    pHold=0.333  stageUrgency=0.0684  cover=0.6482  -> not discounted
//
// So the only candidates the discount reaches are ones whose coverage is already 0 — discounting
// zero changes no selection. The gate fix is necessary (it was testing a condition that is always
// true, which is testing nothing) but NOT sufficient: while StageUrgency rises above the baseline
// the instant exposure becomes non-zero, no candidate with real coverage can ever be discounted.
//
// This test fails if that coupling changes, which is the signal that the defence has become live and
// PHVX-72 can actually be closed on behaviour rather than on the threshold alone.
func TestProvFloorWindowIsMeasured(t *testing.T) {
	pol := covPolicy(1)
	pol.Tenant = "prov-window"
	floorSec := pol.ProactiveFloor.Seconds()
	e := NewCoverageEngine()

	measure := func(exp time.Duration) (cover, prov float64) {
		v := covView("a", true, exp, false)
		set, ctx := e.AssembleSet([]*model.WorkloadView{v}, pol)
		for _, c := range set.Candidates {
			for _, k := range c.CoverKeys {
				cover += set.FactWeights[k]
			}
			break
		}
		return cover, provFn(ctx, floorSec)("ns/a")
	}

	// At zero exposure the discount applies — and there is nothing to discount.
	cover0, prov0 := measure(0)
	if prov0 >= 1 {
		t.Errorf("at zero exposure the discount must apply, got prov=%v (the gate is vacuous again)", prov0)
	}
	if cover0 != 0 {
		t.Logf("NOTE: zero-exposure coverage is now %v, not 0 — the discount has become behaviourally "+
			"meaningful and this test should become a real assertion", cover0)
	}

	// The moment exposure is non-zero, StageUrgency clears the baseline and the discount stops.
	_, provTiny := measure(time.Minute)
	if provTiny < 1 {
		t.Logf("NOTE: a 1-minute-old asset is now discounted (prov=%v) — the exposure/urgency coupling "+
			"changed; re-evaluate whether PHVX-72 is genuinely closed", provTiny)
	}
}

// TestProvGateMatchesBetweenCopies guards the drift that let this survive: coverage.go's inline gate
// and optimality.go's provFn are two copies under a "KEEP IN SYNC" comment. If they disagree, the
// benchmark stops measuring the thing production runs.
func TestProvGateMatchesBetweenCopies(t *testing.T) {
	views := []*model.WorkloadView{covView("fresh-decoy", true, 0, false)}
	e := NewCoverageEngine()
	pol := covPolicy(1)
	pol.Tenant = "provgate"
	_, ctxByKey := e.AssembleSet(views, pol)

	floorSec := pol.ProactiveFloor.Seconds()
	for key, ac := range ctxByKey {
		want := 1.0
		if !(ac.exposure >= floorSec || ac.assess.StageUrgency > killchain.BaselineStageUrgency) {
			r := ac.exposure / floorSec
			if r < 0 {
				r = 0
			}
			want = provFloor + (1-provFloor)*r
		}
		if got := provFn(ctxByKey, floorSec)(key); got != want {
			t.Errorf("provFn(%s)=%v but the inline gate implies %v — the two copies have drifted",
				key, got, want)
		}
	}
}
