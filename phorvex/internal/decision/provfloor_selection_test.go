package decision

import (
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
)

// provfloor_selection_test.go — PHVX-72 / PHORVEXSEC-128, acceptance criterion 4.
//
// The earlier round of this ticket fixed the tautological gate (StageUrgency > 0) but could not show
// the defence changing an outcome, because the fixture's decoy had zero coverage at every point the
// discount was active. The threshold analysis attached to the ticket set the criterion: the gate must
// be compared against the onset of BUDGET-COMPETITIVE decoy coverage, not the zero-exposure baseline.
//
// Measured onset on the live tenant policies (antiOverRotationWindow 60-90s, proactiveFloor 15m):
// competitive coverage begins at U = 0.0502-0.0504, i.e. at the baseline. ProvenanceEvidenceThreshold
// (0.0625) sits above that and strictly below the weakest evidenced stage (0.075), so it both acts on
// the decoy and preserves genuine evidence.

// decoyScenario is the adversary shape the provenance floor exists for: one move slot, a genuine
// foothold nearing its floor, and a freshly-spawned decoy with a MANUFACTURED asset weight. The two
// carry DISJOINT recon facts — sharing a neighbour would make the loser's reported coverage merely
// its marginal value after the winner consumed the common fact, which is not what we are measuring.
func decoyScenario(t *testing.T, decoyWeight float64) (decoySelected, realSelected bool) {
	t.Helper()
	pol := covPolicy(1)
	pol.Tenant = "phvx72"
	pol.DryRun = true
	pol.ProactiveFloor = 15 * time.Minute         // live tenant value
	pol.AntiOverRotationWindow = 90 * time.Second // live tenant value
	pol.AssetWeightFromLabels = func(l map[string]string) float64 {
		if l["role"] == "decoy" {
			return decoyWeight
		}
		return 40
	}
	decoy := covView("decoy", true, 90*time.Second, false) // fresh: just clears feasibility
	decoy.Pod.Labels = map[string]string{"role": "decoy"}
	decoy.Neighbors = []model.NeighborRef{{Key: "ns/decoy-nb", Value: 5.0}}
	real := covView("foothold", true, 14*time.Minute, false) // genuine, nearly overdue
	real.Pod.Labels = map[string]string{"role": "real"}
	real.Neighbors = []model.NeighborRef{{Key: "ns/real-nb", Value: 5.0}}

	for _, d := range NewCoverageEngine().Decide([]*model.WorkloadView{decoy, real}, pol) {
		if strings.Contains(d.Pod, "decoy") {
			decoySelected = d.Selected
		} else {
			realSelected = d.Selected
		}
	}
	return
}

// TestProvenanceFloorChangesSelection is acceptance criterion 4: with the floor active, a
// manufactured decoy that WOULD out-gain the genuine foothold does not take the slot.
//
// weight 160 is inside the band the discount can absorb (measured: raw advantage 1.06x, and the
// discount factor at onset is 0.406, so it absorbs up to ~2.46x). This is the honest scope of the
// defence, and it is asserted rather than described so the limit cannot silently drift.
func TestProvenanceFloorChangesSelection(t *testing.T) {
	decoyWins, realWins := decoyScenario(t, 160)
	if decoyWins {
		t.Fatalf("the manufactured decoy took the move slot: the provenance floor did not act")
	}
	if !realWins {
		t.Fatalf("the genuine foothold did not take the freed slot (selected=%v)", realWins)
	}
}

// TestProvenanceFloorLimitIsMeasuredNotAssumed records where the defence STOPS working. A decoy
// manufactured far beyond what provFloor can absorb still wins, and claiming otherwise would be the
// same overclaim this ticket was reopened for.
func TestProvenanceFloorLimitIsMeasuredNotAssumed(t *testing.T) {
	decoyWins, _ := decoyScenario(t, 1000)
	if !decoyWins {
		t.Fatalf("expected a 1000-weight decoy to STILL win (provFloor=0.34 absorbs only ~2.5x); " +
			"if this now passes, the floor's depth changed and the report's limit section is stale")
	}
	t.Logf("documented limit holds: a decoy manufactured beyond ~2.5x the genuine gain still wins")
}

// TestThresholdPreservesWeakestGenuineEvidence is criterion 2: the threshold must sit strictly below
// the weakest genuinely-evidenced stage, or real evidence would be discounted as if manufactured.
func TestThresholdPreservesWeakestGenuineEvidence(t *testing.T) {
	if killchain.ProvenanceEvidenceThreshold >= killchain.LowestEvidencedStageUrgency {
		t.Fatalf("threshold %.4f must be < the weakest evidenced urgency %.4f, or GPU side-channel evidence is discounted",
			killchain.ProvenanceEvidenceThreshold, killchain.LowestEvidencedStageUrgency)
	}
	if killchain.ProvenanceEvidenceThreshold <= killchain.BaselineStageUrgency {
		t.Fatalf("threshold %.4f must be > the evidence-less baseline %.4f, or the gate is the tautology PHVX-72 reported",
			killchain.ProvenanceEvidenceThreshold, killchain.BaselineStageUrgency)
	}
}
