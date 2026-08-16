package decision

import (
	"reflect"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
)

// threatMappingSnapshot captures K(E) from PHORVEXSEC-89: the complete
// kill-chain assessment, the P1 recon-fact weights derived from it, and the
// anti-decoy provenance factor. ThreatPosture is kept separately so the test
// can ask whether K(E) determines it.
type threatMappingSnapshot struct {
	posture     float64
	assessment  killchain.Assessment
	factWeights map[string]float64
	provenance  float64
}

func snapshotThreatMapping(t *testing.T, events []model.SecurityEventInfo) threatMappingSnapshot {
	t.Helper()
	pol := covPolicy(1)
	v := covView("candidate", true, 10*time.Minute, false)
	v.Events = events

	e := NewCoverageEngine()
	set, contexts := e.AssembleSet([]*model.WorkloadView{v}, pol)
	key := v.Pod.Namespace + "/" + v.Pod.Name
	ctx, ok := contexts[key]
	if !ok {
		t.Fatalf("missing assembled context for %s", key)
	}
	return threatMappingSnapshot{
		posture:     ctx.sig.ThreatPosture,
		assessment:  ctx.assess,
		factWeights: set.FactWeights,
		provenance:  provFn(contexts, pol.ProactiveFloor.Seconds())(key),
	}
}

func directAlert(level string, age time.Duration) model.SecurityEventInfo {
	return model.SecurityEventInfo{
		Type:        "generic-alert",
		ThreatLevel: level,
		Age:         age,
		TargetsPod:  true,
	}
}

// TestThreatPostureIsNotInformationallyRedundantWithP1 constructs the requested
// counterexample. Killchain.Assess and every downstream P1 fact/provenance value
// are identical because that path does not consume SecurityEventInfo.Age, while
// ThreatPosture age-decays the same event over ProactiveFloor.
func TestThreatPostureIsNotInformationallyRedundantWithP1(t *testing.T) {
	fresh := snapshotThreatMapping(t, []model.SecurityEventInfo{directAlert("medium", 0)})
	aged := snapshotThreatMapping(t, []model.SecurityEventInfo{directAlert("medium", 30*time.Minute)})

	if !reflect.DeepEqual(fresh.assessment, aged.assessment) {
		t.Fatalf("precondition failed: recency changed Killchain.Assess:\n fresh=%+v\n aged=%+v",
			fresh.assessment, aged.assessment)
	}
	if !reflect.DeepEqual(fresh.factWeights, aged.factWeights) {
		t.Fatalf("precondition failed: recency changed P1 fact weights:\n fresh=%v\n aged=%v",
			fresh.factWeights, aged.factWeights)
	}
	if fresh.provenance != aged.provenance {
		t.Fatalf("precondition failed: recency changed provenance: fresh=%v aged=%v",
			fresh.provenance, aged.provenance)
	}
	if fresh.posture == aged.posture {
		t.Fatalf("counterexample disappeared: ThreatPosture fresh=%v aged=%v", fresh.posture, aged.posture)
	}

	t.Logf("counterexample: K is identical (P(hold)=%.6f, stageUrgency=%.6f, facts=%d, prov=%.3f), "+
		"but ThreatPosture fresh=%.3f and aged=%.3f",
		fresh.assessment.PHold, fresh.assessment.StageUrgency, len(fresh.factWeights), fresh.provenance,
		fresh.posture, aged.posture)
}

// TestThreatPostureAndKillchainAggregateSeverityAndCountDifferently covers the
// remaining requested shapes. Low and medium generic alerts stay at the same
// stage, and duplicate alerts keep the same max posture; Killchain.Assess still
// retains their severity/count through eventAlpha -> P(hold) -> fact weights.
func TestThreatPostureAndKillchainAggregateSeverityAndCountDifferently(t *testing.T) {
	t.Run("severity rises without stage advancement", func(t *testing.T) {
		low := snapshotThreatMapping(t, []model.SecurityEventInfo{directAlert("low", 0)})
		medium := snapshotThreatMapping(t, []model.SecurityEventInfo{directAlert("medium", 0)})

		if low.assessment.Stage != medium.assessment.Stage ||
			low.assessment.StageUrgency != medium.assessment.StageUrgency {
			t.Fatalf("low and medium generic alerts should share stage/urgency: low=%+v medium=%+v",
				low.assessment, medium.assessment)
		}
		if low.posture == medium.posture {
			t.Fatal("ThreatPosture must retain the low-to-medium severity increase")
		}
		if low.assessment.PHold == medium.assessment.PHold ||
			reflect.DeepEqual(low.factWeights, medium.factWeights) {
			t.Fatal("kill-chain eventAlpha must retain severity through P(hold) and P1 fact weights")
		}
	})

	t.Run("repeated same-stage alerts", func(t *testing.T) {
		one := snapshotThreatMapping(t, []model.SecurityEventInfo{directAlert("low", 0)})
		two := snapshotThreatMapping(t, []model.SecurityEventInfo{
			directAlert("low", 0),
			directAlert("low", 0),
		})

		if one.posture != two.posture {
			t.Fatalf("max-aggregated ThreatPosture should ignore an identical duplicate: one=%v two=%v",
				one.posture, two.posture)
		}
		if one.assessment.Stage != two.assessment.Stage ||
			one.assessment.StageUrgency != two.assessment.StageUrgency {
			t.Fatal("an identical duplicate should not advance stage or stage urgency")
		}
		if one.assessment.PHold == two.assessment.PHold ||
			reflect.DeepEqual(one.factWeights, two.factWeights) {
			t.Fatal("kill-chain eventAlpha must count repeated direct alerts in P(hold) and fact weights")
		}
	})
}
