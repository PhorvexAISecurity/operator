package decision

import (
	"math"
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

// TestThreatPostureIsNotInformationallyRedundantWithP1 — INVERTED by PHORVEXSEC-186 (M-27).
// Until M-27 this test asserted that Killchain.Assess, the P1 fact weights and the provenance
// were byte-identical for a 0 s and a 30 min event ("that path does not consume
// SecurityEventInfo.Age"), i.e. it pinned the defect: an alert from last week set today's
// stage. Now BOTH halves of belief age the same event over the same τ_ev (= proactiveFloor):
// the 30 min event weighs 0, carries no evidence and sets no event stage, so the assessment
// and the fact weights must differ, while ThreatPosture keeps its own decay as before.
func TestThreatPostureIsNotInformationallyRedundantWithP1(t *testing.T) {
	fresh := snapshotThreatMapping(t, []model.SecurityEventInfo{directAlert("medium", 0)})
	aged := snapshotThreatMapping(t, []model.SecurityEventInfo{directAlert("medium", 30*time.Minute)})

	if reflect.DeepEqual(fresh.assessment, aged.assessment) {
		t.Fatalf("M-27 regression: recency no longer changes Killchain.Assess (a 30 min event still "+
			"weighs like a fresh one):\n fresh=%+v\n aged=%+v", fresh.assessment, aged.assessment)
	}
	// The fixture floor is 1h, so the 30 min event still weighs w = 1 − 30/60 = 0.5: half the
	// evidence of the fresh one, same (recon) event stage. Past τ_ev it must vanish entirely.
	if fresh.assessment.EventEvidence <= 0 || fresh.assessment.EventStageName == "" || !fresh.assessment.HasEvidence {
		t.Fatalf("fresh event must carry evidence and an event stage: %+v", fresh.assessment)
	}
	if want := 0.5 * fresh.assessment.EventEvidence; math.Abs(aged.assessment.EventEvidence-want) > 1e-9 {
		t.Fatalf("30 min event under tau_ev=1h must weigh 0.5: evidence=%.4f want %.4f", aged.assessment.EventEvidence, want)
	}
	if len(aged.assessment.Events) != 1 || math.Abs(aged.assessment.Events[0].Weight-0.5) > 1e-9 {
		t.Fatalf("aged event record = %+v, want weight 0.5", aged.assessment.Events)
	}
	expired := snapshotThreatMapping(t, []model.SecurityEventInfo{directAlert("medium", 2*time.Hour)})
	if expired.assessment.EventEvidence != 0 || expired.assessment.EventStageName != "" || expired.assessment.HasEvidence {
		t.Fatalf("a 2h event past tau_ev=1h must carry no evidence, no event stage and no HasEvidence: %+v", expired.assessment)
	}
	if reflect.DeepEqual(fresh.factWeights, aged.factWeights) {
		t.Fatalf("P1 fact weights must follow the aged evidence through P(hold): fresh=%v aged=%v",
			fresh.factWeights, aged.factWeights)
	}
	if fresh.posture == aged.posture {
		t.Fatalf("ThreatPosture must still decay: fresh=%v aged=%v", fresh.posture, aged.posture)
	}

	t.Logf("M-27: fresh K (P(hold)=%.6f, evidence=%.4f, stageEvent=%q) vs aged K (P(hold)=%.6f, evidence=%.4f, stageEvent=%q); "+
		"ThreatPosture fresh=%.3f aged=%.3f",
		fresh.assessment.PHold, fresh.assessment.EventEvidence, fresh.assessment.EventStageName,
		aged.assessment.PHold, aged.assessment.EventEvidence, aged.assessment.EventStageName,
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
