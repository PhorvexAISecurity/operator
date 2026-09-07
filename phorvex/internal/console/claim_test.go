package console

import (
	"bytes"
	"encoding/json"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"testing"
)

func TestModeledClaimLeavesFixtureSelectionsAndScoresIdentical(t *testing.T) {
	for _, scenario := range []string{"nats-broker", "mixed-fleet", "ai-gpu"} {
		t.Run(scenario, func(t *testing.T) {
			views, _ := benchScenario(scenario)
			pol := benchPolicy(benchConfig{MaxMovesPerTick: 2, NormSparsity: 0.4, FlowDisruption: 0.6, WeightSecrets: 0.8, MinAvailableReplicas: 2, ProactiveFloorSec: 900})
			decisions := decision.NewCoverageEngine().Decide(views, pol)
			if len(decisions) == 0 {
				t.Fatal("empty fixture")
			}
			for _, d := range decisions {
				before, _ := json.Marshal(d)
				for _, ids := range [][]string{nil, {"trusted-a"}, {"trusted-b", "trusted-a"}} {
					claim := model.NewClaimScope(ids, true, "fixture-build", "fixture-sha")
					d.Claim = &claim
					rec := audit.ToRecord(d)
					ev := ToOwnerEvent(rec)
					if ev.Claim.GitSHA != "fixture-sha" || ev.OutcomeEvidence != "dispatch-only" {
						t.Fatal("projection lost evidence boundary")
					}
					d.Claim = nil
					after, _ := json.Marshal(d)
					if !bytes.Equal(before, after) {
						t.Fatal("claim changed selection/score")
					}
				}
			}
		})
	}
}

func TestOwnerHistoricalClaimUnknown(t *testing.T) {
	ev := ToOwnerEvent(audit.Record{Action: "quarantine", Selected: true, Actuated: true})
	if ev.Claim.DetectorSetKnown || ev.Claim.RecallCap != "unknown" || ev.Claim.GitSHA != "unavailable" {
		t.Fatal("invented historical evidence")
	}
}
