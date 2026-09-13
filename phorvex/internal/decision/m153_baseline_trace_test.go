package decision

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// TestM153ActualBoostIsAttributed is the immutable RED/head probe. It drives the
// real UCW producer and decision trace, proves the session weight was multiplied,
// then checks the serialized contract without injecting a final attribution flag.
func TestM153ActualBoostIsAttributed(t *testing.T) {
	view := covView("m153-red", true, 2*time.Hour, false)
	view.Pod.HasGPU, view.Pod.ModelID = true, "model"
	view.Physics = model.NeutralPhysics()
	view.Events = []model.SecurityEventInfo{{Name: "actual-event", Type: model.AttackVectorKV, Source: "detector", TargetsPod: true}}
	engine := fixedTraceEngine()
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon unavailable")
	}
	engine.Recon = profile
	set, contexts := engine.AssembleSet([]*model.WorkloadView{view}, decisionTracePolicy(1, true))
	ctx := contexts["ns/m153-red"]
	unboosted := *view
	unboosted.Events = nil
	neighbors := make([]recon.NeighborRef, len(view.Neighbors))
	for i, neighbor := range view.Neighbors {
		neighbors[i] = recon.NeighborRef{Key: neighbor.Key, Value: neighbor.Value}
	}
	baseFacts := profile.AssetFacts(&unboosted, recon.FactContext{AssetValue: ctx.sig.AssetValue, PHold: ctx.assess.PHold,
		StageUrgency: ctx.assess.StageUrgency, LateralUrgency: ctx.assess.LateralUrgency, BlastRadius: view.BlastRadius,
		Neighbors: neighbors, HasGPU: view.Pod.HasGPU, Stateful: view.Pod.Stateful})
	var baseWeight float64
	for _, fact := range baseFacts.Facts {
		if fact.Kind == recon.FactSession {
			baseWeight = fact.Weight
		}
	}
	if got := set.FactWeights["pod|ns/m153-red|session"]; got != baseWeight*3 {
		t.Fatalf("producer did not apply actual x3 boost: %g vs %g", got, baseWeight)
	}
	// Use a fresh engine so the trace check does not inherit dual state from the probe.
	engine = fixedTraceEngine()
	engine.Recon = profile
	decisions := engine.Decide([]*model.WorkloadView{view}, decisionTracePolicy(1, true))
	if len(decisions) != 1 || decisions[0].Trace == nil {
		t.Fatalf("actual trace absent: %+v", decisions)
	}
	raw, err := json.Marshal(decisions[0].Trace)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"steeredBy"`) {
		t.Fatalf("boosted actual trace omits steeredBy: %s", raw)
	}
}

func TestM153UnboostedTraceOmitsAttributionControl(t *testing.T) {
	view := covView("m153-control", true, 2*time.Hour, false)
	view.Pod.HasGPU, view.Pod.ModelID = true, "model"
	view.Physics = model.NeutralPhysics()
	engine := fixedTraceEngine()
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon unavailable")
	}
	engine.Recon = profile
	raw, err := json.Marshal(engine.Decide([]*model.WorkloadView{view}, decisionTracePolicy(1, true))[0].Trace)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"steeredBy"`) {
		t.Fatalf("unboosted trace fabricated attribution: %s", raw)
	}
}
