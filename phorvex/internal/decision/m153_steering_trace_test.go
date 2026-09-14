package decision

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

func m153Trace(t *testing.T, events []model.SecurityEventInfo) *model.DecisionTraceV2 {
	t.Helper()
	view := covView("serve", true, 2*time.Hour, false)
	view.Pod.HasGPU, view.Pod.ModelID = true, "model"
	view.Physics = model.NeutralPhysics()
	view.Events = events
	engine := fixedTraceEngine()
	var ok bool
	engine.Recon, ok = recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon unavailable")
	}
	decisions := engine.Decide([]*model.WorkloadView{view}, decisionTracePolicy(1, true))
	if len(decisions) != 1 || decisions[0].Trace == nil {
		t.Fatalf("trace missing: %+v", decisions)
	}
	return decisions[0].Trace
}

func m153TraceFact(t *testing.T, trace *model.DecisionTraceV2, kind string) model.DecisionFactV2 {
	t.Helper()
	for _, fact := range trace.Facts {
		if fact.FactType == kind {
			return fact
		}
	}
	t.Fatalf("trace fact %q absent", kind)
	return model.DecisionFactV2{}
}

func TestM153FactAttributionReachesCanonicalSerializedTrace(t *testing.T) {
	events := []model.SecurityEventInfo{
		{Name: "token=secret-b", UID: "uid-b", Type: model.AttackVectorKV, Source: "Bearer hidden", Trust: "trusted", CreatorIdentity: "password=hidden", TargetsPod: true},
		{Name: "event-a", UID: "uid-a", Type: model.AttackVectorKV, Source: "detector", Trust: "trusted", CreatorIdentity: "creator", TargetsPod: true},
	}
	original := append([]model.SecurityEventInfo(nil), events...)
	trace := m153Trace(t, events)
	fact := m153TraceFact(t, trace, recon.FactSession)
	if fact.SteeredBy == nil || fact.SteeredBy.AppliedMultiplier != 3 || fact.DecompositionAvailable {
		t.Fatalf("steering/decomposition=%+v/%t", fact.SteeredBy, fact.DecompositionAvailable)
	}
	attachedName := fact.SteeredBy.Events[1].EventName
	raw1, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw1) != string(raw2) {
		t.Fatal("trace JSON is not stable")
	}
	if strings.Contains(string(raw1), "secret-b") || strings.Contains(string(raw1), "Bearer hidden") || strings.Contains(string(raw1), "password=hidden") {
		t.Fatalf("steering identity was not sanitized: %s", raw1)
	}
	var decoded model.DecisionTraceV2
	if err := json.Unmarshal(raw1, &decoded); err != nil {
		t.Fatal(err)
	}
	refs := m153TraceFact(t, &decoded, recon.FactSession).SteeredBy.Events
	if len(refs) != 2 || refs[0].EventUID != "uid-a" || refs[1].EventUID != "uid-b" {
		t.Fatalf("canonical event references=%+v", refs)
	}
	if !reflect.DeepEqual(events, original) {
		t.Fatalf("serialization mutated caller input: %+v", events)
	}
	after := m153TraceFact(t, trace, recon.FactSession)
	if after.SteeredBy.Events[1].EventName != attachedName {
		t.Fatalf("Canonical mutated attached trace: %q -> %q", attachedName, after.SteeredBy.Events[1].EventName)
	}
}

func TestM153TraceOmitsSteeringForUnboostedFacts(t *testing.T) {
	trace := m153Trace(t, nil)
	for _, fact := range trace.Facts {
		if fact.SteeredBy != nil {
			t.Fatalf("unboosted fact %s has steering: %+v", fact.FactType, fact.SteeredBy)
		}
	}
	raw, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "steeredBy") {
		t.Fatalf("optional attribution was serialized: %s", raw)
	}
}
