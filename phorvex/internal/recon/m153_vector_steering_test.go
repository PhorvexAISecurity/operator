package recon

import (
	"reflect"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func m153View(events ...model.SecurityEventInfo) *model.WorkloadView {
	return &model.WorkloadView{
		Pod:     model.Pod{Namespace: "ns", Name: "serve", UID: "pod-uid", HasGPU: true, ModelID: "model"},
		Physics: model.NeutralPhysics(), Events: events,
	}
}

func m153Facts(events ...model.SecurityEventInfo) AssetFacts {
	return ucwRecon{}.AssetFacts(m153View(events...), FactContext{AssetValue: 2, PHold: 0.5, StageUrgency: 0.4})
}

func m153Fact(t *testing.T, facts AssetFacts, kind string) Fact {
	t.Helper()
	for _, fact := range facts.Facts {
		if fact.Kind == kind {
			return fact
		}
	}
	t.Fatalf("fact %q absent", kind)
	return Fact{}
}

func m153Event(name, uid, vector string) model.SecurityEventInfo {
	return model.SecurityEventInfo{Name: name, UID: uid, Type: vector, Source: "declared-source",
		Trust: "trusted", CreatorIdentity: "system:serviceaccount:ns:detector", TargetsPod: true}
}

func TestM153VectorProducerCarriesExactAttributionOnce(t *testing.T) {
	base := m153Facts()
	cases := []struct{ vector, kind string }{
		{model.AttackVectorKV, FactSession},
		{model.AttackVectorGuardrail, FactGuardrailBypass},
		{model.AttackVectorInflight, FactInflightRequests},
	}
	for _, tc := range cases {
		t.Run(tc.vector, func(t *testing.T) {
			a, b := m153Event("event-b", "uid-b", tc.vector), m153Event("event-a", "uid-a", tc.vector)
			got := m153Fact(t, m153Facts(a, b, a), tc.kind)
			wantWeight := m153Fact(t, base, tc.kind).Weight * vectorDominance
			if got.Weight != wantWeight {
				t.Fatalf("weight=%g want one factor=%g", got.Weight, wantWeight)
			}
			if got.SteeredBy == nil || got.SteeredBy.RuleType != tc.vector || got.SteeredBy.AppliedMultiplier != 3 || len(got.SteeredBy.Events) != 2 {
				t.Fatalf("attribution=%+v", got.SteeredBy)
			}
			if got.SteeredBy.Events[0].EventUID != "uid-a" || got.SteeredBy.Events[1].EventUID != "uid-b" {
				t.Fatalf("references not canonical and deduplicated: %+v", got.SteeredBy.Events)
			}
			reordered := m153Fact(t, m153Facts(b, a), tc.kind)
			if !reflect.DeepEqual(got.SteeredBy, reordered.SteeredBy) || got.Weight != reordered.Weight {
				t.Fatalf("event order or duplication changed output: %+v / %+v", got, reordered)
			}
		})
	}
}

func TestM153VectorControlsNeverFabricateAttribution(t *testing.T) {
	wrongTarget := m153Event("wrong-target", "u1", model.AttackVectorKV)
	wrongTarget.TargetsPod = false
	wrongType := m153Event("wrong-type", "u2", "Persistence")
	adapter := m153Event("adapter", "u3", model.AttackVectorAdapter)
	old := m153Event("old", "u4", model.AttackVectorKV)
	old.Age = 365 * 24 * time.Hour
	for name, events := range map[string][]model.SecurityEventInfo{
		"none": nil, "wrong-target": {wrongTarget}, "wrong-type": {wrongType}, "adapter-vector-only": {adapter},
	} {
		t.Run(name, func(t *testing.T) {
			for _, fact := range m153Facts(events...).Facts {
				if fact.SteeredBy != nil {
					t.Fatalf("fact %s fabricated attribution: %+v", fact.Kind, fact.SteeredBy)
				}
			}
		})
	}
	oldFact := m153Fact(t, m153Facts(old), FactSession)
	if oldFact.SteeredBy == nil || oldFact.SteeredBy.Events[0].EventUID != "u4" {
		t.Fatalf("old retained event did not steer: %+v", oldFact)
	}
	direct := m153Event("simulation", "", model.AttackVectorKV)
	direct.Trust, direct.CreatorIdentity = "", ""
	if ref := m153Fact(t, m153Facts(direct), FactSession).SteeredBy.Events[0]; ref.EventUID != "" || ref.TrustVerdict != "" {
		t.Fatalf("direct input invented identity/trust: %+v", ref)
	}
	standard := standardRecon{}.AssetFacts(m153View(m153Event("event", "uid", model.AttackVectorKV)), FactContext{AssetValue: 2, PHold: .5, StageUrgency: .4})
	for _, fact := range standard.Facts {
		if fact.SteeredBy != nil {
			t.Fatal("standard profile fabricated steering")
		}
	}
}

func TestM153MissingFactAndZeroPHoldRemainHonest(t *testing.T) {
	nonServing := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "plain"}, Events: []model.SecurityEventInfo{m153Event("event", "uid", model.AttackVectorGuardrail)}}
	af := ucwRecon{}.AssetFacts(nonServing, FactContext{AssetValue: 1, PHold: 1})
	for _, fact := range af.Facts {
		if fact.SteeredBy != nil {
			t.Fatal("missing serving fact fabricated steering")
		}
	}
	zero := m153Fact(t, ucwRecon{}.AssetFacts(m153View(m153Event("event", "uid", model.AttackVectorKV)), FactContext{AssetValue: 1, PHold: 0}), FactSession)
	if zero.Weight != 0 || zero.SteeredBy == nil || zero.SteeredBy.AppliedMultiplier != 3 {
		t.Fatalf("zero pHold math/attribution changed: %+v", zero)
	}
}
