package killchain

import (
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/r6security/phoenix/api/v1beta1"
)

// event_aging_test.go — PHORVEXSEC-186 / M-27 (ruling: linear weight, evidence-following stage).
//
// Old code: the evidence sum and the event-derived stage never read event age; a 0 s and a
// 30 min event produced byte-identical assessments. New: w = 1 − clamp01(age/τ_ev), evidence
// = Σ w·severity, stage from events with w > 0 only. τ_ev = proactiveFloor = 15 m here.

const tauEv = 15 * time.Minute

func agingPolicy() model.Policy {
	return model.Policy{Tenant: "t", ProactiveFloor: tauEv, ExposurePressureCap: 0.5}
}

func persistEvent(age time.Duration) model.SecurityEventInfo {
	return model.SecurityEventInfo{Name: "ev-persist", Source: "det", Type: v1beta1.TypePanic, ThreatLevel: "high", TargetsPod: true, Age: age}
}

func assessWith(t *testing.T, events ...model.SecurityEventInfo) Assessment {
	t.Helper()
	m := NewModel()
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}, Events: events}
	return m.Assess(v, agingPolicy(), 3600, tauEv.Seconds())
}

// The ruling's predicted vector for τ_ev = 15 m.
func TestEventAgeWeightMatchesRulingVector(t *testing.T) {
	for _, tc := range []struct {
		age  time.Duration
		want float64
	}{
		{0, 1.0000}, {7 * time.Minute, 0.5333}, {7*time.Minute + 30*time.Second, 0.5},
		{14 * time.Minute, 0.0667}, {15 * time.Minute, 0}, {30 * time.Minute, 0}, {24 * time.Hour, 0},
	} {
		if got := model.EventAgeWeight(tc.age, tauEv); math.Abs(got-tc.want) > 5e-5 {
			t.Fatalf("w(%v) = %.4f, ruling says %.4f", tc.age, got, tc.want)
		}
	}
	// invariants: w(0)=1, [0,1], monotone non-increasing
	prev := 2.0
	for a := time.Duration(0); a <= 20*time.Minute; a += 10 * time.Second {
		w := model.EventAgeWeight(a, tauEv)
		if w < 0 || w > 1 || w > prev {
			t.Fatalf("invariant broken at %v: w=%.4f prev=%.4f", a, w, prev)
		}
		prev = w
	}
	if model.EventAgeWeight(time.Hour, 0) != 1 {
		t.Fatal("tau_ev <= 0 must disable aging (w = 1)")
	}
}

// (a) age 0 → weight 1, stage set, evidence = severity; identical to the old behaviour.
func TestFreshEventSetsStageAndFullEvidence(t *testing.T) {
	a := assessWith(t, persistEvent(0))
	if a.EventStageName != StagePersist.String() || a.Stage != StagePersist {
		t.Fatalf("fresh persist event: stage=%s eventStage=%q, want persist", a.StageName, a.EventStageName)
	}
	if !a.HasEvidence || math.Abs(a.EventEvidence-0.75) > 1e-9 { // high = rank 3 → sev 0.75
		t.Fatalf("fresh event: hasEvidence=%v evidence=%.4f, want true/0.75", a.HasEvidence, a.EventEvidence)
	}
	if len(a.Events) != 1 || a.Events[0].Weight != 1 || !a.Events[0].TimestampPresent || a.Events[0].Name != "ev-persist" {
		t.Fatalf("event record = %+v", a.Events)
	}
}

// (b) the same event at 30 m with τ_ev = 15 m → weight 0, evidence 0, no event stage.
// Old code: byte-identical to (a) — this test fails on it.
func TestStaleEventCarriesNoEvidenceAndNoStage(t *testing.T) {
	fresh := assessWith(t, persistEvent(0))
	stale := assessWith(t, persistEvent(30*time.Minute))
	if stale.EventStageName != "" || stale.Stage != StageRecon {
		t.Fatalf("30 min event still holds a stage: stage=%s eventStage=%q (old behaviour: identical to fresh)", stale.StageName, stale.EventStageName)
	}
	if stale.EventEvidence != 0 || stale.HasEvidence {
		t.Fatalf("30 min event still carries evidence: evidence=%.4f hasEvidence=%v", stale.EventEvidence, stale.HasEvidence)
	}
	if stale.PHold >= fresh.PHold {
		t.Fatalf("P(hold) must follow the aged evidence: stale=%.4f fresh=%.4f", stale.PHold, fresh.PHold)
	}
	if len(stale.Events) != 1 || stale.Events[0].Weight != 0 || stale.Events[0].AgeSec != 1800 {
		t.Fatalf("stale event record = %+v, want weight 0 age 1800", stale.Events)
	}
}

// (c) age 7.5 m → weight 0.5 → evidence = 0.5·severity.
func TestHalfAgedEventCarriesHalfWeight(t *testing.T) {
	a := assessWith(t, persistEvent(7*time.Minute+30*time.Second))
	if math.Abs(a.EventEvidence-0.375) > 1e-9 || math.Abs(a.Events[0].Weight-0.5) > 1e-9 {
		t.Fatalf("7.5 m event: evidence=%.4f weight=%.4f, want 0.375/0.5", a.EventEvidence, a.Events[0].Weight)
	}
	if a.EventStageName != StagePersist.String() {
		t.Fatalf("a half-weight event (w > 0) must still set its stage: %q", a.EventStageName)
	}
}

// (d) an event with no timestamp → weight 0, recorded present=false.
func TestEventWithoutTimestampWeighsZero(t *testing.T) {
	e := persistEvent(0)
	e.TimestampMissing = true
	a := assessWith(t, e)
	if a.EventEvidence != 0 || a.EventStageName != "" || a.HasEvidence {
		t.Fatalf("no-timestamp event must weigh 0: %+v", a)
	}
	if len(a.Events) != 1 || a.Events[0].TimestampPresent || a.Events[0].Weight != 0 {
		t.Fatalf("no-timestamp record = %+v, want present=false weight 0", a.Events)
	}
}

// (e) fresh low-severity + stale high-severity → evidence and stage from the fresh one only.
func TestFreshLowSeverityOutranksStaleHighSeverity(t *testing.T) {
	fresh := model.SecurityEventInfo{Name: "ev-low", Type: "generic-alert", ThreatLevel: "low", TargetsPod: true, Age: 0}
	stale := persistEvent(30 * time.Minute)
	a := assessWith(t, fresh, stale)
	if a.EventStageName != StageRecon.String() || a.Stage != StageRecon {
		t.Fatalf("stale persist event must not set the stage: stage=%s eventStage=%q", a.StageName, a.EventStageName)
	}
	if math.Abs(a.EventEvidence-0.25) > 1e-9 { // low = rank 1 → 0.25, only the fresh event counts
		t.Fatalf("evidence=%.4f, want 0.25 from the fresh low event only", a.EventEvidence)
	}
	if len(a.Events) != 2 || a.Events[0].Weight != 1 || a.Events[1].Weight != 0 {
		t.Fatalf("event records = %+v", a.Events)
	}
}

// A compromised NEIGHBOUR's event ages the same way: stale neighbour evidence no longer
// projects lateral pressure forever.
func TestNeighborEventAgesOut(t *testing.T) {
	nb := func(age time.Duration) model.SecurityEventInfo {
		return model.SecurityEventInfo{Type: "panic", ThreatLevel: "critical", TargetsPod: false, Age: age}
	}
	fresh := assessWith(t, nb(0))
	stale := assessWith(t, nb(30*time.Minute))
	if fresh.LateralUrgency <= 0 || !fresh.HasEvidence {
		t.Fatalf("fresh neighbour event must project lateral pressure: %+v", fresh)
	}
	if stale.LateralUrgency >= fresh.LateralUrgency || stale.HasEvidence {
		t.Fatalf("stale neighbour event still projects: stale=%.4f fresh=%.4f hasEvidence=%v", stale.LateralUrgency, fresh.LateralUrgency, stale.HasEvidence)
	}
}
