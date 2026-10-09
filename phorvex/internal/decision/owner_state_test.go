package decision

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// gobCopy round-trips through gob, the codec the Math Lab snapshot uses, so the test
// proves exactness for the serialized form rather than for shared pointers.
func gobCopy[T any](t *testing.T, in T) T {
	t.Helper()
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(in); err != nil {
		t.Fatal(err)
	}
	var out T
	if err := gob.NewDecoder(&buf).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func historyFleet(tick int) []*model.WorkloadView {
	a := covView("api", true, time.Duration(30+tick)*time.Minute, false)
	b := covView("cache", false, 3*time.Hour, true)
	c := covView("gpu", true, 50*time.Minute, false)
	c.Pod.HasGPU = true
	c.Telemetry.ReqRate = model.PresentSignal(140, "fixture")
	if tick >= 2 {
		a.Events = []model.SecurityEventInfo{{Name: "ev", UID: "ev-1", Type: "Anomaly", ThreatLevel: "high", TargetsPod: true, Age: 20 * time.Second}}
	}
	if tick >= 4 {
		a.Events[0].ThreatLevel = "critical"
	}
	return []*model.WorkloadView{a, b, c}
}

func historyPolicy() model.Policy {
	pol := decisionTracePolicy(1, true)
	pol.Lambda = 0.45
	pol.EnabledActions = map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true, model.ActionKVReset: true}
	return pol
}

func TestRestoredOwnerStateReplaysProductionTickByteForByte(t *testing.T) {
	base := time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)
	prod := NewCoverageEngine()
	pol := historyPolicy()
	var lastViews []*model.WorkloadView
	for tick := 0; tick < 6; tick++ {
		now := base.Add(time.Duration(tick) * 10 * time.Second)
		prod.Now = func() time.Time { return now }
		views := historyFleet(tick)
		if tick == 5 {
			lastViews = views
			break
		}
		if _, err := prod.DecideChecked(views, pol); err != nil {
			t.Fatal(err)
		}
		// Rotation feedback primes the RLS and fills the conformal window between ticks.
		prod.ObserveRotation(pol.Owner(), views[2], 0.42+0.03*float64(tick))
	}
	state := gobCopy(t, prod.ExportOwnerState(pol.Owner()))
	if !state.HasBucket || !state.Bucket.HasRLS || !state.Bucket.RLS.Primed || len(state.Bucket.Conformal.Residuals) == 0 {
		t.Fatalf("history did not train the bucket: %+v", state.Bucket)
	}
	if len(state.StageClock) == 0 || !state.Conjugate.Tracked {
		t.Fatalf("history did not populate kill-chain state: %+v", state)
	}
	replayViews := gobCopy(t, lastViews)
	replayPolicy := gobCopy(t, pol)

	decidedAt := base.Add(50 * time.Second)
	prod.Now = func() time.Time { return decidedAt }
	want, err := prod.DecideChecked(lastViews, pol)
	if err != nil {
		t.Fatal(err)
	}

	replay := NewCoverageEngine()
	replay.Now = func() time.Time { return decidedAt }
	if err := replay.RestoreOwnerState(state); err != nil {
		t.Fatal(err)
	}
	got, err := replay.DecideChecked(replayViews, replayPolicy)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, _ := json.Marshal(want)
	gotJSON, _ := json.Marshal(got)
	if !bytes.Equal(wantJSON, gotJSON) {
		t.Fatalf("replay diverged from production:\nwant=%s\n got=%s", wantJSON, gotJSON)
	}
	if countSelected(want) == 0 {
		t.Fatal("fixture selected nothing; the comparison would not exercise selection")
	}
}

func TestShadowAssemblyAfterRestoreMatchesProductionCandidates(t *testing.T) {
	prod := NewCoverageEngine()
	prod.Now = func() time.Time { return traceTestNow }
	pol := historyPolicy()
	if _, err := prod.DecideChecked(historyFleet(2), pol); err != nil {
		t.Fatal(err)
	}
	replay := NewCoverageEngine()
	if err := replay.RestoreOwnerState(gobCopy(t, prod.ExportOwnerState(pol.Owner()))); err != nil {
		t.Fatal(err)
	}
	before := replay.ExportOwnerState(pol.Owner())
	set, err := replay.AssembleSetShadow(historyFleet(3), pol)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Candidates)+len(set.Excluded) == 0 {
		t.Fatal("shadow assembly produced nothing")
	}
	after := replay.ExportOwnerState(pol.Owner())
	b1, _ := json.Marshal(before)
	b2, _ := json.Marshal(after)
	if !bytes.Equal(b1, b2) {
		t.Fatal("shadow assembly changed owner state")
	}
}

func TestRestoreOwnerStateRefusesUsedEngine(t *testing.T) {
	used := NewCoverageEngine()
	pol := historyPolicy()
	used.Decide(historyFleet(0), pol)
	if err := used.RestoreOwnerState(used.ExportOwnerState(pol.Owner())); err == nil {
		t.Fatal("restore into a used engine succeeded")
	}
	if err := NewCoverageEngine().RestoreOwnerState(OwnerState{}); err == nil {
		t.Fatal("restore without owner succeeded")
	}
}
