package calib

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

func runtimeSnapshot(at time.Time) (*ingest.Snapshot, map[string]model.PhysicsWitness) {
	snap := &ingest.Snapshot{
		Now:   at,
		Nodes: []ingest.NodeInfo{{Name: "n1", Schedulable: true}, {Name: "n2", Schedulable: true}},
		Pods: []model.Pod{
			{Namespace: "a", Name: "p1", Node: "n1", Phase: string(corev1.PodRunning)},
			{Namespace: "b", Name: "p2", Node: "n1", Phase: string(corev1.PodRunning), HasGPU: true},
			{Namespace: "c", Name: "p3", Node: "n2", Phase: string(corev1.PodRunning)},
		},
	}
	witness := map[string]model.PhysicsWitness{
		"a/p1": {Scanned: true, ImageRarity: 1.2, EPSS: 1.1, ModelRarity: 1},
		"b/p2": {Scanned: true, ImageRarity: 1.8, EPSS: 1.3, ModelRarity: 1.5},
		"c/p3": {Scanned: true, ImageRarity: 1.4, EPSS: 1, ModelRarity: 1},
	}
	return snap, witness
}

func TestRuntimeRefreshesAtStartupThenThirtyMinutesAndExportsRawEvidence(t *testing.T) {
	dir := t.TempDir()
	runtime := NewRuntime(RuntimeConfig{ExportDir: dir, MinObservations: 1}, logr.Discard())
	base := at0()
	snap, witness := runtimeSnapshot(base)
	result, refreshed, err := runtime.ObserveSnapshot(snap, witness)
	if err != nil || !refreshed {
		t.Fatalf("startup refresh: refreshed=%v err=%v", refreshed, err)
	}
	if result.GeneratedAt != base || len(result.Nodes) != 2 || len(result.Assets) != 3 || len(result.JointSweep) != 16 {
		t.Fatalf("unexpected startup result: %+v", result)
	}
	for _, name := range []string{
		"evidence-manifest.json",
		"co-residency.csv", "co-residency.json", "dispersion.csv", "dispersion.json",
		"ready-delay.csv", "ready-delay.json", "joint-percentile-sweep.csv",
		"joint-percentile-sweep.json", "cadence-sweep.csv", "cadence-sweep.json",
		"optimizer-comparisons.csv", "optimizer-comparisons.json",
	} {
		if info, statErr := os.Stat(filepath.Join(dir, name)); statErr != nil || info.Size() == 0 {
			t.Fatalf("export %s missing/empty: info=%v err=%v", name, info, statErr)
		}
	}

	snap.Now = base.Add(5 * time.Minute)
	if _, refreshed, err = runtime.ObserveSnapshot(snap, witness); err != nil || refreshed {
		t.Fatalf("five-minute sample unexpectedly refreshed: refreshed=%v err=%v", refreshed, err)
	}
	snap.Now = base.Add(30 * time.Minute)
	if _, refreshed, err = runtime.ObserveSnapshot(snap, witness); err != nil || !refreshed {
		t.Fatalf("thirty-minute refresh: refreshed=%v err=%v", refreshed, err)
	}
}

func TestShadowViewsApplyCandidateScalesWithoutMutatingProduction(t *testing.T) {
	runtime := NewRuntime(RuntimeConfig{MinObservations: 1}, logr.Discard())
	base := at0()
	snap, witness := runtimeSnapshot(base)
	if _, refreshed, err := runtime.ObserveSnapshot(snap, witness); err != nil || !refreshed {
		t.Fatalf("refresh: refreshed=%v err=%v", refreshed, err)
	}
	production := []*model.WorkloadView{
		{Pod: snap.Pods[0], Physics: witness["a/p1"]},
		{Pod: snap.Pods[2], Physics: witness["c/p3"]},
	}
	shadow, ok := runtime.ShadowViews(production)
	if !ok || len(shadow) != 2 {
		t.Fatalf("shadow views unavailable: ok=%v views=%d", ok, len(shadow))
	}
	if production[0].Physics.DispersionCap != 0 || production[0].Physics.CoResidency != witness["a/p1"].CoResidency {
		t.Fatal("shadow construction mutated a production witness")
	}
	if shadow[0].Physics.DispersionCap <= 0 || shadow[0].Physics.CoResidency != 2 {
		t.Fatalf("candidate scales not applied to shared node: %+v", shadow[0].Physics)
	}
	if shadow[1].Physics.CoResidency != 1 {
		t.Fatalf("single-namespace node co-residency=%v want=1", shadow[1].Physics.CoResidency)
	}
}

func TestRuntimeSevenDayLookbackDropsOldReadyDelayRecords(t *testing.T) {
	runtime := NewRuntime(RuntimeConfig{MinObservations: 1}, logr.Discard())
	base := at0()
	runtime.ObserveRotation(RotationRecord{
		ID: "old", StartedAt: base.Add(-8 * 24 * time.Hour), RecordedAt: base.Add(-8 * 24 * time.Hour),
		Elapsed: time.Minute, Outcome: OutcomeObserved,
	})
	runtime.ObserveRotation(RotationRecord{
		ID: "new", StartedAt: base.Add(-time.Hour), RecordedAt: base.Add(-30 * time.Minute),
		Elapsed: 30 * time.Minute, Outcome: OutcomeCensored,
		ReferenceAtStart: ShippedReadyDelayReference,
	})
	snap, witness := runtimeSnapshot(base)
	result, refreshed, err := runtime.ObserveSnapshot(snap, witness)
	if err != nil || !refreshed {
		t.Fatalf("refresh: refreshed=%v err=%v", refreshed, err)
	}
	if len(result.Rotations) != 1 || result.Rotations[0].ID != "new" {
		t.Fatalf("lookback retained wrong records: %+v", result.Rotations)
	}
}

func TestReadyDelayJSONUsesSecondsAndHonestOutcome(t *testing.T) {
	dir := t.TempDir()
	base := at0()
	result := RefreshResult{
		GeneratedAt: base,
		Rotations: []RotationRecord{{
			ID: "r", StartedAt: base, RecordedAt: base.Add(800 * time.Second),
			Elapsed: 800 * time.Second, Outcome: OutcomeCensored,
			ReferenceAtStart: ShippedReadyDelayReference,
			CensorDeadline:   base.Add(800 * time.Second),
		}},
	}
	if err := Export(dir, result); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "ready-delay.json"))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Rows []readyDelayRow `json:"rows"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Rows) != 1 || payload.Rows[0].ElapsedSeconds != 800 || payload.Rows[0].ReferenceSeconds != 400 || payload.Rows[0].Normalized != 2 || payload.Rows[0].Outcome != OutcomeCensored {
		t.Fatalf("ready-delay row = %+v", payload.Rows)
	}
}
