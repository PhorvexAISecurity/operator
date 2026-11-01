package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/buildinfo"
	"github.com/phorvex/phorvex/internal/cost/endpoint"
	"github.com/phorvex/phorvex/internal/mathlab"
	"github.com/phorvex/phorvex/internal/model"
)

func TestEndpointCLIExplicitCrossSourceAndJSONResult(t *testing.T) {
	dir, output := t.TempDir(), filepath.Join(t.TempDir(), "export.jsonl")
	captureSHA, replaySHA := strings.Repeat("a", 40), strings.Repeat("b", 40)
	writeSnapshot(t, dir, captureSHA, func(views []*model.WorkloadView) {
		views[0].Pod.WorkloadSpec = model.WorkloadSpecObservation{Known: true, PodUID: "ua", SpecReplicas: 3,
			Workload: model.ObjectIdentity{Kind: "Deployment", Namespace: "ns", Name: "workload", UID: "workload-uid"}}
	})
	id := buildinfo.Identity{GitSHA: replaySHA}
	if err := runEndpointMode(dir, output, "", "", "", true, false, false, id); err == nil || !strings.Contains(err.Error(), "VERSION_MISMATCH") {
		t.Fatalf("implicit cross-source accepted: %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("refused export left output")
	}
	if err := runEndpointMode(dir, output, "", "", "", true, false, true, id); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var ex mathlab.StudyCandidates
	if err := json.Unmarshal(raw, &ex); err != nil {
		t.Fatal(err)
	}
	if !ex.CandidateSetComplete || !ex.BaselineReproduced || !ex.CrossVersion || !ex.Observational || ex.SourceRevision != replaySHA || ex.SnapshotSourceRevision != captureSHA {
		t.Fatalf("export: %+v", ex)
	}
	completeFrom, zero, hold, one := ex.At-100000, 0.0, 30.0, 1
	tick := endpoint.Tick{ID: ex.SnapshotDigest, At: ex.At, WorkloadUID: ex.WorkloadUID, PolicyUID: ex.PolicyUID,
		SpecReplicas: ex.SpecReplicas, Candidates: ex.Candidates, CandidateSetComplete: true,
		SLO:    &endpoint.SLO{Target: .5, Window: 600, StudyAssumption: true},
		Ledger: &endpoint.Ledger{At: ex.At, CompleteFrom: &completeFrom, Measurement: "watch-observed-service-ready-backends", Moves: []endpoint.Move{}}}
	for i := range tick.Candidates {
		c := &tick.Candidates[i]
		c.K, c.HistoryKnown, c.WorthThreshold, c.HoldCap = &one, true, &zero, &hold
	}
	trace := endpoint.Trace{Schema: endpoint.TraceSchema, Evidence: "recorded", SourceRevision: replaySHA, Ticks: []endpoint.Tick{tick}}
	tracePath, summary := filepath.Join(t.TempDir(), "trace.json"), filepath.Join(t.TempDir(), "summary.json")
	raw, err = json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tracePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := runEndpointMode(dir, output, summary, tracePath, "", false, false, true, id); err != nil {
		t.Fatal(err)
	}
	var result mathlab.EndpointStudyResult
	if err := readStudyJSON(output, &result); err != nil {
		t.Fatal(err)
	}
	if result.Mode != "PAIRED_BRAIN_REPLAY" || result.State != "COMPLETE" || result.BaselineExactCount != 1 || !result.BrainParity || result.ReplayGitSHA != replaySHA || result.SnapshotSourceRevision != captureSHA || !result.CrossVersion {
		t.Fatalf("result: %+v", result)
	}
	var report map[string]any
	if err := readStudyJSON(summary, &report); err != nil || report["snapshot_source_revision"] != captureSHA || report["source_revision"] != replaySHA {
		t.Fatalf("summary=%v err=%v", report, err)
	}
}

func TestEndpointCLIRejectsMixedSnapshotSources(t *testing.T) {
	dir := t.TempDir()
	writeSnapshot(t, dir, strings.Repeat("a", 40))
	writeSnapshot(t, dir, strings.Repeat("b", 40))
	err := runEndpointMode(dir, filepath.Join(t.TempDir(), "out"), "", "", "", true, false, true, buildinfo.Identity{GitSHA: strings.Repeat("c", 40)})
	if err == nil || !strings.Contains(err.Error(), "mixes source revisions") {
		t.Fatalf("mixed source accepted: %v", err)
	}
}

func TestStudyJSONRejectsAmbiguousOrUnknownInput(t *testing.T) {
	for _, input := range []string{`{"lookback":60,"lookback":30}`, `{"unexpected":1}`, `{"lookback":60} {"lookback":30}`, `{"lookback":"60"}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		var cfg endpoint.Config
		if err := readStudyJSON(path, &cfg); err == nil {
			t.Fatalf("ambiguous input accepted: %s", input)
		}
	}
}

func TestReplayIdentityCannotBeOverriddenByEnvironment(t *testing.T) {
	want := buildinfo.Embedded().GitSHA
	t.Setenv("PHORVEX_GIT_SHA", strings.Repeat("f", 40))
	t.Setenv("PHORVEX_BRAIN_IMAGE", "test-image")
	got := replayIdentity()
	if got.GitSHA != want || got.BrainImage != "test-image" {
		t.Fatalf("identity was relabelled: %+v want source %s", got, want)
	}
}
