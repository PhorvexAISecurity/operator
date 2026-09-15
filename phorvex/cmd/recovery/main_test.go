package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/actuator"
)

type failLaterFile struct {
	*os.File
	writes int
}

func (f *failLaterFile) Write(p []byte) (int, error) {
	f.writes++
	if f.writes == 2 {
		n, _ := f.File.Write(p[:len(p)/2])
		return n, errors.New("injected later write failure")
	}
	return f.File.Write(p)
}

func TestResultRecorderPersistsIntentAndProgress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	r := &resultRecorder{file: f}
	intent := actuator.RecoveryApplyResult{Contract: actuator.RecoveryContractVersion, PlanHash: "hash", State: "applying"}
	if err = r.Write(intent); err != nil {
		t.Fatal(err)
	}
	progress := intent
	progress.Items = []actuator.RecoveryApplyItem{{Receipt: "receipt", Outcome: "restored"}}
	if err = r.Write(progress); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	var got []actuator.RecoveryApplyResult
	for s.Scan() {
		var record actuator.RecoveryApplyResult
		if err = json.Unmarshal(s.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		got = append(got, record)
	}
	if err = s.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].State != "applying" || len(got[0].Items) != 0 || len(got[1].Items) != 1 || got[1].Items[0].Outcome != "restored" {
		t.Fatalf("durable result=%+v", got)
	}
}

func TestResultRecorderFailedLaterAppendRetainsLastDurableRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	sink := &failLaterFile{File: f}
	r := &resultRecorder{file: sink}
	intent := actuator.RecoveryApplyResult{Contract: actuator.RecoveryContractVersion, PlanHash: "hash", State: "applying"}
	if err = r.Write(intent); err != nil {
		t.Fatal(err)
	}
	progress := intent
	progress.Items = []actuator.RecoveryApplyItem{{Receipt: "receipt", Outcome: "restored"}}
	if err = r.Write(progress); err == nil {
		t.Fatal("later writer failure not surfaced")
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("record fragments=%d, want retained intent plus incomplete tail", len(lines))
	}
	var got actuator.RecoveryApplyResult
	if err = json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("prior record damaged: %v", err)
	}
	if got.State != "applying" || len(got.Items) != 0 {
		t.Fatalf("wrong retained intent: %+v", got)
	}
	if json.Valid([]byte(lines[1])) {
		t.Fatal("failure injection unexpectedly wrote a complete later record")
	}
}

func TestReadBoundedPlanRejectsOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-plan.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(actuator.RecoveryPlanMaxBytes + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err = readBoundedPlan(path); err == nil {
		t.Fatal("oversized plan file accepted")
	}
}
