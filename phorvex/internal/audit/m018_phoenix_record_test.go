/*
 * Phorvex — M-18: the Phoenix forensic payload must survive the canonical v2 record
 * path, and its compatibility limits must be demonstrated rather than asserted.
 */

package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/model"
)

func m018Payload() *model.PhoenixForensics {
	return &model.PhoenixForensics{
		AMTDName:      "phorvex-ns-team-a",
		AMTDNamespace: "ns",
		EventName:     "phorvex-rotate-vdn2f",
		EventUID:      "3f7c1e02-9a4b-4c1d-8e55-1b2a3c4d5e6f",
		RuleType:      "PhorvexRotate", RuleThreatLevel: "high", RuleSource: "phorvex",
	}
}

func m018Decision() model.Decision {
	return model.Decision{
		Tenant: "team-a", Namespace: "ns", Pod: "p1",
		Action: model.ActionRotate, Selected: true, Actuated: true,
		DecidedAt: time.Unix(1700000000, 0).UTC(),
		Phoenix:   m018Payload(),
	}
}

// The payload survives ToRecord -> canonical v2 JSON -> UnmarshalJSON with exact values.
func TestM018PayloadSurvivesCanonicalV2RoundTrip(t *testing.T) {
	rec := ToRecord(m018Decision())
	if rec.Phoenix == nil {
		t.Fatal("ToRecord dropped the phoenix payload")
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Record
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Phoenix == nil {
		t.Fatalf("typed replay lost the payload; json was: %s", b)
	}
	if *back.Phoenix != *m018Payload() {
		t.Fatalf("payload changed across the round trip:\n got %+v\nwant %+v", *back.Phoenix, *m018Payload())
	}
	if back.SchemaVersion != SchemaVersionCurrent {
		t.Errorf("schemaVersion = %q, want %q (v2 contract unchanged)", back.SchemaVersion, SchemaVersionCurrent)
	}
}

// A record with no Phoenix metadata must serialize EXACTLY as before: the additive field
// is absent from the JSON, not present-and-empty.
func TestM018AbsentPayloadIsOmittedFromTheRecord(t *testing.T) {
	d := m018Decision()
	d.Phoenix = nil
	b, err := json.Marshal(ToRecord(d))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "phoenix") {
		t.Fatalf("absent payload still serialized a phoenix key: %s", b)
	}
}

// ToRecord must OWN its copy. The audit logger serializes asynchronously with respect to
// the tick, so a shared pointer would let a later tick change an in-flight record.
func TestM018RecordOwnsItsPayloadCopy(t *testing.T) {
	d := m018Decision()
	rec := ToRecord(d)
	if rec.Phoenix == d.Phoenix {
		t.Fatal("record aliases the decision's payload; a later tick could mutate it")
	}
	d.Phoenix.EventUID = "mutated-by-a-later-tick"
	if rec.Phoenix.EventUID == "mutated-by-a-later-tick" {
		t.Fatal("mutating the decision changed an already-built record")
	}
}

// A LEGACY row (schema v0/v1, written before this field existed) must still read, and its
// missing payload means UNAVAILABLE — never evidence that no SecurityEvent was emitted.
func TestM018LegacyRowsStillReadAndMeanUnavailable(t *testing.T) {
	legacy := `{"kind":"phorvex.decision","tenant":"team-a","namespace":"ns","pod":"p1",` +
		`"action":"rotate","selected":true,"actuated":true,"risk":0.42,"engine":"p1-coverage"}`
	var rec Record
	if err := json.Unmarshal([]byte(legacy), &rec); err != nil {
		t.Fatalf("legacy row no longer reads: %v", err)
	}
	if rec.Phoenix != nil {
		t.Fatalf("legacy row invented a payload: %+v", *rec.Phoenix)
	}
	if rec.SourceSchemaVersion != SchemaVersionLegacy {
		t.Errorf("sourceSchemaVersion = %q, want %q", rec.SourceSchemaVersion, SchemaVersionLegacy)
	}
	// The legacy translation still works: risk -> coverageValue for the P1 engine.
	if rec.CoverageValue != 0.42 {
		t.Errorf("legacy risk translation broke: coverageValue = %v", rec.CoverageValue)
	}
}

// m018OldReader is a reader built BEFORE this field existed: it knows the surrounding
// fields and nothing about phoenix.
type m018OldReader struct {
	Kind     string `json:"kind"`
	Tenant   string `json:"tenant"`
	Pod      string `json:"pod"`
	Action   string `json:"action"`
	Actuated bool   `json:"actuated"`
	Handler  string `json:"handler,omitempty"`
}

// COMPATIBILITY LIMIT, DEMONSTRATED. An old reader TOLERATES the additive field — it
// decodes without error and every field it knows is intact. But it does NOT preserve the
// payload through a decode/re-serialize cycle: the unknown field is dropped on the way
// out. This test exists so that limit is a proven property, not a claim in a document.
func TestM018OldReaderToleratesButDoesNotPreserveTheAdditiveField(t *testing.T) {
	b, err := json.Marshal(ToRecord(m018Decision()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var old m018OldReader
	if err := json.Unmarshal(b, &old); err != nil {
		t.Fatalf("an old reader must tolerate the additive field, got: %v", err)
	}
	if old.Tenant != "team-a" || old.Pod != "p1" || !old.Actuated {
		t.Fatalf("the old reader's known fields changed: %+v", old)
	}

	round, err := json.Marshal(old)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if strings.Contains(string(round), "phoenix") {
		t.Fatal("fixture is not exercising the limit: the old reader kept the field")
	}
	// Documented and now proven: re-serialization through an old binary LOSES the metadata.
	t.Logf("documented limit confirmed — old-reader re-serialization drops the payload: %s", round)
}

// The audit logger is SHARED across tenants and goroutines, so the payload crosses a
// concurrency boundary on its way to the serialized record. Under -race this exercises
// that boundary: many concurrent writers, each with its own forensic identity, and every
// saved line must carry its OWN identity — no torn value, no substitution.
func TestM018ConcurrentRecordingKeepsEachPayloadIntact(t *testing.T) {
	const writers = 32
	var sink m018SyncBuffer
	l := New(logr.Discard(), &sink)

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := m018Decision()
			uid := fmt.Sprintf("uid-%02d", i)
			d.Pod = fmt.Sprintf("p%02d", i)
			// A fresh payload per decision, exactly as the runner allocates per attempt.
			p := *m018Payload()
			p.EventUID = uid
			p.EventName = "event-" + uid
			d.Phoenix = &p
			if err := l.Record(d); err != nil {
				t.Errorf("record: %v", err)
			}
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimSpace(sink.String()), "\n")
	if len(lines) != writers {
		t.Fatalf("wrote %d lines, want %d", len(lines), writers)
	}
	seen := map[string]string{}
	for _, line := range lines {
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		if rec.Phoenix == nil {
			t.Fatalf("a concurrently written record lost its payload: %s", line)
		}
		// The identity must match the pod that produced it — no substitution.
		wantUID := "uid-" + strings.TrimPrefix(rec.Pod, "p")
		if rec.Phoenix.EventUID != wantUID {
			t.Errorf("pod %s carries uid %q, want %q", rec.Pod, rec.Phoenix.EventUID, wantUID)
		}
		if rec.Phoenix.EventName != "event-"+wantUID {
			t.Errorf("pod %s: torn payload %+v", rec.Pod, *rec.Phoenix)
		}
		if prior, dup := seen[rec.Phoenix.EventUID]; dup {
			t.Fatalf("uid %q claimed by both %s and %s", rec.Phoenix.EventUID, prior, rec.Pod)
		}
		seen[rec.Phoenix.EventUID] = rec.Pod
	}
}

// m018SyncBuffer is a race-free sink; the logger serializes writes under its own lock,
// but the test reads the result afterwards.
type m018SyncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *m018SyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *m018SyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
