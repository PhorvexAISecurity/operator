package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

var currentRequiredAuditKeys = []string{
	"schemaVersion", "kind", "time", "tenant", "namespace", "pod", "action",
	"selected", "feasible", "dryRun", "actuated", "coverageValue", "cost", "net",
	"residual", "threatPosture", "exposure", "pHold", "assetValue",
	"blastRadius", "sloHeadroom", "phase", "reason", "r6Counterfactual",
}

var legacyRequiredAuditKeys = []string{
	"kind", "time", "tenant", "namespace", "pod", "action",
	"selected", "feasible", "dryRun", "actuated", "risk", "cost", "net",
	"residual", "threatPosture", "exposure", "belief", "assetValue",
	"blastRadius", "sloHeadroom", "phase", "reason", "r6Counterfactual",
}

func assertRequiredAuditKeys(t *testing.T, fields map[string]json.RawMessage, keys []string, context string) {
	t.Helper()
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			t.Errorf("%s is missing required key %q", context, key)
		}
	}
}

func TestCurrentAuditRecordDeclaresSchemaAndRequiredKeys(t *testing.T) {
	rec := Record{
		Kind: "phorvex.decision", Time: time.Unix(1, 0).UTC(), Tenant: "tenant",
		Namespace: "ns", Pod: "pod", Action: "noop", Reason: "test",
		R6Counterfactual: "rotate",
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	assertRequiredAuditKeys(t, fields, currentRequiredAuditKeys, "current audit record")
	for _, retired := range []string{"risk", "belief"} {
		if _, ok := fields[retired]; ok {
			t.Errorf("current audit record still emits retired key %q", retired)
		}
	}
	var decoded Record
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != SchemaVersionCurrent {
		t.Fatalf("schemaVersion = %q, want %q", decoded.SchemaVersion, SchemaVersionCurrent)
	}
}

func TestReplayEveryShippedAuditJSONL(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate replay test source")
	}
	pattern := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "build", "test-harness", "out-*", "phorvex-audit-*.jsonl")
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no shipped audit JSONL matched %s", pattern)
	}

	records := 0
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(f)
		// The audit contract permits large attribution arrays; do not inherit Scanner's 64 KiB cap.
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		line := 0
		for scanner.Scan() {
			line++
			if len(scanner.Bytes()) == 0 {
				continue
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(scanner.Bytes(), &fields); err != nil {
				f.Close()
				t.Fatalf("%s:%d does not decode as an audit object: %v", path, line, err)
			}
			// The shipped corpus is v0/v1. Its old keys must be physically present before
			// the read shim translates them, rather than supplied as Go zero values.
			assertRequiredAuditKeys(t, fields, legacyRequiredAuditKeys, path+":"+strconv.Itoa(line))
			var rec Record
			if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
				f.Close()
				t.Fatalf("%s:%d does not decode as audit.Record: %v", path, line, err)
			}
			expectedSource := SchemaVersionLegacy
			if rawVersion, ok := fields["schemaVersion"]; ok {
				if err := json.Unmarshal(rawVersion, &expectedSource); err != nil {
					f.Close()
					t.Fatalf("%s:%d has invalid schemaVersion: %v", path, line, err)
				}
			}
			if rec.SchemaVersion != SchemaVersionCurrent || rec.SourceSchemaVersion != expectedSource {
				f.Close()
				t.Fatalf("%s:%d translated version = %q from %q, want %q from %q", path, line,
					rec.SchemaVersion, rec.SourceSchemaVersion, SchemaVersionCurrent, expectedSource)
			}
			if rec.Kind == "" || rec.Time.IsZero() || rec.Tenant == "" || rec.Namespace == "" || rec.Pod == "" || rec.Action == "" {
				f.Close()
				t.Fatalf("%s:%d is missing a required audit identity field", path, line)
			}
			records++
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			t.Fatalf("scan %s: %v", path, err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if records == 0 {
		t.Fatal("shipped audit corpus contained no records")
	}
}
