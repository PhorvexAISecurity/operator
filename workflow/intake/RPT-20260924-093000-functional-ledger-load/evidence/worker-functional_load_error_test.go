package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

// Source-only reproduction: this valid fixed profile must refuse a launch
// when the retained run ledger cannot prove whether an unsafe run exists.
func TestFunctionalLaunchRefusesUnknownRetainedRunState(t *testing.T) {
	state := t.TempDir()
	for name, bytes := range map[string][]byte{
		"run-events.jsonl": []byte("{broken\n"),
		"token":            []byte(strings.Repeat("x", 64)),
		"grant":            []byte("{}\n"),
		"inert-worker":     []byte("#!/bin/sh\nexit 0\n"),
	} {
		mode := os.FileMode(0600)
		if name == "inert-worker" {
			mode = 0700
		}
		if err := os.WriteFile(filepath.Join(state, name), bytes, mode); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{StateDir: state, CatalogueV1: CatalogueV1Config{Enabled: true, Executable: filepath.Join(state, "inert-worker"),
		LoopbackURL: "http://127.0.0.1:8090", ScopedTokenFile: filepath.Join(state, "token"),
		AllowedTenant: "vllm", DeniedTenant: "other", DeniedTarget: "other-target", ExpectedSubject: "subject", GrantFile: filepath.Join(state, "grant")}}
	rm := NewRunManager(cfg)
	if rm.loadErr == nil {
		t.Fatal("malformed retained ledger did not surface a load error")
	}
	before, err := os.ReadFile(filepath.Join(state, "run-events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := rm.StartFunctional(cataloguev1.AuthUnauth, tsNow(), "owned-test-operator")
	after, readErr := os.ReadFile(filepath.Join(state, "run-events.jsonl"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err == nil || id != "" || !strings.Contains(err.Error(), "retained") || rm.seq != 0 || len(rm.runs) != 0 || string(before) != string(after) {
		t.Fatalf("unknown retained fixed-suite state admitted or changed: id=%q err=%v seq=%d runs=%d ledgerChanged=%t", id, err, rm.seq, len(rm.runs), string(before) != string(after))
	}
}
