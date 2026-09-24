package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

func functionalLedgerTestConfig(t *testing.T) Config {
	t.Helper()
	state := t.TempDir()
	for name, contents := range map[string]string{
		"token":        strings.Repeat("x", 64),
		"grant":        "{}\n",
		"inert-worker": "#!/bin/sh\nexit 0\n",
	} {
		mode := os.FileMode(0600)
		if name == "inert-worker" {
			mode = 0700
		}
		if err := os.WriteFile(filepath.Join(state, name), []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
	}
	return Config{StateDir: state, CatalogueV1: CatalogueV1Config{Enabled: true, Executable: filepath.Join(state, "inert-worker"),
		LoopbackURL: "http://127.0.0.1:8090", ScopedTokenFile: filepath.Join(state, "token"),
		AllowedTenant: "vllm", DeniedTenant: "other", DeniedTarget: "other-target", ExpectedSubject: "subject", GrantFile: filepath.Join(state, "grant")}}
}

func TestFixedSuiteStartRefusesMalformedRetainedLedger(t *testing.T) {
	cfg := functionalLedgerTestConfig(t)
	ledger := filepath.Join(cfg.StateDir, "run-events.jsonl")
	if err := os.WriteFile(ledger, []byte("{broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rm := NewRunManager(cfg)
	if rm.loadErr == nil {
		t.Fatal("malformed retained ledger did not surface load error")
	}
	before, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	id, startErr := rm.StartFunctional(cataloguev1.AuthUnauth, tsNow(), "owned-test-operator")
	after, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if startErr == nil || id != "" || !strings.Contains(startErr.Error(), "retained") ||
		rm.seq != 0 || len(rm.runs) != 0 || string(after) != string(before) {
		t.Fatalf("unknown retained state admitted or changed: id=%q err=%v seq=%d runs=%d ledgerChanged=%t",
			id, startErr, rm.seq, len(rm.runs), string(after) != string(before))
	}
	if _, err := os.Stat(cfg.runOutputPath("v1run-1")); !os.IsNotExist(err) {
		t.Fatalf("refused launch created an output directory: %v", err)
	}
}

func TestFixedSuiteStartAdmitsHealthyRetainedLedger(t *testing.T) {
	cfg := functionalLedgerTestConfig(t)
	rm := NewRunManager(cfg)
	prior := &RunStatus{ID: "v1run-1", Config: string(cataloguev1.AuthUnauth), State: "done", ExecutionKind: "fixed-suite"}
	if err := rm.persistStatus(prior, prior.ID); err != nil {
		t.Fatal(err)
	}
	reloaded := NewRunManager(cfg)
	if reloaded.loadErr != nil || reloaded.seq != 1 {
		t.Fatalf("healthy retained ledger unavailable: load=%v seq=%d", reloaded.loadErr, reloaded.seq)
	}
	id, err := reloaded.StartFunctional(cataloguev1.AuthUnauth, tsNow(), "owned-test-operator")
	if err != nil || id != "v1run-2" {
		t.Fatalf("healthy retained ledger prevented safe admission: id=%q err=%v", id, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status, ok := reloaded.Status(id)
		if ok && status.State != "running" {
			return // the inert local worker never contacts a cluster or provider
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("inert worker did not reach a terminal state")
}

func TestFixedSuiteRetainedUnsafeRunBlocksAfterRestart(t *testing.T) {
	cfg := functionalLedgerTestConfig(t)
	rm := NewRunManager(cfg)
	prior := &RunStatus{ID: "v1run-1", Config: string(cataloguev1.VoiceRecovery), State: "partial",
		ExecutionKind: "fixed-suite", UnsafeToRetry: true, CleanupStatus: "FAIL"}
	if err := rm.persistStatus(prior, prior.ID); err != nil {
		t.Fatal(err)
	}
	reloaded := NewRunManager(cfg)
	if reloaded.loadErr != nil || reloaded.runs[prior.ID] == nil || !reloaded.runs[prior.ID].UnsafeToRetry {
		t.Fatalf("unsafe retained run lost on restart: load=%v status=%+v", reloaded.loadErr, reloaded.runs[prior.ID])
	}
	ledger := filepath.Join(cfg.StateDir, "run-events.jsonl")
	before, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	id, startErr := reloaded.StartFunctional(cataloguev1.AuthUnauth, tsNow(), "owned-test-operator")
	after, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if startErr == nil || id != "" || !strings.Contains(startErr.Error(), "requires reconciliation") ||
		reloaded.seq != 1 || string(after) != string(before) {
		t.Fatalf("retained unsafe run did not block without mutation: id=%q err=%v seq=%d ledgerChanged=%t",
			id, startErr, reloaded.seq, string(after) != string(before))
	}
}
