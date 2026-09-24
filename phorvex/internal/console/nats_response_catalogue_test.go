package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNATSResponseCatalogueUsesOnlyNamedSuite(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "harness")
	listing := "#!/bin/sh\nprintf '%s\\n' 'Registered scenarios:' ' - c2-nats-uncredentialed-exposure [ModernUnsupported] R6=R6CannotRespond realism=executable benign=true declared=[] exercised=[] caps=[] limits=synthetic'\n"
	if err := os.WriteFile(bin, []byte(listing), 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(dir, allowedConfigs[natsResponseConfig].File)
	if err := os.WriteFile(profile, []byte("context: reviewed-dev-cluster\nnamespace: phorvex-nats-exposure-fixture\nkubeconfig: ''\nnatsExposureFixture:\n  transport: in-cluster\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{HarnessDir: dir, HarnessBin: bin, StateDir: t.TempDir()}
	check := func(wantAvailable bool) {
		t.Helper()
		count := 0
		for _, item := range cfg.Catalog() {
			if item.Name != "c2-nats-owned-client-response" {
				continue
			}
			count++
			if item.LaunchKind != "named-suite" || item.Profile != natsResponseConfig || item.ClaimClass != "effect" ||
				item.Product != "application" || item.R6Tag != "not-applicable" || item.Available != wantAvailable ||
				len(item.ExpectedActuators) != 0 || item.BenignControl == nil || *item.BenignControl ||
				!strings.Contains(item.RunnableNote, "server-owned") || !strings.Contains(item.ResponseGuidance, "injected trusted SecurityEvent") {
				t.Fatalf("response case gained generic or scored claim: %+v", item)
			}
			if wantAvailable && item.RuntimeContext != "reviewed-dev-cluster" {
				t.Fatalf("fixed response context absent: %+v", item)
			}
		}
		if count != 1 {
			t.Fatalf("server-owned response row count=%d", count)
		}
	}
	check(true)
	rm := NewRunManager(cfg)
	if _, err := rm.StartScenario([]string{"c2-nats-owned-client-response"}, false, false, "target", "", "", "operator"); err == nil || !strings.Contains(err.Error(), "named suite") {
		t.Fatalf("generic scenario route admitted response case: %v", err)
	}
	if _, err := (&Server{cfg: cfg}).catalogueSignalDefinition("c2-nats-owned-client-response"); err == nil {
		t.Fatal("generic signal route admitted response case")
	}
	if err := os.Remove(profile); err != nil {
		t.Fatal(err)
	}
	check(false)
}
