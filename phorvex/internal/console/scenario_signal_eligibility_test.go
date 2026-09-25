package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogueSignalEligibilityMatchesAPIProjection(t *testing.T) {
	attack, benign := false, true
	tests := []struct {
		name   string
		item   CatalogItem
		want   bool
		reason string
	}{
		{"attack", CatalogItem{Name: "attack", LaunchKind: "harness-scenario", BenignControl: &attack, ExpectedActuators: []string{"rotate"}}, true, "eligible"},
		{"benign", CatalogItem{Name: "benign", LaunchKind: "harness-scenario", BenignControl: &benign, ExpectedActuators: []string{"rotate"}}, false, "benign"},
		{"legacy", CatalogItem{Name: "legacy", LaunchKind: "harness-scenario", ExpectedActuators: []string{"rotate"}}, false, "legacy"},
		{"empty-first-hint", CatalogItem{Name: "empty-first-hint", LaunchKind: "harness-scenario", BenignControl: &attack, ExpectedActuators: []string{" ", "rotate"}}, false, "no server-authoritative"},
		{"named", CatalogItem{Name: "named", LaunchKind: "named-control", BenignControl: &attack, ExpectedActuators: []string{"rotate"}}, false, "not a harness"},
		{"fixed", CatalogItem{Name: "fixed", LaunchKind: "fixed-suite", BenignControl: &attack, ExpectedActuators: []string{"rotate"}}, false, "not a harness"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := catalogueSignalEligibility(tc.item)
			if got != tc.want || !strings.Contains(reason, tc.reason) {
				t.Fatalf("eligibility=%v reason=%q", got, reason)
			}
			projection := catalogueCompatProjection(tc.item, true, "stack supports this scenario")
			if projection["signalEligible"] != tc.want || projection["signalEligibilityReason"] != reason || projection["compatible"] != true {
				t.Fatalf("projection=%v", projection)
			}
		})
	}
}

func TestCatalogueSignalDefinitionUsesProjectedEligibility(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "harness")
	lines := []string{
		"Registered scenarios:",
		"  - ai1-inference-manipulation [AI] R6=AI1 realism=real benign=false declared=[T0001] exercised=[] caps=[]",
		"  - c2-voice-websocket-continuity [Application] R6=R6Partial realism=executable-mechanism benign=true declared=[] exercised=[] caps=[]",
		"  - c1-credtheft-rbac [ClassicChain] R6=R6CannotRespond techniques=[T1528] caps=[]",
		"  - c2-nats-uncredentialed-exposure [Application] R6=R6Partial realism=real benign=false declared=[] exercised=[] caps=[]",
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\ncat <<'CATALOG'\n"+strings.Join(lines, "\n")+"\nCATALOG\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{HarnessDir: dir, HarnessBin: bin}}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"ai1-inference-manipulation", true},
		{"c2-voice-websocket-continuity", false},
		{"c1-credtheft-rbac", false},
		{"c2-nats-uncredentialed-exposure", false},
		{limitedV1GuardrailID, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item, err := s.catalogueSignalDefinition(tc.name)
			if (err == nil) != tc.want {
				t.Fatalf("definition=%+v err=%v", item, err)
			}
			for _, projected := range s.cfg.Catalog() {
				if projected.Name == tc.name {
					api := catalogueCompatProjection(projected, true, "stack supports this scenario")
					if api["signalEligible"] != tc.want {
						t.Fatalf("server admission and API projection disagree: %v", api)
					}
					return
				}
			}
			t.Fatal("fixture item missing from authoritative catalogue")
		})
	}
}
