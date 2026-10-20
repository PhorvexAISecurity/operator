package main

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/brainsvc"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/scopedoutcome"
)

func TestPost25M106ScopedOutcomeDisabledByDefault(t *testing.T) {
	producer, err := openConfiguredScopedOutcome(t.Context(), "", nil, nil, "")
	if err != nil || producer != nil {
		t.Fatalf("empty configuration changed the default runtime: producer=%v err=%v", producer, err)
	}
}

func TestPost25M106BadScopedOutcomeConfigLeavesNoProducer(t *testing.T) {
	producer, err := openConfiguredScopedOutcome(t.Context(), filepath.Join(t.TempDir(), "missing.json"), nil, brainsvc.NewLocal(decision.NewCoverageEngine(), nil), actuatorapi.BackendNative)
	if producer != nil || scopedoutcome.StartupErrorCode(err) != "config-read" {
		t.Fatalf("bad startup config created a producer: producer=%v err=%v code=%q", producer, err, scopedoutcome.StartupErrorCode(err))
	}
}

func TestPost25M106ManagerExitAlwaysClosesScopedOutcomeProducer(t *testing.T) {
	want := errors.New("manager stopped")
	var disabled *scopedoutcome.Producer
	if err := runWithScopedOutcomeClose(func() error { return want }, disabled); !errors.Is(err, want) {
		t.Fatalf("typed nil producer changed manager exit or panicked: err=%v", err)
	}
}

func TestPost25M106PhoenixOnlyRouteRefusesObserverBeforeReadingConfig(t *testing.T) {
	producer, err := openConfiguredScopedOutcome(t.Context(), filepath.Join(t.TempDir(), "missing.json"), nil, brainsvc.NewLocal(decision.NewCoverageEngine(), nil), actuatorapi.BackendPhoenix)
	if producer != nil || err == nil || scopedoutcome.StartupErrorCode(err) != "unknown" {
		t.Fatalf("Phoenix-only runtime enabled scoped observer: producer=%v err=%v", producer, err)
	}
}
