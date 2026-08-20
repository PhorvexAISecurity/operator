/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package slo

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func TestEveryShippedActionHasExplicitClassification(t *testing.T) {
	actions := append([]model.Action{model.ActionNoop, model.ActionDisable}, model.MutatingActions...)
	for _, action := range actions {
		b, ok := Classify(action)
		if !ok {
			t.Fatalf("%s has no deterministic-impact classification", action)
		}
		if b.Action != action || (b.Status != StatusZero && b.Status != StatusBounded && b.Status != StatusUnknown) {
			t.Fatalf("%s has invalid classification: %+v", action, b)
		}
		if b.Status == StatusUnknown && b.MissingBound == "" {
			t.Fatalf("%s is unknown without naming the missing proof", action)
		}
		if b.Status == StatusZero && b.Evidence == "" {
			t.Fatalf("%s is zero without structural evidence", action)
		}
	}
}

func TestObservedMaximumIsNeverPromotedToDeterministicBound(t *testing.T) {
	b, ok := Classify(model.ActionRotate)
	if !ok {
		t.Fatal("rotate classification missing")
	}
	if b.Status != StatusUnknown {
		t.Fatalf("rotate status = %s, want unknown until deadlines and safe recovery are enforced", b.Status)
	}
	if b.ObservedMaxRecovery != 117*time.Second || b.ObservedEvidence == "" {
		t.Fatalf("rotate observed evidence not retained separately: %+v", b)
	}
	if b.MaxUnavailableDuration != 0 {
		t.Fatalf("117s leaked into deterministic duration: %+v", b)
	}
	if _, finite := b.ReplicaSeconds(); finite {
		t.Fatal("unknown rotate produced a numeric replica-seconds bound")
	}
	if _, finite := BoundFor(model.ActionRotate); finite {
		t.Fatal("BoundFor promoted an empirical maximum to a deterministic bound")
	}
}

func TestOnlyStructurallyZeroActionsProduceNumericZero(t *testing.T) {
	for _, action := range []model.Action{
		model.ActionNoop, model.ActionDisable, model.ActionIdentityRotate, model.ActionRouteRotate,
	} {
		b, ok := BoundFor(action)
		if !ok || b.Status != StatusZero {
			t.Fatalf("%s = %+v, %v; want a proven zero", action, b, ok)
		}
		value, finite := b.ReplicaSeconds()
		if !finite || value != 0 {
			t.Fatalf("%s replica-seconds = %v, %v; want finite zero", action, value, finite)
		}
	}
}

func TestServingPathAndArbitraryPayloadActionsStayUnknown(t *testing.T) {
	for _, action := range []model.Action{
		model.ActionWarmSwap, model.ActionMIGRebind, model.ActionEndpointRotate,
		model.ActionModelShardReplace, model.ActionAdapterRotate, model.ActionRequestDrain,
		model.ActionGuardrailRotate, model.ActionKVMigrateInvalidate,
		model.ActionDebugger, model.ActionCustomInject,
	} {
		b, _ := Classify(action)
		if b.Status != StatusUnknown || b.MissingBound == "" {
			t.Fatalf("%s must remain explicitly unknown: %+v", action, b)
		}
		if _, finite := b.ReplicaSeconds(); finite {
			t.Fatalf("%s unknown impact was exposed as a number", action)
		}
	}
}

func TestUnknownListIncludesRotateDespiteMeasurement(t *testing.T) {
	enabled := []model.Action{model.ActionKVReset, model.ActionRotate, model.ActionQuarantine}
	got := Unknown(enabled)
	if len(got) != 3 || got[0] != model.ActionKVReset || got[1] != model.ActionQuarantine || got[2] != model.ActionRotate {
		t.Fatalf("unknown actions = %v, want [kv-reset quarantine rotate]", got)
	}
	if legacy := Unmeasured(enabled); len(legacy) != len(got) || legacy[0] != got[0] || legacy[1] != got[1] || legacy[2] != got[2] {
		t.Fatalf("compatibility alias disagrees: %v vs %v", legacy, got)
	}
}

func TestFiniteBoundUsesOnlyEnforcedDuration(t *testing.T) {
	b := Bound{
		Action: model.ActionRotate, Status: StatusBounded,
		MaxUnavailableReplicas: 2, MaxUnavailableDuration: 15 * time.Second,
		Evidence: "test-only enforced action+rollback deadline",
	}
	value, finite := b.ReplicaSeconds()
	if !finite || value != 30 {
		t.Fatalf("finite bound = %v, %v; want 30 replica-seconds", value, finite)
	}
	requests, finite := LostRequestBound(b, 50)
	if !finite || requests != 750 {
		t.Fatalf("lost-request bound = %v, %v; want 750", requests, finite)
	}
	unknown, _ := Classify(model.ActionRotate)
	if _, finite := LostRequestBound(unknown, 50); finite {
		t.Fatal("unknown disruption produced a lost-request number")
	}
}

func TestAvailabilityIsServiceSpecificAndSeparate(t *testing.T) {
	if got := AvailabilityFor(model.ActionRotate, 3, 2); got.Status != StatusZero {
		t.Fatalf("3 ready, floor 2, max loss 1 should have zero breach: %+v", got)
	}
	if got := AvailabilityFor(model.ActionRotate, 2, 2); got.Status != StatusUnknown {
		t.Fatalf("2 ready, floor 2 can breach on unknown rotate path: %+v", got)
	}
	if got := AvailabilityFor(model.ActionKVReset, 1, 1); got.Status != StatusUnknown {
		t.Fatalf("external cache flush without safe recovery must remain unknown: %+v", got)
	}
	if got := AvailabilityFor(model.ActionRotate, -1, 1); got.Status != StatusUnknown {
		t.Fatalf("missing Ready count must remain unknown: %+v", got)
	}
}

func TestLoadNeverEntersReplicaSeconds(t *testing.T) {
	b := Bound{Status: StatusBounded, MaxUnavailableReplicas: 1, MaxUnavailableDuration: 3 * time.Second}
	value, finite := b.ReplicaSeconds()
	if !finite || value != 3 {
		t.Fatalf("replica-seconds = %v, %v; want 3 independent of load", value, finite)
	}
	requests, finite := LostRequestBound(b, 1_000)
	if !finite || requests != 3_000 {
		t.Fatalf("separate request-loss quantity = %v, %v; want 3000", requests, finite)
	}
}
