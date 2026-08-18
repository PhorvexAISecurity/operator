/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package slo

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/model"
)

// An action that removes no Ready replica is bounded at exactly zero, and that
// conclusion needs no measurement — it follows from what the action does. If this
// ever regressed to "unbounded", the model would block the gentle in-process
// defense on the single-replica inference pods it suits best.
func TestInProcessActionsAreBoundedAtZeroWithoutMeasurement(t *testing.T) {
	for _, a := range []model.Action{
		model.ActionKVReset,
		model.ActionWarmSwap,
		model.ActionEndpointRotate,
		model.ActionIdentityRotate,
		model.ActionRouteRotate,
		model.ActionAdapterRotate,
		model.ActionGuardrailRotate,
	} {
		b, ok := BoundFor(a)
		if !ok {
			t.Fatalf("%s: expected a bound, got unbounded", a)
		}
		if b.MaxUnavailableReplicas != 0 {
			t.Fatalf("%s: expected 0 replicas removed, got %d", a, b.MaxUnavailableReplicas)
		}
		if got := b.ReplicaSeconds(); got != 0 {
			t.Fatalf("%s: expected 0 replica-seconds, got %v", a, got)
		}
		if b.Evidence == "" {
			t.Fatalf("%s: bound carries no evidence", a)
		}
	}
}

// rotate is the one replica-removing action with a measured recovery, so it is
// bounded and its bound is that measurement — not a rounded or assumed figure.
func TestRotateBoundIsTheMeasuredWorstRecovery(t *testing.T) {
	b, ok := BoundFor(model.ActionRotate)
	if !ok {
		t.Fatal("rotate: expected a bound")
	}
	if b.MaxUnavailableReplicas != 1 {
		t.Fatalf("rotate removes one Ready replica per move, got %d", b.MaxUnavailableReplicas)
	}
	if b.MaxUnavailableDuration != 117*time.Second {
		t.Fatalf("rotate duration must be the measured 117s worst recovery, got %v", b.MaxUnavailableDuration)
	}
	if got, want := b.ReplicaSeconds(), 117.0; got != want {
		t.Fatalf("rotate bound = %v replica-seconds, want %v", got, want)
	}
}

// The load-bearing negative. quarantine removes a Ready replica and nobody has
// measured how long it stays removed, so it must report UNBOUNDED. A default
// would turn a hard gate into one that silently is not.
func TestUnmeasuredReplicaRemovingActionIsUnbounded(t *testing.T) {
	if _, ok := BoundFor(model.ActionQuarantine); ok {
		t.Fatal("quarantine has no measured recovery and must be unbounded until it does")
	}
	if Bounded(model.ActionQuarantine) {
		t.Fatal("Bounded disagrees with BoundFor for quarantine")
	}
}

func TestUnmeasuredListsOnlyTheBlockedActions(t *testing.T) {
	enabled := []model.Action{
		model.ActionRotate,     // measured
		model.ActionKVReset,    // removes nothing
		model.ActionQuarantine, // removes a replica, unmeasured
	}
	got := Unmeasured(enabled)
	if len(got) != 1 || got[0] != model.ActionQuarantine {
		t.Fatalf("expected only quarantine unmeasured, got %v", got)
	}
}

// Load never enters the replica-seconds bound; it belongs to the separately
// dimensioned request-loss ceiling. Adding it to the first would sum quantities
// in different units.
func TestLoadDoesNotEnterTheReplicaSecondsBound(t *testing.T) {
	b, _ := BoundFor(model.ActionRotate)
	if got, want := b.ReplicaSeconds(), 117.0; got != want {
		t.Fatalf("replica-seconds must not depend on load: got %v want %v", got, want)
	}
	// The request ceiling does take load, and is a different number entirely.
	if got, want := LostRequestBound(b, 50), 5850.0; got != want {
		t.Fatalf("LostRequestBound = %v, want %v", got, want)
	}
	// An action that removes nothing loses no requests, whatever the load.
	zero, _ := BoundFor(model.ActionKVReset)
	if got := LostRequestBound(zero, 1e6); got != 0 {
		t.Fatalf("in-process action must lose no requests, got %v", got)
	}
}

// The bound derives "how many Ready replicas can this take out" from the SAME
// predicate the availability floor gates on. If a new action is added to one and
// not the other, the bound silently starts reporting zero disruption for an
// action that removes a replica — a hard gate that is not one. This pins them
// together.
func TestReplicaCountAgreesWithTheFeasibilityPredicate(t *testing.T) {
	all := []model.Action{
		model.ActionNoop, model.ActionRotate, model.ActionQuarantine,
		model.ActionDebugger, model.ActionCustomInject, model.ActionDisable,
		model.ActionIdentityRotate, model.ActionRouteRotate, model.ActionWarmSwap,
		model.ActionMIGRebind, model.ActionKVReset, model.ActionEndpointRotate,
		model.ActionModelShardReplace, model.ActionAdapterRotate,
		model.ActionRequestDrain, model.ActionGuardrailRotate,
		model.ActionKVMigrateInvalidate,
	}
	for _, a := range all {
		b, ok := BoundFor(a)
		removes := feasibility.RemovesReadyReplica(a)
		switch {
		case !removes && !ok:
			t.Fatalf("%s: removes no replica, so it must be bounded at zero, not unbounded", a)
		case !removes && b.MaxUnavailableReplicas != 0:
			t.Fatalf("%s: removes no replica but bound claims %d", a, b.MaxUnavailableReplicas)
		case removes && ok && b.MaxUnavailableReplicas == 0:
			t.Fatalf("%s: removes a replica but its bound claims zero disruption", a)
		case removes && ok && b.MaxUnavailableDuration <= 0:
			t.Fatalf("%s: bounded with no measured duration", a)
		}
	}
}
