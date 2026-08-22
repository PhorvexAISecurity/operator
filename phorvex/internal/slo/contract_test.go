/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package slo

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func boundedPhase(name string, replicas int, deadline time.Duration) Phase {
	return Phase{
		Name: name, MaxUnavailableReplicas: replicas, Deadline: deadline,
		DeadlineEnforced: true, StopsAtDeadline: true, BoundSource: "test enforced path",
	}
}

func completeContract(paths ...ExecutionPath) ActionContract {
	return ActionContract{
		Action: model.ActionWarmSwap, Paths: paths, EnumerationComplete: true,
		Provenance: "test contract",
	}
}

func TestContractDerivationIsDeterministicAndSelectsWorstPath(t *testing.T) {
	contract := completeContract(
		ExecutionPath{Name: "success", Kind: PathSuccess, SafeReturnVerified: true, Phases: []Phase{
			boundedPhase("cutover", 1, 5*time.Second),
		}},
		ExecutionPath{Name: "failure+rollback", Kind: PathFailure, SafeReturnVerified: true, Phases: []Phase{
			boundedPhase("failed cutover", 1, 5*time.Second),
			boundedPhase("rollback", 1, 10*time.Second),
		}},
		ExecutionPath{Name: "deadline+rollback", Kind: PathDeadlineExpiry, SafeReturnVerified: true, Phases: []Phase{
			boundedPhase("deadline", 1, 7*time.Second),
			boundedPhase("rollback", 1, 10*time.Second),
		}},
		ExecutionPath{Name: "explicit rollback", Kind: PathRollback, SafeReturnVerified: true, Phases: []Phase{
			boundedPhase("rollback", 1, 10*time.Second),
		}},
	)
	one, two := DeriveContract(contract), DeriveContract(contract)
	if !reflect.DeepEqual(one, two) {
		t.Fatalf("same contract derived different results: %+v vs %+v", one, two)
	}
	value, finite := one.ReplicaSeconds()
	if one.Status != StatusBounded || !finite || value != 17 {
		t.Fatalf("worst path = %+v, value=%v finite=%v; want bounded 17", one, value, finite)
	}
}

func TestSerialPhasesAddReplicaSecondsAndWarmupIsExcluded(t *testing.T) {
	contract := completeContract(ExecutionPath{
		Name: "warm-swap success", Kind: PathSuccess, SafeReturnVerified: true,
		Phases: []Phase{
			{Name: "warm-up while old serves", MaxUnavailableReplicas: 0, Deadline: 120 * time.Second},
			boundedPhase("cutover", 1, 5*time.Second),
			boundedPhase("retire", 2, 3*time.Second),
		},
	})
	bound := DeriveContract(contract)
	value, finite := bound.ReplicaSeconds()
	if !finite || value != 11 {
		t.Fatalf("serial bound = %+v, value=%v; want 1*5 + 2*3 = 11", bound, value)
	}
	if bound.MaxUnavailableDuration != 8*time.Second {
		t.Fatalf("loss duration = %s, want 8s (warm-up excluded)", bound.MaxUnavailableDuration)
	}
}

func TestParallelCompositeUsesLongestDeadlineAndMaximumLoss(t *testing.T) {
	contract := completeContract(ExecutionPath{
		Name: "parallel cutover", Kind: PathSuccess, SafeReturnVerified: true,
		Phases: []Phase{{Name: "composite", Parallel: []Phase{
			boundedPhase("route update", 1, 5*time.Second),
			boundedPhase("old retire", 2, 3*time.Second),
		}}},
	})
	bound := DeriveContract(contract)
	value, finite := bound.ReplicaSeconds()
	if !finite || value != 10 || bound.MaxUnavailableDuration != 5*time.Second {
		t.Fatalf("parallel envelope = %+v, value=%v; want max(n)=2 * max(t)=5", bound, value)
	}
}

func TestReturnOnlyTimeoutAndMissingRecoveryStayUnknown(t *testing.T) {
	returnsOnly := completeContract(ExecutionPath{
		Name: "timeout", Kind: PathDeadlineExpiry, SafeReturnVerified: true,
		Phases: []Phase{{
			Name: "async operation", MaxUnavailableReplicas: 1, Deadline: 10 * time.Second,
			DeadlineEnforced: true, StopsAtDeadline: false, BoundSource: "caller context only",
		}},
	})
	if got := DeriveContract(returnsOnly); got.Status != StatusUnknown || !strings.Contains(got.MissingBound, "may continue") {
		t.Fatalf("return-only timeout was accepted: %+v", got)
	}

	missingRecovery := completeContract(ExecutionPath{
		Name: "failure", Kind: PathFailure, SafeReturnVerified: false,
		Phases: []Phase{boundedPhase("failed cutover", 1, 5*time.Second)},
	})
	if got := DeriveContract(missingRecovery); got.Status != StatusUnknown || !strings.Contains(got.MissingBound, "safe state") {
		t.Fatalf("missing recovery verification was accepted: %+v", got)
	}
}

func TestIncompleteInventoryNeverProducesFiniteBound(t *testing.T) {
	contract := completeContract(ExecutionPath{
		Name: "success", Kind: PathSuccess, SafeReturnVerified: true,
		Phases: []Phase{boundedPhase("cutover", 1, time.Second)},
	})
	contract.EnumerationComplete = false
	if got := DeriveContract(contract); got.Status != StatusUnknown || got.MissingBound == "" {
		t.Fatalf("incomplete path inventory was accepted: %+v", got)
	}
}

func TestStructurallyZeroContractNeedsNoDuration(t *testing.T) {
	contract := completeContract(
		ExecutionPath{Name: "success", Kind: PathSuccess, Phases: []Phase{{Name: "metadata patch"}}},
		ExecutionPath{Name: "failure", Kind: PathFailure, Phases: []Phase{{Name: "API error before mutation"}}},
	)
	bound := DeriveContract(contract)
	value, finite := bound.ReplicaSeconds()
	if bound.Status != StatusZero || !finite || value != 0 {
		t.Fatalf("zero contract = %+v, value=%v finite=%v", bound, value, finite)
	}
}

func TestPositiveDisruptionCanHaveZeroAvailabilityBreach(t *testing.T) {
	contract := completeContract(ExecutionPath{
		Name: "cutover", Kind: PathSuccess, SafeReturnVerified: true,
		Phases: []Phase{boundedPhase("one replica", 1, 15*time.Second)},
	})
	if disruption := DeriveContract(contract); disruption.Status != StatusBounded {
		t.Fatalf("positive disruption not bounded: %+v", disruption)
	}
	if availability := AvailabilityFromContract(contract, 2, 1); availability.Status != StatusZero {
		t.Fatalf("headroom should prove zero breach: %+v", availability)
	}
	if availability := AvailabilityFromContract(contract, 1, 1); availability.Status != StatusBounded || availability.MaxDuration != 15*time.Second {
		t.Fatalf("floor-crossing availability = %+v, want bounded 15s", availability)
	}
}
