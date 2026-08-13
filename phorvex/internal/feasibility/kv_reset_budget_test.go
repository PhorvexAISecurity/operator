package feasibility

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// kv_reset_budget_test.go — PHVX-67 / PHORVEXSEC-67.
//
// Reproduces the live defect. On phorvex-dev-eks one vllm pod took 2360 kv-resets in 10h21m, a
// median of 20s apart, against an antiOverRotationWindow of 15m — 45x over budget, continuously.
//
// The cause was not a bypassed gate. The gate ran, and read the wrong clock: it always consulted
// podIdentity, and kv-reset leaves the pod alive, so that clock only ever grew.

func viewWithClocks(podIdentity, session time.Duration) *model.WorkloadView {
	return &model.WorkloadView{
		Pod: model.Pod{Namespace: "vllm", Name: "vllm-1", UID: "u1"},
		ExposureByVariable: map[string]time.Duration{
			model.VarPodIdentity: podIdentity,
			model.VarSession:     session,
		},
	}
}

func TestKVResetRespectsItsOwnBudget(t *testing.T) {
	pol := model.Policy{AntiOverRotationWindow: 15 * time.Minute}

	// The live shape: the pod has been alive for hours, but its session was flushed 20s ago.
	v := viewWithClocks(10*time.Hour, 20*time.Second)

	got := (antiOverRotation{}).Check(v, model.Move{Action: model.ActionKVReset}, pol)
	if got.Feasible {
		t.Fatalf("kv-reset 20s after the last flush was allowed against a 15m budget. The guard is "+
			"reading podIdentity (%s), which kv-reset never changes, instead of the session clock.",
			v.ExposureByVariable[model.VarPodIdentity])
	}

	// kv-migrate-invalidate flushes the same state and must share the clock.
	if (antiOverRotation{}).Check(v, model.Move{Action: model.ActionKVMigrateInvalidate}, pol).Feasible {
		t.Error("kv-migrate-invalidate flushes the same session state and must share the budget")
	}
}

// TestKVResetAllowedOnceTheBudgetElapses is the other side: the fix must not disable the action.
func TestKVResetAllowedOnceTheBudgetElapses(t *testing.T) {
	pol := model.Policy{AntiOverRotationWindow: 15 * time.Minute}
	v := viewWithClocks(10*time.Hour, 16*time.Minute)
	if got := (antiOverRotation{}).Check(v, model.Move{Action: model.ActionKVReset}, pol); !got.Feasible {
		t.Fatalf("kv-reset 16m after the last flush must be allowed against a 15m budget: %s", got.Reason)
	}
}

// TestRotateStillUsesPodIdentity guards the actions the old behaviour was correct for. A rotate
// replaces the pod, so podIdentity IS its clock — reading the session clock for it would let a
// freshly-rotated pod be rotated again.
func TestRotateStillUsesPodIdentity(t *testing.T) {
	pol := model.Policy{AntiOverRotationWindow: 15 * time.Minute}
	// Pod replaced 20s ago; session flushed long ago.
	v := viewWithClocks(20*time.Second, 10*time.Hour)
	for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine, model.ActionWarmSwap} {
		if (antiOverRotation{}).Check(v, model.Move{Action: a}, pol).Feasible {
			t.Errorf("%q 20s after the pod was replaced must be blocked — it reads podIdentity", a)
		}
	}
}

// TestUnknownActionFallsBackConservatively pins the default. A new action with no mapping must fall
// back to podIdentity, which over-restricts rather than under-restricts.
func TestUnknownActionFallsBackConservatively(t *testing.T) {
	if got := exposureVarFor(model.Action("some-future-action")); got != model.VarPodIdentity {
		t.Fatalf("unmapped action fell back to %q; it must default to %q so a missing mapping "+
			"cannot silently remove a budget", got, model.VarPodIdentity)
	}
}
