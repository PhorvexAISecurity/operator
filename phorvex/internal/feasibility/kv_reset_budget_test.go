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

// TestRotateStillUsesPodIdentity guards the actions that REPLACE the pod — podIdentity IS their
// clock, so a freshly-rotated pod cannot be rotated again inside the window. (M-23 moved quarantine
// off podIdentity onto its own VarNetworkIdentity clock — see TestPerActionClockThrottles.)
func TestRotateStillUsesPodIdentity(t *testing.T) {
	pol := model.Policy{AntiOverRotationWindow: 15 * time.Minute}
	// Pod replaced 20s ago; session flushed long ago.
	v := viewWithClocks(20*time.Second, 10*time.Hour)
	for _, a := range []model.Action{
		model.ActionRotate, model.ActionWarmSwap, model.ActionMIGRebind, model.ActionModelShardReplace,
	} {
		if (antiOverRotation{}).Check(v, model.Move{Action: a}, pol).Feasible {
			t.Errorf("%q 20s after the pod was replaced must be blocked — it reads podIdentity", a)
		}
	}
}

// TestUnmappedActionIsUngovernedFailOpen pins the M-23 default: an action with NO exposure mapping
// returns "" (ungoverned) and the guard fail-OPENs — the old podIdentity fallback is gone (it hid
// pod-alive actions behind a clock they never reset). A missing mapping for a REAL generatable
// action is a build-time failure of TestExposureVarForCompleteness, not a silent runtime pass.
func TestUnmappedActionIsUngovernedFailOpen(t *testing.T) {
	if got := ExposureVarFor(model.Action("some-future-action")); got != "" {
		t.Fatalf("unmapped action mapped to %q; M-23 wants \"\" (ungoverned, fail-open) so a stale "+
			"podIdentity clock can't silently un-throttle a pod-alive action", got)
	}
	// And an ungoverned action on a pod with clocks is feasible (fail-open).
	v := viewWithClocks(20*time.Second, 20*time.Second)
	pol := model.Policy{AntiOverRotationWindow: 15 * time.Minute}
	if got := (antiOverRotation{}).Check(v, model.Move{Action: model.Action("some-future-action")}, pol); !got.Feasible {
		t.Fatalf("an ungoverned action must be feasible (fail-open), got veto: %s", got.Reason)
	}
}
