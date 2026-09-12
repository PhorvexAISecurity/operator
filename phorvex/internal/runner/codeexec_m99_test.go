/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (M-6)
 *
 * M99 coexistence regression: the qualified-outcome / SLO-breach path must NOT be able to
 * re-admit a code-exec move whose API-server admission is unverified. The production tick
 * closure is codeExecAwareEligibility; these tests exercise that exact function so the
 * precedence (full gate first, M99 no-rbac fallback only when eligible) cannot regress.
 */

package runner

import (
	"context"
	"testing"

	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/model"
)

type fakeAdmission struct {
	ok     bool
	reason string
}

func (f fakeAdmission) Available(map[string]string) (bool, string) { return f.ok, f.reason }

func unverifiedCodeExecWitness() capability.Witness {
	// Empty fleet/index; no installability gaps; no SSAR checker; code-exec admission
	// UNVERIFIED for the labelled namespace. The backend is an EXPLICIT support double
	// (M-21): these tests isolate the code-exec and M99 no-rbac legs, and an absent
	// backend would now exclude every action first, for the wrong reason.
	return capability.BuildWitness(context.Background(), capability.BuildIndex(nil, nil, nil), nil, nil, supportsAll{}).
		WithCodeExec(
			fakeAdmission{ok: false, reason: capability.ReasonCodeExec + ": not verified"},
			map[string]map[string]string{"ns": {"phorvex.ai/codeexec-managed": "true"}},
		)
}

func TestM99CannotBypassCodeExecAdmissionGate(t *testing.T) {
	wit := unverifiedCodeExecWitness()
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "victim"}}
	qualified := func(*model.WorkloadView) bool { return true } // M99 active

	// authzNil=true + qualified outcome = the M99 fallback path. A code-exec move is STILL
	// excluded by the admission leg, attributed to the code-exec class — never re-admitted.
	for _, action := range []model.Action{model.ActionDebugger, model.ActionCustomInject} {
		got := codeExecAwareEligibility(wit, true, qualified, v, action, []string{"cover-key"})
		if got == nil || !got.Excluded {
			t.Fatalf("%s must be excluded under M99 (authzNil+qualified), got %+v", action, got)
		}
		if got.Kind != capability.ReasonCodeExec {
			t.Fatalf("%s exclusion must be attributed to %q, got %q", action, capability.ReasonCodeExec, got.Kind)
		}
	}
}

// Positive control: a non-code-exec action that is otherwise eligible still receives the
// M99 no-rbac marker under authzNil+qualified — proving the extraction preserved the M99
// path exactly and the code-exec leg does not disturb it.
func TestM99NoRBACPathPreservedForNonCodeExec(t *testing.T) {
	wit := unverifiedCodeExecWitness()
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "victim"}}
	got := codeExecAwareEligibility(wit, true, func(*model.WorkloadView) bool { return true }, v, model.ActionRotate, []string{"cover-key"})
	if got == nil || !got.Excluded || got.Kind != capability.ReasonNoRBAC {
		t.Fatalf("rotate under M99+authzNil must carry the m99 no-rbac marker, got %+v", got)
	}
	// And with a live SSAR checker (authzNil=false) + no qualified outcome, an eligible action
	// is not excluded at all.
	got = codeExecAwareEligibility(wit, false, func(*model.WorkloadView) bool { return false }, v, model.ActionRotate, []string{"cover-key"})
	if got != nil {
		t.Fatalf("rotate with live authz and no qualified outcome must be eligible, got %+v", got)
	}
}
