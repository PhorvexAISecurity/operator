/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (M-6)
 *
 * The T1-E gate's code-exec admission leg: debugger/custom-inject are offered ONLY when the
 * admission verifier reports available for the target namespace; the exclusion is attributed
 * to the distinct ReasonCodeExec class; non-code-exec actions are unaffected; and the tick's
 * per-namespace labels are threaded to the verifier (the C3 scope input).
 */

package capability

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// recordingAdmission is a fake AdmissionVerifier: it returns a configured verdict and records
// the namespace labels the gate passed (to prove the C3 scope input is threaded through).
type recordingAdmission struct {
	ok        bool
	reason    string
	sawLabels map[string]string
	calls     int
}

func (r *recordingAdmission) Available(nsLabels map[string]string) (bool, string) {
	r.calls++
	r.sawLabels = nsLabels
	return r.ok, r.reason
}

func codeExecView() *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "victim"}}
}

func TestEligible_CodeExecUnverifiedExcluded(t *testing.T) {
	_, wit := capFleet()
	adm := &recordingAdmission{ok: false, reason: ReasonCodeExec + ": not verified"}
	wit = wit.WithCodeExec(adm, map[string]map[string]string{"ns": {"phorvex.ai/codeexec-managed": "true"}})

	for _, action := range []model.Action{model.ActionDebugger, model.ActionCustomInject} {
		r := wit.Eligible(codeExecView(), action, []string{"cover-key"})
		if r == nil || !r.Excluded {
			t.Fatalf("%s must be excluded when admission is unverified", action)
		}
		if r.Kind != ReasonCodeExec {
			t.Fatalf("%s exclusion must be attributed to %q, got %q (detail %q)", action, ReasonCodeExec, r.Kind, r.Detail)
		}
	}
	// The tick's namespace labels were threaded to the verifier (C3 scope input).
	if adm.sawLabels["phorvex.ai/codeexec-managed"] != "true" {
		t.Fatalf("gate must pass the target namespace labels to the verifier, saw %v", adm.sawLabels)
	}
}

func TestEligible_CodeExecVerifiedOffered(t *testing.T) {
	_, wit := capFleet()
	adm := &recordingAdmission{ok: true}
	wit = wit.WithCodeExec(adm, map[string]map[string]string{"ns": {"phorvex.ai/codeexec-managed": "true"}})
	for _, action := range []model.Action{model.ActionDebugger, model.ActionCustomInject} {
		if r := wit.Eligible(codeExecView(), action, []string{"cover-key"}); r != nil {
			t.Fatalf("%s must be eligible when admission is verified+in-scope, got %+v", action, r)
		}
	}
}

// A non-code-exec action is never touched by the code-exec leg (even with a verifier that
// reports unavailable): rotate stays eligible.
func TestEligible_NonCodeExecUnaffectedByAdmissionLeg(t *testing.T) {
	_, wit := capFleet()
	adm := &recordingAdmission{ok: false, reason: "unverified"}
	wit = wit.WithCodeExec(adm, map[string]map[string]string{"ns": {"x": "y"}})
	if r := wit.Eligible(codeExecView(), model.ActionRotate, []string{"cover-key"}); r != nil {
		t.Fatalf("rotate must be unaffected by the code-exec admission leg, got %+v", r)
	}
	if adm.calls != 0 {
		t.Fatalf("the admission verifier must not be consulted for a non-code-exec action (calls=%d)", adm.calls)
	}
}

// A nil verifier (unit fixtures that do not wire one) skips the leg — never a hard failure.
// The runtime path always wires a real verifier, so this documents the fixture-only behavior.
func TestEligible_NilVerifierSkipsLeg(t *testing.T) {
	_, wit := capFleet()
	if r := wit.Eligible(codeExecView(), model.ActionDebugger, []string{"cover-key"}); r != nil {
		t.Fatalf("with no verifier wired the leg is skipped; got exclusion %+v", r)
	}
}
