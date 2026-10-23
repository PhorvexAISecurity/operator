/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (M-6)
 *
 * The pre-submit admission gate at the actuate boundary: a code-exec move (debugger/custom-
 * inject) is dispatched ONLY after a fresh FinalCheck (by namespace identity) passes. Fail-
 * closed on a nil verifier (unwired) and on an unverified/unavailable verifier; a verified+in-
 * scope verifier lets the dispatch proceed (positive control). Guards both direct dispatch and
 * any queued work reaching this boundary.
 */

package runner

import (
	"context"
	"testing"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
)

// fakeAdmissionFinal implements the runner's codeExecVerifier (Available + FinalCheck).
type fakeAdmissionFinal struct {
	ok     bool
	reason string
	sawNS  string
}

func (f *fakeAdmissionFinal) Available(map[string]string) (bool, string) { return f.ok, f.reason }
func (f *fakeAdmissionFinal) FinalCheck(_ context.Context, namespace string) (bool, string) {
	f.sawNS = namespace
	return f.ok, f.reason
}

func TestCodeExecPreSubmitGateFailsClosed(t *testing.T) {
	view := map[string]*model.WorkloadView{
		"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", ReadyReplicas: 3}},
	}
	dec := func() []model.Decision {
		return []model.Decision{{Selected: true, Feasible: true, Action: model.ActionDebugger, Namespace: "ns", Pod: "p1"}}
	}
	pol := model.Policy{Tenant: "t", EnabledActions: map[model.Action]bool{model.ActionDebugger: true}}
	e := &policyEntry{namespace: "ns"}

	// (a) nil verifier (unwired) => fail-closed, zero actuations.
	fa := &fakeActuator{}
	m := &Manager{Local: &inprocess.Services{Actuator: fa}, Log: logr.Discard()}
	if n := actuateWithBoundary(t, m, context.Background(), e, pol, dec(), view); n != 0 || fa.calls != 0 {
		t.Fatalf("nil verifier must fail-closed (n=%d, Actuate calls=%d)", n, fa.calls)
	}

	// (b) unavailable verifier => refused before the irreversible submit; FinalCheck saw the
	// target namespace identity (not stale labels).
	fa = &fakeActuator{}
	adm := &fakeAdmissionFinal{ok: false, reason: capability.ReasonCodeExec + ": not verified"}
	m = &Manager{Local: &inprocess.Services{Actuator: fa}, Log: logr.Discard(), CodeExec: adm}
	if n := actuateWithBoundary(t, m, context.Background(), e, pol, dec(), view); n != 0 || fa.calls != 0 {
		t.Fatalf("unavailable verifier must refuse dispatch (n=%d, Actuate calls=%d)", n, fa.calls)
	}
	if adm.sawNS != "ns" {
		t.Fatalf("FinalCheck must receive the target namespace identity, saw %q", adm.sawNS)
	}

	// (c) verified => the code-exec gate does not block; dispatch proceeds once.
	fa = &fakeActuator{}
	m = &Manager{Local: &inprocess.Services{Actuator: fa}, Log: logr.Discard(), CodeExec: &fakeAdmissionFinal{ok: true}}
	if n := actuateWithBoundary(t, m, context.Background(), e, pol, dec(), view); n != 1 || fa.calls != 1 {
		t.Fatalf("verified verifier must allow dispatch (n=%d, Actuate calls=%d)", n, fa.calls)
	}
}
