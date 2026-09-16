package runner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

type m040ResultActuator struct {
	result actuator.Result
	err    error
	calls  int
}

func (*m040ResultActuator) Name() string { return "m040-result" }
func (*m040ResultActuator) EnsurePolicy(context.Context, actuator.TenantTarget) error {
	return nil
}
func (a *m040ResultActuator) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}
func (a *m040ResultActuator) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	a.calls++
	return a.result, a.err
}

// The real API producer test in internal/actuator establishes these result shapes from
// request-drain. This control exercises their actual Manager consumer: only confirmed abort
// plus completed restoration is Actuated; partial and unknown writes retain forensic fields,
// report dispatch error and cannot enter the clean-no-effect fallback path.
func TestM040RunnerAccountsConfirmedPartialAndUnknownDrainOutcomes(t *testing.T) {
	tests := []struct {
		name           string
		result         actuator.Result
		err            error
		wantActuated   bool
		wantOutcome    string
		wantReason     string
		wantObjects    int
		wantActuations int
	}{
		{
			name:         "confirmed-abort-and-restoration",
			result:       actuator.Result{Emitted: true, Handler: string(model.ActionRequestDrain), MutationKind: "reversible", ObjectsTouched: []string{"Pod/ns/p1", "ConfigMap/operator/receipt"}, Note: "request-drain: 1 in-flight aborted; exact serving state restored"},
			wantActuated: true, wantOutcome: model.DispatchEmitted, wantReason: "1 in-flight aborted", wantObjects: 2, wantActuations: 1,
		},
		{
			name:   "confirmed-write-restoration-unresolved",
			result: actuator.Result{Emitted: true, Handler: string(model.ActionRequestDrain), MutationKind: "reversible", ObjectsTouched: []string{"Pod/ns/p1", "ConfigMap/operator/receipt"}, Note: "request-drain partial confirmed mutation: restoration unresolved"},
			err:    errors.New("request-drain incomplete"), wantOutcome: model.DispatchError, wantReason: "partial confirmed mutation", wantObjects: 2,
		},
		{
			name:   "write-acceptance-unknown-receipt-retained",
			result: actuator.Result{Emitted: false, Handler: string(model.ActionRequestDrain), MutationKind: "reversible", ObjectsTouched: []string{"Pod/ns/p1", "ConfigMap/operator/receipt"}, Note: "request-drain outcome unknown: authoritative Pod outcome unreadable; receipt retained"},
			err:    errors.New("request-drain incomplete"), wantOutcome: model.DispatchError, wantReason: "outcome unknown", wantObjects: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			act := &m040ResultActuator{result: tc.result, err: tc.err}
			m := &Manager{Actuator: act, Log: logr.Discard()}
			decisions := tracedSelectedDecision()
			decisions[0].Action = model.ActionRequestDrain
			views := map[string]*model.WorkloadView{"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", UID: "pod-uid", ModelID: "fixture-model", DesiredReplicas: 3, ReadyReplicas: 3, Ready: true}}}
			policy := model.Policy{Tenant: "tenant", MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRequestDrain: true}}
			got := m.actuate(context.Background(), &policyEntry{namespace: "ns"}, policy, decisions, views)
			decision := decisions[0]
			if act.calls != 1 || got != tc.wantActuations || decision.Actuated != tc.wantActuated || decision.Trace.DispatchOutcome != tc.wantOutcome || !strings.Contains(decision.Trace.DispatchReason, tc.wantReason) || len(decision.ObjectsTouched) != tc.wantObjects {
				t.Fatalf("calls=%d actuations=%d decision=%+v trace=%+v", act.calls, got, decision, decision.Trace)
			}
			if tc.err != nil && len(m.fallbackDecisions) != 0 {
				t.Fatalf("partial/unknown request-drain entered fallback: %+v", m.fallbackDecisions)
			}
		})
	}
}
