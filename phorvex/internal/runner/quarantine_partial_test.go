package runner

import (
	"context"
	"errors"
	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
	"testing"
)

type partialQuarantineActuator struct{ dispatchFakeActuator }

func (*partialQuarantineActuator) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	return actuator.Result{Emitted: true, Handler: "quarantine", ObjectsTouched: []string{"NetworkPolicy/ns/q"}, Note: "partial quarantine: Pod update conflict"}, errors.New("conflict")
}
func TestM038RunnerRetainsPartialEvidence(t *testing.T) {
	m := &Manager{Actuator: &partialQuarantineActuator{}, Log: logr.Discard()}
	ds := tracedSelectedDecision()
	ds[0].Action = model.ActionQuarantine
	views := map[string]*model.WorkloadView{"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", UID: "pod-uid", DesiredReplicas: 3, ReadyReplicas: 3, Ready: true}}}
	actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, model.Policy{Tenant: "t"}, ds, views)
	if ds[0].Actuated || ds[0].Trace.DispatchOutcome != model.DispatchError || len(ds[0].ObjectsTouched) != 1 || ds[0].Trace.DispatchReason != "outcome-unknown" {
		t.Fatalf("lost/misstated partial evidence: %+v", ds[0])
	}
}

type partialWarmActuator struct{ dispatchFakeActuator }

func (*partialWarmActuator) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	return actuator.Result{Emitted: false, Handler: "warm-swap", MutationKind: "swap", ObjectsTouched: []string{"Pod/ns/old", "Pod/ns/new"}, Note: "partial cutover: promoted leader and old retiring route retained"}, errors.New("drain failed")
}

func TestM086RunnerRetainsFailedWarmCutoverEffects(t *testing.T) {
	m := &Manager{Actuator: &partialWarmActuator{}, Log: logr.Discard()}
	ds := tracedSelectedDecision()
	ds[0].Action = model.ActionWarmSwap
	views := map[string]*model.WorkloadView{"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", UID: "pod-uid", ModelID: "fixture-model", DesiredReplicas: 3, ReadyReplicas: 3, Ready: true}}}
	actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, model.Policy{Tenant: "t"}, ds, views)
	if ds[0].Actuated || ds[0].Trace.DispatchOutcome != model.DispatchError || len(ds[0].ObjectsTouched) != 2 || ds[0].MutationKind != "swap" || ds[0].Trace.DispatchReason != "outcome-unknown" {
		t.Fatalf("failed warm cutover effects lost or claimed successful: %+v", ds[0])
	}
}
