package runner

import (
	"context"
	"errors"
	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
	"strings"
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
	m.actuate(context.Background(), &policyEntry{namespace: "ns"}, model.Policy{Tenant: "t"}, ds, views)
	if ds[0].Actuated || ds[0].Trace.DispatchOutcome != model.DispatchError || len(ds[0].ObjectsTouched) != 1 || !strings.Contains(ds[0].Trace.DispatchReason, "partial quarantine") {
		t.Fatalf("lost/misstated partial evidence: %+v", ds[0])
	}
}
