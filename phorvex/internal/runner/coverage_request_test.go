package runner

import (
	"context"
	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
	"testing"
)

type coverageCapture struct {
	dispatchFakeActuator
	request actuator.Request
}

func (f *coverageCapture) Actuate(_ context.Context, r actuator.Request) (actuator.Result, error) {
	f.request = r
	f.calls++
	return actuator.Result{Emitted: true}, nil
}
func TestM032RunnerPreservesRawCoverage(t *testing.T) {
	fa := &coverageCapture{}
	m := &Manager{Actuator: fa, Log: logr.Discard()}
	ds := tracedSelectedDecision()
	ds[0].CoverageValue = 8.125
	ds[0].Engine = "p1-coverage"
	views := map[string]*model.WorkloadView{"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", DesiredReplicas: 3, ReadyReplicas: 3, Ready: true}}}
	actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, model.Policy{Tenant: "tenant"}, ds, views)
	if fa.calls != 1 || fa.request.CoverageValue == nil || *fa.request.CoverageValue != 8.125 || fa.request.Score != -1 {
		t.Fatalf("calls=%d request=%+v", fa.calls, fa.request)
	}
}
