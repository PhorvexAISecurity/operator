package runner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
)

type fakeActuator struct{ calls int }

func (f *fakeActuator) Name() string                                              { return "fake" }
func (f *fakeActuator) EnsurePolicy(context.Context, actuator.TenantTarget) error { return nil }
func (f *fakeActuator) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	f.calls++
	return actuator.Result{Emitted: true}, nil
}
func (f *fakeActuator) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}

// TestEmitBoundaryFailsClosedOnMapMiss — P4c D3/F5: a selected+feasible move whose target pod is
// ABSENT from the tick view (map-miss) must be VETOED at the emit boundary (fail-CLOSED,
// 0 actuations), not actuated on the stale cached bool. A present+feasible move still actuates.
func TestEmitBoundaryFailsClosedOnMapMiss(t *testing.T) {
	fa := &fakeActuator{}
	m := &Manager{Local: &inprocess.Services{Actuator: fa}, Log: logr.Discard()}
	e := &policyEntry{namespace: "ns"}
	pol := model.Policy{Tenant: "t", EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	mkDec := func() []model.Decision {
		return []model.Decision{{Selected: true, Feasible: true, Action: model.ActionRotate, Namespace: "ns", Pod: "p1"}}
	}

	// map-MISS: empty tick view => invariant check fails CLOSED => 0 actuations.
	if n := actuateWithBoundary(t, m, context.Background(), e, pol, mkDec(), map[string]*model.WorkloadView{}); n != 0 || fa.calls != 0 {
		t.Fatalf("FAIL-OPEN: map-miss actuated (n=%d, Actuate calls=%d); must fail CLOSED", n, fa.calls)
	}

	// present + feasible: the move IS actuated (proves the veto is the map-miss, not a blanket block).
	fa.calls = 0
	view := map[string]*model.WorkloadView{"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", ReadyReplicas: 3}}}
	if actuateWithBoundary(t, m, context.Background(), e, pol, mkDec(), view); fa.calls != 1 {
		t.Fatalf("present+feasible move should actuate once, got %d calls", fa.calls)
	}
}

func TestEmitBoundaryDoesNotClaimFreshResnapshot(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "manager.go"))
	if err != nil {
		t.Fatalf("read manager.go: %v", err)
	}
	text := string(raw)
	for _, misleading := range []string{"feasibility RE-GATE", "on live view state"} {
		if strings.Contains(text, misleading) {
			t.Fatalf("emit-boundary comment restored misleading fresh-state claim %q", misleading)
		}
	}
	for _, required := range []string{"same tick snapshot", "does not refresh Kubernetes state"} {
		if !strings.Contains(text, required) {
			t.Fatalf("emit-boundary limitation must remain explicit; missing %q", required)
		}
	}
}
