package runner

import (
	"context"
	"sync"
	"testing"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/model"
)

// probingBackend counts support questions; for a real backend each may read the
// cluster, read journals or probe the workload.
type probingBackend struct {
	supportsAll
	mu     sync.Mutex
	probes int
}

func (b *probingBackend) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probes++
	return true, ""
}

func (b *probingBackend) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.probes
}

// TestShadowArmProbesNoWorkload runs the tick's own pieces in the tick's order: the
// ActionsSupported status pass, then the counterfactual arm over calibration-style
// view copies through the wired shadow gate. The shadow must reuse the status
// pass's support answers and send nothing to the actuator (M-163).
func TestShadowArmProbesNoWorkload(t *testing.T) {
	backend := &probingBackend{}
	wit := capability.BuildWitness(context.Background(), capability.BuildIndex(nil, nil, nil), nil, nil, localActuator(backend))
	views := []*model.WorkloadView{
		{Pod: model.Pod{Namespace: "vllm", Name: "web-0", UID: "uid-0", Labels: map[string]string{"app": "web"}}},
		{Pod: model.Pod{Namespace: "vllm", Name: "web-1", UID: "uid-1", Labels: map[string]string{"app": "web"}}},
	}
	pol := model.Policy{} // the default action set: rotate and quarantine
	capabilityGaps(pol, views, wit)
	reviewed := backend.count()
	if reviewed != len(views)*2 {
		t.Fatalf("the status pass asked %d support questions, want %d", reviewed, len(views)*2)
	}

	gate := capabilityGate(wit, true, noQualified)
	for _, view := range views {
		shadow := *view // calibration's shadow views copy the view and change only its physics
		shadow.Physics.DispersionCap = 0.5
		for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
			if got := gate.ShadowCapability(&shadow, a, []string{"cover-key"}); got != nil && got.Excluded && got.Kind == capability.ReasonCapability {
				t.Fatalf("the shadow did not reuse the status pass's support answer for %s on %s: %+v", a, view.Pod.Name, got)
			}
		}
	}
	if backend.count() != reviewed {
		t.Fatalf("the shadow arm sent %d support questions to the actuator", backend.count()-reviewed)
	}
}
