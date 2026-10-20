package capability

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/phorvex/phorvex/internal/actuatorapi"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/model"
)

// countingActuator stands in for a backend whose support checks probe the
// workload: every call is one probe.
type countingActuator struct {
	mu        sync.Mutex
	calls     int
	supported map[model.Action]bool
}

func (c *countingActuator) SupportsAction(_ context.Context, a model.Action, t actuatorapi.Target) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.supported[a] {
		return true, ""
	}
	return false, "probe refused " + string(a) + " on " + t.Pod
}
func (c *countingActuator) CapabilityAdvisory(context.Context, model.Action, actuatorapi.Target) string {
	return ""
}
func (c *countingActuator) RequiredVerbs(model.Action) []authz.Verb { return nil }
func (c *countingActuator) probes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func supportView(name string) *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{Namespace: "vllm", Name: name, UID: "uid-" + name, Labels: map[string]string{"app": "web"}}}
}

// TestShadowAnswersSupportFromTheTicksReviews pins the M-163 contract for the
// backend support leg: the counterfactual pass never asks the actuator, and
// answers exactly what the tick's reviewing passes were told.
func TestShadowAnswersSupportFromTheTicksReviews(t *testing.T) {
	act := &countingActuator{supported: map[model.Action]bool{model.ActionRotate: true}}
	w := BuildWitness(context.Background(), BuildIndex(nil, nil, nil), nil, nil, act)
	cover := []string{"fact"}
	web := supportView("web-0")

	// The ActionsSupported status reviews every enabled action on every Pod first.
	for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
		w.CapableAndAuthorized(web, a)
	}
	reviewed := act.probes()
	if reviewed != 2 {
		t.Fatalf("status pass probed %d times, want 2", reviewed)
	}

	if r := w.EligibleObserved(web, model.ActionRotate, cover); r != nil {
		t.Fatalf("a supported action was excluded in the shadow: %+v", r)
	}
	r := w.EligibleObserved(web, model.ActionQuarantine, cover)
	if r == nil || !r.Excluded || r.Kind != ReasonCapability || r.Detail != "probe refused quarantine on web-0" {
		t.Fatalf("the shadow did not repeat the recorded refusal: %+v", r)
	}
	if act.probes() != reviewed {
		t.Fatalf("the shadow probed the workload: %d calls after the reviews' %d", act.probes(), reviewed)
	}

	// A question nobody asked is excluded, never asked by the shadow.
	r = w.EligibleObserved(supportView("web-1"), model.ActionRotate, cover)
	if r == nil || !r.Excluded || r.Kind != ReasonCapability || !strings.HasPrefix(r.Detail, SupportUnobserved+": ") {
		t.Fatalf("an unasked question was answered: %+v", r)
	}
	relabelled := supportView("web-0")
	relabelled.Pod.Labels = map[string]string{"app": "db"}
	if r := w.EligibleObserved(relabelled, model.ActionRotate, cover); r == nil || !strings.HasPrefix(r.Detail, SupportUnobserved+": ") {
		t.Fatalf("an answer about another target was reused: %+v", r)
	}
	if act.probes() != reviewed {
		t.Fatalf("the shadow probed the workload: %d calls after the reviews' %d", act.probes(), reviewed)
	}

	// The real gate still asks, as before, and its answer is what a later shadow reads.
	act.supported[model.ActionQuarantine] = true
	if r := w.Eligible(web, model.ActionQuarantine, cover); r != nil {
		t.Fatalf("the real gate did not ask the actuator again: %+v", r)
	}
	if act.probes() != reviewed+1 {
		t.Fatalf("the real gate probed %d times, want 1", act.probes()-reviewed)
	}
	if r := w.EligibleObserved(web, model.ActionQuarantine, cover); r != nil {
		t.Fatalf("the shadow did not read the latest review: %+v", r)
	}

	// Each tick builds its own witness, and with it its own answers.
	next := BuildWitness(context.Background(), BuildIndex(nil, nil, nil), nil, nil, act)
	if r := next.EligibleObserved(web, model.ActionRotate, cover); r == nil || !strings.HasPrefix(r.Detail, SupportUnobserved+": ") {
		t.Fatalf("a previous tick's answer was reused: %+v", r)
	}
}
