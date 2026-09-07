package physics

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// flow_activation_test.go — PHORVEXSEC-198 / M-115 conformance round (2026-09-06):
// having the three inputs is NOT activation. Until the ruling activates a class, the
// component is absent with a reason and enters neither the aggregate nor any fact.

func activateOnly(t *testing.T, classes ...string) {
	t.Helper()
	prev := ActivatedFlowClasses()
	t.Cleanup(func() { ConfigureFlowActivation(prev) })
	ConfigureFlowActivation(classes)
}

func vllmView(ns string) *model.WorkloadView {
	return &model.WorkloadView{
		Pod: model.Pod{Namespace: ns, Name: "p"},
		Telemetry: model.Telemetry{
			InFlightMean:   model.PresentSignal(15, "prom"),
			CompletionRate: model.PresentSignal(5, "prom"),
			MeanSojournSec: model.PresentSignal(1, "prom"),
		},
	}
}

// A class the ruling has not activated is absent WITH THE REASON, even though every input is present.
func TestUnactivatedClassIsAbsentWithReason(t *testing.T) {
	activateOnly(t) // no class active — the shipped default
	v := vllmView("vllm")
	fr := FlowResidualFor(v.Pod.Namespace, v.Telemetry)
	if fr.Present || fr.Basis != FlowBasisAbsent || fr.Reason != FlowReasonNotActivated {
		t.Fatalf("unactivated class → %+v, want absent/%s", fr, FlowReasonNotActivated)
	}
	// and it must not reach the aggregate
	for _, c := range Components(v) {
		if c.Name == "flow-littles-law" {
			if c.Present || c.Reason != FlowReasonNotActivated {
				t.Fatalf("flow component = %+v, want absent with the activation reason", c)
			}
			return
		}
	}
	t.Fatal("the flow component must still be listed, as an absent one")
}

// Activation is per class: the ruled mathematics runs for an activated class only.
func TestActivationIsPerClass(t *testing.T) {
	activateOnly(t, "vllm")
	if fr := FlowResidualFor("vllm", vllmView("vllm").Telemetry); !fr.Present || fr.Basis != FlowBasisLittle || fr.Residual != 0.5 {
		t.Fatalf("activated class → %+v, want the ruled residual 0.5", fr)
	}
	if fr := FlowResidualFor("litellm", vllmView("litellm").Telemetry); fr.Present || fr.Reason != FlowReasonNotActivated {
		t.Fatalf("a different class must stay absent: %+v", fr)
	}
	// the pure ruled function is untouched by activation (the conformance vector runs on it)
	if fr := FlowResidual(vllmView("anything").Telemetry); !fr.Present || fr.Residual != 0.5 {
		t.Fatalf("FlowResidual must remain the pure ruled mathematics: %+v", fr)
	}
}

// With no class activated, an all-absent component set aggregates to absent — no fact basis.
func TestUnactivatedFlowLeavesTheAggregateHonest(t *testing.T) {
	activateOnly(t)
	v := vllmView("vllm")
	if _, present := Aggregate(Components(v)); present {
		t.Fatal("with every component absent the aggregate must be absent, not 0")
	}
}

// The retired queue/backlog term never contributes again — not even when both of its inputs
// are present. Its formula subtracted a rate from a count, which M-115 lists as a defect
// (conformance round, 2026-09-06); absence-when-unavailable was not enough.
func TestQueueTermStaysDisabledEvenWithBothInputsPresent(t *testing.T) {
	v := &model.WorkloadView{
		Pod: model.Pod{Namespace: "vllm", Name: "p"},
		Telemetry: model.Telemetry{
			QueueDepth: model.PresentSignal(40, "prom"), // both inputs measured...
			ReqRate:    model.PresentSignal(2, "prom"),  // ...and a large backlog
		},
	}
	for _, c := range Components(v) {
		if c.Name != "queue" {
			continue
		}
		if c.Present || c.Magnitude != 0 || c.Reason != QueueReasonDisabled {
			t.Fatalf("queue component = %+v, want permanently absent with reason %q", c, QueueReasonDisabled)
		}
		if _, present := Aggregate(Components(v)); present {
			t.Fatal("a disabled component must not make the aggregate present")
		}
		return
	}
	t.Fatal("the queue component must still be listed, as a disabled one")
}
