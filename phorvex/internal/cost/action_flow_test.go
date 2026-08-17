package cost

import (
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestEveryMutatingActionHasExplicitFlowFamily(t *testing.T) {
	for _, action := range model.MutatingActions {
		family := flowFamilyForAction(action)
		if family == flowUnknown || family == flowNone {
			t.Errorf("mutating action %q has no explicit flow-cost family", action)
		}
	}
}

func TestActionFlowFamiliesUseSeparateShapes(t *testing.T) {
	c := NewP1Cost()
	view := bareView()
	view.Phase = model.PhaseWarm
	pol := model.Policy{FlowDisruption: 1}

	tests := []struct {
		name    string
		actions []model.Action
		want    float64
	}{
		{name: "respawn", actions: []model.Action{model.ActionRotate, model.ActionMIGRebind}, want: 0.70},
		{name: "quarantine", actions: []model.Action{model.ActionQuarantine}, want: 0.25},
		{name: "cutover", actions: []model.Action{
			model.ActionWarmSwap, model.ActionModelShardReplace,
			model.ActionEndpointRotate, model.ActionRequestDrain,
		}, want: estimatedCutoverBase},
		{name: "kv-reset-measured", actions: []model.Action{
			model.ActionKVReset,
		}, want: measuredKVResetTTFTPenaltyFraction},
		{name: "serving-state", actions: []model.Action{
			model.ActionKVMigrateInvalidate, model.ActionAdapterRotate, model.ActionGuardrailRotate,
		}, want: estimatedServingStateBase},
		{name: "lightweight", actions: []model.Action{
			model.ActionIdentityRotate, model.ActionRouteRotate,
			model.ActionDebugger, model.ActionCustomInject,
		}, want: estimatedLightweightFlow},
	}

	for _, tc := range tests {
		for _, action := range tc.actions {
			if got := c.ECost(view, model.Move{Action: action}, pol); math.Abs(got-tc.want) > eps {
				t.Errorf("%s action %q cost = %.6f, want %.6f", tc.name, action, got, tc.want)
			}
		}
	}
}

func TestRotationObservationOnlyRepricesRespawnFamily(t *testing.T) {
	c := NewP1Cost()
	view := bareView()
	view.Phase = model.PhaseWarm
	pol := model.Policy{FlowDisruption: 1}

	before := make(map[model.Action]float64, len(model.MutatingActions))
	for _, action := range model.MutatingActions {
		before[action] = c.ECost(view, model.Move{Action: action}, pol)
	}
	c.ObserveRotation(view, 1.9)

	for _, action := range model.MutatingActions {
		after := c.ECost(view, model.Move{Action: action}, pol)
		changed := math.Abs(after-before[action]) > eps
		wantChanged := flowFamilyForAction(action) == flowRespawn
		if changed != wantChanged {
			t.Errorf("action %q changed=%v after a rotation observation; want changed=%v (%.6f -> %.6f)",
				action, changed, wantChanged, before[action], after)
		}
	}
}

func TestCutoverAndUnmeasuredServingStateEstimatesRespondOnlyToBoundedServingLoad(t *testing.T) {
	c := NewP1Cost()
	view := bareView()
	view.Phase = model.PhaseColdStarting // must not leak the respawn phase prior
	view.Pod.HasGPU = true               // must not leak the respawn GPU prior
	view.Telemetry = model.Telemetry{Present: true, ReqRate: 1e9, ConnCount: 1e9}
	pol := model.Policy{FlowDisruption: 1}

	if got, want := c.ECost(view, model.Move{Action: model.ActionWarmSwap}, pol),
		estimatedCutoverBase+estimatedCutoverLoadSpan; math.Abs(got-want) > eps {
		t.Errorf("loaded warm-swap cost = %.6f, want bounded cutover estimate %.6f", got, want)
	}
	if got, want := c.ECost(view, model.Move{Action: model.ActionKVMigrateInvalidate}, pol),
		estimatedServingStateBase+estimatedServingLoadSpan; math.Abs(got-want) > eps {
		t.Errorf("loaded unmeasured serving-state cost = %.6f, want bounded estimate %.6f", got, want)
	}
	if got := c.ECost(view, model.Move{Action: model.ActionRequestDrain}, pol); got > 0.25+eps {
		t.Errorf("request-drain count pressure escaped its own bounded cutover model: %.6f", got)
	}
}

func TestKVResetUsesMeasuredTTFTPenaltyNotServingLoadEstimate(t *testing.T) {
	c := NewP1Cost()
	pol := model.Policy{FlowDisruption: 1}
	idle := bareView()
	loaded := bareView()
	loaded.Telemetry = model.Telemetry{Present: true, ReqRate: 1e9, ConnCount: 1e9}
	move := model.Move{Action: model.ActionKVReset}

	want := (measuredKVResetPostResetTTFTMilliseconds - measuredKVResetCachedTTFTMilliseconds) /
		measuredKVResetPostResetTTFTMilliseconds
	if got := c.ECost(idle, move, pol); math.Abs(got-want) > eps {
		t.Fatalf("idle kv-reset C_flow = %.12f, want measured penalty fraction %.12f", got, want)
	}
	if got := c.ECost(loaded, move, pol); math.Abs(got-want) > eps {
		t.Fatalf("loaded kv-reset C_flow = %.12f, want same measured value %.12f; do not extrapolate an unmeasured load curve", got, want)
	}
}

func TestUnknownActionUsesConservativeMaximumFlowCost(t *testing.T) {
	c := NewP1Cost()
	pol := model.Policy{FlowDisruption: 1}
	if got := c.ECost(bareView(), model.Move{Action: model.Action("future-unclassified-action")}, pol); got != unknownActionFlowMax {
		t.Fatalf("unclassified action cost = %.6f, want conservative maximum %.6f", got, unknownActionFlowMax)
	}
}
