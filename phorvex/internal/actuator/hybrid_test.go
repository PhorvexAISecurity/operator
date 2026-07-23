package actuator

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// TestHybridRouting pins the capability split: whatever Phoenix can enact (RuleTypeFor != "")
// must route to Phoenix so the AMTD-CR path is preserved; everything else (the AI-native
// moves) must route to native. This mirrors HybridActuator.Actuate's branch exactly, so a
// change to RuleTypeFor that silently steals an action from native fails here.
func TestHybridRouting(t *testing.T) {
	cases := []struct {
		action    model.Action
		wantSide  string // "phoenix" | "native"
	}{
		{model.ActionRotate, "phoenix"},
		{model.ActionQuarantine, "phoenix"},
		{model.ActionKVReset, "native"},
		{model.ActionEndpointRotate, "native"},
		{model.ActionModelShardReplace, "native"},
		{model.ActionWarmSwap, "native"},
		{model.ActionMIGRebind, "native"},
	}
	for _, c := range cases {
		side := "native"
		if RuleTypeFor(c.action) != "" {
			side = "phoenix"
		}
		if side != c.wantSide {
			t.Errorf("action %q routed to %s, want %s", c.action, side, c.wantSide)
		}
	}
}

// TestHybridSatisfiesActuator is a belt-and-braces runtime check alongside the compile-time
// guard, and confirms the composite reports its own name (not a sub-actuator's).
func TestHybridSatisfiesActuator(t *testing.T) {
	var a Actuator = NewHybridActuator(nil)
	if a.Name() != "hybrid" {
		t.Fatalf("Name()=%q, want hybrid", a.Name())
	}
}
