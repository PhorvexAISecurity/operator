/*
 * Phorvex — regression gate: every DEFENSIVE actuator must carry a non-empty cover set on the asset
 * it defends, otherwise the submodular optimizer (gain = marginal·prov − λ·ECost) can never select it.
 * debugger + custom-inject are MANUAL-BY-DESIGN (no cover) and are intentionally NOT asserted here.
 */

package recon

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestDefensiveActuatorsHaveCover(t *testing.T) {
	// ucw-recon is the runtime default the runner installs (SetDefault at manager.go); use it directly
	// since the runner's init doesn't run in this package test.
	prof := ucwRecon{}
	// FactContext mirrors the pod's GPU/stateful nature (the runtime sets HasGPU from view.Pod.HasGPU);
	// kv-reset's cover is gated on it.
	fctx := FactContext{AssetValue: 1, PHold: 1, StageUrgency: 1, LateralUrgency: 1, HasGPU: true,
		Neighbors: []NeighborRef{{Key: "ns/neighbor", Value: 1}}}

	// (1) generic pod — identity-rotate + route-rotate are the gentle subsets of rotate/quarantine.
	generic := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "web"}}
	gc := prof.AssetFacts(generic, fctx).CoverByAction
	for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine, model.ActionIdentityRotate, model.ActionRouteRotate} {
		if len(gc[a]) == 0 {
			t.Errorf("generic pod: %q has EMPTY cover set — optimizer can never select it", a)
		}
	}

	// (2) AI serving pod — the serving actuators become selectable (request-drain / guardrail-rotate /
	//     kv-reset / endpoint-rotate / model-shard-replace / mig-rebind / warm-swap / kv-migrate-invalidate).
	ai := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "llm", HasGPU: true, ModelID: "m", SuspectAdapter: "evil"}}
	ac := prof.AssetFacts(ai, fctx).CoverByAction
	for _, a := range []model.Action{
		model.ActionRequestDrain, model.ActionGuardrailRotate, model.ActionKVReset, model.ActionEndpointRotate,
		model.ActionModelShardReplace, model.ActionMIGRebind, model.ActionWarmSwap, model.ActionKVMigrateInvalidate,
		model.ActionAdapterRotate,
	} {
		if len(ac[a]) == 0 {
			t.Errorf("AI serving pod: %q has EMPTY cover set — optimizer can never select it", a)
		}
	}

	// debugger + custom-inject are manual-by-design: assert they DO stay coverless (documents intent).
	for _, a := range []model.Action{model.ActionDebugger, model.ActionCustomInject} {
		if len(gc[a]) != 0 || len(ac[a]) != 0 {
			t.Errorf("%q is manual-by-design and must have NO cover set (got some)", a)
		}
	}
}
