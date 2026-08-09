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

	// (1) generic pod — rotate and quarantine really do invalidate recon, so they must have cover.
	generic := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "web"}}
	gc := prof.AssetFacts(generic, fctx).CoverByAction
	for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
		if len(gc[a]) == 0 {
			t.Errorf("generic pod: %q has EMPTY cover set — optimizer can never select it", a)
		}
	}

	// (1b) identity-rotate and route-rotate must have NO cover (PHVX-9e). Both write a single
	// phorvex.ai/*-epoch LABEL and nothing else: identity-rotate's SA-token branch is a no-op on
	// modern K8s, route-rotate touches no Service selector or EndpointSlice, and nothing in the repo
	// or on the live cluster selects on either label. So neither invalidates the fact it used to
	// claim. Granting cover for work an action does not do is worse than granting none: the
	// optimiser would pick the cheap relabel INSTEAD of the rotate that would really have staled the
	// attacker's recon. If either action later gains a real mechanism (a Service restitch, a genuine
	// token rotation), restore its grant IN THE SAME CHANGE.
	for _, a := range []model.Action{model.ActionIdentityRotate, model.ActionRouteRotate} {
		if len(gc[a]) != 0 {
			t.Errorf("%q claims cover %v, but it only writes an epoch label — the optimizer would be "+
				"credited for recon invalidation that never happens", a, gc[a])
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
