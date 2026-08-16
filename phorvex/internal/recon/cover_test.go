/*
 * Phorvex — regression gate: every DEFENSIVE actuator must carry a non-empty cover set on the asset
 * it defends, otherwise the submodular optimizer (gain = marginal·prov − λ·ECost) can never select it.
 * debugger + custom-inject are MANUAL-BY-DESIGN (no cover) and are intentionally NOT asserted here.
 */

package recon

import (
	"os"
	"strings"
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
		model.ActionModelShardReplace, model.ActionKVMigrateInvalidate, model.ActionAdapterRotate,
	} {
		if len(ac[a]) == 0 {
			t.Errorf("AI serving pod: %q has EMPTY cover set — optimizer can never select it", a)
		}
	}

	// [PHVX-26a] warm-swap and mig-rebind were removed from the list above ON PURPOSE, and the
	// obvious "fix" for this test is to put them back — which would restore exactly the false grants
	// the split removed. That is the trap PHVX-9e fell into, so both are asserted explicitly:
	//
	//   warm-swap  — covers NOTHING until required podAntiAffinity excludes the old node. Without it
	//                the scheduler may re-place the shadow on the same device, so "may relocate"
	//                cannot back a binary grant. Both facts stay audit-only.
	//   mig-rebind — covers gpuContentionChannel ONLY, and only on a pod that has a MIG device.
	//                It never covers gpuColocation: repartitioning severs the contention path
	//                without moving the pod, so co-residency knowledge survives.
	if got := ac[model.ActionWarmSwap]; len(got) != 0 {
		t.Errorf("warm-swap must have NO cover until anti-affinity lands (PHVX-26a); got %v", got)
	}
	if got := ac[model.ActionMIGRebind]; len(got) != 0 {
		t.Errorf("mig-rebind must have no cover on a pod with no MIG device; got %v", got)
	}

	// The same pod WITH a MIG device: mig-rebind gets exactly the contention channel, nothing else.
	migPod := &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "llm", HasGPU: true, ModelID: "m", SuspectAdapter: "evil",
		MIGDevice: "MIG-abc",
	}}
	mc := prof.AssetFacts(migPod, fctx)
	byKey := map[string]string{}
	for _, f := range mc.Facts {
		byKey[f.Key()] = f.Kind
	}
	got := mc.CoverByAction[model.ActionMIGRebind]
	if len(got) != 1 || byKey[got[0]] != FactGPUContentionChannel {
		kinds := []string{}
		for _, k := range got {
			kinds = append(kinds, byKey[k])
		}
		t.Errorf("mig-rebind on a MIG-capable pod must cover exactly {%s}; got %v",
			FactGPUContentionChannel, kinds)
	}
	if len(mc.CoverByAction[model.ActionWarmSwap]) != 0 {
		t.Errorf("warm-swap must stay coverless even on MIG-capable hardware (PHVX-26a); got %v",
			mc.CoverByAction[model.ActionWarmSwap])
	}

	// debugger + custom-inject are manual-by-design: assert they DO stay coverless (documents intent).
	for _, a := range []model.Action{model.ActionDebugger, model.ActionCustomInject} {
		if len(gc[a]) != 0 || len(ac[a]) != 0 {
			t.Errorf("%q is manual-by-design and must have NO cover set (got some)", a)
		}
	}
}

// TestActionDocCommentsDoNotClaimUnearnedEffects binds the model/types.go doc comments to what the
// handlers actually do (PHVX-9e). The comments there described identity-rotate as rotating the
// "SA-token/IP" and route-rotate as repointing the "Service selector / EndpointSlice". Neither is
// true — both write a single label — and it is those false descriptions that justified the recon
// cover grants this ticket removed. Correcting handlers_k8s.go while leaving model/types.go saying
// the opposite is how a disproven claim survives a fix.
func TestActionDocCommentsDoNotClaimUnearnedEffects(t *testing.T) {
	src, err := os.ReadFile("../model/types.go")
	if err != nil {
		t.Fatalf("read model/types.go: %v", err)
	}
	text := string(src)
	for _, banned := range []struct{ phrase, why string }{
		{"SA-token/IP", "identity-rotate does not change the SA token, the UID or the IP"},
		{"repoints Service selector", "route-rotate writes a label; endpoint-rotate is what re-keys a Service"},
	} {
		if strings.Contains(text, banned.phrase) {
			t.Errorf("model/types.go still claims %q — %s", banned.phrase, banned.why)
		}
	}
	// And the positive half: the corrected text must actually say what the action does.
	for _, required := range []string{"identity-epoch", "route-epoch"} {
		if !strings.Contains(text, required) {
			t.Errorf("model/types.go no longer names the %q label the action really writes", required)
		}
	}
}
