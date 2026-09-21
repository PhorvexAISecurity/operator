/*
 * Phorvex — regression gate: only actuators with supported invalidation effects receive cover.
 * Cover-free actuators remain unavailable to the coverage optimizer until their effects are proven.
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

	// (1) generic pod — rotate and quarantine have supported invalidation effects.
	generic := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "web"}}
	genericFacts := prof.AssetFacts(generic, fctx)
	gc := genericFacts.CoverByAction
	for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
		if len(gc[a]) == 0 {
			t.Errorf("generic pod: %q has EMPTY cover set — optimizer can never select it", a)
		}
	}
	genericByKey := map[string]string{}
	for _, fact := range genericFacts.Facts {
		genericByKey[fact.Key()] = fact.Kind
	}
	routeCover := gc[model.ActionRouteRotate]
	if len(routeCover) != 0 {
		t.Errorf("route-rotate cover = %v, want empty because selector membership retains Pod and Service locators", routeCover)
	}
	quarantineCover := gc[model.ActionQuarantine]
	networkCovered := false
	for _, key := range quarantineCover {
		networkCovered = networkCovered || genericByKey[key] == FactNetworkIdentity
	}
	if !networkCovered {
		t.Errorf("quarantine cover = %v, missing %s positive control", quarantineCover, FactNetworkIdentity)
	}

	// (1b) identity-rotate remains coverless. It writes an inert identity-epoch label and
	// changes neither the projected ServiceAccount token nor the pod UID/IP. route-rotate
	// is likewise coverless because its real Service-selector restitch retains both Pod
	// and stable Service locators.
	if got := gc[model.ActionIdentityRotate]; len(got) != 0 {
		t.Errorf("identity-rotate claims cover %v, but it changes no identity or credential fact", got)
	}

	// (2) AI serving pod — preserve the existing grants for these serving actuators.
	// model-shard-replace is withheld pending loaded-identity/effect evidence (M-037).
	ai := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "llm", HasGPU: true, ModelID: "m", SuspectAdapter: "evil", ServingEndpointReady: true}}
	detectorAdapter(&ai.Pod, "evil")
	ac := prof.AssetFacts(ai, fctx).CoverByAction
	for _, a := range []model.Action{
		model.ActionRequestDrain, model.ActionGuardrailRotate, model.ActionKVReset,
		model.ActionKVMigrateInvalidate, model.ActionAdapterRotate,
	} {
		if len(ac[a]) == 0 {
			t.Errorf("AI serving pod: %q has EMPTY cover set — optimizer can never select it", a)
		}
	}

	if got := ac[model.ActionEndpointRotate]; len(got) != 0 {
		t.Errorf("endpoint-rotate must have no cover without locator invalidation proof; got %v", got)
	}

	if got := ac[model.ActionModelShardReplace]; len(got) != 0 {
		t.Errorf("model-shard-replace must have no cover without identity/effect evidence; got %v", got)
	}

	// An ordinary AI pod has no verified scalar pool witness, so warm-swap remains coverless.
	if got := ac[model.ActionWarmSwap]; len(got) != 0 {
		t.Errorf("warm-swap must have no cover without a verified scalar pool; got %v", got)
	}
	if got := ac[model.ActionMIGRebind]; len(got) != 0 {
		t.Errorf("mig-rebind must have no cover on a pod with no MIG device; got %v", got)
	}

	// The same pod WITH a MIG device: mig-rebind gets exactly the contention channel, nothing else.
	migPod := &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "llm", HasGPU: true, ModelID: "m", SuspectAdapter: "evil",
		MIGDevice: "MIG-abc",
	}}
	detectorAdapter(&migPod.Pod, "evil")
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
		t.Errorf("warm-swap must stay coverless without a verified pool even on MIG hardware; got %v",
			mc.CoverByAction[model.ActionWarmSwap])
	}

	pool := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "leader", HasGPU: true,
		ModelID: "m", WarmPoolConfigured: true, WarmPoolOwnerUID: "rs-uid", RouteService: "infer",
		Labels: map[string]string{"phorvex.ai/role": "leader", "phorvex.ai/swap-group": "g"}}}
	pf := prof.AssetFacts(pool, fctx)
	kinds := map[string]string{}
	for _, f := range pf.Facts {
		kinds[f.Key()] = f.Kind
	}
	gotKinds := map[string]bool{}
	for _, key := range pf.CoverByAction[model.ActionWarmSwap] {
		gotKinds[kinds[key]] = true
	}
	wantKinds := map[string]bool{FactPodIdentity: true, FactInMemory: true, FactSession: true}
	if len(gotKinds) != len(wantKinds) {
		t.Fatalf("configured warm-swap cover kinds = %v, want %v", gotKinds, wantKinds)
	}
	for kind := range wantKinds {
		if !gotKinds[kind] {
			t.Errorf("configured warm-swap missing %s: %v", kind, gotKinds)
		}
	}
	for _, forbidden := range []string{FactGPUColocation, FactGPUContentionChannel, FactNetworkIdentity, FactModelFingerprint, FactEndpointPath} {
		if gotKinds[forbidden] {
			t.Errorf("configured warm-swap unsoundly covers %s", forbidden)
		}
	}
	for name, mutate := range map[string]func(*model.Pod){
		"unverified-pool": func(p *model.Pod) { p.WarmPoolConfigured = false },
		"missing-owner":   func(p *model.Pod) { p.WarmPoolOwnerUID = "" },
		"missing-route":   func(p *model.Pod) { p.RouteService = "" },
		"missing-group":   func(p *model.Pod) { delete(p.Labels, "phorvex.ai/swap-group") },
		"warm-shadow":     func(p *model.Pod) { p.Labels["phorvex.ai/role"] = "warm-shadow" },
		"non-ai":          func(p *model.Pod) { p.HasGPU, p.ModelID = false, "" },
	} {
		candidate := pool.Pod
		candidate.Labels = map[string]string{}
		for k, v := range pool.Pod.Labels {
			candidate.Labels[k] = v
		}
		mutate(&candidate)
		if got := prof.AssetFacts(&model.WorkloadView{Pod: candidate}, fctx).CoverByAction[model.ActionWarmSwap]; len(got) != 0 {
			t.Errorf("%s target must not receive warm-swap cover: %v", name, got)
		}
	}

	// debugger + custom-inject are manual-by-design: assert they DO stay coverless (documents intent).
	for _, a := range []model.Action{model.ActionDebugger, model.ActionCustomInject} {
		if len(gc[a]) != 0 || len(ac[a]) != 0 {
			t.Errorf("%q is manual-by-design and must have NO cover set (got some)", a)
		}
	}
}

// TestActionDocCommentsDoNotClaimUnearnedEffects binds the model/types.go doc comments to what the
// handlers actually do. identity-rotate must never claim token/UID/IP invalidation, while
// route-rotate may claim only its implemented Service-selector membership restitch.
func TestActionDocCommentsDoNotClaimUnearnedEffects(t *testing.T) {
	src, err := os.ReadFile("../model/types.go")
	if err != nil {
		t.Fatalf("read model/types.go: %v", err)
	}
	text := string(src)
	for _, banned := range []struct{ phrase, why string }{
		{"SA-token/IP", "identity-rotate does not change the SA token, the UID or the IP"},
		{"SA-token re-issue", "identity-rotate does not re-issue a projected ServiceAccount token"},
	} {
		if strings.Contains(text, banned.phrase) {
			t.Errorf("model/types.go still claims %q — %s", banned.phrase, banned.why)
		}
	}
	// And the positive half: the corrected text must actually say what the action does.
	for _, required := range []string{"identity-epoch", "route-key", "route-service"} {
		if !strings.Contains(text, required) {
			t.Errorf("model/types.go no longer names the %q contract the action uses", required)
		}
	}

	handlerSrc, err := os.ReadFile("../actuator/handlers_k8s.go")
	if err != nil {
		t.Fatalf("read actuator/handlers_k8s.go: %v", err)
	}
	handlerText := string(handlerSrc)
	for _, falseClaim := range []string{"SA-token re-issue best-effort", "label-stale the attacker's identity recon"} {
		if strings.Contains(handlerText, falseClaim) {
			t.Errorf("identity-rotate handler still claims %q", falseClaim)
		}
	}
}
