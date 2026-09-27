package recon

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voicemcppolicy"
)

// no_identical_cover_test.go — PHVX-26 / PHORVEXSEC-120.
//
// Byte-identical non-empty cover sets make two actuators indistinguishable to
// the optimizer: only cost can choose between them, regardless of their physical
// mechanism. The exceptions below are explicit descriptions of capabilities
// that are genuinely identical today, and the second test makes each exception
// self-expiring when its cause disappears.

var knownIdenticalPairs = map[string]string{
	pairKey(model.ActionKVMigrateInvalidate, model.ActionKVReset): "remote KV migration is not built; both actions currently invalidate only local session state",
	pairKey(model.ActionRotate, model.ActionWarmSwap):             "both successful actions retire the exact old process and invalidate its identity, memory and session facts",
}

type coverArchetype struct {
	name string
	view *model.WorkloadView
	fctx FactContext
}

func boundVoiceMCPView() *model.WorkloadView {
	p := model.Pod{Namespace: "voice", Name: "voice-mcp", UID: "11111111-1111-4111-8111-111111111111",
		VoiceMCPConfigMap: "voice-mcp-tool-policy", VoiceMCPDeploymentUID: "22222222-2222-4222-8222-222222222222",
		VoiceMCPSourceSHA256: strings.Repeat("a", 64), VoiceMCPEventCreator: "system:serviceaccount:phorvex-system:console"}
	p.VoiceMCPObservation = &model.VoiceMCPObservation{EventName: "mcp-event", EventUID: "33333333-3333-4333-8333-333333333333",
		CreatorIdentity: p.VoiceMCPEventCreator, ScenarioID: "ai2-mcp-tool-poisoning", RunSHA256: strings.Repeat("b", 64),
		TargetPodUID: p.UID, DeploymentUID: p.VoiceMCPDeploymentUID, ConfigMapUID: "44444444-4444-4444-8444-444444444444",
		SourceConfigMapUID: "55555555-5555-4555-8555-555555555555", SourceSHA256: p.VoiceMCPSourceSHA256,
		ToolName: voicemcppolicy.StoreDirectory, GoodDescriptorSHA256: voicemcppolicy.StoreDirectoryGoodSHA256,
		ObservedDescriptorSHA256: strings.Repeat("c", 64), MCPServiceName: voicemcppolicy.MCPServiceName,
		MCPServiceUID: "66666666-6666-4666-8666-666666666666", MCPPodName: "mcp-server-1",
		MCPPodUID: "77777777-7777-4777-8777-777777777777", MCPDeploymentUID: "88888888-8888-4888-8888-888888888888",
		MCPConfigMapUID: "99999999-9999-4999-8999-999999999999", MCPSourceSHA256: voicemcppolicy.ReviewedMCPSourceSHA256,
		PolicyName: "voice-defense", PolicyUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", PolicyGeneration: 1}
	return &model.WorkloadView{Pod: p, Physics: model.NeutralPhysics()}
}

// coverArchetypes derives the ordinary boolean product and adds separate
// source-bound Voice MCP and warm-pool witnesses for their event/owner branches.
func coverArchetypes() []coverArchetype {
	bools := []bool{false, true}
	out := make([]coverArchetype, 0, 64)
	for _, gpu := range bools {
		for _, modelServer := range bools {
			for _, stateful := range bools {
				for _, poisoned := range bools {
					for _, mig := range bools {
						if mig && !gpu {
							continue
						}
						for _, route := range bools {
							pod := model.Pod{
								Namespace: "ns", Name: "asset", Node: "node-a",
								HasGPU: gpu, Stateful: stateful,
							}
							if modelServer {
								pod.ModelID = "model-v1"
							}
							if poisoned {
								detectorAdapter(&pod, "untrusted-lora")
							}
							if mig {
								pod.MIGDevice = "MIG-abc"
							}
							if route {
								pod.RouteService = "infer"
								pod.GuardrailVariants = 2
							}
							pod.ServingEndpointReady = modelServer
							name := fmt.Sprintf("gpu=%t/model=%t/stateful=%t/adapter=%t/mig=%t/route=%t",
								gpu, modelServer, stateful, poisoned, mig, route)
							out = append(out, coverArchetype{
								name: name,
								view: &model.WorkloadView{Pod: pod, Physics: model.NeutralPhysics()},
								fctx: FactContext{
									AssetValue: 10, PHold: 1, StageUrgency: 1, LateralUrgency: 1,
									HasGPU: gpu, Stateful: stateful,
									Neighbors: []NeighborRef{{Key: "ns/neighbor", Value: 1}},
								},
							})
						}
					}
				}
			}
		}
	}
	// A genuine verified scalar warm-pool leader exercises the conditional process-fact
	// grant without multiplying every unrelated boolean archetype.
	pod := model.Pod{Namespace: "ns", Name: "configured-pool", HasGPU: true, ModelID: "model-v1",
		WarmPoolConfigured: true, WarmPoolOwnerUID: "rs-uid", RouteService: "infer",
		Labels: map[string]string{"phorvex.ai/role": "leader", "phorvex.ai/swap-group": "g"}}
	out = append(out, coverArchetype{name: "configured-warm-pool", view: &model.WorkloadView{Pod: pod, Physics: model.NeutralPhysics()},
		fctx: FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1, LateralUrgency: 1, HasGPU: true,
			Neighbors: []NeighborRef{{Key: "ns/neighbor", Value: 1}}}})
	out = append(out, coverArchetype{name: "voice-mcp-observed", view: boundVoiceMCPView(),
		fctx: FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1, LateralUrgency: 1}})
	return out
}

func pairKey(a, b model.Action) string {
	parts := []string{string(a), string(b)}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func normalizedCover(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	copyKeys := append([]string(nil), keys...)
	sort.Strings(copyKeys)
	return strings.Join(copyKeys, "\x00")
}

func identicalCoverPairs() map[string][]string {
	found := map[string][]string{}
	for _, profile := range Registry.All() {
		for _, archetype := range coverArchetypes() {
			cover := profile.AssetFacts(archetype.view, archetype.fctx).CoverByAction
			for i, a := range model.MutatingActions {
				aKeys := normalizedCover(cover[a])
				if aKeys == "" {
					continue // empty cover is PHVX-18; manual/audit-only actions may share it
				}
				for _, b := range model.MutatingActions[i+1:] {
					if aKeys == normalizedCover(cover[b]) {
						pair := pairKey(a, b)
						where := profile.Name() + "/" + archetype.name
						found[pair] = append(found[pair], where)
					}
				}
			}
		}
	}
	return found
}

func TestNoTwoActuatorsShareIdenticalCover(t *testing.T) {
	for pair, where := range identicalCoverPairs() {
		if reason, known := knownIdenticalPairs[pair]; known {
			t.Logf("known identical cover %s (%s), observed at %s", pair, reason, strings.Join(where, ", "))
			continue
		}
		t.Errorf("actions %s share byte-identical non-empty cover at %s; split the physical erasers or explicitly document a self-expiring exception",
			pair, strings.Join(where, ", "))
	}
}

func TestKnownCoverCollisionsStillExist(t *testing.T) {
	found := identicalCoverPairs()
	for pair, reason := range knownIdenticalPairs {
		if len(found[pair]) == 0 {
			t.Errorf("exempted pair %s no longer shares cover (%s); delete it from knownIdenticalPairs so the assertion is strict again",
				pair, reason)
		}
	}
}
