package recon

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
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
}

type coverArchetype struct {
	name string
	view *model.WorkloadView
	fctx FactContext
}

// coverArchetypes derives the boolean product of every workload predicate that gates fact emission
// or cover today. It is generated rather than hand-listed: HasGPU, ModelID, Stateful,
// SuspectAdapter, MIGDevice and RouteService exercise the production branches.
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
							pod.ServingEndpointReady = gpu || stateful || modelServer
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
