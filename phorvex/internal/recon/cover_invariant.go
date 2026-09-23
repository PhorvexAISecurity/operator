/*
 * Phorvex — startup guard for the block-disjoint recon-cover invariant.
 */

package recon

import (
	"fmt"
	"sort"
	"strings"

	"github.com/phorvex/phorvex/internal/model"
)

type coverInvariantProbe struct {
	view *model.WorkloadView
	ctx  FactContext
}

// ValidateRegistryCoverKeys checks every registered profile before the tick loop starts.
// A cover key owned by pod block "ns/pod" must start with "pod|ns/pod|"; this makes it
// impossible for two pod blocks to share a key regardless of the live fleet topology.
func ValidateRegistryCoverKeys() error {
	return validateCoverKeys(Registry.All(), coverInvariantProbes())
}

func validateCoverKeys(profiles []ReconProfile, probes []coverInvariantProbe) error {
	for _, profile := range profiles {
		for _, probe := range probes {
			owner := probe.view.Pod.Namespace + "/" + probe.view.Pod.Name
			af := profile.AssetFacts(probe.view, probe.ctx)
			actions := make([]model.Action, 0, len(af.CoverByAction))
			for action := range af.CoverByAction {
				actions = append(actions, action)
			}
			sort.Slice(actions, func(i, j int) bool { return actions[i] < actions[j] })
			for _, action := range actions {
				for _, key := range af.CoverByAction[action] {
					if !strings.HasPrefix(key, string(ScopePod)+"|"+owner+"|") {
						return fmt.Errorf("profile %q view %q action %q emits cover key %q outside owning block %q",
							profile.Name(), owner, action, key, owner)
					}
				}
			}
		}
	}
	return nil
}

// coverInvariantProbes are fleet-independent branch probes, not a sample of the live
// fleet. Together they activate generic, stateful, model-only, GPU/MIG, lateral-edge,
// and suspect-adapter cover paths in the built-in profiles.
func coverInvariantProbes() []coverInvariantProbe {
	probe := func(name string, pod model.Pod, ctx FactContext) coverInvariantProbe {
		pod.Namespace = "cover-invariant"
		pod.Name = name
		if pod.SuspectAdapter != "" {
			pod.UID = "cover-invariant-" + name
			pod.AdapterObservation = &model.AdapterObservation{EventName: "probe-detector", EventUID: "probe-event",
				CreatorIdentity: "system:serviceaccount:cover-invariant:detector", TargetPodUID: pod.UID, AdapterName: pod.SuspectAdapter}
		}
		pod.Node = "shared-node"
		pod.Labels = map[string]string{"app": "cover-invariant"}
		ctx.AssetValue = 1
		ctx.PHold = 1
		ctx.StageUrgency = 1
		ctx.LateralUrgency = 1
		ctx.Neighbors = []NeighborRef{{Key: "cover-invariant/neighbor", Value: 1}}
		return coverInvariantProbe{
			view: &model.WorkloadView{Pod: pod, Physics: model.NeutralPhysics()},
			ctx:  ctx,
		}
	}

	return []coverInvariantProbe{
		probe("generic", model.Pod{}, FactContext{}),
		probe("stateful", model.Pod{Stateful: true, ServingEndpointReady: true}, FactContext{Stateful: true}),
		probe("model", model.Pod{ModelID: "shared-model", ServingEndpointReady: true}, FactContext{}),
		probe("gpu", model.Pod{HasGPU: true, MIGDevice: "1g.10gb", ModelID: "shared-model", SuspectAdapter: "suspect", ServingEndpointReady: true}, FactContext{HasGPU: true}),
		probe("api-token", model.Pod{UID: "api-uid", PodResourceVersion: "10", ServiceAccount: "reader",
			PodBoundKubeAPIAuth: &model.PodBoundKubeAPIAuthProjection{PodUID: "api-uid", PodResourceVersion: "10",
				ServiceAccountName: "reader", ServiceAccountUID: "sa-uid", VolumeName: "api-token", MountedContainer: "api",
				AudienceSource: "kube-apiserver-default", EvidenceSource: "admitted-pod-and-serviceaccount"}}, FactContext{}),
	}
}
