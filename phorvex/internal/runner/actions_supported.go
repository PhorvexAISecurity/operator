/*
 * Phorvex — operator-facing dynamic capability status for enabled actions.
 */

package runner

import (
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	ConditionActionsSupported            = "ActionsSupported"
	DefaultActionsSupportedDebounceTicks = 3
	actionsSupportedReason               = "AllEnabledActionsSupported"
	actionsUnsupportedReason             = "UnsupportedActionsEnabled"
	actionsSupportedDegradedReason       = "Degraded"
	labelSwapGroup                       = "phorvex.ai/swap-group"
	labelModelShard                      = "phorvex.ai/model-shard"
	labelParallelGroup                   = "phorvex.ai/parallel-group"
	labelRank                            = "phorvex.ai/rank"
	labelWarmRole                        = "phorvex.ai/role"
	labelModelLoaded                     = "phorvex.ai/model-loaded"
	labelLoRAEnabled                     = "phorvex.ai/lora-enabled"
	labelGuardrailTier                   = "phorvex.ai/guardrail-tier"
	labelServing                         = "phorvex.ai/serving"
	warmShadowRole                       = "warm-shadow"
)

var aiCapabilityActions = map[model.Action]bool{
	model.ActionWarmSwap: true, model.ActionMIGRebind: true,
	model.ActionKVReset: true, model.ActionEndpointRotate: true,
	model.ActionModelShardReplace: true, model.ActionAdapterRotate: true,
	model.ActionRequestDrain: true, model.ActionGuardrailRotate: true,
	model.ActionKVMigrateInvalidate: true,
}

type unsupportedAction struct {
	action model.Action
	reason string
}

type actionsSupportStatus struct {
	status  metav1.ConditionStatus
	reason  string
	message string
}

func unsupportedEnabledActions(pol model.Policy, views []*model.WorkloadView, snap *ingest.Snapshot) []unsupportedAction {
	hasAI, migRebindConfigured, servingEndpoint, adapterTarget := false, false, false, false
	guardrailVariants, routeService := false, false
	for _, view := range views {
		pod := &view.Pod
		if pod.HasGPU || pod.ModelID != "" {
			hasAI = true
		}
		if pod.MIGDevice != "" && pod.Node != "" && pod.MIGGPUID != "" && pod.MIGTargetProfile != "" {
			migRebindConfigured = true
		}
		if pod.ServingEndpointReady {
			servingEndpoint = true
		}
		if pod.Labels[labelLoRAEnabled] == "true" && pod.SuspectAdapter != "" {
			adapterTarget = true
		}
		if pod.Labels[labelGuardrailTier] == "true" && pod.GuardrailVariants >= 2 {
			guardrailVariants = true
		}
		if pod.RouteService != "" {
			routeService = true
		}
	}
	warmSwapPool := hasMatchingWarmSwapPool(views, snap.Pods)
	modelShardPool := hasMatchingModelShardPool(views, snap.Pods)

	schedulableGPUNodes := 0
	for _, node := range snap.Nodes {
		if node.Schedulable && hasAllocatableGPU(node) {
			schedulableGPUNodes++
		}
	}
	requestDrainService := hasServingSelectorService(views, snap.Services)

	var unsupported []unsupportedAction
	for action, enabled := range pol.EnabledActions {
		if !enabled || !aiCapabilityActions[action] {
			continue
		}
		if !hasAI {
			unsupported = append(unsupported, unsupportedAction{action, "no selected pod advertises a GPU or model identity"})
			continue
		}
		switch action {
		case model.ActionMIGRebind:
			if !migRebindConfigured {
				unsupported = append(unsupported, unsupportedAction{action, "no selected pod has a MIG device, scheduled node, GPU id, and target profile"})
			}
		case model.ActionWarmSwap:
			if reason := warmPoolReason(warmSwapPool, schedulableGPUNodes, "matching swap-group"); reason != "" {
				unsupported = append(unsupported, unsupportedAction{action, reason})
			}
		case model.ActionModelShardReplace:
			if reason := warmPoolReason(modelShardPool, schedulableGPUNodes, "matching model-shard/parallel-group"); reason != "" {
				unsupported = append(unsupported, unsupportedAction{action, reason})
			}
		case model.ActionKVReset, model.ActionKVMigrateInvalidate:
			if !servingEndpoint {
				unsupported = append(unsupported, unsupportedAction{action, "no selected pod has a Ready serving endpoint"})
			}
		case model.ActionAdapterRotate:
			if !adapterTarget {
				unsupported = append(unsupported, unsupportedAction{action, "no selected pod is LoRA-enabled and names an adapter to rotate"})
			}
		case model.ActionGuardrailRotate:
			if !guardrailVariants {
				unsupported = append(unsupported, unsupportedAction{action, "no selected guardrail-tier pod declares at least 2 distinct guardrail variants"})
			}
		case model.ActionEndpointRotate:
			if !routeService {
				unsupported = append(unsupported, unsupportedAction{action, "no selected pod declares phorvex.ai/route-service"})
			}
		case model.ActionRequestDrain:
			if !requestDrainService {
				unsupported = append(unsupported, unsupportedAction{action, "no target Service selects on phorvex.ai/serving"})
			}
		}
	}
	sort.Slice(unsupported, func(i, j int) bool { return unsupported[i].action < unsupported[j].action })
	return unsupported
}

// hasMatchingWarmSwapPool mirrors the actuator's warm-swap lookup: a selected,
// non-shadow AI target must declare a swap group, and the observed namespace must
// contain a different Ready, model-loaded warm shadow in that exact group. Looking
// for an arbitrary shadow anywhere in the selected fleet can report a false positive
// even though warmCutover would fail closed for the actual target.
func hasMatchingWarmSwapPool(views []*model.WorkloadView, fleet []model.Pod) bool {
	for _, view := range views {
		target := &view.Pod
		group := target.Labels[labelSwapGroup]
		if !capabilityTarget(target) || group == "" {
			continue
		}
		if hasMatchingPromotableShadow(target, fleet, func(shadow *model.Pod) bool {
			return shadow.Labels[labelSwapGroup] == group
		}) {
			return true
		}
	}
	return false
}

// hasMatchingModelShardPool mirrors both actuator paths. An independent shard needs
// one matching promotable shadow. A tensor/pipeline-parallel target needs a valid
// parallel-size and a complete replacement group with one distinct Ready shadow rank
// per member; otherwise groupCoherentCutover fails closed without flipping anything.
func hasMatchingModelShardPool(views []*model.WorkloadView, fleet []model.Pod) bool {
	for _, view := range views {
		target := &view.Pod
		shard := target.Labels[labelModelShard]
		if !capabilityTarget(target) || shard == "" {
			continue
		}
		parallel := target.Labels[labelParallelGroup]
		if parallel != "" {
			if hasCompleteParallelShadowGroup(target, fleet, shard, parallel) {
				return true
			}
			continue
		}
		if hasMatchingPromotableShadow(target, fleet, func(shadow *model.Pod) bool {
			return shadow.Labels[labelModelShard] == shard
		}) {
			return true
		}
	}
	return false
}

func hasCompleteParallelShadowGroup(target *model.Pod, fleet []model.Pod, shard, parallel string) bool {
	if target.ParallelSize <= 0 {
		return false
	}
	readyRanks := make(map[string]struct{}, target.ParallelSize)
	for i := range fleet {
		shadow := &fleet[i]
		rank := shadow.Labels[labelRank]
		if shadow.Namespace != target.Namespace || shadow.Name == target.Name ||
			!shadow.Ready || shadow.Labels[labelWarmRole] != warmShadowRole ||
			shadow.Labels[labelModelLoaded] != "true" || rank == "" ||
			shadow.Labels[labelModelShard] != shard || shadow.Labels[labelParallelGroup] != parallel {
			continue
		}
		readyRanks[rank] = struct{}{}
	}
	return len(readyRanks) >= target.ParallelSize
}

func capabilityTarget(pod *model.Pod) bool {
	return pod != nil && pod.Labels[labelWarmRole] != warmShadowRole &&
		(pod.HasGPU || pod.ModelID != "")
}

func hasMatchingPromotableShadow(target *model.Pod, fleet []model.Pod, samePool func(*model.Pod) bool) bool {
	for i := range fleet {
		shadow := &fleet[i]
		if shadow.Namespace != target.Namespace || shadow.Name == target.Name ||
			!shadow.Ready || shadow.Labels[labelWarmRole] != warmShadowRole ||
			shadow.Labels[labelModelLoaded] != "true" || !samePool(shadow) {
			continue
		}
		return true
	}
	return false
}

func hasAllocatableGPU(node ingest.NodeInfo) bool {
	if node.AllocatableGPU > 0 {
		return true
	}
	for _, count := range node.MIGResources {
		if count > 0 {
			return true
		}
	}
	return false
}

func warmPoolReason(pool bool, gpuNodes int, group string) string {
	var reasons []string
	if !pool {
		reasons = append(reasons, "no Ready warm shadow exists for a "+group+" pool")
	}
	if gpuNodes < 2 {
		reasons = append(reasons, fmt.Sprintf("only %d schedulable GPU node(s); need at least 2", gpuNodes))
	}
	return strings.Join(reasons, ", ")
}

func hasServingSelectorService(views []*model.WorkloadView, services []ingest.ServiceInfo) bool {
	for _, view := range views {
		pod := &view.Pod
		for _, service := range services {
			if service.Namespace != pod.Namespace || (pod.RouteService != "" && service.Name != pod.RouteService) {
				continue
			}
			if _, ok := service.Selector[labelServing]; !ok || !selectorMatches(service.Selector, pod.Labels) {
				continue
			}
			return true
		}
	}
	return false
}

func selectorMatches(selector, podLabels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		if podLabels[key] != value {
			return false
		}
	}
	return true
}

func unsupportedMessage(actions []unsupportedAction) string {
	parts := make([]string, 0, len(actions))
	for _, unsupported := range actions {
		parts = append(parts, string(unsupported.action)+": "+unsupported.reason)
	}
	return strings.Join(parts, "; ")
}

func (m *Manager) debounceActionsSupported(e *policyEntry, unsupported []unsupportedAction) actionsSupportStatus {
	threshold := m.ActionsSupportedDebounce
	if threshold <= 0 {
		threshold = DefaultActionsSupportedDebounceTicks
	}
	message := unsupportedMessage(unsupported)

	m.mu.Lock()
	entry := m.policies[e.key.String()]
	if entry == nil {
		entry = e
	}
	if len(unsupported) == 0 {
		entry.actionsUnsupportedTicks = 0
		entry.actionsUnsupportedSignature = ""
		m.mu.Unlock()
		return actionsSupportStatus{
			status: metav1.ConditionTrue, reason: actionsSupportedReason,
			message: "all enabled actions have matching capabilities in the selected fleet",
		}
	}
	if entry.actionsUnsupportedSignature == message {
		entry.actionsUnsupportedTicks++
	} else {
		entry.actionsUnsupportedSignature = message
		entry.actionsUnsupportedTicks = 1
	}
	observations := entry.actionsUnsupportedTicks
	m.mu.Unlock()

	if observations < threshold {
		return actionsSupportStatus{
			status: metav1.ConditionUnknown, reason: actionsSupportedDegradedReason,
			message: fmt.Sprintf("transient capability loss (%d/%d consecutive ticks): %s", observations, threshold, message),
		}
	}
	return actionsSupportStatus{status: metav1.ConditionFalse, reason: actionsUnsupportedReason, message: message}
}
