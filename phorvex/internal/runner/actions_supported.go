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
	labelWarmRole                        = "phorvex.ai/role"
	labelModelLoaded                     = "phorvex.ai/model-loaded"
	labelLoRAEnabled                     = "phorvex.ai/lora-enabled"
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
	hasAI, hasMIG, servingEndpoint, loraEnabled := false, false, false, false
	guardrailVariants, routeService := false, false
	warmSwapPool, modelShardPool := false, false
	for _, view := range views {
		pod := &view.Pod
		if pod.HasGPU || pod.ModelID != "" {
			hasAI = true
		}
		if pod.MIGDevice != "" {
			hasMIG = true
		}
		if pod.ServingEndpointReady {
			servingEndpoint = true
		}
		if strings.EqualFold(pod.Labels[labelLoRAEnabled], "true") {
			loraEnabled = true
		}
		if pod.GuardrailVariants >= 2 {
			guardrailVariants = true
		}
		if pod.RouteService != "" {
			routeService = true
		}
		promotableShadow := pod.Ready && pod.Labels[labelWarmRole] == warmShadowRole &&
			(strings.EqualFold(pod.Labels[labelModelLoaded], "true") || pod.ServingEndpointReady)
		if promotableShadow && pod.Labels[labelSwapGroup] != "" {
			warmSwapPool = true
		}
		if promotableShadow && (pod.Labels[labelModelShard] != "" || pod.Labels[labelParallelGroup] != "") {
			modelShardPool = true
		}
	}

	schedulableGPUNodes := 0
	for _, node := range snap.Nodes {
		if node.Schedulable && (node.AllocatableGPU > 0 || len(node.MIGResources) > 0) {
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
			if !hasMIG {
				unsupported = append(unsupported, unsupportedAction{action, "no selected pod has a MIG device"})
			}
		case model.ActionWarmSwap:
			if reason := warmPoolReason(warmSwapPool, schedulableGPUNodes, "swap-group"); reason != "" {
				unsupported = append(unsupported, unsupportedAction{action, reason})
			}
		case model.ActionModelShardReplace:
			if reason := warmPoolReason(modelShardPool, schedulableGPUNodes, "model-shard/parallel-group"); reason != "" {
				unsupported = append(unsupported, unsupportedAction{action, reason})
			}
		case model.ActionKVReset, model.ActionKVMigrateInvalidate:
			if !servingEndpoint {
				unsupported = append(unsupported, unsupportedAction{action, "no selected pod has a Ready serving endpoint"})
			}
		case model.ActionAdapterRotate:
			if !loraEnabled {
				unsupported = append(unsupported, unsupportedAction{action, "no selected pod is labeled phorvex.ai/lora-enabled=true"})
			}
		case model.ActionGuardrailRotate:
			if !guardrailVariants {
				unsupported = append(unsupported, unsupportedAction{action, "no selected pod declares at least 2 distinct guardrail variants"})
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
