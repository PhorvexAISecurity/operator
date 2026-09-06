/*
 * Phorvex — operator-facing dynamic capability status for enabled actions.
 */

package runner

import (
	"fmt"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	ConditionActionsSupported            = "ActionsSupported"
	DefaultActionsSupportedDebounceTicks = 3
	actionsSupportedReason               = "AllEnabledActionsSupported"
	actionsUnsupportedReason             = "UnsupportedActionsEnabled"
	actionsSupportedDegradedReason       = "Degraded"
)

type unsupportedAction struct {
	action model.Action
	reason string
}

type actionsSupportStatus struct {
	status  metav1.ConditionStatus
	reason  string
	message string
}

// unsupportedEnabledActions returns the enabled AI-capability actions that NO selected
// pod can serve (T1-E, the M-20 fix). Honest-∃: an action is unsupported iff ZERO pods
// are FULLY eligible for it — the per-pod capability conjunction via the shared witness
// (the same predicate the generator's gate uses, so the two cannot drift). This replaces
// the old fleet-wide OR of INDEPENDENT predicates, which called an action supported when
// no single pod satisfied all its requirements (the smeared conjunction: pod A's GPU +
// pod B's serving endpoint ⇒ kv-reset "supported" though neither pod has both). Normal
// fleet heterogeneity stays quiet; the condition flips only when nobody can serve, and
// per-pod gaps live in the message, never the flip (∀-strict would be alert-fatigue).
func unsupportedEnabledActions(pol model.Policy, views []*model.WorkloadView, wit capability.Witness) []unsupportedAction {
	var unsupported []unsupportedAction
	for action, enabled := range pol.EnabledActions {
		if !enabled || !capability.AICapabilityActions[action] {
			continue
		}
		eligibleSomewhere, firstWhy := false, ""
		for _, v := range views {
			ok, why := wit.Capable(v, action)
			if ok {
				eligibleSomewhere = true
				break
			}
			if firstWhy == "" && why != "" {
				firstWhy = why
			}
		}
		if !eligibleSomewhere {
			if firstWhy == "" {
				firstWhy = "no selected pod is eligible"
			}
			unsupported = append(unsupported, unsupportedAction{action, firstWhy})
		}
	}
	sort.Slice(unsupported, func(i, j int) bool { return unsupported[i].action < unsupported[j].action })
	return unsupported
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
