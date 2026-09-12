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
	ConditionActionsSupported = "ActionsSupported"
	// ConditionTelemetryDegraded is True while a telemetry SOURCE is unreachable (M-113/M-130).
	ConditionTelemetryDegraded           = "TelemetryDegraded"
	DefaultActionsSupportedDebounceTicks = 3
	actionsSupportedReason               = "AllEnabledActionsSupported"
	actionsUnsupportedReason             = "UnsupportedActionsEnabled"
	actionsSupportedDegradedReason       = "Degraded"
	// actionsNoAssetsReason marks a tick that OBSERVED NOTHING: the selector matched no
	// assets, so per-target capability was never evaluated. [M-21] It is reported Unknown
	// rather than True because "we saw nothing" is not "everything is ready" — the old
	// code returned an affirmative all-supported claim for an empty fleet, which is a
	// runtime-readiness assertion no observation supports.
	actionsNoAssetsReason = "NoSelectedAssets"
)

// actionGap is one enabled AI-capability action that is not serviceable on the WHOLE
// selected fleet (M-20): unsupported on `unsupported` of `total` pods, first failing
// predicate `why`. unsupportedEverywhere() (∃ nobody eligible, incl. an empty fleet) is
// the FLIP set — the only thing that moves the ActionsSupported condition. A PARTIAL gap
// (0 < unsupported < total) is serviceable somewhere: it never flips, but it is surfaced
// in the message with its per-asset count (the count-while-green half of the fix).
type actionGap struct {
	action      model.Action
	unsupported int
	total       int
	why         string
}

func (g actionGap) unsupportedEverywhere() bool { return g.unsupported >= g.total }

type actionsSupportStatus struct {
	status  metav1.ConditionStatus
	reason  string
	message string
}

// capabilityReport is ONE tick's capability picture for one policy: the per-action gaps
// PLUS the observation context needed to describe them truthfully. A bare gap list cannot
// distinguish "every enabled action is serviceable" from "no asset was observed at all",
// and reporting the second as the first is the readiness claim M-21 removes.
type capabilityReport struct {
	gaps []actionGap
	// observed is how many selected assets this tick actually saw.
	observed int
	// enabled is how many enabled, actionable entries were evaluated.
	enabled int
}

// capabilityGaps returns every enabled AI-capability action that is not serviceable on
// the WHOLE selected fleet, with its per-asset count (T1-E's M-20 witness, now counted).
// Honest-∃ per pod via the shared witness (the same predicate the generator's gate uses,
// so the two cannot drift) — replacing the old fleet-wide OR of INDEPENDENT predicates
// that called an action supported when no single pod satisfied all its requirements (the
// smeared conjunction: pod A's GPU + pod B's serving endpoint ⇒ kv-reset "supported"
// though neither has both). A fully-supported action (every pod eligible) yields no gap;
// a fully-unsupported one is a FLIP gap; a partial one is surfaced but does not flip.
func capabilityGaps(pol model.Policy, views []*model.WorkloadView, wit capability.Witness) capabilityReport {
	total := len(views)
	rep := capabilityReport{observed: total}
	var gaps []actionGap
	// [M-21] Enumerate the enabled actions through the SAME source of truth the generator
	// uses (model.MutatingActions filtered by model.ActionEnabled), for two reasons the
	// old `range pol.EnabledActions` got wrong:
	//   - a NIL EnabledActions map means the documented default set (rotate+quarantine),
	//     which the raw range skipped entirely, so a default policy was never evaluated;
	//   - the AICapabilityActions filter dropped every non-AI action, so a backend that
	//     cannot enact rotate, identity-rotate or debugger was never even asked about it.
	// Backend support is now part of the witness for EVERY action, so both had to go.
	for _, action := range model.MutatingActions {
		if !model.ActionEnabled(pol, action) {
			continue
		}
		rep.enabled++
		unsupported := 0
		whyCount := map[string]int{}
		for _, v := range views {
			// M-160: Capable AND authorized — the condition now reflects no-rbac gaps too,
			// not only runtime fixtures (RBAC-unknown fails open inside, never a status gap).
			if ok, why := wit.CapableAndAuthorized(v, action); !ok {
				unsupported++
				if why != "" {
					whyCount[why]++
				}
			}
		}
		// total==0 (selector matches no pods) skips here too: no assets ≠ unsupported —
		// "your policy selects nothing" is a different signal, not a capability gap (M-20).
		if unsupported == 0 {
			continue
		}
		gaps = append(gaps, actionGap{action: action, unsupported: unsupported, total: total, why: dominantWhy(whyCount)})
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].action < gaps[j].action })
	rep.gaps = gaps
	return rep
}

// dominantWhy picks the reason DETERMINISTICALLY — the mode over the unsupported assets,
// lexical-min on a tie (REQ-2). A view-order-dependent "first why" would flap per tick on
// a mixed-reason fleet, and because the flip debounce keys on the reason, a flapping why
// would keep the counter below threshold forever — the condition could never go False.
func dominantWhy(counts map[string]int) string {
	best, bestN := "no selected pod is eligible", 0
	for why, n := range counts {
		if n > bestN || (n == bestN && why < best) {
			best, bestN = why, n
		}
	}
	return best
}

// gapMessage renders gaps as "<action> unsupported on N/M assets (<why>)", the <why>
// being the witness predicate name — the SAME vocabulary the record's exclusionReason
// carries (M-20 test c), so a record and this condition never disagree.
func gapMessage(gaps []actionGap) string {
	parts := make([]string, 0, len(gaps))
	for _, g := range gaps {
		parts = append(parts, fmt.Sprintf("%s unsupported on %d/%d assets (%s)", g.action, g.unsupported, g.total, g.why))
	}
	return strings.Join(parts, "; ")
}

// flipGaps is the subset that moves the condition: an action no pod can serve (∃ nobody
// eligible). Partial gaps are excluded — they are message-only.
func flipGaps(gaps []actionGap) []actionGap {
	var flip []actionGap
	for _, g := range gaps {
		if g.unsupportedEverywhere() {
			flip = append(flip, g)
		}
	}
	return flip
}

// flipSignature is the debounce key: sorted (action, why) pairs of the FLIP set, WITHOUT
// counts. A changing fleet size (N/M) must not re-arm the transient-loss debounce while
// the same actions stay fully unsupported for the same reasons; only the flip set or its
// reasons changing resets it. (gaps arrive action-sorted from capabilityGaps.)
func flipSignature(flip []actionGap) string {
	parts := make([]string, 0, len(flip))
	for _, g := range flip {
		parts = append(parts, string(g.action)+"="+g.why)
	}
	return strings.Join(parts, ",")
}

func (m *Manager) debounceActionsSupported(e *policyEntry, rep capabilityReport) actionsSupportStatus {
	threshold := m.ActionsSupportedDebounce
	if threshold <= 0 {
		threshold = DefaultActionsSupportedDebounceTicks
	}
	gaps := rep.gaps
	flip := flipGaps(gaps)
	// The condition FLIP debounces on the fully-unsupported set ONLY (count-free signature)
	// — a fluctuating partial count, or a changing fleet size, must never trip or hold the
	// transient-capability-loss debounce.
	flipSig := flipSignature(flip)
	message := gapMessage(gaps) // shown in every state; carries partial + full counts

	m.mu.Lock()
	entry := m.policies[e.key.String()]
	if entry == nil {
		entry = e
	}
	// [M-21] Nothing observed: the selector matched no asset this tick, so no per-target
	// capability was evaluated for any enabled action. Disclose the absent observation
	// instead of asserting readiness. It resets the debounce (an empty fleet is not
	// evidence of capability loss) and stays Unknown rather than False, preserving M-20's
	// deliberate refusal to flip a policy that simply matches nothing yet.
	if rep.enabled > 0 && rep.observed == 0 {
		entry.actionsUnsupportedTicks = 0
		entry.actionsUnsupportedSignature = ""
		m.mu.Unlock()
		return actionsSupportStatus{
			status: metav1.ConditionUnknown, reason: actionsNoAssetsReason,
			message: fmt.Sprintf("no selected assets observed; per-target capability for the %d enabled action(s) was not evaluated", rep.enabled),
		}
	}
	if len(flip) == 0 {
		// No action is unsupported fleet-wide: the condition stays TRUE. If there are
		// PARTIAL gaps (serviceable somewhere, not everywhere) surface their per-asset
		// counts in the message anyway — count-while-green (M-20 test b) — but do not flip.
		entry.actionsUnsupportedTicks = 0
		entry.actionsUnsupportedSignature = ""
		m.mu.Unlock()
		msg := "all enabled actions have matching capabilities in the selected fleet"
		if len(gaps) > 0 {
			msg = "all enabled actions serviceable; " + message
		}
		return actionsSupportStatus{status: metav1.ConditionTrue, reason: actionsSupportedReason, message: msg}
	}
	if entry.actionsUnsupportedSignature == flipSig {
		entry.actionsUnsupportedTicks++
	} else {
		entry.actionsUnsupportedSignature = flipSig
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
