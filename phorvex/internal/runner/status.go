/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package runner

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/phorvex/phorvex/api/v1alpha1"
)

// metav1SelAsSel compiles a metav1.LabelSelector into a labels.Selector. An empty
// selector matches everything (so a tenant can protect all pods in its namespace).
func metav1SelAsSel(sel *metav1.LabelSelector) (labels.Selector, error) {
	if sel == nil {
		return labels.Everything(), nil
	}
	return metav1.LabelSelectorAsSelector(sel)
}

// updateStatus writes the operational tick result back onto the PhorvexPolicy status
// subresource. Conflicts (the controller also touches status) are ignored — the next
// tick re-writes. protected = pods covered; moves = decisions selected this tick.
func (m *Manager) updateStatus(ctx context.Context, e *policyEntry, protected, moves, actuated int, killEngaged bool, now time.Time) {
	var p v1alpha1.PhorvexPolicy
	if err := m.Client.Get(ctx, e.key, &p); err != nil {
		return
	}
	p.Status.Tenant = e.tenant
	p.Status.ObservedGeneration = p.Generation
	p.Status.SelectedPods = protected
	p.Status.MovesThisWindow = moves
	p.Status.DecisionsTotal += int64(moves)
	p.Status.LastTickTime = metav1.Time{Time: now}
	if moves > 0 {
		p.Status.LastDecisionTime = metav1.Time{Time: now}
	}
	if actuated > 0 {
		p.Status.Actuated = true
	}
	p.Status.KillSwitchEngaged = killEngaged

	meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Ticking",
		Message:            "phorvex is ingesting, scoring and logging decisions",
		ObservedGeneration: p.Generation,
	})
	dryReason, dryMsg := "Active", "actuation enabled"
	dryStatus := metav1.ConditionFalse
	if e.spec.IsDryRun() {
		dryStatus, dryReason, dryMsg = metav1.ConditionTrue, "DryRun", "decide+log+metrics only; no actuation"
	}
	meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{
		Type:               "DryRun",
		Status:             dryStatus,
		Reason:             dryReason,
		Message:            dryMsg,
		ObservedGeneration: p.Generation,
	})

	_ = m.Client.Status().Update(ctx, &p)
}
