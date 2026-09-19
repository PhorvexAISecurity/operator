package runner

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/model"
)

func (m *Manager) updateExistentialStatus(ctx context.Context, e *policyEntry, ds []model.Decision, inventories ...*model.ExistentialInventory) {
	var blocked []string
	for _, d := range ds {
		if d.Existential != nil && d.Existential.Result == "uncontainable" {
			blocked = append(blocked, d.Namespace+"/"+d.Pod)
		}
	}
	condition := metav1.Condition{Type: "ExistentialUncontainable", Status: metav1.ConditionFalse, Reason: "NoUncontainableDecision", Message: "PHORVEXSEC-208 interim: no qualified exposure lacked a selected containing move this tick; not a safety claim"}
	if len(blocked) > 0 {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "Uncontainable"
		condition.Message = "PHORVEXSEC-208 interim: " + strings.Join(blocked, ", ") + " have no selected full-containing move under this tick's bounds"
	}
	var obj v1alpha1.PhorvexPolicy
	emit := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		emit = false
		if err := m.Client.Get(ctx, e.key, &obj); err != nil {
			return err
		}
		// The policy name may have been deleted and recreated after this tick's
		// outer owner check. Never attach predecessor existential evidence or an
		// event to the replacement UID.
		if string(obj.UID) != e.uid {
			return nil
		}
		old := meta.FindStatusCondition(obj.Status.Conditions, condition.Type)
		emit = condition.Status == metav1.ConditionTrue && (old == nil || old.Status != condition.Status || old.Message != condition.Message)
		condition.ObservedGeneration = obj.Generation
		meta.SetStatusCondition(&obj.Status.Conditions, condition)
		inventoryCondition := metav1.Condition{Type: "ExistentialScopeComplete", Status: metav1.ConditionTrue, Reason: "NoUnresolvedScope", Message: "no unresolved scope in supplied outcome inventory; not a completeness or safety claim", ObservedGeneration: obj.Generation}
		if len(inventories) > 0 && inventories[0] != nil && !inventories[0].ScopeComplete {
			inventoryCondition.Status = metav1.ConditionFalse
			inventoryCondition.Reason = "ScopeUnresolved"
			inventoryCondition.Message = "PHORVEXSEC-208 interim: outcome inventory contains unresolved policy/workload scope; see policy inventory audit record"
		}
		meta.SetStatusCondition(&obj.Status.Conditions, inventoryCondition)
		return m.Client.Status().Update(ctx, &obj)
	})
	if err != nil {
		m.Log.Error(err, "existential status update failed")
		return
	}
	if emit && m.Recorder != nil {
		m.Recorder.Event(&obj, corev1.EventTypeWarning, "ExistentialUncontainable", condition.Message)
	}
}

// Actuator success is only a dispatch observation. This boundary never manufactures
// T2-01 confirmation or claims a selected/dry-run action contained an exposure.
func recordExistentialEffect(d *model.Decision, attempted bool) {
	if d.Existential == nil || !d.Existential.Present || !d.Selected {
		return
	}
	d.Existential.EffectStatus = "not-attempted"
	if attempted {
		d.Existential.EffectStatus = "failed-or-unconfirmed"
		if d.Actuated {
			d.Existential.EffectStatus = "attempted-unconfirmed"
		}
	}
}

func outcomeInventory(events []model.SecurityEventInfo, p model.Policy) *model.ExistentialInventory {
	inventory := &model.ExistentialInventory{PolicyUID: p.PolicyUID, ScopeComplete: true}
	for _, event := range events {
		if event.OutcomeParseError != "" {
			inventory.ScopeComplete = false
			inventory.Reasons = append(inventory.Reasons, event.Name+":"+event.OutcomeParseError)
		}
		for _, r := range event.Outcomes {
			if r.PolicyUID != "" && r.PolicyUID != p.PolicyUID {
				continue
			}
			row := model.OutcomeAssertion{Event: event.Name, EventTrust: event.Trust, Outcome: r}
			if r.PolicyUID == "" || r.DecisionAsset == "" || p.DecisionAssets[r.DecisionAsset] == "" || p.DecisionAssets[r.DecisionAsset] != r.DecisionAssetUID || r.ScopeBasis == "" {
				inventory.ScopeComplete = false
				row.Reasons = append(row.Reasons, "scope-unresolved")
			}
			inventory.Records = append(inventory.Records, row)
		}
	}
	if len(inventory.Records) == 0 && len(inventory.Reasons) == 0 {
		return nil
	}
	return inventory
}

// The emit boundary repeats the SAME permitted SLO exception as selection and
// rechecks all retained laws against the same tick view. It does not refresh state.
func existentialEmitVerdict(d model.Decision, v *model.WorkloadView, p model.Policy) feasibility.Verdict {
	move := model.Move{Action: d.Action}
	if p.MayBreachSLO && d.Existential != nil && d.Existential.Present && decision.HasQualifiedOutcome(v, p) {
		for _, c := range d.Existential.Candidates {
			if c.Action == d.Action && c.Contains && c.SLORelaxed {
				verdict, _ := feasibility.EvaluateWithSLOSeparation(v, move, p)
				return verdict
			}
		}
	}
	return feasibility.Evaluate(v, move, p)
}
