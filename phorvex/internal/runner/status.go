/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package runner

import (
	"context"
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/retry"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/metrics"
)

// metav1SelAsSel compiles a metav1.LabelSelector into a labels.Selector. An empty
// selector matches everything (so a tenant can protect all pods in its namespace).
func metav1SelAsSel(sel *metav1.LabelSelector) (labels.Selector, error) {
	if sel == nil {
		return labels.Everything(), nil
	}
	return metav1.LabelSelectorAsSelector(sel)
}

func preparationRouteDetail(err error, skipped bool) string {
	if skipped {
		return "not required"
	}
	if err != nil {
		return "refused (" + err.Error() + ")"
	}
	return "prepared"
}

// updateStatus writes the operational tick result back onto the PhorvexPolicy status
// subresource. The controller also owns one status condition, so conflicts are retried from a
// fresh object instead of dropping this tick or overwriting the controller's condition.
// protected = pods covered; moves = decisions selected this tick; actuated = moves really
// emitted this tick. MovesThisWindow and Actuated are ROLLING (PHORVEXSEC-176): they describe
// the enacted moves inside the trailing AntiOverRotationWindow, never selections, and return
// to 0/false once the window passes without an emit.
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
func (m *Manager) updateStatus(ctx context.Context, e *policyEntry, protected, moves, actuated int, killEngaged bool, now time.Time, actionStatuses ...actionsSupportStatus) {
	actions := actionsSupportStatus{
		status:  metav1.ConditionTrue,
		reason:  actionsSupportedReason,
		message: "all enabled actions have matching capabilities in the selected fleet",
	}
	if len(actionStatuses) > 0 {
		actions = actionStatuses[0]
	}
	enactedInWindow, historyComplete := m.emissionWindow(e, actuated, now)
	var updated v1alpha1.PhorvexPolicy
	emitUnsupportedEvent := false
	lastOperation := "read"
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var p v1alpha1.PhorvexPolicy
		lastOperation = "read"
		if err := m.Client.Get(ctx, e.key, &p); err != nil {
			return err
		}

		if string(p.UID) != e.uid {
			return nil
		}
		before := p.Status.DeepCopy()
		// Publish the disagreement before attempting the transition. A successful write clears it;
		// any exhausted read/update failure below asserts it so the alert survives the failure.
		metrics.SetKillSwitchStatusDisagreement(
			p.Namespace, p.Name, p.Status.KillSwitchEngaged != killEngaged,
		)
		p.Status.Tenant = e.tenant
		p.Status.ObservedGeneration = p.Generation
		p.Status.SelectedPods = protected
		p.Status.MovesThisWindow = enactedInWindow
		p.Status.Actuated = enactedInWindow > 0
		setEmissionHistoryCondition(&p, enactedInWindow, historyComplete)
		p.Status.DecisionsTotal += int64(moves)
		p.Status.LastTickTime = metav1.Time{Time: now}
		if moves > 0 {
			p.Status.LastDecisionTime = metav1.Time{Time: now}
		}
		p.Status.KillSwitchEngaged = killEngaged
		previous := meta.FindStatusCondition(p.Status.Conditions, ConditionActionsSupported)
		emitUnsupportedEvent = actions.status == metav1.ConditionFalse &&
			(previous == nil || previous.Status != actions.status || previous.Message != actions.message)

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
		meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{
			Type:               ConditionActionsSupported,
			Status:             actions.status,
			Reason:             actions.reason,
			Message:            actions.message,
			ObservedGeneration: p.Generation,
		})
		prepStatus, prepReason, prepMessage := metav1.ConditionUnknown, "NotAttempted", "actuator preparation was not attempted this tick"
		if actions.preparation != nil && e.generation != p.Generation {
			prepReason, prepMessage = "StalePreparation", fmt.Sprintf("preparation was for generation %d; current policy generation is %d", e.generation, p.Generation)
		} else if actions.preparation != nil && m.Actuator != nil {
			prepStatus, prepReason, prepMessage = metav1.ConditionTrue, "Prepared", "selected actuator route prepared this tick"
			prep := actions.preparation
			switch m.Actuator.Name() {
			case "hybrid":
				if prep.PhoenixSkipped && prep.NativeSkipped {
					prepStatus, prepReason, prepMessage = metav1.ConditionUnknown, "NoEnabledRoutes", "no enabled action route required preparation this tick"
				} else if prep.PhoenixSkipped || prep.NativeSkipped {
					prepMessage = fmt.Sprintf("Phoenix route: %s; native route: %s", preparationRouteDetail(prep.PhoenixErr, prep.PhoenixSkipped), preparationRouteDetail(prep.NativeErr, prep.NativeSkipped))
				}
				if prep.PhoenixErr != nil || prep.NativeErr != nil {
					prepStatus, prepReason = metav1.ConditionFalse, "RoutePreparationRefused"
					prepMessage = fmt.Sprintf("Phoenix route: %s; native route: %s. Existing AMTD objects, if any, are retained; refused routes emit no new event", preparationRouteDetail(prep.PhoenixErr, prep.PhoenixSkipped), preparationRouteDetail(prep.NativeErr, prep.NativeSkipped))
				}
			case "native":
				if prep.NativeErr != nil {
					prepStatus, prepReason, prepMessage = metav1.ConditionFalse, "NativePreparationRefused", prep.NativeErr.Error()
				}
			default:
				if prep.PhoenixErr != nil {
					prepStatus, prepReason, prepMessage = metav1.ConditionFalse, "PhoenixPreparationRefused", prep.PhoenixErr.Error()+"; existing AMTD objects, if any, are retained"
				}
			}
		}
		meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{
			Type: "ActuationPrepared", Status: prepStatus, Reason: prepReason, Message: prepMessage, ObservedGeneration: p.Generation,
		})
		vocabularyStatus, vocabularyReason, vocabularyMessage := m.VocabularySnapshot().diagnostic()
		meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{
			Type: "PolicyActionVocabulary", Status: vocabularyStatus,
			Reason: vocabularyReason, Message: vocabularyMessage,
			ObservedGeneration: p.Generation,
		})

		// [PHVX-17] The CRD documents a "KillSwitch" condition ("Conditions includes Ready, DryRun,
		// ValidationError, KillSwitch") and nothing ever wrote one. A condition carries a reason and a
		// timestamp, which a bare bool cannot: an operator can see WHEN actuation stopped and why.
		ksStatus, ksReason, ksMsg := metav1.ConditionFalse, "Disengaged", "actuation is permitted"
		if killEngaged {
			ksStatus, ksReason, ksMsg = metav1.ConditionTrue, "Engaged",
				"actuation suppressed globally; the engine still decides, logs and emits metrics"
		}
		// [PHORVEXSEC-200 / M-113] TelemetryDegraded: a whole-source scrape outage is visible on
		// the policy within one tick, with the source, the reason and since when; cleared on the
		// first tick the source answers again. Per-signal absence stays per-signal (T1-C).
		tdStatus, tdReason, tdMsg := metav1.ConditionFalse, "Healthy", "telemetry source answering"
		if src, st := m.sourceOutageState(); st.Down {
			tdStatus, tdReason = metav1.ConditionTrue, "SourceUnreachable"
			tdMsg = "telemetry source " + src + " unreachable since " + st.Since.UTC().Format(time.RFC3339) + " (" + st.Reason + "); affected signals read State=Error, never 0"
		}
		meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{
			Type:               ConditionTelemetryDegraded,
			Status:             tdStatus,
			Reason:             tdReason,
			Message:            tdMsg,
			ObservedGeneration: p.Generation,
		})
		meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{
			Type:               "KillSwitch",
			Status:             ksStatus,
			Reason:             ksReason,
			Message:            ksMsg,
			ObservedGeneration: p.Generation,
		})

		if reflect.DeepEqual(*before, p.Status) {
			updated = p
			return nil
		}
		lastOperation = "update"
		if err := m.Client.Status().Update(ctx, &p); err != nil {
			return err
		}
		updated = p
		return nil
	})
	if err != nil {
		metrics.SetKillSwitchStatusDisagreement(e.key.Namespace, e.key.Name, true)
		if lastOperation == "read" {
			m.Log.Error(err, "status read failed; kill-switch readout is UNKNOWN",
				"tenant", e.tenant, "policy", e.key.String(), "killSwitchEngaged", killEngaged)
		} else {
			m.Log.Error(err, "status update failed; the policy CR now shows a STALE kill-switch and "+
				"decision state", "tenant", e.spec.Tenant, "policy", e.key.String(),
				"killSwitchEngaged", killEngaged)
		}
		return
	}
	metrics.SetKillSwitchStatusDisagreement(updated.Namespace, updated.Name, false)
	if emitUnsupportedEvent && m.Recorder != nil {
		m.Recorder.Event(&updated, corev1.EventTypeWarning, actionsUnsupportedReason, actions.message)
	}
}
