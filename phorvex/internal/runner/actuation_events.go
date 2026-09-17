package runner

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

func actuationEventTarget(v *model.WorkloadView) *corev1.Pod {
	if v == nil || v.Pod.UID == "" || v.Pod.Namespace == "" || v.Pod.Name == "" {
		return nil
	}
	return &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{Namespace: v.Pod.Namespace, Name: v.Pod.Name, UID: types.UID(v.Pod.UID)}}
}

// notifyActuation is called exactly once after Actuate, never on selection or
// pre-dispatch exclusion. The recorder queues best-effort output, not audit proof.
// Deliberately omit raw errors/notes, tenant/policy IDs, scores and transport data.
func (m *Manager) notifyActuation(target *corev1.Pod, action model.Action, res actuator.Result, err error) {
	if m.ActuationRecorder == nil {
		return
	}
	if target == nil {
		m.Log.Info("actuation notification omitted: original target identity unavailable")
		return
	}
	safeAction := "action"
	for _, known := range model.MutatingActions {
		if action == known {
			safeAction = string(known)
			break
		}
	}
	eventType, reason, message := corev1.EventTypeWarning, "PhorvexActuationOutcomeUnknown", "request outcome uncertain; partial changes may exist; effect unconfirmed"
	if err == nil && res.Emitted && !contradictoryNoEffectResult(res, err) {
		eventType, reason, message = corev1.EventTypeNormal, "PhorvexActuationEmitted", "request reported emitted for this target; effect unconfirmed"
	} else {
		switch noEffectDisposition(res, err) {
		case actuator.NoEffectRefused:
			reason, message = "PhorvexActuationNotEmitted", "request definitely refused before effect; no mutation credited"
		case actuator.NoEffectSatisfied:
			eventType, reason, message = corev1.EventTypeNormal, "PhorvexActuationAlreadySatisfied", "no new mutation; current evidence says the requested state was already satisfied"
		case actuator.NoEffectReconciled:
			eventType, reason, message = corev1.EventTypeNormal, "PhorvexActuationReconciled", "no new mutation was submitted; a prior operation or observation was reconciled without claiming availability or effect"
		case actuator.NoEffectDeclared:
			eventType, reason, message = corev1.EventTypeNormal, "PhorvexActuationDeclaredOnly", "no mutation was submitted; this administrative action is declared without an implementation"
		}
	}
	m.ActuationRecorder.Event(target, eventType, reason, safeAction+": "+message)
}
