package runner

import (
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

// A configured lease boundary cannot allow a different action to bypass the
// protected same-Pod journal fence when its read authority is missing. The
// default-off legacy route remains available under the same ordinary policy.
func TestEndpointLeaseMissingJournalAuthorityFencesOtherVLLMAction(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		policy := m135Policy("active")
		policy.Namespace = "vllm"
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "vllm", Name: "api-0", UID: types.UID("pod-uid"), Labels: map[string]string{"app": "api"}}}
		base := fake.NewClientBuilder().WithScheme(m135RunnerScheme(t)).WithObjects(policy, pod,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "vllm"}},
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}},
		).Build()
		maintainer := &m135Maintainer{}
		m, entry, pol := m135MaintenanceUnit(t, base, maintainer, policy)
		m.Log = logr.Discard()
		m.EndpointLeaseAuthorityEnabled = enabled
		m.OperatorNamespace = "" // The exact protected journal cannot be addressed.
		decision := []model.Decision{{Namespace: "vllm", Pod: "api-0", Action: model.ActionRotate,
			Selected: true, Feasible: true,
			Trace: &model.DecisionTraceV2{DispatchOutcome: model.DispatchNotAttempted, DispatchReason: "pending-dispatch"}}}
		view := &model.WorkloadView{Pod: model.Pod{Namespace: "vllm", Name: "api-0", UID: "pod-uid",
			Labels: map[string]string{"app": "api"}, Ready: true, DesiredReplicas: 2, ReadyReplicas: 2}}
		_, _, attempted := m.actuatePreparedMode(t.Context(), entry, pol, decision,
			map[string]*model.WorkloadView{"vllm/api-0": view}, true,
			&killSwitchTickState{observation: KillSwitchObservation{Cause: KillSwitchStaticOnly}},
			&actuationBrakeTickState{namespace: actuationbrake.Namespace(nil)},
			&actuator.RoutePreparation{PhoenixSkipped: true})
		if enabled {
			if attempted || maintainer.actuateCalls != 0 || decision[0].Trace.DispatchReason != "protected-endpoint-lease-journal-authority-unavailable" {
				t.Fatalf("enabled lease boundary bypassed: attempted=%v calls=%d trace=%+v", attempted, maintainer.actuateCalls, decision[0].Trace)
			}
		} else if !attempted || maintainer.actuateCalls != 1 {
			t.Fatalf("default-off route changed: attempted=%v calls=%d trace=%+v", attempted, maintainer.actuateCalls, decision[0].Trace)
		}
	}
}
