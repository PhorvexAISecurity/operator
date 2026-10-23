package runner

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
)

func TestM071RunnerKeepsUncertainAdapterDispatchOutOfFallback(t *testing.T) {
	act := &m040ResultActuator{
		result: actuator.Result{
			Emitted: true, Handler: string(model.ActionAdapterRotate), MutationKind: "partial",
			ObjectsTouched: []string{"ConfigMap/operator/receipt"}, RollbackRef: "operator/receipt@uid",
			Note: "adapter-rotate outcome partial or unknown; protected recovery receipt retained",
		},
		err: errors.New("adapter inventory did not converge"),
	}
	m := &Manager{Local: &inprocess.Services{Actuator: act}, Log: logr.Discard()}
	if cleanNoEffectResult(act.result) {
		t.Fatal("protected adapter recovery debt was classified as fallback-safe no-effect")
	}
	decisions := tracedSelectedDecision()
	decisions[0].Action = model.ActionAdapterRotate
	decisions[0].Trace.DecisionID = "selected-adapter-decision"
	pod := model.Pod{
		Namespace: "ns", Name: "p1", UID: "pod-uid", ModelID: "fixture-model",
		SuspectAdapter: "adapter-a", DesiredReplicas: 3, ReadyReplicas: 3, Ready: true,
	}
	pod.AdapterObservation = &model.AdapterObservation{
		EventName:       "adapter-detected",
		EventUID:        "event-uid",
		CreatorIdentity: "system:serviceaccount:ns:detector",
		TargetPodUID:    pod.UID,
		AdapterName:     pod.SuspectAdapter,
	}
	views := map[string]*model.WorkloadView{"ns/p1": {Pod: pod}}
	policy := model.Policy{Tenant: "tenant", TickID: "selected-tick", MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionAdapterRotate: true}}
	got := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, policy, decisions, views)
	decision := decisions[0]
	if act.calls != 1 || got != 0 || decision.Actuated || decision.Trace.DispatchOutcome != model.DispatchError ||
		decision.Trace.DispatchReason != "outcome-unknown" || len(decision.ObjectsTouched) != 1 || len(m.fallbackDecisions) != 0 {
		t.Fatalf("uncertain adapter effect entered fallback or lost evidence: calls=%d actuations=%d decision=%+v fallbacks=%+v", act.calls, got, decision, m.fallbackDecisions)
	}
}

func TestAdapterSelectionIDsReachNativeRequest(t *testing.T) {
	act := &dispatchFakeActuator{emit: true}
	m := &Manager{Local: &inprocess.Services{Actuator: act}, Log: logr.Discard()}
	decisions := tracedSelectedDecision()
	decisions[0].Action = model.ActionAdapterRotate
	decisions[0].Trace.DecisionID = "selected-adapter-decision"
	pod := model.Pod{Namespace: "ns", Name: "p1", UID: "pod-uid", SuspectAdapter: "adapter-a", DesiredReplicas: 3, ReadyReplicas: 3, Ready: true,
		AdapterObservation: &model.AdapterObservation{EventName: "adapter-detected", EventUID: "event-uid", CreatorIdentity: "system:serviceaccount:ns:detector", TargetPodUID: "pod-uid", AdapterName: "adapter-a"}}
	views := map[string]*model.WorkloadView{"ns/p1": {Pod: pod}}
	policy := model.Policy{Tenant: "tenant", TickID: "selected-tick", MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionAdapterRotate: true}}
	_ = actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, policy, decisions, views)
	if act.calls != 1 || act.last.OperationID != "selected-adapter-decision" || act.last.TickID != "selected-tick" {
		t.Fatalf("adapter request lost selecting identity: calls=%d request=%+v", act.calls, act.last)
	}
}
