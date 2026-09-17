package runner

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/actuator"
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
	m := &Manager{Actuator: act, Log: logr.Discard()}
	if cleanNoEffectResult(act.result) {
		t.Fatal("protected adapter recovery debt was classified as fallback-safe no-effect")
	}
	decisions := tracedSelectedDecision()
	decisions[0].Action = model.ActionAdapterRotate
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
	policy := model.Policy{Tenant: "tenant", MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionAdapterRotate: true}}
	got := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, policy, decisions, views)
	decision := decisions[0]
	if act.calls != 1 || got != 0 || decision.Actuated || decision.Trace.DispatchOutcome != model.DispatchError ||
		decision.Trace.DispatchReason != "outcome-unknown" || len(decision.ObjectsTouched) != 1 || len(m.fallbackDecisions) != 0 {
		t.Fatalf("uncertain adapter effect entered fallback or lost evidence: calls=%d actuations=%d decision=%+v fallbacks=%+v", act.calls, got, decision, m.fallbackDecisions)
	}
}
