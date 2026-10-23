package runner

import (
	"context"
	"testing"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
)

type m054ReceiptActuator struct {
	target actuator.TenantTarget
	req    actuator.Request
	result actuator.Result
}

func (*m054ReceiptActuator) Name() string { return "m054-receipt" }
func (a *m054ReceiptActuator) EnsurePolicy(_ context.Context, target actuator.TenantTarget) error {
	a.target = target
	return nil
}
func (*m054ReceiptActuator) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}
func (a *m054ReceiptActuator) Actuate(_ context.Context, req actuator.Request) (actuator.Result, error) {
	a.req = req
	return a.result, nil
}

func TestM054RunnerPropagatesPolicyEpochCapAndOwnsReceipt(t *testing.T) {
	receipt := &model.GracefulTerminationReceipt{PolicyUID: "policy-uid", PolicyGeneration: 9, PolicyGraceCapSeconds: 17, EffectiveGracePeriodSeconds: 17, TerminationStatus: "unconfirmed"}
	hands := &m054ReceiptActuator{result: actuator.Result{Emitted: true, GracefulTermination: receipt}}
	manager := &Manager{Local: &inprocess.Services{Actuator: hands}, Log: logr.Discard()}
	policy := model.Policy{
		Tenant: "tenant", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 9,
		MaxGracePeriodSeconds: 17, MinAvailableReplicas: 1,
		EnabledActions: map[model.Action]bool{model.ActionRotate: true},
	}
	entry := &policyEntry{namespace: "ns", generation: 9}
	decisions := []model.Decision{{Selected: true, Feasible: true, Action: model.ActionRotate, Namespace: "ns", Pod: "p1"}}
	views := map[string]*model.WorkloadView{"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", UID: "pod-uid", Ready: true, DesiredReplicas: 2, ReadyReplicas: 2}}}
	if got := actuateWithBoundary(t, manager, t.Context(), entry, policy, decisions, views); got != 1 {
		t.Fatalf("actuated=%d decision=%+v", got, decisions[0])
	}
	if hands.target.Generation != 9 || hands.req.PolicyGeneration != 9 || hands.req.MaxGracePeriodSeconds != 17 || hands.req.PolicyUID != "policy-uid" {
		t.Fatalf("target=%+v request=%+v", hands.target, hands.req)
	}
	if decisions[0].GracefulTermination == nil || decisions[0].GracefulTermination == receipt || *decisions[0].GracefulTermination != *receipt {
		t.Fatalf("decision receipt=%+v result receipt=%+v", decisions[0].GracefulTermination, receipt)
	}
	receipt.TerminationStatus = "mutated"
	if decisions[0].GracefulTermination.TerminationStatus != "unconfirmed" {
		t.Fatal("decision aliases actuator receipt")
	}
}
