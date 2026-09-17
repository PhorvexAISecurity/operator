/*
 * Phorvex — T0-C (B.5): every selected decision's dispatch outcome is stamped on the
 * trace before the audit write, across the whole pre-Actuate guard surface. A
 * selected-but-refused move never reads as unselected.
 */

package runner

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

type routedDispatchFake struct {
	dispatchFakeActuator
	prep   actuator.RoutePreparation
	target actuator.TenantTarget
}

func (*routedDispatchFake) Name() string { return "hybrid" }

func (f *routedDispatchFake) PrepareRoutes(_ context.Context, target actuator.TenantTarget) actuator.RoutePreparation {
	f.target = target
	return f.prep
}

func TestActuateRefusesOnlyFailedPreparationRoute(t *testing.T) {
	fa := &routedDispatchFake{dispatchFakeActuator: dispatchFakeActuator{emit: true}, prep: actuator.RoutePreparation{PhoenixErr: errors.New("unrepresentable Phoenix selector")}}
	m := &Manager{Actuator: fa, Log: logr.Discard()}
	pol := model.Policy{Tenant: "t", EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionKVReset: true}}
	e := &policyEntry{namespace: "ns"}
	e.spec.Selector.MatchLabels = map[string]string{"app": "demo"}
	e.spec.Selector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpExists}}
	views := map[string]*model.WorkloadView{"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", UID: "uid-1", Ready: true, DesiredReplicas: 3, ReadyReplicas: 3, ServingDeclared: true}}}
	refused := tracedSelectedDecision()
	if n := actuateWithBoundary(t, m, context.Background(), e, pol, refused, views); n != 0 || fa.calls != 0 || refused[0].Trace.DispatchReason != "route-preparation-failed" {
		t.Fatalf("Phoenix refusal dispatched: n=%d calls=%d trace=%+v", n, fa.calls, refused[0].Trace)
	}
	if fa.target.Selector == nil || len(fa.target.Selector.MatchExpressions) != 1 {
		t.Fatalf("runner dropped expression: %+v", fa.target.Selector)
	}
	e.spec.Selector.MatchLabels["app"] = "changed"
	e.spec.Selector.MatchExpressions[0].Key = "changed"
	if fa.target.Selector.MatchLabels["app"] != "demo" || fa.target.Selector.MatchExpressions[0].Key != "tier" {
		t.Fatalf("runner target aliases policy selector: %+v", fa.target.Selector)
	}
	e.spec.Selector.MatchLabels["app"] = "demo"
	e.spec.Selector.MatchExpressions[0].Key = "tier"
	fa.calls = 0
	native := tracedSelectedDecision()
	native[0].Action = model.ActionKVReset
	if n := actuateWithBoundary(t, m, context.Background(), e, pol, native, views); n != 1 || fa.calls != 1 || native[0].Trace.DispatchOutcome != model.DispatchEmitted {
		t.Fatalf("native route suppressed by Phoenix refusal: n=%d calls=%d trace=%+v", n, fa.calls, native[0].Trace)
	}
	fa.calls = 0
	mixed := append(tracedSelectedDecision(), native[0])
	if n := actuateWithBoundary(t, m, context.Background(), e, pol, mixed, views); n != 1 || fa.calls != 1 || mixed[0].Trace.DispatchOutcome != model.DispatchNotAttempted || mixed[1].Trace.DispatchOutcome != model.DispatchEmitted {
		t.Fatalf("mixed route isolation failed: n=%d calls=%d traces=%+v / %+v", n, fa.calls, mixed[0].Trace, mixed[1].Trace)
	}
	// The native leg is prepared independently and reaches its own downstream
	// guards. A fresh preparation call cannot inherit the previous refusal.
	fa.prep = actuator.RoutePreparation{}
	fa.calls = 0
	allowed := tracedSelectedDecision()
	if n := actuateWithBoundary(t, m, context.Background(), e, pol, allowed, views); n != 1 || fa.calls != 1 {
		t.Fatalf("fresh supported route not delivered: n=%d calls=%d trace=%+v", n, fa.calls, allowed[0].Trace)
	}
}

// configurable fake: separate from regate_test's always-emitting fakeActuator.
type dispatchFakeActuator struct {
	ensureErr error
	emit      bool
	actErr    error
	calls     int
	last      actuator.Request
}

func (f *dispatchFakeActuator) Name() string { return "dispatch-fake" }
func (f *dispatchFakeActuator) EnsurePolicy(context.Context, actuator.TenantTarget) error {
	return f.ensureErr
}
func (f *dispatchFakeActuator) Actuate(_ context.Context, req actuator.Request) (actuator.Result, error) {
	f.calls++
	f.last = req
	return actuator.Result{Emitted: f.emit}, f.actErr
}
func (f *dispatchFakeActuator) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}

func tracedSelectedDecision() []model.Decision {
	return []model.Decision{{
		Selected: true, Feasible: true, Action: model.ActionRotate,
		Namespace: "ns", Pod: "p1",
		Trace: &model.DecisionTraceV2{
			DispatchOutcome: model.DispatchNotAttempted, DispatchReason: "pending-dispatch",
		},
	}}
}

func dispatchOutcomeOf(t *testing.T, ds []model.Decision) (string, string) {
	t.Helper()
	if ds[0].Trace == nil {
		t.Fatal("trace missing")
	}
	return ds[0].Trace.DispatchOutcome, ds[0].Trace.DispatchReason
}

func TestRouteActionsCarryStableDecisionIdentityToActuator(t *testing.T) {
	for _, action := range []model.Action{model.ActionRouteRotate, model.ActionEndpointRotate} {
		t.Run(string(action), func(t *testing.T) {
			fake := &dispatchFakeActuator{emit: true}
			manager := &Manager{Actuator: fake, Log: logr.Discard()}
			policy := model.Policy{
				Tenant: "tenant", PolicyName: "policy", PolicyUID: "policy-uid", MinAvailableReplicas: 1,
				EnabledActions: map[model.Action]bool{action: true},
			}
			decisions := tracedSelectedDecision()
			decisions[0].Action = action
			decisions[0].Trace.DecisionID = "stable-route-decision"
			views := map[string]*model.WorkloadView{
				"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", UID: "target-uid", DesiredReplicas: 1, ReadyReplicas: 1, Ready: true}},
			}
			if action == model.ActionEndpointRotate {
				views["ns/p1"].Pod.ModelID = "fixture-model"
			}
			if got := actuateWithBoundary(t, manager, context.Background(), &policyEntry{namespace: "ns"}, policy, decisions, views); got != 1 {
				t.Fatalf("actuated %d decisions, want 1; trace=%+v", got, decisions[0].Trace)
			}
			if fake.last.OperationID != decisions[0].Trace.DecisionID || fake.last.TargetUID != "target-uid" || fake.last.Action != action {
				t.Fatalf("request lost route identity: %+v", fake.last)
			}
		})
	}
}

func TestM064TraceDisabledServingActionCarriesTickAndStructuredObservation(t *testing.T) {
	fake := &dispatchFakeActuator{emit: true}
	manager := &Manager{Actuator: fake, Log: logr.Discard(), DecisionTraceEnabled: false}
	policy := model.Policy{Tenant: "tenant", PolicyName: "policy", PolicyUID: "policy-uid", TickID: "real-tick-id", EnabledActions: map[model.Action]bool{model.ActionKVReset: true}}
	decisions := []model.Decision{{Selected: true, Feasible: true, Action: model.ActionKVReset, Namespace: "ns", Pod: "p1"}}
	views := map[string]*model.WorkloadView{"ns/p1": {Pod: model.Pod{
		Namespace: "ns", Name: "p1", UID: "target-uid", Ready: true, DesiredReplicas: 1, ReadyReplicas: 1, ServingDeclared: true,
		KVResetEpoch: model.OwnedValue{Present: true, Value: ""}, KVMigrateEpoch: model.OwnedValue{Present: true, Value: "m1"},
		KVLocalEffectEpoch: model.OwnedValue{Present: false}, GuardrailEpochObservation: model.OwnedValue{Present: true, Value: ""},
	}}}
	if got := actuateWithBoundary(t, manager, context.Background(), &policyEntry{namespace: "ns"}, policy, decisions, views); got != 1 {
		t.Fatalf("trace-disabled serving dispatch count=%d", got)
	}
	if fake.last.TickID != policy.TickID || fake.last.OperationID != "" || fake.last.ServingObservation == nil ||
		!fake.last.ServingObservation.KVReset.Present || fake.last.ServingObservation.KVReset.Value != "" ||
		!fake.last.ServingObservation.KVMigrate.Present || fake.last.ServingObservation.KVMigrate.Value != "m1" ||
		fake.last.ServingObservation.KVLocalEffect.Present || !fake.last.ServingObservation.Guardrail.Present || fake.last.ServingObservation.Guardrail.Value != "" {
		t.Fatalf("trace-disabled request lost protected identity/observation: %+v", fake.last)
	}
}

func TestActuateStampsDispatchOutcomeAcrossTheGuardSurface(t *testing.T) {
	feasibleView := map[string]*model.WorkloadView{
		"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", DesiredReplicas: 3, ReadyReplicas: 3, Ready: true}},
	}
	pol := model.Policy{Tenant: "t", MinAvailableReplicas: 1,
		EnabledActions: map[model.Action]bool{model.ActionRotate: true}}

	t.Run("ensure-policy-failed", func(t *testing.T) {
		fa := &dispatchFakeActuator{ensureErr: errors.New("rbac denied")}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		if n := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView); n != 0 {
			t.Fatalf("actuated %d under EnsurePolicy failure", n)
		}
		if got, want := ds[0].Trace.DispatchReason, "ensure-policy-failed"; got != want {
			t.Fatalf("reason = %q, want %q", got, want)
		}
		if ds[0].Trace.DispatchOutcome != model.DispatchNotAttempted {
			t.Fatalf("outcome = %q", ds[0].Trace.DispatchOutcome)
		}
	})

	t.Run("inviolability-guard", func(t *testing.T) {
		fa := &dispatchFakeActuator{emit: true}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		ds[0].Feasible = false // selected but infeasible: the invariant-violation path
		actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView)
		if fa.calls != 0 {
			t.Fatal("infeasible selected move reached Actuate")
		}
		if got, want := ds[0].Trace.DispatchReason, "inviolability-guard"; got != want {
			t.Fatalf("reason = %q, want %q", got, want)
		}
	})

	t.Run("no-tick-view", func(t *testing.T) {
		fa := &dispatchFakeActuator{emit: true}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, map[string]*model.WorkloadView{})
		if fa.calls != 0 {
			t.Fatal("map-miss reached Actuate (fail-open)")
		}
		if got, want := ds[0].Trace.DispatchReason, "no-tick-view"; got != want {
			t.Fatalf("reason = %q, want %q", got, want)
		}
	})

	t.Run("emit-boundary-infeasible", func(t *testing.T) {
		fa := &dispatchFakeActuator{emit: true}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		notReady := map[string]*model.WorkloadView{
			"ns/p1": {Pod: model.Pod{Namespace: "ns", Name: "p1", DesiredReplicas: 3, ReadyReplicas: 0}},
		}
		actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, notReady)
		if fa.calls != 0 {
			t.Fatal("infeasible-at-boundary move reached Actuate")
		}
		outcome, reason := dispatchOutcomeOf(t, ds)
		if outcome != model.DispatchNotAttempted || len(reason) < len("emit-boundary-infeasible") ||
			reason[:len("emit-boundary-infeasible")] != "emit-boundary-infeasible" {
			t.Fatalf("outcome/reason = %q/%q", outcome, reason)
		}
	})

	t.Run("dispatch-error-failed", func(t *testing.T) {
		fa := &dispatchFakeActuator{actErr: errors.New("boom")}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView)
		outcome, reason := dispatchOutcomeOf(t, ds)
		if outcome != model.DispatchError || reason != "outcome-unknown" {
			t.Fatalf("outcome/reason = %q/%q", outcome, reason)
		}
	})

	t.Run("dispatch-error-deadline-expired", func(t *testing.T) {
		fa := &dispatchFakeActuator{actErr: context.DeadlineExceeded}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView)
		outcome, reason := dispatchOutcomeOf(t, ds)
		if outcome != model.DispatchError || reason != "deadline-expired" {
			t.Fatalf("outcome/reason = %q/%q", outcome, reason)
		}
	})

	t.Run("emitted-false", func(t *testing.T) {
		fa := &dispatchFakeActuator{emit: false}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView)
		outcome, _ := dispatchOutcomeOf(t, ds)
		if outcome != model.DispatchEmittedFalse {
			t.Fatalf("outcome = %q", outcome)
		}
	})

	t.Run("emitted", func(t *testing.T) {
		fa := &dispatchFakeActuator{emit: true}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		if n := actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView); n != 1 {
			t.Fatalf("actuated %d, want 1", n)
		}
		outcome, reason := dispatchOutcomeOf(t, ds)
		if outcome != model.DispatchEmitted || reason != "emitted-unconfirmed" {
			t.Fatalf("outcome/reason = %q/%q", outcome, reason)
		}
	})

	t.Run("unselected-untouched", func(t *testing.T) {
		fa := &dispatchFakeActuator{emit: true}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		ds[0].Selected = false
		ds[0].Trace.DispatchReason = "unselected"
		actuateWithBoundary(t, m, context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView)
		outcome, reason := dispatchOutcomeOf(t, ds)
		if outcome != model.DispatchNotAttempted || reason != "unselected" {
			t.Fatalf("unselected decision was re-stamped: %q/%q", outcome, reason)
		}
	})
}
