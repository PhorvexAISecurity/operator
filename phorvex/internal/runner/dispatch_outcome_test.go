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

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

// configurable fake: separate from regate_test's always-emitting fakeActuator.
type dispatchFakeActuator struct {
	ensureErr error
	emit      bool
	actErr    error
	calls     int
}

func (f *dispatchFakeActuator) Name() string { return "dispatch-fake" }
func (f *dispatchFakeActuator) EnsurePolicy(context.Context, actuator.TenantTarget) error {
	return f.ensureErr
}
func (f *dispatchFakeActuator) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	f.calls++
	return actuator.Result{Emitted: f.emit}, f.actErr
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
		if n := m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView); n != 0 {
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
		m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView)
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
		m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, map[string]*model.WorkloadView{})
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
		m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, notReady)
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
		m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView)
		outcome, reason := dispatchOutcomeOf(t, ds)
		if outcome != model.DispatchError || reason != "failed" {
			t.Fatalf("outcome/reason = %q/%q", outcome, reason)
		}
	})

	t.Run("dispatch-error-deadline-expired", func(t *testing.T) {
		fa := &dispatchFakeActuator{actErr: context.DeadlineExceeded}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView)
		outcome, reason := dispatchOutcomeOf(t, ds)
		if outcome != model.DispatchError || reason != "deadline-expired" {
			t.Fatalf("outcome/reason = %q/%q", outcome, reason)
		}
	})

	t.Run("emitted-false", func(t *testing.T) {
		fa := &dispatchFakeActuator{emit: false}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView)
		outcome, _ := dispatchOutcomeOf(t, ds)
		if outcome != model.DispatchEmittedFalse {
			t.Fatalf("outcome = %q", outcome)
		}
	})

	t.Run("emitted", func(t *testing.T) {
		fa := &dispatchFakeActuator{emit: true}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		if n := m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView); n != 1 {
			t.Fatalf("actuated %d, want 1", n)
		}
		outcome, reason := dispatchOutcomeOf(t, ds)
		if outcome != model.DispatchEmitted || reason != "" {
			t.Fatalf("outcome/reason = %q/%q", outcome, reason)
		}
	})

	t.Run("unselected-untouched", func(t *testing.T) {
		fa := &dispatchFakeActuator{emit: true}
		m := &Manager{Actuator: fa, Log: logr.Discard()}
		ds := tracedSelectedDecision()
		ds[0].Selected = false
		ds[0].Trace.DispatchReason = "unselected"
		m.actuate(context.Background(), &policyEntry{namespace: "ns"}, pol, ds, feasibleView)
		outcome, reason := dispatchOutcomeOf(t, ds)
		if outcome != model.DispatchNotAttempted || reason != "unselected" {
			t.Fatalf("unselected decision was re-stamped: %q/%q", outcome, reason)
		}
	})
}
