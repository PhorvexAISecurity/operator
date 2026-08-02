package runner

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

type rotationObservation struct {
	tenant string
	view   *model.WorkloadView
	flow   float64
}

type observingOptimizer struct{ observations []rotationObservation }

func (*observingOptimizer) Name() string { return "observing-test" }
func (*observingOptimizer) Decide([]*model.WorkloadView, model.Policy) []model.Decision {
	return nil
}
func (o *observingOptimizer) ObserveRotation(tenant string, view *model.WorkloadView, measuredFlow float64) {
	o.observations = append(o.observations, rotationObservation{tenant: tenant, view: view, flow: measuredFlow})
}

func TestLiveActuationLearnsOnlyFromNewReadyReplacement(t *testing.T) {
	fa := &fakeActuator{}
	opt := &observingOptimizer{}
	m := &Manager{Actuator: fa, Optimizer: opt, Log: logr.Discard()}
	e := &policyEntry{namespace: "ns"}
	pol := model.Policy{Tenant: "tenant-a", EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	views := map[string]*model.WorkloadView{
		"ns/old":     {Pod: model.Pod{Namespace: "ns", Name: "old", UID: "old-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs", ReadyReplicas: 3}, Phase: model.PhaseWarm},
		"ns/sibling": {Pod: model.Pod{Namespace: "ns", Name: "sibling", UID: "sibling-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true, ReadyReplicas: 3}},
	}
	decisions := []model.Decision{{Selected: true, Feasible: true, Action: model.ActionRotate, Namespace: "ns", Pod: "old"}}
	if got := m.actuate(context.Background(), e, pol, decisions, views); got != 1 {
		t.Fatalf("actuate count = %d, want 1", got)
	}
	if len(m.pendingRotations) != 1 {
		t.Fatalf("pending rotations = %d, want 1", len(m.pendingRotations))
	}
	var startedAt time.Time
	for _, p := range m.pendingRotations {
		startedAt = p.startedAt
	}

	// A replacement candidate is not complete while the rotation target is still
	// alive and the candidate has not reached Ready.
	m.observeReadyRotations(&ingest.Snapshot{Now: startedAt.Add(30 * time.Second), Pods: []model.Pod{
		{Namespace: "ns", UID: "old-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true},
		{Namespace: "ns", UID: "sibling-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true},
		{Namespace: "ns", UID: "replacement-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: false},
	}})
	if len(opt.observations) != 0 {
		t.Fatal("rotation was learned while the original UID was still present")
	}

	readyAt := startedAt.Add(60 * time.Second)
	m.observeReadyRotations(&ingest.Snapshot{Now: startedAt.Add(70 * time.Second), Pods: []model.Pod{
		{Namespace: "ns", UID: "sibling-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true},
		{Namespace: "ns", UID: "replacement-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true, ReadyAt: readyAt},
	}})
	if len(opt.observations) != 1 {
		t.Fatalf("rotation observations = %d, want 1", len(opt.observations))
	}
	got := opt.observations[0]
	if got.tenant != "tenant-a" || got.view.Pod.UID != "old-uid" || math.Abs(got.flow-0.15) > 1e-12 {
		t.Fatalf("unexpected observation: tenant=%q oldUID=%q flow=%v", got.tenant, got.view.Pod.UID, got.flow)
	}
	if len(m.pendingRotations) != 0 {
		t.Fatal("completed rotation observation was not retired")
	}
}

func TestUnresolvedRotationUsesCensoredMaximum(t *testing.T) {
	opt := &observingOptimizer{}
	m := &Manager{Optimizer: opt, Log: logr.Discard()}
	startedAt := time.Unix(1_700_000_000, 0).UTC()
	view := &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "old", UID: "old-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs",
	}}
	m.trackRotation("tenant-a", view, map[string]*model.WorkloadView{"ns/old": view}, startedAt)
	m.trackRotation("tenant-a", view, map[string]*model.WorkloadView{"ns/old": view}, startedAt.Add(time.Minute))
	for _, pending := range m.pendingRotations {
		if !pending.startedAt.Equal(startedAt) {
			t.Fatalf("repeated emit reset recovery clock to %s; want first emit %s", pending.startedAt, startedAt)
		}
	}
	m.observeReadyRotations(&ingest.Snapshot{Now: startedAt.Add(2 * cost.ReadyDelayReference)})
	if len(opt.observations) != 1 || opt.observations[0].flow != 2 {
		t.Fatalf("censored observation = %+v, want one flow=2 record", opt.observations)
	}
}

func TestEmittedButUnexecutedRotationDoesNotTrain(t *testing.T) {
	opt := &observingOptimizer{}
	m := &Manager{Optimizer: opt, Log: logr.Discard()}
	startedAt := time.Unix(1_700_000_000, 0).UTC()
	view := &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "old", UID: "old-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs",
	}}
	m.trackRotation("tenant-a", view, map[string]*model.WorkloadView{"ns/old": view}, startedAt)
	m.observeReadyRotations(&ingest.Snapshot{Now: startedAt.Add(2 * cost.ReadyDelayReference), Pods: []model.Pod{{
		Namespace: "ns", UID: "old-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true,
	}}})
	if len(opt.observations) != 0 {
		t.Fatal("SecurityEvent emission trained the RLS even though the original pod UID was never deleted")
	}
	if len(m.pendingRotations) != 0 {
		t.Fatal("expired unexecuted rotation was not retired")
	}
}

var _ actuator.Actuator = (*fakeActuator)(nil)
