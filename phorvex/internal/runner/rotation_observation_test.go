package runner

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/calib"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/slo"
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

func TestSameSecondReadyTimestampIsAcceptedAtKubernetesPrecision(t *testing.T) {
	opt := &observingOptimizer{}
	m := &Manager{Optimizer: opt, Log: logr.Discard()}
	startedAt := time.Date(2026, 8, 2, 12, 28, 17, 600_000_000, time.UTC)
	view := &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "old", UID: "old-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs",
	}}
	m.trackRotation("tenant-a", view, map[string]*model.WorkloadView{"ns/old": view}, startedAt)

	// A candidate from an earlier whole timestamp second still predates the action.
	m.observeReadyRotations(&ingest.Snapshot{Now: startedAt.Add(100 * time.Millisecond), Pods: []model.Pod{{
		Namespace: "ns", UID: "stale-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true,
		ReadyAt: startedAt.Truncate(time.Second).Add(-time.Second),
	}}})
	if len(opt.observations) != 0 || len(m.pendingRotations) != 1 {
		t.Fatalf("earlier-second candidate was accepted: observations=%d pending=%d", len(opt.observations), len(m.pendingRotations))
	}

	// The Kubernetes API rounds this genuine sub-second recovery down to the same
	// whole second as the action. It must be accepted, with the negative rounding
	// artifact clamped to the model's zero-cost boundary.
	m.observeReadyRotations(&ingest.Snapshot{Now: startedAt.Add(500 * time.Millisecond), Pods: []model.Pod{{
		Namespace: "ns", UID: "replacement-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true,
		ReadyAt: startedAt.Truncate(time.Second),
	}}})
	if len(opt.observations) != 1 || opt.observations[0].flow != 0 {
		t.Fatalf("same-second observation = %+v, want one flow=0 record", opt.observations)
	}
	if len(m.pendingRotations) != 0 {
		t.Fatal("same-second replacement observation was not retired")
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

func TestPendingRotationFreezesReferenceAndCensorDeadline(t *testing.T) {
	opt := &observingOptimizer{}
	m := &Manager{Optimizer: opt, Log: logr.Discard()}
	startedAt := time.Unix(1_700_000_000, 0).UTC()
	view := &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "old", UID: "old-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs",
	}}
	m.trackRotation("tenant-a", view, map[string]*model.WorkloadView{"ns/old": view}, startedAt)
	m.trackRotation("tenant-a", view, map[string]*model.WorkloadView{"ns/old": view}, startedAt.Add(time.Minute))

	for _, pending := range m.pendingRotations {
		if pending.referenceAtStart != cost.ReadyDelayReference {
			t.Fatalf("frozen reference = %v, want %v", pending.referenceAtStart, cost.ReadyDelayReference)
		}
		if want := startedAt.Add(2 * cost.ReadyDelayReference); !pending.censorDeadline.Equal(want) {
			t.Fatalf("censor deadline = %v, want frozen %v", pending.censorDeadline, want)
		}
	}
}

func TestShadowCalibrationReceivesObservedCensoredAndInvalidRotations(t *testing.T) {
	runtime := calib.NewRuntime(calib.RuntimeConfig{}, logr.Discard())
	startedAt := time.Unix(1_700_000_000, 0).UTC()
	view := &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "old", UID: "old-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs",
	}}

	observed := &Manager{Optimizer: &observingOptimizer{}, Log: logr.Discard(), Calibration: runtime}
	observed.trackRotation("tenant-a", view, map[string]*model.WorkloadView{"ns/old": view}, startedAt)
	observed.observeReadyRotations(&ingest.Snapshot{Now: startedAt.Add(70 * time.Second), Pods: []model.Pod{{
		Namespace: "ns", UID: "new-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true,
		ReadyAt: startedAt.Add(60 * time.Second),
	}}})

	censored := &Manager{Optimizer: &observingOptimizer{}, Log: logr.Discard(), Calibration: runtime}
	censored.trackRotation("tenant-b", view, map[string]*model.WorkloadView{"ns/old": view}, startedAt)
	censored.observeReadyRotations(&ingest.Snapshot{Now: startedAt.Add(2 * cost.ReadyDelayReference)})

	invalid := &Manager{Optimizer: &observingOptimizer{}, Log: logr.Discard(), Calibration: runtime}
	invalid.trackRotation("tenant-c", &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "ownerless"}}, nil, startedAt)

	records := runtime.RotationRecords(startedAt.Add(2 * cost.ReadyDelayReference))
	if len(records) != 3 {
		t.Fatalf("rotation records = %+v, want three outcomes", records)
	}
	want := map[calib.Outcome]bool{calib.OutcomeObserved: true, calib.OutcomeCensored: true, calib.OutcomeInvalid: true}
	for _, record := range records {
		delete(want, record.Outcome)
		if record.ReferenceAtStart != cost.ReadyDelayReference || !record.CensorDeadline.Equal(record.StartedAt.Add(2*cost.ReadyDelayReference)) {
			t.Fatalf("record did not preserve frozen reference/deadline: %+v", record)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing outcomes: %+v", want)
	}
}

func TestCensoredRotationContinuesUpdatingDisruptionUntilRecovery(t *testing.T) {
	opt := &observingOptimizer{}
	ledger := slo.NewLedger(0)
	m := &Manager{Optimizer: opt, Log: logr.Discard(), Disruption: ledger}
	startedAt := time.Unix(1_700_000_000, 0).UTC()
	view := &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "old", UID: "old-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs",
	}}
	m.trackRotation("tenant-a", view, map[string]*model.WorkloadView{"ns/old": view}, startedAt)

	m.observeReadyRotations(&ingest.Snapshot{Now: startedAt.Add(800 * time.Second)})
	if got := ledger.Consumed("tenant-a", startedAt); got != 800 {
		t.Fatalf("first censored floor = %v, want 800 replica-seconds", got)
	}
	if len(m.pendingRotations) != 1 {
		t.Fatal("ledger-enabled censored rotation was retired before recovery")
	}

	m.observeReadyRotations(&ingest.Snapshot{Now: startedAt.Add(1200 * time.Second)})
	if got := ledger.Consumed("tenant-a", startedAt); got != 1200 {
		t.Fatalf("extended censored floor = %v, want 1200 replica-seconds", got)
	}
	if len(opt.observations) != 1 {
		t.Fatalf("RLS censoring was counted %d times, want once", len(opt.observations))
	}

	m.observeReadyRotations(&ingest.Snapshot{
		Now: startedAt.Add(1400 * time.Second),
		Pods: []model.Pod{{
			Namespace: "ns", Name: "new", UID: "new-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs",
			Ready: true, ReadyAt: startedAt.Add(1300 * time.Second),
		}},
	})
	if got := ledger.Consumed("tenant-a", startedAt); got != 1300 {
		t.Fatalf("final disruption = %v, want measured 1300 replica-seconds", got)
	}
	entries := ledger.Entries("tenant-a", startedAt)
	if len(entries) != 1 || entries[0].Censored {
		t.Fatalf("final recovery did not replace censored entry: %+v", entries)
	}
	if len(m.pendingRotations) != 0 {
		t.Fatal("recovered disruption remained pending")
	}
}

func TestRecoveryAfterFrozenDeadlineIsCensoredForCalibrationButMeasuredForLedger(t *testing.T) {
	opt := &observingOptimizer{}
	ledger := slo.NewLedger(0)
	runtime := calib.NewRuntime(calib.RuntimeConfig{}, logr.Discard())
	m := &Manager{Optimizer: opt, Log: logr.Discard(), Disruption: ledger, Calibration: runtime}
	startedAt := time.Unix(1_700_000_000, 0).UTC()
	view := &model.WorkloadView{Pod: model.Pod{
		Namespace: "ns", Name: "old", UID: "old-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs",
	}}
	m.trackRotation("tenant-a", view, map[string]*model.WorkloadView{"ns/old": view}, startedAt)
	m.observeReadyRotations(&ingest.Snapshot{
		Now: startedAt.Add(900 * time.Second),
		Pods: []model.Pod{{
			Namespace: "ns", Name: "new", UID: "new-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs",
			Ready: true, ReadyAt: startedAt.Add(850 * time.Second),
		}},
	})

	records := runtime.RotationRecords(startedAt.Add(900 * time.Second))
	if len(records) != 1 || records[0].Outcome != calib.OutcomeCensored || records[0].Elapsed != 800*time.Second {
		t.Fatalf("calibration outcome = %+v, want one frozen 800s right-censored record", records)
	}
	if len(opt.observations) != 1 || opt.observations[0].flow != 2 {
		t.Fatalf("RLS outcome = %+v, want one censored flow=2", opt.observations)
	}
	entries := ledger.Entries("tenant-a", startedAt)
	if len(entries) != 1 || entries[0].Censored || entries[0].Duration != 850*time.Second {
		t.Fatalf("ledger outcome = %+v, want final measured 850s recovery", entries)
	}
	if len(m.pendingRotations) != 0 {
		t.Fatal("late recovered rotation remained pending")
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
