package runner

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/sensorapi"
)

func m009Pending(t *testing.T, m *Manager, started time.Time) pendingRotation {
	t.Helper()
	result := actuator.Result{Actuator: "phoenix", EventName: "phorvex-rotate-a", EventUID: "event-uid-a", Emitted: true}
	return m009PendingResult(t, m, started, result)
}

func m009PendingResult(t *testing.T, m *Manager, started time.Time, result actuator.Result) pendingRotation {
	t.Helper()
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "old", UID: "old-uid", OwnerKind: "ReplicaSet", OwnerName: "api-rs"}}
	if !m.trackRotationReceipt(model.OwnerKey(model.OwnerKindName, "tenant"), "tenant", view,
		map[string]*model.WorkloadView{"ns/old": view}, 1, started, result, "decision-a") {
		t.Fatal("Phoenix receipt was not tracked")
	}
	for _, p := range m.pendingRotations {
		return p
	}
	t.Fatal("pending receipt missing")
	return pendingRotation{}
}

func m009Receipt(p pendingRotation, processed time.Time) model.PhoenixExecutionReceipt {
	return model.PhoenixExecutionReceipt{
		EventName: p.phoenixEventName, EventUID: p.phoenixEventUID,
		RuleType: amtdv1beta1.PhorvexRuleTypeRotate, ThreatLevel: amtdv1beta1.PhorvexRuleThreatLevel, RuleSource: amtdv1beta1.PhorvexRuleSource,
		Targets: []string{p.view.Pod.Namespace + "/" + p.view.Pod.Name}, TargetUID: p.view.Pod.UID,
		AppliedAction: "rotate", CreatedAt: p.startedAt.Add(time.Second), ProcessedAt: processed,
	}
}

func TestM009LegacyAcceptedEventWithoutReceiptDoesNotTrain(t *testing.T) {
	var out bytes.Buffer
	opt := &observingOptimizer{}
	m := &Manager{Optimizer: opt, Log: logr.Discard(), Audit: audit.New(logr.Discard(), &out)}
	started := time.Unix(1_800_000_000, 0).UTC()
	// Current pure-Phoenix rotate dispatch is refused because its Delete strategy
	// cannot carry the policy grace cap. This fixture retains a historical accepted
	// event to prove that an uncorrelated replacement still cannot train the model.
	result := actuator.Result{
		Actuator: "phoenix", EventName: "phorvex-rotate-a", EventUID: "event-uid-a",
		RuleType: amtdv1beta1.PhorvexRuleTypeRotate, RuleThreatLevel: amtdv1beta1.PhorvexRuleThreatLevel,
		RuleSource: amtdv1beta1.PhorvexRuleSource, Emitted: true,
	}
	p := m009PendingResult(t, m, started, result)
	m.observeReadyRotations(&sensorapi.Observation{
		Now: started.Add(2 * cost.ReadyDelayReference), PhoenixReceiptInventoryComplete: true,
		PhoenixReceipts: map[string]model.PhoenixExecutionReceipt{},
		Pods:            []model.Pod{{Namespace: "ns", Name: "new", UID: "external-rollout", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true, ReadyAt: started.Add(time.Minute)}},
	})
	if len(opt.observations) != 0 || len(m.pendingRotations) != 0 {
		t.Fatalf("unprocessed event learned replacement: observations=%v pending=%d", opt.observations, len(m.pendingRotations))
	}
	if body := out.String(); !strings.Contains(body, `"kind":"phorvex.actuation-observation"`) ||
		!strings.Contains(body, `"eventUID":"`+p.phoenixEventUID+`"`) ||
		!strings.Contains(body, `"outcome":"unconfirmed-execution"`) {
		t.Fatalf("missing correlated unconfirmed audit: %s", body)
	}
}

func TestM009ExactReceiptAndReadyReplacementTrain(t *testing.T) {
	var out bytes.Buffer
	opt := &observingOptimizer{}
	m := &Manager{Optimizer: opt, Log: logr.Discard(), Audit: audit.New(logr.Discard(), &out)}
	started := time.Unix(1_800_000_000, 0).UTC()
	p := m009Pending(t, m, started)
	receipt := m009Receipt(p, started.Add(2*time.Second))
	m.observeReadyRotations(&sensorapi.Observation{
		Now: started.Add(30 * time.Second), PhoenixReceiptInventoryComplete: true,
		PhoenixReceipts: map[string]model.PhoenixExecutionReceipt{receipt.EventName: receipt},
		Pods:            []model.Pod{{Namespace: "ns", Name: "new", UID: "replacement", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true, ReadyAt: started.Add(20 * time.Second)}},
	})
	if len(opt.observations) != 1 || len(m.pendingRotations) != 0 {
		t.Fatalf("exact receipt did not resolve: observations=%v pending=%d", opt.observations, len(m.pendingRotations))
	}
	if body := out.String(); !strings.Contains(body, `"outcome":"confirmed-execution-recovery"`) ||
		!strings.Contains(body, `"outcome":"confirmed-execution-recovery-pending"`) ||
		!strings.Contains(body, `"executionConfirmed":true`) || !strings.Contains(body, `"recoveryConfirmed":true`) {
		t.Fatalf("missing confirmed audit: %s", body)
	}
}

func TestM009WrongReceiptFieldsNeverConfirm(t *testing.T) {
	for _, mutate := range []func(*model.PhoenixExecutionReceipt){
		func(r *model.PhoenixExecutionReceipt) { r.EventName = "other-event" },
		func(r *model.PhoenixExecutionReceipt) { r.EventUID = "recreated" },
		func(r *model.PhoenixExecutionReceipt) { r.RuleType = "timed" },
		func(r *model.PhoenixExecutionReceipt) { r.ThreatLevel = "critical" },
		func(r *model.PhoenixExecutionReceipt) { r.RuleSource = "external" },
		func(r *model.PhoenixExecutionReceipt) { r.AppliedAction = "quarantine" },
		func(r *model.PhoenixExecutionReceipt) { r.TargetUID = "replacement" },
		func(r *model.PhoenixExecutionReceipt) { r.Targets = []string{"ns/other"} },
		func(r *model.PhoenixExecutionReceipt) { r.Targets = append(r.Targets, "ns/other") },
		func(r *model.PhoenixExecutionReceipt) { r.ProcessedAt = time.Time{} },
		func(r *model.PhoenixExecutionReceipt) { r.CreatedAt = time.Time{} },
		func(r *model.PhoenixExecutionReceipt) {
			r.CreatedAt = r.CreatedAt.Add(-2 * time.Second)
		},
		func(r *model.PhoenixExecutionReceipt) {
			r.ProcessedAt = r.CreatedAt.Add(-time.Second)
		},
		func(r *model.PhoenixExecutionReceipt) {
			r.ProcessedAt = r.ProcessedAt.Add(2 * cost.ReadyDelayReference)
		},
	} {
		m := &Manager{Optimizer: &observingOptimizer{}, Log: logr.Discard()}
		started := time.Unix(1_800_000_000, 0).UTC()
		p := m009Pending(t, m, started)
		r := m009Receipt(p, started.Add(time.Second))
		mutate(&r)
		if phoenixRotationReceiptConfirmed(p, &sensorapi.Observation{Now: started.Add(3 * time.Second), PhoenixReceiptInventoryComplete: true, PhoenixReceipts: map[string]model.PhoenixExecutionReceipt{p.phoenixEventName: r}}) {
			t.Fatalf("invalid receipt confirmed: %+v", r)
		}
	}
}

func TestM009ReceiptUsesKubernetesTimestampPrecisionAndRejectsFuture(t *testing.T) {
	started := time.Unix(1_800_000_000, 900_000_000).UTC()
	m := &Manager{Log: logr.Discard()}
	p := m009Pending(t, m, started)
	r := m009Receipt(p, started.Truncate(time.Second).Add(time.Second))
	snap := &ingest.Snapshot{Now: started.Add(2 * time.Second), PhoenixReceiptInventoryComplete: true,
		PhoenixReceipts: map[string]model.PhoenixExecutionReceipt{r.EventName: r}}
	if !phoenixRotationReceiptConfirmed(p, observationOf(snap)) {
		t.Fatal("same-wire-second receipt was rejected against nanosecond dispatch time")
	}
	r.ProcessedAt = snap.Now.Add(time.Second)
	snap.PhoenixReceipts[r.EventName] = r
	if phoenixRotationReceiptConfirmed(p, observationOf(snap)) {
		t.Fatal("future receipt timestamp was accepted")
	}
}

func TestM009IncompleteReceiptInventoryNeverConfirms(t *testing.T) {
	started := time.Unix(1_800_000_000, 0).UTC()
	m := &Manager{Log: logr.Discard()}
	p := m009Pending(t, m, started)
	r := m009Receipt(p, started.Add(time.Second))
	if phoenixRotationReceiptConfirmed(p, &sensorapi.Observation{Now: started.Add(2 * time.Second), PhoenixReceipts: map[string]model.PhoenixExecutionReceipt{r.EventName: r}}) {
		t.Fatal("receipt confirmed while cluster-wide event inventory was unavailable")
	}
}

func TestM009PhoenixObservationRunsWithoutLearningConsumers(t *testing.T) {
	var out bytes.Buffer
	m := &Manager{Log: logr.Discard(), Audit: audit.New(logr.Discard(), &out)}
	started := time.Unix(1_800_000_000, 0).UTC()
	p := m009Pending(t, m, started)
	r := m009Receipt(p, started.Add(time.Second))
	m.observeReadyRotations(&sensorapi.Observation{Now: started.Add(2 * time.Second), PhoenixReceiptInventoryComplete: true,
		PhoenixReceipts: map[string]model.PhoenixExecutionReceipt{r.EventName: r}, Pods: []model.Pod{{Namespace: "ns", UID: "new", OwnerKind: "ReplicaSet", OwnerName: "api-rs", Ready: true, ReadyAt: started.Add(time.Second)}}})
	if !strings.Contains(out.String(), `"kind":"phorvex.actuation-observation"`) {
		t.Fatalf("observer-disabled path omitted audit: %s", out.String())
	}
}
