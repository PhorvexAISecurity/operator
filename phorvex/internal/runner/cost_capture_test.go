package runner

import (
	"encoding/json"
	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/slo"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCostEvidenceRealOutcomeProducerNeverQualifiesEndpointLoss(t *testing.T) {
	at := time.Now().UTC().Add(time.Second)
	m := &Manager{Disruption: slo.NewLedger(time.Hour)}
	pol := model.Policy{Tenant: "t", Namespace: "ns", PolicyUID: "policy"}
	v := &model.WorkloadView{Pod: model.Pod{Name: "p", Namespace: "ns", UID: "pu", WorkloadSpec: model.WorkloadSpecObservation{Known: true, SpecReplicas: 4, Workload: model.ObjectIdentity{UID: "wu"}}}}
	if got := m.replayCostEvidence([]*model.WorkloadView{v}, pol, v1alpha1.PhorvexPolicySpec{}, at); got != nil {
		t.Fatal("capture must default off")
	}
	m.recordActionOutcome("t", v, model.ActionQuarantine, 1, at.Add(-time.Second), at, slo.OutcomeEmitted, pol.Owner())
	m.CaptureCostEvidence = true
	got := m.replayCostEvidence([]*model.WorkloadView{v}, pol, v1alpha1.PhorvexPolicySpec{}, at)
	if got.EndpointLossStatus != "unavailable" || got.AdmissionLedgerStatus != "not-authoritative" || got.ReplicaHistory.HistoryComplete || !slices.Contains(got.Missing, "accepted-slo-window:unavailable") {
		t.Fatalf("replica evidence was promoted: %+v", got)
	}
	if len(got.ReplicaHistory.Entries) != 1 {
		t.Fatal(got.ReplicaHistory)
	}
	row := got.ReplicaHistory.Entries[0]
	if row.PolicyOwner != pol.Owner() || row.PodUID != "pu" || row.WorkloadUID != "wu" || row.Outcome != slo.OutcomeEmitted || row.ReplicaImpact != slo.ImpactUnmeasured {
		t.Fatalf("real outcome producer lost provenance: %+v", row)
	}
	v.Pod.WorkloadSpec.Workload.UID = "changed"
	if got.Workloads[0].Observation.Workload.UID != "wu" {
		t.Fatal("capture references live view")
	}
	// The real unconfirmed-rotation producer also preserves attribution, without
	// upgrading an emitted action to observed recovery or endpoint history.
	p := pendingRotation{ledgerID: "rotation", tenant: "t", owner: pol.Owner(), view: *v, startedAt: at.Add(-time.Second)}
	m.recordUnknownRotation(p, at)
	next := m.replayCostEvidence([]*model.WorkloadView{v}, pol, v1alpha1.PhorvexPolicySpec{}, at)
	if len(next.ReplicaHistory.Entries) != 2 || next.EndpointLossStatus != "unavailable" {
		t.Fatal(next)
	}
	m.Disruption = nil
	if missing := m.replayCostEvidence(nil, pol, v1alpha1.PhorvexPolicySpec{}, at); missing.ReplicaHistory.Available || !slices.Contains(missing.Missing, "replica-history:unavailable") {
		t.Fatal(missing)
	}
}

func TestCostEvidenceCountAndByteLimitsRemainUnavailable(t *testing.T) {
	m := &Manager{CaptureCostEvidence: true}
	pol := model.Policy{Tenant: "t", Namespace: "ns", PolicyUID: "p"}
	got := m.replayCostEvidence(make([]*model.WorkloadView, 1000), pol, v1alpha1.PhorvexPolicySpec{}, time.Now())
	if !got.WorkloadsTruncated || len(got.Missing) > 280 || got.EndpointLossStatus != "unavailable" {
		t.Fatalf("nil views bypassed bound: %+v", got)
	}
	v := &model.WorkloadView{Pod: model.Pod{UID: "pod", WorkloadSpec: model.WorkloadSpecObservation{Reason: strings.Repeat("x", slo.MaxReplayEvidenceBytes)}}}
	got = m.replayCostEvidence([]*model.WorkloadView{v}, pol, v1alpha1.PhorvexPolicySpec{}, time.Now())
	raw, err := json.Marshal(got)
	if err != nil || len(raw) > slo.MaxReplayEvidenceBytes || !got.CaptureByteLimit || !got.WorkloadsTruncated || !got.ReplicaHistory.Truncated || got.EndpointLossStatus != "unavailable" || got.ReplicaHistory.HistoryComplete {
		t.Fatalf("byte cap lost missing status: %+v %v", got, err)
	}
}
