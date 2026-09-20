package runner

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"k8s.io/apimachinery/pkg/types"
)

type m106RunnerAuthority struct {
	binding model.PersistenceOperationBinding
}

func (a m106RunnerAuthority) Source() string { return "runner-fixture-observer" }
func (a m106RunnerAuthority) AuthorizeObservation(observation model.PersistenceObservation) (model.PersistenceOperationBinding, bool) {
	return a.binding, observation.OperationID == a.binding.OperationID && observation.Outcome == model.PersistenceHeld && observation.EvidenceID == "evidence"
}

func TestPost25M106ManagerRegistersExactPolicyEpoch(t *testing.T) {
	engine := decision.NewCoverageEngine()
	entry := &policyEntry{namespace: "ns", key: types.NamespacedName{Namespace: "ns", Name: "policy"}, uid: "policy-uid", generation: 9, tenant: "tenant"}
	manager := &Manager{Optimizer: engine, policies: map[string]*policyEntry{entry.key.String(): entry}}
	manager.syncOwnerLiveness()

	policy := buildPolicy(entry)
	if policy.PolicyGeneration != entry.generation || policy.PolicyUID != entry.uid || policy.PolicyName != entry.key.Name {
		t.Fatalf("resolved policy lost exact epoch: %+v", policy)
	}
	status, allocated := engine.PersistenceLearningStatusFor(policy.Owner())
	wantEpoch := model.PolicyEpoch{Namespace: policy.Namespace, Name: policy.PolicyName, UID: policy.PolicyUID, Generation: policy.PolicyGeneration}
	if allocated || status.Source != "none" || status.Disposition != model.PersistenceDispositionNoProducer || status.QualifiedLabels != 0 ||
		status.Policy == nil || *status.Policy != wantEpoch {
		t.Fatalf("initial manager wiring invented a qualified label producer: %+v allocated=%t", status, allocated)
	}

	now := time.Date(2026, 9, 20, 23, 0, 0, 0, time.UTC)
	epoch := wantEpoch
	binding := model.PersistenceOperationBinding{Policy: epoch, OperationID: "operation", TargetUID: "old-target-uid", Capability: "persistence", Scope: "pod/process", ObservationNotBefore: now.Add(-time.Hour), ObservationDeadline: now.Add(time.Hour)}
	engine.Now = func() time.Time { return now }
	engine.PersistenceAuthority = m106RunnerAuthority{binding: binding}
	result := engine.AdmitPersistenceObservation(model.PersistenceObservation{
		SchemaVersion: model.PersistenceObservationSchemaV1, Source: "runner-fixture-observer", EvidenceID: "evidence",
		Policy: epoch, OperationID: binding.OperationID, TargetUID: binding.TargetUID, Capability: binding.Capability, Scope: binding.Scope,
		ObservationStart: now.Add(-30 * time.Minute), ObservationEnd: now.Add(-time.Minute), Outcome: model.PersistenceHeld,
	})
	if !result.Applied || result.Status.QualifiedLabels != 1 {
		t.Fatalf("manager did not register the exact active epoch: %+v", result)
	}
}
