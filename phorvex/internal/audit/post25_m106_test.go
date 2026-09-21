package audit

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestPost25M106PersistenceLearningSurvivesTraceOffAudit(t *testing.T) {
	decision := model.Decision{Tenant: "tenant", Namespace: "ns", Pod: "pod", PersistenceLearning: &model.PersistenceLearningStatus{
		SchemaVersion:   model.PersistenceLearningSchemaV1,
		Source:          "fixture-effect-observer",
		Disposition:     model.PersistenceDispositionApplied,
		Policy:          &model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 4},
		EvidenceID:      "evidence-1",
		Outcome:         model.PersistenceRevoked,
		QualifiedLabels: 1,
		RevokedLabels:   1,
		DedupEntries:    1,
		DedupCapacity:   8,
	}}
	record := ToRecord(decision)
	if record.DecisionTrace != nil || record.PersistenceLearning == nil {
		t.Fatalf("trace-off learning provenance missing: %+v", record)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Record
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PersistenceLearning == nil || !reflect.DeepEqual(decoded.PersistenceLearning, decision.PersistenceLearning) {
		t.Fatalf("learning provenance changed across audit wire: got=%+v want=%+v", decoded.PersistenceLearning, decision.PersistenceLearning)
	}
	decision.PersistenceLearning.Source = "mutated-after-record"
	decision.PersistenceLearning.Policy.UID = "mutated-policy"
	if decoded.PersistenceLearning.Source != "fixture-effect-observer" || record.PersistenceLearning.Source != "fixture-effect-observer" ||
		record.PersistenceLearning.Policy.UID != "policy-uid" {
		t.Fatal("audit record aliased mutable decision learning metadata")
	}
}

func TestPost25M106AuditRejectsInvalidLearningProvenance(t *testing.T) {
	for name, status := range map[string]*model.PersistenceLearningStatus{
		"unknown disposition":  {SchemaVersion: model.PersistenceLearningSchemaV1, Source: "source", Disposition: "invented", DedupCapacity: 1},
		"contradictory counts": {SchemaVersion: model.PersistenceLearningSchemaV1, Source: "source", Disposition: model.PersistenceDispositionApplied, QualifiedLabels: 2, HeldLabels: 1, DedupCapacity: 1},
		"unknown outcome":      {SchemaVersion: model.PersistenceLearningSchemaV1, Source: "source", Disposition: model.PersistenceDispositionRejected, Outcome: "maybe", DedupCapacity: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := json.Marshal(Record{PersistenceLearning: status}); err == nil {
				t.Fatal("invalid persistence learning provenance was serialized")
			}
		})
	}
}
