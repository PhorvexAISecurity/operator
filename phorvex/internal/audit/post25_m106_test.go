package audit

import (
	"encoding/json"
	"reflect"
	"strings"
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

func TestPost25M106ScopedOutcomeSurvivesTraceOffAuditWithoutLegacyRelabel(t *testing.T) {
	lower, upper := model.Wilson95(1, 1)
	decision := model.Decision{Tenant: "tenant", Namespace: "ns", Pod: "pod", ScopedOutcomes: &model.ScopedOutcomeReport{
		SchemaVersion: model.ScopedOutcomeReportSchemaV1, Source: model.ScopedSessionCapability, ProcessEpochID: "process-epoch",
		ResetBoundary: "process-start", Disposition: model.PersistenceDispositionApplied,
		Policy: &model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 4}, EvidenceID: "evidence", Outcome: model.PersistenceHeld,
		Cohorts: []model.ScopedOutcomeCohort{{
			Key:  model.ScopedOutcomeCohortKey{PolicyUID: "policy-uid", PolicyGeneration: 4, WorkloadScopeSHA256: strings.Repeat("a", 64), Capability: model.ScopedSessionCapability, Action: model.ActionRotate, ContractVersion: model.ScopedSessionNativeRotateV1},
			Held: 1, N: 1, PriorAlpha: 1, PriorBeta: 1, PosteriorMean: 2.0 / 3.0,
			RawHeldInterval: &model.ScopedOutcomeInterval{Method: model.ScopedOutcomeIntervalWilson95, Lower: lower, Upper: upper},
		}}, ReplayEntries: 1, ReplayCapacity: model.ScopedOutcomeEvidenceCapacity, CohortCapacity: model.ScopedOutcomeCohortCapacity,
		LifetimeOwners: 1, LifetimeOwnerCapacity: model.ScopedOutcomeOwnerCapacity,
	}}
	record := ToRecord(decision)
	if record.DecisionTrace != nil || record.ScopedOutcomes == nil || record.PersistenceLearning != nil {
		t.Fatalf("trace-off scoped report was omitted or relabelled: %+v", record)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Record
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.ScopedOutcomes, decision.ScopedOutcomes) {
		t.Fatalf("scoped report changed across audit wire: got=%+v want=%+v", decoded.ScopedOutcomes, decision.ScopedOutcomes)
	}
	decision.ScopedOutcomes.Policy.UID = "mutated"
	decision.ScopedOutcomes.Cohorts[0].RawHeldInterval.Lower = .5
	if record.ScopedOutcomes.Policy.UID != "policy-uid" || record.ScopedOutcomes.Cohorts[0].RawHeldInterval.Lower != lower {
		t.Fatal("audit record aliases mutable scoped outcome metadata")
	}
}

func TestPost25M106AuditRejectsInvalidScopedOutcomeClaims(t *testing.T) {
	valid := model.ScopedOutcomeReport{SchemaVersion: model.ScopedOutcomeReportSchemaV1, Source: model.ScopedSessionCapability,
		ProcessEpochID: "epoch", ResetBoundary: "process-start", Disposition: model.PersistenceDispositionNoLabel,
		Policy:         &model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "uid", Generation: 1},
		ReplayCapacity: model.ScopedOutcomeEvidenceCapacity, CohortCapacity: model.ScopedOutcomeCohortCapacity,
		LifetimeOwnerCapacity: model.ScopedOutcomeOwnerCapacity}
	setOne := func(r *model.ScopedOutcomeReport) {
		lower, upper := model.Wilson95(1, 1)
		r.Disposition, r.EvidenceID, r.Outcome, r.ReplayEntries = model.PersistenceDispositionApplied, "evidence", model.PersistenceHeld, 1
		r.Cohorts = []model.ScopedOutcomeCohort{{
			Key:  model.ScopedOutcomeCohortKey{PolicyUID: "uid", PolicyGeneration: 1, WorkloadScopeSHA256: strings.Repeat("a", 64), Capability: model.ScopedSessionCapability, Action: model.ActionRotate, ContractVersion: model.ScopedSessionNativeRotateV1},
			Held: 1, N: 1, PriorAlpha: 1, PriorBeta: 1, PosteriorMean: 2.0 / 3.0,
			RawHeldInterval: &model.ScopedOutcomeInterval{Method: model.ScopedOutcomeIntervalWilson95, Lower: lower, Upper: upper},
		}}
	}
	for name, mutate := range map[string]func(*model.ScopedOutcomeReport){
		"calibrated": func(r *model.ScopedOutcomeReport) {
			setOne(r)
			r.Cohorts[0].Calibrated = true
		},
		"wrong reset boundary":          func(r *model.ScopedOutcomeReport) { r.ResetBoundary = "durable" },
		"contradictory replay capacity": func(r *model.ScopedOutcomeReport) { r.ReplayEntries = r.ReplayCapacity + 1 },
		"cohort exceeds replay bound": func(r *model.ScopedOutcomeReport) {
			setOne(r)
			r.Cohorts[0].Held = int(^uint(0) >> 1)
			r.Cohorts[0].N = r.Cohorts[0].Held
		},
		"cohort sum contradicts replay entries": func(r *model.ScopedOutcomeReport) {
			setOne(r)
			r.ReplayEntries = 0
		},
		"no-label carries counts": func(r *model.ScopedOutcomeReport) {
			setOne(r)
			r.Disposition, r.EvidenceID, r.Outcome = model.PersistenceDispositionNoLabel, "", ""
		},
		"no-producer carries retained cohort": func(r *model.ScopedOutcomeReport) {
			setOne(r)
			r.Disposition, r.Source, r.ProcessEpochID, r.EvidenceID, r.Outcome = model.PersistenceDispositionNoProducer, "none", "unconfigured", "", ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := json.Marshal(Record{ScopedOutcomes: &candidate}); err == nil {
				t.Fatal("invalid scoped outcome report was serialized")
			}
		})
	}
}
