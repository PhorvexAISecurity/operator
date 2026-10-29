package console

import (
	"slices"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/attackcatalog"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

type auditReceiptConformanceFixture struct {
	id, family, helper string
	record             audit.Record
	evaluate           func(audit.Record) (bool, AttackCatalogActuatorResult)
}

type auditReceiptMutation struct {
	name   string
	mutate func(*audit.Record)
}

func cloneReceiptAuditRecord(record audit.Record) audit.Record {
	cloned := record
	cloned.Events = slices.Clone(record.Events)
	cloned.ObjectsTouched = slices.Clone(record.ObjectsTouched)
	if record.DecisionTrace != nil {
		trace := *record.DecisionTrace
		cloned.DecisionTrace = &trace
	}
	if record.GracefulTermination != nil {
		termination := *record.GracefulTermination
		cloned.GracefulTermination = &termination
	}
	return cloned
}

func receiptAuditMutations() []auditReceiptMutation {
	return []auditReceiptMutation{
		{name: "missing-top-level-dispatch", mutate: func(row *audit.Record) { row.DispatchOutcome = "" }},
		{name: "missing-trace-dispatch", mutate: func(row *audit.Record) { row.DecisionTrace.DispatchOutcome = "" }},
		{name: "missing-both-dispatches", mutate: func(row *audit.Record) {
			row.DispatchOutcome, row.DecisionTrace.DispatchOutcome = "", ""
		}},
		{name: "top-level-emitted-trace-rejected", mutate: func(row *audit.Record) {
			row.DispatchOutcome, row.DecisionTrace.DispatchOutcome = model.DispatchEmitted, model.DispatchRefused
		}},
		{name: "top-level-rejected-trace-emitted", mutate: func(row *audit.Record) {
			row.DispatchOutcome, row.DecisionTrace.DispatchOutcome = model.DispatchRefused, model.DispatchEmitted
		}},
		{name: "rejected-dispatch-with-actuation", mutate: func(row *audit.Record) {
			row.DispatchOutcome, row.DecisionTrace.DispatchOutcome = model.DispatchRefused, model.DispatchRefused
		}},
		{name: "non-emitted-dispatch-with-actuation", mutate: func(row *audit.Record) {
			row.DispatchOutcome, row.DecisionTrace.DispatchOutcome = model.DispatchError, model.DispatchError
		}},
		{name: "top-level-active-trace-dry-run", mutate: func(row *audit.Record) { row.DecisionTrace.DryRun = true }},
		{name: "top-level-dry-run-trace-active", mutate: func(row *audit.Record) { row.DryRun = true }},
		{name: "dry-run-both", mutate: func(row *audit.Record) { row.DryRun, row.DecisionTrace.DryRun = true, true }},
		{name: "not-selected", mutate: func(row *audit.Record) { row.Selected = false }},
		{name: "not-feasible", mutate: func(row *audit.Record) { row.Feasible = false }},
		{name: "not-actuated", mutate: func(row *audit.Record) { row.Actuated = false }},
		{name: "wrong-id-action-contract", mutate: func(row *audit.Record) {
			row.Action, row.DecisionTrace.SelectedAction = "other-action", "other-action"
		}},
		{name: "trace-action-disagreement", mutate: func(row *audit.Record) { row.DecisionTrace.SelectedAction = "other-action" }},
		{name: "wrong-handler", mutate: func(row *audit.Record) { row.Handler = "other-handler" }},
		{name: "wrong-target", mutate: func(row *audit.Record) { row.DecisionTrace.AssetUID = "other-target" }},
		{name: "cross-run-signal", mutate: func(row *audit.Record) {
			row.Events[0].Name, row.Events[0].EventUID = "other-run-signal", "other-run-uid"
		}},
		{name: "wrong-receipt-target", mutate: func(row *audit.Record) { row.ObjectsTouched = []string{"Other/wrong/target"} }},
		{name: "stale-timestamp", mutate: func(row *audit.Record) { row.Time = time.Time{} }},
		{name: "fabricated-future-timestamp", mutate: func(row *audit.Record) { row.Time = time.Now().UTC().Add(time.Hour) }},
	}
}

func auditReceiptConformanceFixtures(t *testing.T) []auditReceiptConformanceFixture {
	t.Helper()
	fixtures := make([]auditReceiptConformanceFixture, 0, 166)

	retainedFixture, retainedSignal := identityCatalogFixtureAndSignal()
	fixtures = append(fixtures, auditReceiptConformanceFixture{
		id: attackcatalog.FirstID, family: string(identityCatalogueRotation), helper: "retained-identity",
		record: exactIdentityCatalogAudit(retainedFixture, retainedSignal),
		evaluate: func(row audit.Record) (bool, AttackCatalogActuatorResult) {
			observed, _, receipt := identityCatalogueDecision(row, retainedFixture, retainedSignal)
			return observed, receipt
		},
	})

	for _, factory := range newIdentityCatalogueAdapters() {
		profile := factory.profile
		binding := newIdentityTestBinding(profile)
		fixtures = append(fixtures, auditReceiptConformanceFixture{
			id: profile.ID, family: string(profile.Family), helper: "identity-family",
			record: identityTestDecision(profile, binding.prepared, binding.signal),
			evaluate: func(row audit.Record) (bool, AttackCatalogActuatorResult) {
				observed, _, receipt := identityFamilyCatalogueDecision(profile, row, binding.prepared, binding.signal)
				return observed, receipt
			},
		})
	}

	for _, profile := range infraCatalogueProfiles() {
		runtime := infraTestRuntimeFor(t, profile)
		fixtures = append(fixtures, auditReceiptConformanceFixture{
			id: profile.ID, family: profile.Family, helper: "infrastructure",
			record: infraTestDecisionRecord(profile, runtime.fixture, runtime.arm, runtime.signal),
			evaluate: func(row audit.Record) (bool, AttackCatalogActuatorResult) {
				observed, _, receipt := infraCatalogueDecision(row, profile, runtime.fixture, runtime.arm, runtime.signal)
				return observed, receipt
			},
		})
	}

	entries, err := attackcatalog.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		profile, err := k8sCatalogueProfileForFamily(entry.Family)
		if err != nil {
			continue
		}
		fixture := k8sCatalogueTestFixture(entry, profile, AttackCatalogExecutionActive, true)
		signal := k8sCatalogueSignal{Name: "catalog-k8s-conformance-" + entry.ID, UID: "event-uid-" + entry.ID,
			Creator: profile.DetectorIdentity, CreatedAt: time.Now().UTC().Add(-time.Second)}
		prepared := &k8sCataloguePreparation{entry: entry, profile: profile, fixture: fixture, signal: signal}
		fixtures = append(fixtures, auditReceiptConformanceFixture{
			id: entry.ID, family: entry.Family, helper: "kubernetes",
			record: k8sCatalogueTestAudit(entry, profile, fixture, signal),
			evaluate: func(row audit.Record) (bool, AttackCatalogActuatorResult) {
				observed, _, receipt := k8sCatalogueDecision(row, prepared)
				return observed, receipt
			},
		})
	}
	return fixtures
}

func TestIdentityReceiptRejectsMissingTopLevelDispatchEveryPath(t *testing.T) {
	tests := []struct {
		name     string
		evaluate func() (bool, AttackCatalogActuatorResult)
	}{
		{
			name: "credential",
			evaluate: func() (bool, AttackCatalogActuatorResult) {
				profile := identityTestProfile(t, identityCatalogueCredential)
				binding := newIdentityTestBinding(profile)
				row := identityTestDecision(profile, binding.prepared, binding.signal)
				row.DispatchOutcome = ""
				observed, _, receipt := identityFamilyCatalogueDecision(profile, row, binding.prepared, binding.signal)
				return observed, receipt
			},
		},
		{
			name: "identity-sa-rotate",
			evaluate: func() (bool, AttackCatalogActuatorResult) {
				profile := identityTestProfile(t, identityCatalogueRotation)
				binding := newIdentityTestBinding(profile)
				row := identityTestDecision(profile, binding.prepared, binding.signal)
				row.DispatchOutcome = ""
				observed, _, receipt := identityFamilyCatalogueDecision(profile, row, binding.prepared, binding.signal)
				return observed, receipt
			},
		},
		{
			name: "agent-action",
			evaluate: func() (bool, AttackCatalogActuatorResult) {
				profile := identityTestProfile(t, identityCatalogueAgent)
				binding := newIdentityTestBinding(profile)
				row := identityTestDecision(profile, binding.prepared, binding.signal)
				row.DispatchOutcome = ""
				observed, _, receipt := identityFamilyCatalogueDecision(profile, row, binding.prepared, binding.signal)
				return observed, receipt
			},
		},
		{
			name: "AML.T0012",
			evaluate: func() (bool, AttackCatalogActuatorResult) {
				fixture, signal := identityCatalogFixtureAndSignal()
				row := exactIdentityCatalogAudit(fixture, signal)
				row.DispatchOutcome = ""
				observed, _, receipt := identityCatalogueDecision(row, fixture, signal)
				return observed, receipt
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			observed, receipt := tt.evaluate()
			if observed || receipt.ReceiptObserved || receipt.AcceptedAt != nil {
				t.Fatalf("missing top-level dispatch was accepted: observed=%t receipt=%+v", observed, receipt)
			}
		})
	}
}

func TestAttackCatalogueReceiptConformanceEveryFamilyAndHelper(t *testing.T) {
	seen := map[string]string{}
	for _, fixture := range auditReceiptConformanceFixtures(t) {
		fixture := fixture
		t.Run(fixture.family+"/"+fixture.id+"/strict-positive", func(t *testing.T) {
			observed, receipt := fixture.evaluate(cloneReceiptAuditRecord(fixture.record))
			if !observed || !receipt.ReceiptObserved || receipt.AcceptedAt == nil ||
				!receipt.AcceptedAt.Equal(fixture.record.Time) {
				t.Fatalf("%s positive receipt rejected or timestamp fabricated: observed=%t receipt=%+v", fixture.helper, observed, receipt)
			}
			if previous := seen[fixture.id]; previous != "" {
				t.Fatalf("catalogue ID reached multiple receipt helpers: %s and %s", previous, fixture.helper)
			}
			seen[fixture.id] = fixture.helper
		})

		for _, mutation := range receiptAuditMutations() {
			mutation := mutation
			t.Run(fixture.family+"/"+fixture.id+"/"+mutation.name, func(t *testing.T) {
				row := cloneReceiptAuditRecord(fixture.record)
				mutation.mutate(&row)
				_, receipt := fixture.evaluate(row)
				if receipt.ReceiptObserved || receipt.AcceptedAt != nil {
					t.Fatalf("%s accepted %s: %+v", fixture.helper, mutation.name, receipt)
				}
			})
		}
	}

	for _, profile := range servingCatalogueProfiles() {
		profile := profile
		t.Run(profile.Family+"/"+profile.CatalogueID+"/strict-positive", func(t *testing.T) {
			row, prepared, signal := servingDecisionAuditFixture(profile)
			matchedSignal, decision, matched := matchServingDecision(row, profile, prepared, signal)
			if !matched || !acceptedServingCatalogueReceipt(profile, matchedSignal, decision) {
				t.Fatalf("serving positive receipt rejected: matched=%t signal=%+v decision=%+v", matched, matchedSignal, decision)
			}
			adapter, _, run := newPositiveServingAdapter(t, profile.CatalogueID)
			preflight, err := adapter.Preflight(t.Context(), run)
			if err != nil {
				t.Fatal(err)
			}
			observation, err := adapter.Execute(t.Context(), run, preflight)
			if err != nil || !observation.Actuator.ReceiptObserved || observation.Actuator.AcceptedAt == nil ||
				observation.Decision.ObservedAt == nil || !observation.Actuator.AcceptedAt.Equal(*observation.Decision.ObservedAt) {
				t.Fatalf("serving receipt builder rejected strict positive: observation=%+v err=%v", observation, err)
			}
			if previous := seen[profile.CatalogueID]; previous != "" {
				t.Fatalf("catalogue ID reached multiple receipt helpers: %s and serving", previous)
			}
			seen[profile.CatalogueID] = "serving"
		})

		for _, mutation := range receiptAuditMutations() {
			mutation := mutation
			t.Run(profile.Family+"/"+profile.CatalogueID+"/"+mutation.name, func(t *testing.T) {
				row, prepared, signal := servingDecisionAuditFixture(profile)
				mutation.mutate(&row)
				matchedSignal, decision, matched := matchServingDecision(row, profile, prepared, signal)
				if matched && acceptedServingCatalogueReceipt(profile, matchedSignal, decision) {
					t.Fatalf("serving accepted %s: signal=%+v decision=%+v", mutation.name, matchedSignal, decision)
				}
			})
		}
	}

	entries, err := attackcatalog.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != attackcatalog.ExpectedSize || len(entries) != attackcatalog.ExpectedSize {
		t.Fatalf("strict positive receipt coverage=%d entries=%d want=%d", len(seen), len(entries), attackcatalog.ExpectedSize)
	}
	for _, entry := range entries {
		if seen[entry.ID] == "" {
			t.Errorf("catalogue ID %s/%s has no strict positive receipt control", entry.Family, entry.ID)
		}
	}
}

func TestBindAttackCatalogEvidenceNeverFabricatesAcceptedAt(t *testing.T) {
	observedAt := time.Now().UTC()
	base := AttackCatalogResult{
		CatalogueID: "catalogue-id", RunID: "run-id",
		Signal:   AttackCatalogSignalResult{UID: "signal-uid", TargetUID: "target-uid"},
		Decision: AttackCatalogDecisionResult{ID: "decision-id", ObservedAt: attackCatalogTime(observedAt)},
		Actuator: AttackCatalogActuatorResult{ReceiptObserved: true, Handler: "handler"},
	}
	missing := base
	if err := bindAttackCatalogEvidence(&missing, "credential"); err == nil || missing.Actuator.AcceptedAt != nil {
		t.Fatalf("release evidence fabricated an acceptance timestamp: result=%+v err=%v", missing, err)
	}

	accepted := base
	accepted.Actuator.AcceptedAt = attackCatalogTime(observedAt)
	if err := bindAttackCatalogEvidence(&accepted, "credential"); err != nil {
		t.Fatalf("valid accepted receipt timestamp rejected: %v", err)
	}
	if accepted.Actuator.Status != "accepted" || accepted.Actuator.DecisionID != accepted.Decision.ID ||
		accepted.Actuator.ReceiptID == "" || accepted.Actuator.AcceptedAt == nil ||
		!accepted.Actuator.AcceptedAt.Equal(observedAt) {
		t.Fatalf("valid receipt binding changed: %+v", accepted.Actuator)
	}
}
