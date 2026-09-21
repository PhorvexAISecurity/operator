package decision

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

type m106Authority struct {
	bindings map[string]model.PersistenceOperationBinding
	allowed  map[string]model.PersistenceObservation
}

func (*m106Authority) Source() string { return model.ScopedSessionCapability }
func (a *m106Authority) AuthorizeObservation(observation model.PersistenceObservation) (model.PersistenceOperationBinding, bool) {
	allowed, ok := a.allowed[observation.EvidenceID]
	if !ok || !reflect.DeepEqual(allowed, observation) {
		return model.PersistenceOperationBinding{}, false
	}
	binding, ok := a.bindings[observation.OperationID]
	return binding, ok
}

func m106Fixture(t *testing.T) (*CoverageEngine, model.Policy, *m106Authority, model.PersistenceObservation) {
	t.Helper()
	now := time.Date(2026, 9, 21, 4, 0, 0, 0, time.UTC)
	e := NewCoverageEngine()
	e.Now = func() time.Time { return now }
	pol := covPolicy(1)
	pol.Tenant = "tenant"
	pol.Namespace, pol.PolicyName, pol.PolicyUID, pol.PolicyGeneration = "ns", "policy", "policy-uid", 1
	epoch := model.PolicyEpoch{Namespace: pol.Namespace, Name: pol.PolicyName, UID: pol.PolicyUID, Generation: pol.PolicyGeneration}
	if err := e.SetOwnerEpoch(epoch, true); err != nil {
		t.Fatal(err)
	}
	dispatched := now.Add(-62 * time.Second)
	workload := model.PersistenceWorkloadScope{Namespace: "ns", OwnerKind: "Deployment", OwnerName: "app", OwnerUID: "deployment-uid"}
	binding := model.PersistenceOperationBinding{
		Policy: epoch, ProcessEpochID: e.ScopedOutcomeProcessEpochID(), ContractVersion: model.ScopedSessionNativeRotateV1,
		Workload: workload, OperationID: "operation-1", TargetUID: "old-pod-uid", Capability: model.ScopedSessionCapability,
		Action: model.ActionRotate, DispatchAcknowledgedAt: dispatched, ObservationNotBefore: dispatched.Add(60 * time.Second),
		ObservationDeadline: dispatched.Add(65 * time.Second), TargetTerminationGraceSeconds: 30,
	}
	authority := &m106Authority{bindings: map[string]model.PersistenceOperationBinding{binding.OperationID: binding}, allowed: map[string]model.PersistenceObservation{}}
	e.PersistenceAuthority = authority
	observation := model.PersistenceObservation{
		SchemaVersion: model.ScopedOutcomeObservationSchemaV1, Source: model.ScopedSessionCapability,
		ProcessEpochID: binding.ProcessEpochID, ContractVersion: binding.ContractVersion, EvidenceID: "evidence-1",
		Policy: epoch, Workload: workload, OperationID: binding.OperationID, TargetUID: binding.TargetUID,
		Capability: binding.Capability, Action: binding.Action, BeforeSHA256: strings.Repeat("a", 64),
		ActionSHA256: strings.Repeat("b", 64), AfterSHA256: strings.Repeat("c", 64),
		ObservationStart: dispatched.Add(60 * time.Second), ObservationEnd: dispatched.Add(61 * time.Second), Outcome: model.PersistenceHeld,
	}
	authority.allowed[observation.EvidenceID] = observation
	return e, pol, authority, observation
}

func m106Bind(authority *m106Authority, template model.PersistenceObservation, evidenceID, operationID, outcome string) model.PersistenceObservation {
	observation := template
	observation.EvidenceID, observation.OperationID, observation.Outcome = evidenceID, operationID, outcome
	binding := authority.bindings[template.OperationID]
	binding.OperationID = operationID
	authority.bindings[operationID] = binding
	authority.allowed[evidenceID] = observation
	return observation
}

func TestPost25M106ScopedOutcomeDoesNotTrainPHold(t *testing.T) {
	e, pol, _, observation := m106Fixture(t)
	alphaBefore, betaBefore := e.Killchain.Memory.Prior(pol.Owner())
	unrelated := covView("unrelated-capability", true, 2*time.Hour, false)
	beforeRows, err := e.DecideShadowChecked([]*model.WorkloadView{unrelated}, pol)
	if err != nil {
		t.Fatal(err)
	}
	before := beforeRows[0]
	result := e.AdmitPersistenceObservation(observation)
	afterRows, err := e.DecideShadowChecked([]*model.WorkloadView{unrelated}, pol)
	if err != nil {
		t.Fatal(err)
	}
	after := afterRows[0]
	alphaAfter, betaAfter := e.Killchain.Memory.Prior(pol.Owner())
	if !result.Applied || len(result.Status.Cohorts) != 1 || result.Status.Cohorts[0].Held != 1 || result.Status.Cohorts[0].N != 1 {
		t.Fatalf("held result was not retained in its exact cohort: %+v", result)
	}
	if alphaAfter != alphaBefore || betaAfter != betaBefore || before.PHold != after.PHold || before.Action != after.Action || before.Selected != after.Selected {
		t.Fatalf("reporting-only outcome contaminated attacker belief or selection: prior (%g,%g)->(%g,%g), before=%+v after=%+v", alphaBefore, betaBefore, alphaAfter, betaAfter, before, after)
	}
	if after.PersistenceLearning != nil || after.ScopedOutcomes == nil || after.ScopedOutcomes.Cohorts[0].Held != 1 {
		t.Fatalf("decision used the legacy learning field or omitted scoped report: learning=%+v scoped=%+v", after.PersistenceLearning, after.ScopedOutcomes)
	}
}

func TestPost25M106ScopedCountsAndWilsonReporting(t *testing.T) {
	e, pol, authority, first := m106Fixture(t)
	observations := []model.PersistenceObservation{
		first,
		m106Bind(authority, first, "evidence-2", "operation-2", model.PersistenceRevoked),
		m106Bind(authority, first, "evidence-3", "operation-3", model.PersistenceUnknown),
		m106Bind(authority, first, "evidence-4", "operation-4", model.PersistenceCensored),
	}
	for _, observation := range observations {
		if result := e.AdmitPersistenceObservation(observation); !result.Applied {
			t.Fatalf("authenticated categorical result was not retained: %+v", result)
		}
	}
	report, ok := e.ScopedOutcomeReportFor(pol.Owner())
	if !ok || len(report.Cohorts) != 1 {
		t.Fatalf("missing exact cohort: %+v ok=%t", report, ok)
	}
	cohort := report.Cohorts[0]
	lower, upper := model.Wilson95(1, 2)
	if cohort.Held != 1 || cohort.Revoked != 1 || cohort.Unknown != 1 || cohort.Censored != 1 || cohort.N != 2 ||
		cohort.PosteriorMean != .5 || cohort.Calibrated || cohort.RawHeldInterval == nil ||
		cohort.RawHeldInterval.Lower != lower || cohort.RawHeldInterval.Upper != upper {
		t.Fatalf("scoped descriptive report is incorrect: %+v", cohort)
	}
}

func TestPost25M106UnknownOnlyCohortHasNoWilsonInterval(t *testing.T) {
	e, _, authority, template := m106Fixture(t)
	unknown := m106Bind(authority, template, "unknown-only", "unknown-operation", model.PersistenceUnknown)
	result := e.AdmitPersistenceObservation(unknown)
	if !result.Applied || len(result.Status.Cohorts) != 1 {
		t.Fatalf("unknown result was not retained descriptively: %+v", result)
	}
	cohort := result.Status.Cohorts[0]
	if cohort.Unknown != 1 || cohort.N != 0 || cohort.PosteriorMean != .5 || cohort.RawHeldInterval != nil || cohort.Calibrated {
		t.Fatalf("n=0 report made a statistical claim: %+v", cohort)
	}
}

func TestPost25M106LateCensoredIsDescriptiveButLateCategoricalIsRejected(t *testing.T) {
	e, _, authority, template := m106Fixture(t)
	binding := authority.bindings[template.OperationID]
	e.Now = func() time.Time { return binding.ObservationDeadline.Add(3 * time.Second) }
	censored := m106Bind(authority, template, "late-censored", "late-censored-operation", model.PersistenceCensored)
	censored.ObservationStart = binding.ObservationDeadline.Add(time.Second)
	censored.ObservationEnd = binding.ObservationDeadline.Add(2 * time.Second)
	authority.allowed[censored.EvidenceID] = censored
	result := e.AdmitPersistenceObservation(censored)
	if !result.Applied || len(result.Status.Cohorts) != 1 || result.Status.Cohorts[0].Censored != 1 || result.Status.Cohorts[0].N != 0 {
		t.Fatalf("authenticated deadline miss was not retained descriptively: %+v", result)
	}

	held := m106Bind(authority, template, "late-held", "late-held-operation", model.PersistenceHeld)
	held.ObservationStart = binding.ObservationDeadline.Add(time.Second)
	held.ObservationEnd = binding.ObservationDeadline.Add(2 * time.Second)
	authority.allowed[held.EvidenceID] = held
	result = e.AdmitPersistenceObservation(held)
	if result.Applied || result.Disposition != model.PersistenceDispositionExpired {
		t.Fatalf("late categorical result crossed the strict window: %+v", result)
	}
}

func TestPost25M106DecodeRejectsInvalidUTF8BeforeJSONNormalization(t *testing.T) {
	_, _, _, observation := m106Fixture(t)
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"evidence-1"`), []byte{'"', 'e', 0xff, '"'}, 1)
	if _, err := DecodeScopedOutcomeObservation(raw); err == nil || err.Error() != "scoped outcome payload is not valid UTF-8" {
		t.Fatalf("invalid UTF-8 was normalized before refusal: %v", err)
	}
}

func TestPost25M106GenerationTransitionRetainsPriorCohortInNoLabelAudit(t *testing.T) {
	e, _, _, observation := m106Fixture(t)
	if result := e.AdmitPersistenceObservation(observation); !result.Applied {
		t.Fatalf("initial exact cohort was not admitted: %+v", result)
	}
	next := observation.Policy
	next.Generation++
	if err := e.SetOwnerEpoch(next, true); err != nil {
		t.Fatal(err)
	}
	report, ok := e.ScopedOutcomeReportFor(next.Owner())
	if !ok || report.Disposition != model.PersistenceDispositionNoLabel || report.ReplayEntries != 1 || len(report.Cohorts) != 1 || report.Cohorts[0].Key.PolicyGeneration != observation.Policy.Generation {
		t.Fatalf("generation transition lost or mislabeled prior reporting history: %+v ok=%t", report, ok)
	}
	if _, err := json.Marshal(audit.Record{ScopedOutcomes: &report}); err != nil {
		t.Fatalf("retained prior-generation no-label report failed audit wire validation: %v", err)
	}
}

func TestPost25M106ExactAuthorityWindowReplayAndConflict(t *testing.T) {
	e, _, authority, observation := m106Fixture(t)
	for name, mutate := range map[string]func(*model.PersistenceObservation){
		"wrong process epoch": func(o *model.PersistenceObservation) { o.ProcessEpochID = "prior-process" },
		"wrong scope":         func(o *model.PersistenceObservation) { o.Workload.OwnerUID = "other-deployment" },
		"wrong action":        func(o *model.PersistenceObservation) { o.Action = model.ActionQuarantine },
		"wrong old target":    func(o *model.PersistenceObservation) { o.TargetUID = "replacement-pod" },
		"forged result":       func(o *model.PersistenceObservation) { o.Outcome = model.PersistenceRevoked },
		"bad evidence hash":   func(o *model.PersistenceObservation) { o.AfterSHA256 = strings.Repeat("A", 64) },
		"early sample": func(o *model.PersistenceObservation) {
			o.ObservationStart = authority.bindings[o.OperationID].DispatchAcknowledgedAt.Add(59 * time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := observation
			mutate(&candidate)
			// Only non-forged structural variants are placed in the complete-payload
			// authority. Exact binding and window validation must still reject them.
			if name != "forged result" {
				authority.allowed[candidate.EvidenceID] = candidate
			}
			result := e.AdmitPersistenceObservation(candidate)
			if result.Applied {
				t.Fatalf("invalid observation was retained: %+v", result)
			}
		})
	}
	authority.allowed[observation.EvidenceID] = observation
	first := e.AdmitPersistenceObservation(observation)
	duplicate := e.AdmitPersistenceObservation(observation)
	conflict := observation
	conflict.AfterSHA256 = strings.Repeat("d", 64)
	authority.allowed[conflict.EvidenceID] = conflict
	contradiction := e.AdmitPersistenceObservation(conflict)
	if !first.Applied || duplicate.Disposition != model.PersistenceDispositionDuplicate || contradiction.Disposition != model.PersistenceDispositionConflict {
		t.Fatalf("replay barrier failed: first=%+v duplicate=%+v conflict=%+v", first, duplicate, contradiction)
	}
}

func TestPost25M106GenerationCohortRetirementAndRestartBoundaries(t *testing.T) {
	e, pol, authority, first := m106Fixture(t)
	if !e.AdmitPersistenceObservation(first).Applied {
		t.Fatal("first result was not retained")
	}
	newEpoch := first.Policy
	newEpoch.Generation++
	if err := e.SetOwnerEpoch(newEpoch, true); err != nil {
		t.Fatal(err)
	}
	stale := e.AdmitPersistenceObservation(first)
	if stale.Applied {
		t.Fatalf("old generation crossed epoch: %+v", stale)
	}
	second := m106Bind(authority, first, "evidence-2", "operation-2", model.PersistenceRevoked)
	second.Policy = newEpoch
	binding := authority.bindings[second.OperationID]
	binding.Policy = newEpoch
	authority.bindings[second.OperationID] = binding
	authority.allowed[second.EvidenceID] = second
	if result := e.AdmitPersistenceObservation(second); !result.Applied || len(result.Status.Cohorts) != 2 {
		t.Fatalf("new generation did not get a separate cohort: %+v", result)
	}
	if err := e.SetOwnerEpoch(first.Policy, true); err == nil {
		t.Fatal("stale policy generation replaced the current scoped lifecycle")
	}
	e.SetOwnerLive(pol.Owner(), false)
	e.ForgetOwner(pol.Owner())
	if result := e.AdmitPersistenceObservation(second); result.Applied {
		t.Fatalf("retired owner resurrected: %+v", result)
	}
	if err := e.SetOwnerEpoch(newEpoch, true); err == nil {
		t.Fatal("retired UID was reactivated")
	}

	restarted := NewCoverageEngine()
	restarted.Now = e.Now
	restarted.PersistenceAuthority = authority
	restarted.SetOwnerEpoch(newEpoch, true)
	if result := restarted.AdmitPersistenceObservation(second); result.Applied || result.Reason != "observation does not match the current process epoch" {
		t.Fatalf("prior-process evidence crossed restart boundary: %+v", result)
	}
}

func TestPost25M106CohortAndReplayBoundsDoNotEvict(t *testing.T) {
	e, _, authority, template := m106Fixture(t)
	for i := 0; i < model.ScopedOutcomeCohortCapacity; i++ {
		o := m106Bind(authority, template, fmt.Sprintf("cohort-evidence-%d", i), fmt.Sprintf("cohort-operation-%d", i), model.PersistenceHeld)
		o.Workload.OwnerUID = fmt.Sprintf("deployment-%d", i)
		binding := authority.bindings[o.OperationID]
		binding.Workload = o.Workload
		authority.bindings[o.OperationID] = binding
		authority.allowed[o.EvidenceID] = o
		if result := e.AdmitPersistenceObservation(o); !result.Applied {
			t.Fatalf("cohort %d refused early: %+v", i, result)
		}
	}
	extra := m106Bind(authority, template, "cohort-extra", "cohort-extra-operation", model.PersistenceHeld)
	extra.Workload.OwnerUID = "deployment-extra"
	binding := authority.bindings[extra.OperationID]
	binding.Workload = extra.Workload
	authority.bindings[extra.OperationID] = binding
	authority.allowed[extra.EvidenceID] = extra
	if result := e.AdmitPersistenceObservation(extra); result.Applied || result.Disposition != model.PersistenceDispositionSaturated {
		t.Fatalf("cohort capacity did not refuse without eviction: %+v", result)
	}
	if result := e.AdmitPersistenceObservation(authority.allowed["cohort-evidence-0"]); result.Disposition != model.PersistenceDispositionDuplicate {
		t.Fatalf("saturation evicted replay identity: %+v", result)
	}
}

func TestPost25M106ReplayCapacityDoesNotEvict(t *testing.T) {
	e, _, authority, template := m106Fixture(t)
	for i := 0; i < model.ScopedOutcomeEvidenceCapacity; i++ {
		o := m106Bind(authority, template, fmt.Sprintf("evidence-%d", i), fmt.Sprintf("operation-%d", i), model.PersistenceUnknown)
		if result := e.AdmitPersistenceObservation(o); !result.Applied {
			t.Fatalf("evidence %d refused before the bound: %+v", i, result)
		}
	}
	extra := m106Bind(authority, template, "evidence-extra", "operation-extra", model.PersistenceUnknown)
	if result := e.AdmitPersistenceObservation(extra); result.Applied || result.Disposition != model.PersistenceDispositionSaturated {
		t.Fatalf("replay capacity did not refuse without eviction: %+v", result)
	}
	if result := e.AdmitPersistenceObservation(authority.allowed["evidence-0"]); result.Disposition != model.PersistenceDispositionDuplicate {
		t.Fatalf("replay saturation evicted an old identity: %+v", result)
	}
}

func TestPost25M106StrictWireAndShadowReadDoNotAllocate(t *testing.T) {
	e, pol, _, observation := m106Fixture(t)
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeScopedOutcomeObservation(append(raw, []byte(` {}`)...)); err == nil {
		t.Fatal("accepted trailing JSON")
	}
	withUnknown := append(raw[:len(raw)-1], []byte(`,"prediction":true}`)...)
	if _, err := DecodeScopedOutcomeObservation(withUnknown); err == nil {
		t.Fatal("accepted unknown prediction field")
	}
	duplicate := append(raw[:len(raw)-1], []byte(`,"outcome":"revoked"}`)...)
	if _, err := DecodeScopedOutcomeObservation(duplicate); err == nil {
		t.Fatal("accepted duplicate categorical outcome")
	}

	newPolicy := pol
	newPolicy.PolicyUID = "unregistered-policy"
	report, allocated := e.ScopedOutcomeReportFor(newPolicy.Owner())
	if allocated || len(report.Cohorts) != 0 || report.ReplayEntries != 0 {
		t.Fatalf("shadow report allocated state: %+v allocated=%t", report, allocated)
	}
}

func TestPost25M106LifetimeOwnerCapacityIncludesRetiredUIDs(t *testing.T) {
	e := NewCoverageEngine()
	for i := 0; i < model.ScopedOutcomeOwnerCapacity; i++ {
		epoch := model.PolicyEpoch{Namespace: "ns", Name: fmt.Sprintf("policy-%d", i), UID: fmt.Sprintf("uid-%d", i), Generation: 1}
		if err := e.SetOwnerEpoch(epoch, true); err != nil {
			t.Fatalf("owner %d refused early: %v", i, err)
		}
	}
	first := model.PolicyEpoch{Namespace: "ns", Name: "policy-0", UID: "uid-0", Generation: 1}
	e.SetOwnerLive(first.Owner(), false)
	e.ForgetOwner(first.Owner())
	extra := model.PolicyEpoch{Namespace: "ns", Name: "extra", UID: "extra-uid", Generation: 1}
	if err := e.SetOwnerEpoch(extra, true); err == nil {
		t.Fatal("retirement evicted a lifetime UID and reopened capacity")
	}
	if _, allocated := e.ScopedOutcomeReportFor(extra.Owner()); allocated {
		t.Fatal("capacity refusal allocated an unbounded owner")
	}
	report, allocated := e.ScopedOutcomeReportFor(first.Owner())
	if !allocated || report.LifetimeOwners != model.ScopedOutcomeOwnerCapacity {
		t.Fatalf("retired replay tombstone was lost: %+v", report)
	}
}
