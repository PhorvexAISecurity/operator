package decision

import (
	"fmt"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

type m106Authority struct {
	source   string
	bindings map[string]model.PersistenceOperationBinding
	allowed  map[string]model.PersistenceObservation
}

func (a *m106Authority) Source() string { return a.source }

func (a *m106Authority) AuthorizeObservation(observation model.PersistenceObservation) (model.PersistenceOperationBinding, bool) {
	authorized, ok := a.allowed[observation.EvidenceID]
	if !ok || authorized != observation {
		return model.PersistenceOperationBinding{}, false
	}
	binding, ok := a.bindings[observation.OperationID]
	return binding, ok
}

func m106Fixture(t *testing.T, limit int) (*CoverageEngine, model.Policy, *m106Authority, model.PersistenceObservation) {
	t.Helper()
	now := traceTestNow
	pol := decisionTracePolicy(1, false)
	pol.PolicyGeneration = 7
	epoch := model.PolicyEpoch{Namespace: pol.Namespace, Name: pol.PolicyName, UID: pol.PolicyUID, Generation: pol.PolicyGeneration}
	binding := model.PersistenceOperationBinding{
		Policy: epoch, OperationID: "operation-1", TargetUID: "old-pod-uid",
		Capability: "credential-persistence", Scope: "pod/process",
		ObservationNotBefore: now.Add(-time.Hour), ObservationDeadline: now.Add(time.Hour),
	}
	authority := &m106Authority{source: "fixture-effect-observer", bindings: map[string]model.PersistenceOperationBinding{"operation-1": binding}, allowed: map[string]model.PersistenceObservation{}}
	e := fixedTraceEngine()
	e.PersistenceAuthority = authority
	e.PersistenceDedupLimit = limit
	e.SetOwnerLive(pol.Owner(), true)
	if err := e.SetOwnerEpoch(epoch, true); err != nil {
		t.Fatal(err)
	}
	observation := model.PersistenceObservation{
		SchemaVersion: model.PersistenceObservationSchemaV1, Source: authority.source,
		EvidenceID: "evidence-1", Policy: epoch, OperationID: binding.OperationID,
		TargetUID: binding.TargetUID, Capability: binding.Capability, Scope: binding.Scope,
		ObservationStart: now.Add(-30 * time.Minute), ObservationEnd: now.Add(-time.Minute),
		Outcome: model.PersistenceHeld,
	}
	authority.allowed[observation.EvidenceID] = observation
	return e, pol, authority, observation
}

func TestPost25M106RepeatedActualSelectionsDoNotSelfTrain(t *testing.T) {
	e := fixedTraceEngine()
	pol := decisionTracePolicy(1, false)
	view := covView("m106-repeated", true, 2*time.Hour, false)

	first := e.Decide([]*model.WorkloadView{view}, pol)[0]
	if !first.Selected || first.PHold == 0.5 {
		t.Fatalf("fixture needs a selected decision whose old prediction-as-label delta is nonzero: %+v", first)
	}
	if oldDelta := 0.5 * (first.PHold - 0.5); oldDelta == 0 {
		t.Fatal("pre-fix self-training rule would be inert in this fixture")
	}
	wantAlpha, wantBeta := e.Killchain.Memory.Prior(pol.Owner())
	for i := 0; i < 12; i++ {
		decision := e.Decide([]*model.WorkloadView{view}, pol)[0]
		if !decision.Selected {
			t.Fatalf("tick %d stopped exercising the actual selected producer: %+v", i, decision)
		}
	}
	gotAlpha, gotBeta := e.Killchain.Memory.Prior(pol.Owner())
	if gotAlpha != wantAlpha || gotBeta != wantBeta {
		t.Fatalf("optimizer predictions trained persistence memory: before=(%g,%g) after=(%g,%g)", wantAlpha, wantBeta, gotAlpha, gotBeta)
	}
	if first.PersistenceLearning == nil || first.PersistenceLearning.Disposition != model.PersistenceDispositionNoProducer ||
		first.PersistenceLearning.QualifiedLabels != 0 {
		t.Fatalf("decision did not disclose the absent qualified producer: %+v", first.PersistenceLearning)
	}
}

func TestPost25M106QualifiedHeldAndRevokedApplyOneBernoulliCount(t *testing.T) {
	e, pol, authority, held := m106Fixture(t, 8)
	a0, b0 := e.Killchain.Memory.Prior(pol.Owner())
	result := e.AdmitPersistenceObservation(held)
	if !result.Applied || result.Disposition != model.PersistenceDispositionApplied {
		t.Fatalf("held observation was not applied: %+v", result)
	}
	a1, b1 := e.Killchain.Memory.Prior(pol.Owner())
	if a1 != a0+1 || b1 != b0 {
		t.Fatalf("held observation changed wrong pseudo-counts: before=(%g,%g) after=(%g,%g)", a0, b0, a1, b1)
	}

	revoked := held
	revoked.EvidenceID = "evidence-2"
	revoked.Outcome = model.PersistenceRevoked
	authority.allowed[revoked.EvidenceID] = revoked
	result = e.AdmitPersistenceObservation(revoked)
	a2, b2 := e.Killchain.Memory.Prior(pol.Owner())
	if !result.Applied || a2 != a1 || b2 != b1+1 || result.Status.QualifiedLabels != 2 ||
		result.Status.HeldLabels != 1 || result.Status.RevokedLabels != 1 {
		t.Fatalf("revoked observation changed wrong pseudo-counts: result=%+v before=(%g,%g) after=(%g,%g)", result, a1, b1, a2, b2)
	}
	decision := e.Decide([]*model.WorkloadView{covView("m106-labelled", true, 2*time.Hour, false)}, pol)[0]
	if decision.PersistenceLearning == nil || decision.PersistenceLearning.Disposition != model.PersistenceDispositionApplied ||
		decision.PersistenceLearning.Source != "fixture-effect-observer" || decision.PersistenceLearning.QualifiedLabels != 2 {
		t.Fatalf("real decision omitted observed-label provenance: %+v", decision.PersistenceLearning)
	}
	if a3, b3 := e.Killchain.Memory.Prior(pol.Owner()); a3 != a2 || b3 != b2 {
		t.Fatalf("selection added another count after qualified labels: before=(%g,%g) after=(%g,%g)", a2, b2, a3, b3)
	}
}

func TestPost25M106QualifiedCountIsRawWhileBeliefMassRemainsCapped(t *testing.T) {
	const observations = 210
	e, pol, authority, template := m106Fixture(t, observations+1)
	initialAlpha, initialBeta := e.Killchain.Memory.Prior(pol.Owner())
	for i := 0; i < observations; i++ {
		observation := template
		observation.EvidenceID = fmt.Sprintf("evidence-%03d", i)
		observation.OperationID = fmt.Sprintf("operation-%03d", i)
		binding := authority.bindings[template.OperationID]
		binding.OperationID = observation.OperationID
		authority.bindings[observation.OperationID] = binding
		authority.allowed[observation.EvidenceID] = observation
		if result := e.AdmitPersistenceObservation(observation); !result.Applied {
			t.Fatalf("qualified outcome %d was not applied: %+v", i, result)
		}
	}
	status, ok := e.PersistenceLearningStatusFor(pol.Owner())
	if !ok || status.QualifiedLabels != observations || status.HeldLabels != observations || status.DedupEntries != observations {
		t.Fatalf("raw qualified outcome accounting changed: %+v ok=%t", status, ok)
	}
	alpha, beta := e.Killchain.Memory.Prior(pol.Owner())
	if alpha+beta >= initialAlpha+initialBeta+float64(status.QualifiedLabels) {
		t.Fatalf("effective pseudo-count mass was not capped: initial=%g final=%g raw=%d", initialAlpha+initialBeta, alpha+beta, status.QualifiedLabels)
	}
	if alpha+beta > 200.000000001 {
		t.Fatalf("effective pseudo-count mass exceeded the existing cap: alpha=%g beta=%g", alpha, beta)
	}
}

func TestPost25M106BindingDedupAndUnresolvedOutcomesCannotTrain(t *testing.T) {
	e, pol, authority, observation := m106Fixture(t, 4)
	a0, b0 := e.Killchain.Memory.Prior(pol.Owner())
	forged := observation
	forged.Outcome = model.PersistenceRevoked
	if result := e.AdmitPersistenceObservation(forged); result.Applied || result.Disposition != model.PersistenceDispositionRejected {
		t.Fatalf("source name and valid operation binding authorized a forged outcome: %+v", result)
	}

	for name, tc := range map[string]struct {
		mutate func(*model.PersistenceObservation)
		want   string
	}{
		"replacement UID is not the revoked old target": {func(o *model.PersistenceObservation) { o.TargetUID = "replacement-uid" }, model.PersistenceDispositionRejected},
		"wrong owner generation":                        {func(o *model.PersistenceObservation) { o.Policy.Generation++ }, model.PersistenceDispositionRejected},
		"unknown outcome":                               {func(o *model.PersistenceObservation) { o.Outcome = model.PersistenceUnknown }, model.PersistenceDispositionUnresolved},
		"censored outcome":                              {func(o *model.PersistenceObservation) { o.Outcome = model.PersistenceCensored }, model.PersistenceDispositionUnresolved},
		"future observation":                            {func(o *model.PersistenceObservation) { o.ObservationEnd = traceTestNow.Add(time.Minute) }, model.PersistenceDispositionExpired},
		"reversed timestamps":                           {func(o *model.PersistenceObservation) { o.ObservationStart = o.ObservationEnd.Add(time.Minute) }, model.PersistenceDispositionRejected},
		"oversized scope":                               {func(o *model.PersistenceObservation) { o.Scope = string(make([]byte, 1025)) }, model.PersistenceDispositionRejected},
		"invalid UTF-8 evidence ID":                     {func(o *model.PersistenceObservation) { o.EvidenceID = string([]byte{'x', 0xff}) }, model.PersistenceDispositionRejected},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := observation
			tc.mutate(&candidate)
			authority.allowed[candidate.EvidenceID] = candidate
			result := e.AdmitPersistenceObservation(candidate)
			if result.Applied || result.Disposition != tc.want {
				t.Fatalf("unexpected result: %+v", result)
			}
		})
	}
	if _, allocated := e.persistenceLearning[pol.Owner()]; allocated {
		t.Fatal("rejected/unresolved observations allocated dedup learning state")
	}
	a1, b1 := e.Killchain.Memory.Prior(pol.Owner())
	if a1 != a0 || b1 != b0 {
		t.Fatalf("rejected/unresolved observations trained memory: before=(%g,%g) after=(%g,%g)", a0, b0, a1, b1)
	}

	authority.allowed[observation.EvidenceID] = observation
	first := e.AdmitPersistenceObservation(observation)
	duplicate := e.AdmitPersistenceObservation(observation)
	conflict := observation
	conflict.Outcome = model.PersistenceRevoked
	authority.allowed[conflict.EvidenceID] = conflict
	contradiction := e.AdmitPersistenceObservation(conflict)
	if !first.Applied || duplicate.Disposition != model.PersistenceDispositionDuplicate || duplicate.Applied ||
		contradiction.Disposition != model.PersistenceDispositionConflict || contradiction.Applied {
		t.Fatalf("dedup/conflict contract failed: first=%+v duplicate=%+v conflict=%+v", first, duplicate, contradiction)
	}
	a2, b2 := e.Killchain.Memory.Prior(pol.Owner())
	if a2 != a0+1 || b2 != b0 {
		t.Fatalf("duplicate/conflict replay changed counts: before=(%g,%g) after=(%g,%g)", a0, b0, a2, b2)
	}
}

func TestPost25M106SameTenantOwnersRemainIsolated(t *testing.T) {
	e, firstPolicy, authority, first := m106Fixture(t, 8)
	secondPolicy := firstPolicy
	secondPolicy.PolicyUID = "second-policy-uid"
	secondEpoch := model.PolicyEpoch{Namespace: secondPolicy.Namespace, Name: "second-policy", UID: secondPolicy.PolicyUID, Generation: 1}
	secondPolicy.PolicyName = secondEpoch.Name
	e.SetOwnerLive(secondPolicy.Owner(), true)
	if err := e.SetOwnerEpoch(secondEpoch, true); err != nil {
		t.Fatal(err)
	}
	secondBinding := authority.bindings[first.OperationID]
	secondBinding.Policy = secondEpoch
	secondBinding.OperationID = "second-operation"
	authority.bindings[secondBinding.OperationID] = secondBinding

	secondAlphaBefore, secondBetaBefore := e.Killchain.Memory.Prior(secondPolicy.Owner())
	if !e.AdmitPersistenceObservation(first).Applied {
		t.Fatal("first owner label did not apply")
	}
	secondAlphaAfter, secondBetaAfter := e.Killchain.Memory.Prior(secondPolicy.Owner())
	if secondAlphaAfter != secondAlphaBefore || secondBetaAfter != secondBetaBefore {
		t.Fatalf("same-display-tenant owner inherited another UID's label: before=(%g,%g) after=(%g,%g)", secondAlphaBefore, secondBetaBefore, secondAlphaAfter, secondBetaAfter)
	}
	if _, allocated := e.PersistenceLearningStatusFor(secondPolicy.Owner()); allocated {
		t.Fatal("same-display-tenant owner inherited another UID's dedup history")
	}
}

func TestPost25M106DedupSaturationRefusesWithoutEviction(t *testing.T) {
	e, pol, authority, first := m106Fixture(t, 2)
	if !e.AdmitPersistenceObservation(first).Applied {
		t.Fatal("first label did not apply")
	}
	second := first
	second.EvidenceID, second.OperationID = "evidence-2", "operation-2"
	authority.bindings[second.OperationID] = authority.bindings[first.OperationID]
	b := authority.bindings[second.OperationID]
	b.OperationID = second.OperationID
	authority.bindings[second.OperationID] = b
	authority.allowed[second.EvidenceID] = second
	if !e.AdmitPersistenceObservation(second).Applied {
		t.Fatal("second label did not apply")
	}
	third := first
	third.EvidenceID, third.OperationID = "evidence-3", "operation-3"
	b.OperationID = third.OperationID
	authority.bindings[third.OperationID] = b
	authority.allowed[third.EvidenceID] = third
	if result := e.AdmitPersistenceObservation(third); result.Disposition != model.PersistenceDispositionSaturated || result.Applied {
		t.Fatalf("third label did not fail closed at capacity: %+v", result)
	}
	if result := e.AdmitPersistenceObservation(first); result.Disposition != model.PersistenceDispositionDuplicate || result.Status.DedupEntries != 2 {
		t.Fatalf("saturation evicted an old ID and permitted replay: %+v", result)
	}
	status, ok := e.PersistenceLearningStatusFor(pol.Owner())
	if !ok || status.DedupEntries != 2 || status.DedupCapacity != 2 || status.QualifiedLabels != 2 {
		t.Fatalf("bounded status is not truthful: %+v ok=%t", status, ok)
	}
}

func TestPost25M106GenerationAdvancePreservesReplayBarrierWithCurrentProvenance(t *testing.T) {
	e, pol, authority, oldObservation := m106Fixture(t, 8)
	if result := e.AdmitPersistenceObservation(oldObservation); !result.Applied {
		t.Fatalf("old-generation label did not apply: %+v", result)
	}

	newEpoch := oldObservation.Policy
	newEpoch.Generation++
	if err := e.SetOwnerEpoch(newEpoch, true); err != nil {
		t.Fatal(err)
	}
	transition, allocated := e.PersistenceLearningStatusFor(pol.Owner())
	if !allocated || transition.Policy == nil || *transition.Policy != newEpoch ||
		transition.Disposition != model.PersistenceDispositionNoLabel || transition.EvidenceID != "" || transition.Outcome != "" ||
		transition.QualifiedLabels != 1 || transition.DedupEntries != 1 {
		t.Fatalf("generation transition lost lifecycle state or misattributed old evidence: %+v allocated=%t", transition, allocated)
	}
	transition.Policy.Generation = 99
	unchanged, _ := e.PersistenceLearningStatusFor(pol.Owner())
	if unchanged.Policy == nil || *unchanged.Policy != newEpoch {
		t.Fatalf("status reader exposed mutable internal policy provenance: %+v", unchanged)
	}
	if stale := e.AdmitPersistenceObservation(oldObservation); stale.Applied || stale.Disposition != model.PersistenceDispositionRejected {
		t.Fatalf("old-generation label crossed the active epoch: %+v", stale)
	}

	newObservation := oldObservation
	newObservation.Policy = newEpoch
	newObservation.EvidenceID = "new-generation-evidence"
	newObservation.OperationID = "new-generation-operation"
	newObservation.Outcome = model.PersistenceRevoked
	newBinding := authority.bindings[oldObservation.OperationID]
	newBinding.Policy = newEpoch
	newBinding.OperationID = newObservation.OperationID
	authority.bindings[newObservation.OperationID] = newBinding
	authority.allowed[newObservation.EvidenceID] = newObservation
	result := e.AdmitPersistenceObservation(newObservation)
	if !result.Applied || result.Status.Policy == nil || *result.Status.Policy != newEpoch ||
		result.Status.QualifiedLabels != 2 || result.Status.HeldLabels != 1 || result.Status.RevokedLabels != 1 {
		t.Fatalf("new-generation label has stale provenance or counts: %+v", result)
	}
	result.Status.Policy.Generation = 100
	current, _ := e.PersistenceLearningStatusFor(pol.Owner())
	if current.Policy == nil || *current.Policy != newEpoch {
		t.Fatalf("admission result exposed mutable internal policy provenance: %+v", current)
	}

	reusedID := newObservation
	reusedID.EvidenceID = oldObservation.EvidenceID
	authority.allowed[reusedID.EvidenceID] = reusedID
	if replay := e.AdmitPersistenceObservation(reusedID); replay.Applied || replay.Disposition != model.PersistenceDispositionConflict {
		t.Fatalf("generation advance evicted prior lifecycle replay barrier: %+v", replay)
	}
}

func TestPost25M106ShadowAndOwnerRecreationIsolation(t *testing.T) {
	e, oldPolicy, authority, oldObservation := m106Fixture(t, 8)
	shadow, err := e.DecideShadowChecked([]*model.WorkloadView{covView("m106-shadow", true, 2*time.Hour, false)}, oldPolicy)
	if err != nil || len(shadow) != 1 {
		t.Fatalf("shadow failed: decisions=%+v err=%v", shadow, err)
	}
	if e.Killchain.Memory.Tracked(oldPolicy.Owner()) || e.persistenceLearning[oldPolicy.Owner()] != nil {
		t.Fatal("shadow seeded belief or observed-label state")
	}
	if status := shadow[0].PersistenceLearning; status == nil || status.Source != authority.source ||
		status.Disposition != model.PersistenceDispositionNoLabel || status.QualifiedLabels != 0 {
		t.Fatalf("shadow did not report the read-only no-label state: %+v", status)
	}
	if !e.AdmitPersistenceObservation(oldObservation).Applied {
		t.Fatal("old owner label did not apply")
	}
	e.SetOwnerLive(oldPolicy.Owner(), false)
	e.ForgetOwner(oldPolicy.Owner())
	if e.Killchain.Memory.Tracked(oldPolicy.Owner()) || e.persistenceLearning[oldPolicy.Owner()] != nil || e.persistenceEpochs[oldPolicy.Owner()] != (model.PolicyEpoch{}) {
		t.Fatal("retirement retained owner learning state")
	}
	if stale := e.AdmitPersistenceObservation(oldObservation); stale.Applied || stale.Disposition != model.PersistenceDispositionRejected {
		t.Fatalf("stale observation recreated retired owner: %+v", stale)
	}

	newPolicy := oldPolicy
	newPolicy.PolicyUID = "replacement-policy-uid"
	newPolicy.PolicyGeneration = 1
	newEpoch := model.PolicyEpoch{Namespace: newPolicy.Namespace, Name: newPolicy.PolicyName, UID: newPolicy.PolicyUID, Generation: newPolicy.PolicyGeneration}
	e.SetOwnerLive(newPolicy.Owner(), true)
	if err := e.SetOwnerEpoch(newEpoch, true); err != nil {
		t.Fatal(err)
	}
	newObservation := oldObservation
	newObservation.Policy = newEpoch
	newObservation.EvidenceID = "replacement-evidence"
	newObservation.OperationID = "replacement-operation"
	binding := authority.bindings[oldObservation.OperationID]
	binding.Policy, binding.OperationID = newEpoch, newObservation.OperationID
	authority.bindings[newObservation.OperationID] = binding
	authority.allowed[newObservation.EvidenceID] = newObservation
	if result := e.AdmitPersistenceObservation(newObservation); !result.Applied || result.Status.QualifiedLabels != 1 {
		t.Fatalf("replacement owner did not start a fresh lifecycle: %+v", result)
	}
}
