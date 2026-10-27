package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// TestGate0DatastoreRestoreSelectedParametricNamespace is the Gate-0 proof for the NEW
// namespace-parametric actuator datastore-restore. It shows the frozen decision engine
// SELECTS datastore-restore for a serving pod with a bound, trusted datastore-poisoning
// observation in an ARBITRARY namespace ("p3-demo" — no hard-coded app namespace), under the
// UNTUNED default cost ceiling, with rotate+quarantine also enabled; and that it is NOT
// selected once the selecting policy's identity differs or the bound observation is absent.
// Decision LOGIC is untouched: selectability comes only from the additive recon cover + cost
// + vocabulary entries, under NeutralPhysics (the live colocation contest is governed by
// policy scope, proven separately in the lane).
func TestGate0DatastoreRestoreSelectedParametricNamespace(t *testing.T) {
	creator := "system:serviceaccount:p3:p3-attacks" // a lane trusted detector, NOT a prod console injector
	ns := "p3-demo"                                  // parametric: any namespace, no literal in the brain path
	pod := model.Pod{Namespace: ns, Name: "rag-store-1", UID: "55555555-5555-4555-8555-555555555555",
		Ready: true, ReadyReplicas: 1, StartedAt: time.Now().Add(-2 * time.Hour)}
	pod.DatastoreRestoreObservation = &model.DatastoreRestoreObservation{
		EventName: "datastore-poison-observed", EventUID: "66666666-6666-4666-8666-666666666666",
		CreatorIdentity: creator, Namespace: ns, StoreName: "datastore-content",
		StoreConfigMapUID: "44444444-4444-4444-8444-444444444444", TrustedSnapshotConfigMapUID: "22222222-2222-4222-8222-222222222222",
		ServiceUID: "11111111-1111-4111-8111-111111111111", TargetPodUID: pod.UID,
		PoisonedSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TrustedSHA256:  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ObservedAt:     time.Now().Add(-5 * time.Second),
		PolicyName:     "datastore-defense", PolicyUID: "33333333-3333-4333-8333-333333333333", PolicyGeneration: 1}
	v := &model.WorkloadView{Pod: pod, Physics: model.NeutralPhysics(), Phase: model.PhaseWarm,
		Events: []model.SecurityEventInfo{{Name: pod.DatastoreRestoreObservation.EventName, UID: pod.DatastoreRestoreObservation.EventUID,
			Type: model.AttackVectorDatastorePoison, ThreatLevel: "critical", Source: "p3-attacks", Trust: "trusted", CreatorIdentity: creator,
			TargetsPod: true, ConsoleTargetPodUID: pod.UID, Age: 5 * time.Second, CreatedAt: time.Now().Add(-5 * time.Second), AnomalyScore: .95}}}
	pol := model.Policy{Tenant: ns, Namespace: ns, PolicyName: "datastore-defense", PolicyUID: pod.DatastoreRestoreObservation.PolicyUID, PolicyGeneration: 1,
		Mode: "active", TraceEnabled: true, MaxMovesPerTick: 1, NormSparsity: .4, FlowDisruption: .6, WeightSecrets: .8, Lambda: .4,
		CostCeiling: model.DefaultCostCeiling, MinAvailableReplicas: 1, ProactiveFloor: 15 * time.Minute, ExposurePressureScale: 15 * time.Minute,
		AntiOverRotationWindow: 90 * time.Second, TickInterval: 10 * time.Second, EventAgeHorizon: time.Hour, EventDriven: true, ReactiveOnly: true,
		AssetWeights:   model.AssetLabelWeights{Default: .4},
		EnabledActions: map[model.Action]bool{model.ActionDatastoreRestore: true, model.ActionRotate: true, model.ActionQuarantine: true}}
	clock := exposure.NewClock()
	now := time.Now()
	clock.Observe(exposure.Observation{Owner: pol.Owner(), Namespace: pod.Namespace, Pod: pod.Name, StartedAt: pod.StartedAt, Fingerprints: model.ExposureFingerprints(pod)}, now)
	v.ExposureByVariable = clock.Since(pol.Owner(), pod.Namespace, pod.Name, now)
	engine := NewCoverageEngine()
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("UCW recon profile absent")
	}
	engine.Recon = profile
	set, _ := engine.AssembleSet([]*model.WorkloadView{v}, pol)
	seen := map[model.Action]bool{}
	for _, c := range set.Candidates {
		seen[c.Action] = true
	}
	for _, e := range set.Excluded {
		seen[e.Action] = true
	}
	if !seen[model.ActionDatastoreRestore] || !seen[model.ActionRotate] || !seen[model.ActionQuarantine] {
		t.Fatalf("normal policy alternatives absent: candidates=%+v excluded=%+v", set.Candidates, set.Excluded)
	}
	foundCover := false
	for _, c := range set.Candidates {
		if c.Action == model.ActionDatastoreRestore && len(c.CoverKeys) > 0 {
			foundCover = true
		}
	}
	if !foundCover {
		t.Fatalf("exact datastore observation gave no action-specific cover: %+v", set)
	}
	decisions := engine.Decide([]*model.WorkloadView{v}, pol)
	if len(decisions) != 1 || decisions[0].Trace == nil {
		t.Fatalf("normal datastore decision absent: %+v", decisions)
	}
	if !decisions[0].Selected || decisions[0].Action != model.ActionDatastoreRestore {
		t.Fatalf("frozen active policy did not select datastore-restore over rotate/quarantine: %+v", decisions[0])
	}
	// Negative control 1: a selecting policy whose identity differs drops the candidate.
	bad := pol
	bad.PolicyUID = "77777777-7777-4777-8777-777777777777"
	wrong, _ := engine.AssembleSet([]*model.WorkloadView{v}, bad)
	for _, c := range wrong.Candidates {
		if c.Action == model.ActionDatastoreRestore {
			t.Fatal("wrong selecting policy kept datastore-restore candidate")
		}
	}
	// Negative control 2: without the bound observation the action gets no cover and is not selected.
	v2 := &model.WorkloadView{Pod: model.Pod{Namespace: ns, Name: "rag-store-2", UID: "88888888-8888-4888-8888-888888888888",
		Ready: true, ReadyReplicas: 1, StartedAt: pod.StartedAt}, Physics: model.NeutralPhysics(), Phase: model.PhaseWarm}
	clock.Observe(exposure.Observation{Owner: pol.Owner(), Namespace: ns, Pod: v2.Pod.Name, StartedAt: v2.Pod.StartedAt, Fingerprints: model.ExposureFingerprints(v2.Pod)}, now)
	v2.ExposureByVariable = clock.Since(pol.Owner(), ns, v2.Pod.Name, now)
	d2 := engine.Decide([]*model.WorkloadView{v2}, pol)
	for _, d := range d2 {
		if d.Selected && d.Action == model.ActionDatastoreRestore {
			t.Fatalf("datastore-restore selected WITHOUT a bound observation: %+v", d)
		}
	}
	// Negative control 3: an observation whose current content already equals the trusted
	// snapshot is NOT poisoned, so the fact is not minted and the action gets no cover.
	v3 := &model.WorkloadView{Pod: pod, Physics: model.NeutralPhysics(), Phase: model.PhaseWarm, Events: v.Events, ExposureByVariable: v.ExposureByVariable}
	clean := *pod.DatastoreRestoreObservation
	clean.PoisonedSHA256 = clean.TrustedSHA256 // store already matches trusted => nothing to remediate
	v3.Pod.DatastoreRestoreObservation = &clean
	for _, d := range engine.Decide([]*model.WorkloadView{v3}, pol) {
		if d.Selected && d.Action == model.ActionDatastoreRestore {
			t.Fatalf("datastore-restore selected when store already matches trusted snapshot: %+v", d)
		}
	}
}
