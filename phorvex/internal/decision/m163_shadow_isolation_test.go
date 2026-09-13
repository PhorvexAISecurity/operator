/*
 * M-163 head regressions (decision side): a shadow evaluation must read production
 * knowledge and cost state, compute its hypothetical decision, and leave production state
 * and operational counters untouched.
 *
 * The producers are REAL. platform.Derive supplies the production physics witness and
 * calib.Runtime.ShadowViews supplies the counterfactual one, from a calibration snapshot the
 * runtime legitimately retains under its DEFAULT 30-minute refresh cadence. Every Pod is
 * Running: the divergence is a real rescheduling (a second tenant moved from n2 to n1 ten
 * minutes after the last refresh), not an unset Phase. The two witnesses then land on
 * opposite sides of killchain's `CoResidency > 1` AI-stage predicate, which is what let the
 * shadow pass fold a stage transition into the production stage clock.
 *
 * The retained baseline characterization is preserved separately at
 * workflow/fixes/V3-M163/evidence/baseline-repro/r2_shadow_stageclock_test.go (executed
 * output in evidence/baseline-stale-shadow.log); these are the permanent assertions.
 */

package decision

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/go-logr/logr"
	dto "github.com/prometheus/client_model/go"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/calib"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/platform"
)

const m163SnapshotAt = "2026-09-10T00:00:00Z"

func m163Now(t *testing.T) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, m163SnapshotAt)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// m163Snapshot is the CURRENT fleet: a GPU pod and a second tenant's pod co-resident on n1.
// Both are Running, so platform and calib admit the same population — the disagreement below
// comes from calibration's retained sample, not from a filter mismatch.
func m163Snapshot(t *testing.T) *ingest.Snapshot {
	t.Helper()
	now := m163Now(t)
	pods := []model.Pod{
		{
			Namespace: "ns-a", Name: "gpu-pod", UID: "uid-gpu", Node: "n1",
			Phase: "Running", HasGPU: true, ModelID: "m1", ImageID: "img-1",
			DesiredReplicas: 3, ReadyReplicas: 3, Ready: true,
			StartedAt: now.Add(-time.Hour), Age: time.Hour,
		},
		{
			Namespace: "ns-b", Name: "neighbour", UID: "uid-neighbour", Node: "n1",
			Phase: "Running", ModelID: "m2", ImageID: "img-2",
			DesiredReplicas: 3, ReadyReplicas: 3, Ready: true,
			StartedAt: now.Add(-time.Hour), Age: time.Hour,
		},
	}
	byKey := map[string]*model.Pod{}
	for i := range pods {
		byKey[pods[i].Namespace+"/"+pods[i].Name] = &pods[i]
	}
	return &ingest.Snapshot{
		Now: now, Pods: pods, PodByKey: byKey,
		Nodes:                []ingest.NodeInfo{{Name: "n1", Schedulable: true, AllocatableCPUMilli: 8000, AllocatableMemBytes: 1 << 34}},
		NamespaceLabels:      map[string]map[string]string{},
		EventByPod:           map[string][]model.SecurityEventInfo{},
		PodInventoryComplete: true, PolicyInventoryComplete: true, EventInventoryComplete: true,
	}
}

// m163StaleRuntime returns a calibration Runtime whose ACTIVE refresh still describes the
// fleet ten minutes ago, when the second tenant was on n2. The second ObserveSnapshot is past
// the 5-minute sample interval but inside the 30-minute DEFAULT refresh interval, so the
// runtime legitimately keeps the earlier node population — the production condition.
func m163StaleRuntime(t *testing.T, snap *ingest.Snapshot, physicsByKey map[string]model.PhysicsWitness) *calib.Runtime {
	t.Helper()
	rt := calib.NewRuntime(calib.RuntimeConfig{}, logr.Discard())

	previous := *snap
	previous.Now = snap.Now.Add(-10 * time.Minute)
	previous.Pods = append([]model.Pod(nil), snap.Pods...)
	previous.Pods[1].Node = "n2"
	previous.Nodes = append(append([]ingest.NodeInfo(nil), snap.Nodes...),
		ingest.NodeInfo{Name: "n2", Schedulable: true})
	_, previousPhysics := platform.Derive(&previous)
	if _, refreshed, err := rt.ObserveSnapshot(&previous, previousPhysics); err != nil || !refreshed {
		t.Fatalf("fixture: initial calibration refresh did not happen: refreshed=%v err=%v", refreshed, err)
	}
	if _, refreshed, err := rt.ObserveSnapshot(snap, physicsByKey); err != nil || refreshed {
		t.Fatalf("fixture: current snapshot must be retained under the default cadence: refreshed=%v err=%v", refreshed, err)
	}
	return rt
}

func m163Policy() model.Policy {
	return model.Policy{
		Tenant:                 "t",
		Namespace:              "ns-a",
		PolicyName:             "defense",
		PolicyUID:              "uid-policy-a",
		TickID:                 "tick-fixed",
		Lambda:                 0.6,
		NormSparsity:           1,
		FlowDisruption:         1,
		MaxMovesPerTick:        1,
		ProactiveFloor:         30 * time.Minute,
		EventAgeHorizon:        30 * time.Minute,
		AntiOverRotationWindow: 5 * time.Minute,
		MinAvailableReplicas:   1,
		TraceEnabled:           true,
		DryRun:                 true,
		EnabledActions: map[model.Action]bool{
			model.ActionRotate: true, model.ActionQuarantine: true,
		},
		AssetWeightFromLabels: func(map[string]string) float64 { return 1 },
	}
}

// m163View rebuilds the per-pod view the runner assembles (manager.go), using the REAL
// platform witness for this snapshot. A fresh view per tick mirrors the runner, which
// rebuilds views every tick from the snapshot.
func m163View(t *testing.T, snap *ingest.Snapshot) *model.WorkloadView {
	t.Helper()
	_, physicsByKey := platform.Derive(snap)
	ph, ok := physicsByKey["ns-a/gpu-pod"]
	if !ok {
		t.Fatal("fixture: platform produced no witness for the GPU pod")
	}
	return &model.WorkloadView{
		Pod:                snap.Pods[0],
		Phase:              model.PhaseWarm,
		Physics:            ph,
		ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: 20 * time.Minute},
	}
}

func m163Views(t *testing.T, snap *ingest.Snapshot) []*model.WorkloadView {
	t.Helper()
	return []*model.WorkloadView{m163View(t, snap)}
}

func m163Engine(t *testing.T) *CoverageEngine {
	t.Helper()
	e := NewCoverageEngine()
	at := m163Now(t)
	e.Now = func() time.Time { return at }
	return e
}

// m163StaleShadowViews runs the real ShadowViews producer over a real production view.
func m163StaleShadowViews(t *testing.T, rt *calib.Runtime, snap *ingest.Snapshot) []*model.WorkloadView {
	t.Helper()
	shadowViews, ok := rt.ShadowViews(m163Views(t, snap))
	if !ok || len(shadowViews) != 1 {
		t.Fatalf("fixture: ShadowViews unavailable: ok=%v n=%d", ok, len(shadowViews))
	}
	return shadowViews
}

// m163Belief is the part of the production record the kill-chain belief writes.
type m163Belief struct {
	stage    string
	inStage  float64
	hazard   float64
	urgency  float64
	preempt  float64
	coverage float64
}

func m163Read(t *testing.T, d model.Decision) m163Belief {
	t.Helper()
	if d.Trace == nil {
		t.Fatal("fixture: trace disabled")
	}
	return m163Belief{
		stage:    d.Stage,
		inStage:  d.Trace.Inputs.Clocks.InStageSec,
		hazard:   d.StageHazard,
		urgency:  d.Trace.Inputs.StageUrgency.Value,
		preempt:  d.PreemptMargin,
		coverage: d.CoverageValue,
	}
}

func m163Decide(t *testing.T, e *CoverageEngine, snap *ingest.Snapshot, pol model.Policy) []model.Decision {
	t.Helper()
	decisions, err := e.DecideChecked(m163Views(t, snap), pol)
	if err != nil {
		t.Fatalf("production decide: %v", err)
	}
	return decisions
}

func m163Shadow(t *testing.T, e *CoverageEngine, views []*model.WorkloadView, pol model.Policy) []model.Decision {
	t.Helper()
	decisions, err := e.DecideShadowChecked(views, pol)
	if err != nil {
		t.Fatalf("shadow decide: %v", err)
	}
	return decisions
}

// ---------------------------------------------------------------------------
// Fixture relevance: the incident condition must actually be produced.
// ---------------------------------------------------------------------------

// The bug needs the two REAL witnesses to straddle killchain's AI-stage predicate. If a
// producer changes and they stop disagreeing, the regression below would pass vacuously —
// so this test fails instead, loudly.
func TestM163_FixtureCrossesTheStagePredicateThroughRealProducers(t *testing.T) {
	snap := m163Snapshot(t)
	_, physicsByKey := platform.Derive(snap)
	production := physicsByKey["ns-a/gpu-pod"]
	shadow := m163StaleShadowViews(t, m163StaleRuntime(t, snap, physicsByKey), snap)[0].Physics

	if !(production.CoResidency > 1) {
		t.Fatalf("fixture stale: production CoResidency %.4f is not > 1", production.CoResidency)
	}
	if !(production.ModelRarity > 1) {
		t.Fatalf("fixture stale: production ModelRarity %.4f is not > 1, arm (2) cannot fire", production.ModelRarity)
	}
	if shadow.CoResidency > 1 {
		t.Fatalf("fixture stale: shadow CoResidency %.4f is also > 1, the arms no longer disagree", shadow.CoResidency)
	}

	// Confirm the disagreement reaches the STAGE, not just the physics field.
	km := killchain.NewModel()
	pol := m163Policy()
	prodView := m163View(t, snap)
	shadowView := m163StaleShadowViews(t, m163StaleRuntime(t, snap, physicsByKey), snap)[0]
	prodStage := km.AssessMode(prodView, pol, 1200, pol.ProactiveFloor.Seconds(), killchain.EvalShadow).StageName
	shadowStage := km.AssessMode(shadowView, pol, 1200, pol.ProactiveFloor.Seconds(), killchain.EvalShadow).StageName
	if prodStage == shadowStage {
		t.Fatalf("fixture stale: production and shadow agree on stage %q; the incident needs disagreement", prodStage)
	}
	t.Logf("fixture live: production stage=%s (coResidency %.4f) vs shadow stage=%s (coResidency %.4f)",
		prodStage, production.CoResidency, shadowStage, shadow.CoResidency)
}

// ---------------------------------------------------------------------------
// The incident: a shadow evaluation must not change the next production decision.
// ---------------------------------------------------------------------------

// The core invariant, through the shipped flow (ShadowViews -> DecideShadowChecked ->
// DecideChecked): an engine with the shadow arm must produce the byte-identical next
// production decision as the same engine history with the shadow step omitted.
func TestM163_StaleShadowLeavesNextProductionDecisionIdentical(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163Policy()
	_, physicsByKey := platform.Derive(snap)

	// Arm A — control: production only. Tick 1 seeds the stage slot; tick 2 is the subject.
	control := m163Engine(t)
	m163Decide(t, control, snap, pol)
	controlDecisions := m163Decide(t, control, snap, pol)

	// Arm B — the shipped ordering: on tick 2 the shadow arm runs FIRST.
	subject := m163Engine(t)
	m163Decide(t, subject, snap, pol)
	m163Shadow(t, subject, m163StaleShadowViews(t, m163StaleRuntime(t, snap, physicsByKey), snap), pol)
	subjectDecisions := m163Decide(t, subject, snap, pol)

	want, got := m163Read(t, controlDecisions[0]), m163Read(t, subjectDecisions[0])
	if got != want {
		t.Fatalf("a stale shadow perturbed the next production belief:\n control : %+v\n shadowed: %+v", want, got)
	}
	if want.inStage <= 0 {
		t.Fatalf("fixture: the control tick accrued no dwell (%v), so a reset would be invisible", want.inStage)
	}
	if !reflect.DeepEqual(controlDecisions, subjectDecisions) {
		t.Fatalf("a stale shadow changed the complete production decision:\n control : %+v\n shadowed: %+v",
			controlDecisions[0], subjectDecisions[0])
	}
	t.Logf("production belief preserved across a stale shadow: stage=%s inStage=%.1fs hazard=%.6f urgency=%.6f preempt=%.6f coverage=%.6f",
		got.stage, got.inStage, got.hazard, got.urgency, got.preempt, got.coverage)
}

// Positive control on attribution: a shadow that derives the SAME stage was already benign on
// baseline, so it cannot be what proves the repair. Both arms must stay identical, and the
// stale arm must be identical to the same-stage arm — otherwise the isolation is partial.
func TestM163_SameStageShadowAndStaleShadowAreEquallyInert(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163Policy()
	_, physicsByKey := platform.Derive(snap)

	control := m163Engine(t)
	m163Decide(t, control, snap, pol)
	controlDecisions := m163Decide(t, control, snap, pol)

	benign := m163Engine(t)
	m163Decide(t, benign, snap, pol)
	m163Shadow(t, benign, m163Views(t, snap), pol) // same physics => same stage
	benignDecisions := m163Decide(t, benign, snap, pol)

	stale := m163Engine(t)
	m163Decide(t, stale, snap, pol)
	m163Shadow(t, stale, m163StaleShadowViews(t, m163StaleRuntime(t, snap, physicsByKey), snap), pol)
	staleDecisions := m163Decide(t, stale, snap, pol)

	if !reflect.DeepEqual(controlDecisions, benignDecisions) {
		t.Fatalf("a same-stage shadow perturbed production: control=%+v benign=%+v",
			m163Read(t, controlDecisions[0]), m163Read(t, benignDecisions[0]))
	}
	if !reflect.DeepEqual(benignDecisions, staleDecisions) {
		t.Fatalf("a stage-changing shadow is not as inert as a same-stage one: benign=%+v stale=%+v",
			m163Read(t, benignDecisions[0]), m163Read(t, staleDecisions[0]))
	}
}

// Isolation must not depend on how MANY shadows ran, nor on their mix.
func TestM163_RepeatedAndMixedShadowsLeaveProductionIdentical(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163Policy()
	_, physicsByKey := platform.Derive(snap)

	control := m163Engine(t)
	var controlTicks [][]model.Decision
	for i := 0; i < 4; i++ {
		controlTicks = append(controlTicks, m163Decide(t, control, snap, pol))
	}

	subject := m163Engine(t)
	var subjectTicks [][]model.Decision
	for i := 0; i < 4; i++ {
		rt := m163StaleRuntime(t, snap, physicsByKey)
		for j := 0; j < 3; j++ {
			m163Shadow(t, subject, m163StaleShadowViews(t, rt, snap), pol)
			m163Shadow(t, subject, m163Views(t, snap), pol)
		}
		subjectTicks = append(subjectTicks, m163Decide(t, subject, snap, pol))
	}

	for i := range controlTicks {
		if !reflect.DeepEqual(controlTicks[i], subjectTicks[i]) {
			t.Fatalf("tick %d diverged after 6 shadows: control=%+v subject=%+v",
				i, m163Read(t, controlTicks[i][0]), m163Read(t, subjectTicks[i][0]))
		}
	}
}

// A shadow arriving BEFORE the owner's first production tick must not seed the stage slot:
// the first real tick still has to take the pod-age fallback, and the second still has to
// accrue dwell from it.
func TestM163_ShadowOnAFreshSlotDoesNotSeedTheStageClock(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163Policy()
	_, physicsByKey := platform.Derive(snap)

	control := m163Engine(t)
	controlFirst := m163Decide(t, control, snap, pol)
	controlSecond := m163Decide(t, control, snap, pol)

	subject := m163Engine(t)
	subject.SetOwnerLive(pol.Owner(), true)
	m163Shadow(t, subject, m163StaleShadowViews(t, m163StaleRuntime(t, snap, physicsByKey), snap), pol)
	subjectFirst := m163Decide(t, subject, snap, pol)
	subjectSecond := m163Decide(t, subject, snap, pol)

	if got, want := m163Read(t, subjectFirst[0]), m163Read(t, controlFirst[0]); got != want {
		t.Fatalf("a shadow before the first production tick changed it:\n control: %+v\n subject: %+v", want, got)
	}
	if got, want := m163Read(t, subjectSecond[0]), m163Read(t, controlSecond[0]); got != want {
		t.Fatalf("a shadow before the first production tick changed the second one:\n control: %+v\n subject: %+v", want, got)
	}
}

// A pod recreated under a new UID is a fresh slot. A shadow observing the replacement must
// not adopt it on production's behalf.
func TestM163_ShadowDoesNotAdoptAUIDReplacement(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163Policy()

	recreated := m163Snapshot(t)
	recreated.Pods[0].UID = "uid-gpu-2"
	recreated.PodByKey["ns-a/gpu-pod"] = &recreated.Pods[0]
	_, recreatedPhysics := platform.Derive(recreated)

	control := m163Engine(t)
	m163Decide(t, control, snap, pol)
	controlAfter := m163Decide(t, control, recreated, pol)

	subject := m163Engine(t)
	m163Decide(t, subject, snap, pol)
	m163Shadow(t, subject, m163StaleShadowViews(t, m163StaleRuntime(t, recreated, recreatedPhysics), recreated), pol)
	subjectAfter := m163Decide(t, subject, recreated, pol)

	if got, want := m163Read(t, subjectAfter[0]), m163Read(t, controlAfter[0]); got != want {
		t.Fatalf("a shadow consumed the UID replacement:\n control: %+v\n subject: %+v", want, got)
	}
}

// Positive control on the MODEL: the repair is isolation, not a frozen clock. A real
// production stage transition must still restart the dwell at 0.
func TestM163_ProductionStageTransitionStillResetsDwell(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163Policy()

	e := m163Engine(t)
	before := m163Read(t, m163Decide(t, e, snap, pol)[0])
	if before.inStage <= 0 {
		t.Fatalf("fixture: first tick accrued no dwell (%v)", before.inStage)
	}

	// Move the co-resident tenant off n1: the REAL platform witness now falls below the
	// AI-stage predicate, so production genuinely transitions.
	moved := m163Snapshot(t)
	moved.Pods[1].Node = "n2"
	moved.PodByKey["ns-b/neighbour"] = &moved.Pods[1]
	moved.Nodes = append(moved.Nodes, ingest.NodeInfo{Name: "n2", Schedulable: true})

	after := m163Read(t, m163Decide(t, e, moved, pol)[0])
	if after.stage == before.stage {
		t.Fatalf("fixture: production did not transition; both ticks read stage %q", before.stage)
	}
	if after.inStage != 0 {
		t.Fatalf("a REAL production stage transition must restart the dwell: inStage=%v, want 0", after.inStage)
	}
	t.Logf("production transition preserved: %s (inStage %.1fs) -> %s (inStage %.1fs)",
		before.stage, before.inStage, after.stage, after.inStage)
}

// ---------------------------------------------------------------------------
// Lazy owner/learning state.
// ---------------------------------------------------------------------------

// The legacy-alias case under an ENABLED freeze. Creating the first bucket calls
// RLS.SetFrozen(true) on the legacy singleton, and that REVERTS theta to the shipped prior
// and clears primed — so the learned values sitting in the singleton before creation are
// values production is about to discard. A shadow that priced against them would report a
// cost the production tick can never produce. It must price against the prior instead, and
// must not perform the reversion itself.
func TestM163_ShadowUnderAnEnabledFreezePricesWhatProductionWillPrice(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163Policy()

	e := m163Engine(t)
	e.SetOwnerLive(pol.Owner(), true)
	// Train the legacy singleton directly: this is the state a pre-existing single-tenant
	// deployment carries into its first per-owner bucket creation.
	for i := 0; i < 8; i++ {
		e.Cost.ObserveRotation(m163View(t, snap), 0.5)
	}
	if !e.Cost.RLS.Primed() {
		t.Fatal("precondition: the legacy singleton did not become primed")
	}
	learnedRotate := e.Cost.ECost(m163View(t, snap), model.Move{Action: model.ActionRotate}, pol)

	e.SetCostCalibrationFrozen(true) // the operator throws the PHVX-2 switch BEFORE any bucket exists
	if !e.CostCalibrationFrozen() {
		t.Fatal("precondition: the freeze switch did not take")
	}
	if !e.Cost.RLS.Primed() {
		t.Fatal("precondition: with no buckets yet, the switch must not have touched the singleton")
	}

	shadow := m163Shadow(t, e, m163Views(t, snap), pol)

	// The shadow must not have performed production's reversion on the shared calibrator.
	if !e.Cost.RLS.Primed() {
		t.Fatal("the shadow reverted the legacy singleton's learned parameters")
	}

	// Production now creates the bucket, which reverts theta to the prior.
	prod := m163Decide(t, e, snap, pol)
	if e.Cost.RLS.Primed() {
		t.Fatal("precondition: creating the first bucket under a freeze must revert the RLS")
	}
	frozenRotate := e.Cost.ECost(m163View(t, snap), model.Move{Action: model.ActionRotate}, pol)
	if frozenRotate == learnedRotate {
		t.Fatalf("precondition: the freeze did not change the price (%v), so this test cannot discriminate", frozenRotate)
	}

	if shadow[0].BlindCost != frozenRotate {
		t.Fatalf("the shadow priced %v against learned values production discarded; production prices %v",
			shadow[0].BlindCost, frozenRotate)
	}
	if shadow[0].BlindCost != prod[0].BlindCost {
		t.Fatalf("the shadow's price %v differs from the production price %v it was meant to preview",
			shadow[0].BlindCost, prod[0].BlindCost)
	}
}

// A shadow must not be the event that brings an owner's economic unit into existence: no
// bucket, no consumed seed, no legacy alias, no BucketMeta, no creation event, no prior.
func TestM163_ShadowDoesNotCreateOwnerStateOrConsumeSeed(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163Policy()
	pol.Lambda = 3.0
	_, physicsByKey := platform.Derive(snap)

	e := m163Engine(t)
	e.SetOwnerLive(pol.Owner(), true)
	aliasDualBefore := e.Cost.Dual.Lambda()

	shadow := m163Shadow(t, e, m163StaleShadowViews(t, m163StaleRuntime(t, snap, physicsByKey), snap), pol)
	if len(shadow) != 1 {
		t.Fatalf("shadow produced %d decisions, want 1", len(shadow))
	}

	if c, ok := e.costByOwner[pol.Owner()]; ok {
		t.Fatalf("a shadow created the owner's cost bucket: %+v", c)
	}
	if _, ok := e.BucketMetaFor(pol.Owner()); ok {
		t.Fatal("a shadow minted a BucketMeta ownership record")
	}
	if e.aliasOwner != "" || e.aliasRetired {
		t.Fatalf("a shadow claimed or retired the legacy alias: owner=%q retired=%v", e.aliasOwner, e.aliasRetired)
	}
	if e.creationEvent != 0 {
		t.Fatalf("a shadow advanced the creation counter to %d", e.creationEvent)
	}
	if got := e.Cost.Dual.Lambda(); got != aliasDualBefore {
		t.Fatalf("a shadow reseeded the legacy singleton's dual: %v -> %v", aliasDualBefore, got)
	}
	if e.Killchain.Memory.Tracked(pol.Owner()) {
		t.Fatal("a shadow seeded the owner's conjugate prior")
	}

	// The FIRST production tick still creates the bucket itself, at the seed IT carries.
	later := pol
	later.Lambda = 0.25
	m163Decide(t, e, snap, later)
	meta, ok := e.BucketMetaFor(later.Owner())
	if !ok {
		t.Fatal("production did not create the owner's bucket")
	}
	if meta.LambdaSeedConsumed != 0.25 {
		t.Fatalf("the shadow consumed the seed: bucket was born at lambda %v, want the production tick's 0.25",
			meta.LambdaSeedConsumed)
	}
	if meta.CreationEvent != 1 {
		t.Fatalf("creation event = %d, want 1 (the shadow must not have advanced it)", meta.CreationEvent)
	}
	if e.aliasOwner != later.Owner() {
		t.Fatalf("the legacy alias went to %q, want the first PRODUCTION owner %q", e.aliasOwner, later.Owner())
	}
}

// The M-140 lifecycle guard applies to the shadow entrypoint too: a retired owner is
// rejected before allocation, and a live owner's state is untouched by another's shadow.
func TestM163_ShadowRejectsRetiredOwnerAndIsolatesLiveOwners(t *testing.T) {
	snap := m163Snapshot(t)
	_, physicsByKey := platform.Derive(snap)

	retiring := m163Policy()
	retiring.PolicyUID = "uid-policy-retired"
	live := m163Policy()
	live.PolicyUID = "uid-policy-live"

	// Control: the same two owners, the same retirement, and NO shadow work at all.
	control := m163Engine(t)
	control.SetOwnerLive(retiring.Owner(), true)
	control.SetOwnerLive(live.Owner(), true)
	m163Decide(t, control, snap, retiring)
	m163Decide(t, control, snap, live)
	control.SetOwnerLive(retiring.Owner(), false)
	control.ForgetOwner(retiring.Owner())
	controlLive := m163Decide(t, control, snap, live)

	subject := m163Engine(t)
	subject.SetOwnerLive(retiring.Owner(), true)
	subject.SetOwnerLive(live.Owner(), true)
	m163Decide(t, subject, snap, retiring)
	m163Decide(t, subject, snap, live)
	subject.SetOwnerLive(retiring.Owner(), false)
	subject.ForgetOwner(retiring.Owner())

	liveBucket := subject.costByOwner[live.Owner()]
	liveLambda := liveBucket.Dual.Lambda()
	liveAlpha, liveBeta := subject.Killchain.Memory.Prior(live.Owner())

	shadowViews := m163StaleShadowViews(t, m163StaleRuntime(t, snap, physicsByKey), snap)
	if _, err := subject.DecideShadowChecked(shadowViews, retiring); err != ErrOwnerRetired {
		t.Fatalf("shadow for a retired owner returned %v, want ErrOwnerRetired", err)
	}
	if _, ok := subject.costByOwner[retiring.Owner()]; ok {
		t.Fatal("a shadow resurrected the retired owner's bucket")
	}
	if subject.Killchain.Memory.Tracked(retiring.Owner()) {
		t.Fatal("a shadow resurrected the retired owner's prior")
	}

	// The live owner is untouched by the retired owner's rejected shadow AND by its own.
	m163Shadow(t, subject, shadowViews, live)
	if got := subject.costByOwner[live.Owner()]; got != liveBucket {
		t.Fatal("the live owner's bucket was replaced")
	}
	if got := liveBucket.Dual.Lambda(); got != liveLambda {
		t.Fatalf("the live owner's lambda moved: %v -> %v", liveLambda, got)
	}
	if a, b := subject.Killchain.Memory.Prior(live.Owner()); a != liveAlpha || b != liveBeta {
		t.Fatalf("the live owner's prior moved: (%v,%v) -> (%v,%v)", liveAlpha, liveBeta, a, b)
	}
	if subjectLive := m163Decide(t, subject, snap, live); !reflect.DeepEqual(controlLive, subjectLive) {
		t.Fatalf("the live owner's next production decision moved:\n control: %+v\n subject: %+v",
			m163Read(t, controlLive[0]), m163Read(t, subjectLive[0]))
	}
}

// A shadow must price from the owner's EXISTING learned state — substituting a fresh belief
// or cost model would report a price the production tick never saw. The trained values must
// also survive the shadow untouched.
func TestM163_ShadowPricesFromLearnedStateAndPreservesIt(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163Policy()
	_, physicsByKey := platform.Derive(snap)

	trained := m163Engine(t)
	for i := 0; i < 6; i++ {
		m163Decide(t, trained, snap, pol)
	}
	for i := 0; i < 8; i++ {
		trained.ObserveRotation(pol.Owner(), m163View(t, snap), 0.5)
	}
	bucket := trained.costByOwner[pol.Owner()]
	alpha, beta := trained.Killchain.Memory.Prior(pol.Owner())
	if alpha == 1 && beta == 4 {
		t.Fatalf("precondition: the conjugate prior never left the shipped default (%v,%v)", alpha, beta)
	}
	if !bucket.RLS.Primed() || bucket.RLS.Updates() != 8 {
		t.Fatalf("precondition: RLS not trained (primed=%v updates=%d)", bucket.RLS.Primed(), bucket.RLS.Updates())
	}
	lambda := bucket.Dual.Lambda()
	quantile, _ := bucket.ConformalQuantile()
	updates := bucket.RLS.Updates()

	shadowViews := m163StaleShadowViews(t, m163StaleRuntime(t, snap, physicsByKey), snap)
	shadow := m163Shadow(t, trained, shadowViews, pol)

	// Priced from the trained bucket, not from a fresh model.
	fresh := m163Engine(t)
	fresh.SetOwnerLive(pol.Owner(), true)
	freshShadow := m163Shadow(t, fresh, shadowViews, pol)
	if shadow[0].Cost == freshShadow[0].Cost && shadow[0].BlindCost == freshShadow[0].BlindCost {
		t.Fatalf("the shadow priced identically to an untrained engine (cost=%v blind=%v): "+
			"a fresh-model substitution would be undetectable here",
			shadow[0].Cost, shadow[0].BlindCost)
	}
	if want := bucket.ECost(shadowViews[0], model.Move{Action: model.ActionRotate}, pol); shadow[0].BlindCost != want {
		t.Fatalf("the shadow's blind cost %v is not the TRAINED bucket's price %v", shadow[0].BlindCost, want)
	}
	if shadow[0].Trace == nil || shadow[0].Trace.LambdaRuntimeLegacy != lambda {
		t.Fatalf("the shadow did not read the trained runtime lambda %v", lambda)
	}

	// And nothing it read moved.
	if got := trained.costByOwner[pol.Owner()]; got != bucket {
		t.Fatal("the shadow replaced the owner's cost bucket")
	}
	if got := bucket.Dual.Lambda(); got != lambda {
		t.Fatalf("the shadow moved the dual price: %v -> %v", lambda, got)
	}
	if got := bucket.RLS.Updates(); got != updates {
		t.Fatalf("the shadow taught the RLS: %d -> %d updates", updates, got)
	}
	if got, _ := bucket.ConformalQuantile(); got != quantile {
		t.Fatalf("the shadow moved the conformal quantile: %v -> %v", quantile, got)
	}
	if a, b := trained.Killchain.Memory.Prior(pol.Owner()); a != alpha || b != beta {
		t.Fatalf("the shadow taught the conjugate prior: (%v,%v) -> (%v,%v)", alpha, beta, a, b)
	}
	if shadow[0].Trace.DualUpdate.Applied {
		t.Fatalf("the shadow reported a production dual mutation: %+v", shadow[0].Trace.DualUpdate)
	}
}

// ---------------------------------------------------------------------------
// Caller-owned views.
// ---------------------------------------------------------------------------

// M-28 stamps HasEventEvidence onto the view so the proactive-cadence law can read it. A
// shadow must not write the runner's view — but its own generator still has to see its own
// correctly computed evidence, or the counterfactual action set silently loses candidates.
func TestM163_ShadowDoesNotStampCallerViewsButGeneratesFromItsOwnEvidence(t *testing.T) {
	pol := m163Policy()
	// Exposure is inside the 30m proactive floor and outside the 5m reactive window, so the
	// cadence cap governs: with evidence it fails open, without evidence it vetoes.
	build := func() *model.WorkloadView {
		v := covView("evidenced", true, 10*time.Minute, false)
		v.Events = []model.SecurityEventInfo{{
			Name: "evt-1", Source: "detector", Type: "PolicyViolation",
			ThreatLevel: "high", TargetsPod: true, Age: time.Minute,
		}}
		return v
	}

	e := m163Engine(t)
	shadowView := build()
	if shadowView.HasEventEvidence {
		t.Fatal("fixture: the caller's view already carries the stamp")
	}
	shadow := m163Shadow(t, e, []*model.WorkloadView{shadowView}, pol)

	if shadowView.HasEventEvidence {
		t.Fatal("a shadow stamped HasEventEvidence onto the caller's view")
	}
	if !shadow[0].Feasible {
		t.Fatalf("the shadow generator did not consume its own evidence: %q", shadow[0].InfeasibleWhy)
	}

	// Production still stamps, and an evidence-less pod is still capped — the M-28 behaviour
	// this isolation must not weaken.
	prodView := build()
	prod := m163Decide2(t, e, []*model.WorkloadView{prodView}, pol)
	if !prodView.HasEventEvidence {
		t.Fatal("production stopped stamping HasEventEvidence onto the shared view")
	}
	if !prod[0].Feasible {
		t.Fatalf("production lost the evidenced candidate: %q", prod[0].InfeasibleWhy)
	}

	bare := covView("evidence-less", true, 10*time.Minute, false)
	capped := m163Decide2(t, e, []*model.WorkloadView{bare}, pol)
	if capped[0].Feasible {
		t.Fatal("the M-28 proactive-cadence cap stopped firing on an evidence-less pod")
	}
	shadowBare := covView("evidence-less", true, 10*time.Minute, false)
	shadowCapped := m163Shadow(t, e, []*model.WorkloadView{shadowBare}, pol)
	if shadowCapped[0].Feasible {
		t.Fatal("the shadow arm bypassed the proactive-cadence cap on an evidence-less pod")
	}
}

func m163Decide2(t *testing.T, e *CoverageEngine, views []*model.WorkloadView, pol model.Policy) []model.Decision {
	t.Helper()
	decisions, err := e.DecideChecked(views, pol)
	if err != nil {
		t.Fatalf("production decide: %v", err)
	}
	return decisions
}

// ---------------------------------------------------------------------------
// Production metrics.
// ---------------------------------------------------------------------------

// counterFor sums one counter family restricted to a tenant label.
func counterFor(t *testing.T, family, tenant string) float64 {
	t.Helper()
	gathered, err := crmetrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	total := 0.0
	for _, f := range gathered {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.Metric {
			if labelValue(m, "tenant") == tenant {
				total += m.GetCounter().GetValue()
			}
		}
	}
	return total
}

func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.Label {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}

// Operational counters describe what the OPERATOR's cluster did this tick. A shadow adds
// zero; the real pass adds exactly the expected counts.
func TestM163_ShadowAddsNoProductionCountersAndProductionAddsExactly(t *testing.T) {
	const (
		excludedFamily = "phorvex_candidates_excluded_total"
		rbacFamily     = "phorvex_candidates_rbac_unknown_total"
		agedFamily     = "phorvex_events_aged_out_total"
	)
	pol := covPolicy(1)
	pol.Tenant = "m163-metrics"
	pol.PolicyUID = "uid-policy-metrics"
	pol.TraceEnabled = true
	pol.EventAgeHorizon = 30 * time.Minute

	// The T1-E capability gate: rotate is excluded, quarantine proceeds with unknown RBAC.
	// This fixture gate is a pure predicate, so the same function serves both modes — the
	// point of the test is the COUNTERS, not the collaborator.
	e := m163Engine(t)
	gate := func(_ *model.WorkloadView, a model.Action, _ []string) *actionset.Eligibility {
		if a == model.ActionRotate {
			return &actionset.Eligibility{Excluded: true, Kind: "no-rbac", Detail: "ssar denied"}
		}
		return &actionset.Eligibility{RBACUnknown: true, Detail: "ssar errored"}
	}
	e.Capability, e.ShadowCapability = gate, gate
	// One event aged past tau_ev: weight 0, counted once per production assessment.
	build := func() *model.WorkloadView {
		v := covView("metrics", true, 2*time.Hour, false)
		v.Events = []model.SecurityEventInfo{{
			Name: "stale-evt", Source: "detector", Type: "PolicyViolation",
			ThreatLevel: "high", TargetsPod: true, Age: 24 * time.Hour,
		}}
		return v
	}

	excludedBefore := counterFor(t, excludedFamily, pol.Tenant)
	rbacBefore := counterFor(t, rbacFamily, pol.Tenant)
	agedBefore := counterFor(t, agedFamily, pol.Tenant)

	const shadows = 5
	for i := 0; i < shadows; i++ {
		m163Shadow(t, e, []*model.WorkloadView{build()}, pol)
	}
	shadowDecisions := m163Shadow(t, e, []*model.WorkloadView{build()}, pol)

	if got := counterFor(t, excludedFamily, pol.Tenant) - excludedBefore; got != 0 {
		t.Fatalf("%d shadows added %v candidate exclusions, want 0", shadows+1, got)
	}
	if got := counterFor(t, rbacFamily, pol.Tenant) - rbacBefore; got != 0 {
		t.Fatalf("%d shadows added %v rbac-unknown counts, want 0", shadows+1, got)
	}
	if got := counterFor(t, agedFamily, pol.Tenant) - agedBefore; got != 0 {
		t.Fatalf("%d shadows added %v aged-out event counts, want 0", shadows+1, got)
	}

	// The shadow still REPORTS what it found; it just does not count it as production work.
	excludedInTrace := 0
	rbacInTrace := 0
	for _, status := range shadowDecisions[0].Trace.ActionStatus {
		if status.ExclusionKind == "no-rbac" {
			excludedInTrace++
		}
		if status.RBACUnknown {
			rbacInTrace++
		}
	}
	if excludedInTrace != 1 || rbacInTrace != 1 {
		t.Fatalf("the shadow trace lost its own annotations: excluded=%d rbacUnknown=%d",
			excludedInTrace, rbacInTrace)
	}

	// One real pass: exactly one exclusion, one rbac-unknown, one aged-out event.
	m163Decide2(t, e, []*model.WorkloadView{build()}, pol)
	if got := counterFor(t, excludedFamily, pol.Tenant) - excludedBefore; got != 1 {
		t.Fatalf("production added %v candidate exclusions, want exactly 1", got)
	}
	if got := counterFor(t, rbacFamily, pol.Tenant) - rbacBefore; got != 1 {
		t.Fatalf("production added %v rbac-unknown counts, want exactly 1", got)
	}
	if got := counterFor(t, agedFamily, pol.Tenant) - agedBefore; got != 1 {
		t.Fatalf("production added %v aged-out event counts, want exactly 1", got)
	}
}

// The NaN-cost counter is on the same contract: fail-conservative exclusion is reported in
// the shadow's own record, counted only for the real pass.
func TestM163_ShadowAddsNoNaNCostCountsButStillReportsThem(t *testing.T) {
	const nanFamily = "phorvex_cost_nan_unactionable_total"
	pol := m163Policy()
	pol.Tenant = "m163-nan"
	pol.EnabledActions = map[model.Action]bool{model.ActionRotate: true}

	build := func() *model.WorkloadView {
		v := covView("nan", true, 2*time.Hour, false)
		v.Telemetry = model.Telemetry{ReqRate: model.Signal{Value: math.NaN(), State: model.Error}}
		return v
	}

	e := m163Engine(t)
	before := counterFor(t, nanFamily, pol.Tenant)

	shadow := m163Shadow(t, e, []*model.WorkloadView{build()}, pol)
	if got := counterFor(t, nanFamily, pol.Tenant) - before; got != 0 {
		t.Fatalf("a shadow added %v NaN-cost counts, want 0", got)
	}
	if shadow[0].Feasible {
		t.Fatal("the shadow lost the fail-conservative NaN exclusion")
	}

	m163Decide2(t, e, []*model.WorkloadView{build()}, pol)
	if got := counterFor(t, nanFamily, pol.Tenant) - before; got != 1 {
		t.Fatalf("production added %v NaN-cost counts, want exactly 1", got)
	}
}
