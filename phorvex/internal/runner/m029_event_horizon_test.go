package runner

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/ctxprov"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func m029PublicPolicy(floor time.Duration, horizon *metav1.Duration) model.Policy {
	entry := &policyEntry{
		key:       types.NamespacedName{Namespace: "m029", Name: "policy"},
		uid:       "policy-uid",
		tenant:    "m029",
		namespace: "m029",
		spec: v1alpha1.PhorvexPolicySpec{
			Budget: v1alpha1.BudgetSpec{ProactiveFloor: metav1.Duration{Duration: floor}},
			Triggers: v1alpha1.TriggersSpec{
				EventDriven: true, EventAgeHorizon: horizon,
			},
		},
	}
	pol := buildPolicy(entry)
	pol.TraceEnabled = true
	pol.BrainImage = "m029-fixture"
	pol.GitSHA = "m029-fixture"
	return pol
}

func m029EventView(age time.Duration) *model.WorkloadView {
	return &model.WorkloadView{
		Pod: model.Pod{
			Namespace: "m029", Name: "target", UID: "target-uid",
			Ready: true, DesiredReplicas: 3, ReadyReplicas: 3,
			MountedSecrets: []string{"credential-ref"},
		},
		Phase: model.PhaseWarm,
		Events: []model.SecurityEventInfo{{
			Name: "authenticated-event", ThreatLevel: "high", TargetsPod: true, Age: age,
			Trust: "trusted", CreatorIdentity: "system:serviceaccount:m029:detector",
		}},
		ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: 0},
	}
}

func m029OutcomeView(age time.Duration) *model.WorkloadView {
	view := m029EventView(age)
	outcome := model.ProtectedOutcome{
		ID: "outcome", PolicyUID: "policy-uid", DecisionAsset: "m029/target", DecisionAssetUID: "target-uid",
		ProtectedAsset: "dataset", Version: "v1", Portion: "records", Property: "confidentiality",
		Outcome: "unauthorized-disclosure", ClassBasis: "protected data", ScopeBasis: "complete scope",
		LossState: "at-risk", StateBasis: "trusted observation", RequiredKeys: []string{"event"},
		MappingComplete: true, MappingBasis: "rotation interrupts the scoped channel",
	}
	event := view.Events[0]
	event.ResolvedTargets = []string{"m029/target"}
	event.Outcomes = []model.ProtectedOutcome{outcome}
	view.OutcomeEvents = []model.SecurityEventInfo{event}
	return view
}

func TestM029PublicBuilderDecouplesEventMemoryFromProactiveCadence(t *testing.T) {
	a := m029PublicPolicy(10*time.Minute, nil)
	b := m029PublicPolicy(2*time.Hour, nil)
	if a.EventAgeHorizon != time.Hour || b.EventAgeHorizon != time.Hour {
		t.Fatalf("omitted public horizon not independently defaulted: %v %v", a.EventAgeHorizon, b.EventAgeHorizon)
	}
	if a.ProactiveFloor != 10*time.Minute || b.ProactiveFloor != 2*time.Hour ||
		a.ExposurePressureScale != a.ProactiveFloor || b.ExposurePressureScale != b.ProactiveFloor {
		t.Fatalf("proactive floor/exposure scale changed: a=%+v b=%+v", a, b)
	}
	if wa, wb := model.EventAgeWeight(30*time.Minute, a.EventAgeHorizon), model.EventAgeWeight(30*time.Minute, b.EventAgeHorizon); wa != 0.5 || wb != wa {
		t.Fatalf("proactive-only change altered event weight: %g %g", wa, wb)
	}

	short := m029PublicPolicy(time.Hour, &metav1.Duration{Duration: 10 * time.Minute})
	long := m029PublicPolicy(time.Hour, &metav1.Duration{Duration: 2 * time.Hour})
	if got := model.EventAgeWeight(30*time.Minute, short.EventAgeHorizon); got != 0 {
		t.Fatalf("short explicit horizon weight=%g, want 0", got)
	}
	if got := model.EventAgeWeight(30*time.Minute, long.EventAgeHorizon); got != 0.75 {
		t.Fatalf("long explicit horizon weight=%g, want .75", got)
	}
	if short.ProactiveFloor != long.ProactiveFloor || short.ExposurePressureScale != long.ExposurePressureScale {
		t.Fatalf("event horizon changed proactive policy: short=%+v long=%+v", short, long)
	}
}

func TestM029BuiltPolicyReachesEventConsumersAndTrace(t *testing.T) {
	defaultA := m029PublicPolicy(10*time.Minute, nil)
	defaultB := m029PublicPolicy(2*time.Hour, nil)
	short := m029PublicPolicy(time.Hour, &metav1.Duration{Duration: 10 * time.Minute})
	view := m029EventView(30 * time.Minute)

	contextProvider, ok := ctxprov.Registry.Get("sensed-context")
	if !ok {
		t.Fatal("sensed context provider unavailable")
	}
	if a, b := contextProvider.Context(view, defaultA).ThreatPosture, contextProvider.Context(view, defaultB).ThreatPosture; a != b || a == 0 {
		t.Fatalf("proactive-only variation changed sensed event posture: %g %g", a, b)
	}
	if got := contextProvider.Context(view, short).ThreatPosture; got != 0 {
		t.Fatalf("expired event retained sensed posture under short horizon: %g", got)
	}

	assessDefault := killchain.NewModel().Assess(view, defaultA, 0, defaultA.ProactiveFloor.Seconds())
	assessShort := killchain.NewModel().Assess(view, short, 0, short.ProactiveFloor.Seconds())
	if assessDefault.EventEvidence == 0 || assessShort.EventEvidence != 0 {
		t.Fatalf("kill-chain horizon propagation failed: default=%g short=%g", assessDefault.EventEvidence, assessShort.EventEvidence)
	}
	for name, noEvidence := range map[string]*model.WorkloadView{
		"boundary":          m029EventView(10 * time.Minute),
		"future-timestamp":  m029EventView(-time.Minute),
		"missing-timestamp": m029EventView(0),
	} {
		if name == "missing-timestamp" {
			noEvidence.Events[0].TimestampMissing = true
		}
		if got := contextProvider.Context(noEvidence, short).ThreatPosture; got != 0 {
			t.Errorf("%s retained sensed posture=%g", name, got)
		}
		if got := killchain.NewModel().Assess(noEvidence, short, 0, short.ProactiveFloor.Seconds()).EventEvidence; got != 0 {
			t.Errorf("%s retained kill-chain evidence=%g", name, got)
		}
	}

	traceView := m029EventView(30 * time.Minute)
	traceView.ExposureByVariable = map[string]time.Duration{}
	for _, variable := range model.LiveExposureVariables {
		traceView.ExposureByVariable[variable] = 2 * time.Hour
	}
	decisions := decision.NewCoverageEngine().Decide([]*model.WorkloadView{traceView}, defaultA)
	if len(decisions) != 1 || decisions[0].Trace == nil {
		t.Fatalf("decision trace unavailable: %+v", decisions)
	}
	if got := decisions[0].Trace.Inputs.Clocks.EventAgeHorizonSec; got != time.Hour.Seconds() {
		t.Fatalf("trace event horizon=%g, want %g", got, time.Hour.Seconds())
	}
}

func TestM029EventHorizonDoesNotChangeProactiveEligibility(t *testing.T) {
	constraint, ok := feasibility.Registry.Get("proactive-cadence")
	if !ok {
		t.Fatal("proactive cadence constraint unavailable")
	}
	view := &model.WorkloadView{
		Pod:                model.Pod{Namespace: "m029", Name: "target", UID: "target-uid"},
		ExposureByVariable: map[string]time.Duration{model.VarSession: 30 * time.Minute},
	}
	short := m029PublicPolicy(time.Hour, &metav1.Duration{Duration: 10 * time.Minute})
	long := m029PublicPolicy(time.Hour, &metav1.Duration{Duration: 2 * time.Hour})
	a := constraint.Check(view, model.Move{Action: model.ActionKVReset}, short)
	b := constraint.Check(view, model.Move{Action: model.ActionKVReset}, long)
	if a.Feasible != b.Feasible || a.Reason != b.Reason || a.Feasible {
		t.Fatalf("event horizon altered proactive cadence: short=%+v long=%+v", a, b)
	}
}

func TestM029BuiltPolicyControlsExistentialTrustedEvidenceExpiry(t *testing.T) {
	defaulted := m029PublicPolicy(time.Hour, nil)
	short := m029PublicPolicy(time.Hour, &metav1.Duration{Duration: 10 * time.Minute})
	defaulted.TrustBoundaryReady = true
	short.TrustBoundaryReady = true

	decide := func(pol model.Policy, view *model.WorkloadView) *model.ExistentialDecision {
		t.Helper()
		decisions := decision.NewCoverageEngine().Decide([]*model.WorkloadView{view}, pol)
		if len(decisions) != 1 || decisions[0].Existential == nil {
			t.Fatalf("existential evidence missing: %+v", decisions)
		}
		return decisions[0].Existential
	}
	if got := decide(defaulted, m029OutcomeView(30*time.Minute)); !got.TrustedEvidence || !got.Present {
		t.Fatalf("default one-hour evidence unexpectedly expired: %+v", got)
	}
	if got := decide(short, m029OutcomeView(30*time.Minute)); got.TrustedEvidence || got.Present {
		t.Fatalf("short-horizon expired evidence remained trusted: %+v", got)
	}
	for name, noEvidence := range map[string]*model.WorkloadView{
		"boundary":          m029OutcomeView(10 * time.Minute),
		"future-timestamp":  m029OutcomeView(-time.Minute),
		"missing-timestamp": m029OutcomeView(0),
	} {
		if name == "missing-timestamp" {
			noEvidence.OutcomeEvents[0].TimestampMissing = true
		}
		if got := decide(short, noEvidence); got.TrustedEvidence || got.Present {
			t.Errorf("%s existential evidence remained trusted: %+v", name, got)
		}
	}
}
