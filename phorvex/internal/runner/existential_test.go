package runner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

func TestM99UncontainableConditionAndEvent(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", Generation: 7}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(policy).WithObjects(policy).Build()
	recorder := record.NewFakeRecorder(5)
	m := &Manager{Client: c, Recorder: recorder}
	e := &policyEntry{key: clientKey(policy)}
	ds := []model.Decision{{Namespace: "ns", Pod: "protected", Existential: &model.ExistentialDecision{Present: true, Result: "uncontainable"}}}
	for i := 0; i < 2; i++ {
		m.updateExistentialStatus(context.Background(), e, ds)
	}
	got := &v1alpha1.PhorvexPolicy{}
	if err := c.Get(context.Background(), e.key, got); err != nil {
		t.Fatal(err)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, "ExistentialUncontainable")
	if cond == nil || cond.Status != metav1.ConditionTrue || !strings.Contains(cond.Message, "ns/protected") {
		t.Fatalf("condition=%+v", cond)
	}
	select {
	case msg := <-recorder.Events:
		if !strings.Contains(msg, "ExistentialUncontainable") {
			t.Fatal(msg)
		}
	default:
		t.Fatal("missing Event")
	}
	select {
	case msg := <-recorder.Events:
		t.Fatal("repeated unchanged Event:", msg)
	default:
	}
	ds[0].Existential.Result = "selected"
	m.updateExistentialStatus(context.Background(), e, ds)
	_ = c.Get(context.Background(), e.key, got)
	if meta.FindStatusCondition(got.Status.Conditions, "ExistentialUncontainable").Status != metav1.ConditionFalse {
		t.Fatal("stale condition")
	}
}

func TestM99DispatchNeverClaimsConfirmedContainment(t *testing.T) {
	for _, mode := range []string{"dry-run", "kill-switch", "failed", "dispatched"} {
		t.Run(mode, func(t *testing.T) {
			d := model.Decision{Selected: true, Actuated: mode == "dispatched", Existential: &model.ExistentialDecision{Present: true, Result: "selected"}}
			recordExistentialEffect(&d, mode == "failed" || mode == "dispatched")
			want := "not-attempted"
			if mode == "failed" {
				want = "failed-or-unconfirmed"
			}
			if mode == "dispatched" {
				want = "attempted-unconfirmed"
			}
			if d.Existential.EffectStatus != want || !d.Existential.Present {
				t.Fatalf("effect=%+v", d.Existential)
			}
		})
	}
}

func TestM99PolicySLOOptInDefaultsOff(t *testing.T) {
	e := &policyEntry{}
	if buildPolicy(e).MayBreachSLO {
		t.Fatal("default opt-in")
	}
	e.spec.Existential.MayBreachSLO = true
	if !buildPolicy(e).MayBreachSLO {
		t.Fatal("opt-in lost in resolution")
	}
}

func TestM99PolicyInventorySurvivesEmptyFleet(t *testing.T) {
	p := model.Policy{PolicyUID: "policy"}
	events := []model.SecurityEventInfo{{Name: "detector", Outcomes: []model.ProtectedOutcome{{ID: "lost-scope", PolicyUID: "policy", DecisionAsset: "ns/missing", DecisionAssetUID: "old"}}}}
	inventory := outcomeInventory(events, p)
	if inventory == nil || inventory.ScopeComplete || len(inventory.Records) != 1 {
		t.Fatalf("scope gap vanished: %+v", inventory)
	}
}

func TestM99SLOExceptionReachesDispatchAndRetainsVetoes(t *testing.T) {
	for _, mode := range []string{"slo-permitted", "stateful-veto", "untrusted-veto", "missing-view", "ensure-failure", "actuation-failure"} {
		t.Run(mode, func(t *testing.T) {
			p := model.Policy{Tenant: "t", PolicyUID: "policy", MayBreachSLO: true, TrustBoundaryReady: true, MinAvailableReplicas: 1}
			r := model.ProtectedOutcome{ID: "r", PolicyUID: "policy", DecisionAsset: "ns/p", DecisionAssetUID: "uid", ProtectedAsset: "dataset", Version: "v1", Portion: "remaining", Property: "confidentiality", Outcome: "unauthorized-disclosure", ClassBasis: "protected", ScopeBasis: "all copies", LossState: "at-risk", StateBasis: "preventable", RequiredKeys: []string{"e"}, MappingComplete: true, MappingBasis: "sound"}
			v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p", UID: "uid", DesiredReplicas: 1, ReadyReplicas: 1}, OutcomeEvents: []model.SecurityEventInfo{{Name: "ev", Trust: "trusted", CreatorIdentity: "detector", ResolvedTargets: []string{"ns/p"}, Outcomes: []model.ProtectedOutcome{r}}}}
			ds := []model.Decision{{Namespace: "ns", Pod: "p", Action: model.ActionRotate, Selected: true, Feasible: true, Existential: &model.ExistentialDecision{Present: true, EffectStatus: "not-attempted", Candidates: []model.ExistentialCandidate{{Action: model.ActionRotate, Contains: true, SLORelaxed: true}}}}}
			fa := &dispatchFakeActuator{emit: true}
			views := map[string]*model.WorkloadView{"ns/p": v}
			switch mode {
			case "stateful-veto":
				v.Pod.Stateful = true
			case "untrusted-veto":
				v.OutcomeEvents[0].Trust = "untrusted-identity"
			case "missing-view":
				views = nil
			case "ensure-failure":
				fa.ensureErr = errors.New("fixture ensure failure")
			case "actuation-failure":
				fa.actErr = errors.New("fixture actuator failure")
			}
			m := &Manager{Actuator: fa, Log: logr.Discard()}
			e := &policyEntry{namespace: "ns"}
			m.actuate(context.Background(), e, p, ds, views)
			wantCalls := 0
			wantEffect := "not-attempted"
			if mode == "slo-permitted" {
				wantCalls = 1
				wantEffect = "attempted-unconfirmed"
			}
			if mode == "actuation-failure" {
				wantCalls = 1
				wantEffect = "failed-or-unconfirmed"
			}
			if fa.calls != wantCalls || ds[0].Existential.EffectStatus != wantEffect {
				t.Fatalf("calls=%d effect=%s", fa.calls, ds[0].Existential.EffectStatus)
			}
		})
	}
}
