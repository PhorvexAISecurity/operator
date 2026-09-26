package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// This fixture goes through the real UCW producer and action-set generator. It
// represents a declared serving pod with no SecurityEvent and no observation
// that the next guardrail variant protects an objective the current one misses.
func guardrailCoverFixture(t *testing.T, event *model.SecurityEventInfo, elapsed, serving bool) (*CoverageEngine, *model.WorkloadView, model.Policy, actionset.ActionSet) {
	t.Helper()
	e := NewCoverageEngine()
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("runtime UCW recon producer absent")
	}
	e.Recon = profile
	v := covView("serve", false, 16*time.Minute, false)
	if serving {
		v.Pod.ModelID = "declared-model"
		v.Pod.ServingDeclared = true
	}
	v.Physics = model.NeutralPhysics()
	if event != nil {
		v.Events = []model.SecurityEventInfo{*event}
	}
	if !elapsed {
		v.ExposureByVariable = realisticClocks(16 * time.Minute)
	}
	pol := covPolicy(1)
	pol.ProactiveFloor = 15 * time.Minute
	pol.AntiOverRotationWindow = 90 * time.Second
	pol.CostCeiling = 10
	pol.EnabledActions = map[model.Action]bool{
		model.ActionGuardrailRotate: true,
		model.ActionRotate:          true,
	}
	set, _ := e.AssembleSet([]*model.WorkloadView{v}, pol)
	return e, v, pol, set
}

func candidateBenefit(set actionset.ActionSet, action model.Action) (float64, bool) {
	benefit := map[model.Action]float64{}
	for _, candidate := range set.Candidates {
		if candidate.Action != action {
			continue
		}
		for _, key := range candidate.CoverKeys {
			benefit[candidate.Action] += set.FactWeights[key]
		}
		return benefit[action], true
	}
	return 0, false
}

func assertGuardrailAuditFact(t *testing.T, set actionset.ActionSet, steered bool) {
	t.Helper()
	for _, fact := range set.FactsByAsset["ns/serve"] {
		if fact.Kind != recon.FactGuardrailBypass {
			continue
		}
		if fact.Weight <= 0 || (fact.SteeredBy != nil) != steered || set.FactWeights[fact.Key()] != 0 {
			t.Fatalf("guardrail bypass audit fact or selectable weight changed: %+v", fact)
		}
		return
	}
	t.Fatal("declared serving workload lost guardrail bypass audit fact")
}

func assertGuardrailNoCover(t *testing.T, set actionset.ActionSet) {
	t.Helper()
	for _, exclusion := range set.Excluded {
		if exclusion.Action == model.ActionGuardrailRotate {
			if exclusion.Reason != model.GuardrailBypassNoCoverReason {
				t.Fatalf("guardrail exclusion = %q, want precise no-cover reason", exclusion.Reason)
			}
			return
		}
	}
	t.Fatal("guardrail action has no no-cover exclusion")
}

// Before the cover correction this fixture failed because a serving declaration
// alone gave guardrail-rotate positive modeled bypass benefit. A future
// directional effectiveness witness must be produced before that benefit may
// be scored; a variant change or synthetic event alone is not such a witness.
func TestGuardrailUnwitnessedBypassDoesNotEarnBenefit(t *testing.T) {
	for _, elapsed := range []bool{false, true} {
		e, v, pol, set := guardrailCoverFixture(t, nil, elapsed, true)
		if benefit, found := candidateBenefit(set, model.ActionGuardrailRotate); found || benefit != 0 {
			t.Fatalf("elapsed=%t: unwitnessed guardrail bypass earned benefit %.6f", elapsed, benefit)
		}
		assertGuardrailAuditFact(t, set, false)
		assertGuardrailNoCover(t, set)
		decisions := e.Decide([]*model.WorkloadView{v}, pol)
		if len(decisions) != 1 || decisions[0].Action == model.ActionGuardrailRotate {
			t.Fatalf("elapsed=%t: unsupported guardrail selected: %+v", elapsed, decisions)
		}
	}
}

// Positive control: correcting guardrail-specific benefit must not disable
// evidence-less proactive motion whose invalidation is independently grounded.
func TestGuardrailUnwitnessedFixtureRetainsProactiveRotate(t *testing.T) {
	e, v, pol, set := guardrailCoverFixture(t, nil, true, true)
	if benefit, found := candidateBenefit(set, model.ActionRotate); !found || benefit <= 0 {
		t.Fatalf("ordinary proactive rotate lost its real-producer cover: benefit %.6f", benefit)
	}
	decisions := e.Decide([]*model.WorkloadView{v}, pol)
	if len(decisions) != 1 || !decisions[0].Selected || decisions[0].Action != model.ActionRotate {
		t.Fatalf("ordinary physically feasible proactive rotate not selected: %+v", decisions)
	}
}

func TestGuardrailTrustedObservationRetainsAuditAttributionWithoutCover(t *testing.T) {
	event := &model.SecurityEventInfo{Name: "observed-1", UID: "event-uid", Type: model.AttackVectorGuardrail,
		Source: "redteam", Trust: "trusted", CreatorIdentity: "system:serviceaccount:ns:detector", TargetsPod: true}
	_, _, _, set := guardrailCoverFixture(t, event, true, true)
	if benefit, found := candidateBenefit(set, model.ActionGuardrailRotate); found || benefit != 0 {
		t.Fatalf("trusted event alone manufactured guardrail bypass benefit %.6f", benefit)
	}
	assertGuardrailAuditFact(t, set, true)
	assertGuardrailNoCover(t, set)
	for _, fact := range set.FactsByAsset["ns/serve"] {
		if fact.Kind == recon.FactGuardrailBypass &&
			(len(fact.SteeredBy.Events) != 1 || fact.SteeredBy.Events[0].EventUID != event.UID) {
			t.Fatalf("exact event attribution lost: %+v", fact.SteeredBy)
		}
	}
}

func TestGuardrailCoverCorrectionKeepsPodAndPolicyScope(t *testing.T) {
	_, _, _, nonServing := guardrailCoverFixture(t, nil, true, false)
	for _, fact := range nonServing.FactsByAsset["ns/serve"] {
		if fact.Kind == recon.FactGuardrailBypass {
			t.Fatal("non-serving pod fabricated guardrail bypass fact")
		}
	}
	if benefit, found := candidateBenefit(nonServing, model.ActionGuardrailRotate); found || benefit != 0 {
		t.Fatalf("non-serving pod has guardrail candidate benefit %.6f", benefit)
	}
	e, v, pol, _ := guardrailCoverFixture(t, nil, true, true)
	pol.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
	disabled, _ := e.AssembleSet([]*model.WorkloadView{v}, pol)
	if _, found := candidateBenefit(disabled, model.ActionGuardrailRotate); found {
		t.Fatal("disabled guardrail policy generated a candidate")
	}
	assertGuardrailAuditFact(t, disabled, false)
}
