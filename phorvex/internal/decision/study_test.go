package decision

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost/endpoint"
	"github.com/phorvex/phorvex/internal/model"
)

func studyTickForPreparation(p StudyPreparation, mandatory string) endpoint.Tick {
	n, k, zero, hold, from := 3, 1, 0.0, 30.0, 0.0
	tick := endpoint.Tick{ID: "tick", At: 100000, WorkloadUID: "workload", PolicyUID: p.policyUID,
		SpecReplicas: &n, CandidateSetComplete: true, MandatoryID: mandatory,
		SLO:    &endpoint.SLO{Target: .5, Window: 600, StudyAssumption: true},
		Ledger: &endpoint.Ledger{At: 100000, CompleteFrom: &from, Measurement: "watch-observed-service-ready-backends"}}
	for _, c := range p.Candidates {
		c.K, c.WorthThreshold, c.HistoryKnown, c.HoldCap = &k, &zero, true, &hold
		tick.Candidates = append(tick.Candidates, c)
	}
	return tick
}

func studyPrices(t *testing.T, tick endpoint.Tick) endpoint.ArmResult {
	t.Helper()
	result, err := endpoint.Run(endpoint.Trace{Schema: endpoint.TraceSchema, Evidence: "synthetic", SourceRevision: "test-source", Ticks: []endpoint.Tick{tick}}, endpoint.Defaults(), endpoint.FileStore{Dir: t.TempDir()})
	if err != nil || result.State != "COMPLETE" {
		t.Fatalf("pricing fixture: state=%s missing=%v err=%v", result.State, result.MissingReasons, err)
	}
	return result.Ticks[0].V2
}

func studyWorkload(v *model.WorkloadView) {
	v.Pod.WorkloadSpec = model.WorkloadSpecObservation{Known: true, PodUID: v.Pod.UID, SpecReplicas: 3,
		Workload: model.ObjectIdentity{Kind: "Deployment", Namespace: v.Pod.Namespace, UID: "workload"}}
}

func TestStudyPreparationDoesNotMutateOwnerViewsOrCallImpureCapability(t *testing.T) {
	e := NewCoverageEngine()
	e.Now = func() time.Time { return time.Unix(100000, 0) }
	v, p := covView("candidate", true, 2*time.Hour, false), covPolicy(1)
	p.PolicyUID = "study-policy"
	studyWorkload(v)
	e.Capability = func(*model.WorkloadView, model.Action, []string) *actionset.Eligibility {
		t.Fatal("study called impure capability")
		return nil
	}
	if _, err := e.PrepareEndpointStudy([]*model.WorkloadView{v}, p); err != ErrShadowCapabilityUnavailable {
		t.Fatalf("missing read-only capability accepted: %v", err)
	}
	observations := 0
	e.ShadowCapability = func(*model.WorkloadView, model.Action, []string) *actionset.Eligibility { observations++; return nil }
	beforeState := e.ExportOwnerState(p.Owner())
	beforeViews, _ := json.Marshal(v)
	prepared, err := e.PrepareEndpointStudy([]*model.WorkloadView{v}, p)
	if err != nil || len(prepared.Candidates) == 0 || observations == 0 {
		t.Fatalf("real preparation failed: %+v %v", prepared, err)
	}
	afterViews, _ := json.Marshal(v)
	if !reflect.DeepEqual(beforeState, e.ExportOwnerState(p.Owner())) || string(beforeViews) != string(afterViews) {
		t.Fatal("offline preparation mutated owner state or input view")
	}
}

func TestStudyRealContainmentAndHardGateOverridePrices(t *testing.T) {
	for _, stateful := range []bool{false, true} {
		v, p := m99Fixture()
		e := NewCoverageEngine()
		bindRotate(t, e, v, p) // required keys from the real production recon grant
		p.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
		p.MayBreachSLO = true
		studyWorkload(v)
		v.Pod.Stateful = stateful
		prepared, err := e.PrepareEndpointStudy([]*model.WorkloadView{v}, p)
		if err != nil || !prepared.Mandatory {
			t.Fatalf("mandatory fixture: %+v %v", prepared, err)
		}
		id := StudyCandidateID(p.PolicyUID, v.Pod.UID, model.ActionRotate)
		tick := studyTickForPreparation(prepared, id)
		arm := studyPrices(t, tick)
		for _, lambda := range []float64{0, 1, 1e12} {
			pick, err := prepared.SelectEndpointStudy(tick, arm, lambda)
			if err != nil || (pick != nil) == stateful || (pick != nil && *pick != id) {
				t.Fatalf("stateful=%v lambda=%v pick=%v err=%v", stateful, lambda, pick, err)
			}
		}
	}
}

func TestStudyNegativePricedGainDoesNotAddAPricedWorthGate(t *testing.T) {
	v, p := covView("candidate", true, 2*time.Hour, false), covPolicy(1)
	p.PolicyUID, p.EnabledActions = "study-policy", map[model.Action]bool{model.ActionRotate: true}
	studyWorkload(v)
	prepared, err := NewCoverageEngine().PrepareEndpointStudy([]*model.WorkloadView{v}, p)
	if err != nil || len(prepared.Candidates) != 1 {
		t.Fatal(prepared, err)
	}
	tick := studyTickForPreparation(prepared, "")
	arm := studyPrices(t, tick)
	if arm.Pick == nil || arm.Rows[0].Cost.E == nil || *arm.Rows[0].Cost.E <= 0 {
		t.Fatal("fixture must admit a positive-cost candidate")
	}
	pick, err := prepared.SelectEndpointStudy(tick, arm, 1e12)
	if err != nil || !reflect.DeepEqual(pick, arm.Pick) {
		t.Fatalf("negative priced gain silently vetoed: %v %v", pick, err)
	}
	wrong := *arm.Rows[0].V + 1
	arm.Rows[0].V = &wrong
	if _, err := prepared.SelectEndpointStudy(tick, arm, 1); err == nil {
		t.Fatal("uploaded value displaced grounded source facts")
	}
}

func TestStudyPreservesRealResourceAndFailureGates(t *testing.T) {
	for _, gate := range []string{"resource", "failure"} {
		v, p := covView("candidate", true, 2*time.Hour, false), covPolicy(1)
		p.PolicyUID, p.EnabledActions = "study-policy", map[model.Action]bool{model.ActionRotate: true}
		studyWorkload(v)
		e := NewCoverageEngine()
		if gate == "resource" {
			p.SharedResourceCapacityConfigured, p.SharedResourceReservationsKnown = true, true
			v.Pod.ServiceAvailabilityKnown = true // complete inventory says no target Service membership
		} else {
			e.FailureExclusion = func(*model.WorkloadView, model.Action) (string, bool) { return "cooldown-fixture", true }
		}
		prepared, err := e.PrepareEndpointStudy([]*model.WorkloadView{v}, p)
		if err != nil || len(prepared.Candidates) != 1 || len(prepared.Candidates[0].Gates) == 0 {
			t.Fatalf("lost gate=%s: %+v %v", gate, prepared, err)
		}
		reason := strings.Join(prepared.Candidates[0].Gates, ",")
		if (gate == "resource" && !strings.Contains(reason, "resource-capacity")) || (gate == "failure" && !strings.Contains(reason, "cooldown-fixture")) {
			t.Fatal(reason)
		}
		tick := studyTickForPreparation(prepared, "")
		arm := studyPrices(t, tick)
		pick, err := prepared.SelectEndpointStudy(tick, arm, 0)
		if err != nil || pick != nil {
			t.Fatalf("gate bypassed: %v %v", pick, err)
		}
	}
}
