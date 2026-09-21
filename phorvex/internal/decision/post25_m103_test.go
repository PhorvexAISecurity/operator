package decision

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
)

func m103Scope(service, serviceUID, controllerUID string) model.ResourceScope {
	return model.ResourceScope{Kind: model.ResourceUnavailableReadyReplica, Namespace: "ns", ServiceName: service, ServiceUID: serviceUID, ControllerUID: controllerUID}
}

func m103CapacityView(name string, scopes ...model.ResourceScope) *model.WorkloadView {
	v := covView(name, true, 2*time.Hour, false)
	v.Pod.ControllerUID = scopes[0].ControllerUID
	v.Pod.ServiceAvailabilityKnown = true
	for _, scope := range scopes {
		v.Pod.ServiceAvailability = append(v.Pod.ServiceAvailability, model.ServiceAvailabilityObservation{
			Scope: scope, ReadyMembers: 2, TargetReady: true, Complete: true,
		})
	}
	return v
}

func m103Policy() model.Policy {
	pol := covPolicy(2)
	pol.Namespace = "ns"
	pol.PolicyUID = "policy-uid"
	pol.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
	pol.SharedResourceCapacityConfigured = true
	pol.SharedResourceReservationsKnown = true
	pol.SharedResourceReservations = map[string]int{}
	pol.TraceEnabled = true
	return pol
}

func TestM103ActualSelectionAccumulatesSharedServiceCapacity(t *testing.T) {
	shared := m103Scope("serving", "service-uid", "controller-uid")
	views := []*model.WorkloadView{
		m103CapacityView("a", shared),
		m103CapacityView("b", shared),
	}
	ds := NewCoverageEngine().Decide(views, m103Policy())
	if got := countSelected(ds); got != 1 {
		t.Fatalf("same Service ready=2 floor=1 selected %d removals, want exactly 1: %+v", got, ds)
	}
	for _, d := range ds {
		if d.Trace == nil {
			t.Fatal("M103 selection did not emit V6 trace")
		}
		if err := d.Trace.Validate(); err != nil {
			t.Fatalf("V6 trace is not reconstructable: %v", err)
		}
		found := false
		for _, capacity := range d.Trace.Resources {
			if capacity.Scope.Key() == shared.Key() {
				found = true
				if capacity.Limit != 1 || capacity.Selected != 1 {
					t.Fatalf("shared capacity trace = %+v, want limit=1 selected=1", capacity)
				}
			}
		}
		if !found {
			t.Fatalf("decision for %s omitted its shared Service capacity", d.Pod)
		}
	}

	// Each candidate still passes the historical per-object ready=2-1>=1
	// predicate; only accumulated shared capacity prevents the second selection.
	for _, view := range views {
		if view.Pod.ReadyReplicas-1 < 1 {
			t.Fatalf("counterexample fixture does not independently pass the old floor: %+v", view.Pod)
		}
	}
}

func TestM103IndependentAndOverlappingScopes(t *testing.T) {
	left := m103Scope("left", "service-left", "controller-left")
	right := m103Scope("right", "service-right", "controller-right")
	independent := []*model.WorkloadView{m103CapacityView("a", left), m103CapacityView("b", right)}
	if got := countSelected(NewCoverageEngine().Decide(independent, m103Policy())); got != 2 {
		t.Fatalf("independent resource scopes selected %d moves, want 2", got)
	}

	shared := m103Scope("shared", "service-shared", "controller-shared")
	overlapped := []*model.WorkloadView{
		m103CapacityView("a", left, shared),
		m103CapacityView("b", right, shared),
	}
	if got := countSelected(NewCoverageEngine().Decide(overlapped, m103Policy())); got != 1 {
		t.Fatalf("overlapping Service membership selected %d moves, want 1", got)
	}

	// Human-readable names do not alias recreated Services or controllers.
	recreated := []*model.WorkloadView{
		m103CapacityView("a", m103Scope("serving", "service-old", "controller-old")),
		m103CapacityView("b", m103Scope("serving", "service-new", "controller-new")),
	}
	if got := countSelected(NewCoverageEngine().Decide(recreated, m103Policy())); got != 2 {
		t.Fatalf("same Service name with distinct immutable UIDs selected %d moves, want 2", got)
	}
}

func TestM103UnknownInventoryRefusesOnlyReplicaRemovingCandidates(t *testing.T) {
	for _, floor := range []int{1, 0} {
		t.Run(fmt.Sprintf("floor-%d", floor), func(t *testing.T) {
			view := covView("unknown", true, 2*time.Hour, false)
			view.Pod.ServiceAvailabilityKnown = false
			view.Pod.ServiceAvailabilityReason = "EndpointSlice inventory unavailable"
			pol := m103Policy()
			pol.MinAvailableReplicas = floor
			set, _ := NewCoverageEngine().AssembleSet([]*model.WorkloadView{view}, pol)
			for _, candidate := range set.Candidates {
				if candidate.Action == model.ActionRotate {
					t.Fatal("unknown shared inventory authorized a replica-removing candidate")
				}
			}
			found := false
			for _, excluded := range set.Excluded {
				if excluded.Action == model.ActionRotate && strings.Contains(excluded.Reason, "EndpointSlice inventory unavailable") {
					found = true
				}
			}
			if !found {
				t.Fatalf("unknown shared inventory lacks explicit exclusion: %+v", set.Excluded)
			}
		})
	}
}

func TestM103ZeroFloorCandidateCarriesAuthoritativeServiceDemand(t *testing.T) {
	shared := m103Scope("serving", "service-uid", "controller-uid")
	view := m103CapacityView("a", shared)
	view.Pod.ServiceAvailability[0].ReadyMembers = 3
	pol := m103Policy()
	pol.MinAvailableReplicas = 0
	set, _ := NewCoverageEngine().AssembleSet([]*model.WorkloadView{view}, pol)
	for _, candidate := range set.Candidates {
		if candidate.Action != model.ActionRotate {
			continue
		}
		for _, demand := range candidate.Resources {
			if demand.Scope == shared && demand.Units == 1 {
				return
			}
		}
	}
	t.Fatalf("floor-zero replica removal omitted authoritative Service demand: %+v", set)
}

func TestM103OutstandingReadinessAndZeroBudgetRemainHardBounds(t *testing.T) {
	shared := m103Scope("serving", "service-uid", "controller-uid")
	view := m103CapacityView("a", shared)
	pol := m103Policy()
	pol.SharedResourceReservations[shared.Key()] = 1
	if got := countSelected(NewCoverageEngine().Decide([]*model.WorkloadView{view}, pol)); got != 0 {
		t.Fatalf("durable outstanding removal allowed %d new moves", got)
	}
	pol.SharedResourceReservations = map[string]int{}
	view.Pod.ServiceAvailability[0].ReadyMembers = 1
	if got := countSelected(NewCoverageEngine().Decide([]*model.WorkloadView{view}, pol)); got != 0 {
		t.Fatalf("ready=floor allowed %d new moves", got)
	}
	view.Pod.ServiceAvailability[0].ReadyMembers = 2
	pol.MaxMovesPerTick = 0
	ds := NewCoverageEngine().Decide([]*model.WorkloadView{view}, pol)
	if got := countSelected(ds); got != 0 {
		t.Fatalf("explicit zero move budget selected %d moves", got)
	}
	if len(ds) != 1 || ds[0].Trace == nil || ds[0].Trace.Validate() != nil {
		t.Fatalf("zero-budget V6 decision is not reconstructable: %+v", ds)
	}
}

func TestM103ExactAndComparisonSolversRespectUnequalResourceCosts(t *testing.T) {
	move := model.ResourceScope{Kind: model.ResourceMoveCount, Namespace: "ns", ControllerUID: "policy"}
	shared := m103Scope("serving", "service-uid", "controller-uid")
	set := actionset.ActionSet{
		Resources:   []model.ResourceCapacity{{Scope: move, Limit: 2}, {Scope: shared, Limit: 1}},
		FactWeights: map[string]float64{"a": 3, "b": 5},
		Candidates: []actionset.Candidate{
			{Key: "ns/a", Action: model.ActionRotate, CoverKeys: []string{"a"}, ECost: .1, Resources: []model.ResourceConsumption{{Scope: move, Units: 1}, {Scope: shared, Units: 1}}},
			{Key: "ns/b", Action: model.ActionRotate, CoverKeys: []string{"b"}, ECost: .7, Resources: []model.ResourceConsumption{{Scope: move, Units: 1}, {Scope: shared, Units: 1}}},
		},
	}
	prov := func(string) float64 { return 1 }
	picks := greedyPicksOnSet(set, 2, prov, .5)
	if len(picks) != 1 || !resourceFeasible(set, picks) {
		t.Fatalf("greedy comparison returned infeasible picks: %+v", picks)
	}
	exact, skipped := exactObjectiveWithBudget(set, 2, prov, .5, math.MaxFloat64)
	if skipped || math.Abs(exact-setObjective(picks, set.FactWeights, prov, .5)) > 1e-12 {
		t.Fatalf("exact resource oracle disagrees: exact=%v skipped=%v picks=%+v", exact, skipped, picks)
	}
	if got := greedyThenSwaps(set, 2, prov, .5); !resourceFeasible(set, got) || len(got) != 1 {
		t.Fatalf("local search returned infeasible picks: %+v", got)
	}
}

func TestM103V6RejectsAggregateUsageAndLegacyResourceFields(t *testing.T) {
	shared := m103Scope("serving", "service-uid", "controller-uid")
	ds := NewCoverageEngine().Decide([]*model.WorkloadView{m103CapacityView("a", shared), m103CapacityView("b", shared)}, m103Policy())
	var trace *model.DecisionTraceV2
	for _, d := range ds {
		if d.Trace != nil {
			copy := *d.Trace
			trace = &copy
			break
		}
	}
	if trace == nil {
		t.Fatal("missing V6 trace")
	}
	for i := range trace.Resources {
		if trace.Resources[i].Scope.Key() == shared.Key() {
			trace.Resources[i].Selected = trace.Resources[i].Limit + 1
		}
	}
	if err := trace.Validate(); err == nil || !strings.Contains(err.Error(), "invalid resource capacity") {
		t.Fatalf("aggregate-infeasible V6 trace accepted: %v", err)
	}
	trace.SchemaVersion = model.DecisionTraceSchemaV5
	trace.Resources = nil
	if err := trace.Validate(); err == nil || !strings.Contains(err.Error(), "historical candidate") {
		t.Fatalf("legacy trace accepted V6 candidate resources: %v", err)
	}
}
