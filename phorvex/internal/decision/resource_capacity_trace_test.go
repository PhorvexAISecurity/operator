package decision

import (
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

type noQuarantineCoverRecon struct{ recon.ReconProfile }

func (noQuarantineCoverRecon) Name() string { return "no-quarantine-cover-fixture" }

func (r noQuarantineCoverRecon) AssetFacts(v *model.WorkloadView, ctx recon.FactContext) recon.AssetFacts {
	af := r.ReconProfile.AssetFacts(v, ctx)
	delete(af.CoverByAction, model.ActionQuarantine)
	return af
}

// This fixture has the same two eligible, generic-cover actions and missing
// authoritative Service membership as the owned round-17 Pod. The actual
// generator must exclude both before cost and the decision trace must preserve
// that capacity cause rather than calling the nonempty covers absent.
func TestResourceCapacityExclusionIsNotNoCover(t *testing.T) {
	view := covView("unrouted-source", true, 2*time.Hour, false)
	view.Pod.ServiceAvailabilityKnown = true
	pol := decisionTracePolicy(1, true)
	pol.SharedResourceCapacityConfigured = true
	pol.SharedResourceReservationsKnown = true
	engine := fixedTraceEngine()
	set, _ := engine.AssembleSet([]*model.WorkloadView{view}, pol)
	if len(set.Candidates) != 0 || len(set.Excluded) != 2 {
		t.Fatalf("expected two capacity exclusions and no candidates, got %+v", set)
	}
	const reason = "resource-capacity: target has no authoritative Service/EndpointSlice membership"
	for _, ex := range set.Excluded {
		if ex.Reason != reason || len(ex.CoverKeys) == 0 || ex.FeasibilityEvaluated || ex.CostEvaluated {
			t.Fatalf("capacity exclusion lost its existing cover/phase/reason: %+v", ex)
		}
	}
	decisions := engine.Decide([]*model.WorkloadView{view}, pol)
	if len(decisions) != 1 || decisions[0].Trace == nil || decisions[0].Action != model.ActionNoop || decisions[0].Selected {
		t.Fatalf("expected traced no-op, got %+v", decisions)
	}
	trace := decisions[0].Trace
	for _, action := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
		row := actionStatusRow(t, trace, action)
		if row.Status != model.ActionStatusInfeasible || row.ExclusionKind != "resource-capacity" || row.Scored || row.Reason != reason {
			t.Fatalf("%s capacity row = %+v", action, row)
		}
	}
	if trace.SchemaVersion != "phorvex.decision-trace.v7" {
		t.Fatalf("new trace schema=%q, want v7", trace.SchemaVersion)
	}
	if err := trace.Validate(); err != nil {
		t.Fatalf("new trace invalid: %v", err)
	}
	for _, field := range []string{"marginal", "cost"} {
		forged := *trace
		forged.Candidates = append([]model.DecisionCandidateV2(nil), trace.Candidates...)
		if field == "marginal" {
			forged.Candidates[0].MarginalCoverage = model.OptionalFloat{Present: true, Value: 1}
		} else {
			forged.Candidates[0].ExpectedCost = model.OptionalFloat{Present: true, Value: 1}
		}
		if err := forged.Validate(); err == nil {
			t.Fatalf("V7 resource exclusion accepted a fabricated %s score", field)
		}
	}
	if trace.NoopReason != reason || trace.MovesSpent != 0 || trace.CandidateDemand != 0 {
		t.Fatalf("capacity refusal reached selection: %+v", trace)
	}
	for _, row := range trace.Candidates {
		if !strings.HasPrefix(row.ExistingExclusionReason, "resource-capacity: ") || len(row.CoverKeys) == 0 || row.MarginalCoverage.Present || row.NetGain.Present {
			t.Fatalf("excluded capacity action was scored or lost cover: %+v", row)
		}
	}
	// Closed V6 vocabulary must reject the new cause, while historical V6
	// records using only existing kinds remain readable by the same validator.
	historical := *trace
	historical.SchemaVersion = model.DecisionTraceSchemaV6
	if err := historical.Validate(); err == nil {
		t.Fatal("historical V6 accepted new resource-capacity exclusion kind")
	}
	for i := range historical.ActionStatus {
		if historical.ActionStatus[i].ExclusionKind == "resource-capacity" {
			historical.ActionStatus[i].ExclusionKind = model.ExclusionFeasibility
		}
	}
	if err := historical.Validate(); err != nil {
		t.Fatalf("historical V6 with its original vocabulary became unreadable: %v", err)
	}
}

func TestQuarantineCapacityEarlyRefusalsHaveTypedCause(t *testing.T) {
	for _, tc := range []struct {
		name, reasonPrefix string
		known              bool
		used               int
	}{
		{name: "unknown", reasonPrefix: "quarantine-capacity-inventory-unknown:", known: false},
		{name: "exhausted", reasonPrefix: "quarantine-capacity-exhausted:", known: true, used: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pol := decisionTracePolicy(1, true)
			pol.EnabledActions = map[model.Action]bool{model.ActionQuarantine: true}
			pol.QuarantineCapacityConfigured = true
			pol.QuarantineCapacityKnown = tc.known
			pol.QuarantineCapacityLimit = 1
			pol.QuarantineCapacityUsed = tc.used
			view := covView("quarantine-"+tc.name, true, 2*time.Hour, false)
			engine := fixedTraceEngine()
			set, _ := engine.AssembleSet([]*model.WorkloadView{view}, pol)
			if len(set.Candidates) != 0 || len(set.Excluded) != 1 || len(set.Excluded[0].CoverKeys) == 0 || !strings.HasPrefix(set.Excluded[0].Reason, tc.reasonPrefix) {
				t.Fatalf("wrong capacity producer exclusion: %+v", set)
			}
			decision := engine.Decide([]*model.WorkloadView{view}, pol)
			if len(decision) != 1 || decision[0].Trace == nil {
				t.Fatalf("missing capacity decision: %+v", decision)
			}
			row := actionStatusRow(t, decision[0].Trace, model.ActionQuarantine)
			if row.Status != model.ActionStatusInfeasible || row.ExclusionKind != "resource-capacity" || row.Scored || !strings.HasPrefix(row.Reason, tc.reasonPrefix) {
				t.Fatalf("wrong typed quarantine refusal: %+v", row)
			}
			if err := decision[0].Trace.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestQuarantineCapacityMayPrecedeEmptyReconCover(t *testing.T) {
	pol := decisionTracePolicy(1, true)
	pol.EnabledActions = map[model.Action]bool{model.ActionQuarantine: true}
	pol.QuarantineCapacityConfigured = true
	pol.QuarantineCapacityKnown = false
	engine := fixedTraceEngine()
	engine.Recon = noQuarantineCoverRecon{engine.Recon}
	view := covView("coverless-quarantine", true, 2*time.Hour, false)
	set, _ := engine.AssembleSet([]*model.WorkloadView{view}, pol)
	if len(set.Excluded) != 1 || len(set.Excluded[0].CoverKeys) != 0 {
		t.Fatalf("quarantine capacity no-cover ordering changed: %+v", set)
	}
	decisions := engine.Decide([]*model.WorkloadView{view}, pol)
	if len(decisions) != 1 || decisions[0].Trace == nil {
		t.Fatalf("missing empty-cover capacity trace: %+v", decisions)
	}
	row := actionStatusRow(t, decisions[0].Trace, model.ActionQuarantine)
	if row.ExclusionKind != "resource-capacity" || row.Status != model.ActionStatusInfeasible {
		t.Fatalf("early capacity cause was rewritten as no-cover: %+v", row)
	}
	if err := decisions[0].Trace.Validate(); err != nil {
		t.Fatalf("V7 rejected real early empty-cover capacity producer: %v", err)
	}
}

func TestResourceCapacityTraceRemainsPerAssetInMultiViewTick(t *testing.T) {
	views := []*model.WorkloadView{
		covView("source-one", true, 2*time.Hour, false),
		covView("source-two", true, 2*time.Hour, false),
	}
	for _, view := range views {
		view.Pod.ServiceAvailabilityKnown = true
	}
	pol := decisionTracePolicy(1, true)
	pol.SharedResourceCapacityConfigured = true
	pol.SharedResourceReservationsKnown = true
	decisions := fixedTraceEngine().Decide(views, pol)
	if len(decisions) != len(views) {
		t.Fatalf("multi-view decisions=%d, want %d", len(decisions), len(views))
	}
	for i, decision := range decisions {
		if decision.Trace == nil || decision.Pod != views[i].Pod.Name {
			t.Fatalf("decision %d lost asset identity: %+v", i, decision)
		}
		if err := decision.Trace.Validate(); err != nil {
			t.Fatalf("asset %s V7 trace invalid: %v", decision.Pod, err)
		}
		if len(decision.Trace.Candidates) != 2 {
			t.Fatalf("asset %s carries %d candidates, want own two", decision.Pod, len(decision.Trace.Candidates))
		}
		for _, candidate := range decision.Trace.Candidates {
			if !strings.HasPrefix(candidate.CandidateKey, "ns/"+decision.Pod+"|") {
				t.Fatalf("asset %s acquired another view's candidate: %+v", decision.Pod, candidate)
			}
		}
	}
}

func TestGenuineEmptyReconCoverRemainsNoCover(t *testing.T) {
	view := covView("coverless", true, 2*time.Hour, false)
	pol := decisionTracePolicy(1, true)
	pol.EnabledActions = map[model.Action]bool{model.ActionDebugger: true}
	decision := fixedTraceEngine().Decide([]*model.WorkloadView{view}, pol)
	if len(decision) != 1 || decision[0].Trace == nil {
		t.Fatalf("missing coverless decision trace: %+v", decision)
	}
	row := actionStatusRow(t, decision[0].Trace, model.ActionDebugger)
	if row.Status != model.ActionStatusNoCover || row.ExclusionKind != model.ExclusionReconCover || row.Scored {
		t.Fatalf("genuine coverless action was reclassified: %+v", row)
	}
	if err := decision[0].Trace.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOrdinaryFeasibilityRefusalRemainsDistinctFromResourceCapacity(t *testing.T) {
	view := covView("stateful", true, 2*time.Hour, true)
	pol := decisionTracePolicy(1, true)
	pol.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
	decision := fixedTraceEngine().Decide([]*model.WorkloadView{view}, pol)
	if len(decision) != 1 || decision[0].Trace == nil {
		t.Fatalf("missing stateful feasibility trace: %+v", decision)
	}
	row := actionStatusRow(t, decision[0].Trace, model.ActionRotate)
	if row.Status != model.ActionStatusInfeasible || row.ExclusionKind != model.ExclusionFeasibility || row.Scored {
		t.Fatalf("ordinary feasibility refusal was reclassified: %+v", row)
	}
	if err := decision[0].Trace.Validate(); err != nil {
		t.Fatal(err)
	}
}
