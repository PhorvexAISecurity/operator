/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package decision

import (
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/model"
)

func TestNaNCostReportsDistinctUnactionableCategory(t *testing.T) {
	e := NewCoverageEngine()
	view := covView("nan-cost", true, 2*time.Hour, false)
	view.Telemetry = model.Telemetry{ReqRate: model.Signal{Value: math.NaN(), State: model.Error}}
	pol := covPolicy(1)
	pol.EnabledActions = map[model.Action]bool{model.ActionRotate: true}

	decisions := e.Decide([]*model.WorkloadView{view}, pol)
	if len(decisions) != 1 {
		t.Fatalf("got %d decisions, want 1", len(decisions))
	}
	d := decisions[0]
	if d.Feasible || d.InfeasibleWhy != cost.UnactionableNaNCategory+": telemetry.reqRate" {
		t.Fatalf("NaN decision category not distinct: %+v", d)
	}
}

// ownerName builds the M-140 owner key for a fixture tenant. Test policies carry no
// PolicyUID, so they use the name-kind fallback — the same key model.Policy.Owner()
// returns for them. Probes that reach into the engine must use it, or they create a
// second, empty bucket instead of reading the one the policy actually priced from.
func ownerName(tenant string) string { return model.OwnerKey(model.OwnerKindName, tenant) }

func covPolicy(b int) model.Policy {
	return model.Policy{
		Tenant:                 "t",
		DryRun:                 true,
		Lambda:                 cost.DefaultLambdaSeed,
		NormSparsity:           0.4,
		FlowDisruption:         0.6,
		WeightSecrets:          0.8,
		BlastRadiusFromGraph:   true,
		MaxMovesPerTick:        b,
		ProactiveFloor:         time.Hour,
		AntiOverRotationWindow: 5 * time.Minute,
		MinAvailableReplicas:   1,
		EnabledActions:         map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true},
	}
}

// allVarsAt clocks every M-23 live exposure variable at the same duration, so a fixture pod is
// gated the same for any enabled action (before M-23 every action shared the podIdentity clock).
func allVarsAt(d time.Duration) map[string]time.Duration {
	m := make(map[string]time.Duration, len(model.LiveExposureVariables))
	for _, v := range model.LiveExposureVariables {
		m[v] = d
	}
	return m
}

// realisticClocks returns ONLY the always-on exposure clocks (podIdentity, nodePlacement, session)
// at d — the exposure state ExposureFingerprints emits for an UNACTUATED pod, whose 6 *-epoch
// markers (networkIdentity/quarantine, routeKey, identity, adapter, drain, guardrail) are absent
// until their first actuation. allVarsAt fabricates those 6 too, which pre-dates the M-28
// proactive-cadence cap; a fresh-decoy fixture must use this so the cap fail-OPENs on the
// epoch-clocked actions (quarantine/route/…) — exactly where M-110's provenance floor, not M-28,
// governs the first move. (M-28 governs re-actuation on podIdentity/session and written epochs.)
func realisticClocks(d time.Duration) map[string]time.Duration {
	return map[string]time.Duration{
		model.VarPodIdentity:   d,
		model.VarNodePlacement: d,
		model.VarSession:       d,
	}
}

func covView(name string, secrets bool, exposure time.Duration, stateful bool) *model.WorkloadView {
	v := &model.WorkloadView{
		Pod: model.Pod{
			Namespace: "ns", Name: name, UID: "u-" + name,
			DesiredReplicas: 3, ReadyReplicas: 3, Ready: true, Stateful: stateful,
		},
		Phase:       model.PhaseWarm,
		BlastRadius: 0.6,
		Neighbors:   []model.NeighborRef{{Key: "ns/crown", Value: 5.0}},
		// M-23: every action now reads its OWN per-action exposure clock, not a shared
		// podIdentity default. Clock every live variable at `exposure` so a fixture pod is gated
		// identically whatever action a test enables (pre-M-23 all read podIdentity=exposure).
		ExposureByVariable: allVarsAt(exposure),
	}
	if secrets {
		v.Pod.MountedSecrets = []string{"creds"}
	}
	return v
}

func countSelected(ds []model.Decision) int {
	n := 0
	for _, d := range ds {
		if d.Selected {
			n++
		}
	}
	return n
}

func TestCoverageUsesPolicyLambdaAsPerTenantDualSeed(t *testing.T) {
	e := NewCoverageEngine()
	view := covView("lambda-seed", true, 2*time.Hour, false)

	polA := covPolicy(1)
	polA.Tenant = "tenant-a"
	polA.Lambda = 0.2
	set, _ := e.AssembleSet([]*model.WorkloadView{view}, polA)
	if len(set.Candidates) == 0 {
		t.Fatal("lambda seed test produced no candidates")
	}
	if got := e.costFor(polA.Owner()).Dual.Lambda(); got != 0.2 {
		t.Fatalf("tenant A dual seed = %v, want policy lambda 0.2", got)
	}

	polB := covPolicy(1)
	polB.Tenant = "tenant-b"
	polB.Lambda = 0.9
	decisions := e.Decide([]*model.WorkloadView{view}, polB)
	if len(decisions) == 0 || decisions[0].Lambda != 0.9 {
		t.Fatalf("tenant B first decision did not use policy lambda: %+v", decisions)
	}

	// Lambda is an initial condition for the legacy runtime controller, not a reset switch. A
	// reconcile with a different value must not erase already-learned tenant state.
	polA.Lambda = 1.7
	e.AssembleSet([]*model.WorkloadView{view}, polA)
	if got := e.costFor(polA.Owner()).Dual.Lambda(); got != 0.2 {
		t.Fatalf("existing tenant runtime lambda was reset by policy reconcile: got %v, want 0.2", got)
	}
}

func TestCoverageBudgetAndPartition(t *testing.T) {
	e := NewCoverageEngine()
	views := []*model.WorkloadView{
		covView("a", true, 2*time.Hour, false),
		covView("b", true, 2*time.Hour, false),
		covView("c", true, 2*time.Hour, false),
	}
	ds := e.Decide(views, covPolicy(2))
	if got := countSelected(ds); got != 2 {
		t.Errorf("budget=2 should select exactly 2 moves, got %d", got)
	}
	// Partition: a selected asset has exactly one action (no asset selected twice — one
	// decision per pod by construction).
	seen := map[string]int{}
	for _, d := range ds {
		if d.Selected {
			seen[d.Namespace+"/"+d.Pod]++
		}
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("asset %s selected %d times (must be 1: one move per asset)", k, n)
		}
	}
}

func TestStrictPositiveGainRulingBoundary(t *testing.T) {
	if strictPositiveGain(0) {
		t.Fatal("TV1 gain == 0 passed the strict production comparator")
	}
	if !strictPositiveGain(1e-12) {
		t.Fatal("TV2 positive gain did not pass")
	}
	if strictPositiveGain(-1e-12) {
		t.Fatal("TV3 negative gain passed")
	}
}

func TestLegacyMixedGainMonotonicityProperties(t *testing.T) {
	values := []float64{0, 0.1, 0.5, 1, 2}
	for _, marginal := range values {
		for _, provenance := range []float64{0.34, 0.7, 1} {
			for _, lambda := range values {
				previous := legacyMixedGain(marginal, provenance, lambda, values[0])
				for _, expectedCost := range values[1:] {
					got := legacyMixedGain(marginal, provenance, lambda, expectedCost)
					if got > previous {
						t.Fatalf("larger cost improved gain: marginal=%g provenance=%g lambda=%g previous=%g got=%g",
							marginal, provenance, lambda, previous, got)
					}
					if math.IsNaN(got) || math.IsInf(got, 0) {
						t.Fatalf("finite inputs produced %g", got)
					}
					previous = got
				}
			}
		}
	}
	for _, expectedCost := range values {
		previous := legacyMixedGain(values[0], 0.7, 0.6, expectedCost)
		for _, marginal := range values[1:] {
			got := legacyMixedGain(marginal, 0.7, 0.6, expectedCost)
			if got < previous {
				t.Fatalf("larger marginal value reduced gain: cost=%g previous=%g got=%g", expectedCost, previous, got)
			}
			previous = got
		}
	}
}

func TestShadowAndUnlabelledProductionDoNotAdvancePersistenceLearning(t *testing.T) {
	e := NewCoverageEngine()
	views := []*model.WorkloadView{covView("a", true, 2*time.Hour, false)}
	pol := covPolicy(1)
	beforeLambda := e.Cost.Dual.Lambda()
	beforePrior := e.Killchain.Memory.PriorMean(pol.Owner())

	shadow, err := e.DecideShadowChecked(views, pol)
	if err != nil || countSelected(shadow) != 1 {
		t.Fatalf("shadow decision unavailable: selected=%d err=%v", countSelected(shadow), err)
	}
	if got := e.Cost.Dual.Lambda(); got != beforeLambda {
		t.Fatalf("shadow advanced dual state: %v -> %v", beforeLambda, got)
	}
	if got := e.Killchain.Memory.PriorMean(pol.Owner()); got != beforePrior {
		t.Fatalf("shadow advanced kill-chain memory: %v -> %v", beforePrior, got)
	}

	e.Decide(views, pol)
	if got := e.Killchain.Memory.PriorMean(pol.Owner()); got != beforePrior {
		t.Fatalf("unlabelled production selection self-trained persistence: %v -> %v", beforePrior, got)
	}
}

func TestCoverageZeroDayProactiveNoEvents(t *testing.T) {
	// No SecurityEvents at all, but long exposure (past the proactive floor) => a
	// net-positive move is still selected: detector-INDEPENDENT proactive firing.
	e := NewCoverageEngine()
	v := covView("dweller", true, 3*time.Hour, false) // no Events on the view
	ds := e.Decide([]*model.WorkloadView{v}, covPolicy(3))
	d := ds[0]
	if d.CoverageValue <= 0 || d.ThreatRisk != 0 || d.DecisionValue() != d.CoverageValue {
		t.Fatalf("P1 value fields mixed coverage with deprecated threat risk: %+v", d)
	}
	if !d.Selected || d.Action == model.ActionNoop {
		t.Errorf("long-exposed pod with NO detector event must still get a proactive move (criterion 5); got action=%s selected=%v perDollar=%.3f", d.Action, d.Selected, d.PerDollar)
	}
	if d.Stage == "" || d.Lambda == 0 && d.PerDollar == 0 {
		t.Errorf("P1 decision should carry stage/lambda/perDollar; got stage=%q lambda=%.3f perDollar=%.3f", d.Stage, d.Lambda, d.PerDollar)
	}
	if d.Measurements == nil || !d.Measurements.Lambda.Present || !d.Measurements.PerDollar.Present ||
		!d.Measurements.AIClassified.Present || !d.Measurements.EventEvidence.Present {
		t.Fatalf("real coverage producer did not attest computed fields: %+v", d.Measurements)
	}
	if d.Measurements.ThreatRisk.Present {
		t.Fatal("P1 producer falsely attested deprecated P0 threat risk")
	}
}

func TestCoverageNoCandidateKeepsComputedInputsDistinct(t *testing.T) {
	e := NewCoverageEngine()
	p := covPolicy(1)
	p.EnabledActions = map[model.Action]bool{}
	d := e.Decide([]*model.WorkloadView{covView("no-candidate", false, 10*time.Minute, false)}, p)[0]
	if d.Measurements == nil {
		t.Fatal("coverage assessment omitted measurement contract")
	}
	if d.Measurements.PerDollar.Present || d.Measurements.CoveredWeight.Present ||
		d.Measurements.CoveredFacts.Present || d.Measurements.ProactiveRate.Present {
		t.Fatalf("no-candidate defaults reported as computed: %+v", d.Measurements)
	}
	if !d.Measurements.StageHazard.Present || !d.Measurements.Lambda.Present ||
		!d.Measurements.PreemptMargin.Present || !d.Measurements.AIClassified.Present {
		t.Fatalf("assessment-owned values reported unavailable: %+v", d.Measurements)
	}
}

func TestCoverageStatefulNeverRotated(t *testing.T) {
	e := NewCoverageEngine()
	v := covView("db", true, 2*time.Hour, true) // stateful + high value
	ds := e.Decide([]*model.WorkloadView{v}, covPolicy(3))
	d := ds[0]
	if d.Action == model.ActionRotate {
		t.Errorf("stateful pod must never be rotated (inviolable); got rotate")
	}
}

func TestCoverageAttributionExplainable(t *testing.T) {
	e := NewCoverageEngine()
	v := covView("x", true, 2*time.Hour, false)
	ds := e.Decide([]*model.WorkloadView{v}, covPolicy(3))
	d := ds[0]
	if !d.Selected {
		t.Fatalf("expected a selected move to attribute")
	}
	if len(d.Attribution) == 0 {
		t.Errorf("selected decision must carry SHAP-style attribution terms")
	}
	if d.PerDollar <= 0 {
		t.Errorf("selected decision must have a positive per-dollar coverage ratio")
	}
	// attribution must include at least one cover term and the cost term.
	var sawCover, sawCost bool
	for _, a := range d.Attribution {
		if len(a.Source) > 6 && a.Source[:6] == "cover:" {
			sawCover = true
		}
		if a.Source == "cost:-lambda*C" {
			sawCost = true
		}
	}
	if !sawCover || !sawCost {
		t.Errorf("attribution must decompose into cover + cost terms; got %+v", d.Attribution)
	}
}
