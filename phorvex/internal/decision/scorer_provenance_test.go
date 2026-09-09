package decision

import (
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// scorer_provenance_test.go — PHORVEXSEC-196 / M-110, the three call-site corrections.

// (a) Site 1 — blind cost is priced by the TARGET tenant's calibrator. Old code read e.Cost,
// the legacy scalar that costFor hands to the FIRST tenant, so B's blind cost carried A's
// learned rotation costs. Fails on old code.
func TestBlindCostIsPricedByTargetTenantCalibrator(t *testing.T) {
	e := NewCoverageEngine()
	e.Now = vtClock()
	_ = e.costFor(ownerName("A")) // A owns the legacy scalar bucket (e.Cost)
	aView := covView("a-expensive", true, 3*time.Hour, false)
	for i := 0; i < 50; i++ {
		e.costFor(ownerName("A")).ObserveRotation(aView, 9.0) // prime A's RLS/Conformal with costly rotations
	}
	bView := covView("b-target", true, 3*time.Hour, false)
	polB := vtPol("B")
	polB.TraceEnabled = true
	rotate := model.Move{Action: model.ActionRotate}
	wantB := e.costFor(ownerName("B")).ECost(bView, rotate, polB)
	wrongA := e.costFor(ownerName("A")).ECost(bView, rotate, polB)
	if wantB == wrongA {
		t.Fatalf("fixture: A's primed bucket and B's bucket price the rotate identically (%v); the test cannot discriminate", wantB)
	}
	decs := e.Decide([]*model.WorkloadView{bView}, polB)
	d := decs[0]
	if math.Abs(d.BlindCost-wantB) > 1e-12 {
		t.Fatalf("B's blind cost = %v, want B's own calibrator %v (old code priced it from A's bucket: %v)", d.BlindCost, wantB, wrongA)
	}
	if d.Trace == nil || d.Trace.Inputs.CostCalibratorTenant != "B" || d.Trace.Inputs.BlindCostSource != "tenant-calibrator" {
		t.Fatalf("record must name the pricing calibrator: %+v", d.Trace)
	}
	stateful := covView("b-stateful", true, 3*time.Hour, true)
	if sd := e.Decide([]*model.WorkloadView{stateful}, polB)[0]; sd.BlindCost != 1.0 || sd.Trace.Inputs.BlindCostSource != "stateful-max" {
		t.Fatalf("stateful blind cost = %v source=%q, want 1.0/stateful-max", sd.BlindCost, sd.Trace.Inputs.BlindCostSource)
	}
}

// decoyLambdaWindow returns a λ inside the window where a fresh evidence-less decoy has a
// POSITIVE raw net (cov − λ·cost) but a NON-positive provenance-discounted gain
// (cov·prov − λ·cost), i.e. exactly the case selection discounts away.
func decoyLambdaWindow(t *testing.T, cov, ecost, prov float64) float64 {
	t.Helper()
	lo, hi := prov*cov/ecost, cov/ecost // discounted gain ≤ 0 at λ ≥ lo; raw net > 0 at λ < hi
	if !(lo < hi) {
		t.Fatalf("fixture: no λ window (cov=%v cost=%v prov=%v)", cov, ecost, prov)
	}
	return (lo + hi) / 2
}

// (b) Site 2 — demand applies the same provenance discount as selection: a prov-discounted
// decoy adds no λ pressure. Old code counted it at face value (demand=1). Fails on old code.
func TestDemandExcludesProvenanceDiscountedDecoys(t *testing.T) {
	probe := NewCoverageEngine()
	probe.Now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	pol := covPolicy(2)
	pol.ProactiveFloor = 15 * time.Minute                        // live tenant value (as in decoyScenario)
	pol.AntiOverRotationWindow = 90 * time.Second                // live tenant value
	decoy := covView("decoy", true, 90*time.Second, false)       // fresh: just clears the anti-over-rotation window
	decoy.ExposureByVariable = realisticClocks(90 * time.Second) // unactuated: epoch clocks absent, so M-28 fail-opens on quarantine (still prov-discounted)
	set, ctx := probe.AssembleSet([]*model.WorkloadView{decoy}, pol)
	if len(set.Candidates) == 0 {
		t.Fatal("fixture: decoy has no feasible candidate")
	}
	prov := provFn(ctx, pol.ProactiveFloor.Seconds())("ns/decoy")
	if prov >= 1 {
		t.Fatalf("fixture: decoy is not provenance-discounted (prov=%v)", prov)
	}
	// the decoy's best raw candidate
	bestCov, bestCost := 0.0, 0.0
	for _, c := range set.Candidates {
		cov := 0.0
		for _, k := range c.CoverKeys {
			cov += set.FactWeights[k]
		}
		if cov-bestCost > bestCov-bestCost || bestCov == 0 {
			bestCov, bestCost = cov, c.ECost
		}
	}
	lambda := decoyLambdaWindow(t, bestCov, bestCost, prov)

	e := NewCoverageEngine()
	e.Now = probe.Now
	pol.Lambda = lambda // seeds the tenant dual at first use
	pol.TraceEnabled = true
	d := e.Decide([]*model.WorkloadView{decoy}, pol)[0]
	if d.Trace == nil {
		t.Fatal("trace missing")
	}
	if d.Selected {
		t.Fatalf("fixture: the decoy was selected at λ=%v; selection should discount it away", lambda)
	}
	if d.Trace.CandidateDemand != 0 {
		t.Fatalf("demand = %d at λ=%.4f (raw net > 0, discounted gain ≤ 0): the decoy still pumps λ pressure (old behaviour)", d.Trace.CandidateDemand, lambda)
	}
	if d.Trace.DualUpdate.Demand != 0 {
		t.Fatalf("dual update saw demand %d, want 0", d.Trace.DualUpdate.Demand)
	}
}

// (c) Site 3 — the standalone fallback (attack-backed, unselected asset) picks the action
// the MAIN path would rank first: coverage·prov − λ·cost. Old code ranked by coverage − λ·cost,
// which can pick a different action whenever prov < 1 and the candidates' costs differ.
func TestFallbackActionUsesTheSameProvenancedScore(t *testing.T) {
	probe := NewCoverageEngine()
	probe.Now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	// budget 0: nothing is ever selected, so every asset takes the standalone fallback path
	// (without reactiveOnly every asset is attack-backed). The asset is fresh and evidence-less,
	// so prov < 1 — a targeting event would make prov = 1 and hide the site-3 difference.
	pol := covPolicy(0)
	pol.ProactiveFloor = 15 * time.Minute
	pol.AntiOverRotationWindow = 90 * time.Second
	// Non-AI, epoch-clocked actions (networkIdentity / routeKey / identity): on a fresh UNACTUATED
	// pod their epoch markers are absent, so the M-28 cadence cap fail-OPENs and each is a feasible,
	// provenance-discounted candidate with its own cover/cost — the ≥2-differing-cost shape this
	// site needs. (Pre-M-28 rotate carried the large cover here, but rotate reads podIdentity, which
	// a fresh pod HAS, so the cap now vetoes it — the provenance floor governs the first move of the
	// epoch-clocked actions instead.)
	pol.EnabledActions = map[model.Action]bool{
		model.ActionQuarantine:     true,
		model.ActionRouteRotate:    true,
		model.ActionIdentityRotate: true,
	}
	asset := covView("attacked", true, 90*time.Second, false) // fresh → prov < 1
	asset.ExposureByVariable = realisticClocks(90 * time.Second)
	// Keep the default neighbor so quarantine carries the LARGER cover (networkIdentity + lateral
	// edge) AND the larger cost, while route-rotate carries a single-fact cover at a smaller cost —
	// the shape where a per-asset provenance discount flips the standalone argmax.
	set, ctx := probe.AssembleSet([]*model.WorkloadView{asset}, pol)
	prov := provFn(ctx, pol.ProactiveFloor.Seconds())("ns/attacked")
	type cand struct {
		action    model.Action
		cov, cost float64
	}
	var cands []cand
	for _, c := range set.Candidates {
		cov := 0.0
		for _, k := range c.CoverKeys {
			cov += set.FactWeights[k]
		}
		cands = append(cands, cand{c.Action, cov, c.ECost})
	}
	if len(cands) < 2 {
		t.Fatalf("fixture: need ≥2 candidates, got %+v (prov=%v)", cands, prov)
	}
	// find a λ where the raw argmax and the provenanced argmax differ
	argmax := func(score func(cand) float64) model.Action {
		best, bestV := model.ActionNoop, math.Inf(-1)
		for _, c := range cands {
			if v := score(c); v > bestV {
				best, bestV = c.action, v
			}
		}
		return best
	}
	var lambda float64
	var rawPick, provPick model.Action
	for l := 0.05; l < 10; l += 0.05 {
		raw := argmax(func(c cand) float64 { return c.cov - l*c.cost })
		pv := argmax(func(c cand) float64 { return c.cov*prov - l*c.cost })
		if raw != pv {
			lambda, rawPick, provPick = l, raw, pv
			break
		}
	}
	if lambda == 0 {
		t.Fatalf("fixture: no λ separates raw and provenanced argmax (prov=%v cands=%+v)", prov, cands)
	}
	e := NewCoverageEngine()
	e.Now = probe.Now
	pol.Lambda = lambda
	d := e.Decide([]*model.WorkloadView{asset}, pol)[0]
	if d.Selected {
		t.Fatal("fixture: budget 0 must select nothing")
	}
	if d.Action != provPick {
		t.Fatalf("fallback picked %s at λ=%.2f; the main-path score ranks %s first (old raw ranking picked %s)", d.Action, lambda, provPick, rawPick)
	}
	// The fallback record carries the provenance it was scored with.
	if math.Abs(d.Provenance-prov) > 1e-12 {
		t.Fatalf("fallback record provenance = %v, want prov(key) = %v", d.Provenance, prov)
	}
}

// Same function AND same inputs (Math review): with owning-block-disjoint covers no other
// asset's selection can shrink a candidate's marginal, so the coverage input demand uses
// (the standalone cover) equals the marginal the main path evaluated, and prov(key), λ and
// ECost are the same per candidate. Hence candidateDemand must equal the number of assets
// whose best main-path netGain (recorded per candidate in the trace) is positive.
func TestDemandIsRebuildableFromMainPathCandidateGains(t *testing.T) {
	e := NewCoverageEngine()
	e.Now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	pol := covPolicy(1)
	pol.ProactiveFloor = 15 * time.Minute
	pol.AntiOverRotationWindow = 90 * time.Second
	pol.TraceEnabled = true
	fleet := []*model.WorkloadView{
		covView("fresh-decoy", true, 90*time.Second, false),
		covView("mid", true, 7*time.Minute, false),
		covView("due", true, 2*time.Hour, false),
	}
	decs := e.Decide(fleet, pol)
	rebuilt, demand := 0, -1
	for _, d := range decs {
		if d.Trace == nil {
			t.Fatalf("%s: trace missing", d.Pod)
		}
		demand = d.Trace.CandidateDemand
		best := math.Inf(-1)
		for _, c := range d.Trace.Candidates {
			if c.TieBreakRank < 0 || !c.NetGain.Present {
				continue // exclusions carry no main-path gain
			}
			if c.NetGain.Value > best {
				best = c.NetGain.Value
			}
			if !c.Provenance.Present || math.Abs(c.Provenance.Value-d.Provenance) > 1e-12 {
				t.Fatalf("%s/%s: candidate provenance %v differs from the decision's %v", d.Pod, c.Action, c.Provenance, d.Provenance)
			}
		}
		if best > 0 {
			rebuilt++
		}
	}
	if demand != rebuilt {
		t.Fatalf("candidateDemand = %d but %d assets have a positive main-path netGain: demand and selection do not share inputs", demand, rebuilt)
	}
}
