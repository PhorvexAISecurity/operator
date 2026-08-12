package decision

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
)

// provfloor_sweep_measure_test.go — PHVX-72 / PHORVEXSEC-128, the measurement §6 of the threshold
// analysis asked for, recorded as a PERMANENT artifact.
//
// The first round ran this sweep in throwaway diagnostic files and published only the conclusion, so
// the reviewer could not check the reasoning. Every column §6 listed is emitted here:
//
//   exposure · pHold · stage/nextStage · hazard · StageUrgency · raw coverage
//   · coverage AFTER provenance weighting · can it consume budget / displace the real foothold
//
// Run with -v to print the tables. The key reported conclusions are asserted; individual floating-
// point rows remain measurements so harmless numeric drift does not turn the table into a golden.

// sweepRow is one measured point.
type sweepRow struct {
	exposure           time.Duration
	pHold, hazard, urg float64
	stage, next        string
	rawCover, provCov  float64
	prov               float64
	feasible, selected bool
	realSelected       bool
}

// measureSweep drives the REAL Decide() path with a decoy at the given exposure competing against a
// genuine, nearly-overdue foothold for one move slot. gateProv lets a caller evaluate a hypothetical
// gate without rebuilding the engine: it returns the provenance factor that gate WOULD apply.
func measureSweep(t *testing.T, exposure time.Duration, floor, antiOver time.Duration,
	decoyWeight float64, gateProv func(a killchain.Assessment, exposureSec, floorSec float64) float64) sweepRow {
	t.Helper()
	pol := covPolicy(1)
	pol.Tenant = "sweep"
	pol.DryRun = true
	pol.ProactiveFloor = floor
	pol.AntiOverRotationWindow = antiOver
	pol.AssetWeightFromLabels = func(l map[string]string) float64 {
		if l["role"] == "decoy" {
			return decoyWeight
		}
		return 40
	}
	decoy := covView("decoy", true, exposure, false)
	decoy.Pod.Labels = map[string]string{"role": "decoy"}
	decoy.Neighbors = []model.NeighborRef{{Key: "ns/decoy-nb", Value: 5.0}}
	real := covView("foothold", true, 14*time.Minute, false)
	real.Pod.Labels = map[string]string{"role": "real"}
	real.Neighbors = []model.NeighborRef{{Key: "ns/real-nb", Value: 5.0}}

	r := sweepRow{exposure: exposure}
	for _, d := range NewCoverageEngine().Decide([]*model.WorkloadView{decoy, real}, pol) {
		if strings.Contains(d.Pod, "decoy") {
			r.pHold, r.hazard = d.PHold, d.StageHazard
			r.stage, r.next = d.Stage, d.NextStage
			r.rawCover, r.feasible, r.selected = d.CoveredWeight, d.Feasible, d.Selected
		} else {
			r.realSelected = d.Selected
		}
	}
	// The assessment as the engine computed it, so the hypothetical gate sees the same input.
	m := killchain.NewModel()
	v := covView("decoy", true, exposure, false)
	a := m.Assess(v, pol, exposure.Seconds(), floor.Seconds())
	r.urg = a.StageUrgency
	r.prov = gateProv(a, exposure.Seconds(), floor.Seconds())
	r.provCov = r.rawCover * r.prov
	return r
}

// The gates being compared. provFloor and the exposure ramp are reproduced from coverage.go.
const measProvFloor = 0.34

func rampProv(exposureSec, floorSec float64) float64 {
	if floorSec <= 0 {
		return 1
	}
	r := exposureSec / floorSec
	if r < 0 {
		r = 0
	}
	return measProvFloor + (1-measProvFloor)*r
}

func gateOriginal(a killchain.Assessment, e, f float64) float64 { // StageUrgency > 0 — the tautology
	if e >= f || a.StageUrgency > 0 {
		return 1
	}
	return rampProv(e, f)
}
func gateBaseline(a killchain.Assessment, e, f float64) float64 { // > 0.05, the first fix
	if e >= f || a.StageUrgency > killchain.BaselineStageUrgency {
		return 1
	}
	return rampProv(e, f)
}
func gateThresholdAt(tau float64) func(killchain.Assessment, float64, float64) float64 {
	return func(a killchain.Assessment, e, f float64) float64 {
		if e >= f || a.StageUrgency > tau {
			return 1
		}
		return rampProv(e, f)
	}
}
func gateEvidence(a killchain.Assessment, e, f float64) float64 { // what shipped
	if e >= f || a.HasEvidence {
		return 1
	}
	return rampProv(e, f)
}

// TestSweepTableSection6 emits the full eight-column table §6 asked for, on the LIVE tenant policy
// (antiOverRotationWindow 90s, proactiveFloor 15m) rather than the fixture's 5m/1h.
func TestSweepTableSection6(t *testing.T) {
	floor, antiOver := 15*time.Minute, 90*time.Second
	fmt.Printf("\nSWEEP — live tenant policy (antiOverRotation=%v, proactiveFloor=%v), gate = HasEvidence\n", antiOver, floor)
	fmt.Printf("%8s %8s %8s %9s %-8s %-9s %10s %8s %11s %6s %6s\n",
		"exposure", "pHold", "hazard", "urgency", "stage", "next", "rawCover", "prov", "provCover", "feas", "decoy?")
	var firstPositive, firstCompetitive time.Duration = -1, -1
	for _, sec := range []int{0, 30, 60, 89, 90, 120, 180, 240, 300, 420, 600, 720, 899, 900, 1200} {
		r := measureSweep(t, time.Duration(sec)*time.Second, floor, antiOver, 160, gateEvidence)
		fmt.Printf("%8s %8.4f %8.4f %9.4f %-8s %-9s %10.3f %8.3f %11.3f %6v %6v\n",
			r.exposure, r.pHold, r.hazard, r.urg, r.stage, r.next, r.rawCover, r.prov, r.provCov, r.feasible, r.selected)
		if r.rawCover > 0 && firstPositive < 0 {
			firstPositive = r.exposure
		}
		if r.selected && firstCompetitive < 0 {
			firstCompetitive = r.exposure
		}
	}
	fmt.Printf("\nfirst POSITIVE coverage      : %v\n", firstPositive)
	fmt.Printf("first BUDGET-COMPETITIVE     : %v  (decoy actually takes the slot)\n", firstCompetitive)
	fmt.Printf("note: coverage is 0 below antiOverRotationWindow because the candidate is INFEASIBLE\n")
	if firstPositive != antiOver {
		t.Errorf("first positive coverage = %v, want anti-over-rotation boundary %v", firstPositive, antiOver)
	}
	if firstCompetitive != 5*time.Minute {
		t.Errorf("first budget-competitive exposure = %v, report records 5m", firstCompetitive)
	}
}

// assetShape is one population member the gate must classify correctly.
type assetShape struct {
	name     string
	events   []model.SecurityEventInfo
	genuine  bool // true => a gate that discounts this is producing a FALSE POSITIVE
	exposure time.Duration
}

func shapes(floor time.Duration) []assetShape {
	fresh := 90 * time.Second
	return []assetShape{
		{"decoy (fresh, no evidence)", nil, false, fresh},
		{"decoy (5m, no evidence)", nil, false, 5 * time.Minute},
		{"decoy (12m, no evidence)", nil, false, 12 * time.Minute},
		{"aged, no evidence (legitimately due)", nil, false, floor + time.Minute},
		{"DIRECT low-severity event", []model.SecurityEventInfo{
			{Type: "Anomaly", ThreatLevel: "low", TargetsPod: true, Age: 10 * time.Second}}, true, fresh},
		{"DIRECT medium-severity event", []model.SecurityEventInfo{
			{Type: "Anomaly", ThreatLevel: "medium", TargetsPod: true, Age: 10 * time.Second}}, true, fresh},
		{"NEIGHBOUR compromised (critical)", []model.SecurityEventInfo{
			{Type: "panic", ThreatLevel: "critical", TargetsPod: false, Age: 10 * time.Second}}, true, fresh},
		{"DIRECT high-severity event", []model.SecurityEventInfo{
			{Type: "Anomaly", ThreatLevel: "high", TargetsPod: true, Age: 10 * time.Second}}, true, fresh},
	}
}

// TestGateComparisonAgainstBaseline is the comparison the reviewer asked for and the first round did
// not produce: every candidate gate scored on the SAME population, so "did this approach help, or
// not" is answerable from numbers rather than from prose.
//
//	suppressed   = a manufactured decoy is discounted (what the defence is FOR)
//	false alarms = a genuinely-attacked asset is discounted as if manufactured (the cost)
func TestGateComparisonAgainstBaseline(t *testing.T) {
	floor, antiOver := 15*time.Minute, 90*time.Second
	_ = antiOver
	m := killchain.NewModel()
	pol := covPolicy(1)
	pol.Tenant = "cmp"
	pol.ProactiveFloor = floor

	gates := []struct {
		short, name string
		fn          func(killchain.Assessment, float64, float64) float64
	}{
		{"urg>0", "original: StageUrgency > 0 (the tautology)", gateOriginal},
		{"t.0500", "baseline: StageUrgency > 0.0500", gateBaseline},
		{"t.0625", "threshold 0.0625 (midpoint of 0.05 and 0.075)", gateThresholdAt(0.0625)},
		{"t.0649", "threshold 0.0649 (S7 formula on the MEASURED U_competitive 0.0548)", gateThresholdAt(0.0649)},
		{"t.0700", "threshold 0.0700 (just under the weakest evidenced stage)", gateThresholdAt(0.0700)},
		{"EVIDNCE", "SHIPPED: HasEvidence", gateEvidence},
	}

	fmt.Printf("\nPER-ASSET provenance factor (1.000 = full weight, lower = discounted as a decoy)\n")
	fmt.Printf("%-38s", "asset")
	for _, g := range gates {
		fmt.Printf(" %8s", g.short)
	}
	fmt.Println()
	for _, sh := range shapes(floor) {
		v := covView("x", true, sh.exposure, false)
		v.Events = sh.events
		a := m.Assess(v, pol, sh.exposure.Seconds(), floor.Seconds())
		tag := sh.name
		if sh.genuine {
			tag = "GENUINE " + tag
		}
		fmt.Printf("%-38s", tag[:min(38, len(tag))])
		for _, g := range gates {
			fmt.Printf(" %8.3f", g.fn(a, sh.exposure.Seconds(), floor.Seconds()))
		}
		fmt.Println()
	}

	fmt.Printf("\nSCORECARD\n%-62s %9s %11s  %s\n", "gate", "suppressed", "falseAlarms", "verdict")
	wantScore := map[string][2]int{
		"urg>0":   {0, 0},
		"t.0500":  {0, 0},
		"t.0625":  {2, 3},
		"t.0649":  {2, 3},
		"t.0700":  {2, 3},
		"EVIDNCE": {3, 0},
	}
	for _, g := range gates {
		sup, fa, decoys, genuines := 0, 0, 0, 0
		for _, sh := range shapes(floor) {
			v := covView("x", true, sh.exposure, false)
			v.Events = sh.events
			a := m.Assess(v, pol, sh.exposure.Seconds(), floor.Seconds())
			p := g.fn(a, sh.exposure.Seconds(), floor.Seconds())
			if sh.genuine {
				genuines++
				if p < 1 {
					fa++
				}
			} else {
				decoys++
				if p < 1 {
					sup++
				}
			}
		}
		verdict := "inert"
		if sup > 0 && fa == 0 {
			verdict = "acts, no false alarms"
		} else if sup > 0 && fa > 0 {
			verdict = "acts BUT penalises real threats"
		}
		fmt.Printf("%-62s %5d/%-3d %7d/%-3d  %s\n", g.name, sup, decoys, fa, genuines, verdict)
		if want := wantScore[g.short]; sup != want[0] || fa != want[1] {
			t.Errorf("gate %s score = suppressed %d, false alarms %d; report records %d, %d",
				g.short, sup, fa, want[0], want[1])
		}
	}
	fmt.Println("\nnote: 'aged, no evidence' is counted as a non-decoy target because a pod past its")
	fmt.Println("proactive floor is legitimately due; every gate returns 1 for it via the exposure arm.")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
