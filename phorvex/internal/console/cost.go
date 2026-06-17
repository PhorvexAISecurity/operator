/*
 * Phorvex Console — COST: with-Phorvex vs without-Phorvex, in dollars.
 *
 * For each scenario the benchmark ran, this contrasts the cost the operator carries:
 *   - Phorvex OFF (d-nomtd): the attack lands -> the avoided-breach value is NOT avoided
 *     (residual = avoidedBreach * (1 - disruption)), defense overhead $0.
 *   - Phorvex ON (d-phorvex): the attack is disrupted -> residual breach shrinks by the
 *     measured disruption, for a defense overhead of the MTD rotation cost ($/yr).
 * Savings = costOFF - costON. Every number traces to the same metrics.jsonl roi block; the
 * $ knobs (avoidedBreach, overhead) are the swappable ROI inputs, never hardcoded here.
 */

package console

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type costParse struct {
	Scenario        string `json:"scenario"`
	Defender        string `json:"defender"`
	Disruption      float64 `json:"disruptionVsOracle"`
	Skipped         bool   `json:"skipped"`
	NegativeControl bool   `json:"negativeControl"`
	ROI             struct {
		AvoidedBreachValueDollars      float64 `json:"avoidedBreachValueDollars"`
		GpuOverheadDollarsPerYearSaved float64 `json:"gpuOverheadDollarsPerYearSaved"`
		AnnualDefenseCostDollars       float64 `json:"annualDefenseCostDollars"`
	} `json:"roi"`
}

// CostScenario is the per-scenario with/without-Phorvex dollar contrast.
type CostScenario struct {
	Scenario       string  `json:"scenario"`
	AvoidedBreach  float64 `json:"avoidedBreach"`  // $ a prevented compromise saves
	DisruptWithout float64 `json:"disruptWithout"` // d-nomtd disruption (≈0 — attack lands)
	DisruptWith    float64 `json:"disruptWith"`    // d-phorvex disruption
	DefenseCost    float64 `json:"defenseCost"`    // $/yr cost of running Phorvex (MTD rotation overhead)
	CostWithout    float64 `json:"costWithout"`    // Phorvex OFF: residual breach exposure
	CostWith       float64 `json:"costWith"`       // Phorvex ON: residual breach + defense overhead
	Savings        float64 `json:"savings"`        // costWithout - costWith
	Helps          bool    `json:"helps"`          // PX measurably reduces cost here
}

// CostComparison reads the benchmark metrics and returns the with/without-Phorvex cost per
// scenario plus totals. defenseOverride (>0) replaces the placeholder defense overhead with the
// REAL cloud-priced rotation cost computed from the detected cluster. ok=false if no metrics.
func (c *Config) CostComparison(defenseOverride float64) (scen []CostScenario, totWithout, totWith, totSavings float64, ok bool) {
	path := filepath.Join(c.Root, "build", "test-harness", "out-eks", "metrics.jsonl")
	f, err := os.Open(path)
	if err != nil {
		// fall back to whatever the effectiveness board reads
		path = c.harnessOut("out-p3deep")
		if f, err = os.Open(path); err != nil {
			return nil, 0, 0, 0, false
		}
	}
	defer f.Close()

	type agg struct {
		withoutSum, withSum float64
		withoutN, withN     int
		avoided, defense    float64
	}
	m := map[string]*agg{}
	order := []string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		var r costParse
		if json.Unmarshal([]byte(strings.TrimSpace(sc.Text())), &r) != nil || r.Skipped || r.NegativeControl {
			continue
		}
		a := m[r.Scenario]
		if a == nil {
			a = &agg{}
			m[r.Scenario] = a
			order = append(order, r.Scenario)
		}
		if r.ROI.AvoidedBreachValueDollars > 0 {
			a.avoided = r.ROI.AvoidedBreachValueDollars
		}
		// the cost of running Phorvex = the MTD rotation overhead ($/yr).
		if r.ROI.GpuOverheadDollarsPerYearSaved > 0 {
			a.defense = r.ROI.GpuOverheadDollarsPerYearSaved
		}
		switch r.Defender {
		case "d-nomtd":
			a.withoutSum += r.Disruption
			a.withoutN++
		case "d-phorvex":
			a.withSum += r.Disruption
			a.withN++
		}
	}
	for _, s := range order {
		a := m[s]
		if a.withoutN == 0 || a.withN == 0 {
			continue
		}
		defense := a.defense
		if defenseOverride > 0 {
			defense = defenseOverride // real cloud-priced rotation overhead (overrides the harness placeholder)
		}
		cs := CostScenario{
			Scenario: s, AvoidedBreach: a.avoided, DefenseCost: defense,
			DisruptWithout: clampUnitC(a.withoutSum / float64(a.withoutN)),
			DisruptWith:    clampUnitC(a.withSum / float64(a.withN)),
		}
		cs.CostWithout = a.avoided * (1 - cs.DisruptWithout)
		cs.CostWith = a.avoided*(1-cs.DisruptWith) + a.defense
		cs.Savings = cs.CostWithout - cs.CostWith
		cs.Helps = cs.Savings > 0.5
		scen = append(scen, cs)
		totWithout += cs.CostWithout
		totWith += cs.CostWith
		totSavings += cs.Savings
	}
	sort.Slice(scen, func(i, j int) bool { return scen[i].Savings > scen[j].Savings })
	return scen, totWithout, totWith, totSavings, true
}

func clampUnitC(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
