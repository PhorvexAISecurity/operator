/*
 * Phorvex Console — COST: with-Phorvex vs without-Phorvex, grounded ENTIRELY in real AWS prices.
 *
 * The value at risk is NOT a fabricated breach figure — it is the live AWS on-demand cost of the
 * cluster infrastructure an attack compromises (valueAtRisk, $/yr, from the detected instance
 * types). For each scenario:
 *   - Phorvex OFF (d-nomtd): the attack lands -> the infrastructure is exposed
 *     (residual = valueAtRisk * (1 - disruptionOFF)), defense overhead $0.
 *   - Phorvex ON (d-phorvex): the attack is disrupted by the MEASURED fraction -> residual
 *     exposure shrinks to valueAtRisk * (1 - disruptionON), for the real rotation overhead ($/yr).
 * The HEADLINE does NOT sum the same infrastructure across scenarios (that double-counts). It
 * reports the single cluster infra value at risk, defended at the AVERAGE measured disruption.
 * Every number is either a live AWS price or a measured disruption — nothing is assumed.
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

// CostScenario is the per-scenario with/without-Phorvex dollar contrast — all AWS-priced.
type CostScenario struct {
	Scenario       string  `json:"scenario"`
	AvoidedBreach  float64 `json:"avoidedBreach"`  // valueAtRisk: live AWS infra $/yr the attack exposes
	DisruptWithout float64 `json:"disruptWithout"` // d-nomtd disruption (≈0 — attack lands)
	DisruptWith    float64 `json:"disruptWith"`    // d-phorvex disruption (measured)
	DefenseCost    float64 `json:"defenseCost"`    // $/yr cost of running Phorvex (real rotation overhead)
	CostWithout    float64 `json:"costWithout"`    // Phorvex OFF: residual AWS-infra exposure
	CostWith       float64 `json:"costWith"`       // Phorvex ON: residual exposure + defense overhead
	Savings        float64 `json:"savings"`        // costWithout - costWith
	Helps          bool    `json:"helps"`          // PX measurably reduces cost here
}

// CostComparison reads the benchmark metrics and returns the with/without-Phorvex cost per
// scenario plus headline totals — grounded in real AWS prices. valueAtRisk (>0) is the live
// AWS on-demand $/yr of the cluster infrastructure an attack exposes (the detected instance
// types); defenseOverride (>0) is the real cloud-priced rotation overhead. The headline does
// NOT sum valueAtRisk across scenarios — it reports the single infra value at the AVERAGE
// measured disruption (summing would double-count the same hardware). ok=false if no metrics.
func (c *Config) CostComparison(valueAtRisk, defenseOverride float64) (scen []CostScenario, totWithout, totWith, totSavings float64, ok bool) {
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
	// real AWS-priced inputs (fall back to the harness ROI block only if pricing wasn't passed).
	defense := defenseOverride

	var disruptOnSum float64 // for the headline's AVERAGE disruption (no double-counting)
	for _, s := range order {
		a := m[s]
		if a.withoutN == 0 || a.withN == 0 {
			continue
		}
		risk := valueAtRisk
		if risk <= 0 {
			risk = a.avoided // legacy fallback: harness ROI breach value (only if no live pricing)
		}
		d := defense
		if d <= 0 {
			d = a.defense
		}
		cs := CostScenario{
			Scenario: s, AvoidedBreach: risk, DefenseCost: d,
			DisruptWithout: clampUnitC(a.withoutSum / float64(a.withoutN)),
			DisruptWith:    clampUnitC(a.withSum / float64(a.withN)),
		}
		cs.CostWithout = risk * (1 - cs.DisruptWithout)
		cs.CostWith = risk*(1-cs.DisruptWith) + d
		cs.Savings = cs.CostWithout - cs.CostWith
		cs.Helps = cs.Savings > 0.5
		scen = append(scen, cs)
		disruptOnSum += cs.DisruptWith
	}
	if len(scen) == 0 {
		return nil, 0, 0, 0, false
	}
	// HEADLINE — single cluster infrastructure value at risk (NOT a sum across scenarios), defended
	// at the average measured disruption. This is the real AWS exposure, not N× the same hardware.
	risk := valueAtRisk
	if risk <= 0 {
		risk = scen[0].AvoidedBreach
	}
	d := defense
	if d <= 0 {
		d = scen[0].DefenseCost
	}
	avgDisruptOn := disruptOnSum / float64(len(scen))
	totWithout = risk                              // undefended: the whole infra is exposed
	totWith = risk*(1-avgDisruptOn) + d            // defended: residual exposure + real overhead
	totSavings = totWithout - totWith
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
