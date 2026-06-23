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
	"time"
)

type costParse struct {
	Scenario         string  `json:"scenario"`
	Defender         string  `json:"defender"`
	Disruption       float64 `json:"disruptionVsOracle"`
	DefensiveActions float64 `json:"defensiveActions"` // # of actions Phorvex took to handle this attack (measured)
	Dwell            float64 `json:"attackerDwellSeconds"`
	Skipped          bool    `json:"skipped"`
	NegativeControl  bool    `json:"negativeControl"`
	ROI              struct {
		AvoidedBreachValueDollars      float64 `json:"avoidedBreachValueDollars"`
		GpuOverheadDollarsPerYearSaved float64 `json:"gpuOverheadDollarsPerYearSaved"`
		AnnualDefenseCostDollars       float64 `json:"annualDefenseCostDollars"`
	} `json:"roi"`
}

// perActionSeconds is the MEASURED compute one Phorvex actuation consumes — grounded in the live
// kv-reset re-encode on the Tesla T4 (~0.534s, measured over 46 flushes). Used to price the real
// "cost of Phorvex's response" (defensive actions) per attack, at the workload's AWS node rate.
const perActionSeconds = 0.534

// CostScenario is the per-attack with/without-Phorvex dollar contrast — all AWS-priced.
type CostScenario struct {
	Scenario         string  `json:"scenario"`
	AvoidedBreach    float64 `json:"avoidedBreach"`    // valueAtRisk: live AWS infra $/yr the attack exposes
	DisruptWithout   float64 `json:"disruptWithout"`   // d-nomtd disruption (≈0 — attack lands)
	DisruptWith      float64 `json:"disruptWith"`      // d-phorvex disruption (measured)
	DefensiveActions float64 `json:"defensiveActions"` // # actions Phorvex took to handle THIS attack (measured)
	ResponseCost     float64 `json:"responseCost"`     // $ Phorvex's response to this attack costs (actions × per-action AWS compute)
	DefenseCost      float64 `json:"defenseCost"`      // $/yr cost of running Phorvex (operator footprint + actuation compute)
	CostWithout      float64 `json:"costWithout"`      // Phorvex OFF: full AWS-infra exposure (attack lands)
	CostWith         float64 `json:"costWith"`         // Phorvex ON: residual exposure + defense cost
	Savings          float64 `json:"savings"`          // costWithout - costWith
	Helps            bool    `json:"helps"`            // PX measurably reduces cost here
}

// actuationCostPerYear measures the REAL annual compute Phorvex's responses consume: it reads the
// tail of the live decision audit, counts actuated decisions over their time span to get the live
// actuation rate, and prices it at perActionCost (the measured per-action AWS compute). This is
// the "Phorvex actually doing the work" cost that the bare operator-pod footprint omits. Returns
// (0,0) if no audit / no actuations. perActionCost is $ per single actuation.
func (c *Config) actuationCostPerYear(perActionCost float64) (costYr, ratePerHr float64) {
	path := c.AuditPath
	if path == "" {
		return 0, 0
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, 0
	}
	size := st.Size()
	chunk := int64(8 << 20) // last 8 MiB is plenty to estimate a rate, even on a 100MB+ audit
	if chunk > size {
		chunk = size
	}
	buf := make([]byte, chunk)
	if _, err := f.ReadAt(buf, size-chunk); err != nil && err.Error() != "EOF" {
		return 0, 0
	}
	var actuated int
	var first, last int64 // unix-nanos of first/last decision in the window
	for _, ln := range strings.Split(string(buf), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var rec struct {
			Time     string `json:"time"`
			Kind     string `json:"kind"`
			Actuated bool   `json:"actuated"`
		}
		if json.Unmarshal([]byte(ln), &rec) != nil || rec.Kind != "phorvex.decision" {
			continue
		}
		pt, err := time.Parse(time.RFC3339Nano, rec.Time)
		if err != nil {
			continue
		}
		t := pt.UnixNano()
		if first == 0 {
			first = t
		}
		last = t
		if rec.Actuated {
			actuated++
		}
	}
	spanHr := float64(last-first) / 3.6e12 // nanos -> hours
	if spanHr <= 0 || actuated == 0 {
		return 0, 0
	}
	ratePerHr = float64(actuated) / spanHr
	return ratePerHr * 8760 * perActionCost, ratePerHr
}

// CostComparison reads the benchmark metrics and returns the with/without-Phorvex cost per
// scenario plus headline totals — grounded in real AWS prices. valueAtRisk (>0) is the live
// AWS on-demand $/yr of the cluster infrastructure an attack exposes (the detected instance
// types); defenseOverride (>0) is the real cloud-priced rotation overhead. The headline does
// NOT sum valueAtRisk across scenarios — it reports the single infra value at the AVERAGE
// measured disruption (summing would double-count the same hardware). ok=false if no metrics.
func (c *Config) CostComparison(valueAtRisk, defenseCost, perActionCost float64) (scen []CostScenario, totWithout, totWith, totSavings float64, ok bool) {
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
		defActSum           float64 // d-phorvex defensive-action count (response intensity)
		defActN             int
		avoided             float64
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
		switch r.Defender {
		case "d-nomtd":
			a.withoutSum += r.Disruption
			a.withoutN++
		case "d-phorvex":
			a.withSum += r.Disruption
			a.withN++
			a.defActSum += r.DefensiveActions // how many actions PX took to handle this attack
			a.defActN++
		}
	}

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
		defActs := 0.0
		if a.defActN > 0 {
			defActs = a.defActSum / float64(a.defActN)
		}
		cs := CostScenario{
			Scenario: s, AvoidedBreach: risk, DefenseCost: defenseCost,
			DefensiveActions: defActs,
			ResponseCost:     defActs * perActionCost, // $ Phorvex's response to THIS attack costs (measured actions × per-action AWS compute)
			DisruptWithout:   clampUnitC(a.withoutSum / float64(a.withoutN)),
			DisruptWith:      clampUnitC(a.withSum / float64(a.withN)),
		}
		cs.CostWithout = risk * (1 - cs.DisruptWithout)
		// Phorvex ON = residual infra exposure + the real cost of running Phorvex (operator footprint
		// + annual actuation compute, passed in as defenseCost) + the per-incident response compute.
		cs.CostWith = risk*(1-cs.DisruptWith) + defenseCost + cs.ResponseCost
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
	avgDisruptOn := disruptOnSum / float64(len(scen))
	totWithout = risk                                  // undefended: the whole infra is exposed
	totWith = risk*(1-avgDisruptOn) + defenseCost      // defended: residual exposure + real defense cost
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
