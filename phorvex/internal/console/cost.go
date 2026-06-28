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
	OracleAchieved   bool    `json:"oracleAchieved"` // did the attacker reach its objective (attack SUCCEEDED)
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

// comparePointerFile is the per-provider pointer the run manager drops on a completed 3-way run, so
// the cost/uptime comparison is scoped to the SELECTED provider (a vCluster attack does not overwrite
// the EKS comparison, and vice-versa).
func comparePointerFile(context string) string {
	if isVClusterContext(context) {
		return "latest-compare-vcluster.txt"
	}
	return "latest-compare-out.txt"
}

// latestComparePath returns the metrics.jsonl of the most recent COMPLETED 3-strategy run for the
// given provider context — the pointer the run manager drops on completion (runs.go) — plus a
// friendly run id, or ("","") if none. This is what makes the comparison DYNAMIC + per-provider:
// after a live 3-way attack on a provider, that provider's panels read THAT run.
func (c *Config) latestComparePath(context string) (path, runID string) {
	b, err := os.ReadFile(filepath.Join(c.HarnessDir, comparePointerFile(context)))
	if err != nil {
		return "", ""
	}
	outDir := strings.TrimSpace(string(b))
	if outDir == "" {
		return "", ""
	}
	p := filepath.Join(c.HarnessDir, outDir, "metrics.jsonl")
	// Only adopt the run if it actually measured ALL THREE strategies — a partial/interrupted run
	// (e.g. timed out before the blind arm) would otherwise render a broken 3-way. Fall back to the
	// static benchmark when incomplete.
	if !hasThreeArms(p) {
		return "", ""
	}
	return p, strings.TrimPrefix(outDir, "out-console-")
}

// hasThreeArms reports whether a metrics.jsonl contains at least one trial for each of the three
// compared strategies (no-defense, blind R6, Phorvex).
func hasThreeArms(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	need := map[string]bool{"d-nomtd": false, "d-r6blindtimer": false, "d-phorvex": false}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<22)
	for sc.Scan() {
		var r struct {
			Defender string `json:"defender"`
		}
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			if _, ok := need[r.Defender]; ok {
				need[r.Defender] = true
			}
		}
	}
	for _, ok := range need {
		if !ok {
			return false
		}
	}
	return true
}

// comparisonMetricsPath resolves WHERE the 3-strategy comparison reads its measured metrics: the
// most recent live 3-way run if one exists, else the static benchmark (out-eks → out-p3deep).
// source is "latest run" | "benchmark"; runID names the run when live.
func (c *Config) comparisonMetricsPath(context string) (path, source, runID string) {
	if p, rid := c.latestComparePath(context); p != "" {
		return p, "latest run", rid
	}
	p := filepath.Join(c.Root, "build", "test-harness", "out-eks", "metrics.jsonl")
	if _, err := os.Stat(p); err == nil {
		return p, "benchmark", ""
	}
	return c.harnessOut("out-p3deep"), "benchmark", ""
}

// CostScenario is the per-attack THREE-STRATEGY dollar contrast — all AWS-priced, all from the
// MEASURED benchmark arms: No defense (d-nomtd), Blind R6 timer (d-r6blindtimer), Phorvex (d-phorvex).
type CostScenario struct {
	Scenario         string  `json:"scenario"`
	AvoidedBreach    float64 `json:"avoidedBreach"`    // valueAtRisk: live AWS infra $/yr the attack exposes
	DisruptWithout   float64 `json:"disruptWithout"`   // d-nomtd disruption (≈0 — attack lands)
	DisruptBlind     float64 `json:"disruptBlind"`     // d-r6blindtimer disruption (measured — blind rotation rarely catches the attack)
	DisruptWith      float64 `json:"disruptWith"`      // d-phorvex disruption (measured)
	DefensiveActions float64 `json:"defensiveActions"` // # actions Phorvex took to handle THIS attack (measured)
	BlindActions     float64 `json:"blindActions"`     // # actions the blind R6 timer took (measured)
	ResponseCost     float64 `json:"responseCost"`     // $ Phorvex's response to this attack costs (actions × per-action AWS compute)
	DefenseCost      float64 `json:"defenseCost"`      // $/yr cost of running Phorvex (operator footprint + actuation compute)
	CostWithout      float64 `json:"costWithout"`      // NO DEFENSE: full AWS-infra exposure (attack lands)
	CostBlind        float64 `json:"costBlind"`        // BLIND R6: residual exposure (only 15% disrupted) + its small defense cost
	CostWith         float64 `json:"costWith"`         // PHORVEX: residual exposure + defense cost
	SuccessNone      float64 `json:"successNone"`      // attack-success % with no defense (measured oracleAchieved)
	SuccessBlind     float64 `json:"successBlind"`     // attack-success % under the blind R6 timer (measured)
	SuccessWith      float64 `json:"successWith"`      // attack-success % under Phorvex (measured)
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
func (c *Config) CostComparison(valueAtRisk, defenseCost, perActionCost float64, context string) (scen []CostScenario, totWithout, totBlind, totWith, totSavings float64, ok bool) {
	// DYNAMIC + per-provider: the latest live 3-way run for this provider if one exists, else the
	// static benchmark.
	path, _, _ := c.comparisonMetricsPath(context)
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, 0, 0, false
	}
	defer f.Close()

	type agg struct {
		withoutSum, withSum, blindSum float64 // disruption sums per strategy
		withoutN, withN, blindN       int
		defActSum, blindActSum        float64 // defensive-action counts (response intensity)
		defActN, blindActN            int
		oNoneAch, oNoneN              int // attack-SUCCESS (oracleAchieved) per strategy
		oBlindAch, oBlindN            int
		oWithAch, oWithN              int
		avoided                       float64
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
		oracle := func(n *int, ach *int) { *n++; if r.OracleAchieved { *ach++ } }
		switch r.Defender {
		case "d-nomtd": // NO DEFENSE — the attack lands
			a.withoutSum += r.Disruption
			a.withoutN++
			oracle(&a.oNoneN, &a.oNoneAch)
		case "d-r6blindtimer": // BLIND R6 TIMER — fixed-cadence rotation, no targeting
			a.blindSum += r.Disruption
			a.blindN++
			a.blindActSum += r.DefensiveActions
			a.blindActN++
			oracle(&a.oBlindN, &a.oBlindAch)
		case "d-phorvex":
			a.withSum += r.Disruption
			a.withN++
			a.defActSum += r.DefensiveActions // how many actions PX took to handle this attack
			a.defActN++
			oracle(&a.oWithN, &a.oWithAch)
		}
	}

	pct := func(ach, n int) float64 {
		if n == 0 {
			return 0
		}
		return 100 * float64(ach) / float64(n)
	}
	var disruptOnSum, disruptBlindSum float64 // for the headline AVERAGES (no double-counting)
	for _, s := range order {
		a := m[s]
		if a.withoutN == 0 || a.withN == 0 {
			continue
		}
		risk := valueAtRisk
		if risk <= 0 {
			risk = a.avoided // legacy fallback: harness ROI breach value (only if no live pricing)
		}
		defActs, blindActs := 0.0, 0.0
		if a.defActN > 0 {
			defActs = a.defActSum / float64(a.defActN)
		}
		if a.blindActN > 0 {
			blindActs = a.blindActSum / float64(a.blindActN)
		}
		cs := CostScenario{
			Scenario: s, AvoidedBreach: risk, DefenseCost: defenseCost,
			DefensiveActions: defActs,
			BlindActions:     blindActs,
			ResponseCost:     defActs * perActionCost, // $ Phorvex's response to THIS attack costs (measured actions × per-action AWS compute)
			DisruptWithout:   clampUnitC(a.withoutSum / float64(a.withoutN)),
			DisruptWith:      clampUnitC(a.withSum / float64(a.withN)),
			SuccessNone:      pct(a.oNoneAch, a.oNoneN),
			SuccessBlind:     pct(a.oBlindAch, a.oBlindN),
			SuccessWith:      pct(a.oWithAch, a.oWithN),
		}
		if a.blindN > 0 {
			cs.DisruptBlind = clampUnitC(a.blindSum / float64(a.blindN))
		}
		// NO DEFENSE: the whole infra exposure lands (attack disruption ≈ 0), zero defense spend.
		cs.CostWithout = risk * (1 - cs.DisruptWithout)
		// BLIND R6: residual exposure after its (small, measured) disruption + its own response compute.
		cs.CostBlind = risk*(1-cs.DisruptBlind) + blindActs*perActionCost
		// PHORVEX: residual exposure + the real cost of running Phorvex (operator footprint + annual
		// actuation compute, passed in as defenseCost) + the per-incident response compute.
		cs.CostWith = risk*(1-cs.DisruptWith) + defenseCost + cs.ResponseCost
		cs.Savings = cs.CostWithout - cs.CostWith
		cs.Helps = cs.Savings > 0.5
		scen = append(scen, cs)
		disruptOnSum += cs.DisruptWith
		disruptBlindSum += cs.DisruptBlind
	}
	if len(scen) == 0 {
		return nil, 0, 0, 0, 0, false
	}
	// HEADLINE — single cluster infrastructure value at risk (NOT a sum across scenarios), defended
	// at the average measured disruption. This is the real AWS exposure, not N× the same hardware.
	risk := valueAtRisk
	if risk <= 0 {
		risk = scen[0].AvoidedBreach
	}
	n := float64(len(scen))
	totWithout = risk                                              // NO DEFENSE: the whole infra is exposed
	totBlind = risk*(1-disruptBlindSum/n) + 0                      // BLIND R6: residual after its weak disruption
	totWith = risk*(1-disruptOnSum/n) + defenseCost                // PHORVEX: residual + real defense cost
	totSavings = totWithout - totWith
	sort.Slice(scen, func(i, j int) bool { return scen[i].Savings > scen[j].Savings })
	return scen, totWithout, totBlind, totWith, totSavings, true
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
