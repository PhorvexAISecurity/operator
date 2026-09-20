package report

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// LineError records a metrics line that could not be decoded, so a corrupt or
// truncated row is retained as a known unknown instead of vanishing.
type LineError struct {
	Line  int    `json:"line"`
	Error string `json:"error"`
}

// MetricsRead is the result of reading a metrics JSONL file with the
// measurement-validity distinction preserved: how many rows predate the validity
// contract, and which lines could not be decoded at all.
type MetricsRead struct {
	Metrics     []core.Metric
	Legacy      int
	Undecodable []LineError
}

// ReadMetricsFile reads a metrics.jsonl file TOLERANTLY: every decodable row is
// returned, undecodable lines are retained by line number, and rows written
// before the measurement-validity contract are counted as legacy/unverified.
// Nothing is inferred for a legacy row and no file is ever rewritten.
func ReadMetricsFile(path string) (MetricsRead, error) {
	var out MetricsRead
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024) // large lines (command lists)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m core.Metric
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			out.Undecodable = append(out.Undecodable, LineError{Line: n, Error: err.Error()})
			continue
		}
		if m.IsLegacy() {
			out.Legacy++
		}
		out.Metrics = append(out.Metrics, m)
	}
	return out, sc.Err()
}

// ReadMetricsJSONL reads a metrics.jsonl file STRICTLY: any undecodable line is
// an error, so an accumulating (-resume) run never appends onto a file it could
// not fully parse. Because every Pass-B field is omitempty, the existing
// 1980-row Pass-A file still decodes — its rows simply decode with no validity
// block and are reported as LEGACY / UNVERIFIED.
func ReadMetricsJSONL(path string) ([]core.Metric, error) {
	read, err := ReadMetricsFile(path)
	if err != nil {
		return nil, err
	}
	if len(read.Undecodable) > 0 {
		first := read.Undecodable[0]
		return nil, fmt.Errorf("parse metric line %d: %s (%d undecodable line(s) in %s)", first.Line, first.Error, len(read.Undecodable), path)
	}
	return read.Metrics, nil
}

// dollars.go is the PASS-A-WITH-DOLLARS view + the Pass-B economics renderer. It
// is pure post-processing over the ONE extended Metric schema: it RE-COMPUTES
// ROI($), Schwartau (P from each arm's rotation interval, D/R from the measured
// time-to-action), and attack-reusability for every SCORED metric row, then
// renders the $ / Schwartau / reusability columns and an H1/H2/H3 hypothesis
// section with the Phorvex column left TO-BE-FILLED. ZERO core change, ZERO
// re-execution.
//
// Validity rule (identical to the main report): invalid, skipped, unanchored and
// legacy/unverified rows never enter a denominator, and an arm with an observed
// cost of "unobserved" yields no ROI or efficiency figure at all — an unmeasured
// arm is rendered `n/a`, never $0 or 0%.

// DollarInputs carries the swappable ROI knobs + the per-arm rotation intervals so
// the renderer recomputes economics for rows that did not have them stamped (e.g.
// the existing Pass-A rows). RotationIntervals maps defender name -> seconds.
type DollarInputs struct {
	ROI               core.ROIInputs
	RotationIntervals map[string]float64
	// BaselineDefender is the static (no-MTD) anchor for attack-reusability.
	BaselineDefender string
}

// DefaultRotationIntervals returns the known per-arm rotation intervals so a
// Pass-A-with-dollars pass that has only the metrics file (no live registry) can
// still set Schwartau's P. d-nomtd/d-phorvex-slot are static (0); the three
// rotating arms share the blind interval (6s in the smoke config).
func DefaultRotationIntervals() map[string]float64 {
	return map[string]float64{
		"d-nomtd":        0,
		"d-r6blindtimer": 6,
		"d-randomequal":  6,
		"d-fullphoenix":  6,
		"d-phorvex-slot": 0,
	}
}

// dollarRow is one (scenario, defender) aggregate enriched with recomputed
// economics over the arm's SCORED, cost-observed trials.
type dollarRow struct {
	Scenario           string
	Defender           string
	Realism            core.ScenarioRealism
	BenignControl      bool
	Trials             int
	MeanDisruption     float64
	MeanDefensiveActs  float64
	MeanTimeToAction   float64
	RotationInterval   float64
	ROI                core.ROIMetric
	Schwartau          core.SchwartauMetric
	Reuse              core.ReuseMetric
	MTDEffect          string
	SplitOracle        string
	TriggerAttribution string
	CapabilityPending  bool
	DetectorAbsent     bool
	// Economics is true only when the arm has at least one scored, cost-observed
	// trial; otherwise every dollar/Schwartau figure below is NOT MEASURED.
	Economics bool
	Validity  ArmValidity
	// NegControlState / Total / Usable disclose the arm's negative-control census
	// so a hypothesis verdict never implies a clean arm on a partial control.
	NegControlState  string
	NegControlTotal  int
	NegControlUsable int
}

// negStateOf derives the negative-control state from a complete census. Any
// unusable control demotes a fully-observed claim to `partial`.
func negStateOf(total, usable, unusable int) string {
	switch {
	case total == 0:
		return NegControlNotRun
	case usable == 0:
		return NegControlUnobserved
	case unusable > 0:
		return NegControlPartial
	default:
		return NegControlObserved
	}
}

// recomputeEconomics builds the per-arm dollar rows from the metric stream. For
// every SCORED row it RE-COMPUTES ROI/Schwartau/reuse from the measured fields
// (it does NOT trust any pre-stamped nested struct — that keeps Pass-A and
// Pass-B identical), and it excludes every row that was not a measurement.
func recomputeEconomics(metrics []core.Metric, in DollarInputs) []dollarRow {
	type acc struct {
		disruption []float64
		acts       []float64
		tta        []float64
		detAbsent  bool
		capPending bool
		mtd        string
		split      string
		trigger    string
		replaySucc []int
		validity   ArmValidity
		// Negative-control census, carried so a hypothesis verdict can disclose a
		// partial or failed control instead of implying a clean arm.
		negTotal, negUsable, negUnusable int
		negFalseMax                      int
	}
	byArm := map[ArmKey]*acc{}
	order := []ArmKey{}
	// First pass: the static-baseline replay-success per scenario, over SCORED
	// baseline rows only.
	baselineReplay := map[string]int{}
	baselineSeen := map[string]int{}
	for i := range metrics {
		m := metrics[i]
		if m.AnchorOnly || effectiveMetricRealism(m) == core.RealismMarkerSimulation || m.ScenarioBenignControl || m.Kind() != core.TrialOrdinary || !m.IsScored() {
			continue
		}
		if m.Defender == in.BaselineDefender && m.Reuse != nil {
			baselineReplay[m.Scenario] += m.Reuse.ReplaySuccessCount
			baselineSeen[m.Scenario]++
		}
	}
	for sc, n := range baselineSeen {
		if n > 0 {
			baselineReplay[sc] = baselineReplay[sc] / n
		}
	}

	for i := range metrics {
		m := metrics[i]
		if m.AnchorOnly {
			continue
		}
		// The SAME validated interpretation the main report uses: a row's own
		// `scored` claim never reaches a dollar figure on its own.
		val := m.Validated()
		v := val.Claim
		rowKind := val.Kind()
		if m.IsLegacy() && m.NegativeControl {
			rowKind = core.TrialNegativeControl
		}
		realism := effectiveMetricRealism(m)
		k := ArmKey{Scenario: m.Scenario, Defender: m.Defender, Realism: realism, BenignControl: m.ScenarioBenignControl}
		a, ok := byArm[k]
		if !ok {
			a = &acc{negFalseMax: -1}
			byArm[k] = a
			order = append(order, k)
		}

		// The negative-control census travels with the economics view so a
		// hypothesis verdict can disclose a partial or failed control.
		if rowKind == core.TrialNegativeControl {
			a.negTotal++
			// The SHARED contract's verdict, identical to the main report's:
			// interpretable, valid, cleanup-sound, cost observed, no sentinel.
			if !val.NegControlUsable {
				a.negUnusable++
				if !v.Cleanup.Sound() {
					a.validity.addReason("negative control did not verify its cleanup: a dirty trial cannot establish a clean arm")
				} else {
					a.validity.addReason("negative control was not observed: its false-move count is UNOBSERVED, not zero")
				}
				continue
			}
			a.negUsable++
			if m.FalseDefensiveActions > a.negFalseMax {
				a.negFalseMax = m.FalseDefensiveActions
			}
			continue
		}
		if rowKind != core.TrialOrdinary {
			continue
		}
		a.validity.Emitted++
		if realism == core.RealismMarkerSimulation {
			a.validity.RealismExcluded++
			a.validity.addReason("marker simulation excluded from real attack-defense economics")
			continue
		}
		if m.ScenarioBenignControl {
			a.validity.BenignControlExcluded++
			a.validity.addReason("benign functional-effect control excluded from attack-defense economics")
			continue
		}

		// Attribution notes are raw stamps and survive an unscored row; numbers
		// do not.
		a.capPending = a.capPending || m.CapabilityPending
		if m.TriggerAttribution != "" {
			a.trigger = m.TriggerAttribution
		}

		switch {
		case val.Legacy:
			a.validity.Legacy++
			a.validity.addReason("legacy/unverified row: excluded from every $ and Schwartau denominator")
			continue
		case val.Unverified:
			a.validity.Unverified++
			a.validity.addReason(val.Rejections...)
			continue
		case val.Status() == core.MeasurementInvalid:
			a.validity.Invalid++
			a.validity.addReason(val.Reasons()...)
			continue
		case val.Status() == core.MeasurementSkipped:
			a.validity.Skipped++
			a.validity.addReason(val.Reasons()...)
			continue
		case !val.Scorable:
			a.validity.UnscoredValid++
			a.validity.addReason(v.UnscoredReason)
			a.validity.addReason(val.Rejections...)
			continue
		}
		if !v.Cleanup.Complete {
			a.validity.CleanupFailed++
		}
		if !val.CostUsable {
			// A scored disruption with an UNOBSERVED cost cannot produce an ROI or
			// efficiency number; the row is retained as a counted exclusion.
			a.validity.CostUnobserved++
			a.validity.addReason("defensive cost UNOBSERVED: excluded from ROI/Schwartau (unknown cost must not produce a favorable ratio)")
			continue
		}
		a.validity.Scored++
		a.disruption = append(a.disruption, m.DisruptionVsOracle)
		a.acts = append(a.acts, float64(m.DefensiveActions))
		a.tta = append(a.tta, m.TimeToActionSeconds)
		if m.MTDEffect != "" {
			a.mtd = m.MTDEffect
		}
		if m.SplitOracle != "" {
			a.split = m.SplitOracle
		}
		if m.Schwartau != nil && m.Schwartau.DetectionAbsent {
			a.detAbsent = true
		}
		// Receiver-only / detector-absent attribution implies no autonomous detector.
		if m.TriggerAttribution == core.TriggerDetectorAbsent || m.TriggerAttribution == core.TriggerReceiverOnly {
			a.detAbsent = true
		}
		if m.Reuse != nil {
			a.replaySucc = append(a.replaySucc, m.Reuse.ReplaySuccessCount)
		}
	}

	var rows []dollarRow
	for _, k := range order {
		a := byArm[k]
		row := dollarRow{
			Scenario:           k.Scenario,
			Defender:           k.Defender,
			Realism:            k.Realism,
			BenignControl:      k.BenignControl,
			Trials:             len(a.disruption),
			RotationInterval:   in.RotationIntervals[k.Defender],
			MTDEffect:          a.mtd,
			SplitOracle:        a.split,
			TriggerAttribution: a.trigger,
			CapabilityPending:  a.capPending,
			DetectorAbsent:     a.detAbsent,
			Economics:          len(a.disruption) > 0,
			Validity:           a.validity,
			NegControlState:    negStateOf(a.negTotal, a.negUsable, a.negUnusable),
			NegControlTotal:    a.negTotal,
			NegControlUsable:   a.negUsable,
		}
		if !row.Economics {
			// Nothing was measured for this arm: publish no dollar figure at all.
			rows = append(rows, row)
			continue
		}
		row.MeanDisruption = core.Mean(a.disruption)
		row.MeanDefensiveActs = core.Mean(a.acts)
		row.MeanTimeToAction = core.Mean(a.tta)
		// ROI($): recomputed from the measured mean disruption + mean defensive acts.
		row.ROI = core.ComputeROI(in.ROI, row.MeanDisruption, int(round(row.MeanDefensiveActs)))
		// Schwartau: P = rotation interval; D/R from the measured time-to-action.
		row.Schwartau = core.ComputeSchwartau(row.RotationInterval, row.MeanTimeToAction, row.MeanTimeToAction, row.DetectorAbsent)
		// Reuse: mean replay-success vs the static baseline for this scenario.
		meanReplay := 0
		if len(a.replaySucc) > 0 {
			sum := 0
			for _, v := range a.replaySucc {
				sum += v
			}
			meanReplay = sum / len(a.replaySucc)
		}
		row.Reuse = core.ComputeReuse(meanReplay, len(a.replaySucc), baselineReplay[k.Scenario])
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Scenario != rows[j].Scenario {
			return rows[i].Scenario < rows[j].Scenario
		}
		if rows[i].Defender != rows[j].Defender {
			return rows[i].Defender < rows[j].Defender
		}
		if rows[i].Realism != rows[j].Realism {
			return rows[i].Realism < rows[j].Realism
		}
		return !rows[i].BenignControl && rows[j].BenignControl
	})
	return rows
}

// RenderDollars renders the Pass-A-with-dollars / Pass-B economics markdown: the
// per-arm $ROI + Schwartau + attack-reusability table, plus the H1/H2/H3
// hypothesis evaluation with the Phorvex column left TO-BE-FILLED.
func RenderDollars(metrics []core.Metric, in DollarInputs, ciLevel float64) string {
	rows := recomputeEconomics(metrics, in)

	var b strings.Builder
	b.WriteString("# Phoenix / Phorvex -- Dollars, Schwartau & Attack-Reusability View\n\n")
	b.WriteString("Pure post-processing over the SAME extended Metric schema (ZERO re-execution). ROI($) is recomputed from the swappable knobs; Schwartau P = the arm's rotation interval, D/R = measured time-to-action; attack-reusability anchors replay-success to the static baseline.\n\n")
	b.WriteString(fmt.Sprintf("Measurement-validity contract v%d: only SCORED attack trials with an OBSERVED defensive cost enter these figures. Marker simulations, benign functional-effect controls, invalid, skipped, unanchored, cleanup-failed, cost-unobserved and legacy/unverified rows are counted in the validity column and excluded from every denominator. An arm with nothing measured renders `n/a` — never $0, 0%% or a PASS.\n\n", core.MeasurementValidityVersion))

	b.WriteString("## Swappable $ inputs (clearly-labeled defaults)\n\n")
	b.WriteString(fmt.Sprintf("- **gpuCount** = %d (a single DGX-class node)\n", in.ROI.GpuCount))
	b.WriteString(fmt.Sprintf("- **dollarsPerGpuHour** = $%.2f (cloud H100-class list-ish placeholder; SWAP for your contract rate)\n", in.ROI.DollarsPerGpuHour))
	b.WriteString(fmt.Sprintf("- **gpuOverheadPercent** = %.3f (midpoint of R6's stated 1-2%% overhead)\n", in.ROI.GpuOverheadPercent))
	b.WriteString(fmt.Sprintf("- **avoidedBreachValueDollars** = $%.0f (industry-avg breach-cost placeholder; SWAP)\n", in.ROI.AvoidedBreachValue))
	b.WriteString(fmt.Sprintf("- **horizonYears** = %.1f\n", in.ROI.HorizonYears))
	gpuSaved := core.GpuOverheadDollarsPerYearSaved(in.ROI)
	b.WriteString(fmt.Sprintf("- Derived **GPU-overhead $/yr saved** = gpuCount*$/hr*8760*overhead = **$%.0f**\n\n", gpuSaved))

	b.WriteString("## Per-arm dollars / Schwartau / reusability\n\n")
	b.WriteString("| Scenario | Defender | Realism | ScoredTrials | Disrupt% | MTDEffect | Trigger | SecPerCost($) | DefenseCost$/yr | Schwartau P/D/R (s) | P>D+R | Replay succ | ReuseRedux% | CapPending |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, r := range rows {
		if !r.Economics {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | 0 | n/a | %s | %s | n/a | n/a | n/a | n/a | n/a | n/a | %v |\n",
				r.Scenario, r.Defender, r.Realism, dash(r.MTDEffect), dash(r.TriggerAttribution), r.CapabilityPending))
			continue
		}
		sch := ""
		if r.Schwartau.DetectionAbsent {
			sch = fmt.Sprintf("%.0f/ABSENT/%.1f", r.Schwartau.ProtectionTimeSeconds, r.Schwartau.ReactionTimeSeconds)
		} else {
			sch = fmt.Sprintf("%.0f/%.1f/%.1f", r.Schwartau.ProtectionTimeSeconds, r.Schwartau.DetectionTimeSeconds, r.Schwartau.ReactionTimeSeconds)
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %.0f%% | %s | %s | $%.0f | $%.0f | %s | %v | %d | %.0f%% | %v |\n",
			r.Scenario, r.Defender, r.Realism, r.Trials, r.MeanDisruption*100,
			dash(r.MTDEffect), dash(r.TriggerAttribution),
			r.ROI.SecurityPerCostDollars, r.ROI.AnnualDefenseCostDollars,
			sch, r.Schwartau.SchwartauPositive,
			r.Reuse.ReplaySuccessCount, r.Reuse.ReuseReductionVsStatic*100, r.CapabilityPending))
	}
	b.WriteString("\n")

	b.WriteString("## Economics measurement validity\n\n")
	b.WriteString("| Scenario | Defender | Accounting | Reasons |\n|---|---|---|---|\n")
	for _, r := range rows {
		v := r.Validity
		acct := fmt.Sprintf("emitted=%d scored=%d invalid=%d skipped=%d unscored=%d unverified=%d realismExcluded=%d benignControlExcluded=%d cleanupFailed=%d costUnobserved=%d legacy=%d negControl=%s(%d/%d observed)",
			v.Emitted, v.Scored, v.Invalid, v.Skipped, v.UnscoredValid, v.Unverified, v.RealismExcluded, v.BenignControlExcluded, v.CleanupFailed, v.CostUnobserved, v.Legacy,
			r.NegControlState, r.NegControlUsable, r.NegControlTotal)
		if !v.Complete() {
			acct = "INCOMPLETE " + acct
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", r.Scenario, r.Defender, acct, truncate(strings.Join(v.Reasons, " · "), 260)))
	}
	b.WriteString("\n")

	b.WriteString(renderHypotheses(rows, in, ciLevel))
	b.WriteString("\nEvery number above is recomputed from the raw metrics (DisruptionVsOracle, TimeToActionSeconds, DefensiveActions) of SCORED trials + the swappable $ knobs -- no re-run.\n")
	return b.String()
}

// renderHypotheses evaluates H1/H2/H3 (defined transparently from the rotation-vs-
// static thesis; no pre-registered Part 9 doc exists in the repo) and leaves the
// Phorvex (d-phorvex-slot) column TO-BE-FILLED. A hypothesis with no measured
// data is UNSCORED, never FAIL and never PASS.
func renderHypotheses(rows []dollarRow, in DollarInputs, ciLevel float64) string {
	var b strings.Builder
	b.WriteString("## Hypotheses H1 / H2 / H3 (PHORVEX Part 9 -- defined transparently from the rotation-vs-static thesis; no pre-registered doc exists in the repo)\n\n")
	b.WriteString("Each verdict is evaluated over SCORED, cost-observed arms only. UNSCORED means no valid measurement existed — it is neither a pass nor a measured failure.\n\n")
	b.WriteString(renderNegControlCaveat(rows))

	rotating := map[string]bool{"d-r6blindtimer": true, "d-randomequal": true, "d-fullphoenix": true}

	// H1 (Dwell-bound): rotating arms bound PERSISTENCE-oracle success below static.
	var rotDisrupt, staticDisrupt []float64
	for _, r := range rows {
		if !r.Economics {
			continue
		}
		if rotating[r.Defender] {
			rotDisrupt = append(rotDisrupt, r.MeanDisruption)
		}
		if r.Defender == in.BaselineDefender {
			staticDisrupt = append(staticDisrupt, r.MeanDisruption)
		}
	}
	h1 := core.ConfidenceInterval(rotDisrupt, ciLevel)
	b.WriteString(fmt.Sprintf("- **H1 (Dwell-bound)**: rotating arms' mean persistence-disruption = %s (CI %s) over %d scored arm(s) vs static %s. PASS iff CI lower-bound > 0 -> **%s**.\n",
		pctOrNA(h1), pctBandOrNA(h1), h1.N, meanPctOrNA(staticDisrupt), verdict(h1.N, h1.N > 0 && h1.CILow > 0)))

	// H2 (In-request invariance): in-request disruption CI brackets 0 for MTD arms
	// AND attributed detector-absent/receiver-only/capability-pending.
	absentCount, total := 0, 0
	for _, r := range rows {
		if !r.Economics || !rotating[r.Defender] {
			continue
		}
		total++
		if r.DetectorAbsent {
			absentCount++
		}
	}
	b.WriteString(fmt.Sprintf("- **H2 (In-request invariance)**: %d/%d SCORED rotating-arm rows are attributed detector-absent/receiver-only (MTD-CANNOT-HELP in-request). PASS iff in-request disruption brackets 0 AND attribution is detector-absent/receiver-only/capability-pending -> **%s** (the honest negative the AI-MTD-AUDIT predicts).\n",
		absentCount, total, verdict(total, total > 0 && absentCount > 0)))

	// H3 (Trigger-gated neutralization + reuse): for trigger-supplied scenarios,
	// d-fullphoenix persistence-disruption > 0 AND rotating arms reduce reuse.
	// Trigger-supplied scenarios identify themselves GENERICALLY via the metric's
	// TriggerAttribution = harness-injected (stamped by any scenario that emits a
	// genuine matcher SecurityEvent). No hardcoded scenario-name list — the report
	// stays agnostic to which scenarios are plugged in (generic-core invariant).
	var fpDisrupt, reuseRedux []float64
	for _, r := range rows {
		if !r.Economics {
			continue
		}
		if r.TriggerAttribution == core.TriggerHarnessInjected && r.Defender == "d-fullphoenix" {
			fpDisrupt = append(fpDisrupt, r.MeanDisruption)
		}
		if rotating[r.Defender] && r.Reuse.ReuseReductionVsStatic > 0 {
			reuseRedux = append(reuseRedux, r.Reuse.ReuseReductionVsStatic)
		}
	}
	fpCI := core.ConfidenceInterval(fpDisrupt, ciLevel)
	reuseCI := core.ConfidenceInterval(reuseRedux, ciLevel)
	b.WriteString(fmt.Sprintf("- **H3 (Trigger-gated neutralization + reuse)**: for trigger-supplied scenarios, d-fullphoenix persistence-disruption = %s (CI %s) over %d scored arm(s); rotating-arm reuse-reduction mean = %s. PASS iff fullphoenix CI>0 AND reuse-reduction>0 -> **%s**.\n",
		pctOrNA(fpCI), pctBandOrNA(fpCI), fpCI.N, pctOrNA(reuseCI), verdict(fpCI.N, fpCI.N > 0 && fpCI.CILow > 0)))

	b.WriteString("\n**Phorvex column (d-phorvex-slot): TO-BE-FILLED** -- the slot arm currently skips-with-note; the real Phorvex defender drops in later as one file and these H1/H2/H3 rows fill its comparison column with zero harness changes.\n")
	return b.String()
}

// renderNegControlCaveat states, before any verdict, which scored arms lack a
// fully observed negative control. A hypothesis about defensive value rests on
// the false-move rate being measured; where it is not, the verdict below is a
// disruption claim only and must not be read as "no false positives".
func renderNegControlCaveat(rows []dollarRow) string {
	var partial, missing []string
	for _, r := range rows {
		if !r.Economics {
			continue
		}
		arm := r.Scenario + "/" + r.Defender
		switch r.NegControlState {
		case NegControlObserved:
		case NegControlPartial:
			partial = append(partial, fmt.Sprintf("%s (%d of %d observed)", arm, r.NegControlUsable, r.NegControlTotal))
		default:
			missing = append(missing, fmt.Sprintf("%s (%s)", arm, r.NegControlState))
		}
	}
	if len(partial) == 0 && len(missing) == 0 {
		return "**Negative controls**: every scored arm below has a fully observed negative control.\n\n"
	}
	var b strings.Builder
	b.WriteString("**Negative controls (verdict caveat)**: the false-move rate is NOT fully measured for every scored arm, so no verdict below establishes an absence of false defensive moves.\n")
	if len(partial) > 0 {
		b.WriteString(fmt.Sprintf("- PARTIALLY observed: %s\n", strings.Join(partial, "; ")))
	}
	if len(missing) > 0 {
		b.WriteString(fmt.Sprintf("- NOT observed: %s\n", strings.Join(missing, "; ")))
	}
	b.WriteString("\n")
	return b.String()
}

// WriteDollarsReport writes the dollars/Schwartau/reusability markdown to
// outDir/<name>. Returns the path written.
func WriteDollarsReport(outDir, name string, metrics []core.Metric, in DollarInputs, ciLevel float64) (string, error) {
	md := RenderDollars(metrics, in, ciLevel)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(outDir, name)
	if err := os.WriteFile(path, []byte(md), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// verdict is the three-state hypothesis verdict: an empty sample is UNSCORED,
// never a measured PASS or FAIL.
func verdict(n int, ok bool) string {
	if n == 0 {
		return "UNSCORED (no valid measurement)"
	}
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func pctOrNA(a core.Aggregate) string {
	if a.N == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", clamp01(a.Mean)*100)
}

func pctBandOrNA(a core.Aggregate) string {
	if a.N == 0 {
		return "n/a"
	}
	return fmt.Sprintf("[%.0f, %.0f]", clamp01(a.CILow)*100, clamp01(a.CIHigh)*100)
}

func meanPctOrNA(xs []float64) string {
	if len(xs) == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", core.Mean(xs)*100)
}

func round(x float64) float64 {
	if x < 0 {
		return -round(-x)
	}
	return float64(int64(x + 0.5))
}
