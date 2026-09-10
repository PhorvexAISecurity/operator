// Package report renders GENERIC tables and a provenance map from the Metric
// JSONL stream. It is agnostic to which scenario/defender produced the metrics —
// it only consumes the ONE Metric schema, so any future plugin is reported
// without a code change here.
//
// Every number this package publishes is derived ONLY from rows whose
// measurement-validity block says they were measured. Invalid, skipped,
// unanchored and legacy/unverified rows are counted and explained, never scored
// and never silently dropped: an arm with nothing scorable is reported as having
// no measurement, not as a measured zero.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// ArmKey identifies one aggregated arm: (scenario, defender). The negative
// control and adaptive trials are aggregated separately by trial kind.
type ArmKey struct {
	Scenario string
	Defender string
}

// Negative-control states. "unobserved" and "not-run" must never be rendered as
// a measured zero false defensive moves.
const (
	NegControlNotRun     = "not-run"
	NegControlUnobserved = "unobserved"
	NegControlObserved   = "observed"
)

// ArmValidity is the honest accounting of what an arm's rows actually measured.
// Emitted is the total number of rows the arm produced; the remaining counters
// explain why Emitted and Scored differ, so an arm with one valid and one
// invalid trial can never look like a complete one-trial result.
type ArmValidity struct {
	Emitted        int
	Scored         int
	Invalid        int
	Skipped        int
	UnscoredValid  int
	CleanupFailed  int
	CostUnobserved int
	Legacy         int
	Reasons        []string
}

func (a *ArmValidity) addReason(reasons ...string) {
	for _, r := range reasons {
		if r == "" {
			continue
		}
		for _, seen := range a.Reasons {
			if seen == r {
				return
			}
		}
		a.Reasons = append(a.Reasons, r)
	}
}

// Complete reports whether every emitted row of the arm was scored.
func (a ArmValidity) Complete() bool { return a.Emitted > 0 && a.Emitted == a.Scored }

// ArmSummary is the per-arm aggregate row. Every statistical field is computed
// over SCORED rows only.
type ArmSummary struct {
	Scenario string
	Defender string
	Category core.Category
	R6Tag    core.R6Tag
	// Kind is the trial kind this summary aggregates (ordinary or adaptive).
	Kind core.TrialKind
	// Trials is the number of SCORED trials behind the statistics below.
	Trials int
	// Skipped/SkipReason mark an arm with nothing scored at all.
	Skipped           bool
	SkipReason        string
	Disruption        core.Aggregate
	Dwell             core.Aggregate
	TimeToAction      core.Aggregate
	SecurityPerCost   core.Aggregate
	EvidenceRetention core.Aggregate
	// OracleAchievedPct is over trials whose oracle was actually OBSERVED.
	OracleAchievedPct    float64
	OracleObservedTrials int
	// NegFalseMovesMax is the max false defensive moves observed by the arm's
	// no-attack negative control. It is `-1` when NegativeControl is not
	// `observed`, so the field alone can never be read as a measured zero.
	NegFalseMovesMax int
	NegativeControl  string
	// AnchorOnly marks a force-included positive-control arm.
	AnchorOnly bool
	// ControlDefender is the positive control the scored rows anchored to.
	ControlDefender string
	Validity        ArmValidity
}

// Aggregate groups the ORDINARY trials by (scenario, defender), computing mean +
// CI per metric over SCORED rows only. Negative-control rows contribute the
// false-move state; adaptive rows are aggregated separately by AggregateAdaptive
// because they have no paired ordinary control.
func Aggregate(metrics []core.Metric, ciLevel float64) []ArmSummary {
	return aggregate(metrics, ciLevel, core.TrialOrdinary, false)
}

// AggregateAdaptive groups the ADAPTIVE-attacker passes. They are reported
// separately and are scored only when a matching adaptive control was observed.
func AggregateAdaptive(metrics []core.Metric, ciLevel float64) []ArmSummary {
	return aggregate(metrics, ciLevel, core.TrialAdaptive, false)
}

// AggregateAnchorControls summarises the FORCE-INCLUDED (anchor-only) positive
// control arms. They are omitted from the requested-arm view, but their observed
// results are the provenance of every anchored comparison, so they are reported
// here instead of being invisible.
func AggregateAnchorControls(metrics []core.Metric, ciLevel float64) []ArmSummary {
	return aggregate(metrics, ciLevel, core.TrialOrdinary, true)
}

type armAcc struct {
	disruption, dwell, tta, spc, evr []float64
	oracleHits, oracleObserved       int
	category                         core.Category
	r6                               core.R6Tag
	negState                         string
	negFalseMax                      int
	control                          string
	validity                         ArmValidity
	skipReason                       string
}

func aggregate(metrics []core.Metric, ciLevel float64, kind core.TrialKind, anchorOnly bool) []ArmSummary {
	byArm := map[ArmKey]*armAcc{}
	order := []ArmKey{}
	touch := func(m core.Metric) *armAcc {
		k := ArmKey{Scenario: m.Scenario, Defender: m.Defender}
		a, ok := byArm[k]
		if !ok {
			// negFalseMax starts at -1 (UNOBSERVED) so an arm that never observed a
			// negative control can never present a zero.
			a = &armAcc{category: m.Category, r6: m.R6Tag, negState: NegControlNotRun, negFalseMax: -1}
			byArm[k] = a
			order = append(order, k)
		}
		return a
	}

	for _, m := range metrics {
		if m.AnchorOnly != anchorOnly {
			continue
		}
		v := m.MeasurementState()
		rowKind := m.Kind()

		if rowKind == core.TrialNegativeControl {
			// The negative control belongs to the ordinary view of its arm.
			if kind != core.TrialOrdinary {
				continue
			}
			a := touch(m)
			switch {
			case m.IsLegacy():
				if a.negState != NegControlObserved {
					a.negState = NegControlUnobserved
				}
				a.validity.addReason("negative control is a legacy/unverified row: its false-move count is not evidence of a measurement")
			case v.Status != core.MeasurementValid || !v.CostObserved:
				if a.negState != NegControlObserved {
					a.negState = NegControlUnobserved
				}
				a.validity.addReason("negative control was not observed: its false-move count is UNOBSERVED, not zero")
				a.validity.addReason(v.Reasons...)
			default:
				a.negState = NegControlObserved
				if m.FalseDefensiveActions > a.negFalseMax {
					a.negFalseMax = m.FalseDefensiveActions
				}
			}
			continue
		}
		if rowKind != kind {
			continue
		}

		a := touch(m)
		a.validity.Emitted++
		if m.IsLegacy() {
			a.validity.Legacy++
			a.validity.addReason(v.Reasons...)
			continue
		}
		if !v.CostObserved {
			a.validity.CostUnobserved++
		}
		if !v.Cleanup.Complete {
			a.validity.CleanupFailed++
		}
		if v.Baseline.Defender != "" && a.control == "" {
			a.control = v.Baseline.Defender
		}
		switch v.Status {
		case core.MeasurementInvalid:
			a.validity.Invalid++
			a.validity.addReason(v.Reasons...)
			if a.skipReason == "" {
				a.skipReason = m.SkipReason
			}
			continue
		case core.MeasurementSkipped:
			a.validity.Skipped++
			a.validity.addReason(v.Reasons...)
			if a.skipReason == "" {
				a.skipReason = m.SkipReason
			}
			continue
		}
		// Valid measurement: its oracle observation counts even when the
		// comparison could not be anchored.
		if v.OracleObserved {
			a.oracleObserved++
			if m.OracleAchieved {
				a.oracleHits++
			}
		}
		if !v.Scored {
			a.validity.UnscoredValid++
			a.validity.addReason(v.UnscoredReason)
			if a.skipReason == "" {
				a.skipReason = v.UnscoredReason
			}
			continue
		}
		a.validity.Scored++
		a.disruption = append(a.disruption, m.DisruptionVsOracle)
		a.dwell = append(a.dwell, m.AttackerDwellSeconds)
		a.tta = append(a.tta, m.TimeToActionSeconds)
		a.evr = append(a.evr, m.EvidenceRetention)
		if v.CostObserved {
			// Efficiency is only defined against an OBSERVED cost.
			a.spc = append(a.spc, m.SecurityPerCost)
		} else {
			a.validity.addReason("defensive cost UNOBSERVED: this row is excluded from the security-per-cost denominator")
		}
	}

	var out []ArmSummary
	for _, k := range order {
		a := byArm[k]
		s := ArmSummary{
			Scenario:             k.Scenario,
			Defender:             k.Defender,
			Category:             a.category,
			R6Tag:                a.r6,
			Kind:                 kind,
			Trials:               a.validity.Scored,
			Skipped:              a.validity.Scored == 0,
			SkipReason:           a.skipReason,
			Disruption:           core.ConfidenceInterval(a.disruption, ciLevel),
			Dwell:                core.ConfidenceInterval(a.dwell, ciLevel),
			TimeToAction:         core.ConfidenceInterval(a.tta, ciLevel),
			SecurityPerCost:      core.ConfidenceInterval(a.spc, ciLevel),
			EvidenceRetention:    core.ConfidenceInterval(a.evr, ciLevel),
			OracleObservedTrials: a.oracleObserved,
			NegFalseMovesMax:     a.negFalseMax,
			NegativeControl:      a.negState,
			AnchorOnly:           anchorOnly,
			ControlDefender:      a.control,
			Validity:             a.validity,
		}
		if a.negState != NegControlObserved {
			s.NegFalseMovesMax = -1 // UNOBSERVED / not run — never a measured zero
		}
		if a.oracleObserved > 0 {
			s.OracleAchievedPct = 100 * float64(a.oracleHits) / float64(a.oracleObserved)
		}
		if s.Skipped && s.SkipReason == "" {
			s.SkipReason = "no trial of this arm produced a scoreable measurement"
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scenario != out[j].Scenario {
			return out[i].Scenario < out[j].Scenario
		}
		return out[i].Defender < out[j].Defender
	})
	return out
}

// RenderMarkdown produces the human report without asserting anything about
// matrix completeness. Prefer RenderMarkdownRun, which carries the run outcome.
func RenderMarkdown(metrics []core.Metric, ciLevel float64, capNotes map[string]string) string {
	return RenderMarkdownRun(metrics, ciLevel, capNotes, nil)
}

// RenderMarkdownRun produces the human report: the run's completeness, a
// per-scenario disruption table (defense ON vs OFF) over SCORED trials only, the
// measurement-validity accounting, the control provenance, the separately
// reported adaptive observations, and the honest R6 verdict.
func RenderMarkdownRun(metrics []core.Metric, ciLevel float64, capNotes map[string]string, run *core.RunOutcome) string {
	var b strings.Builder
	summaries := Aggregate(metrics, ciLevel)
	adaptive := AggregateAdaptive(metrics, ciLevel)
	anchors := AggregateAnchorControls(metrics, ciLevel)

	b.WriteString("# Phoenix / Phorvex Attack-Harness Report\n\n")
	b.WriteString(fmt.Sprintf("Confidence level: %.0f%%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control OBSERVED AT THE SAME TRIAL INDEX AND KIND.\n\n", ciLevel*100))
	b.WriteString(fmt.Sprintf("Measurement-validity contract v%d: only rows whose validity block records a completed lifecycle, an observed outcome and a usable positive control are scored. Invalid, skipped, unanchored and legacy/unverified rows are counted below and excluded from every mean, denominator and ROI figure. `n/a` means NOT MEASURED — it is never a measured zero.\n\n", core.MeasurementValidityVersion))
	b.WriteString(renderRunCompleteness(run))

	if len(capNotes) > 0 {
		b.WriteString("## Detected cluster capabilities\n\n")
		keys := make([]string, 0, len(capNotes))
		for k := range capNotes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(fmt.Sprintf("- **%s**: %s\n", k, capNotes[k]))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Per-arm results (scenario x defender)\n\n")
	b.WriteString("Trials counts SCORED trials only; see Measurement validity for what the arm emitted.\n\n")
	b.WriteString(renderArmTable(summaries))

	b.WriteString(renderValidityTable("Measurement validity", summaries))

	// Controls.
	b.WriteString("## Controls\n\n")
	b.WriteString("- **Positive control (undefended):** every attack MUST achieve its oracle on the undefended arm (OracleHit% should be ~100). A comparison is scored ONLY against a control that was observed, valid and successful at the same trial index and kind.\n")
	b.WriteString("- **Negative control (no-attack):** each defender arm should show ~0 disruption and a MEASURED 0 false defensive moves. `not-run` and `unobserved` are reported as such and never as a measured 0.\n")
	b.WriteString("- **Pairing scope:** `TrialSeed` includes the defender identity, so the baseline arm's trial *i* and a defended arm's trial *i* are seeded differently. Read a scored comparison as \"this arm vs the undefended arm at the same index\", NOT as the same trial re-run with the defense removed.\n\n")
	if len(anchors) > 0 {
		b.WriteString("### Force-included anchor-only control arms\n\n")
		b.WriteString("These arms were excluded by the DefenderFilter and run for their positive trials ONLY. Their negative-control and adaptive passes were NOT run and are reported as `not-run`.\n\n")
		b.WriteString(renderArmTable(anchors))
		b.WriteString(renderValidityTable("Anchor-only control validity", anchors))
	}

	// Adaptive observations, reported separately from the ordinary comparison.
	if len(adaptive) > 0 {
		b.WriteString("## Adaptive-attacker observations (reported separately)\n\n")
		b.WriteString("The adaptive pass runs at trial index TrialsPerArm+1 and is comparable ONLY to the baseline arm's own adaptive pass at that index. Where that control was not observed, the row is UNSCORED with an explicit missing-control reason and never borrows an ordinary baseline.\n\n")
		b.WriteString("EXPERIMENTAL LIMITATION: even when an adaptive control exists, the undefended control has no rotation rhythm to learn and therefore strikes immediately. A scored adaptive comparison contrasts a lull-timed attack against an undefended immediate attack; it does NOT isolate the value of the learned strategy. Redesigning that comparison is out of scope here.\n\n")
		b.WriteString(renderArmTable(adaptive))
		b.WriteString(renderValidityTable("Adaptive measurement validity", adaptive))
	}

	// Pass-B AI split-oracle / MTD-effect surface (only rows that stamped it).
	b.WriteString(renderMTDEffectTable(metrics))

	// Honest R6 grounding per scenario, taken from a row whose oracle was
	// actually observed (an errored oracle has no observed state to report).
	b.WriteString("## Honest R6 grounding\n\n")
	for _, g := range r6Grounding(metrics) {
		b.WriteString(g)
	}
	b.WriteString("\nEvery number above traces to a raw log + command via provenance.json.\n")
	return b.String()
}

func renderRunCompleteness(run *core.RunOutcome) string {
	var b strings.Builder
	b.WriteString("## Run completeness\n\n")
	if run == nil {
		b.WriteString("- Matrix completeness was NOT asserted by the producer of this report (rendered from a metrics stream alone). Treat the rows below as whatever the file contains, not as a complete matrix.\n\n")
		return b.String()
	}
	state := "COMPLETE"
	if !run.Complete {
		state = "INCOMPLETE"
	}
	b.WriteString(fmt.Sprintf("- **%s**: planned %d trial(s), executed %d, written %d.\n", state, run.PlannedTrials, run.ExecutedTrials, run.WrittenTrials))
	if run.BaselineDefender == "" {
		b.WriteString("- **No undefended positive-control defender was registered**: no ordinary comparison in this run can be scored.\n")
	} else {
		b.WriteString(fmt.Sprintf("- Positive control arm: `%s`%s.\n", run.BaselineDefender, anchorNote(run.BaselineAnchorOnly)))
	}
	if run.Aborted {
		b.WriteString(fmt.Sprintf("- **ABORTED**: %s\n", run.AbortReason))
	}
	for _, x := range run.Barriers {
		b.WriteString(fmt.Sprintf("- **Barrier**: %s\n", x))
	}
	b.WriteString("\n")
	return b.String()
}

func anchorNote(anchorOnly bool) string {
	if anchorOnly {
		return " (force-included ANCHOR-ONLY: its negative-control and adaptive passes were not run)"
	}
	return ""
}

func renderArmTable(summaries []ArmSummary) string {
	var b strings.Builder
	b.WriteString("| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, s := range summaries {
		if s.Skipped {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | 0 | NOT MEASURED: %s | %s | n/a | n/a | n/a | n/a | %s |\n",
				s.Scenario, s.Category, s.R6Tag, s.Defender, truncate(s.SkipReason, 60), oraclePct(s), negCell(s)))
			continue
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %d | %s | %s | %s | %s | %s | %s | %s |\n",
			s.Scenario, s.Category, s.R6Tag, s.Defender, s.Trials,
			pctCI(s.Disruption), oraclePct(s),
			valCI(s.Dwell), valCI(s.TimeToAction),
			meanOrNA(s.SecurityPerCost), meanOrNA(s.EvidenceRetention), negCell(s)))
	}
	b.WriteString("\n")
	return b.String()
}

func renderValidityTable(title string, summaries []ArmSummary) string {
	if len(summaries) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## " + title + "\n\n")
	b.WriteString("| Scenario | Defender | Accounting | Control | Reasons |\n|---|---|---|---|---|\n")
	for _, s := range summaries {
		v := s.Validity
		acct := fmt.Sprintf("emitted=%d scored=%d invalid=%d skipped=%d unscored=%d cleanupFailed=%d costUnobserved=%d legacy=%d",
			v.Emitted, v.Scored, v.Invalid, v.Skipped, v.UnscoredValid, v.CleanupFailed, v.CostUnobserved, v.Legacy)
		if !v.Complete() {
			acct = "INCOMPLETE " + acct
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			s.Scenario, s.Defender, acct, dash(s.ControlDefender), truncate(strings.Join(v.Reasons, " · "), 220)))
	}
	b.WriteString("\n")
	return b.String()
}

// r6Grounding reports each scenario's observed state, preferring a row whose
// oracle was actually observed so a failed measurement is not published as the
// scenario's grounding.
func r6Grounding(metrics []core.Metric) []string {
	type note struct {
		tag      core.R6Tag
		state    string
		observed bool
	}
	best := map[string]note{}
	var order []string
	for _, m := range metrics {
		v := m.MeasurementState()
		cur, seen := best[m.Scenario]
		if !seen {
			order = append(order, m.Scenario)
			best[m.Scenario] = note{tag: m.R6Tag, state: m.ObservedState, observed: v.OracleObserved}
			continue
		}
		if !cur.observed && v.OracleObserved {
			best[m.Scenario] = note{tag: m.R6Tag, state: m.ObservedState, observed: true}
		}
	}
	out := make([]string, 0, len(order))
	for _, s := range order {
		n := best[s]
		state := n.state
		if !n.observed || state == "" {
			state = "no oracle observation was recorded for this scenario"
		}
		out = append(out, fmt.Sprintf("- **%s** [%s]: %s\n", s, n.tag, state))
	}
	return out
}

// renderMTDEffectTable surfaces the Pass-B split-oracle / MEASURED MTD-effect /
// trigger-attribution per (scenario, defender) for rows that stamped it. It is
// EMPTY (no section) for a pure Pass-A metric stream, so the Pass-A report is
// unchanged. Invalid and legacy rows never contribute a MEASURED effect. The
// dollars/Schwartau/reusability + H1/H2/H3 detail lives in report-dollars.md
// (RenderDollars).
func renderMTDEffectTable(metrics []core.Metric) string {
	type key struct{ s, d string }
	seen := map[key]bool{}
	type row struct {
		scenario, defender, split, mtd, trigger string
		capPending                              bool
	}
	var rows []row
	for _, m := range metrics {
		if m.Kind() != core.TrialOrdinary || m.AnchorOnly || m.IsLegacy() {
			continue
		}
		if m.MeasurementState().Status != core.MeasurementValid {
			continue
		}
		if m.SplitOracle == "" && m.MTDEffect == "" {
			continue // not a Pass-B AI row
		}
		k := key{m.Scenario, m.Defender}
		if seen[k] {
			continue
		}
		seen[k] = true
		rows = append(rows, row{m.Scenario, m.Defender, m.SplitOracle, m.MTDEffect, m.TriggerAttribution, m.CapabilityPending})
	}
	if len(rows) == 0 {
		return ""
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].scenario != rows[j].scenario {
			return rows[i].scenario < rows[j].scenario
		}
		return rows[i].defender < rows[j].defender
	})
	var b strings.Builder
	b.WriteString("## AI split-oracle & MEASURED MTD-effect (Pass-B)\n\n")
	b.WriteString("MTDEffect is MEASURED per arm from the oracle + persistence outcome of a VALID trial (never assumed, never lifted from an invalid or legacy row). Trigger attribution carries the audit honesty so a missing-trigger result is not read as a Phoenix failure. See report-dollars.md for ROI($)/Schwartau/reusability + H1/H2/H3.\n\n")
	b.WriteString("| Scenario | Defender | SplitOracle | MTDEffect | TriggerAttribution | CapPending |\n|---|---|---|---|---|---|\n")
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %v |\n", r.scenario, r.defender, dash(r.split), dash(r.mtd), dash(r.trigger), r.capPending))
	}
	b.WriteString("\n")
	return b.String()
}

func oraclePct(s ArmSummary) string {
	if s.OracleObservedTrials == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%% (n=%d)", s.OracleAchievedPct, s.OracleObservedTrials)
}

// negCell renders the negative-control column. An unrun or unobserved control is
// NEVER rendered as 0.
func negCell(s ArmSummary) string {
	switch s.NegativeControl {
	case NegControlObserved:
		return fmt.Sprintf("%d", s.NegFalseMovesMax)
	case NegControlUnobserved:
		return "n/a (unobserved)"
	default:
		return "n/a (not run)"
	}
}

func pctCI(a core.Aggregate) string {
	if a.N == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%% [%.0f,%.0f]", a.Mean*100, clamp01(a.CILow)*100, clamp01(a.CIHigh)*100)
}

func valCI(a core.Aggregate) string {
	if a.N == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f [%.1f,%.1f]", a.Mean, a.CILow, a.CIHigh)
}

// meanOrNA renders a mean, or `n/a` when nothing was measured — never 0.00.
func meanOrNA(a core.Aggregate) string {
	if a.N == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.2f", a.Mean)
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// WriteReport writes the markdown report to outDir/report.md without asserting
// matrix completeness.
func WriteReport(outDir string, metrics []core.Metric, ciLevel float64, capNotes map[string]string) (string, error) {
	return WriteReportRun(outDir, metrics, ciLevel, capNotes, nil)
}

// WriteReportRun writes the markdown report to outDir/report.md, carrying the
// run outcome so a partial run is never published as a complete matrix.
func WriteReportRun(outDir string, metrics []core.Metric, ciLevel float64, capNotes map[string]string, run *core.RunOutcome) (string, error) {
	md := RenderMarkdownRun(metrics, ciLevel, capNotes, run)
	path := filepath.Join(outDir, "report.md")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(md), 0o644); err != nil {
		return "", err
	}
	return path, nil
}
