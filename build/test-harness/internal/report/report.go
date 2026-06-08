// Package report renders GENERIC tables and a provenance map from the Metric
// JSONL stream. It is agnostic to which scenario/defender produced the metrics —
// it only consumes the ONE Metric schema, so any future plugin is reported
// without a code change here.
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
// control and adaptive trials are aggregated separately by the marker columns.
type ArmKey struct {
	Scenario string
	Defender string
}

// ArmSummary is the per-arm aggregate row.
type ArmSummary struct {
	Scenario          string
	Defender          string
	Category          core.Category
	R6Tag             core.R6Tag
	Trials            int
	Skipped           bool
	SkipReason        string
	Disruption        core.Aggregate
	Dwell             core.Aggregate
	TimeToAction      core.Aggregate
	SecurityPerCost   core.Aggregate
	EvidenceRetention core.Aggregate
	OracleAchievedPct float64
	NegFalseMovesMax  int // max false defensive moves in negative-control trials
}

// Aggregate groups metrics by (scenario, defender) over the NON-control,
// NON-adaptive trials, computing mean + CI per metric. Negative-control and
// skipped trials are accounted separately.
func Aggregate(metrics []core.Metric, ciLevel float64) []ArmSummary {
	type acc struct {
		disruption, dwell, tta, spc, evr []float64
		oracleHits                       int
		oracleTrials                     int
		category                         core.Category
		r6                               core.R6Tag
		skipped                          bool
		skipReason                       string
		negFalseMax                      int
		negSeen                          bool
	}
	byArm := map[ArmKey]*acc{}
	order := []ArmKey{}

	for _, m := range metrics {
		if m.AnchorOnly {
			// Force-included baseline (anchor only): omitted from the report so a
			// DefenderFilter's intent is honored, while it still anchored disruption.
			continue
		}
		k := ArmKey{Scenario: m.Scenario, Defender: m.Defender}
		a, ok := byArm[k]
		if !ok {
			a = &acc{category: m.Category, r6: m.R6Tag, negFalseMax: 0}
			byArm[k] = a
			order = append(order, k)
		}
		if m.NegativeControl {
			a.negSeen = true
			if m.FalseDefensiveActions > a.negFalseMax {
				a.negFalseMax = m.FalseDefensiveActions
			}
			continue
		}
		if m.Skipped {
			a.skipped = true
			a.skipReason = m.SkipReason
			continue
		}
		a.disruption = append(a.disruption, m.DisruptionVsOracle)
		a.dwell = append(a.dwell, m.AttackerDwellSeconds)
		a.tta = append(a.tta, m.TimeToActionSeconds)
		a.spc = append(a.spc, m.SecurityPerCost)
		a.evr = append(a.evr, m.EvidenceRetention)
		a.oracleTrials++
		if m.OracleAchieved {
			a.oracleHits++
		}
	}

	var out []ArmSummary
	for _, k := range order {
		a := byArm[k]
		s := ArmSummary{
			Scenario:          k.Scenario,
			Defender:          k.Defender,
			Category:          a.category,
			R6Tag:             a.r6,
			Trials:            a.oracleTrials,
			Skipped:           a.skipped && a.oracleTrials == 0,
			SkipReason:        a.skipReason,
			Disruption:        core.ConfidenceInterval(a.disruption, ciLevel),
			Dwell:             core.ConfidenceInterval(a.dwell, ciLevel),
			TimeToAction:      core.ConfidenceInterval(a.tta, ciLevel),
			SecurityPerCost:   core.ConfidenceInterval(a.spc, ciLevel),
			EvidenceRetention: core.ConfidenceInterval(a.evr, ciLevel),
			NegFalseMovesMax:  a.negFalseMax,
		}
		if a.oracleTrials > 0 {
			s.OracleAchievedPct = 100 * float64(a.oracleHits) / float64(a.oracleTrials)
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

// RenderMarkdown produces the human report: a per-scenario disruption table
// (defense ON vs OFF), the metric columns with CIs, and the honest R6 verdict.
func RenderMarkdown(metrics []core.Metric, ciLevel float64, capNotes map[string]string) string {
	var b strings.Builder
	summaries := Aggregate(metrics, ciLevel)

	b.WriteString("# Phoenix / Phorvex Attack-Harness Report\n\n")
	b.WriteString(fmt.Sprintf("Confidence level: %.0f%%. Disruption is measured STRICTLY against each scenario's concrete observable oracle, anchored to the undefended positive control (d-nomtd).\n\n", ciLevel*100))

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
	b.WriteString("| Scenario | Category | R6 | Defender | Trials | Disruption% (CI) | OracleHit% | Dwell s (CI) | TimeToAction s | Sec/Cost | EvidRetain | NegFalseMoves |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, s := range summaries {
		if s.Skipped {
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | - | SKIP: %s | - | - | - | - | - | - |\n",
				s.Scenario, s.Category, s.R6Tag, s.Defender, truncate(s.SkipReason, 40)))
			continue
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %d | %s | %.0f%% | %s | %s | %.2f | %.2f | %d |\n",
			s.Scenario, s.Category, s.R6Tag, s.Defender, s.Trials,
			pctCI(s.Disruption), s.OracleAchievedPct,
			valCI(s.Dwell), valCI(s.TimeToAction),
			s.SecurityPerCost.Mean, s.EvidenceRetention.Mean, s.NegFalseMovesMax))
	}
	b.WriteString("\n")

	// Negative-control summary.
	b.WriteString("## Controls\n\n")
	b.WriteString("- **Positive control (d-nomtd, undefended):** every attack MUST achieve its oracle (OracleHit% should be ~100). This anchors the 100% baseline.\n")
	b.WriteString("- **Negative control (no-attack):** each defender arm should show ~0 disruption and 0 false defensive moves (NegFalseMoves column).\n\n")

	// Pass-B AI split-oracle / MTD-effect surface (only rows that stamped it).
	b.WriteString(renderMTDEffectTable(metrics))

	// Honest R6 grounding per scenario (first metric per scenario carries it).
	b.WriteString("## Honest R6 grounding\n\n")
	seen := map[string]bool{}
	for _, m := range metrics {
		if seen[m.Scenario] {
			continue
		}
		seen[m.Scenario] = true
		b.WriteString(fmt.Sprintf("- **%s** [%s]: %s\n", m.Scenario, m.R6Tag, m.ObservedState))
	}
	b.WriteString("\nEvery number above traces to a raw log + command via provenance.json.\n")
	return b.String()
}

// renderMTDEffectTable surfaces the Pass-B split-oracle / MEASURED MTD-effect /
// trigger-attribution per (scenario, defender) for rows that stamped it. It is
// EMPTY (no section) for a pure Pass-A metric stream, so the Pass-A report is
// unchanged. The dollars/Schwartau/reusability + H1/H2/H3 detail lives in
// report-dollars.md (RenderDollars).
func renderMTDEffectTable(metrics []core.Metric) string {
	type key struct{ s, d string }
	seen := map[key]bool{}
	type row struct {
		scenario, defender, split, mtd, trigger string
		capPending                              bool
	}
	var rows []row
	for _, m := range metrics {
		if m.NegativeControl || m.AnchorOnly {
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
	b.WriteString("MTDEffect is MEASURED per arm from the oracle + persistence outcome (never assumed). Trigger attribution carries the audit honesty so a missing-trigger result is not read as a Phoenix failure. See report-dollars.md for ROI($)/Schwartau/reusability + H1/H2/H3.\n\n")
	b.WriteString("| Scenario | Defender | SplitOracle | MTDEffect | TriggerAttribution | CapPending |\n|---|---|---|---|---|---|\n")
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %v |\n", r.scenario, r.defender, dash(r.split), dash(r.mtd), dash(r.trigger), r.capPending))
	}
	b.WriteString("\n")
	return b.String()
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

// WriteReport writes the markdown report to outDir/report.md.
func WriteReport(outDir string, metrics []core.Metric, ciLevel float64, capNotes map[string]string) (string, error) {
	md := RenderMarkdown(metrics, ciLevel, capNotes)
	path := filepath.Join(outDir, "report.md")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(md), 0o644); err != nil {
		return "", err
	}
	return path, nil
}
