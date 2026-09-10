package report

import (
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// anchored builds a MEASURED row: a valid, cost-observed trial anchored to an
// observed successful undefended control. Rows without such a validity block are
// legacy/unverified and are deliberately NOT scored (see
// TestAggregateExcludesLegacyRowsFromCertifiedScores).
func anchored(scn, def string, trial int, achieved bool, disruption float64, actions int) core.Metric {
	m := scoredRow(scn, def, trial, disruption, achieved, actions)
	m.Category, m.R6Tag = core.CategoryR6Claimed, core.R6Covers
	m.SecurityPerCost = disruption
	return m
}

func TestAggregateAnchorsDisruption(t *testing.T) {
	metrics := []core.Metric{
		// Baseline arm hits the oracle both trials (undefended, 0 disruption).
		anchored("s1", "d-nomtd", 0, true, 0, 0),
		anchored("s1", "d-nomtd", 1, true, 0, 0),
		// Defended arm disrupts both trials.
		anchored("s1", "d-full", 0, false, 1, 1),
		anchored("s1", "d-full", 1, false, 1, 1),
		// Negative control: a MEASURED 0 false defensive moves.
		negControlRow("s1", "d-full", 2, 0, true),
	}
	sums := Aggregate(metrics, 0.95)
	if len(sums) != 2 {
		t.Fatalf("want 2 arms, got %d", len(sums))
	}
	var base, full *ArmSummary
	for i := range sums {
		switch sums[i].Defender {
		case "d-nomtd":
			base = &sums[i]
		case "d-full":
			full = &sums[i]
		}
	}
	if base == nil || full == nil {
		t.Fatalf("missing arms")
	}
	if base.Disruption.Mean != 0 {
		t.Fatalf("baseline disruption should be 0, got %v", base.Disruption.Mean)
	}
	if base.OracleAchievedPct != 100 {
		t.Fatalf("baseline oracle hit should be 100%%, got %v", base.OracleAchievedPct)
	}
	if full.Disruption.Mean != 1 {
		t.Fatalf("full disruption should be 1.0, got %v", full.Disruption.Mean)
	}
	if full.NegFalseMovesMax != 0 || full.NegativeControl != NegControlObserved {
		t.Fatalf("negative control false moves should be an OBSERVED 0, got %d (%s)", full.NegFalseMovesMax, full.NegativeControl)
	}
	if !full.Validity.Complete() || full.Validity.Emitted != 2 {
		t.Fatalf("a fully measured arm must report a complete accounting: %+v", full.Validity)
	}
}

// The SAME rows without a validity block are legacy/unverified: they are counted
// but never enter a certified score.
func TestAggregateExcludesLegacyRowsFromCertifiedScores(t *testing.T) {
	metrics := []core.Metric{
		{Scenario: "s1", Defender: "d-nomtd", Trial: 0, OracleAchieved: true, DisruptionVsOracle: 0, Category: core.CategoryR6Claimed, R6Tag: core.R6Covers},
		{Scenario: "s1", Defender: "d-full", Trial: 0, OracleAchieved: false, DisruptionVsOracle: 1, DefensiveActions: 1, Category: core.CategoryR6Claimed, R6Tag: core.R6Covers},
	}
	for _, s := range Aggregate(metrics, 0.95) {
		if s.Trials != 0 || s.Disruption.N != 0 || s.OracleObservedTrials != 0 {
			t.Errorf("legacy arm %q was scored: trials=%d n=%d oracleObserved=%d", s.Defender, s.Trials, s.Disruption.N, s.OracleObservedTrials)
		}
		if s.Validity.Legacy != 1 {
			t.Errorf("legacy arm %q not counted as legacy: %+v", s.Defender, s.Validity)
		}
	}
}

func TestRenderMarkdownContainsControls(t *testing.T) {
	metrics := []core.Metric{anchored("s1", "d-nomtd", 0, true, 0, 0)}
	md := RenderMarkdown(metrics, 0.95, map[string]string{"CapGPU": "no GPU"})
	for _, want := range []string{"Per-arm results", "Controls", "Positive control", "Negative control", "CapGPU", "Measurement validity", "Pairing scope"} {
		if !strings.Contains(md, want) {
			t.Fatalf("report missing %q", want)
		}
	}
}

func TestProvenanceMapsCellsToCommands(t *testing.T) {
	m := anchored("s1", "d-full", 0, false, 1, 1)
	m.Seed, m.RawLogPath, m.Commands = 99, "out/raw/x.log", []string{"kubectl get pods"}
	pm := BuildProvenance([]core.Metric{m}, 1337, 2, "kind-amtd-test", "sandbox", "out/metrics.jsonl", "reproduce-cmd")
	if pm.MasterSeed != 1337 || len(pm.Entries) != 1 {
		t.Fatalf("provenance map malformed: %+v", pm)
	}
	e := pm.Entries[0]
	if e.RawLogPath != "out/raw/x.log" || len(e.Commands) != 1 || e.Seed != 99 {
		t.Fatalf("provenance entry does not tie number->command+log+seed: %+v", e)
	}
	// Provenance must also carry the validity verdict for the cell.
	if !e.Scored || !e.OracleObserved || e.ControlDefender != "d-nomtd" || !e.CleanupComplete || e.Status != core.MeasurementValid {
		t.Fatalf("provenance entry does not carry the measurement verdict: %+v", e)
	}
}

// A provenance entry for an unmeasured row must say so, not present its zero
// disruption as a measurement.
func TestProvenanceMarksUnmeasuredCells(t *testing.T) {
	m := notMeasuredRow("s1", "d-broken", 0, core.MeasurementInvalid, "oracle transport unavailable")
	pm := BuildProvenance([]core.Metric{m}, 1, 1, "ctx", "ns", "out/metrics.jsonl", "cmd")
	e := pm.Entries[0]
	if e.Scored || e.OracleObserved || e.Status != core.MeasurementInvalid || e.UnscoredReason == "" {
		t.Fatalf("provenance presented an invalid row as a measurement: %+v", e)
	}
}
