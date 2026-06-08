package report

import (
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func TestAggregateAnchorsDisruption(t *testing.T) {
	metrics := []core.Metric{
		// Baseline arm hits the oracle both trials (undefended, 0 disruption).
		{Scenario: "s1", Defender: "d-nomtd", Trial: 0, OracleAchieved: true, DisruptionVsOracle: 0, Category: core.CategoryR6Claimed, R6Tag: core.R6Covers},
		{Scenario: "s1", Defender: "d-nomtd", Trial: 1, OracleAchieved: true, DisruptionVsOracle: 0, Category: core.CategoryR6Claimed, R6Tag: core.R6Covers},
		// Defended arm disrupts both trials.
		{Scenario: "s1", Defender: "d-full", Trial: 0, OracleAchieved: false, DisruptionVsOracle: 1, DefensiveActions: 1, Category: core.CategoryR6Claimed, R6Tag: core.R6Covers},
		{Scenario: "s1", Defender: "d-full", Trial: 1, OracleAchieved: false, DisruptionVsOracle: 1, DefensiveActions: 1, Category: core.CategoryR6Claimed, R6Tag: core.R6Covers},
		// Negative control: 0 false defensive moves expected.
		{Scenario: "s1", Defender: "d-full", Trial: 2, NegativeControl: true, FalseDefensiveActions: 0},
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
	if full.NegFalseMovesMax != 0 {
		t.Fatalf("negative control false moves should be 0, got %d", full.NegFalseMovesMax)
	}
}

func TestRenderMarkdownContainsControls(t *testing.T) {
	metrics := []core.Metric{
		{Scenario: "s1", Defender: "d-nomtd", OracleAchieved: true, ObservedState: "achieved", R6Tag: core.R6Covers},
	}
	md := RenderMarkdown(metrics, 0.95, map[string]string{"CapGPU": "no GPU"})
	for _, want := range []string{"Per-arm results", "Controls", "Positive control", "Negative control", "CapGPU"} {
		if !strings.Contains(md, want) {
			t.Fatalf("report missing %q", want)
		}
	}
}

func TestProvenanceMapsCellsToCommands(t *testing.T) {
	metrics := []core.Metric{
		{Scenario: "s1", Defender: "d-full", Trial: 0, Seed: 99, RawLogPath: "out/raw/x.log", Commands: []string{"kubectl get pods"}, OracleAchieved: false, DisruptionVsOracle: 1},
	}
	pm := BuildProvenance(metrics, 1337, 2, "kind-amtd-test", "sandbox", "out/metrics.jsonl", "reproduce-cmd")
	if pm.MasterSeed != 1337 || len(pm.Entries) != 1 {
		t.Fatalf("provenance map malformed: %+v", pm)
	}
	e := pm.Entries[0]
	if e.RawLogPath != "out/raw/x.log" || len(e.Commands) != 1 || e.Seed != 99 {
		t.Fatalf("provenance entry does not tie number->command+log+seed: %+v", e)
	}
}
