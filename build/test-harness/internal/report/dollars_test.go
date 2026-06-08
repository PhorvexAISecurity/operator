package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func dollarTestInputs() DollarInputs {
	return DollarInputs{
		ROI:               core.ROIInputs{GpuCount: 8, DollarsPerGpuHour: 2.50, GpuOverheadPercent: 0.015, AvoidedBreachValue: 4_880_000, HorizonYears: 1.0},
		RotationIntervals: DefaultRotationIntervals(),
		BaselineDefender:  "d-nomtd",
	}
}

// TestRenderDollarsRecomputesFromPassAShapedRows feeds PASS-A-SHAPED rows (no
// nested ROI/Schwartau/Reuse set — exactly like the 1980 existing rows) and asserts
// the renderer RE-COMPUTES the dollar/Schwartau columns and emits the H1/H2/H3
// section. This is the no-re-run Pass-A-with-dollars guarantee.
func TestRenderDollarsRecomputesFromPassAShapedRows(t *testing.T) {
	metrics := []core.Metric{
		// Static baseline: hits oracle, 0 disruption, 0 actions.
		{Scenario: "s1", Defender: "d-nomtd", Trial: 0, OracleAchieved: true, DisruptionVsOracle: 0, DefensiveActions: 0},
		{Scenario: "s1", Defender: "d-nomtd", Trial: 1, OracleAchieved: true, DisruptionVsOracle: 0, DefensiveActions: 0},
		// Rotating arm: disrupts, 1 action, time-to-action 1s.
		{Scenario: "s1", Defender: "d-r6blindtimer", Trial: 0, OracleAchieved: false, DisruptionVsOracle: 1, DefensiveActions: 1, TimeToActionSeconds: 1},
		{Scenario: "s1", Defender: "d-r6blindtimer", Trial: 1, OracleAchieved: false, DisruptionVsOracle: 1, DefensiveActions: 1, TimeToActionSeconds: 1},
	}
	md := RenderDollars(metrics, dollarTestInputs(), 0.95)
	for _, want := range []string{
		"Dollars, Schwartau & Attack-Reusability",
		"Swappable $ inputs",
		"GPU-overhead $/yr saved",
		"Per-arm dollars",
		"Hypotheses H1 / H2 / H3",
		"TO-BE-FILLED",
		"d-r6blindtimer",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("dollars report missing %q", want)
		}
	}
	// The recomputed GPU-overhead saved (8*2.5*8760*0.015) = 2628 must appear.
	if !strings.Contains(md, "$2628") {
		t.Errorf("dollars report must show the recomputed $2628 GPU-overhead saved, got:\n%s", md)
	}
}

// TestDollarsSchwartauUsesRotationInterval asserts P (protection time) is taken
// from the arm's rotation interval: a rotating arm gets P=6, a static arm P=0.
func TestDollarsSchwartauUsesRotationInterval(t *testing.T) {
	in := dollarTestInputs()
	metrics := []core.Metric{
		{Scenario: "s1", Defender: "d-nomtd", Trial: 0, OracleAchieved: true, DisruptionVsOracle: 0},
		{Scenario: "s1", Defender: "d-fullphoenix", Trial: 0, OracleAchieved: false, DisruptionVsOracle: 1, DefensiveActions: 1, TimeToActionSeconds: 1,
			SplitOracle: core.SplitPersistence, MTDEffect: core.MTDNeutralizes, TriggerAttribution: core.TriggerHarnessInjected},
	}
	rows := recomputeEconomics(metrics, in)
	var fp *dollarRow
	for i := range rows {
		if rows[i].Defender == "d-fullphoenix" {
			fp = &rows[i]
		}
	}
	if fp == nil {
		t.Fatalf("missing fullphoenix row")
	}
	if fp.Schwartau.ProtectionTimeSeconds != 6 {
		t.Fatalf("fullphoenix P must equal its 6s rotation interval, got %.1f", fp.Schwartau.ProtectionTimeSeconds)
	}
	if fp.MTDEffect != core.MTDNeutralizes {
		t.Fatalf("fullphoenix MTDEffect carried through, got %q", fp.MTDEffect)
	}
}

// TestReadMetricsJSONLRoundTrip ensures the extended-schema reader parses a row and
// that a Pass-A-shaped line (no Pass-B keys) decodes with zero Pass-B fields.
func TestReadMetricsJSONLRoundTrip(t *testing.T) {
	// A Pass-A-shaped JSON line (the additive keys are absent).
	line := `{"scenario":"s1","defender":"d-nomtd","trial":0,"oracleAchieved":true,"disruptionVsOracle":0,"r6Tag":"R6Partial","category":"ClassicChain"}`
	var m core.Metric
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("decode Pass-A line: %v", err)
	}
	if m.SplitOracle != "" || m.ROI != nil || m.Schwartau != nil {
		t.Fatalf("Pass-A line must decode with zero Pass-B fields, got %+v", m)
	}
}
