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
		// Static baseline: hits oracle, 0 disruption, 0 observed actions.
		scoredRow("s1", "d-nomtd", 0, 0, true, 0),
		scoredRow("s1", "d-nomtd", 1, 0, true, 0),
		// Rotating arm: disrupts, 1 action, time-to-action 1s.
		scoredRow("s1", "d-r6blindtimer", 0, 1, false, 1),
		scoredRow("s1", "d-r6blindtimer", 1, 1, false, 1),
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
	fullRow := scoredRow("s1", "d-fullphoenix", 0, 1, false, 1)
	fullRow.SplitOracle, fullRow.MTDEffect, fullRow.TriggerAttribution = core.SplitPersistence, core.MTDNeutralizes, core.TriggerHarnessInjected
	metrics := []core.Metric{
		scoredRow("s1", "d-nomtd", 0, 0, true, 0),
		fullRow,
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
// that a Pass-A-shaped line (no Pass-B keys) decodes with zero Pass-B fields —
// and that such a row is visibly LEGACY / UNVERIFIED rather than being read as a
// measurement with a zero cost.
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
	if !m.IsLegacy() || m.IsScored() || m.CostObserved() {
		t.Fatalf("a pre-contract row must decode as legacy/unverified, got legacy=%v scored=%v costObserved=%v",
			m.IsLegacy(), m.IsScored(), m.CostObserved())
	}
	if s := m.MeasurementState().Status; s != core.MeasurementLegacy {
		t.Fatalf("legacy status = %q, want %q", s, core.MeasurementLegacy)
	}
}
