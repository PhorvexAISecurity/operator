package console

// metrics_validity_test.go — the console metrics reader CONSUMES the harness
// measurement-validity contract (V3-M161, lead review R1 finding 4).
//
// Every case decodes REAL JSON lines in the shipping metrics.jsonl format
// through the real readMetrics, then asserts what the panels are allowed to
// publish. A valid observed contrast is kept as the positive control.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/phorvex/metricvalidity"
)

// fixtureRow is a metrics.jsonl line built from the CONTRACT'S OWN TYPES rather
// than hand-written JSON. A hand-written block silently omits whatever fields
// the contract has started checking, which makes the fixture more permissive
// than the producer and the test worthless. See also the corpus parity tests,
// which run real producer output through this same reader.
type fixtureRow struct {
	Scenario              string                   `json:"scenario"`
	Defender              string                   `json:"defender"`
	Trial                 int                      `json:"trial"`
	OracleAchieved        bool                     `json:"oracleAchieved"`
	DisruptionVsOracle    float64                  `json:"disruptionVsOracle"`
	DefensiveActions      int                      `json:"defensiveActions"`
	FalseDefensiveActions int                      `json:"falseDefensiveActions"`
	TimeToActionSeconds   float64                  `json:"timeToActionSeconds"`
	NegativeControl       bool                     `json:"negativeControl,omitempty"`
	ObservedState         string                   `json:"observedState,omitempty"`
	Validity              *metricvalidity.Validity `json:"validity,omitempty"`
}

func (f fixtureRow) line(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// certifiedRow is what Runner.Run writes for a genuine, fully anchored,
// cost-observed comparison.
func certifiedRow(scenario, defender string, trial int) fixtureRow {
	return fixtureRow{
		Scenario: scenario, Defender: defender, Trial: trial,
		DisruptionVsOracle: 1, DefensiveActions: 2, FalseDefensiveActions: -1, TimeToActionSeconds: 1,
		Validity: &metricvalidity.Validity{
			Version: metricvalidity.Version, Kind: metricvalidity.TrialOrdinary,
			Status: metricvalidity.StatusValid, Phase: metricvalidity.PhaseComplete,
			AttackExecuted: true, OracleObserved: true, ObserverPresent: true, CostObserved: true,
			Scored: true,
			Baseline: metricvalidity.BaselineRef{Required: true, Defender: "d-nomtd",
				Kind: metricvalidity.TrialOrdinary, Trial: trial,
				Observed: true, Valid: true, OracleAchieved: true, Usable: true},
			Cleanup: metricvalidity.CleanupRecord{Complete: true, Verified: true},
		},
	}
}

// negControlFixture is what Runner.Run writes for a no-attack negative control.
func negControlFixture(scenario, defender string, trial, falseMoves int, costObserved bool) fixtureRow {
	f := fixtureRow{
		Scenario: scenario, Defender: defender, Trial: trial, NegativeControl: true,
		FalseDefensiveActions: -1, DefensiveActions: -1,
		Validity: &metricvalidity.Validity{
			Version: metricvalidity.Version, Kind: metricvalidity.TrialNegativeControl,
			Status: metricvalidity.StatusValid, Phase: metricvalidity.PhaseComplete,
			AttackExecuted: true, OracleObserved: true, ObserverPresent: true,
			CostObserved: costObserved,
			Cleanup:      metricvalidity.CleanupRecord{Complete: true, Verified: true},
		},
	}
	if costObserved {
		f.FalseDefensiveActions, f.DefensiveActions = falseMoves, falseMoves
	}
	return f
}

// validRow is the certified positive control as a metrics.jsonl line.
func validRowLine(t *testing.T) string { return certifiedRow("s1", "d-phorvex", 0).line(t) }

func writeMetrics(t *testing.T, lines ...string) []metricRow {
	t.Helper()
	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	var body string
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, ok := readMetrics(path)
	if !ok {
		t.Fatalf("readMetrics refused the file")
	}
	return rows
}

// POSITIVE CONTROL: a genuine certified row is published normally.
func TestConsoleValidRowIsPublished(t *testing.T) {
	rows := writeMetrics(t, validRowLine(t))
	if len(rows) != 1 {
		t.Fatalf("decoded %d rows, want 1", len(rows))
	}
	m := rows[0]
	if m.legacy() || !m.scorable() || m.excluded() || !m.costUsable() {
		t.Fatalf("a certified row was refused: legacy=%v scorable=%v excluded=%v costUsable=%v",
			m.legacy(), m.scorable(), m.excluded(), m.costUsable())
	}
	kept := fixedTrials(rows, "s1", "d-phorvex")
	if len(kept) != 1 || kept[0].DisruptionVsOracle != 1 {
		t.Fatalf("the certified trial was dropped: %+v", kept)
	}
	if len(costObservedTrials(kept)) != 1 {
		t.Fatalf("the observed cost was dropped")
	}
}

// Rows the contract refuses must not reach a panel.
func TestConsoleRefusedRowsAreExcluded(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*metricvalidity.Validity)
	}{
		{"future-version", func(v *metricvalidity.Validity) { v.Version = metricvalidity.Version + 1 }},
		{"unknown-status", func(v *metricvalidity.Validity) { v.Status = "unrecognized" }},
		{"invalid-status", func(v *metricvalidity.Validity) { v.Status = metricvalidity.StatusInvalid }},
		{"oracle-not-observed", func(v *metricvalidity.Validity) { v.OracleObserved = false }},
		{"control-not-usable", func(v *metricvalidity.Validity) { v.Baseline.Usable = false }},
		{"cleanup-incomplete", func(v *metricvalidity.Validity) { v.Cleanup.Complete = false }},
		{"cleanup-unresolved", func(v *metricvalidity.Validity) {
			v.Cleanup.Complete, v.Cleanup.Unresolved = false, true
		}},
		{"retained-cleanup-failure", func(v *metricvalidity.Validity) {
			v.Cleanup.Attempted = []metricvalidity.CleanupStep{{Step: "env.Close", Error: "forbidden"}}
		}},
		{"not-scored", func(v *metricvalidity.Validity) { v.Scored = false }},
		{"baseline-kind-mismatch", func(v *metricvalidity.Validity) { v.Baseline.Kind = metricvalidity.TrialAdaptive }},
		{"baseline-trial-mismatch", func(v *metricvalidity.Validity) { v.Baseline.Trial = 99 }},
		{"oracle-without-attack", func(v *metricvalidity.Validity) { v.AttackExecuted = false }},
		{"cost-without-observer", func(v *metricvalidity.Validity) { v.ObserverPresent = false }},
		{"valid-at-non-terminal-phase", func(v *metricvalidity.Validity) { v.Phase = metricvalidity.PhaseScenarioSetup }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := certifiedRow("s1", "d-phorvex", 0)
			tc.mutate(row.Validity)
			rows := writeMetrics(t, row.line(t))
			if len(rows) != 1 {
				t.Fatalf("the row must still DECODE (it is disclosed, not dropped on read)")
			}
			if !rows[0].excluded() {
				t.Fatalf("a refused row was accepted: %+v", rows[0].Validity)
			}
			if kept := fixedTrials(rows, "s1", "d-phorvex"); len(kept) != 0 {
				t.Fatalf("a refused row reached the panels: %+v", kept)
			}
		})
	}
}

// An UNOBSERVED cost is never a zero cost.
func TestConsoleUnknownCostNeverBecomesZeroCost(t *testing.T) {
	row := certifiedRow("s1", "d-phorvex", 0)
	row.DefensiveActions = -1
	row.Validity.CostObserved = false
	rows := writeMetrics(t, row.line(t))
	m := rows[0]
	if m.costUsable() {
		t.Fatalf("an unobserved cost was accepted as an observation")
	}
	// The comparison itself is still publishable; only the cost is not.
	kept := fixedTrials(rows, "s1", "d-phorvex")
	if len(kept) != 1 {
		t.Fatalf("the row was dropped entirely; only its COST is unobserved: %+v", kept)
	}
	if got := costObservedTrials(kept); len(got) != 0 {
		t.Fatalf("an unobserved cost entered the cost set: %+v", got)
	}
}

// A legacy row (no validity block) stays readable but is never certified.
// A legacy row stays READABLE and identifiable, but it never contaminates a
// certified aggregate: it carries no evidence that it measured anything, so
// blending it into a current score or efficiency mean would launder unverified
// history into a fresh measurement.
func TestConsoleLegacyRowIsReadableButExcludedFromCertifiedAggregates(t *testing.T) {
	legacy := `{"scenario":"s1","defender":"d-phorvex","trial":0,"oracleAchieved":false,"disruptionVsOracle":1,"defensiveActions":2}`
	rows := writeMetrics(t, legacy)
	if len(rows) != 1 {
		t.Fatalf("a legacy row must still DECODE and stay readable, got %d rows", len(rows))
	}
	m := rows[0]
	if !m.legacy() {
		t.Fatalf("a pre-contract row was not classified as legacy")
	}
	if m.scorable() {
		t.Fatalf("a legacy row was certified")
	}
	if !m.excluded() {
		t.Fatalf("a legacy row must be excluded from certified aggregates")
	}
	if m.costUsable() {
		t.Fatalf("a legacy row's cost was treated as an observation")
	}
	if kept := fixedTrials(rows, "s1", "d-phorvex"); len(kept) != 0 {
		t.Fatalf("a legacy row entered the published trial aggregate: %+v", kept)
	}
	// UNAVAILABLE, not zero: nothing certified remains for this arm.
	if c := negControlCensus(rows, "s1", "d-phorvex"); c.State != "not-run" || c.MaxFalseMoves != -1 {
		t.Fatalf("legacy corpus reported a control result: %+v", c)
	}
}

// Negative controls: partial and unobserved sets never establish a clean arm.
func TestConsoleNegativeControlCensus(t *testing.T) {
	negObserved := negControlFixture("s1", "d-phorvex", 1, 0, true).line(t)
	negUnobserved := negControlFixture("s1", "d-phorvex", 2, 0, false).line(t)
	// A dirty control cannot establish a clean arm even though it is never scored.
	dirty := negControlFixture("s1", "d-phorvex", 4, 0, true)
	dirty.Validity.Cleanup.Attempted = []metricvalidity.CleanupStep{{Step: "env.Close", Error: "forbidden"}}
	negDirty := dirty.line(t)
	negLegacy := `{"scenario":"s1","defender":"d-phorvex","trial":3,"negativeControl":true,"falseDefensiveActions":0}`
	validRow := validRowLine(t)

	cases := []struct {
		name      string
		lines     []string
		wantState string
		wantMax   int
	}{
		{"not-run", []string{validRow}, "not-run", -1},
		{"dirty-control", []string{validRow, negDirty}, "unobserved", -1},
		{"observed", []string{validRow, negObserved}, "observed", 0},
		{"partial", []string{validRow, negObserved, negUnobserved}, "partial", -1},
		{"unobserved", []string{validRow, negUnobserved}, "unobserved", -1},
		{"legacy-demotes", []string{validRow, negObserved, negLegacy}, "partial", -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := writeMetrics(t, tc.lines...)
			c := negControlCensus(rows, "s1", "d-phorvex")
			if c.State != tc.wantState {
				t.Errorf("state = %q, want %q (census %+v)", c.State, tc.wantState, c)
			}
			if c.MaxFalseMoves != tc.wantMax {
				t.Errorf("maxFalseMoves = %d, want %d; only a FULLY observed control may report a measured value",
					c.MaxFalseMoves, tc.wantMax)
			}
		})
	}
}
