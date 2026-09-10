package main

// validity_test.go — p3report CONSUMES the harness measurement-validity contract
// (V3-M161, lead review R1 finding 4).
//
// Each case writes REAL metrics.jsonl lines, reads them with the shipping
// readMetrics, and renders the REAL report, then asserts what the rendered
// markdown is allowed to claim. A valid observed contrast is the positive
// control.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/metricvalidity"
)

// fixtureRow builds a metrics.jsonl line from the CONTRACT'S OWN TYPES rather
// than hand-written JSON. A hand-written block silently omits whatever fields
// the contract has started checking, making the fixture more permissive than the
// producer — see corpus_parity_test.go, which runs real producer output through
// this same reader.
type fixtureRow struct {
	Scenario              string                   `json:"scenario"`
	Defender              string                   `json:"defender"`
	Trial                 int                      `json:"trial"`
	OracleAchieved        bool                     `json:"oracleAchieved"`
	DisruptionVsOracle    float64                  `json:"disruptionVsOracle"`
	AttackerDwellSeconds  float64                  `json:"attackerDwellSeconds"`
	SecurityPerCost       float64                  `json:"securityPerCost"`
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

// ordinaryFixture is what Runner.Run writes for a genuine, fully anchored,
// cost-observed comparison on one arm.
func ordinaryFixture(defender string, trial int, disruption float64, achieved bool, actions int, state string) fixtureRow {
	return fixtureRow{
		Scenario: "s1", Defender: defender, Trial: trial, OracleAchieved: achieved,
		DisruptionVsOracle: disruption, SecurityPerCost: disruption, DefensiveActions: actions,
		FalseDefensiveActions: -1, TimeToActionSeconds: 1, ObservedState: state,
		Validity: &metricvalidity.Validity{
			Version: metricvalidity.Version, Kind: metricvalidity.TrialOrdinary,
			Status: metricvalidity.StatusValid, Phase: metricvalidity.PhaseComplete,
			AttackExecuted: true, OracleObserved: true, ObserverPresent: true, CostObserved: true,
			Scored: true,
			Baseline: metricvalidity.BaselineRef{Required: true, Defender: "d-nomtd",
				Kind: metricvalidity.TrialOrdinary, Trial: trial, IsSelf: defender == "d-nomtd",
				Observed: true, Valid: true, OracleAchieved: true, Usable: true},
			Cleanup: metricvalidity.CleanupRecord{Complete: true, Verified: true},
		},
	}
}

// negControlFixture is what Runner.Run writes for a no-attack negative control.
func negControlFixture(trial, falseMoves int, costObserved bool) fixtureRow {
	f := fixtureRow{
		Scenario: "s1", Defender: "d-phorvex", Trial: trial, NegativeControl: true,
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

// The observed positive control (attack lands undefended), a genuine fully
// observed disruption, a MEASURED clean control and an UNOBSERVED one.
func undefendedLine(t *testing.T) string {
	return ordinaryFixture("d-nomtd", 0, 0, true, 0, "[survival=20s]").line(t)
}
func defendedLine(t *testing.T) string {
	return ordinaryFixture("d-phorvex", 0, 1, false, 2, "[survival=3s]").line(t)
}
func cleanNegControlLine(t *testing.T) string      { return negControlFixture(1, 0, true).line(t) }
func unobservedNegControlLine(t *testing.T) string { return negControlFixture(2, 0, false).line(t) }

func renderLines(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	var body string
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, err := readMetrics(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(lines) {
		t.Fatalf("decoded %d rows, want %d", len(rows), len(lines))
	}
	return render(rows, "SMOKE", 1.0, path)
}

// POSITIVE CONTROL: an observed contrast with a MEASURED clean negative control
// still reports its numbers and passes its control checks.
func TestP3ReportValidObservedContrastIsPublished(t *testing.T) {
	md := renderLines(t, undefendedLine(t), defendedLine(t), cleanNegControlLine(t))
	for _, want := range []string{
		"max falseDefensiveActions = **0**",
		"1/1 observed control trial(s)",
		"Attack rows: **2** total — 2 certified",
		"Negative-control trials: **observed** (1 of 1 observed)",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("report missing %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "NOT MEASURED") {
		t.Errorf("a fully measured report claimed NOT MEASURED:\n%s", md)
	}
}

// A partially observed negative control must never be rendered as a pass.
func TestP3ReportPartialNegativeControlIsNotAPass(t *testing.T) {
	md := renderLines(t, undefendedLine(t), defendedLine(t), cleanNegControlLine(t), unobservedNegControlLine(t))
	if !strings.Contains(md, "Negative control: PARTIAL (1 of 2 control trials observed)") {
		t.Errorf("partial control not disclosed:\n%s", md)
	}
	if !strings.Contains(md, "NOT MEASURED") {
		t.Errorf("partial control not marked NOT MEASURED:\n%s", md)
	}
	if strings.Contains(md, "max falseDefensiveActions = **0** (target 0)") {
		t.Errorf("a partial control was published as a measured clean result:\n%s", md)
	}
}

// A negative control that was never observed is unknown, not zero.
func TestP3ReportUnobservedNegativeControlIsNotZero(t *testing.T) {
	md := renderLines(t, undefendedLine(t), defendedLine(t), unobservedNegControlLine(t))
	if !strings.Contains(md, "Negative control: UNOBSERVED (0 of 1 control trials measured)") {
		t.Errorf("unobserved control not disclosed:\n%s", md)
	}
	if !strings.Contains(md, "unknown, not zero") {
		t.Errorf("unobserved control not stated as unknown:\n%s", md)
	}
}

// An UNOBSERVED cost never enters the cost or efficiency means.
func TestP3ReportUnknownCostIsExcludedFromCostMeans(t *testing.T) {
	unknown := ordinaryFixture("d-phorvex", 0, 1, false, -1, "[survival=3s]")
	unknown.SecurityPerCost = 0
	unknown.Validity.CostObserved = false
	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	if err := os.WriteFile(path, []byte(undefendedLine(t)+"\n"+unknown.line(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, err := readMetrics(path)
	if err != nil {
		t.Fatal(err)
	}
	by, _, _ := aggregate(rows)
	a := by["s1"]["d-phorvex"]
	if a == nil {
		t.Fatal("defended arm missing")
	}
	if len(a.actions) != 0 || len(a.secPerCost) != 0 {
		t.Fatalf("an unobserved cost entered the means: actions=%v secPerCost=%v", a.actions, a.secPerCost)
	}
	// The disruption comparison itself survives.
	if len(a.disruption) != 1 || a.disruption[0] != 1 {
		t.Fatalf("the disruption measurement was lost: %v", a.disruption)
	}
	md := render(rows, "SMOKE", 1.0, path)
	if !strings.Contains(md, "defensive cost UNOBSERVED") {
		t.Errorf("the exclusion is not disclosed:\n%s", md)
	}
}

// Rows the contract refuses are excluded from the published numbers and counted.
func TestP3ReportRefusedRowsAreExcludedAndDisclosed(t *testing.T) {
	broken := ordinaryFixture("d-phorvex", 0, 1, false, 2, "[survival=3s]")
	broken.Validity.Status = metricvalidity.StatusInvalid
	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	if err := os.WriteFile(path, []byte(undefendedLine(t)+"\n"+broken.line(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, err := readMetrics(path)
	if err != nil {
		t.Fatal(err)
	}
	by, _, _ := aggregate(rows)
	if a := by["s1"]["d-phorvex"]; a != nil && len(a.disruption) != 0 {
		t.Fatalf("a refused row entered the disruption mean: %v", a.disruption)
	}
	md := render(rows, "SMOKE", 1.0, path)
	if !strings.Contains(md, "1 REFUSED") {
		t.Errorf("the refusal is not disclosed:\n%s", md)
	}
}

// Legacy rows stay readable but the report says plainly that they are not
// certified measurements.
// A legacy corpus stays readable and COUNTED, but none of it is blended into a
// certified mean, and a report with nothing certified says UNAVAILABLE rather
// than publishing zeros.
func TestP3ReportLegacyRowsAreCountedButExcludedFromCertifiedMeans(t *testing.T) {
	legacyUndefended := `{"scenario":"s1","defender":"d-nomtd","trial":0,"oracleAchieved":true,"disruptionVsOracle":0,"defensiveActions":0,"falseDefensiveActions":-1,"observedState":"[survival=20s]"}`
	legacyDefended := `{"scenario":"s1","defender":"d-phorvex","trial":0,"oracleAchieved":false,"disruptionVsOracle":1,"defensiveActions":2,"falseDefensiveActions":-1,"observedState":"[survival=3s]"}`

	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	if err := os.WriteFile(path, []byte(legacyUndefended+"\n"+legacyDefended+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, err := readMetrics(path)
	if err != nil {
		t.Fatal(err)
	}
	by, _, _ := aggregate(rows)
	for _, arm := range []string{"d-nomtd", "d-phorvex"} {
		a := by["s1"][arm]
		if a == nil {
			continue
		}
		if len(a.disruption) != 0 || len(a.actions) != 0 || len(a.secPerCost) != 0 {
			t.Errorf("legacy rows contaminated %s's certified means: disruption=%v actions=%v secPerCost=%v",
				arm, a.disruption, a.actions, a.secPerCost)
		}
		if a.census.legacy == 0 {
			t.Errorf("%s: legacy rows were dropped instead of counted: %+v", arm, a.census)
		}
	}

	md := render(rows, "SMOKE", 1.0, path)
	if !strings.Contains(md, "2 LEGACY/UNVERIFIED") {
		t.Errorf("legacy rows not counted:\n%s", md)
	}
	if !strings.Contains(md, "EXCLUDED from every certified mean") {
		t.Errorf("legacy exclusion not disclosed:\n%s", md)
	}
	if !strings.Contains(md, "UNAVAILABLE — NO CERTIFIED OBSERVATIONS") {
		t.Errorf("an all-legacy corpus must report UNAVAILABLE, not zeros:\n%s", md)
	}
	if !strings.Contains(md, "Negative control: NOT RUN") {
		t.Errorf("absent control not disclosed:\n%s", md)
	}
}
