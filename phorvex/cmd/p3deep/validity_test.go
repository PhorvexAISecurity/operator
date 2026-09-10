package main

// validity_test.go — p3deep CONSUMES the harness measurement-validity contract
// (V3-M161, lead review R1 finding 4). Real metrics.jsonl lines are decoded by
// the shipping readMetrics and rendered by the real renderer.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/metricvalidity"
)

// fixtureRow builds a metrics.jsonl line from the CONTRACT'S OWN TYPES rather
// than hand-written JSON, so a fixture can never be more permissive than the
// producer. See corpus_parity_test.go for the real-producer counterpart.
type fixtureRow struct {
	Scenario              string                   `json:"scenario"`
	Defender              string                   `json:"defender"`
	Trial                 int                      `json:"trial"`
	OracleAchieved        bool                     `json:"oracleAchieved"`
	DisruptionVsOracle    float64                  `json:"disruptionVsOracle"`
	DefensiveActions      int                      `json:"defensiveActions"`
	FalseDefensiveActions int                      `json:"falseDefensiveActions"`
	TimeToActionSeconds   float64                  `json:"timeToActionSeconds"`
	AttackerDwellSeconds  float64                  `json:"attackerDwellSeconds"`
	NegativeControl       bool                     `json:"negativeControl,omitempty"`
	ObservedState         string                   `json:"observedState,omitempty"`
	MeanRotationInterval  float64                  `json:"meanRotationIntervalSeconds"`
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

// deepFixture is what Runner.Run writes for a genuine, anchored, cost-observed
// comparison.
func deepFixture(trial int, actions int) fixtureRow {
	return fixtureRow{
		Scenario: "c1-heldout-cve", Defender: "d-phorvex", Trial: trial,
		DisruptionVsOracle: 1, DefensiveActions: actions, FalseDefensiveActions: -1,
		TimeToActionSeconds: 1, ObservedState: "[harm=none]",
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

// deepNegFixture is what Runner.Run writes for a no-attack negative control.
func deepNegFixture(trial, falseMoves int, costObserved bool) fixtureRow {
	f := fixtureRow{
		Scenario: "c1-heldout-cve", Defender: "d-phorvex", Trial: trial, NegativeControl: true,
		DefensiveActions: -1, FalseDefensiveActions: -1,
		Validity: &metricvalidity.Validity{
			Version: metricvalidity.Version, Kind: metricvalidity.TrialNegativeControl,
			Status: metricvalidity.StatusValid, Phase: metricvalidity.PhaseComplete,
			AttackExecuted: true, OracleObserved: true, ObserverPresent: true,
			CostObserved: costObserved,
			Cleanup:      metricvalidity.CleanupRecord{Complete: true, Verified: true},
		},
	}
	if costObserved {
		f.DefensiveActions, f.FalseDefensiveActions = falseMoves, falseMoves
	}
	return f
}

func deepValidLine(t *testing.T) string      { return deepFixture(0, 2).line(t) }
func deepNegControlLine(t *testing.T) string { return deepNegFixture(1, 0, true).line(t) }

func renderDeep(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	var body string
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, err := read(path)
	if err != nil {
		t.Fatal(err)
	}
	return render(rows, path)
}

// POSITIVE CONTROL: a certified row with an observed cost and an observed
// negative control publishes cleanly and claims nothing was refused.
func TestP3DeepValidRowIsPublished(t *testing.T) {
	md := renderDeep(t, deepValidLine(t), deepNegControlLine(t))
	if !strings.Contains(md, "0 attack row(s) REFUSED") {
		t.Errorf("a clean corpus reported refusals:\n%s", md)
	}
	if !strings.Contains(md, "Negative controls: observed (1 of 1 observed)") {
		t.Errorf("observed control not disclosed:\n%s", md)
	}
	if !strings.Contains(md, "0 LEGACY/UNVERIFIED") {
		t.Errorf("legacy count wrong:\n%s", md)
	}
}

// A row the contract refuses is excluded from every published number and
// disclosed.
func TestP3DeepRefusedRowIsExcluded(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*metricvalidity.Validity)
	}{
		{"invalid-status", func(v *metricvalidity.Validity) { v.Status = metricvalidity.StatusInvalid }},
		{"future-version", func(v *metricvalidity.Validity) { v.Version = metricvalidity.Version + 1 }},
		{"cleanup-unresolved", func(v *metricvalidity.Validity) {
			v.Cleanup.Complete, v.Cleanup.Unresolved = false, true
		}},
		{"control-not-usable", func(v *metricvalidity.Validity) { v.Baseline.Usable = false }},
		{"baseline-kind-mismatch", func(v *metricvalidity.Validity) { v.Baseline.Kind = metricvalidity.TrialAdaptive }},
		{"oracle-without-attack", func(v *metricvalidity.Validity) { v.AttackExecuted = false }},
		{"cost-without-observer", func(v *metricvalidity.Validity) { v.ObserverPresent = false }},
		{"valid-at-non-terminal-phase", func(v *metricvalidity.Validity) { v.Phase = metricvalidity.PhaseScenarioSetup }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			row := deepFixture(0, 2)
			tc.mutate(row.Validity)
			md := renderDeep(t, row.line(t), deepNegControlLine(t))
			if !strings.Contains(md, "1 attack row(s) REFUSED") {
				t.Errorf("refusal not disclosed:\n%s", md)
			}
		})
	}
}

// An UNOBSERVED cost never enters a cost mean.
func TestP3DeepUnknownCostIsExcludedFromCostMeans(t *testing.T) {
	unknown := deepFixture(0, -1)
	unknown.Validity.CostObserved = false
	md := renderDeep(t, unknown.line(t), deepNegControlLine(t))
	if !strings.Contains(md, "1 row(s) with an UNOBSERVED defensive cost excluded") {
		t.Errorf("unobserved cost not excluded/disclosed:\n%s", md)
	}
}

// A partially observed negative control is never presented as a clean arm.
func TestP3DeepPartialNegativeControlIsDisclosed(t *testing.T) {
	unobservedNeg := deepNegFixture(2, 0, false).line(t)
	md := renderDeep(t, deepValidLine(t), deepNegControlLine(t), unobservedNeg)
	if !strings.Contains(md, "Negative controls: PARTIAL (1 of 2 observed)") {
		t.Errorf("partial control not disclosed:\n%s", md)
	}
	if !strings.Contains(md, "does NOT establish an absence of false defensive moves") {
		t.Errorf("partial control caveat missing:\n%s", md)
	}
}

// Legacy rows remain readable and are counted as unverified.
func TestP3DeepLegacyRowsAreCounted(t *testing.T) {
	legacy := `{"scenario":"c1-heldout-cve","defender":"d-phorvex","trial":0,"oracleAchieved":false,"disruptionVsOracle":1,"defensiveActions":2,"observedState":"[harm=none]"}`
	md := renderDeep(t, legacy)
	if !strings.Contains(md, "1 LEGACY/UNVERIFIED row(s)") {
		t.Errorf("legacy rows not counted:\n%s", md)
	}
	if !strings.Contains(md, "0 attack row(s) REFUSED") {
		t.Errorf("a legacy row must be disclosed, not refused:\n%s", md)
	}
}
