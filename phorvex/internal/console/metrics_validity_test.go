package console

// metrics_validity_test.go — the console metrics reader CONSUMES the harness
// measurement-validity contract (V3-M161, lead review R1 finding 4).
//
// Every case decodes REAL JSON lines in the shipping metrics.jsonl format
// through the real readMetrics, then asserts what the panels are allowed to
// publish. A valid observed contrast is kept as the positive control.

import (
	"os"
	"path/filepath"
	"testing"
)

// validRow is a metrics.jsonl line the harness would certify.
const validRow = `{"scenario":"s1","defender":"d-phorvex","trial":0,"oracleAchieved":false,` +
	`"disruptionVsOracle":1,"defensiveActions":2,"falseDefensiveActions":-1,"timeToActionSeconds":1,` +
	`"validity":{"version":1,"kind":"ordinary","status":"valid","oracleObserved":true,"costObserved":true,` +
	`"scored":true,"baseline":{"required":true,"defender":"d-nomtd","observed":true,"valid":true,` +
	`"oracleAchieved":true,"usable":true},"cleanup":{"complete":true}}}`

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
	rows := writeMetrics(t, validRow)
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
		name string
		line string
	}{
		{"future-version", replaceOnce(validRow, `"version":1`, `"version":999`)},
		{"unknown-status", replaceOnce(validRow, `"status":"valid"`, `"status":"unrecognized"`)},
		{"invalid-status", replaceOnce(validRow, `"status":"valid"`, `"status":"invalid"`)},
		{"oracle-not-observed", replaceOnce(validRow, `"oracleObserved":true`, `"oracleObserved":false`)},
		{"control-not-usable", replaceOnce(validRow, `"usable":true`, `"usable":false`)},
		{"cleanup-incomplete", replaceOnce(validRow, `"cleanup":{"complete":true}`, `"cleanup":{"complete":false}`)},
		{"cleanup-unresolved", replaceOnce(validRow, `"cleanup":{"complete":true}`, `"cleanup":{"complete":false,"unresolved":true}`)},
		{"not-scored", replaceOnce(validRow, `"scored":true`, `"scored":false`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := writeMetrics(t, tc.line)
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
	line := replaceOnce(replaceOnce(validRow, `"defensiveActions":2`, `"defensiveActions":-1`),
		`"costObserved":true`, `"costObserved":false`)
	rows := writeMetrics(t, line)
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
func TestConsoleLegacyRowIsReadableButNotCertified(t *testing.T) {
	legacy := `{"scenario":"s1","defender":"d-phorvex","trial":0,"oracleAchieved":false,"disruptionVsOracle":1,"defensiveActions":2}`
	rows := writeMetrics(t, legacy)
	m := rows[0]
	if !m.legacy() {
		t.Fatalf("a pre-contract row was not classified as legacy")
	}
	if m.scorable() {
		t.Fatalf("a legacy row was certified")
	}
	if m.excluded() {
		t.Fatalf("a legacy row must remain readable (disclosed), not dropped")
	}
}

// Negative controls: partial and unobserved sets never establish a clean arm.
func TestConsoleNegativeControlCensus(t *testing.T) {
	negObserved := `{"scenario":"s1","defender":"d-phorvex","trial":1,"negativeControl":true,` +
		`"falseDefensiveActions":0,"defensiveActions":0,` +
		`"validity":{"version":1,"kind":"negative-control","status":"valid","oracleObserved":true,` +
		`"costObserved":true,"scored":false,"baseline":{},"cleanup":{"complete":true}}}`
	negUnobserved := `{"scenario":"s1","defender":"d-phorvex","trial":2,"negativeControl":true,` +
		`"falseDefensiveActions":-1,"defensiveActions":-1,` +
		`"validity":{"version":1,"kind":"negative-control","status":"valid","oracleObserved":true,` +
		`"costObserved":false,"scored":false,"baseline":{},"cleanup":{"complete":true}}}`
	negLegacy := `{"scenario":"s1","defender":"d-phorvex","trial":3,"negativeControl":true,"falseDefensiveActions":0}`

	cases := []struct {
		name      string
		lines     []string
		wantState string
		wantMax   int
	}{
		{"not-run", []string{validRow}, "not-run", -1},
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

func replaceOnce(s, old, new string) string {
	i := indexOf(s, old)
	if i < 0 {
		panic("fixture does not contain " + old)
	}
	return s[:i] + new + s[i+len(old):]
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
