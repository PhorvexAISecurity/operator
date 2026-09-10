package main

// validity_test.go — p3report CONSUMES the harness measurement-validity contract
// (V3-M161, lead review R1 finding 4).
//
// Each case writes REAL metrics.jsonl lines, reads them with the shipping
// readMetrics, and renders the REAL report, then asserts what the rendered
// markdown is allowed to claim. A valid observed contrast is the positive
// control.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// undefendedRow is the observed positive control (attack lands undefended).
	undefendedRow = `{"scenario":"s1","defender":"d-nomtd","trial":0,"oracleAchieved":true,` +
		`"disruptionVsOracle":0,"defensiveActions":0,"falseDefensiveActions":-1,"securityPerCost":0,` +
		`"observedState":"[survival=20s]","validity":{"version":1,"kind":"ordinary","status":"valid",` +
		`"oracleObserved":true,"costObserved":true,"scored":true,"baseline":{"required":true,` +
		`"defender":"d-nomtd","observed":true,"valid":true,"oracleAchieved":true,"usable":true,"isSelf":true},` +
		`"cleanup":{"complete":true}}}`
	// defendedRow is a genuine, fully observed disruption.
	defendedRow = `{"scenario":"s1","defender":"d-phorvex","trial":0,"oracleAchieved":false,` +
		`"disruptionVsOracle":1,"defensiveActions":2,"falseDefensiveActions":-1,"securityPerCost":0.5,` +
		`"observedState":"[survival=3s]","validity":{"version":1,"kind":"ordinary","status":"valid",` +
		`"oracleObserved":true,"costObserved":true,"scored":true,"baseline":{"required":true,` +
		`"defender":"d-nomtd","observed":true,"valid":true,"oracleAchieved":true,"usable":true},` +
		`"cleanup":{"complete":true}}}`
	// cleanNegControl is a MEASURED zero false defensive moves.
	cleanNegControl = `{"scenario":"s1","defender":"d-phorvex","trial":1,"negativeControl":true,` +
		`"falseDefensiveActions":0,"defensiveActions":0,"validity":{"version":1,"kind":"negative-control",` +
		`"status":"valid","oracleObserved":true,"costObserved":true,"scored":false,"baseline":{},` +
		`"cleanup":{"complete":true}}}`
	// unobservedNegControl never measured its false moves.
	unobservedNegControl = `{"scenario":"s1","defender":"d-phorvex","trial":2,"negativeControl":true,` +
		`"falseDefensiveActions":-1,"defensiveActions":-1,"validity":{"version":1,"kind":"negative-control",` +
		`"status":"valid","oracleObserved":true,"costObserved":false,"scored":false,"baseline":{},` +
		`"cleanup":{"complete":true}}}`
)

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
	md := renderLines(t, undefendedRow, defendedRow, cleanNegControl)
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
	md := renderLines(t, undefendedRow, defendedRow, cleanNegControl, unobservedNegControl)
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
	md := renderLines(t, undefendedRow, defendedRow, unobservedNegControl)
	if !strings.Contains(md, "Negative control: UNOBSERVED (0 of 1 control trials measured)") {
		t.Errorf("unobserved control not disclosed:\n%s", md)
	}
	if !strings.Contains(md, "unknown, not zero") {
		t.Errorf("unobserved control not stated as unknown:\n%s", md)
	}
}

// An UNOBSERVED cost never enters the cost or efficiency means.
func TestP3ReportUnknownCostIsExcludedFromCostMeans(t *testing.T) {
	unknownCost := strings.NewReplacer(
		`"defensiveActions":2`, `"defensiveActions":-1`,
		`"costObserved":true`, `"costObserved":false`,
		`"securityPerCost":0.5`, `"securityPerCost":0`,
	).Replace(defendedRow)
	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	if err := os.WriteFile(path, []byte(undefendedRow+"\n"+unknownCost+"\n"), 0o600); err != nil {
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
	broken := strings.Replace(defendedRow, `"status":"valid"`, `"status":"invalid"`, 1)
	path := filepath.Join(t.TempDir(), "metrics.jsonl")
	if err := os.WriteFile(path, []byte(undefendedRow+"\n"+broken+"\n"), 0o600); err != nil {
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
func TestP3ReportLegacyRowsAreDisclosedAsUncertified(t *testing.T) {
	legacyUndefended := `{"scenario":"s1","defender":"d-nomtd","trial":0,"oracleAchieved":true,"disruptionVsOracle":0,"defensiveActions":0,"falseDefensiveActions":-1,"observedState":"[survival=20s]"}`
	legacyDefended := `{"scenario":"s1","defender":"d-phorvex","trial":0,"oracleAchieved":false,"disruptionVsOracle":1,"defensiveActions":2,"falseDefensiveActions":-1,"observedState":"[survival=3s]"}`
	md := renderLines(t, legacyUndefended, legacyDefended)
	if !strings.Contains(md, "2 LEGACY/UNVERIFIED") {
		t.Errorf("legacy rows not counted:\n%s", md)
	}
	if !strings.Contains(md, "NOT certified measurements") {
		t.Errorf("legacy rows not disclosed as uncertified:\n%s", md)
	}
	if !strings.Contains(md, "Negative control: NOT RUN") {
		t.Errorf("absent control not disclosed:\n%s", md)
	}
}
