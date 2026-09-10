package main

// validity_test.go — p3deep CONSUMES the harness measurement-validity contract
// (V3-M161, lead review R1 finding 4). Real metrics.jsonl lines are decoded by
// the shipping readMetrics and rendered by the real renderer.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	deepValidRow = `{"scenario":"c1-heldout-cve","defender":"d-phorvex","trial":0,"oracleAchieved":false,` +
		`"disruptionVsOracle":1,"defensiveActions":2,"observedState":"[harm=none]","meanRotationIntervalSeconds":0,` +
		`"validity":{"version":1,"kind":"ordinary","status":"valid","oracleObserved":true,"costObserved":true,` +
		`"scored":true,"baseline":{"required":true,"defender":"d-nomtd","observed":true,"valid":true,` +
		`"oracleAchieved":true,"usable":true},"cleanup":{"complete":true}}}`
	deepNegControl = `{"scenario":"c1-heldout-cve","defender":"d-phorvex","trial":1,"negativeControl":true,` +
		`"defensiveActions":0,"falseDefensiveActions":0,"validity":{"version":1,"kind":"negative-control",` +
		`"status":"valid","oracleObserved":true,"costObserved":true,"scored":false,"baseline":{},` +
		`"cleanup":{"complete":true}}}`
)

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
	md := renderDeep(t, deepValidRow, deepNegControl)
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
	for _, tc := range []struct{ name, line string }{
		{"invalid-status", strings.Replace(deepValidRow, `"status":"valid"`, `"status":"invalid"`, 1)},
		{"future-version", strings.Replace(deepValidRow, `"version":1`, `"version":999`, 1)},
		{"cleanup-unresolved", strings.Replace(deepValidRow, `"cleanup":{"complete":true}`, `"cleanup":{"complete":false,"unresolved":true}`, 1)},
		{"control-not-usable", strings.Replace(deepValidRow, `"usable":true`, `"usable":false`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			md := renderDeep(t, tc.line, deepNegControl)
			if !strings.Contains(md, "1 attack row(s) REFUSED") {
				t.Errorf("refusal not disclosed:\n%s", md)
			}
		})
	}
}

// An UNOBSERVED cost never enters a cost mean.
func TestP3DeepUnknownCostIsExcludedFromCostMeans(t *testing.T) {
	unknownCost := strings.NewReplacer(
		`"defensiveActions":2`, `"defensiveActions":-1`,
		`"costObserved":true`, `"costObserved":false`,
	).Replace(deepValidRow)
	md := renderDeep(t, unknownCost, deepNegControl)
	if !strings.Contains(md, "1 row(s) with an UNOBSERVED defensive cost excluded") {
		t.Errorf("unobserved cost not excluded/disclosed:\n%s", md)
	}
}

// A partially observed negative control is never presented as a clean arm.
func TestP3DeepPartialNegativeControlIsDisclosed(t *testing.T) {
	unobservedNeg := strings.NewReplacer(
		`"trial":1`, `"trial":2`,
		`"defensiveActions":0,"falseDefensiveActions":0`, `"defensiveActions":-1,"falseDefensiveActions":-1`,
		`"costObserved":true`, `"costObserved":false`,
	).Replace(deepNegControl)
	md := renderDeep(t, deepValidRow, deepNegControl, unobservedNeg)
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
