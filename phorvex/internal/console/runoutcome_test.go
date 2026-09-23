package console

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phorvex/metricvalidity"
)

func validRunClaim(scored, oracle bool) *metricvalidity.Validity {
	return &metricvalidity.Validity{
		Version:         metricvalidity.Version,
		Kind:            metricvalidity.TrialOrdinary,
		Status:          metricvalidity.StatusValid,
		Phase:           metricvalidity.PhaseComplete,
		AttackExecuted:  true,
		OracleObserved:  true,
		ObserverPresent: true,
		CostObserved:    true,
		Scored:          scored,
		Baseline: metricvalidity.BaselineRef{
			Required: scored, Defender: "d-nomtd", Trial: 0, Kind: metricvalidity.TrialOrdinary,
			Observed: scored, Valid: scored, OracleAchieved: oracle || scored, Usable: scored,
		},
		Cleanup: metricvalidity.CleanupRecord{Complete: true, Verified: true},
	}
}

func benignRunRow(achieved bool) runMetricRow {
	claim := validRunClaim(false, achieved)
	claim.UnscoredReason = "benign functional-effect control is excluded from attack, security and economics scoring"
	return runMetricRow{
		Scenario: "benign", Defender: "d-nomtd", Trial: 0,
		OracleAchieved: achieved, DefensiveActions: 0, FalseDefensiveActions: -1,
		Validity: claim, ScenarioRealism: "executable-mechanism", ScenarioBenignControl: true,
		BenchmarkEvidence: map[string]string{"oracleStatus": "complete"},
	}
}

func TestRunOutcomeConservativeClassification(t *testing.T) {
	pass := benignRunRow(true)
	fail := benignRunRow(false)
	incomplete := benignRunRow(true)
	incomplete.BenchmarkEvidence["oracleStatus"] = "incomplete"
	conflict := benignRunRow(true)
	conflict.BenchmarkEvidence["oracle.status"] = "not-observed"
	unverifiedCleanup := benignRunRow(true)
	unverifiedCleanup.Validity.Cleanup.Verified = false
	legacy := benignRunRow(true)
	legacy.Validity = nil
	scoredBenign := benignRunRow(true)
	scoredBenign.Validity = validRunClaim(true, true)
	scoredBenign.DisruptionVsOracle = 0
	skippedScored := runMetricRow{Scenario: "attack", Defender: "d-phorvex", Trial: 0, OracleAchieved: true, Skipped: true, ScenarioRealism: "executable-mechanism", Validity: validRunClaim(true, true)}
	nonExecutableScored := runMetricRow{Scenario: "attack", Defender: "d-phorvex", Trial: 0, OracleAchieved: true, ScenarioRealism: "marker-simulation", Validity: validRunClaim(true, true)}
	missingScenario := runMetricRow{Defender: "d-phorvex", Trial: 0, OracleAchieved: true, ScenarioRealism: "executable-mechanism", Validity: validRunClaim(true, true)}
	missingDefender := runMetricRow{Scenario: "attack", Trial: 0, OracleAchieved: true, ScenarioRealism: "executable-mechanism", Validity: validRunClaim(true, true)}
	disrupted := runMetricRow{Scenario: "attack", Defender: "d-phorvex", Trial: 0, DisruptionVsOracle: 1, ScenarioRealism: "executable-mechanism", Validity: validRunClaim(true, false)}
	landed := runMetricRow{Scenario: "attack", Defender: "d-phorvex", Trial: 0, OracleAchieved: true, ScenarioRealism: "executable-mechanism", Validity: validRunClaim(true, true)}

	for _, tc := range []struct {
		name string
		row  runMetricRow
		want string
	}{
		{"benign pass", pass, outcomeFunctionalPass},
		{"benign fail", fail, outcomeFunctionalFail},
		{"incomplete benign oracle", incomplete, outcomeInconclusive},
		{"conflicting oracle aliases", conflict, outcomeUnverified},
		{"cleanup absence unverified", unverifiedCleanup, outcomeInconclusive},
		{"missing validity", legacy, outcomeUnverified},
		{"benign scored contradiction", scoredBenign, outcomeUnverified},
		{"skipped scored contradiction", skippedScored, outcomeUnverified},
		{"non-executable scored contradiction", nonExecutableScored, outcomeUnverified},
		{"missing scenario identity", missingScenario, outcomeUnverified},
		{"missing defender identity", missingDefender, outcomeUnverified},
		{"scored disruption", disrupted, outcomeSecurityDisrupted},
		{"scored landed", landed, outcomeSecurityLanded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.row.outcome()
			if got.Outcome != tc.want {
				t.Fatalf("outcome=%q reason=%q want=%q", got.Outcome, got.OutcomeReason, tc.want)
			}
		})
	}
}

func TestRunEvidenceAndStreamRejectMissingIdentity(t *testing.T) {
	for _, row := range []runMetricRow{
		{Defender: "d-phorvex", ScenarioRealism: "executable-mechanism", Validity: validRunClaim(true, true), OracleAchieved: true},
		{Scenario: "attack", ScenarioRealism: "executable-mechanism", Validity: validRunClaim(true, true), OracleAchieved: true},
	} {
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		cfg := Config{StateDir: dir}
		out := cfg.runOutputPath("out-identity")
		if err := os.MkdirAll(out, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "metrics.jsonl"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		rm := &RunManager{cfg: cfg, runs: map[string]*RunStatus{"r": {ID: "r"}}, runOut: map[string]string{"r": "out-identity"}}
		arms, trials, issues, _, ok := rm.RunEvidence("r")
		if !ok || len(arms) != 0 || len(trials) != 1 || len(issues) != 0 || trials[0].Outcome != outcomeUnverified {
			t.Fatalf("reader identity result: arms=%+v trials=%+v issues=%+v ok=%v", arms, trials, issues, ok)
		}
		event := trialEventFromRow(row)
		if event.Outcome != trials[0].Outcome || event.OutcomeReason != trials[0].OutcomeReason {
			t.Fatalf("stream parity: event=%+v trial=%+v", event, trials[0])
		}
	}
}

func TestRunOutcomeRetainedProducerRowsAndStreamParity(t *testing.T) {
	base := filepath.Join("..", "..", "..", "build", "test-harness", "internal", "cataloguecollector", "testdata")
	rows := []struct {
		name string
		path string
		want string
	}{
		{"round57 historical scored benign", filepath.Join(base, "round57-restart", "metrics.raw.jsonl"), outcomeUnverified},
		{"round69 valid benign", filepath.Join(base, "round69-quorum", "metrics.raw.jsonl"), outcomeFunctionalPass},
		{"v11 invalid GPU", filepath.Join("testdata", "v11-invalid-metric.json"), outcomeTestFailed},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			var row runMetricRow
			if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &row); err != nil {
				t.Fatal(err)
			}
			outcome := row.outcome()
			if outcome.Outcome != tc.want {
				t.Fatalf("persisted outcome=%q reason=%q want=%q", outcome.Outcome, outcome.OutcomeReason, tc.want)
			}
			event := trialEventFromRow(row)
			if event.Outcome != outcome.Outcome || event.OutcomeReason != outcome.OutcomeReason || event.MeasurementPhase != outcome.MeasurementPhase {
				t.Fatalf("stream differs: event=%+v outcome=%+v", event, outcome)
			}
			if tc.want == outcomeTestFailed && (event.MeasurementPhase != "attack-execute" || !strings.Contains(event.OutcomeReason, "late-selected drain anchor")) {
				t.Fatalf("invalid producer cause lost: %+v", event)
			}
			dir := t.TempDir()
			cfg := Config{StateDir: dir}
			out := cfg.runOutputPath("out-retained")
			if err := os.MkdirAll(out, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, "metrics.jsonl"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			rm := &RunManager{cfg: cfg, runs: map[string]*RunStatus{"r": {ID: "r"}}, runOut: map[string]string{"r": "out-retained"}}
			arms, trials, issues, _, ok := rm.RunEvidence("r")
			if !ok || len(arms) != 0 || len(trials) != 1 || len(issues) != 0 || trials[0].Outcome != tc.want {
				t.Fatalf("actual reader: arms=%+v trials=%+v issues=%+v ok=%v", arms, trials, issues, ok)
			}
		})
	}
}

func TestRunEvidenceAggregatesOnlyValidatedSecurityRows(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: dir}
	out := cfg.runOutputPath("out-outcomes")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	benign := benignRunRow(true)
	benign.Scenario = "functional"
	attack := runMetricRow{Scenario: "attack", Defender: "d-phorvex", Trial: 0, OracleAchieved: true, ScenarioRealism: "executable-mechanism", Validity: validRunClaim(true, true)}
	invalid := benignRunRow(false)
	invalid.Scenario = "invalid"
	invalid.Validity.Status = metricvalidity.StatusInvalid
	invalid.Validity.Phase = metricvalidity.PhaseAttackExecute
	invalid.Validity.Reasons = []string{"attack-execute: producer failed"}
	invalid.Skipped = true
	var lines []byte
	for _, row := range []runMetricRow{benign, attack, invalid} {
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, append(raw, '\n')...)
	}
	if err := os.WriteFile(filepath.Join(out, "metrics.jsonl"), lines, 0o600); err != nil {
		t.Fatal(err)
	}
	rm := &RunManager{cfg: cfg, runs: map[string]*RunStatus{"r": {ID: "r", State: "done"}}, runOut: map[string]string{"r": "out-outcomes"}}
	arms, trials, issues, _, ok := rm.RunEvidence("r")
	if !ok || len(trials) != 3 || len(arms) != 1 || arms[0].Trials != 1 || len(issues) != 0 {
		t.Fatalf("arms=%+v trials=%+v issues=%+v ok=%v", arms, trials, issues, ok)
	}
	got := map[string]string{}
	for _, trial := range trials {
		got[trial.Scenario] = trial.Outcome
	}
	if got["functional"] != outcomeFunctionalPass || got["attack"] != outcomeSecurityLanded || got["invalid"] != outcomeTestFailed {
		t.Fatalf("typed trials=%+v", trials)
	}
}

func TestRunEvidenceRetainsMalformedRowAsUnverifiedIssue(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: dir}
	out := cfg.runOutputPath("out-malformed")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "metrics.jsonl"), []byte("{\"scenario\":\"known\",\"validity\":{bad}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rm := &RunManager{cfg: cfg, runs: map[string]*RunStatus{"r": {ID: "r"}}, runOut: map[string]string{"r": "out-malformed"}}
	arms, trials, issues, _, ok := rm.RunEvidence("r")
	if !ok || len(arms) != 0 || len(trials) != 0 || len(issues) != 1 || issues[0].Outcome != outcomeUnverified || issues[0].Line != 1 {
		t.Fatalf("arms=%+v trials=%+v issues=%+v ok=%v", arms, trials, issues, ok)
	}
}

func TestRunStatusSummaryExcludesBenignAndConflictingMetadata(t *testing.T) {
	claimAt := func(trial int) *metricvalidity.Validity {
		claim := validRunClaim(true, true)
		claim.Baseline.Trial = trial
		return claim
	}
	rows := []metricRow{
		{Scenario: "attack", Defender: "d-phorvex", Trial: 0, OracleAchieved: true, ScenarioRealism: "executable-mechanism", Validity: claimAt(0)},
		{Scenario: "benign", Defender: "d-phorvex", Trial: 1, OracleAchieved: true, ScenarioRealism: "executable-mechanism", ScenarioBenignControl: true, Validity: claimAt(1)},
		{Scenario: "simulated", Defender: "d-phorvex", Trial: 2, OracleAchieved: true, ScenarioRealism: "marker-simulation", Validity: claimAt(2)},
		{Scenario: "skipped", Defender: "d-phorvex", Trial: 3, OracleAchieved: true, Skipped: true, ScenarioRealism: "executable-mechanism", Validity: claimAt(3)},
	}
	arms, total := summarizeArms(rows)
	if total != 1 || len(arms) != 1 || arms[0].Trials != 1 {
		t.Fatalf("security summary accepted conflicting metadata: total=%d arms=%+v", total, arms)
	}
}
