package report

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

const claimsScenarioPrefix = "post25-claims-"

type claimsScenario struct {
	name    string
	realism core.ScenarioRealism
	benign  bool
}

func (s *claimsScenario) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name: s.name, Category: core.CategoryClassicChain, R6ResponseTag: core.R6Partial,
		Realism: s.realism, BenignControl: s.benign,
		Mechanism: "registered producer fixture", ClaimLimits: "offline reporting boundary only",
	}
}
func (*claimsScenario) Setup(context.Context, *core.Env) error { return nil }
func (*claimsScenario) Execute(_ context.Context, env *core.Env) (core.AttackResult, error) {
	env.Log.Command("claims-producer " + env.ScenarioName)
	return core.AttackResult{Stages: []string{"produced"}, Commands: env.Log.Commands()}, nil
}
func (*claimsScenario) SuccessOracle(_ context.Context, env *core.Env) (core.OracleResult, error) {
	return core.OracleResult{
		Achieved: env.DefenderName == "d-v161-nomtd", ObservedState: "producer-observed-" + env.ScenarioName,
		Evidence: map[string]string{"producer": env.ScenarioName},
	}, nil
}
func (*claimsScenario) Teardown(context.Context, *core.Env) error { return nil }

func init() {
	for _, s := range []claimsScenario{
		{name: claimsScenarioPrefix + "positive", realism: core.RealismExecutable},
		{name: claimsScenarioPrefix + "empty"},
		{name: claimsScenarioPrefix + "unassessed", realism: core.RealismUnassessed},
		{name: claimsScenarioPrefix + "unknown", realism: core.ScenarioRealism("future-unknown")},
		{name: claimsScenarioPrefix + "marker", realism: core.RealismMarkerSimulation},
		{name: claimsScenarioPrefix + "benign", realism: core.RealismExecutable, benign: true},
	} {
		s := s
		core.RegisterScenario(&s)
	}
}

func TestAssessedClaimsBoundaryThroughRunnerWriterReaderAndReports(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.jsonl")
	mw, err := core.NewMetricWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	filter := map[string]bool{}
	for _, suffix := range []string{"positive", "empty", "unassessed", "unknown", "marker", "benign"} {
		filter[claimsScenarioPrefix+suffix] = true
	}
	runner := core.NewRunner(core.RunnerOptions{
		TrialsPerArm: 1, OutDir: dir, ScenarioFilter: filter,
		DefenderFilter: map[string]bool{"d-v161-nomtd": true, "d-v161-arm": true},
	}, func(scenario, defender string, trial int, _ int64, raw string) (*core.Env, func() error, error) {
		return &core.Env{
			Log: &claimsLogger{raw: raw}, Trial: trial, ScenarioName: scenario, DefenderName: defender,
			Config: config.WithDollarDefaults(config.TargetConfig{}),
		}, func() error { return nil }, nil
	}, mw, nil)
	if _, err := runner.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(original), []byte("\n"))
	if len(lines) != 12 {
		t.Fatalf("runner wrote %d rows, want 12", len(lines))
	}
	reversedPath := filepath.Join(dir, "reversed.jsonl")
	if err := os.WriteFile(reversedPath, reverseJSONL(original), 0o600); err != nil {
		t.Fatal(err)
	}
	absent := bytes.ReplaceAll(original, []byte(`,"scenarioRealism":"unassessed"`), nil)
	if bytes.Equal(absent, original) {
		t.Fatal("fixture did not contain the producer's effective unassessed classification")
	}
	absentPath := filepath.Join(dir, "absent-field.jsonl")
	if err := os.WriteFile(absentPath, absent, 0o600); err != nil {
		t.Fatal(err)
	}
	absentReversedPath := filepath.Join(dir, "absent-field-reversed.jsonl")
	if err := os.WriteFile(absentReversedPath, reverseJSONL(absent), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, input := range []string{path, reversedPath, absentPath, absentReversedPath} {
		t.Run(filepath.Base(input), func(t *testing.T) {
			read, err := ReadMetricsJSONL(input)
			if err != nil {
				t.Fatal(err)
			}
			assertProducedClaimsBoundary(t, read)
		})
	}
}

func reverseJSONL(raw []byte) []byte {
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
		lines[i], lines[j] = lines[j], lines[i]
	}
	return append(bytes.Join(lines, []byte("\n")), '\n')
}

func assertProducedClaimsBoundary(t *testing.T, rows []core.Metric) {
	t.Helper()
	if len(rows) != 12 {
		t.Fatalf("decoded %d rows, want 12", len(rows))
	}
	eligible := ExcludeNonAttackControls(rows)
	if len(eligible) != 2 {
		t.Fatalf("eligible attack rows=%d, want the two positive-arm rows: %+v", len(eligible), eligible)
	}
	for _, m := range eligible {
		if m.Scenario != claimsScenarioPrefix+"positive" || m.ScenarioRealism != core.RealismExecutable || m.ScenarioBenignControl {
			t.Fatalf("ineligible row crossed shared claim boundary: %+v", m)
		}
	}
	for _, m := range rows {
		if m.Commands == nil || m.ObservedState == "" || m.RawLogPath == "" || m.ScenarioMechanism == "" || m.ScenarioClaimLimits == "" {
			t.Fatalf("raw producer evidence was not preserved: %+v", m)
		}
	}

	economics := recomputeEconomics(rows, DollarInputs{BaselineDefender: "d-v161-nomtd"})
	economic, excluded := 0, 0
	for _, row := range economics {
		if row.Economics {
			economic++
			if row.Scenario != claimsScenarioPrefix+"positive" {
				t.Fatalf("excluded scenario received economics: %+v", row)
			}
		} else {
			excluded++
		}
	}
	if economic != 2 || excluded != 10 {
		t.Fatalf("economics census = %d eligible / %d excluded, want 2 / 10: %+v", economic, excluded, economics)
	}

	main := RenderMarkdown(rows, 0.95, nil)
	for _, want := range []string{
		"assessed executable attacks", "Unassessed or unsupported mechanism observations",
		"future-unknown", "marker-simulation", "Benign functional-effect controls",
		"mechanismExcluded=1", "realismExcluded=1", "benignControlExcluded=1",
		"producer-observed-" + claimsScenarioPrefix + "unknown",
	} {
		if !strings.Contains(main, want) {
			t.Errorf("main report missing %q:\n%s", want, main)
		}
	}
	grounding := strings.Split(main, "## Honest R6 grounding")
	if len(grounding) != 2 || !strings.Contains(grounding[1], "**"+claimsScenarioPrefix+"positive**") {
		t.Fatalf("assessed grounding missing:\n%s", main)
	}
	for _, excludedName := range []string{"empty", "unassessed", "unknown", "marker", "benign"} {
		if strings.Contains(grounding[1], "**"+claimsScenarioPrefix+excludedName+"**") {
			t.Fatalf("excluded scenario %s entered assessed grounding:\n%s", excludedName, grounding[1])
		}
	}
	dollars := RenderDollars(rows, DollarInputs{BaselineDefender: "d-v161-nomtd"}, 0.95)
	for _, scenario := range []string{"empty", "unassessed", "unknown", "marker", "benign"} {
		if !strings.Contains(dollars, "| "+claimsScenarioPrefix+scenario+" | d-v161-arm |") {
			t.Errorf("dollars report dropped excluded %s observation", scenario)
		}
	}
	if !strings.Contains(dollars, "| "+claimsScenarioPrefix+"positive | d-v161-arm | executable-mechanism | 1 | 100% |") ||
		!strings.Contains(dollars, "| "+claimsScenarioPrefix+"positive | d-v161-nomtd | executable-mechanism | 1 | 0% |") {
		t.Errorf("positive assessed rows missing from economics:\n%s", dollars)
	}

	pm := BuildProvenance(rows, 1, 1, "ctx", "ns", "metrics.jsonl", "cmd", nil)
	if len(pm.Entries) != len(rows) {
		t.Fatalf("provenance dropped rows: got %d want %d", len(pm.Entries), len(rows))
	}
	for _, entry := range pm.Entries {
		if entry.ScenarioRealism == "" {
			t.Fatalf("provenance lost effective mechanism classification: %+v", entry)
		}
	}
}

func TestExcludedBaselineCannotAnchorAssessedReplayEconomics(t *testing.T) {
	baseline := scoredRow("same-scenario", "d-nomtd", 0, 0, true, 0)
	baseline.Reuse = &core.ReuseMetric{ReplaySuccessCount: 10, ReplayAttempts: 10}
	arm := scoredRow("same-scenario", "d-r6blindtimer", 0, 1, false, 1)
	arm.Reuse = &core.ReuseMetric{ReplaySuccessCount: 1, ReplayAttempts: 10}

	for _, realism := range []core.ScenarioRealism{"", core.RealismUnassessed, core.ScenarioRealism("future-unknown"), core.RealismMarkerSimulation} {
		t.Run(string(realism), func(t *testing.T) {
			excludedBaseline := baseline
			excludedBaseline.ScenarioRealism = realism
			excludedBaseline.Reuse = &core.ReuseMetric{ReplaySuccessCount: 99, ReplayAttempts: 100}
			costUnobservedBaseline := baseline
			costValidity := *baseline.Validity
			costUnobservedBaseline.Validity = &costValidity
			costUnobservedBaseline.Validity.CostObserved = false
			costUnobservedBaseline.DefensiveActions = -1
			costUnobservedBaseline.Reuse = &core.ReuseMetric{ReplaySuccessCount: 77, ReplayAttempts: 100}
			for _, metrics := range [][]core.Metric{
				{excludedBaseline, costUnobservedBaseline, baseline, arm},
				{arm, baseline, costUnobservedBaseline, excludedBaseline},
			} {
				rows := recomputeEconomics(metrics, DollarInputs{
					BaselineDefender: "d-nomtd", RotationIntervals: DefaultRotationIntervals(),
				})
				for _, row := range rows {
					if row.Defender == arm.Defender && row.Economics && row.Reuse.StaticBaselineReplaySuccess != 10 {
						t.Fatalf("excluded baseline leaked into replay anchor: %+v", row)
					}
				}
			}
			withoutEligibleBaseline := recomputeEconomics([]core.Metric{excludedBaseline, costUnobservedBaseline, arm}, DollarInputs{BaselineDefender: "d-nomtd"})
			for _, row := range withoutEligibleBaseline {
				if row.Defender == arm.Defender && row.Economics && row.Reuse.StaticBaselineReplaySuccess != 0 {
					t.Fatalf("excluded-only baseline created a replay anchor: %+v", row)
				}
			}
		})
	}
}

func TestUnassessedRowsCannotAffectHypothesesOrMTDEffect(t *testing.T) {
	baseline := scoredRow("assessed", "d-nomtd", 0, 0, true, 0)
	baseline.Reuse = &core.ReuseMetric{ReplaySuccessCount: 10, ReplayAttempts: 10}
	assessed := scoredRow("assessed", "d-r6blindtimer", 0, 1, false, 1)
	assessed.Reuse = &core.ReuseMetric{ReplaySuccessCount: 2, ReplayAttempts: 10}
	assessed.SplitOracle = core.SplitPersistence
	assessed.MTDEffect = core.MTDNeutralizes

	excluded := scoredRow("unassessed-hypothesis", "d-r6blindtimer", 0, 0, true, 1)
	excluded.ScenarioRealism = core.ScenarioRealism("future-unknown")
	excluded.Reuse = &core.ReuseMetric{ReplaySuccessCount: 10, ReplayAttempts: 10}
	excluded.SplitOracle = core.SplitPersistence
	excluded.MTDEffect = core.MTDNeutralizes
	excluded.TriggerAttribution = core.TriggerHarnessInjected
	unanchored := scoredRow("unanchored-observation", "d-fullphoenix", 0, 0, true, 1)
	unanchored.SplitOracle = core.SplitPersistence
	unanchored.MTDEffect = core.MTDNeutralizes
	unanchored.Validity.Scored = false
	unanchored.Validity.Baseline.Usable = false
	unanchored.Validity.Baseline.Observed = false
	unanchored.Validity.UnscoredReason = "positive control unavailable"
	unanchored.DisruptionVsOracle = 0
	unanchored.SecurityPerCost = 0

	for _, metrics := range [][]core.Metric{{baseline, assessed, excluded, unanchored}, {unanchored, excluded, assessed, baseline}} {
		dollars := RenderDollars(metrics, DollarInputs{BaselineDefender: "d-nomtd", RotationIntervals: DefaultRotationIntervals()}, 0.95)
		if !strings.Contains(dollars, "mean persistence-disruption = 100%") || !strings.Contains(dollars, "over 1 scored arm(s)") {
			t.Fatalf("assessed hypothesis input was lost or excluded input changed its denominator:\n%s", dollars)
		}
		main := RenderMarkdown(metrics, 0.95, nil)
		parts := strings.Split(main, "## AI split-oracle & MEASURED MTD-effect")
		if len(parts) != 2 {
			t.Fatalf("measured MTD-effect section missing:\n%s", main)
		}
		mtdSection := strings.Split(parts[1], "\n## ")[0]
		if !strings.Contains(mtdSection, "| assessed | d-r6blindtimer |") || strings.Contains(mtdSection, "unassessed-hypothesis") || strings.Contains(mtdSection, "unanchored-observation") {
			t.Fatalf("unassessed row entered measured MTD-effect section:\n%s", main)
		}
		if !strings.Contains(main, "**unanchored-observation**") || !strings.Contains(main, "positive control unavailable") {
			t.Fatalf("valid but unscored MTD observation was not retained as raw grounding/validity:\n%s", main)
		}
	}
}

func TestClaimExclusionPreservesRawValidityAccounting(t *testing.T) {
	invalid := notMeasuredRow("unknown-invalid", "d-arm", 0, core.MeasurementInvalid, "oracle unavailable")
	invalid.ScenarioRealism = core.ScenarioRealism("future-unknown")
	invalid.Validity.Cleanup = core.CleanupRecord{Attempted: []core.CleanupStep{{Step: "scenario.Teardown", Error: "delete failed"}}}
	invalid.TriggerAttribution = core.TriggerReceiverOnly
	invalid.CapabilityPending = true
	invalid.CapabilityNote = "capability still pending"
	legacy := legacyRow("absent-legacy", "d-arm", 0, 1, false)
	legacy.ScenarioRealism = ""
	marker := notMeasuredRow("marker-invalid", "d-arm", 0, core.MeasurementInvalid, "marker unavailable")
	marker.ScenarioRealism = core.RealismMarkerSimulation
	benign := scoredRow("benign-cost", "d-arm", 0, 1, false, -1)
	benign.ScenarioBenignControl = true
	benign.Validity.CostObserved = false
	benign.SecurityPerCost = 0
	negObserved := negControlRow("unknown-invalid", "d-arm", 1, 0, true)
	negObserved.ScenarioRealism = core.ScenarioRealism("future-unknown")
	negUnobserved := negControlRow("unknown-invalid", "d-arm", 2, 0, false)
	negUnobserved.ScenarioRealism = core.ScenarioRealism("future-unknown")
	metrics := []core.Metric{invalid, legacy, marker, benign, negObserved, negUnobserved}

	for _, summary := range Aggregate(metrics, 0.95) {
		switch summary.Scenario {
		case "unknown-invalid":
			if summary.Validity.MechanismExcluded != 1 || summary.Validity.Invalid != 1 || summary.Validity.CleanupFailed != 1 || summary.Validity.CostUnobserved != 1 {
				t.Fatalf("invalid exclusion lost raw validity accounting: %+v", summary.Validity)
			}
			if summary.NegativeControl != NegControlPartial || summary.NegControlTotal != 2 || summary.NegControlUsable != 1 || summary.NegControlUnusable != 1 {
				t.Fatalf("excluded scenario lost negative-control census: %+v", summary)
			}
		case "absent-legacy":
			if summary.Validity.MechanismExcluded != 1 || summary.Validity.Legacy != 1 {
				t.Fatalf("legacy exclusion lost raw validity accounting: %+v", summary.Validity)
			}
		case "marker-invalid":
			if summary.Validity.RealismExcluded != 1 || summary.Validity.Invalid != 1 || summary.Trials != 0 {
				t.Fatalf("marker exclusion lost invalid accounting: %+v", summary)
			}
		case "benign-cost":
			if summary.Validity.BenignControlExcluded != 1 || summary.Validity.CostUnobserved != 1 || summary.Trials != 0 {
				t.Fatalf("benign exclusion lost cost accounting: %+v", summary)
			}
		}
	}
	for _, row := range recomputeEconomics(metrics, DollarInputs{}) {
		if row.Economics {
			t.Fatalf("excluded validity row received economics or disappeared: %+v", row)
		}
		if row.Scenario == "unknown-invalid" && (row.Validity.Invalid != 1 || row.Validity.CleanupFailed != 1 || row.Validity.CostUnobserved != 1) {
			t.Fatalf("economics view lost invalid row accounting: %+v", row.Validity)
		}
		if row.Scenario == "absent-legacy" && row.Validity.Legacy != 1 {
			t.Fatalf("economics view lost legacy row accounting: %+v", row.Validity)
		}
	}
	for _, rendered := range []string{RenderMarkdown(metrics, 0.95, nil), RenderDollars(metrics, DollarInputs{}, 0.95)} {
		for _, want := range []string{"invalid=1", "legacy=1", "cleanupFailed=1", "costUnobserved=1", "negControl=partial(1/2 observed)", "mechanismExcluded=1", "realismExcluded=1", "benignControlExcluded=1", core.TriggerReceiverOnly, "capability still pending"} {
			if !strings.Contains(rendered, want) {
				t.Fatalf("excluded raw validity disclosure missing %q:\n%s", want, rendered)
			}
		}
	}
}

func TestObservationTableEscapesUntrustedCells(t *testing.T) {
	m := scoredRow("unassessed", "d-arm", 0, 1, false, 1)
	m.ScenarioRealism = core.RealismUnassessed
	m.ObservedState = "state|part\nnext"
	m.TriggerAttribution = "trigger|part\nnext"
	m.CapabilityPending = true
	m.CapabilityNote = "cap|part\nnext"
	m.ScenarioClaimLimits = "limit|part\r\nnext"
	m.RawLogPath = "raw|path\nnext"
	got := RenderMarkdown([]core.Metric{m}, 0.95, nil)
	for _, want := range []string{`state\|part<br>next`, `trigger\|part<br>next`, `true: cap\|part<br>next`, `limit\|part<br>next`, `raw\|path<br>next`} {
		if !strings.Contains(got, want) {
			t.Fatalf("observation table did not escape %q:\n%s", want, got)
		}
	}
	dollars := RenderDollars([]core.Metric{m}, DollarInputs{}, 0.95)
	if !strings.Contains(dollars, `trigger\|part<br>next`) {
		t.Fatalf("dollars trigger cell was not escaped:\n%s", dollars)
	}
}

func TestExcludedAdaptiveAndAnchorRowsRemainRawWithoutPercentages(t *testing.T) {
	adaptive := scoredRow("adaptive-unassessed", "d-arm", 2, 1, false, 1)
	adaptive.ScenarioRealism = core.RealismUnassessed
	adaptive.Validity.Kind = core.TrialAdaptive
	adaptive.Validity.Baseline.Kind = core.TrialAdaptive
	adaptive.ObservedState = "adaptive raw observation"
	anchor := scoredRow("anchor-marker", "d-nomtd", 0, 0, true, 0)
	anchor.ScenarioRealism = core.RealismMarkerSimulation
	anchor.AnchorOnly = true
	anchor.ObservedState = "anchor raw observation"
	benignAdaptive := adaptive
	benignAdaptive.Scenario = "adaptive-benign"
	benignAdaptive.ScenarioRealism = core.RealismExecutable
	benignAdaptive.ScenarioBenignControl = true
	benignAdaptive.ObservedState = "benign adaptive raw observation"

	report := RenderMarkdown([]core.Metric{adaptive, anchor, benignAdaptive}, 0.95, nil)
	for _, observed := range []string{"adaptive raw observation", "anchor raw observation", "benign adaptive raw observation"} {
		if !strings.Contains(report, observed) {
			t.Fatalf("excluded adaptive/anchor raw observation %q missing:\n%s", observed, report)
		}
	}
	for _, heading := range []string{"## Unassessed adaptive observations", "## Additional marker-simulation control/adaptive observations", "## Benign functional-effect adaptive observations"} {
		start := strings.Index(report, heading)
		if start < 0 {
			t.Fatalf("missing excluded section %q:\n%s", heading, report)
		}
		rest := report[start+len(heading):]
		end := strings.Index(rest, "\n## ")
		if end >= 0 {
			rest = rest[:end]
		}
		if strings.Contains(rest, "Disruption%") || strings.Contains(rest, "OracleHit%") {
			t.Fatalf("excluded section %q rendered an aggregate percentage:\n%s", heading, rest)
		}
	}
}

type claimsLogger struct {
	raw      string
	commands []string
}

func (*claimsLogger) Logf(string, ...any) {}
func (l *claimsLogger) Command(c string)  { l.commands = append(l.commands, c) }
func (l *claimsLogger) Commands() []string {
	return append([]string(nil), l.commands...)
}
func (l *claimsLogger) RawLogPath() string { return l.raw }
