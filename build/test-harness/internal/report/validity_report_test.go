package report

// validity_report_test.go — PERMANENT regressions for the honest downstream
// reporting of the measurement-validity contract (V3-M161).
//
// TestValidityEndToEnd... drives the REAL chain: core.Runner.Run -> the real
// core.MetricWriter -> the real JSONL reader -> the real Aggregate/Render. The
// remaining cases exercise the report layer directly over metric streams whose
// validity blocks are stamped explicitly, which is how a stream read back from
// a metrics file reaches this package.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

// ------------------------------------------------------------ stream helpers

func validity(kind core.TrialKind, status core.MeasurementStatus) *core.MeasurementValidity {
	return &core.MeasurementValidity{
		Version: core.MeasurementValidityVersion,
		Kind:    kind,
		Status:  status,
		Phase:   core.PhaseComplete,
		Cleanup: core.CleanupRecord{Complete: true},
	}
}

// scoredRow is a fully valid, anchored, cost-observed measurement.
func scoredRow(scn, def string, trial int, disruption float64, achieved bool, actions int) core.Metric {
	v := validity(core.TrialOrdinary, core.MeasurementValid)
	v.AttackExecuted, v.OracleObserved, v.ObserverPresent, v.CostObserved, v.Scored = true, true, true, true, true
	v.Baseline = core.BaselineRef{Required: true, Defender: "d-nomtd", Kind: core.TrialOrdinary,
		Trial: trial, Observed: true, Valid: true, OracleAchieved: true, Usable: true}
	return core.Metric{
		Scenario: scn, Defender: def, Trial: trial, Validity: v,
		Category: core.CategoryClassicChain, R6Tag: core.R6Partial,
		ScenarioRealism: core.RealismExecutable,
		OracleAchieved:  achieved, DisruptionVsOracle: disruption,
		DefensiveActions: actions, FalseDefensiveActions: -1,
		SecurityPerCost: disruption, EvidenceRetention: 1, ObservedState: "measured",
		TimeToActionSeconds: 1,
	}
}

// notMeasuredRow is an invalid or skipped row: every scoring field stays zero.
func notMeasuredRow(scn, def string, trial int, status core.MeasurementStatus, reason string) core.Metric {
	v := validity(core.TrialOrdinary, status)
	v.Reasons = []string{"oracle: " + reason}
	v.UnscoredReason = reason
	return core.Metric{
		Scenario: scn, Defender: def, Trial: trial, Validity: v,
		Category: core.CategoryClassicChain, R6Tag: core.R6Partial,
		ScenarioRealism: core.RealismExecutable,
		Skipped:         true, SkipReason: reason, DefensiveActions: -1, FalseDefensiveActions: -1,
	}
}

// legacyRow is a pre-contract row: no validity block at all.
func legacyRow(scn, def string, trial int, disruption float64, achieved bool) core.Metric {
	return core.Metric{
		Scenario: scn, Defender: def, Trial: trial,
		Category: core.CategoryClassicChain, R6Tag: core.R6Partial,
		ScenarioRealism: core.RealismExecutable,
		OracleAchieved:  achieved, DisruptionVsOracle: disruption,
		EvidenceRetention: 1, FalseDefensiveActions: -1,
	}
}

func negControlRow(scn, def string, trial int, falseMoves int, costObserved bool) core.Metric {
	v := validity(core.TrialNegativeControl, core.MeasurementValid)
	v.AttackExecuted, v.OracleObserved, v.ObserverPresent = true, true, true
	v.CostObserved = costObserved
	m := core.Metric{
		Scenario: scn, Defender: def, Trial: trial, Validity: v,
		Category: core.CategoryClassicChain, R6Tag: core.R6Partial,
		ScenarioRealism: core.RealismExecutable,
		NegativeControl: true, FalseDefensiveActions: -1, DefensiveActions: -1,
	}
	if costObserved {
		m.FalseDefensiveActions = falseMoves
		m.DefensiveActions = falseMoves
		m.EvidenceRetention = 1
	}
	return m
}

func armByDefender(t *testing.T, sums []ArmSummary, def string) ArmSummary {
	t.Helper()
	for _, s := range sums {
		if s.Defender == def {
			return s
		}
	}
	t.Fatalf("no arm summary for %q in %d summaries", def, len(sums))
	return ArmSummary{}
}

// ------------------------------------------------------------- end-to-end

type e2eLogger struct{ cmds []string }

func (l *e2eLogger) Logf(string, ...any) {}
func (l *e2eLogger) Command(c string)    { l.cmds = append(l.cmds, c) }
func (l *e2eLogger) Commands() []string  { return l.cmds }
func (l *e2eLogger) RawLogPath() string  { return "" }

// e2eScenario fails its oracle for one arm on one trial only, so a single arm
// carries BOTH a valid measurement and an invalid one.
type e2eScenario struct{}

func (s *e2eScenario) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{Name: "v161-mixed", Category: core.CategoryClassicChain, R6ResponseTag: core.R6Partial, Realism: core.RealismExecutable}
}
func (s *e2eScenario) Setup(context.Context, *core.Env) error { return nil }
func (s *e2eScenario) Execute(_ context.Context, env *core.Env) (core.AttackResult, error) {
	env.Log.Command("v161-attack")
	return core.AttackResult{Stages: []string{"staged"}}, nil
}
func (s *e2eScenario) SuccessOracle(_ context.Context, env *core.Env) (core.OracleResult, error) {
	if env.DefenderName == "d-v161-arm" {
		if env.Trial == 1 {
			return core.OracleResult{}, errors.New("oracle transport unavailable")
		}
		return core.OracleResult{Achieved: false, ObservedState: "measured", Evidence: map[string]string{"observed": "yes"}}, nil
	}
	return core.OracleResult{Achieved: true, ObservedState: "measured", Evidence: map[string]string{"observed": "yes"}}, nil
}
func (s *e2eScenario) Teardown(context.Context, *core.Env) error { return nil }

type e2eDefender struct {
	name     string
	baseline bool
	interval float64
	actions  []float64
}

func (d *e2eDefender) Metadata() core.DefenderMeta {
	return core.DefenderMeta{Name: d.name, IsNegativeControlBaseline: d.baseline, MeanRotationIntervalSeconds: d.interval}
}
func (d *e2eDefender) Setup(context.Context, *core.Env) error    { return nil }
func (d *e2eDefender) Start(context.Context, *core.Env) error    { return nil }
func (d *e2eDefender) Stop(context.Context, *core.Env) error     { return nil }
func (d *e2eDefender) Teardown(context.Context, *core.Env) error { return nil }
func (d *e2eDefender) DefensiveActions(_ context.Context, env *core.Env) (int, []float64, error) {
	if len(env.Log.Commands()) == 0 {
		return 0, nil, nil // no attack ran: a genuinely measured zero
	}
	return len(d.actions), d.actions, nil
}

func init() {
	core.RegisterScenario(&e2eScenario{})
	core.RegisterDefender(&e2eDefender{name: "d-v161-nomtd", baseline: true})
	core.RegisterDefender(&e2eDefender{name: "d-v161-arm", interval: 6, actions: []float64{1, 2}})
}

// TestValidityEndToEndMixedArmIsNeverACompleteResult drives the real runner,
// writer, reader and report: one arm with one valid and one invalid trial must
// publish one SCORED trial AND disclose the invalid one.
func TestValidityEndToEndMixedArmIsNeverACompleteResult(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.jsonl")
	mw, err := core.NewMetricWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	runner := core.NewRunner(core.RunnerOptions{
		TrialsPerArm: 2, OutDir: dir, RunNegativeControl: true,
		ScenarioFilter: map[string]bool{"v161-mixed": true},
		DefenderFilter: map[string]bool{"d-v161-nomtd": true, "d-v161-arm": true},
	}, func(scenario, defender string, trial int, _ int64, _ string) (*core.Env, func() error, error) {
		return &core.Env{Log: &e2eLogger{}, Trial: trial, ScenarioName: scenario, DefenderName: defender,
			Config: config.WithDollarDefaults(config.TargetConfig{})}, func() error { return nil }, nil
	}, mw, nil)

	if _, err := runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	outcome := runner.Outcome()
	if outcome.BaselineDefender != "d-v161-nomtd" {
		t.Fatalf("fixture relevance: the run anchored to %q, not this test's control", outcome.BaselineDefender)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	// Read the metrics back through the REAL reader.
	read, err := ReadMetricsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if read.Legacy != 0 || len(read.Undecodable) != 0 {
		t.Fatalf("freshly written metrics must be neither legacy nor undecodable: %+v", read)
	}

	sums := Aggregate(read.Metrics, 0.95)
	arm := armByDefender(t, sums, "d-v161-arm")
	if arm.Trials != 1 {
		t.Errorf("scored trials = %d, want 1", arm.Trials)
	}
	if arm.Validity.Emitted != 2 || arm.Validity.Invalid != 1 || arm.Validity.Scored != 1 {
		t.Errorf("validity accounting = %+v; want emitted 2 / scored 1 / invalid 1", arm.Validity)
	}
	if arm.Validity.Complete() {
		t.Errorf("an arm with an invalid trial must not report a complete result")
	}
	if arm.Disruption.Mean != 1 || arm.Disruption.N != 1 {
		t.Errorf("disruption mean=%v n=%d; the invalid trial must not enter the mean", arm.Disruption.Mean, arm.Disruption.N)
	}
	if arm.NegativeControl != NegControlObserved || arm.NegFalseMovesMax != 0 {
		t.Errorf("negative control = %q falseMoves=%d; want an observed measured zero", arm.NegativeControl, arm.NegFalseMovesMax)
	}
	if arm.ControlDefender != "d-v161-nomtd" {
		t.Errorf("control identity = %q, want d-v161-nomtd", arm.ControlDefender)
	}

	md := RenderMarkdownRun(read.Metrics, 0.95, nil, &outcome)
	for _, want := range []string{"Measurement validity", "emitted=2", "invalid=1", "COMPLETE", "Run completeness"} {
		if !strings.Contains(md, want) {
			t.Errorf("report missing %q:\n%s", want, md)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ------------------------------------------------------------------ legacy

func TestValidityLegacyRowsAreCountedNeverScored(t *testing.T) {
	metrics := []core.Metric{
		legacyRow("s1", "d-legacy", 0, 1, false),
		legacyRow("s1", "d-legacy", 1, 1, false),
	}
	s := armByDefender(t, Aggregate(metrics, 0.95), "d-legacy")
	if s.Trials != 0 || s.Disruption.N != 0 {
		t.Errorf("legacy rows were scored: trials=%d n=%d", s.Trials, s.Disruption.N)
	}
	if s.Validity.Legacy != 2 || s.Validity.Emitted != 2 {
		t.Errorf("legacy accounting = %+v; want emitted 2 / legacy 2", s.Validity)
	}
	if !s.Skipped {
		t.Errorf("an all-legacy arm must not present as a measured arm")
	}
	md := RenderMarkdown(metrics, 0.95, nil)
	if !strings.Contains(md, "legacy=2") {
		t.Errorf("report does not disclose the legacy rows:\n%s", md)
	}
	if strings.Contains(md, "| 100% [") {
		t.Errorf("legacy disruption was published as a measured percentage:\n%s", md)
	}
}

// A mixed legacy/current stream keeps the certified score to the current rows.
func TestValidityMixedLegacyAndCurrentStream(t *testing.T) {
	metrics := []core.Metric{
		scoredRow("s1", "d-arm", 0, 1, false, 2),
		legacyRow("s1", "d-arm", 1, 0, true),
	}
	s := armByDefender(t, Aggregate(metrics, 0.95), "d-arm")
	if s.Disruption.Mean != 1 || s.Disruption.N != 1 {
		t.Errorf("legacy row contaminated the mean: mean=%v n=%d", s.Disruption.Mean, s.Disruption.N)
	}
	if s.Validity.Legacy != 1 || s.Validity.Scored != 1 || s.Validity.Emitted != 2 {
		t.Errorf("accounting = %+v; want emitted 2 / scored 1 / legacy 1", s.Validity)
	}
}

// --------------------------------------------------------------- empty data

func TestValidityNoDataIsNeverAMeasuredZeroOrAPass(t *testing.T) {
	md := RenderMarkdown(nil, 0.95, nil)
	if strings.Contains(md, "| 0 |") || strings.Contains(md, "0% [0,0]") {
		t.Errorf("empty report published a measured zero:\n%s", md)
	}
	dollars := RenderDollars(nil, DollarInputs{ROI: core.ROIInputs{GpuCount: 8, DollarsPerGpuHour: 2.5, GpuOverheadPercent: 0.015, AvoidedBreachValue: 4_880_000, HorizonYears: 1}, BaselineDefender: "d-nomtd"}, 0.95)
	if strings.Count(dollars, "UNSCORED (no valid measurement)") != 3 {
		t.Errorf("empty economics did not mark all three hypotheses UNSCORED:\n%s", dollars)
	}
	if strings.Contains(dollars, "**PASS**") {
		t.Errorf("empty economics published a PASS verdict:\n%s", dollars)
	}
}

// An arm whose every row is invalid renders NOT MEASURED, never 0%.
func TestValidityAllInvalidArmRendersNotMeasured(t *testing.T) {
	metrics := []core.Metric{
		notMeasuredRow("s1", "d-broken", 0, core.MeasurementInvalid, "oracle transport unavailable"),
		notMeasuredRow("s1", "d-broken", 1, core.MeasurementInvalid, "oracle transport unavailable"),
	}
	md := RenderMarkdown(metrics, 0.95, nil)
	if !strings.Contains(md, "NOT MEASURED") {
		t.Errorf("all-invalid arm not rendered as NOT MEASURED:\n%s", md)
	}
	if strings.Contains(md, "| 0% [0,0] |") {
		t.Errorf("all-invalid arm published a measured 0%%:\n%s", md)
	}
	s := armByDefender(t, Aggregate(metrics, 0.95), "d-broken")
	if s.Validity.Invalid != 2 || s.Trials != 0 {
		t.Errorf("accounting = %+v trials=%d", s.Validity, s.Trials)
	}
}

// ------------------------------------------------------- negative controls

func TestValidityNegativeControlStatesAreDistinct(t *testing.T) {
	notRun := []core.Metric{scoredRow("s1", "d-a", 0, 1, false, 2)}
	unobserved := []core.Metric{scoredRow("s1", "d-b", 0, 1, false, 2), negControlRow("s1", "d-b", 1, 0, false)}
	observed := []core.Metric{scoredRow("s1", "d-c", 0, 1, false, 2), negControlRow("s1", "d-c", 1, 0, true)}

	for _, tc := range []struct {
		name    string
		metrics []core.Metric
		def     string
		want    string
	}{
		{"not-run", notRun, "d-a", NegControlNotRun},
		{"unobserved", unobserved, "d-b", NegControlUnobserved},
		{"observed", observed, "d-c", NegControlObserved},
	} {
		s := armByDefender(t, Aggregate(tc.metrics, 0.95), tc.def)
		if s.NegativeControl != tc.want {
			t.Errorf("%s: negative-control state = %q, want %q", tc.name, s.NegativeControl, tc.want)
		}
		wantMax := -1
		if tc.want == NegControlObserved {
			wantMax = 0
		}
		if s.NegFalseMovesMax != wantMax {
			t.Errorf("%s: NegFalseMovesMax = %d, want %d (the field alone must not read as a measured zero)", tc.name, s.NegFalseMovesMax, wantMax)
		}
		cell := lastRowCell(RenderMarkdown(tc.metrics, 0.95, nil), tc.def)
		if tc.want == NegControlObserved {
			// A measured zero, with the census that backs it.
			if !strings.HasPrefix(cell, "0 (n=") {
				t.Errorf("observed clean control cell = %q, want the measured 0 with its census", cell)
			}
			continue
		}
		if cell == "0" {
			t.Errorf("%s control rendered as a measured 0", tc.name)
		}
		if !strings.HasPrefix(cell, "n/a") {
			t.Errorf("%s control cell = %q, want an explicit n/a", tc.name, cell)
		}
	}
}

// --------------------------------------------------------------- adaptive

func TestValidityAdaptiveRowsAreReportedSeparately(t *testing.T) {
	adaptiveUnscored := scoredRow("s1", "d-arm", 2, 0, false, 2)
	av := adaptiveUnscored.Validity
	av.Kind = core.TrialAdaptive
	av.Scored = false
	av.UnscoredReason = "no VALID adaptive control was observed at trial index 2"
	av.Baseline = core.BaselineRef{Required: true, Defender: "d-nomtd", Kind: core.TrialAdaptive, Trial: 2,
		Reason: av.UnscoredReason}
	adaptiveUnscored.DisruptionVsOracle = 0

	metrics := []core.Metric{scoredRow("s1", "d-arm", 0, 1, false, 2), adaptiveUnscored}

	ordinary := armByDefender(t, Aggregate(metrics, 0.95), "d-arm")
	if ordinary.Validity.Emitted != 1 || ordinary.Trials != 1 {
		t.Errorf("the adaptive row leaked into the ordinary arm: %+v", ordinary.Validity)
	}
	if ordinary.Disruption.Mean != 1 {
		t.Errorf("ordinary disruption diluted by the adaptive row: %v", ordinary.Disruption.Mean)
	}
	adaptive := armByDefender(t, AggregateAdaptive(metrics, 0.95), "d-arm")
	if adaptive.Validity.Emitted != 1 || adaptive.Validity.UnscoredValid != 1 || adaptive.Trials != 0 {
		t.Errorf("adaptive accounting = %+v trials=%d", adaptive.Validity, adaptive.Trials)
	}
	md := RenderMarkdown(metrics, 0.95, nil)
	for _, want := range []string{"Adaptive-attacker observations", "EXPERIMENTAL LIMITATION", "no VALID adaptive control"} {
		if !strings.Contains(md, want) {
			t.Errorf("report missing %q:\n%s", want, md)
		}
	}
}

// -------------------------------------------------------------- anchor-only

func TestValidityAnchorOnlyControlsAreDisclosedNotInvented(t *testing.T) {
	anchor := scoredRow("s1", "d-nomtd", 0, 0, true, 0)
	anchor.AnchorOnly = true
	metrics := []core.Metric{anchor, scoredRow("s1", "d-arm", 0, 1, false, 2)}

	main := Aggregate(metrics, 0.95)
	for _, s := range main {
		if s.Defender == "d-nomtd" {
			t.Errorf("anchor-only arm leaked into the requested-arm view")
		}
	}
	controls := AggregateAnchorControls(metrics, 0.95)
	c := armByDefender(t, controls, "d-nomtd")
	if !c.AnchorOnly || c.Trials != 1 {
		t.Errorf("anchor-only control summary wrong: %+v", c)
	}
	if c.NegativeControl != NegControlNotRun {
		t.Errorf("anchor-only arm's unrun negative control = %q, want %q", c.NegativeControl, NegControlNotRun)
	}
	md := RenderMarkdown(metrics, 0.95, nil)
	if !strings.Contains(md, "Force-included anchor-only control arms") {
		t.Errorf("report hides the anchor-only control provenance:\n%s", md)
	}
	if cell := lastRowCell(md, "d-nomtd"); cell == "0" {
		t.Errorf("anchor-only arm's unrun negative control rendered as a measured 0")
	}
}

// ---------------------------------------------------------------- economics

func TestValidityEconomicsExcludeUnmeasuredRows(t *testing.T) {
	in := DollarInputs{
		ROI:               core.ROIInputs{GpuCount: 8, DollarsPerGpuHour: 2.50, GpuOverheadPercent: 0.015, AvoidedBreachValue: 4_880_000, HorizonYears: 1.0},
		RotationIntervals: DefaultRotationIntervals(),
		BaselineDefender:  "d-nomtd",
	}
	// One scored row with an observed cost, one invalid row, one legacy row and
	// one scored row whose cost was UNOBSERVED.
	costUnobserved := scoredRow("s1", "d-r6blindtimer", 3, 1, false, -1)
	costUnobserved.Validity.CostObserved = false
	costUnobserved.SecurityPerCost = 0

	metrics := []core.Metric{
		scoredRow("s1", "d-r6blindtimer", 0, 1, false, 1),
		notMeasuredRow("s1", "d-r6blindtimer", 1, core.MeasurementInvalid, "oracle transport unavailable"),
		legacyRow("s1", "d-r6blindtimer", 2, 1, false),
		costUnobserved,
	}
	rows := recomputeEconomics(metrics, in)
	if len(rows) != 1 {
		t.Fatalf("want 1 arm, got %d", len(rows))
	}
	r := rows[0]
	if r.Trials != 1 {
		t.Errorf("economics used %d trial(s), want only the 1 scored cost-observed row", r.Trials)
	}
	if r.Validity.Emitted != 4 || r.Validity.Invalid != 1 || r.Validity.Legacy != 1 || r.Validity.CostUnobserved != 2 {
		t.Errorf("economics accounting = %+v; invalid and otherwise-valid rows with unobserved cost must both remain disclosed", r.Validity)
	}
	if r.MeanDefensiveActs != 1 {
		t.Errorf("mean defensive acts = %v; the -1 unobserved row must not enter the denominator", r.MeanDefensiveActs)
	}
	md := RenderDollars(metrics, in, 0.95)
	if !strings.Contains(md, "Economics measurement validity") || !strings.Contains(md, "costUnobserved=2") {
		t.Errorf("economics report hides its exclusions:\n%s", md)
	}
}

func TestValidityEconomicsRenderNAForAnUnmeasuredArm(t *testing.T) {
	in := DollarInputs{
		ROI:               core.ROIInputs{GpuCount: 8, DollarsPerGpuHour: 2.50, GpuOverheadPercent: 0.015, AvoidedBreachValue: 4_880_000, HorizonYears: 1.0},
		RotationIntervals: DefaultRotationIntervals(),
		BaselineDefender:  "d-nomtd",
	}
	metrics := []core.Metric{notMeasuredRow("s1", "d-fullphoenix", 0, core.MeasurementInvalid, "oracle transport unavailable")}
	rows := recomputeEconomics(metrics, in)
	if len(rows) != 1 || rows[0].Economics {
		t.Fatalf("an all-invalid arm must carry no economics: %+v", rows)
	}
	if rows[0].ROI.SecurityPerCostDollars != 0 || rows[0].Schwartau.ProtectionTimeSeconds != 0 {
		t.Errorf("an unmeasured arm derived economics: %+v", rows[0])
	}
	md := RenderDollars(metrics, in, 0.95)
	if strings.Contains(md, "| $0 |") {
		t.Errorf("unmeasured arm rendered a $0 figure:\n%s", md)
	}
	if !strings.Contains(md, "| d-fullphoenix | executable-mechanism | 0 | n/a |") {
		t.Errorf("unmeasured arm not rendered as n/a:\n%s", md)
	}
}

// ------------------------------------------------------------------ readers

func TestValidityReaderPreservesTheDistinctionOnDecode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.jsonl")
	content := strings.Join([]string{
		`{"scenario":"s1","defender":"d-nomtd","trial":0,"oracleAchieved":true,"disruptionVsOracle":0,"r6Tag":"R6Partial","category":"ClassicChain"}`,
		`{"scenario":"s1","defender":"d-arm","trial":0,"oracleAchieved":false,"disruptionVsOracle":1,"validity":{"version":1,"kind":"ordinary","status":"valid","phase":"complete","attackExecuted":true,"oracleObserved":true,"observerPresent":true,"costObserved":true,"scored":true,"baseline":{"required":true,"defender":"d-nomtd","trial":0,"kind":"ordinary","observed":true,"valid":true,"oracleAchieved":true,"usable":true},"cleanup":{"complete":true}}}`,
		`{"scenario":"s1","defender":"d-arm","trial":1,`, // truncated / corrupt
		``,
	}, "\n")
	if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	read, err := ReadMetricsFile(path)
	if err != nil {
		t.Fatalf("tolerant read: %v", err)
	}
	if len(read.Metrics) != 2 || read.Legacy != 1 || len(read.Undecodable) != 1 {
		t.Fatalf("tolerant read = %d rows / %d legacy / %d undecodable; want 2/1/1", len(read.Metrics), read.Legacy, len(read.Undecodable))
	}
	if read.Undecodable[0].Line != 3 {
		t.Errorf("undecodable line recorded as %d, want 3", read.Undecodable[0].Line)
	}
	if !read.Metrics[0].IsLegacy() || read.Metrics[1].IsLegacy() {
		t.Errorf("legacy classification wrong after decode")
	}
	if !read.Metrics[1].IsScored() || read.Metrics[1].MeasurementState().Baseline.Defender != "d-nomtd" {
		t.Errorf("current row lost its validity on decode: %+v", read.Metrics[1].MeasurementState())
	}

	// The STRICT reader (used by -resume) refuses a file it cannot fully parse.
	if _, err := ReadMetricsJSONL(path); err == nil {
		t.Errorf("strict reader accepted a file with an undecodable line")
	}
}

// ------------------------------------------------------------- run outcome

func TestValidityReportRefusesToClaimACompleteMatrix(t *testing.T) {
	metrics := []core.Metric{scoredRow("s1", "d-arm", 0, 1, false, 2)}
	aborted := core.RunOutcome{PlannedTrials: 4, ExecutedTrials: 1, WrittenTrials: 1,
		Aborted: true, AbortReason: "cleanup did not verify for s1/d-arm trial 0",
		Barriers:         []string{"cleanup did not verify for s1/d-arm trial 0"},
		BaselineDefender: "d-nomtd"}
	md := RenderMarkdownRun(metrics, 0.95, nil, &aborted)
	for _, want := range []string{"INCOMPLETE", "planned 4 trial(s), executed 1", "ABORTED", "Barrier"} {
		if !strings.Contains(md, want) {
			t.Errorf("aborted run report missing %q:\n%s", want, md)
		}
	}
	// Without a run outcome the report must say completeness was not asserted.
	if !strings.Contains(RenderMarkdown(metrics, 0.95, nil), "was NOT asserted") {
		t.Errorf("a report rendered without a run outcome claimed completeness")
	}
}

// ------------------------------------------------------------------ helper

// lastRowCell returns the final table cell of the first rendered arm row naming
// `defender`.
func lastRowCell(md, defender string) string {
	for _, line := range strings.Split(md, "\n") {
		if !strings.HasPrefix(line, "| ") || !strings.Contains(line, "| "+defender+" |") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		return strings.TrimSpace(cells[len(cells)-1])
	}
	return ""
}
