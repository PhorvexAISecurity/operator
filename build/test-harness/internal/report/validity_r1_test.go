package report

// validity_r1_test.go — PERMANENT regressions for lead review R1 (V3-M161),
// report/reader side:
//
//   1. a decoded `scored: true` is never trusted on its own; unsupported or
//      contradictory rows stay VISIBLE and COUNTED but are never certified;
//   2. a partially observed negative control is not a fully observed one, in the
//      aggregate, in both reports and in the hypothesis verdicts;
//   3. a repeated reason never suppresses the distinct failures recorded after
//      it.
//
// The decode path is the REAL one: rows are produced by the REAL Runner.Run and
// the REAL MetricWriter, written to disk, and read back with ReadMetricsFile
// before any assertion.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

// r1ProducerRow returns the defended arm's row exactly as the reader decodes it,
// straight from Runner.Run -> MetricWriter -> ReadMetricsFile.
func r1ProducerRow(t *testing.T) core.Metric {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "metrics.jsonl")
	mw, err := core.NewMetricWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	runner := core.NewRunner(core.RunnerOptions{
		TrialsPerArm: 1, OutDir: dir,
		ScenarioFilter: map[string]bool{"v161-mixed": true},
		DefenderFilter: map[string]bool{"d-v161-nomtd": true, "d-v161-arm": true},
	}, func(s, d string, i int, _ int64, _ string) (*core.Env, func() error, error) {
		return &core.Env{Log: &e2eLogger{}, Trial: i, ScenarioName: s, DefenderName: d,
			Config: config.WithDollarDefaults(config.TargetConfig{})}, func() error { return nil }, nil
	}, mw, nil)
	if _, err := runner.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	read, err := ReadMetricsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range read.Metrics {
		if m.Defender == "d-v161-arm" {
			return m
		}
	}
	t.Fatal("producer arm missing")
	return core.Metric{}
}

// replayThroughReader writes rows back out and reads them with the REAL reader,
// so every assertion below is about what a consumer of a metrics FILE sees.
func replayThroughReader(t *testing.T, rows ...core.Metric) []core.Metric {
	t.Helper()
	path := filepath.Join(t.TempDir(), "replayed.jsonl")
	var b []byte
	for _, m := range rows {
		line, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		b = append(append(b, line...), '\n')
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	read, err := ReadMetricsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return read.Metrics
}

func scoredCount(sums []ArmSummary) int {
	n := 0
	for _, s := range sums {
		n += s.Validity.Scored
	}
	return n
}

// A tampered or unsupported row must never be certified by the aggregator, and
// must never disappear: it is counted as UNVERIFIED with its reason rendered.
func TestR1AggregationRefusesUnsupportedOrContradictoryRows(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*core.Metric)
	}{
		{"future-version", func(m *core.Metric) { m.Validity.Version = 999 }},
		{"unknown-status", func(m *core.Metric) { m.Validity.Status = "unrecognized" }},
		{"unknown-kind", func(m *core.Metric) { m.Validity.Kind = "sideways" }},
		{"cleanup-incomplete", func(m *core.Metric) { m.Validity.Cleanup.Complete = false }},
		{"cleanup-unresolved", func(m *core.Metric) {
			m.Validity.Cleanup.Complete = false
			m.Validity.Cleanup.Unresolved = true
		}},
		{"missing-control", func(m *core.Metric) { m.Validity.Baseline = core.BaselineRef{Required: true} }},
		{"oracle-not-observed", func(m *core.Metric) { m.Validity.OracleObserved = false }},
		{"cost-sentinel-contradiction", func(m *core.Metric) { m.DefensiveActions = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := r1ProducerRow(t)
			tc.mutate(&m)
			metrics := replayThroughReader(t, m)

			sums := Aggregate(metrics, 0.95)
			if n := scoredCount(sums); n != 0 {
				t.Fatalf("%s still certified: scored=%d", tc.name, n)
			}
			s := armByDefender(t, sums, "d-v161-arm")
			if s.Validity.Emitted != 1 {
				t.Errorf("row vanished from the counts: %+v", s.Validity)
			}
			if s.Validity.Unverified != 1 {
				t.Errorf("row not counted as UNVERIFIED: %+v", s.Validity)
			}
			if s.Disruption.N != 0 {
				t.Errorf("a refused row entered the disruption mean (n=%d)", s.Disruption.N)
			}
			if len(s.Validity.Reasons) == 0 {
				t.Errorf("the refusal is invisible: no reason rendered")
			}
			md := RenderMarkdown(metrics, 0.95, nil)
			if !strings.Contains(md, "unverified=1") {
				t.Errorf("report does not disclose the unverified row:\n%s", md)
			}
			// The economics view must refuse it on the same grounds.
			rows := recomputeEconomics(metrics, r1DollarInputs())
			if len(rows) != 1 || rows[0].Economics || rows[0].Validity.Unverified != 1 {
				t.Errorf("economics did not refuse/count the row: %+v", rows)
			}
		})
	}
}

// POSITIVE CONTROL: the same producer row, unmodified, is still certified end to
// end through the reader and both reports.
func TestR1AggregationKeepsGenuineProducerRows(t *testing.T) {
	metrics := replayThroughReader(t, r1ProducerRow(t))
	sums := Aggregate(metrics, 0.95)
	if n := scoredCount(sums); n != 1 {
		t.Fatalf("the genuine producer row was refused: scored=%d", n)
	}
	s := armByDefender(t, sums, "d-v161-arm")
	if s.Validity.Unverified != 0 || s.Disruption.Mean != 1 || s.Disruption.N != 1 {
		t.Fatalf("genuine row mis-aggregated: %+v disruption=%+v", s.Validity, s.Disruption)
	}
	rows := recomputeEconomics(metrics, r1DollarInputs())
	if len(rows) != 1 || !rows[0].Economics || rows[0].Trials != 1 {
		t.Fatalf("genuine row produced no economics: %+v", rows)
	}
}

// ------------------------------------------------- partial negative controls

// One clean control plus one unusable control is PARTIAL, never fully observed:
// a max of 0 over the usable subset says nothing about the trial that was not
// observed.
func TestR1PartialNegativeControlIsNotFullyObserved(t *testing.T) {
	good := negControlRow("v161-mixed", "d-v161-arm", 1, 0, true)
	bad := negControlRow("v161-mixed", "d-v161-arm", 2, 0, false)
	bad.Validity.Status = core.MeasurementInvalid
	bad.Validity.Reasons = []string{"oracle: oracle unavailable"}
	metrics := replayThroughReader(t, r1ProducerRow(t), good, bad)

	s := armByDefender(t, Aggregate(metrics, 0.95), "d-v161-arm")
	if s.NegativeControl != NegControlPartial {
		t.Fatalf("negative-control state = %q, want %q", s.NegativeControl, NegControlPartial)
	}
	if s.NegFalseMovesMax != -1 {
		t.Errorf("NegFalseMovesMax = %d; a partial control must not present a measured value", s.NegFalseMovesMax)
	}
	if s.NegControlTotal != 2 || s.NegControlUsable != 1 || s.NegControlUnusable != 1 {
		t.Errorf("negative-control census wrong: total=%d usable=%d unusable=%d",
			s.NegControlTotal, s.NegControlUsable, s.NegControlUnusable)
	}
	md := RenderMarkdown(metrics, 0.95, nil)
	if !strings.Contains(md, "n/a (partial: 1 of 2 observed)") {
		t.Errorf("main report does not disclose the partial control:\n%s", md)
	}
	if !strings.Contains(md, "negControl=partial(1/2 observed)") {
		t.Errorf("validity accounting does not disclose the partial control:\n%s", md)
	}
	// The hypothesis verdicts must carry the caveat too.
	dollars := RenderDollars(metrics, r1DollarInputs(), 0.95)
	if !strings.Contains(dollars, "Negative controls (verdict caveat)") ||
		!strings.Contains(dollars, "PARTIALLY observed") {
		t.Errorf("hypothesis section does not disclose the partial control:\n%s", dollars)
	}
}

// POSITIVE CONTROL: when EVERY negative control is observed, the measured zero
// is published with its census and no caveat is raised.
func TestR1FullyObservedNegativeControlStillPublishesItsMeasuredZero(t *testing.T) {
	metrics := replayThroughReader(t,
		r1ProducerRow(t),
		negControlRow("v161-mixed", "d-v161-arm", 1, 0, true),
		negControlRow("v161-mixed", "d-v161-arm", 2, 0, true),
	)
	s := armByDefender(t, Aggregate(metrics, 0.95), "d-v161-arm")
	if s.NegativeControl != NegControlObserved || s.NegFalseMovesMax != 0 {
		t.Fatalf("fully observed control not published: state=%q max=%d", s.NegativeControl, s.NegFalseMovesMax)
	}
	if s.NegControlUsable != 2 || s.NegControlUnusable != 0 {
		t.Errorf("census wrong: usable=%d unusable=%d", s.NegControlUsable, s.NegControlUnusable)
	}
	dollars := RenderDollars(metrics, r1DollarInputs(), 0.95)
	if !strings.Contains(dollars, "every scored arm below has a fully observed negative control") {
		t.Errorf("clean-control disclosure missing:\n%s", dollars)
	}
}

// A legacy negative control is unverified evidence, so an arm holding one is not
// fully observed either.
func TestR1LegacyNegativeControlDemotesTheArm(t *testing.T) {
	legacyNeg := core.Metric{Scenario: "v161-mixed", Defender: "d-v161-arm", Trial: 2,
		NegativeControl: true, FalseDefensiveActions: 0}
	metrics := replayThroughReader(t,
		r1ProducerRow(t),
		negControlRow("v161-mixed", "d-v161-arm", 1, 0, true),
		legacyNeg,
	)
	s := armByDefender(t, Aggregate(metrics, 0.95), "d-v161-arm")
	if s.NegativeControl != NegControlPartial || s.NegFalseMovesMax != -1 {
		t.Fatalf("a legacy control was treated as observed: state=%q max=%d", s.NegativeControl, s.NegFalseMovesMax)
	}
}

// --------------------------------------------------------- reason retention

// A reason that repeats must never suppress the DISTINCT reasons supplied after
// it, or a later cleanup failure disappears behind an earlier oracle failure.
func TestR1DistinctReasonsSurviveADuplicate(t *testing.T) {
	var a ArmValidity
	a.addReason("oracle unavailable")
	a.addReason("oracle unavailable", "cleanup failed")
	a.addReason("cleanup failed", "control never observed", "oracle unavailable")
	want := []string{"oracle unavailable", "cleanup failed", "control never observed"}
	if len(a.Reasons) != len(want) {
		t.Fatalf("reasons = %v, want %v", a.Reasons, want)
	}
	for i, w := range want {
		if a.Reasons[i] != w {
			t.Fatalf("reasons = %v, want %v", a.Reasons, want)
		}
	}
}

// Through the real aggregator: an arm with an oracle failure AND a later cleanup
// failure must render BOTH.
func TestR1BothFailureReasonsAreRendered(t *testing.T) {
	oracleFail := notMeasuredRow("v161-mixed", "d-v161-arm", 5, core.MeasurementInvalid, "oracle transport unavailable")
	cleanupFail := notMeasuredRow("v161-mixed", "d-v161-arm", 6, core.MeasurementInvalid, "oracle transport unavailable")
	cleanupFail.Validity.Reasons = []string{
		"oracle: oracle transport unavailable",
		"cleanup: 1 owed cleanup step(s) did not finish cleanly",
	}
	cleanupFail.Validity.Cleanup = core.CleanupRecord{
		Attempted: []core.CleanupStep{{Step: "scenario.Teardown", Error: "foothold pod still present"}},
	}
	metrics := replayThroughReader(t, oracleFail, cleanupFail)

	s := armByDefender(t, Aggregate(metrics, 0.95), "d-v161-arm")
	joined := strings.Join(s.Validity.Reasons, " | ")
	if !strings.Contains(joined, "oracle transport unavailable") {
		t.Errorf("oracle failure missing from the reasons: %v", s.Validity.Reasons)
	}
	if !strings.Contains(joined, "cleanup") {
		t.Errorf("the later cleanup failure was suppressed by the duplicate oracle reason: %v", s.Validity.Reasons)
	}
	if s.Validity.CleanupFailed != 1 {
		t.Errorf("cleanupFailed = %d, want 1", s.Validity.CleanupFailed)
	}
	md := RenderMarkdown(metrics, 0.95, nil)
	if !strings.Contains(md, "cleanup") {
		t.Errorf("report does not render the cleanup failure:\n%s", md)
	}
}

func r1DollarInputs() DollarInputs {
	return DollarInputs{
		ROI:               core.ROIInputs{GpuCount: 8, DollarsPerGpuHour: 2.50, GpuOverheadPercent: 0.015, AvoidedBreachValue: 4_880_000, HorizonYears: 1.0},
		RotationIntervals: DefaultRotationIntervals(),
		BaselineDefender:  "d-v161-nomtd",
	}
}
