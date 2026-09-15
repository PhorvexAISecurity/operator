package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/report"
)

const m170ScenarioName = "m170-cli-producer"

func init() {
	core.RegisterScenario(m170CLIScenario{})
	core.RegisterDefender(m170CLIDefender{name: "m170-cli-arm"})
}

func TestDollarsOnlyExcludesMarkerRowsInEitherFileOrder(t *testing.T) {
	dir := t.TempDir()
	metricsPath := filepath.Join(dir, "producer.jsonl")
	mw, err := core.NewMetricWriter(metricsPath)
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRunner(core.RunnerOptions{TrialsPerArm: 1, OutDir: dir, ScenarioFilter: map[string]bool{m170ScenarioName: true}, DefenderFilter: map[string]bool{"d-nomtd": true, "m170-cli-arm": true}}, func(s, d string, trial int, _ int64, _ string) (*core.Env, func() error, error) {
		return &core.Env{Log: &m170CLILogger{}, ScenarioName: s, DefenderName: d, Trial: trial, Config: config.WithDollarDefaults(config.TargetConfig{})}, func() error { return nil }, nil
	}, mw, nil)
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	read, err := report.ReadMetricsJSONL(metricsPath)
	if err != nil {
		t.Fatal(err)
	}
	var produced core.Metric
	for _, row := range read {
		if row.Defender == "m170-cli-arm" {
			produced = row
		}
	}
	if produced.Validity == nil || !produced.IsScored() {
		t.Fatalf("real Runner row missing: %+v", produced)
	}
	marker, unassessed := produced, produced
	marker.ScenarioRealism = core.RealismMarkerSimulation
	unassessed.ScenarioRealism = ""
	for i, rows := range [][]core.Metric{{unassessed, marker}, {marker, unassessed}} {
		path := filepath.Join(dir, "order-"+string(rune('a'+i))+".jsonl")
		var raw []byte
		for _, row := range rows {
			line, _ := json.Marshal(row)
			raw = append(append(raw, line...), '\n')
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := dollarsOnly(path); err != nil {
			t.Fatal(err)
		}
		reportBytes, err := os.ReadFile(filepath.Join(dir, "report-dollars.md"))
		if err != nil {
			t.Fatal(err)
		}
		text := string(reportBytes)
		if !strings.Contains(text, "marker-simulation") || !strings.Contains(text, "realismExcluded=1") || !strings.Contains(text, "| "+m170ScenarioName+" | m170-cli-arm | marker-simulation | 0 | n/a |") {
			t.Fatalf("CLI dollars report leaked or hid marker row:\n%s", text)
		}
	}
}

type m170CLIScenario struct{}

func (m170CLIScenario) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{Name: m170ScenarioName, Category: core.CategoryClassicChain, R6ResponseTag: core.R6Partial}
}
func (m170CLIScenario) Setup(context.Context, *core.Env) error { return nil }
func (m170CLIScenario) Execute(_ context.Context, env *core.Env) (core.AttackResult, error) {
	env.Log.Command("marker-producer")
	return core.AttackResult{Commands: []string{"marker-producer"}}, nil
}
func (m170CLIScenario) SuccessOracle(_ context.Context, env *core.Env) (core.OracleResult, error) {
	return core.OracleResult{Achieved: env.DefenderName == "d-nomtd", ObservedState: "runner-produced"}, nil
}
func (m170CLIScenario) Teardown(context.Context, *core.Env) error { return nil }

type m170CLIDefender struct{ name string }

func (d m170CLIDefender) Metadata() core.DefenderMeta {
	return core.DefenderMeta{Name: d.name}
}
func (m170CLIDefender) Setup(context.Context, *core.Env) error    { return nil }
func (m170CLIDefender) Start(context.Context, *core.Env) error    { return nil }
func (m170CLIDefender) Stop(context.Context, *core.Env) error     { return nil }
func (m170CLIDefender) Teardown(context.Context, *core.Env) error { return nil }
func (m170CLIDefender) DefensiveActions(context.Context, *core.Env) (int, []float64, error) {
	return 1, []float64{0}, nil
}

type m170CLILogger struct{ commands []string }

func (*m170CLILogger) Logf(string, ...any)  {}
func (l *m170CLILogger) Command(s string)   { l.commands = append(l.commands, s) }
func (l *m170CLILogger) Commands() []string { return append([]string(nil), l.commands...) }
func (*m170CLILogger) RawLogPath() string   { return "m170-cli.log" }
