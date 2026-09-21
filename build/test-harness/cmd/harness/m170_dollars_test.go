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
	for _, scenario := range []m170CLIScenario{
		{name: m170ScenarioName + "-positive", realism: core.RealismExecutable},
		{name: m170ScenarioName + "-empty"},
		{name: m170ScenarioName + "-unassessed", realism: core.RealismUnassessed},
		{name: m170ScenarioName + "-unknown", realism: core.ScenarioRealism("future-unknown")},
		{name: m170ScenarioName + "-marker", realism: core.RealismMarkerSimulation},
		{name: m170ScenarioName + "-benign", realism: core.RealismExecutable, benign: true},
	} {
		scenario := scenario
		core.RegisterScenario(&scenario)
	}
	core.RegisterDefender(m170CLIDefender{name: "m170-cli-arm"})
}

func TestDollarsOnlyRequiresAssessedExecutableAttackInEitherFileOrder(t *testing.T) {
	dir := t.TempDir()
	metricsPath := filepath.Join(dir, "producer.jsonl")
	mw, err := core.NewMetricWriter(metricsPath)
	if err != nil {
		t.Fatal(err)
	}
	filter := map[string]bool{}
	for _, suffix := range []string{"positive", "empty", "unassessed", "unknown", "marker", "benign"} {
		filter[m170ScenarioName+"-"+suffix] = true
	}
	r := core.NewRunner(core.RunnerOptions{TrialsPerArm: 1, OutDir: dir, ScenarioFilter: filter, DefenderFilter: map[string]bool{"d-nomtd": true, "m170-cli-arm": true}}, func(s, d string, trial int, _ int64, _ string) (*core.Env, func() error, error) {
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
	if len(read) != 12 {
		t.Fatalf("real Runner rows=%d, want 12", len(read))
	}
	reversed := append([]core.Metric(nil), read...)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	for i, rows := range [][]core.Metric{read, reversed} {
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
		for _, want := range []string{
			"| " + m170ScenarioName + "-positive | m170-cli-arm | executable-mechanism | 1 | 100% |",
			"| " + m170ScenarioName + "-empty | m170-cli-arm | unassessed | 0 | n/a |",
			"| " + m170ScenarioName + "-unassessed | m170-cli-arm | unassessed | 0 | n/a |",
			"| " + m170ScenarioName + "-unknown | m170-cli-arm | future-unknown | 0 | n/a |",
			"| " + m170ScenarioName + "-marker | m170-cli-arm | marker-simulation | 0 | n/a |",
			"| " + m170ScenarioName + "-benign | m170-cli-arm | executable-mechanism | 0 | n/a |",
			"realismExcluded=1", "benignControlExcluded=1", "mechanismExcluded=1",
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("CLI dollars report missing %q or leaked an excluded row:\n%s", want, text)
			}
		}
	}
}

type m170CLIScenario struct {
	name    string
	realism core.ScenarioRealism
	benign  bool
}

func (s *m170CLIScenario) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{Name: s.name, Category: core.CategoryClassicChain, R6ResponseTag: core.R6Partial, Realism: s.realism, BenignControl: s.benign}
}
func (*m170CLIScenario) Setup(context.Context, *core.Env) error { return nil }
func (*m170CLIScenario) Execute(_ context.Context, env *core.Env) (core.AttackResult, error) {
	env.Log.Command("marker-producer")
	return core.AttackResult{Commands: []string{"marker-producer"}}, nil
}
func (*m170CLIScenario) SuccessOracle(_ context.Context, env *core.Env) (core.OracleResult, error) {
	return core.OracleResult{Achieved: env.DefenderName == "d-nomtd", ObservedState: "runner-produced"}, nil
}
func (*m170CLIScenario) Teardown(context.Context, *core.Env) error { return nil }

type m170CLIDefender struct{ name string }

func (d m170CLIDefender) Metadata() core.DefenderMeta {
	return core.DefenderMeta{Name: d.name}
}
func (m170CLIDefender) Setup(context.Context, *core.Env) error    { return nil }
func (m170CLIDefender) Start(context.Context, *core.Env) error    { return nil }
func (m170CLIDefender) Stop(context.Context, *core.Env) error     { return nil }
func (m170CLIDefender) Teardown(context.Context, *core.Env) error { return nil }
func (m170CLIDefender) DefensiveActions(context.Context, *core.Env) (int, []float64, error) {
	return 1, []float64{1}, nil
}

type m170CLILogger struct{ commands []string }

func (*m170CLILogger) Logf(string, ...any)  {}
func (l *m170CLILogger) Command(s string)   { l.commands = append(l.commands, s) }
func (l *m170CLILogger) Commands() []string { return append([]string(nil), l.commands...) }
func (*m170CLILogger) RawLogPath() string   { return "m170-cli.log" }
