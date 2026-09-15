package report

import (
	"context"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func TestMitreMatrixSeparatesDeclaredFromExecutable(t *testing.T) {
	marker := metadataScenario{meta: core.ScenarioMeta{Name: "marker", AttackTechniqueIDs: []string{"T1610"}, Realism: core.RealismMarkerSimulation}}
	executable := metadataScenario{meta: core.ScenarioMeta{Name: "executable", AttackTechniqueIDs: []string{"T1610"}, ExercisedTechniqueIDs: []string{"T1610"}, Realism: core.RealismExecutable}}
	legacy := metadataScenario{meta: core.ScenarioMeta{Name: "legacy", AttackTechniqueIDs: []string{"T1190"}}}
	got := RenderMitreMatrix([]core.Scenario{marker, executable, legacy})
	parts := strings.Split(got, "## Executed mechanism inventory")
	if len(parts) != 2 {
		t.Fatalf("missing split inventories:\n%s", got)
	}
	if !strings.Contains(parts[0], "marker") || !strings.Contains(parts[0], "legacy") {
		t.Fatalf("declared mappings missing:\n%s", parts[0])
	}
	if strings.Contains(parts[1], "marker") || strings.Contains(parts[1], "legacy") || !strings.Contains(parts[1], "executable") {
		t.Fatalf("unsupported exercise claim leaked:\n%s", parts[1])
	}
	if !strings.Contains(got, "Neither table proves a successful live defense") {
		t.Fatalf("missing claim limit:\n%s", got)
	}
}

func TestMarkerSummariesAreSeparatedFromRealPercentages(t *testing.T) {
	other, marker := splitMarkerSummaries([]ArmSummary{{Scenario: "m", Realism: core.RealismMarkerSimulation}, {Scenario: "legacy", Realism: core.RealismUnassessed}})
	if len(marker) != 1 || marker[0].Scenario != "m" || len(other) != 1 || other[0].Scenario != "legacy" {
		t.Fatalf("other=%v marker=%v", other, marker)
	}
}

func TestMarkerMetricsExcludedFromRealEconomics(t *testing.T) {
	got := ExcludeMarkerSimulations([]core.Metric{{Scenario: "marker", ScenarioRealism: core.RealismMarkerSimulation}, {Scenario: "legacy"}, {Scenario: "real", ScenarioRealism: core.RealismExecutable}})
	if len(got) != 2 || got[0].Scenario != "legacy" || got[1].Scenario != "real" {
		t.Fatalf("unexpected economics inputs: %+v", got)
	}
}

type metadataScenario struct{ meta core.ScenarioMeta }

func (s metadataScenario) Metadata() core.ScenarioMeta          { return s.meta }
func (metadataScenario) Setup(context.Context, *core.Env) error { return nil }
func (metadataScenario) Execute(context.Context, *core.Env) (core.AttackResult, error) {
	return core.AttackResult{}, nil
}
func (metadataScenario) SuccessOracle(context.Context, *core.Env) (core.OracleResult, error) {
	return core.OracleResult{}, nil
}
func (metadataScenario) Teardown(context.Context, *core.Env) error { return nil }
