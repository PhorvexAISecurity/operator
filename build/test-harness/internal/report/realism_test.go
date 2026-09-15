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

func TestRunnerReaderRowsAreOrderIndependentAtReportBoundaries(t *testing.T) {
	produced := r1ProducerRow(t)
	marker := produced
	marker.ScenarioRealism = core.RealismMarkerSimulation
	unassessed := produced
	unassessed.ScenarioRealism = ""
	for _, rows := range [][]core.Metric{{unassessed, marker}, {marker, unassessed}} {
		read := replayThroughReader(t, rows...)
		ordinary, markers := splitMarkerSummaries(Aggregate(read, 0.95))
		if len(ordinary) != 1 || ordinary[0].Trials != 1 || len(markers) != 1 || markers[0].Trials != 1 {
			t.Fatalf("mixed realism rows changed groups by order: ordinary=%+v marker=%+v", ordinary, markers)
		}
		economics := recomputeEconomics(read, DollarInputs{BaselineDefender: "d-v161-nomtd"})
		var excluded, scored int
		for _, row := range economics {
			if row.Validity.RealismExcluded == 1 && !row.Economics {
				excluded++
			}
			if row.Economics {
				scored++
			}
		}
		if excluded != 1 || scored != 1 {
			t.Fatalf("economics boundary leaked marker: %+v", economics)
		}
		rendered := RenderDollars(read, DollarInputs{BaselineDefender: "d-v161-nomtd"}, 0.95)
		if !strings.Contains(rendered, "realismExcluded=1") || !strings.Contains(rendered, "marker simulation excluded") {
			t.Fatalf("excluded marker not disclosed:\n%s", rendered)
		}
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
