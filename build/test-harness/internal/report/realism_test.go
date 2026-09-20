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

func TestBenignControlsAreSeparatedFromAttackAggregates(t *testing.T) {
	attack, marker, benign := splitControlSummaries([]ArmSummary{
		{Scenario: "attack", Realism: core.RealismExecutable},
		{Scenario: "marker", Realism: core.RealismMarkerSimulation},
		{Scenario: "benign", Realism: core.RealismExecutable, BenignControl: true},
	})
	if len(attack) != 1 || attack[0].Scenario != "attack" || len(marker) != 1 || marker[0].Scenario != "marker" || len(benign) != 1 || benign[0].Scenario != "benign" {
		t.Fatalf("attack=%v marker=%v benign=%v", attack, marker, benign)
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

func TestBenignControlBoundaryIsOrderIndependentAndVisible(t *testing.T) {
	produced := r1ProducerRow(t)
	produced.ScenarioRealism = core.RealismExecutable
	attack := produced
	attack.Scenario = "attack"
	benign := produced
	benign.Scenario = "benign"
	benign.ScenarioBenignControl = true

	for _, rows := range [][]core.Metric{{attack, benign}, {benign, attack}} {
		read := replayThroughReader(t, rows...)
		ordinary, markers, controls := splitControlSummaries(Aggregate(read, 0.95))
		if len(ordinary) != 1 || ordinary[0].Scenario != "attack" || len(markers) != 0 || len(controls) != 1 || controls[0].Scenario != "benign" || controls[0].Trials != 1 {
			t.Fatalf("aggregate boundary changed by order: attack=%+v marker=%+v benign=%+v", ordinary, markers, controls)
		}
		filtered := ExcludeNonAttackControls(read)
		if len(filtered) != 1 || filtered[0].Scenario != "attack" {
			t.Fatalf("coverage filter leaked benign control: %+v", filtered)
		}
		economics := recomputeEconomics(read, DollarInputs{BaselineDefender: "d-v161-nomtd"})
		var excluded, scored int
		for _, row := range economics {
			if row.BenignControl && row.Validity.BenignControlExcluded == 1 && !row.Economics {
				excluded++
			}
			if row.Economics {
				scored++
			}
		}
		if excluded != 1 || scored != 1 {
			t.Fatalf("economics boundary leaked benign control: %+v", economics)
		}
		mainReport := RenderMarkdown(read, 0.95, nil)
		if !strings.Contains(mainReport, "Benign functional-effect controls") || !strings.Contains(mainReport, "do not enter attack-coverage or economics denominators") {
			t.Fatalf("benign grouping not disclosed:\n%s", mainReport)
		}
		parts := strings.Split(mainReport, "## Honest R6 grounding")
		if len(parts) != 2 || strings.Contains(parts[1], "**benign**") || !strings.Contains(mainReport, "### Benign functional-effect grounding") {
			t.Fatalf("benign control leaked into R6 coverage grounding:\n%s", mainReport)
		}
		dollars := RenderDollars(read, DollarInputs{BaselineDefender: "d-v161-nomtd"}, 0.95)
		if !strings.Contains(dollars, "benignControlExcluded=1") || !strings.Contains(dollars, "benign functional-effect control excluded") {
			t.Fatalf("benign economics exclusion not disclosed:\n%s", dollars)
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
