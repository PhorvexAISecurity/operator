package core

import (
	"errors"
	"testing"
)

func TestRunnerCopiesRealismDescriptorToMetric(t *testing.T) {
	s := &vScenario{name: "realism-propagation"}
	r := &Runner{opts: RunnerOptions{MasterSeed: 7, OutDir: t.TempDir()}, factory: func(string, string, int, int64, string) (*Env, func() error, error) {
		return nil, nil, errors.New("stop after metric construction")
	}}
	// Override the fixture metadata through a small wrapper while reusing the
	// validity suite's real scenario and defender lifecycle implementations.
	wrapped := realismScenario{vScenario: s}
	trial := r.newTrialRun(trialSpec{scenario: wrapped, defender: &vDefender{name: "d"}, trial: 1})
	if trial.m.ScenarioRealism != RealismMarkerSimulation || trial.m.ScenarioMechanism != "marker" || trial.m.ScenarioClaimLimits != "fixture only" {
		t.Fatalf("descriptor not propagated: %+v", trial.m)
	}
	if len(trial.m.DeclaredTechniqueIDs) != 1 || len(trial.m.ExercisedTechniqueIDs) != 0 {
		t.Fatalf("technique claims not separated: %+v", trial.m)
	}
}

type realismScenario struct{ *vScenario }

func (s realismScenario) Metadata() ScenarioMeta {
	m := s.vScenario.Metadata()
	m.Realism, m.Mechanism, m.ClaimLimits = RealismMarkerSimulation, "marker", "fixture only"
	m.AttackTechniqueIDs = []string{"T1610"}
	return m
}
