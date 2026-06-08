package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c2DwellRotation{}) }

// DwellOracleSeconds is the window the attacker tries to out-dwell. If the
// foothold survives this long, the attacker "wins" (undefended); a defender that
// caps dwell below the rotation interval disrupts it.
const DwellOracleSeconds = 8.0

// c2DwellRotation: Phoenix's CORE designed-for claim — bound a long-lived
// foothold by the rotation period. ORACLE (attacker): planted foothold stays
// alive LONGER than the dwell window. Defense disruption = dwell capped at/below
// the rotation interval. R6 COVERS (this is the honest strength; even the blind
// timer caps dwell).
type c2DwellRotation struct {
	app          string
	plantedUnix  float64
}

func (s *c2DwellRotation) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c2-dwell-rotation",
		Category:           core.CategoryR6Claimed,
		Source:             "Cat2; Phoenix-K8s DWELL_TIME 0ms; AMTD-AI-infra 150d->60min; ADA Abstract",
		R6ResponseTag:      core.R6Covers,
		AttackTechniqueIDs: []string{"T1543.005", "T1525", "T1133", "T1078.003"},
		R6Justification:    "Phoenix's core designed-for claim and honest strength: a long-lived foothold is bounded by the rotation period regardless of detection. Even the blind timer caps dwell at the interval. Covers — the oracle measures the REAL cap (= interval), not the marketing 0ms.",
	}
}

func (s *c2DwellRotation) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c2dr-target"
	_, err := deployTarget(ctx, env, s.app, "", nil)
	return err
}

func (s *c2DwellRotation) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	cmds := plantBackdoor(ctx, env, pod.Name, firstContainer(pod))
	s.plantedUnix = float64(time.Now().Unix())
	stages := []string{"persistence: plant a long-lived foothold (T1543.005)", "dwell: attempt to out-live the rotation period"}
	return core.AttackResult{Stages: stages, Commands: cmds, Notes: map[string]string{"plantedUnix": fmt.Sprintf("%.0f", s.plantedUnix)}}, nil
}

func (s *c2DwellRotation) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	alive, pod := dwellCheck(ctx, env, s.app, time.Duration(DwellOracleSeconds)*time.Second)
	measuredDwell := float64(time.Now().Unix()) - s.plantedUnix
	ev := map[string]string{
		"aliveAfterWindow": fmt.Sprintf("%v", alive),
		"measuredDwellSec": fmt.Sprintf("%.0f", measuredDwell),
		"dwellWindowSec":   fmt.Sprintf("%.0f", DwellOracleSeconds),
		"observedPod":      pod,
	}
	// Attacker "achieves" iff the foothold out-dwelled the window. A capping
	// defender makes alive=false -> disruption.
	achieved := alive
	state := fmt.Sprintf("foothold dwell out-lived window=%v (measured ~%.0fs vs window %.0fs)", alive, measuredDwell, DwellOracleSeconds)
	return core.OracleResult{Achieved: achieved, ObservedState: state, Evidence: ev}, nil
}

func (s *c2DwellRotation) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
