package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&eDilutionFleet{fleet: 8}) }

// eDilutionFleet is P3-DEEP Test E (TARGETING / DILUTION): N low-value DECOY pods + 1
// high-value AT-RISK pod, all rotation-target. A blind timer has NO targeting and NO
// budget — it rotates ALL N+1 pods every interval, so its defensive COST scales ~N (a
// budget-conservation SCALE property no interval value repairs). Phorvex is capped at
// maxMovesPerTick=1 and CONCENTRATES that move on the exposed at-risk asset (discovered-
// physics fact-weight), so its cost stays ~constant as the fleet grows. Compared against
// the N=1 single-pod scenarios this gives the dilution scaling (blind cost ~ N vs PX ~ 1).
// HONEST: at N=1 PX and blind tie by design; the SLO/PDB move-cap is the real mechanism
// and is left ON (removing it is rigging — uncapped just moves dilution to the cost axis,
// which is exactly what this measures).
type eDilutionFleet struct {
	fleet   int
	app     string
	origUID string
}

func (s *eDilutionFleet) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               fmt.Sprintf("e-dilution-n%d", s.fleet+1),
		Category:           core.CategoryClassicChain,
		Source:             "P3-DEEP Test E; budget-dilution scaling law (blind rotate-all cost ~ N vs PX targeted ~ const)",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1590", "T1078"},
		R6Justification:    "Blind has no targeting/budget -> rotates all N+1 pods -> cost ~ N (uncapped). PX concentrates its 1-move budget on the exposed at-risk asset -> cost ~ const. The at-risk protection holds for PX as the fleet grows; blind pays cost ~ N. Partial: at N=1 they tie.",
	}
}

func (s *eDilutionFleet) Setup(ctx context.Context, env *core.Env) error {
	s.app = "e-atrisk"
	// N low-value decoys (rotation-target, public data-class) that dilute a blind sweep.
	for i := 0; i < s.fleet; i++ {
		_, _ = deployTarget(ctx, env, fmt.Sprintf("e-decoy-%d", i), "", map[string]string{"data-class": "public", "role": "decoy"})
	}
	// the high-value at-risk asset PX should concentrate on.
	_, err := deployTarget(ctx, env, s.app, "", map[string]string{"data-class": "restricted", "role": "at-risk"})
	return err
}

func (s *eDilutionFleet) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.origUID = string(pod.UID)
	cmds := plantBackdoor(ctx, env, pod.Name, firstContainer(pod))
	return core.AttackResult{
		Stages:   []string{fmt.Sprintf("compromise the at-risk asset amid %d decoys (T1078)", s.fleet), "blind must rotate ALL to cover it (cost ~ N); PX targets the exposed one"},
		Commands: cmds,
		Notes:    map[string]string{"fleetSize": fmt.Sprintf("%d", s.fleet+1)},
	}, nil
}

func (s *eDilutionFleet) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	life, stillValid := measureReconLifetime(ctx, env, s.app, s.origUID, 20*time.Second)
	ev := map[string]string{
		"fleetSize":                 fmt.Sprintf("%d", s.fleet+1),
		"reconValidLifetimeSeconds": fmt.Sprintf("%.1f", life),
		core.EvReactionSeconds:      fmt.Sprintf("%.1f", life),
	}
	state := fmt.Sprintf("dilution fleet N=%d: at-risk recon valid %.1fs [recon-valid=%.1fs] [recon-invalidated=%v] [fleet-size=%d] [dilution=true]",
		s.fleet+1, life, life, !stillValid, s.fleet+1)
	return core.OracleResult{Achieved: stillValid, ObservedState: state, Evidence: ev}, nil
}

func (s *eDilutionFleet) Teardown(ctx context.Context, env *core.Env) error {
	apps := []string{s.app}
	for i := 0; i < s.fleet; i++ {
		apps = append(apps, fmt.Sprintf("e-decoy-%d", i))
	}
	return teardownByApp(ctx, env, apps...)
}
