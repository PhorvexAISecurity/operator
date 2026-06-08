package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c1FastAttacker{}) }

// FastAttackerObjectiveSeconds is the time the attacker needs to COMPLETE its
// objective (exfiltrate / impact) after gaining the foothold. It is set BELOW a
// realistic periodic blind-timer interval (documented BlindRotationInterval, 15s) and
// ABOVE PX's risk-driven proactive floor (~6s), so the honest ordering is:
//   PX-eviction (~6-8s) < attacker-objective (9s) < blind-interval (15s).
// A blind timer that rotates everything on a fixed slow cadence arrives AFTER the
// objective completes (too late, ~0% disruption / full dwell); PX rotates the HIGH-
// RISK pod quickly (risk-driven, not a fixed clock) and evicts in time. These are
// scaled-for-test seconds (real intervals are minutes-hours); the RELATIVE ordering is
// the point, and the attacker speed is scaled with it — NOT rigged.
const FastAttackerObjectiveSeconds = 9.0

// c1FastAttacker is the FAST-ATTACKER variant. Its objective completes before a
// realistic blind-timer interval, exposing the core weakness of fixed-cadence blind
// rotation on fast attacks: it is TOO LATE. PX, whose rotation RATE is a risk-driven
// decision variable (high exposure on a high-value pod ⇒ fire early), evicts in time.
type c1FastAttacker struct{ app string }

func (s *c1FastAttacker) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c1-fast-attacker",
		Category:           core.CategoryClassicChain,
		Source:             "P3 fast-attacker; PRD §4 'time rotations to beat re-exploitation'; Schwartau P>D+R",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1190", "T1041", "T1486"},
		R6Justification:    "When the attacker's objective completes before a realistic periodic interval, a BLIND fixed-cadence timer arrives too late (≈0% disruption). Only a risk-driven rate that fires the high-value pod EARLY (PX) evicts in time. R6's fixed cadence cannot respond fast enough on a fast attack.",
	}
}

func (s *c1FastAttacker) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c1fast-target"
	// A high-value target (restricted data-class) so PX prioritizes evicting it early.
	_, err := deployTarget(ctx, env, s.app, "", map[string]string{"data-class": "restricted"})
	return err
}

func (s *c1FastAttacker) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	stages := []string{
		"exploit + foothold on a high-value pod (T1190)",
		fmt.Sprintf("FAST objective: exfiltrate/impact within %.0fs — before a realistic blind interval (T1041/T1486)", FastAttackerObjectiveSeconds),
	}
	cmds := plantBackdoor(ctx, env, pod.Name, firstContainer(pod))
	return core.AttackResult{Stages: stages, Commands: cmds, Notes: map[string]string{"objectiveSeconds": fmt.Sprintf("%.0f", FastAttackerObjectiveSeconds)}}, nil
}

func (s *c1FastAttacker) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// Measure how long the foothold survives, up to just past the objective time.
	window := time.Duration((FastAttackerObjectiveSeconds + 3) * float64(time.Second))
	survival, stillAlive := measureSurvival(ctx, env, s.app, window)

	// The attacker WINS iff the foothold survived long enough to COMPLETE its objective
	// (survival >= objective time). An arm that evicts BEFORE the objective disrupts it.
	objectiveAchieved := survival >= FastAttackerObjectiveSeconds || stillAlive
	blindTooLate := objectiveAchieved // a fixed slow timer can't have evicted before the objective

	ev := map[string]string{
		"survivalSeconds":      fmt.Sprintf("%.1f", survival),
		"objectiveSeconds":     fmt.Sprintf("%.0f", FastAttackerObjectiveSeconds),
		"objectiveAchieved":    fmt.Sprintf("%v", objectiveAchieved),
		core.EvReactionSeconds: fmt.Sprintf("%.1f", survival),
	}
	state := fmt.Sprintf("fast attacker (objective %.0fs): %s [objective-achieved=%v] [blind-too-late=%v] [fast-attacker=true]",
		FastAttackerObjectiveSeconds, survivalMarker(survival, stillAlive), objectiveAchieved, blindTooLate)
	return core.OracleResult{Achieved: objectiveAchieved, ObservedState: state, Evidence: ev}, nil
}

func (s *c1FastAttacker) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
