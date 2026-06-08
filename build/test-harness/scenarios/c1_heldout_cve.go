package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c1HeldoutCVE{}) }

// c1HeldoutCVE is the ZERO-DAY / HELD-OUT-CVE stand-in. The attacker exploits a CVE
// that is HELD OUT of every detector's known set: NO SecurityEvent is ever emitted
// for it (no Falco/Prometheus signature, no panic event). So the ONLY thing that can
// evict the foothold is a DETECTION-INDEPENDENT move:
//   - reactive-only / no-MTD: never act (no detector) -> foothold survives.
//   - R6 blind timer / random: evict ONLY if a blind rotation happens to fire in the
//     window (untargeted).
//   - PX: the PROACTIVE FLOOR (the λ-crossing / exposure-hazard floor, NOT stage
//     classification) evicts the foothold with NO detector and NO known signature.
//
// ORACLE: the backdoor foothold is STILL alive after the dwell window (attacker wins).
// A detection-independent eviction => alive=false => disruption. This is the honest
// zero-day claim: detector-independent, cost-optimal, consequence-targeted dwell
// reduction — NOT "uniquely stops zero-days".
type c1HeldoutCVE struct{ app string }

func (s *c1HeldoutCVE) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c1-heldout-cve",
		Category:           core.CategoryClassicChain,
		Source:             "P3 zero-day stand-in; PRD §5.5 held-out-CVE benchmark; Schwartau time-based security",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1190", "T1543.005", "T1068"},
		R6Justification:    "A held-out CVE emits NO SecurityEvent (no signature, no detector), so the reactive matcher NEVER fires. Only a detection-INDEPENDENT proactive move can evict it — R6's blind timer covers it only by luck/schedule; PX's proactive floor evicts it cost-optimally. R6 cannot respond on the reactive path.",
	}
}

func (s *c1HeldoutCVE) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c1cve-target"
	_, err := deployTarget(ctx, env, s.app, "", nil)
	return err
}

func (s *c1HeldoutCVE) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	stages := []string{
		"exploit: trigger a HELD-OUT CVE (outside every detector's known set) for initial access (T1190/T1068)",
		"persistence: drop a foothold (T1543.005) — NO detection signature, NO SecurityEvent emitted",
	}
	// Plant the foothold. Crucially the harness emits NO event for this CVE (it is
	// held out of the detector's known set), so the reactive path has nothing to match.
	cmds := plantBackdoor(ctx, env, pod.Name, firstContainer(pod))
	env.Log.Logf("c1-heldout-cve: zero-day foothold planted in %s (held-out CVE; no detector event)", pod.Name)
	return core.AttackResult{Stages: stages, Commands: cmds, Notes: map[string]string{"detector": "absent (held-out CVE)"}}, nil
}

func (s *c1HeldoutCVE) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// Measure REAL foothold-survival (dwell-to-eviction). A detection-independent
	// proactive floor (PX) evicts early; reactive/no-MTD never evict (no detector);
	// a blind timer evicts at ~its interval. Window spans one blind interval + margin.
	survival, stillAlive := measureSurvival(ctx, env, s.app, 20*time.Second)
	achieved := stillAlive // attacker wins iff the foothold was never evicted
	ev := map[string]string{
		"survivalSeconds":          fmt.Sprintf("%.1f", survival),
		core.EvDetectorAbsent:      "true",
		core.EvTriggerAttribution:  core.TriggerDetectorAbsent,
		core.EvReactionSeconds:     fmt.Sprintf("%.1f", survival),
		"heldOutCVE":               "true",
		"evictionWasDetectionFree": fmt.Sprintf("%v", !stillAlive),
	}
	state := fmt.Sprintf("held-out CVE foothold (no detector event) %s detection-free-eviction=%v [zero-day=true]",
		survivalMarker(survival, stillAlive), !stillAlive)
	return core.OracleResult{Achieved: achieved, ObservedState: state, Evidence: ev}, nil
}

func (s *c1HeldoutCVE) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
