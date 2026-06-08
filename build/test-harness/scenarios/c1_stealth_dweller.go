package scenarios

import (
	"context"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c1StealthDweller{}) }

// c1StealthDweller: the PHOENIX-THESIS test — a dweller that emits NO detection
// event. ORACLE: the dweller process is alive after a dwell window W AND zero
// SecurityEvent CRs were created for it (pure stealth survival). The defense arm
// only matters if a BLIND/scheduled rotation evicts it within W — this isolates
// Phoenix's enforcement-without-detection value and its limit.
type c1StealthDweller struct{ app string }

func (s *c1StealthDweller) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c1-stealth-dweller",
		Category:           core.CategoryClassicChain,
		Source:             "Cat1; AMTD-AI-infra Defense Evasion; ADA evade-detection",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1070", "T1036.005", "T1685", "T1564"},
		R6Justification:    "A stealth dweller produces NO SecurityEvent, so quarantine never fires; ONLY blind/scheduled rotation (no telemetry) can evict it. Isolates Phoenix's enforcement-without-detection value and its limit. Partial.",
	}
}

func (s *c1StealthDweller) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c1sd-target"
	_, err := deployTarget(ctx, env, s.app, "", nil)
	return err
}

func (s *c1StealthDweller) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	stages := []string{
		"defense-evasion: masquerade as a legitimate process name (T1036.005)",
		"hide-artifacts: drop a quiet dweller that emits NO telemetry (T1564)",
		"indicator-removal: no logs, no events (T1070)",
	}
	// Plant the dweller (same marker mechanism, but the scenario's POINT is that
	// no SecurityEvent is emitted for it — we never call the emitter here).
	cmds := plantBackdoor(ctx, env, pod.Name, firstContainer(pod))
	env.Log.Logf("c1-stealth-dweller: silent dweller planted in %s (no event emitted)", pod.Name)
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *c1StealthDweller) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// REAL survival (dwell-to-eviction). PX's proactive floor evicts the dweller with
	// NO detector; reactive-only/no-MTD never evict (silent); blind evicts at ~interval.
	survival, stillAlive := measureSurvival(ctx, env, s.app, 20*time.Second)

	// Confirm zero (non-PX) detection events fired for this dweller (pure stealth): the
	// reactive matcher had nothing to act on — only proactive movement could evict it.
	events := 0
	if env.Ctrl != nil {
		var list amtdv1beta1.SecurityEventList
		if err := env.Ctrl.List(ctx, &list); err == nil {
			for i := range list.Items {
				// Phorvex's own actuation events are proactive, not a detector signal.
				if list.Items[i].Spec.Rule.Source != "PhorvexController" {
					events++
				}
			}
		}
	}
	ev := map[string]string{
		"survivalSeconds":        fmt.Sprintf("%.1f", survival),
		"detectionEvents":        fmt.Sprintf("%d", events),
		core.EvDetectorAbsent:    "true",
		core.EvReactionSeconds:   fmt.Sprintf("%.1f", survival),
	}
	// Achieved = the dweller survived the window with zero detection events.
	achieved := stillAlive && events == 0
	state := fmt.Sprintf("stealth dweller %s with %d detection events (zero-detection survival=%v) [stealth=true]",
		survivalMarker(survival, stillAlive), events, achieved)
	return core.OracleResult{Achieved: achieved, ObservedState: state, Evidence: ev}, nil
}

func (s *c1StealthDweller) Teardown(ctx context.Context, env *core.Env) error {
	// Best-effort: clear any stray harness events (idempotent).
	if env.Ctrl != nil {
		var list amtdv1beta1.SecurityEventList
		if err := env.Ctrl.List(ctx, &list); err == nil {
			for i := range list.Items {
				it := list.Items[i]
				if it.Labels[core.OwnedLabelKey] == core.OwnedLabelValue {
					_ = env.Ctrl.Delete(ctx, &it, &client.DeleteOptions{})
				}
			}
		}
	}
	return teardownByApp(ctx, env, s.app)
}
