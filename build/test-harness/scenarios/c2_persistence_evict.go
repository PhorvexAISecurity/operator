package scenarios

import (
	"context"
	"fmt"
	"time"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c2PersistenceEvict{}) }

// Emitter is the optional capability a defender exposes so a scenario can drive
// the genuine reactive matcher path by emitting a normalized SecurityEvent. Only
// d-fullphoenix implements it; against other arms the scenario relies purely on
// the arm's own behavior (rotation or none).
type Emitter interface {
	EmitSecurityEvent(ctx context.Context, env *core.Env, targetPod, eventType, threatLevel string) error
}

// emitterFromEnv resolves the active defender (by name) to its Emitter if it
// supports one. The runner sets env.DefenderName; the scenario looks the defender
// up in the registry and type-asserts.
func emitterFromEnv(env *core.Env) (Emitter, bool) {
	d, ok := core.LookupDefender(env.DefenderName)
	if !ok {
		return nil, false
	}
	em, ok := d.(Emitter)
	return em, ok
}

// c2PersistenceEvict: compromised-pod eviction on a DETECTION event — the exact
// reactive path matcher.go implements. ORACLE: after a SecurityEvent is emitted
// for the compromised pod, the malicious process is GONE within time-to-action
// (old pod UID terminated AND backdoor marker absent in the replacement). R6
// COVERS when the emitter+strategy are present (FullPhoenix wires the emitter).
type c2PersistenceEvict struct {
	app    string
	oldUID string
}

func (s *c2PersistenceEvict) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c2-persistence-evict",
		Category:           core.CategoryR6Claimed,
		Source:             "Cat2; Phoenix-K8s Self-Healing/Panic Mutation; ADA 3.3",
		R6ResponseTag:      core.R6Covers,
		AttackTechniqueIDs: []string{"T1543.005", "T1611", "T1059.013", "T1070"},
		R6Justification:    "Compromised-pod eviction on a detection event is the exact reactive path the matcher implements: a Falco {panic/policy-violation,high,emitter} SecurityEvent -> delete/quarantine/rotate on the PodSelector-matched pod. Covers WHEN emitter+strategy present; the harness wires the emitter (FullPhoenix) to test the genuine path.",
	}
}

func (s *c2PersistenceEvict) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c2pe-target"
	pod, err := deployTarget(ctx, env, s.app, "", nil)
	if err != nil {
		return err
	}
	s.oldUID = string(pod.UID)
	return nil
}

func (s *c2PersistenceEvict) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.oldUID = string(pod.UID)
	cmds := plantBackdoor(ctx, env, pod.Name, firstContainer(pod))
	stages := []string{"persistence: plant foothold (T1543.005)", "detection: an emitter raises a normalized panic SecurityEvent"}

	// If the active defender supports the reactive emitter (FullPhoenix), drive the
	// genuine matcher path: emit a {panic,high,emitter} event targeting the pod.
	if em, ok := emitterFromEnv(env); ok {
		if err := em.EmitSecurityEvent(ctx, env, pod.Name, amtdv1beta1.TypePanic, amtdv1beta1.ThreatLevelHigh); err != nil {
			env.Log.Logf("c2-persistence-evict: emit error (genuine path): %v", err)
		} else {
			env.Log.Logf("c2-persistence-evict: emitted panic SecurityEvent for %s (reactive matcher path)", pod.Name)
			cmds = append(cmds, "emit SecurityEvent{panic,high,emitter} -> matcher -> Delete")
		}
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *c2PersistenceEvict) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// Time-to-action: allow the operator/rotation a window to act.
	time.Sleep(6 * time.Second)
	alive, pod := backdoorAliveWrap(ctx, env, s.app)

	// Confirm the old pod UID is gone (terminated/replaced).
	oldGone := true
	if cur, err := runningPodByApp(ctx, env, s.app); err == nil {
		if string(cur.UID) == s.oldUID {
			oldGone = false
		}
	}
	ev := map[string]string{
		"backdoorAlive": fmt.Sprintf("%v", alive),
		"oldPodUID":     s.oldUID,
		"oldPodGone":    fmt.Sprintf("%v", oldGone),
		"observedPod":   pod,
	}
	// Attacker "achieves" iff the backdoor is STILL alive (eviction failed). A
	// successful reactive eviction => alive=false => disruption.
	achieved := alive
	state := fmt.Sprintf("post-detection: backdoor alive=%v, old pod replaced=%v", alive, oldGone)
	return core.OracleResult{Achieved: achieved, ObservedState: state, Evidence: ev}, nil
}

func (s *c2PersistenceEvict) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}

// backdoorAliveWrap is a tiny wrapper so the oracle reads cleanly.
func backdoorAliveWrap(ctx context.Context, env *core.Env, app string) (bool, string) {
	alive, pod, err := backdoorAlive(ctx, env, app)
	if err != nil {
		env.Log.Logf("backdoorAlive error: %v", err)
	}
	return alive, pod
}
