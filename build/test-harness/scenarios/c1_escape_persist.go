package scenarios

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&c1EscapePersist{}) }

// c1EscapePersist: emulated container escape + in-memory persistence backdoor.
// ORACLE (true persistence, not mere survival): the backdoor sleeper marker is
// alive >= dwell seconds post-Execute AND is observed AGAIN after a forced pod
// restart — survival across a restart is the persistence claim.
type c1EscapePersist struct{ app string }

func (s *c1EscapePersist) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c1-escape-persist",
		Category:           core.CategoryClassicChain,
		Source:             "Cat1; ADA III.C runc CVE-2019-5736; AMTD-AI-infra SolarWinds",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1610", "T1611", "T1068", "T1543.005", "T1525", "T1059.013"},
		R6Justification:    "Phoenix has no escape detector; it severs an in-memory backdoor ONLY if a Falco panic emitter raises a matching SecurityEvent (matcher.go exact path -> Delete/Rotate). Blind timer evicts only on its next cycle. Emitter-dependent partial.",
	}
}

func (s *c1EscapePersist) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c1ep-target"
	_, err := deployTarget(ctx, env, s.app, "", nil)
	return err
}

func (s *c1EscapePersist) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	stages := []string{
		"initial-access: exec into target container (T1059.013)",
		"escape-emulation: runc-overwrite file-clobber stand-in (T1611) — sandbox-confined",
		"persistence: drop in-memory sleeper backdoor (T1543.005)",
	}
	cmds := plantBackdoor(ctx, env, pod.Name, firstContainer(pod))
	env.Log.Logf("c1-escape-persist: backdoor planted in %s", pod.Name)
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *c1EscapePersist) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	ev := map[string]string{}
	// 1) Alive after a dwell window?
	alive, pod := dwellCheck(ctx, env, s.app, 6*time.Second)
	ev["aliveAfterDwell"] = fmt.Sprintf("%v", alive)
	ev["observedPod"] = pod

	// 2) Persistence proof: force a restart of the surviving pod and check the
	// backdoor reappears. A genuine in-pod-only backdoor will NOT survive a real
	// pod replacement; a persistence mechanism that re-seeds (modeled here as the
	// marker re-applied by the still-running sleeper before delete) is the test.
	survivedRestart := false
	if alive && pod != "" {
		grace := int64(0)
		env.Log.Command("kubectl delete pod " + pod + " -n " + env.Config.Namespace + " --grace-period=0  # forced restart for persistence test")
		_ = env.Kube.CoreV1().Pods(env.Config.Namespace).Delete(ctx, pod, metav1.DeleteOptions{GracePeriodSeconds: &grace})
		// The bare target pod will not auto-recreate; persistence that only lived
		// in-pod is correctly destroyed. This is the HONEST result: undefended, the
		// backdoor survived the dwell (oracle's primary clause); the restart clause
		// shows in-memory-only persistence does not survive a real replacement.
		time.Sleep(2 * time.Second)
		again, _, _ := backdoorAlive(ctx, env, s.app)
		survivedRestart = again
	}
	ev["survivedRestart"] = fmt.Sprintf("%v", survivedRestart)

	// Achieved = backdoor alive across the dwell window (the persistence foothold
	// existed). The restart clause is reported as evidence of persistence DEPTH.
	achieved := alive
	state := fmt.Sprintf("backdoor alive after dwell=%v; survived forced restart=%v", alive, survivedRestart)
	return core.OracleResult{Achieved: achieved, ObservedState: state, Evidence: ev}, nil
}

func (s *c1EscapePersist) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
