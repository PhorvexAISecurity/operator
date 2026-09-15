package scenarios

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/types"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/defenders"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c3CryptoMining{}) }

// CPUSecondsTarget is C: the CPU-seconds the miner must accrue to "win".
const CPUSecondsTarget = 5

// c3CryptoMining: a CPU-BOUNDED miner stand-in accrues >= C CPU-seconds within a
// window before any rotation. ORACLE (attacker): miner reaches C CPU-seconds.
// Disruption = miner rotated/killed before reaching C. R6 partial: eviction works
// only via a Prometheus emitter + Scored strategy; in default Exact mode the
// anomalyScore clause is INERT (matcher.go).
type c3CryptoMining struct {
	app       string
	targetUID types.UID
}

func (s *c3CryptoMining) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c3-cryptomining",
		Category:           core.CategoryModernUnsupported,
		Source:             "Cat3 c3-cryptomining; Phoenix-AI LLM-Jacking; AMTD-AI-infra cryptojacking",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1496.001", "T1610", "T1059.013"},
		R6Justification:    "Phoenix can evict a miner IF a Prometheus emitter raises a high-CPU SecurityEvent a Scored strategy matches -> rotate. Absent that wired emitter+Scored strategy, the CPU-bounded miner runs uninterrupted until a blind rotation. In default Exact mode the anomalyScore clause is INERT (matcher.go). Partial.",
	}
}

func (s *c3CryptoMining) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c3cm-miner"
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	// CPU-BOUNDED miner: a busy loop under a hard CPU limit; rotation-target so the
	// MTD arms can attempt to kill it. NEVER a real miner / pool.
	labels := mocks.LabelMap(map[string]string{defenders.RotationTargetLabel: "true", "app": s.app}, nil)
	pod := mocks.NewPod(env, s.app, labels).
		WithBusyboxLoop("app", mocks.MinerScript(20), 200, 32). // 200m CPU cap
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s --limits=cpu=200m  # CPU-bounded miner stand-in", s.app, mocks.BusyboxImage, env.Config.Namespace))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return err
	}
	return env.WaitForPodRunning(ctx, s.app, 60*time.Second)
}

func (s *c3CryptoMining) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.targetUID = pod.UID
	stages := []string{"resource-hijack: start CPU-bounded miner (T1496.001)", "accrue: try to reach C CPU-seconds before rotation"}
	env.Log.Logf("c3-cryptomining: miner running in %s, target %d CPU-seconds", pod.Name, CPUSecondsTarget)
	return core.AttackResult{Stages: stages, Commands: []string{"start CPU-bounded busy loop (no pool, no real miner)"}}, nil
}

func (s *c3CryptoMining) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// Let the miner accrue, allowing a rotation window to potentially kill it.
	observationPause(8 * time.Second)
	ev := map[string]string{"target": fmt.Sprintf("%d", CPUSecondsTarget)}
	pod, err := observationTarget(ctx, env, s.app, s.targetUID)
	if err != nil {
		ev["cpuSeconds"] = "0"
		return core.OracleResult{}, fmt.Errorf("observation target unavailable: %w", err)
	}
	res := env.Exec(ctx, pod.Name, firstContainer(pod), mocks.CPUSecondsReadCommand())
	out, err := observationExec(ctx, res)
	if err != nil {
		return core.OracleResult{}, err
	}
	got, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil || got < 0 {
		return core.OracleResult{}, fmt.Errorf("observation CPU counter malformed: %q", strings.TrimSpace(out))
	}
	ev["cpuSeconds"] = fmt.Sprintf("%d", got)
	ev["observedPod"] = pod.Name
	ev["originalPodUID"] = string(s.targetUID)
	ev["observedPodUID"] = string(pod.UID)
	achieved := got >= CPUSecondsTarget
	state := fmt.Sprintf("miner accrued %d/%d CPU-seconds before rotation", got, CPUSecondsTarget)
	return core.OracleResult{Achieved: achieved, ObservedState: state, Evidence: ev}, nil
}

func (s *c3CryptoMining) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
