package scenarios

import (
	"context"
	"fmt"
	"k8s.io/apimachinery/pkg/types"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c3SupplyChain{}) }

// c3SupplyChain: a MOCK in-cluster registry serves a tampered image. ORACLE: a
// pod pulls that image AND the tampered payload runs (marker written by the
// injected layer's entrypoint). R6 CANNOT respond: no admission/image-provenance
// actuator; rotation just re-pulls the same poisoned image.
type c3SupplyChain struct {
	app       string
	targetUID types.UID
	reg       *mocks.MockRegistry
}

func (s *c3SupplyChain) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c3-supplychain",
		Category:           core.CategoryModernUnsupported,
		Source:             "Cat3 c3-supplychain; MAESTRO L4 compromised images",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1525", "T1204.003", "T1610", "T1612"},
		R6Justification:    "Phoenix has no admission/image-provenance actuator in api/v1beta1; the matcher consumes post-hoc events and rotates pods. It cannot block a tampered image; rotation re-pulls the same poisoned image. Genuine Phorvex differentiator. Cannot respond.",
	}
}

func (s *c3SupplyChain) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c3sc-victim"
	reg, err := mocks.DeployRegistry(ctx, env)
	if err != nil {
		return err
	}
	s.reg = reg
	return nil
}

func (s *c3SupplyChain) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return core.AttackResult{}, err
	}
	// "Pull and run" the tampered image: a pod whose entrypoint is the injected
	// layer's payload (writes the tampered marker). Containment-safe stand-in for
	// pulling from the mock registry.
	labels := mocks.LabelMap(map[string]string{"app": s.app}, map[string]string{"r6th.io/from-registry": s.reg.SvcName})
	pod := mocks.NewPod(env, s.app, labels).
		WithBusyboxLoop("app", mocks.PoisonedImageCommand("/tmp/.r6th_tampered"), 100, 32).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s  # pull tampered image from %s", s.app, s.reg.PoisonedImageRef, env.Config.Namespace, s.reg.ClusterDNS))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return core.AttackResult{}, err
	}
	if err := env.WaitForPodRunning(ctx, s.app, 60*time.Second); err != nil {
		return core.AttackResult{}, err
	}
	original, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, fmt.Errorf("stimulus target unavailable: %w", err)
	}
	s.targetUID = original.UID
	stages := []string{"supply-chain: pull tampered image from mock registry (T1204.003)", "exec: injected layer entrypoint runs (T1525)"}
	return core.AttackResult{Stages: stages, Commands: []string{"pull " + s.reg.PoisonedImageRef, "run tampered entrypoint"}}, nil
}

func (s *c3SupplyChain) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	observationPause(3 * time.Second)
	ev := map[string]string{}
	ev["originalPodUID"] = string(s.targetUID)
	pod, err := observationTarget(ctx, env, s.app, s.targetUID)
	if err != nil {
		ev["payloadRan"] = "false"
		return core.OracleResult{}, fmt.Errorf("observation target unavailable: %w", err)
	}
	res := env.Exec(ctx, pod.Name, firstContainer(pod), markerReadCommand("/tmp/.r6th_tampered"))
	ran, err := observedMarker(ctx, res, mocks.TamperedMarker)
	if err != nil {
		return core.OracleResult{}, err
	}
	ev["payloadRan"] = fmt.Sprintf("%v", ran)
	ev["observedPod"] = pod.Name
	ev["observedPodUID"] = string(pod.UID)
	state := fmt.Sprintf("tampered image payload ran=%v in %s (rotation re-pulls same poisoned image)", ran, pod.Name)
	return core.OracleResult{Achieved: ran, ObservedState: state, Evidence: ev}, nil
}

func (s *c3SupplyChain) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app, "mock-registry")
}
