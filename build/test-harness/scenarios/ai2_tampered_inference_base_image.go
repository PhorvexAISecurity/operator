package scenarios

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2TamperedInferenceBaseImage{}) }

// ai2TamperedInferenceBaseImage: AI supply chain — a tampered inference base image
// (poisoned serving image layer), reusing the MockRegistry tamper pattern. SPLIT
// ORACLE: (a) the tampered base image's injected layer ran (TamperedMarker written;
// admission/build-time is ModernUnsupported-class -> CANNOT-HELP autonomously);
// (b) the tamper survives a rotation — rotation churns the pod but RE-PULLS the SAME
// tampered ref, so the marker re-appears -> BOUNDS-ONLY (may stay CANNOT-HELP).
type ai2TamperedInferenceBaseImage struct {
	app string
	reg *mocks.MockModelRegistry
}

func (s *ai2TamperedInferenceBaseImage) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-tampered-inference-base-image",
		Category:           core.CategoryModernUnsupported,
		Source:             "AI supply chain: tampered inference base image; reuses MockRegistry tamper pattern",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1525", "T1204.003"},
		R6Justification:    "Admission/build-time enforcement is outside the reactive actuator model (ModernUnsupported-class). Rotation churns the pod but re-pulls the SAME tampered ref, so the tamper re-appears. May stay CANNOT-HELP. Partial.",
	}
}

func (s *ai2TamperedInferenceBaseImage) Setup(ctx context.Context, env *core.Env) error {
	s.app = "ai2tib-serving"
	reg, err := mocks.DeployMockModelRegistry(ctx, env)
	if err != nil {
		return err
	}
	s.reg = reg
	return nil
}

func (s *ai2TamperedInferenceBaseImage) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return core.AttackResult{}, err
	}
	// "Pull and run" the tampered serving image: a rotation-target pod whose
	// entrypoint is the injected layer's payload (writes the tampered marker).
	labels := stampRotationTarget(map[string]string{"app": s.app, "r6th.io/from-registry": s.reg.SvcName})
	pod := mocks.NewPod(env, s.app, labels).
		WithBusyboxLoop("serving", mocks.PoisonedImageCommand("/tmp/.r6th_tampered"), 100, 32).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s  # pull tampered inference base image from %s", s.app, s.reg.PoisonedImageRef, env.Config.Namespace, s.reg.ClusterDNS))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return core.AttackResult{}, err
	}
	if err := env.WaitForPodRunning(ctx, s.app, 60*time.Second); err != nil {
		return core.AttackResult{}, err
	}
	return core.AttackResult{
		Stages:   []string{"supply-chain: pull tampered inference base image (T1204.003)", "exec: injected layer runs (T1525)"},
		Commands: []string{"pull " + s.reg.PoisonedImageRef, "tampered entrypoint -> " + mocks.TamperedMarker},
	}, nil
}

func (s *ai2TamperedInferenceBaseImage) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	inReq := false
	if err == nil {
		res := env.Exec(ctx, pod.Name, firstContainer(pod), []string{"sh", "-c", "cat /tmp/.r6th_tampered 2>/dev/null"})
		inReq = containsMarker(res.Stdout, mocks.TamperedMarker)
	}
	time.Sleep(6 * time.Second)
	// After a rotation, the replacement re-runs the SAME tampered ref -> marker
	// re-appears. So the tamper survives (rotation cannot break an unchanged ref).
	persisted := false
	if cur, err := runningPodByApp(ctx, env, s.app); err == nil {
		res := env.Exec(ctx, cur.Name, firstContainer(cur), []string{"sh", "-c", "cat /tmp/.r6th_tampered 2>/dev/null"})
		persisted = containsMarker(res.Stdout, mocks.TamperedMarker)
	}
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             persisted,
		inRequestAchieved:    inReq,
		persistenceAchieved:  persisted,
		persistenceDisrupted: armRotates(env) && !persisted, // MEASURED per-arm (rotation re-pulls the same tampered ref, so this measures false)
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0010.001", "AML.T0018", "AML.T0020"},
		owasp:                []string{"LLM03:2025"},
		state:                fmt.Sprintf("tampered layer ran=%v; tamper re-appears after rotation=%v (same ref re-pulled)", inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai2TamperedInferenceBaseImage) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app, "mock-model-registry")
}
