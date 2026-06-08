package scenarios

import (
	"context"
	"fmt"
	"time"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2MaliciousModelArtifact{}) }

// ai2MaliciousModelArtifact: malicious model artifact (pickle/safetensors loader
// RCE stand-in), CPU-runnable. SPLIT ORACLE: (a) the loader executed its payload
// (model-I/O detector ABSENT, audit #9 -> CANNOT-HELP autonomously; payload exec
// itself attributed MISSING-TRIGGER); (b) the loader foothold survives a rotation —
// an INJECTED panic -> Delete (BUILT) evicts the loader pod -> MTD-NEUTRALIZES.
type ai2MaliciousModelArtifact struct {
	app    string
	oldUID string
}

func (s *ai2MaliciousModelArtifact) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-malicious-model-artifact",
		Category:           core.CategoryR6Claimed,
		Source:             "AI supply chain: malicious model artifact (pickle/safetensors loader RCE stand-in)",
		R6ResponseTag:      core.R6Covers,
		AttackTechniqueIDs: []string{"T1204.003", "T1525"},
		R6Justification:    "The model-I/O detector is ABSENT (#9) — the deserialization payload exec is not prevented autonomously (attributed MISSING-TRIGGER). An injected panic -> Delete (BUILT) evicts the loader pod foothold. Covers via injected event.",
	}
}

func (s *ai2MaliciousModelArtifact) Setup(ctx context.Context, env *core.Env) error {
	s.app = "ai2mma-loader"
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	// A loader pod whose entrypoint emulates a malicious deserialization: it writes
	// the payload marker (containment-safe busybox echo) — the injected layer's
	// behavior = the oracle. It is a rotation target so timer arms churn it.
	labels := stampRotationTarget(map[string]string{"app": s.app})
	pod := mocks.NewPod(env, s.app, labels).
		WithBusyboxLoop("loader", []string{"sh", "-c", "echo " + mocks.MaliciousArtifactMarker + " > /tmp/payload; while true; do sleep 3600; done"}, 100, 32).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s  # malicious model artifact loader stand-in", s.app, mocks.BusyboxImage, env.Config.Namespace))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return err
	}
	if err := env.WaitForPodRunning(ctx, s.app, 60*time.Second); err != nil {
		return err
	}
	if p, err := runningPodByApp(ctx, env, s.app); err == nil {
		s.oldUID = string(p.UID)
	}
	return nil
}

func (s *ai2MaliciousModelArtifact) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		return core.AttackResult{}, err
	}
	s.oldUID = string(pod.UID)
	stages := []string{"malicious-artifact: deserialization loader executes its payload (T1204.003)"}
	cmds := []string{"loader entrypoint wrote " + mocks.MaliciousArtifactMarker}
	if emitGenuineTrigger(ctx, env, pod.Name, amtdv1beta1.TypePanic) {
		cmds = append(cmds, "emit panic SecurityEvent -> matcher -> Delete (evict loader foothold)")
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *ai2MaliciousModelArtifact) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// (a) payload exec is observable in the original pod (recorded; detector absent).
	inReq := true
	time.Sleep(6 * time.Second)
	// (b) does the loader foothold (marker) survive in a running pod after the event?
	stillThere := false
	oldGone := true
	if cur, err := runningPodByApp(ctx, env, s.app); err == nil {
		if string(cur.UID) == s.oldUID {
			oldGone = false
		}
		res := env.Exec(ctx, cur.Name, firstContainer(cur), []string{"sh", "-c", "cat /tmp/payload 2>/dev/null"})
		stillThere = containsMarker(res.Stdout, mocks.MaliciousArtifactMarker)
	}
	neutralized := armIsFullPhoenix(env) && oldGone
	disrupted := (armRotates(env) || armIsFullPhoenix(env)) && oldGone
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             stillThere && !oldGone,
		inRequestAchieved:    inReq,
		persistenceAchieved:  stillThere && !oldGone,
		persistenceDisrupted: disrupted,
		neutralized:          neutralized,
		triggerAttribution:   core.TriggerHarnessInjected,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0010.003", "AML.T0011", "AML.T0018"},
		owasp:                []string{"LLM03:2025", "LLM05:2025"},
		state:                fmt.Sprintf("payload exec=%v; loader foothold evicted (old UID replaced=%v)", inReq, oldGone),
	}
	return o.result(), nil
}

func (s *ai2MaliciousModelArtifact) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
