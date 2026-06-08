package scenarios

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&c3CICD{}) }

// c3CICD: a MOCK in-namespace pipeline runner executes; an injected pipeline step
// tampers a build artifact. ORACLE: the injected step runs / artifact is tampered
// (injected marker present in the mock output volume). R6 CANNOT respond: pipeline
// compromise is build-time, before any workload pod exists for Phoenix to rotate.
type c3CICD struct{ app string }

func (s *c3CICD) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "c3-cicd",
		Category:           core.CategoryModernUnsupported,
		Source:             "Cat3 c3-cicd; AMTD-AI-infra SolarWinds CI/CD",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1053.007", "T1610", "T1525", "T1204.003"},
		R6Justification:    "CI/CD compromise occurs at build time, before any workload pod exists for Phoenix to rotate; no emitter covers pipeline-step injection. Phoenix's pod-rotation actuator is out of band. Cannot respond. Differentiator.",
	}
}

func (s *c3CICD) Setup(ctx context.Context, env *core.Env) error {
	s.app = "c3cicd-runner"
	return nil
}

func (s *c3CICD) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return core.AttackResult{}, err
	}
	// A mock pipeline runner pod with a shared output emptyDir. Its script runs
	// build steps + an INJECTED malicious step that tampers the artifact.
	outVol := corev1.Volume{Name: "out", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}
	outMount := corev1.VolumeMount{Name: "out", MountPath: "/out"}
	c := corev1.Container{
		Name:            "runner",
		Image:           mocks.BusyboxImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         mocks.MockPipelineScript("/out/artifact"),
		VolumeMounts:    []corev1.VolumeMount{outMount},
	}
	pod := mocks.NewPod(env, s.app, map[string]string{"app": s.app}).
		WithContainer(c).
		MutateSpec(func(spec *corev1.PodSpec) { spec.Volumes = append(spec.Volumes, outVol) }).
		Build()
	env.Log.Command(fmt.Sprintf("kubectl run %s --image=%s -n %s  # mock CI/CD pipeline runner", s.app, mocks.BusyboxImage, env.Config.Namespace))
	if _, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		return core.AttackResult{}, err
	}
	if err := env.WaitForPodRunning(ctx, s.app, 60*time.Second); err != nil {
		return core.AttackResult{}, err
	}
	stages := []string{"cicd: mock pipeline runs build steps (T1053.007)", "inject: malicious step tampers the build artifact (T1525)"}
	return core.AttackResult{Stages: stages, Commands: []string{"run mock pipeline with injected step"}}, nil
}

func (s *c3CICD) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	time.Sleep(3 * time.Second)
	ev := map[string]string{}
	pod, err := runningPodByApp(ctx, env, s.app)
	if err != nil {
		ev["injectedStepRan"] = "false"
		return core.OracleResult{Achieved: false, ObservedState: "pipeline runner absent", Evidence: ev}, nil
	}
	res := env.Exec(ctx, pod.Name, "runner", []string{"sh", "-c", "cat /out/artifact 2>/dev/null"})
	tampered := strings.Contains(res.Stdout, mocks.InjectedStepMarker)
	ev["injectedStepRan"] = fmt.Sprintf("%v", tampered)
	ev["observedPod"] = pod.Name
	state := fmt.Sprintf("injected pipeline step tampered artifact=%v", tampered)
	return core.OracleResult{Achieved: tampered, ObservedState: state, Evidence: ev}, nil
}

func (s *c3CICD) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, s.app)
}
